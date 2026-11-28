"""出网防护(SSRF,docs/02 WB-S1/S2/S3)。

所有出网请求都必须经过 `EgressClient`。防线:

1. URL 层(`validate_url`):只允许 http/https、端口 80/443、不允许 userinfo;拒绝 localhost/*.localhost、
   结尾带点的主机名、IPv6 zone id、非标准写法的数字 IP(十进制/八进制/十六进制/缩写)。
2. 连接层:代理模式由 Smokescreen 解析 DNS 并校验目标 IP。直连模式下 `GuardedBackend` 在建 TCP 连接时
   解析 DNS,解析结果里**只要有一个**地址不是公网就整体拒绝;
   然后直接连接这个已检查过的 IP(TLS 的 SNI/证书校验仍用原主机名)。检查与连接之间不再有第二次 DNS 查询,
   因此 DNS 重绑定无效。
3. 跳转:不让 HTTP 库自动跳转;每一跳都重新走 1 和 2,最多 `max_redirects` 跳。
4. 资源:流式读取响应,超过 `max_bytes` 立即中断;总时长上限(调用方可按用途显式给别的上限,如网站地图);
   不读环境变量代理(trust_env=False);不存 Cookie。
"""

from __future__ import annotations

import asyncio
import functools
import ipaddress
import re
import socket
import typing
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from http.cookiejar import CookieJar, DefaultCookiePolicy

import httpcore2
import httpx2
from httpcore2 import AsyncNetworkBackend, AsyncNetworkStream
from httpcore2._backends.auto import AutoBackend
from httpcore2._backends.base import SOCKET_OPTION

from capkit.errors import ErrorCode, PlatcapError

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

ALLOWED_SCHEMES = frozenset({"http", "https"})
DEFAULT_PORTS = {"http": 80, "https": 443}
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})

# 公网地址里仍然要挡的:云厂商的特殊服务地址(不在私网段)
EXTRA_DENY_NETWORKS: tuple[IPNetwork, ...] = (
    ipaddress.ip_network("168.63.129.16/32"),  # Azure WireServer
    ipaddress.ip_network("64:ff9b:1::/48"),  # NAT64 本地用途段
)

NAT64_WELL_KNOWN = ipaddress.ip_network("64:ff9b::/96")

# 最后一个标签全是数字或以 0x 开头 → 这是「数字 IP」的某种写法(顶级域名不可能是这样)
_NUMERIC_LAST_LABEL = re.compile(r"^(?:\d+|0x[0-9a-f]*)$", re.IGNORECASE)


class BlockedAddressError(PlatcapError):
    def __init__(self, message: str) -> None:
        super().__init__(ErrorCode.blocked_address, message)


@dataclass(frozen=True)
class EgressPolicy:
    allowed_ports: frozenset[int] = frozenset({80, 443})
    max_redirects: int = 5
    max_bytes: int = 5 * 1024 * 1024
    total_timeout_s: float = 15.0
    # 调用方显式要更大的上限时,最多到这里(不设 = 和默认一样,即不能超过)。如网站地图协议允许 50MB
    max_bytes_ceiling: int | None = None
    total_timeout_ceiling_s: float | None = None
    connect_timeout_s: float = 5.0
    # 同时连外站的连接数上限(连接池)。httpx 默认只有 100:外站慢(每个几秒)时吞吐被卡在 100/延迟,
    # 压测里 14 秒的慢站只跑到约 7 次/秒、其余在池子里排到超时(docs/09)
    max_connections: int = 1000
    max_keepalive_connections: int = 200
    user_agent: str = "platcap/0.1"
    # 仅供测试:放行精确的 (IP, 端口)(例如本机的「恶意」测试服务器)。生产配置不暴露此项。
    test_only_allow_endpoints: frozenset[tuple[str, int]] = field(default=frozenset())

    def endpoint_allowed_for_test(self, ip: IPAddress, port: int) -> bool:
        return (str(ip), port) in self.test_only_allow_endpoints


# ---------------------------------------------------------------- IP 判定


def _embedded_ipv4(ip: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    """IPv6 地址里内嵌的 IPv4(映射、6to4、NAT64、Teredo 客户端地址)。"""
    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    if ip.sixtofour is not None:
        return ip.sixtofour
    if ip.teredo is not None:
        return ip.teredo[1]
    if ip in NAT64_WELL_KNOWN:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return None


def blocked_reason(ip: IPAddress) -> str | None:
    """返回拒绝原因;None 表示是可以连接的公网地址。"""
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.scope_id:
            return "IPv6 带 zone id"
        inner = _embedded_ipv4(ip)
        if inner is not None:
            reason = blocked_reason(inner)
            if reason is not None:
                return f"IPv6 内嵌 IPv4 {inner}: {reason}"
        if ip.is_site_local:
            return "IPv6 站点本地地址"
    if ip.is_loopback:
        return "本机回环地址"
    if ip.is_unspecified:
        return "未指定地址"
    if ip.is_link_local:
        return "链路本地地址(含云元数据 169.254.169.254)"
    if ip.is_multicast:
        return "组播地址"
    if ip.is_reserved:
        return "保留地址"
    if ip.is_private or not ip.is_global:
        return "内网/非公网地址"
    for net in EXTRA_DENY_NETWORKS:
        if ip.version == net.version and ip in net:
            return f"云平台特殊地址 {net}"
    return None


def check_ip(ip: IPAddress, port: int, policy: EgressPolicy) -> None:
    if policy.endpoint_allowed_for_test(ip, port):
        return
    if port not in policy.allowed_ports:
        raise BlockedAddressError(f"只允许端口 {sorted(policy.allowed_ports)},收到 {port}")
    reason = blocked_reason(ip)
    if reason is not None:
        raise BlockedAddressError(f"目标地址不允许访问:{ip}({reason})")


def _parse_ip_literal(host: str) -> IPAddress | None:
    try:
        return ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return None


# ---------------------------------------------------------------- URL 判定


MAX_HOSTNAME_LEN = 253  # DNS 名字上限(RFC 1035)


def validate_host(host: str) -> None:
    """主机名层面的拒绝规则(不解析 DNS)。"""
    if not host:
        raise BlockedAddressError("缺少主机名")
    if len(host) > MAX_HOSTNAME_LEN:
        raise BlockedAddressError("主机名太长")
    if "%" in host:
        raise BlockedAddressError("不允许 IPv6 zone id")
    if host.endswith("."):
        raise BlockedAddressError("不允许结尾带点的主机名")
    lowered = host.lower()
    if lowered == "localhost" or lowered.endswith(".localhost"):
        raise BlockedAddressError("不允许 localhost")
    if _parse_ip_literal(lowered) is not None:
        return
    if "." not in lowered:
        raise BlockedAddressError("不允许单标签主机名(内网短名)")
    if lowered.endswith((".internal", ".local", ".lan", ".home.arpa", ".intranet", ".corp")):
        raise BlockedAddressError("不允许内网专用域名")
    last_label = lowered.rsplit(".", 1)[-1]
    if _NUMERIC_LAST_LABEL.fullmatch(last_label):
        raise BlockedAddressError(f"不允许非标准写法的数字 IP:{host}")


def validate_url(url: str | httpx2.URL, policy: EgressPolicy) -> httpx2.URL:
    try:
        parsed = url if isinstance(url, httpx2.URL) else httpx2.URL(url)
    except httpx2.InvalidURL as exc:
        raise PlatcapError(ErrorCode.invalid_request, f"网址无效:{exc}") from exc
    scheme = parsed.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise BlockedAddressError(f"只允许 http/https,收到 {scheme or '空'}")
    if parsed.userinfo:
        raise BlockedAddressError("网址里不允许带用户名密码")
    host = parsed.host
    validate_host(host)
    port = parsed.port or DEFAULT_PORTS[scheme]
    literal = _parse_ip_literal(host)
    if literal is not None:
        check_ip(literal, port, policy)
    elif port not in policy.allowed_ports and port not in {p for _, p in policy.test_only_allow_endpoints}:
        # 主机名此时还不知道 IP;测试放行的端口先过,连接层按 (IP, 端口) 精确再判
        raise BlockedAddressError(f"只允许端口 {sorted(policy.allowed_ports)},收到 {port}")
    return parsed


# ---------------------------------------------------------------- DNS + 连接


Resolver = typing.Callable[[str, int], typing.Awaitable[list[IPAddress]]]


CONNECT_RETRIES = 1  # 建连阶段超时重试的次数(请求还没发出)
DNS_TIMEOUT_S = 5.0
_DNS_CONCURRENCY = 32
_dns_executor = ThreadPoolExecutor(max_workers=_DNS_CONCURRENCY, thread_name_prefix="egress-dns")


async def system_resolve(host: str, port: int) -> list[IPAddress]:
    """系统解析器,跑在专用的有界线程池里:慢 DNS 只会占满这个池,不拖累进程里其他线程池用户。"""
    loop = asyncio.get_running_loop()
    try:
        async with asyncio.timeout(DNS_TIMEOUT_S):
            infos = await loop.run_in_executor(
                _dns_executor,
                functools.partial(socket.getaddrinfo, host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP),
            )
    except TimeoutError as exc:
        raise PlatcapError(ErrorCode.timeout, f"域名解析超时:{host}") from exc
    except socket.gaierror as exc:
        raise PlatcapError(ErrorCode.upstream_error, f"域名解析失败:{host}") from exc
    ips: list[IPAddress] = []
    for _family, _type, _proto, _canon, sockaddr in infos:
        ip = ipaddress.ip_address(sockaddr[0])
        if ip not in ips:
            ips.append(ip)
    return ips


async def resolve_and_check(host: str, port: int, policy: EgressPolicy, resolver: Resolver) -> list[IPAddress]:
    """解析并检查。任何一个解析结果不是公网 → 整体拒绝(不挑公网的那个)。"""
    validate_host(host)
    literal = _parse_ip_literal(host)
    ips = [literal] if literal is not None else await resolver(host, port)
    if not ips:
        raise PlatcapError(ErrorCode.upstream_error, f"域名没有解析结果:{host}")
    for ip in ips:
        check_ip(ip, port, policy)
    return ips


class GuardedBackend(AsyncNetworkBackend):
    """httpcore 网络后端:连接时解析 + 检查 + 连到已检查的 IP。"""

    def __init__(self, policy: EgressPolicy, resolver: Resolver = system_resolve) -> None:
        self._policy = policy
        self._resolver = resolver
        self._inner = AutoBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,  # noqa: ASYNC109 (httpcore 接口签名)
        local_address: str | None = None,
        socket_options: Iterable[SOCKET_OPTION] | None = None,
    ) -> AsyncNetworkStream:
        ips = await resolve_and_check(host, port, self._policy, self._resolver)
        last_exc: Exception | None = None
        for ip in ips:
            try:
                return await self._inner.connect_tcp(
                    str(ip), port, timeout=timeout, local_address=local_address, socket_options=socket_options
                )
            except (httpcore2.ConnectError, httpcore2.ConnectTimeout) as exc:
                last_exc = exc
        raise last_exc or httpcore2.ConnectError(f"无法连接 {host}")

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,  # noqa: ASYNC109 (httpcore 接口签名)
        socket_options: Iterable[SOCKET_OPTION] | None = None,
    ) -> AsyncNetworkStream:
        raise BlockedAddressError("不允许 unix socket")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


class GuardedTransport(httpx2.AsyncHTTPTransport):
    """httpx2 的默认传输层,只把连接池换成带 GuardedBackend 的版本,不走任何代理。"""

    def __init__(self, policy: EgressPolicy, resolver: Resolver = system_resolve) -> None:
        super().__init__(trust_env=False, retries=0)
        self._pool = httpcore2.AsyncConnectionPool(
            ssl_context=httpx2.create_ssl_context(trust_env=False),
            max_connections=policy.max_connections,
            max_keepalive_connections=policy.max_keepalive_connections,
            keepalive_expiry=5.0,
            http1=True,
            http2=False,
            retries=0,
            network_backend=GuardedBackend(policy, resolver),
        )


POOL_WAIT_S = 2.0  # 等出网连接池里空闲连接的上限


# ---------------------------------------------------------------- 客户端


@dataclass
class FetchResult:
    url: str  # 最终网址(跳转之后)
    status_code: int
    headers: dict[str, str]
    body: bytes
    redirects: list[str]


class EgressClient:
    """出网客户端。

    - 直连模式(proxy_url=None):连接层自己检查并钉 IP(`GuardedTransport`)。只用于本机开发与测试。
    - 代理模式(生产):本地校验 URL,由 Smokescreen 在连接时解析 DNS 并校验目标 IP。
      被 Smokescreen 拒绝时返回 blocked_address。
    """

    def __init__(
        self, policy: EgressPolicy, resolver: Resolver = system_resolve, *, proxy_url: str | None = None
    ) -> None:
        self.policy = policy
        self._resolver = resolver
        self._proxy_url = proxy_url
        no_cookies = CookieJar(policy=DefaultCookiePolicy(allowed_domains=[]))
        transport: httpx2.AsyncBaseTransport = (
            GuardedTransport(policy, resolver)
            if proxy_url is None
            else httpx2.AsyncHTTPTransport(
                proxy=proxy_url,
                trust_env=False,
                retries=0,
                limits=httpx2.Limits(
                    max_connections=policy.max_connections,
                    max_keepalive_connections=policy.max_keepalive_connections,
                ),
            )
        )
        self._client = httpx2.AsyncClient(
            transport=transport,
            trust_env=False,
            follow_redirects=False,
            cookies=no_cookies,
            # 等空闲连接单独给一个短时限:池子满了要报「我们忙」(overloaded,不算目标站的错),
            # 而不是等到总时限变成「目标站超时」去触发熔断(独立复审)
            timeout=httpx2.Timeout(policy.total_timeout_s, connect=policy.connect_timeout_s, pool=POOL_WAIT_S),
            # 只接受 gzip/deflate,不接 br/zstd:解压膨胀可控(解压后照样按 max_bytes 截断)
            headers={"User-Agent": policy.user_agent, "Accept-Encoding": "gzip, deflate"},
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> EgressClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def fetch(
        self,
        url: str,
        *,
        max_bytes: int | None = None,
        headers: dict[str, str] | None = None,
        on_redirect: typing.Callable[[str], None] | None = None,
        timeout_s: float | None = None,
    ) -> FetchResult:
        """on_redirect:每次要跟随跳转之前调用(参数是下一跳网址),可以抛错中止。

        max_bytes / timeout_s 不给就用策略默认值;给了也不超过策略的 *_ceiling(没设 ceiling 就不超过默认值)。
        """
        p = self.policy
        limit = min(max_bytes, p.max_bytes_ceiling or p.max_bytes) if max_bytes else p.max_bytes
        total = min(timeout_s, p.total_timeout_ceiling_s or p.total_timeout_s) if timeout_s else p.total_timeout_s
        try:
            async with asyncio.timeout(total):
                return await self._fetch(url, limit, headers or {}, on_redirect)
        except TimeoutError as exc:
            raise PlatcapError(ErrorCode.timeout, f"超过 {total} 秒") from exc
        except httpx2.PoolTimeout as exc:  # 等不到空闲连接:是我们自己忙,不是目标站慢
            raise PlatcapError(ErrorCode.overloaded, "出网连接已满,请稍后重试", platform_side=True) from exc
        except httpx2.TimeoutException as exc:
            raise PlatcapError(ErrorCode.timeout, "目标站超时") from exc
        except httpx2.ProxyError as exc:
            # CONNECT 被 smokescreen 拒绝时是 407;其他(502/503/504)是代理连不上目标,不算拦截
            if "407" in str(exc):
                raise BlockedAddressError("出网代理拒绝了这个地址") from exc
            raise PlatcapError(ErrorCode.upstream_error, "经出网代理连接目标站失败") from exc
        except httpx2.ConnectError as exc:
            # 经代理时,建连只连代理本身:连不上是我们的出网代理挂了,不是目标站
            raise PlatcapError(
                ErrorCode.upstream_error,
                "经出网代理连接失败" if self._proxy_url else f"连接目标站失败:{type(exc).__name__}",
                platform_side=self._proxy_url is not None,
            ) from exc
        except httpx2.TransportError as exc:
            raise PlatcapError(ErrorCode.upstream_error, f"连接目标站失败:{type(exc).__name__}") from exc

    async def is_blocked_destination(self, url: str) -> bool:
        """自己解析一次:这个网址是不是出网防护要拒绝的(内网/保留地址等)。解析不了按「不是」。

        浏览器只会报「隧道连接失败」,分不出是被代理拒绝还是对方 DNS/网络出错;用这个分开报。
        """
        try:
            parsed = validate_url(url, self.policy)
            await resolve_and_check(
                parsed.host, parsed.port or DEFAULT_PORTS[parsed.scheme], self.policy, self._resolver
            )
        except BlockedAddressError:
            return True
        except Exception:  # 解析失败或任何意外:按「不是被拒」报可重试错误,smokescreen 照样在拦(评审 L1)
            return False
        return False

    async def _send_with_connect_retry(self, url: httpx2.URL, headers: dict[str, str]) -> httpx2.Response:
        """建连(含 TLS 握手)阶段超时就再试一次:请求还没发出去,重试是安全的;CDN 域名有多个 IP,
        经代理重连多半会换到另一个(实测彭博:Fastly 的一个节点 5 秒不回握手,换一个就正常)。总时限照旧。"""
        for attempt in range(CONNECT_RETRIES + 1):
            request = self._client.build_request("GET", url, headers=headers)
            try:
                return await self._client.send(request, stream=True)
            except httpx2.ConnectTimeout:
                if attempt >= CONNECT_RETRIES:
                    raise
        raise AssertionError("unreachable")

    async def _fetch(
        self,
        url: str,
        limit: int,
        headers: dict[str, str],
        on_redirect: typing.Callable[[str], None] | None = None,
    ) -> FetchResult:
        current = validate_url(url, self.policy)
        redirects: list[str] = []
        while True:
            response = await self._send_with_connect_retry(current, headers)
            try:
                # smokescreen 拒绝时回 407 并带这个头(只认 407:目标站自己发的同名头不算)
                if (
                    self._proxy_url is not None
                    and response.status_code == 407
                    and "x-smokescreen-error" in response.headers
                ):
                    raise BlockedAddressError(f"出网代理拒绝:{response.headers['x-smokescreen-error']}")
                location = response.headers.get("location")
                if response.status_code in REDIRECT_STATUSES and location:
                    if len(redirects) >= self.policy.max_redirects:
                        raise PlatcapError(ErrorCode.too_many_redirects, f"跳转超过 {self.policy.max_redirects} 次")
                    current = validate_url(current.join(location), self.policy)
                    if on_redirect is not None:
                        on_redirect(str(current))
                    redirects.append(str(current))
                    continue
                body = await _read_capped(response, limit)
                return FetchResult(
                    url=str(current),
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    body=body,
                    redirects=redirects,
                )
            finally:
                await response.aclose()
                self._client.cookies.clear()


async def _read_capped(response: httpx2.Response, limit: int) -> bytes:
    declared = response.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit:
        raise PlatcapError(ErrorCode.too_large, f"响应大小 {declared} 超过上限 {limit}")
    chunks: list[bytes] = []
    total = 0
    async for chunk in response.aiter_bytes():
        total += len(chunk)
        if total > limit:
            raise PlatcapError(ErrorCode.too_large, f"响应超过上限 {limit} 字节")
        chunks.append(chunk)
    return b"".join(chunks)
