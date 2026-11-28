"""SSRF 套件(docs/02 步骤 1 + bot2-36 补充项)。每个用例都要被拦成 blocked_address(或对应错误码)。"""

import asyncio
import ipaddress
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx2
import pytest

from capkit.egress import (
    EgressClient,
    EgressPolicy,
    GuardedBackend,
    IPAddress,
    blocked_reason,
    system_resolve,
    validate_url,
)
from capkit.errors import ErrorCode, PlatcapError

PUBLIC_IP = "93.184.215.14"


def fake_resolver(table: dict[str, list[str]]) -> Callable[[str, int], Awaitable[list[IPAddress]]]:
    async def resolve(host: str, port: int) -> list[IPAddress]:
        if host in table:
            return [ipaddress.ip_address(x) for x in table[host]]
        return await system_resolve(host, port)

    return resolve


# ---------------------------------------------------------------- 1. 网址/地址层(不发请求就该拦下)

BLOCKED_URLS = {
    # 内网 IP
    "private-10": "http://10.0.0.1/",
    "private-172": "http://172.16.5.4/",
    "private-192": "http://192.168.1.1/",
    "cgnat-100.64": "http://100.64.0.1/",
    # 本机
    "loopback-127": "http://127.0.0.1/",
    "loopback-127.x": "http://127.8.9.10/",
    "loopback-ipv6": "http://[::1]/",
    "unspecified-0.0.0.0": "http://0.0.0.0/",
    "localhost": "http://localhost/",
    "sub.localhost": "http://api.localhost/",
    "localhost-trailing-dot": "http://localhost./",
    "trailing-dot-hostname": "http://example.com./",
    # 云元数据
    "metadata-aws-gcp-azure": "http://169.254.169.254/latest/meta-data/",
    "metadata-aws-ipv6": "http://[fd00:ec2::254]/",
    "metadata-alibaba": "http://100.100.100.200/",
    "azure-wireserver": "http://168.63.129.16/",
    "link-local-ipv6": "http://[fe80::1]/",
    "ipv6-zone-id": "http://[fe80::1%25eth0]/",
    # 非标准数字写法
    "decimal-2130706433": "http://2130706433/",
    "octal-0177.0.0.1": "http://0177.0.0.1/",
    "hex-0x7f.0.0.1": "http://0x7f.0.0.1/",
    "hex-0x7f000001": "http://0x7f000001/",
    "short-127.1": "http://127.1/",
    "decimal-metadata": "http://2852039166/",
    # IPv6 各种包法
    "ipv4-mapped": "http://[::ffff:127.0.0.1]/",
    "ipv4-mapped-hex": "http://[::ffff:7f00:1]/",
    "ipv4-mapped-metadata": "http://[::ffff:169.254.169.254]/",
    "ipv4-compatible": "http://[::127.0.0.1]/",
    "nat64-loopback": "http://[64:ff9b::127.0.0.1]/",
    "6to4-private": "http://[2002:0a00:0001::]/",
    "ula-fc00": "http://[fc00::1]/",
    "site-local-fec0": "http://[fec0::1]/",
    "multicast-v4": "http://224.0.0.1/",
    "multicast-v6": "http://[ff02::1]/",
    "broadcast": "http://255.255.255.255/",
    "reserved-240": "http://240.0.0.1/",
    # 协议/端口/userinfo
    "port-8080": "http://example.com:8080/",
    "port-22": "http://example.com:22/",
    "port-postgres-18310": "http://example.com:18310/",
    "scheme-file": "file:///etc/passwd",
    "scheme-ftp": "ftp://example.com/",
    "scheme-gopher": "gopher://example.com/",
    "userinfo": "http://user:pass@example.com/",
    "userinfo-confusion": "http://example.com@127.0.0.1/",
    # 内网短名 / 专用域名(容器名探测)
    "single-label": "http://valkey/",
    "single-label-port": "http://gateway:18300/",
    "dot-internal": "http://metadata.google.internal/",
    "dot-local": "http://printer.local/",
}


@pytest.mark.parametrize("url", list(BLOCKED_URLS.values()), ids=list(BLOCKED_URLS))
async def test_blocked_before_any_request(url: str) -> None:
    async with EgressClient(EgressPolicy()) as client:
        with pytest.raises(PlatcapError) as exc:
            await client.fetch(url)
    assert exc.value.code in {ErrorCode.blocked_address, ErrorCode.invalid_request}, exc.value.message


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", PUBLIC_IP])
def test_public_addresses_allowed(ip: str) -> None:
    assert blocked_reason(ipaddress.ip_address(ip)) is None


def test_public_hostname_url_passes_url_layer() -> None:
    assert (
        validate_url("https://www.federalreserve.gov/newsevents.htm", EgressPolicy()).host == "www.federalreserve.gov"
    )


# ---------------------------------------------------------------- 2. DNS 层


@pytest.mark.parametrize(
    ("case", "answers"),
    [
        ("dns-to-loopback", ["127.0.0.1"]),
        ("dns-to-metadata", ["169.254.169.254"]),
        ("dns-mixed-public-and-private", [PUBLIC_IP, "10.0.0.5"]),
        ("dns-mixed-private-first", ["192.168.0.10", PUBLIC_IP]),
        ("dns-to-ipv6-mapped", ["::ffff:10.0.0.1"]),
    ],
)
async def test_dns_answer_with_any_private_ip_blocks_whole_request(case: str, answers: list[str]) -> None:
    resolver = fake_resolver({"evil.test": answers})
    async with EgressClient(EgressPolicy(), resolver) as client:
        with pytest.raises(PlatcapError) as exc:
            await client.fetch("http://evil.test/")
    assert exc.value.code is ErrorCode.blocked_address, case


class _RecordingInner:
    def __init__(self) -> None:
        self.connected_to: list[str] = []

    async def connect_tcp(self, host: str, port: int, **_: Any) -> Any:
        self.connected_to.append(host)
        raise ConnectionAbortedError("stop here")  # 不真的连出去


async def test_dns_rebinding_connection_pinned_to_checked_ip() -> None:
    """第一次解析给公网 IP、之后给 127.0.0.1:连接必须用检查过的那个 IP,且只解析一次。"""
    calls: list[str] = []

    async def rebinding(host: str, port: int) -> list[IPAddress]:
        calls.append(host)
        return [ipaddress.ip_address(PUBLIC_IP if len(calls) == 1 else "127.0.0.1")]

    backend = GuardedBackend(EgressPolicy(), rebinding)
    inner = _RecordingInner()
    backend._inner = inner  # type: ignore[assignment]
    with pytest.raises(ConnectionAbortedError):
        await backend.connect_tcp("rebind.test", 443)
    assert calls == ["rebind.test"]
    assert inner.connected_to == [PUBLIC_IP]


async def test_unix_socket_refused() -> None:
    with pytest.raises(PlatcapError):
        await GuardedBackend(EgressPolicy()).connect_unix_socket("/var/run/docker.sock")


# ---------------------------------------------------------------- 3. 端到端:本机「恶意」服务器


@dataclass
class Hostile:
    host: str
    port: int

    @property
    def base(self) -> str:
        return f"http://hostile.test:{self.port}"


async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, port: int) -> None:
    try:
        request_line = (await reader.readline()).decode()
        while (await reader.readline()) not in (b"\r\n", b""):
            pass
        target = request_line.split(" ")[1]
        parts = urlsplit(target)
        query = parse_qs(parts.query)
        if parts.path == "/redirect":
            writer.write(f"HTTP/1.1 302 Found\r\nLocation: {query['to'][0]}\r\nContent-Length: 0\r\n\r\n".encode())
        elif parts.path == "/loop":
            n = int(query.get("n", ["0"])[0])
            writer.write(f"HTTP/1.1 302 Found\r\nLocation: /loop?n={n + 1}\r\nContent-Length: 0\r\n\r\n".encode())
        elif parts.path == "/big-chunked":
            writer.write(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
            chunk = b"x" * 65536
            for _ in range(200):  # 12.5MB,没有 Content-Length
                writer.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
                await writer.drain()
            writer.write(b"0\r\n\r\n")
        elif parts.path == "/big-declared":
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 999999999\r\n\r\n")
        elif target.startswith("http://denied.test"):  # 冒充 smokescreen 的拒绝响应
            writer.write(
                b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                b"X-Smokescreen-Error: denied by rule 'Deny: Private Range'\r\n"
                b"Content-Length: 0\r\n\r\n"
            )
        elif target.startswith("http://public.test/redirect-internal"):
            writer.write(b"HTTP/1.1 302 Found\r\nLocation: http://10.0.0.7/\r\nContent-Length: 0\r\n\r\n")
        elif target.startswith("http://public.test"):
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        elif request_line.startswith("CONNECT upstream-fail.test"):  # 冒充代理:连不上目标(不是拦截)
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
        elif request_line.startswith("CONNECT denied-tls.test"):
            writer.write(
                b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                b"X-Smokescreen-Error: denied\r\nContent-Length: 0\r\n\r\n"
            )
        elif parts.path == "/slow":
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n")
            await writer.drain()
            await asyncio.sleep(10)
        else:
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nSet-Cookie: track=1\r\n\r\nhello")
        await writer.drain()
    except (ConnectionError, IndexError):
        pass
    finally:
        writer.close()


@pytest.fixture(scope="module")
async def hostile() -> AsyncIterator[Hostile]:
    holder: dict[str, int] = {}
    server = await asyncio.start_server(lambda r, w: _handle(r, w, holder["port"]), "127.0.0.1", 0)
    holder["port"] = server.sockets[0].getsockname()[1]
    yield Hostile("127.0.0.1", holder["port"])
    server.close()


def _client(h: Hostile, **policy: Any) -> EgressClient:
    pol = EgressPolicy(test_only_allow_endpoints=frozenset({("127.0.0.1", h.port)}), **policy)
    return EgressClient(pol, fake_resolver({"hostile.test": ["127.0.0.1"]}))


async def test_hostile_server_reachable_when_explicitly_allowed(hostile: Hostile) -> None:
    async with _client(hostile) as c:
        res = await c.fetch(hostile.base + "/ok")
    assert res.status_code == 200 and res.body == b"hello"


@pytest.mark.parametrize(
    "to",
    [
        "http://127.0.0.1:18310/",  # bot2-36 指定:跳到本项目 Postgres
        "http://127.0.0.1/",
        "http://[::1]/",
        "http://169.254.169.254/latest/meta-data/",
        "http://localhost/",
        "http://2130706433/",
        "http://10.0.0.1/",
        "file:///etc/passwd",
    ],
)
async def test_redirect_to_internal_is_blocked(hostile: Hostile, to: str) -> None:
    async with _client(hostile) as c:
        with pytest.raises(PlatcapError) as exc:
            await c.fetch(f"{hostile.base}/redirect?to={to}")
    assert exc.value.code is ErrorCode.blocked_address, exc.value.message


async def test_redirect_to_hostname_resolving_internal_is_blocked(hostile: Hostile) -> None:
    pol = EgressPolicy(test_only_allow_endpoints=frozenset({("127.0.0.1", hostile.port)}))
    resolver = fake_resolver({"hostile.test": ["127.0.0.1"], "inner.test": ["10.1.2.3"]})
    async with EgressClient(pol, resolver) as c:
        with pytest.raises(PlatcapError) as exc:
            await c.fetch(f"{hostile.base}/redirect?to=http://inner.test/")
    assert exc.value.code is ErrorCode.blocked_address


async def test_redirect_limit(hostile: Hostile) -> None:
    async with _client(hostile, max_redirects=5) as c:
        with pytest.raises(PlatcapError) as exc:
            await c.fetch(hostile.base + "/loop")
    assert exc.value.code is ErrorCode.too_many_redirects


async def test_streamed_body_capped(hostile: Hostile) -> None:
    async with _client(hostile, max_bytes=5 * 1024 * 1024) as c:
        with pytest.raises(PlatcapError) as exc:
            await c.fetch(hostile.base + "/big-chunked")
    assert exc.value.code is ErrorCode.too_large


async def test_declared_oversize_rejected_without_reading(hostile: Hostile) -> None:
    async with _client(hostile) as c:
        with pytest.raises(PlatcapError) as exc:
            await c.fetch(hostile.base + "/big-declared")
    assert exc.value.code is ErrorCode.too_large


async def test_total_timeout(hostile: Hostile) -> None:
    async with _client(hostile, total_timeout_s=0.5) as c:
        with pytest.raises(PlatcapError) as exc:
            await c.fetch(hostile.base + "/slow")
    assert exc.value.code is ErrorCode.timeout


async def test_env_proxy_variables_ignored(hostile: Hostile, monkeypatch: pytest.MonkeyPatch) -> None:
    """环境里配了代理也不走(否则检查会被代理绕过);这里代理指向不存在的端口,走了就会失败。"""
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        monkeypatch.setenv(var, "http://127.0.0.1:9")
    monkeypatch.setenv("NO_PROXY", "*")
    async with _client(hostile) as c:
        res = await c.fetch(hostile.base + "/ok")
    assert res.status_code == 200


async def test_cookies_not_kept(hostile: Hostile) -> None:
    async with _client(hostile) as c:
        await c.fetch(hostile.base + "/ok")
        assert len(c._client.cookies.jar) == 0


async def test_caller_max_bytes_cannot_exceed_policy(hostile: Hostile) -> None:
    async with _client(hostile, max_bytes=3) as c:  # /ok 返回 5 字节
        with pytest.raises(PlatcapError) as exc:
            await c.fetch(hostile.base + "/ok", max_bytes=10**9)
    assert exc.value.code is ErrorCode.too_large


# ---------------------------------------------------------------- 代理模式(生产:经 smokescreen)


def _proxied(h: Hostile, table: dict[str, list[str]]) -> EgressClient:
    return EgressClient(EgressPolicy(), fake_resolver(table), proxy_url=f"http://127.0.0.1:{h.port}")


async def test_proxy_mode_leaves_destination_dns_to_proxy(hostile: Hostile) -> None:
    async def resolver(host: str, port: int) -> list[IPAddress]:
        raise AssertionError(f"代理模式意外解析了目标地址 {host}:{port}")

    async with EgressClient(EgressPolicy(), resolver, proxy_url=f"http://127.0.0.1:{hostile.port}") as c:
        res = await c.fetch("http://public.test/")
    assert res.status_code == 200 and res.body == b"ok"


async def test_proxy_mode_smokescreen_denial_is_blocked_address(hostile: Hostile) -> None:
    async with _proxied(hostile, {"denied.test": [PUBLIC_IP]}) as c:
        with pytest.raises(PlatcapError) as exc:
            await c.fetch("http://denied.test/")
    assert exc.value.code is ErrorCode.blocked_address and "Private Range" in exc.value.message


async def test_proxy_mode_redirect_to_internal_blocked_locally(hostile: Hostile) -> None:
    async with _proxied(hostile, {"public.test": [PUBLIC_IP]}) as c:
        with pytest.raises(PlatcapError) as exc:
            await c.fetch("http://public.test/redirect-internal")
    assert exc.value.code is ErrorCode.blocked_address


async def test_proxy_connect_407_is_blocked_but_502_is_upstream_error(hostile: Hostile) -> None:
    async with _proxied(hostile, {"denied-tls.test": [PUBLIC_IP], "upstream-fail.test": [PUBLIC_IP]}) as c:
        with pytest.raises(PlatcapError) as e1:
            await c.fetch("https://denied-tls.test/")
        with pytest.raises(PlatcapError) as e2:
            await c.fetch("https://upstream-fail.test/")
    assert e1.value.code is ErrorCode.blocked_address
    assert e2.value.code is ErrorCode.upstream_error


async def test_on_redirect_callback_can_stop_redirect(hostile: Hostile) -> None:
    seen: list[str] = []

    def stop(url: str) -> None:
        seen.append(url)
        raise PlatcapError(ErrorCode.upstream_blocked, "stop")

    async with _client(hostile) as c:
        with pytest.raises(PlatcapError) as exc:
            await c.fetch(f"{hostile.base}/redirect?to={hostile.base}/ok", on_redirect=stop)
    assert exc.value.code is ErrorCode.upstream_blocked and seen == [f"{hostile.base}/ok"]


def test_overlong_hostname_rejected() -> None:
    from capkit.egress import BlockedAddressError, validate_host

    with pytest.raises(BlockedAddressError):
        validate_host("a" * 250 + ".com")


async def test_is_blocked_destination_separates_denial_from_dns_failure() -> None:
    """浏览器只报「隧道失败」:自己解析一次,内网 → 被拒;解析不了(实测 DNS 超时)→ 不算被拒。"""
    table = {"inner.test": ["10.1.2.3"], "public.test": ["93.184.216.34"]}

    async def resolver(host: str, port: int) -> list[IPAddress]:
        if host not in table:
            raise PlatcapError(ErrorCode.upstream_error, "dns timeout")
        return [ipaddress.ip_address(x) for x in table[host]]

    async with EgressClient(EgressPolicy(), resolver) as client:
        assert await client.is_blocked_destination("https://inner.test/") is True
        assert await client.is_blocked_destination("https://127.0.0.1/") is True
        assert await client.is_blocked_destination("https://public.test/") is False
        assert await client.is_blocked_destination("https://unknown.test/") is False


async def test_explicit_larger_limit_allowed_only_up_to_ceiling(hostile: Hostile) -> None:
    async with _client(hostile, max_bytes=3, max_bytes_ceiling=10) as c:  # /ok 返回 5 字节
        assert (await c.fetch(hostile.base + "/ok", max_bytes=10**9)).body  # 显式要大:到 ceiling 为止
        with pytest.raises(PlatcapError) as exc:
            await c.fetch(hostile.base + "/ok")  # 不显式要:仍按默认 3 字节
    assert exc.value.code is ErrorCode.too_large


async def test_connection_pool_not_capped_at_httpx_default() -> None:
    """压测发现:httpx 显式建传输层时默认只给 100 个连接,外站慢时吞吐卡死(docs/09)。两种模式都用策略里的上限。"""
    pol = EgressPolicy(max_connections=1500)
    for proxy in (None, "http://127.0.0.1:4750"):
        async with EgressClient(pol, proxy_url=proxy) as c:
            pool = c._client._transport._pool  # type: ignore[attr-defined]
            assert pool._max_connections == 1500


async def test_full_pool_is_overloaded_not_a_target_timeout(hostile: Hostile) -> None:
    """复审:连接池满了要报 overloaded(平台忙,platform_side),不能等到总时限报「目标站超时」去触发熔断。"""
    async with _client(hostile, max_connections=1, total_timeout_s=10) as c:
        slow = asyncio.create_task(c.fetch(hostile.base + "/slow"))
        await asyncio.sleep(0.2)
        with pytest.raises(PlatcapError) as exc:
            await c.fetch(hostile.base + "/ok")
        slow.cancel()
    assert exc.value.code is ErrorCode.overloaded and exc.value.platform_side


async def test_connect_timeout_is_retried_once(monkeypatch: pytest.MonkeyPatch) -> None:
    """建连阶段超时(请求还没发出)再试一次:CDN 的某个节点不回握手时,换个连接多半就好(实测彭博)。"""
    from capkit import egress as egress_mod

    async with EgressClient(EgressPolicy(), fake_resolver({"cdn.test": ["93.184.216.34"]})) as client:
        calls = {"n": 0}

        async def flaky_send(request: httpx2.Request, **_: object) -> httpx2.Response:
            calls["n"] += 1
            if calls["n"] == 1:
                raise httpx2.ConnectTimeout("handshake timed out", request=request)
            return httpx2.Response(200, content=b"ok", request=request)

        monkeypatch.setattr(client._client, "send", flaky_send)
        result = await client.fetch("https://cdn.test/sitemap.xml")
        assert result.status_code == 200 and result.body == b"ok" and calls["n"] == 2

        calls["n"] = -10  # 一直超时:重试一次后照常报 timeout,不无限重试

        async def always_timeout(request: httpx2.Request, **_: object) -> httpx2.Response:
            calls["n"] += 1
            raise httpx2.ConnectTimeout("handshake timed out", request=request)

        monkeypatch.setattr(client._client, "send", always_timeout)
        with pytest.raises(PlatcapError) as exc:
            await client.fetch("https://cdn.test/sitemap.xml")
        assert exc.value.code is ErrorCode.timeout and calls["n"] == -10 + 1 + egress_mod.CONNECT_RETRIES
