# Smokescreen 通过统一上网代理访问 Internet

本文说明如何在 Docker Compose 部署中，为 Smokescreen 增加透明出网网关，使其实际出口统一经过 HTTP CONNECT 或 SOCKS5 代理，同时保留 Smokescreen 的 SSRF、目标端口和公网地址检查。

## 1. 前提与目标

以下示例假设：

- 部署环境：Linux Docker Engine。
- 统一代理地址：`10.20.30.40:3128`。
- 统一代理类型：HTTP CONNECT。
- 首先只调整网页爬取链路，暂不调整 `smokescreen-repo`。

最终链路如下：

```text
web / Chromium
    → Smokescreen
    → iptables 透明重定向
    → redsocks
    → 10.20.30.40:3128
    → Internet
```

Smokescreen 继续负责：

- 拒绝内网、本机、链路本地和云元数据地址。
- 只允许目标端口 `80` 和 `443`。
- 解析并检查目标域名对应的 IP 地址。
- 为普通 HTTP 抓取和浏览器抓取提供统一安全边界。

透明网关负责将 Smokescreen 原本准备直接发往目标网站的 TCP 连接转交给统一代理。

## 2. 创建 redsocks 配置

在项目目录中创建：

```text
deploy/secrets/redsocks.conf
```

HTTP CONNECT 代理配置示例：

```conf
base {
    log_debug = off;
    log_info = on;
    log = "stderr";
    daemon = off;
    redirector = iptables;
}

redsocks {
    local_ip = 127.0.0.1;
    local_port = 12345;

    ip = 10.20.30.40;
    port = 3128;

    type = http-connect;

    login = "proxy-user";
    password = "proxy-password";
}
```

如果代理不需要认证，删除：

```conf
login = "proxy-user";
password = "proxy-password";
```

如果统一代理为 SOCKS5，将代理类型改为：

```conf
type = socks5;
```

经典 redsocks 通常要求 `ip` 是 IP 地址，建议不要直接填写域名。如果代理只有域名，应在部署时将其解析为可信、稳定的 IP 地址。

保护配置文件：

```bash
chmod 600 deploy/secrets/redsocks.conf
```

应把该文件加入 `.gitignore`，不要把代理密码提交到代码仓库。非 Swarm 模式下的 Docker Compose Secret 本质上仍是宿主机文件挂载，因此仍需保护宿主机文件权限。

## 3. 创建透明网关启动脚本

创建：

```text
deploy/egress-gateway.sh
```

内容如下：

```sh
#!/bin/sh
set -eu

SMOKESCREEN_UID="${SMOKESCREEN_UID:-65534}"
REDSOCKS_PORT="${REDSOCKS_PORT:-12345}"
DNS_SERVER="${DNS_SERVER:-223.5.5.5}"

# 只拦截 Smokescreen 发出的 80/443 TCP 连接。
iptables -t nat -N PLATCAP_UPSTREAM 2>/dev/null || true
iptables -t nat -F PLATCAP_UPSTREAM

iptables -t nat -C OUTPUT \
    -m owner --uid-owner "${SMOKESCREEN_UID}" \
    -p tcp \
    -m multiport --dports 80,443 \
    -j PLATCAP_UPSTREAM 2>/dev/null ||
iptables -t nat -A OUTPUT \
    -m owner --uid-owner "${SMOKESCREEN_UID}" \
    -p tcp \
    -m multiport --dports 80,443 \
    -j PLATCAP_UPSTREAM

iptables -t nat -A PLATCAP_UPSTREAM \
    -p tcp \
    -j REDIRECT --to-ports "${REDSOCKS_PORT}"

# Fail closed：Smokescreen 只允许连接本地 redsocks 和指定 DNS。
iptables -N PLATCAP_SMOKESCREEN_OUT 2>/dev/null || true
iptables -F PLATCAP_SMOKESCREEN_OUT

iptables -C OUTPUT \
    -m owner --uid-owner "${SMOKESCREEN_UID}" \
    -j PLATCAP_SMOKESCREEN_OUT 2>/dev/null ||
iptables -A OUTPUT \
    -m owner --uid-owner "${SMOKESCREEN_UID}" \
    -j PLATCAP_SMOKESCREEN_OUT

iptables -A PLATCAP_SMOKESCREEN_OUT \
    -p tcp \
    -d 127.0.0.1 \
    --dport "${REDSOCKS_PORT}" \
    -j ACCEPT

iptables -A PLATCAP_SMOKESCREEN_OUT \
    -p udp \
    -d "${DNS_SERVER}" \
    --dport 53 \
    -j ACCEPT

iptables -A PLATCAP_SMOKESCREEN_OUT \
    -p tcp \
    -d "${DNS_SERVER}" \
    --dport 53 \
    -j ACCEPT

iptables -A PLATCAP_SMOKESCREEN_OUT -j REJECT

exec redsocks -c /run/secrets/redsocks.conf
```

赋予执行权限：

```bash
chmod 755 deploy/egress-gateway.sh
```

脚本利用 Smokescreen 镜像里的 `USER nobody`，其 UID 通常是 `65534`。部署前应按照后续步骤确认实际 UID。

只匹配 Smokescreen 的 UID，可以避免 redsocks 连接统一代理时再次被透明重定向而形成死循环。

## 4. 创建透明网关镜像

创建：

```text
deploy/egress-gateway.Dockerfile
```

内容如下：

```dockerfile
FROM alpine:3.22

RUN apk add --no-cache \
    iptables \
    redsocks

COPY deploy/egress-gateway.sh /usr/local/bin/egress-gateway

RUN chmod 0755 /usr/local/bin/egress-gateway

ENTRYPOINT ["/usr/local/bin/egress-gateway"]
```

正式生产环境建议把基础镜像改成固定 digest，与项目现有镜像管理方式保持一致。

## 5. 修改 Docker Compose

编辑 `deploy/compose.yaml`。

### 5.1 增加 egress-gateway 服务

在现有 `smokescreen` 服务前增加：

```yaml
  egress-gateway:
    <<: *hardened
    build:
      context: ..
      dockerfile: deploy/egress-gateway.Dockerfile

    cap_add:
      - NET_ADMIN

    environment:
      SMOKESCREEN_UID: "65534"
      REDSOCKS_PORT: "12345"
      DNS_SERVER: "223.5.5.5"

    secrets:
      - source: upstream_redsocks_conf
        target: redsocks.conf

    networks:
      egress_c:
        ipv4_address: 172.31.250.10
      egress_l:
        ipv4_address: 172.31.252.10
      outside: {}
      default: {}

    ports:
      - "127.0.0.1:18320:4750"

    read_only: true
    tmpfs:
      - /run:size=8m,nosuid,nodev

    healthcheck:
      test: ["CMD-SHELL", "nc -z 127.0.0.1 12345"]
      interval: 3s
      timeout: 2s
      retries: 20
```

该服务接管原先属于 `smokescreen` 的：

- Docker 网络。
- 固定 IP。
- 宿主机端口映射。
- 实际公网出口。
- 网络管理能力 `NET_ADMIN`。

不要把 `NET_ADMIN` 直接授予 Smokescreen。

### 5.2 修改现有 smokescreen 服务

原配置类似：

```yaml
  smokescreen:
    <<: *hardened
    build:
      context: ..
      dockerfile: deploy/smokescreen.Dockerfile
    environment:
      PLATCAP_EGRESS_ALLOWED_PORTS: "80,443"
    command: *smokescreen_args
    networks:
      egress_c:
        ipv4_address: 172.31.250.10
      egress_l:
        ipv4_address: 172.31.252.10
      outside: {}
      default: {}
    ports:
      - "127.0.0.1:18320:4750"
```

将其调整为：

```yaml
  smokescreen:
    <<: *hardened
    build:
      context: ..
      dockerfile: deploy/smokescreen.Dockerfile

    environment:
      PLATCAP_EGRESS_ALLOWED_PORTS: "80,443"

    command: *smokescreen_args

    network_mode: "service:egress-gateway"

    depends_on:
      egress-gateway:
        condition: service_healthy
```

使用 `network_mode: service:egress-gateway` 后，`smokescreen` 下不能再保留 `networks` 和 `ports`，这些配置已经由 `egress-gateway` 持有。

现有以下配置保持不变：

```yaml
PLATCAP_EGRESS_PROXY_URL: http://172.31.250.10:4750
```

以及 Chromium 的：

```yaml
PROXY_URL: http://172.31.250.10:4750
```

`egress-gateway` 接管了原来的固定 IP，而 Smokescreen 在同一个网络命名空间中监听 `4750`，因此 `web` 和 Chromium 不需要改变代理地址。

### 5.3 增加顶层 Secret

在 `deploy/compose.yaml` 中增加与 `services`、`networks`、`volumes` 同级的配置：

```yaml
secrets:
  upstream_redsocks_conf:
    file: ./secrets/redsocks.conf
```

整体结构类似：

```yaml
services:
  egress-gateway:
    # ...

  smokescreen:
    # ...

networks:
  # ...

volumes:
  # ...

secrets:
  upstream_redsocks_conf:
    file: ./secrets/redsocks.conf
```

## 6. 校验配置

先解析 Compose 配置：

```bash
docker compose -f deploy/compose.yaml config
```

如果没有报错，再确认 Smokescreen 的实际 UID：

```bash
docker compose -f deploy/compose.yaml run --rm \
  --entrypoint id \
  smokescreen
```

预期类似：

```text
uid=65534(nobody)
```

如果不是 `65534`，将网关服务中的配置改成实际 UID：

```yaml
SMOKESCREEN_UID: "实际UID"
```

## 7. 构建并启动

构建新镜像：

```bash
docker compose -f deploy/compose.yaml build \
  egress-gateway smokescreen
```

重建相关容器：

```bash
docker compose -f deploy/compose.yaml up -d \
  --force-recreate \
  egress-gateway smokescreen chromium web
```

查看状态：

```bash
docker compose -f deploy/compose.yaml ps
```

查看日志：

```bash
docker compose -f deploy/compose.yaml logs \
  --tail=200 \
  egress-gateway smokescreen
```

由于 Smokescreen 共享 `egress-gateway` 的网络命名空间，每次重建透明网关后，都建议同时强制重建 `smokescreen`。

## 8. 验证透明转发规则

查看 NAT 规则：

```bash
docker compose -f deploy/compose.yaml exec \
  egress-gateway \
  iptables -t nat -S
```

应当能看到包含以下内容的规则：

```text
PLATCAP_UPSTREAM
--uid-owner 65534
--dports 80,443
--to-ports 12345
```

查看规则计数：

```bash
docker compose -f deploy/compose.yaml exec \
  egress-gateway \
  iptables -t nat -L PLATCAP_UPSTREAM -n -v
```

通过 Smokescreen 访问网页后，数据包和字节计数应增加。

## 9. 验证实际公网出口

查询公网 IP：

```bash
curl -sS \
  -x http://127.0.0.1:18320 \
  https://api.ipify.org
```

返回值应当是统一代理的公网出口 IP。

测试普通 HTTPS 网站：

```bash
curl -I \
  -x http://127.0.0.1:18320 \
  https://example.com
```

还应检查统一代理侧的访问日志，确认连接确实经过统一代理。

## 10. 验证 SSRF 防护

尝试访问本机地址：

```bash
curl -v \
  -x http://127.0.0.1:18320 \
  http://127.0.0.1
```

尝试访问云元数据地址：

```bash
curl -v \
  -x http://127.0.0.1:18320 \
  http://169.254.169.254
```

两项都应在 Smokescreen 层被拒绝，不能进入 redsocks，更不能到达统一代理或目标地址。

## 11. 验证禁止回退直连

将 `redsocks.conf` 中的代理端口临时改成不存在的端口，然后重建网关和 Smokescreen：

```bash
docker compose -f deploy/compose.yaml up -d \
  --build \
  --force-recreate \
  egress-gateway smokescreen
```

此时网页请求必须失败，不能绕过统一代理直接访问 Internet。

测试完成后恢复正确的代理配置并再次重建相关服务。

## 12. DNS 配置

当前 Smokescreen 使用类似以下参数：

```yaml
--resolver-address=${PLATCAP_DEV_DNS:-223.5.5.5:53}
```

Smokescreen 必须先解析目标域名，才能判断解析结果是否属于内网或保留地址。因此，即使网页 TCP 流量全部经过统一代理，Smokescreen 仍需要独立的 DNS 通道。

如果公司要求使用内部 DNS，应同时修改：

```yaml
PLATCAP_DEV_DNS: 公司DNS地址:53
```

以及网关服务中的：

```yaml
DNS_SERVER: "公司DNS地址"
```

不能使用返回 `198.18.x.x` 的 fake-ip DNS，否则 Smokescreen 会把结果识别为保留地址并拒绝访问。

如果公司要求包括 DNS 在内的全部流量都不得直接访问公网，应在网关里运行受控 DNS 转发器，或者允许 Smokescreen 只访问公司内部 DNS。

## 13. HTTP CONNECT 的限制

透明方案对 HTTPS 最可靠：

```text
Smokescreen 连接目标 IP:443
→ iptables 重定向到 redsocks
→ redsocks 向统一代理发送 CONNECT 目标 IP:443
→ TLS 流量在隧道中传输
```

需要确认统一代理满足以下要求：

- 允许 `CONNECT 目标IP:443`。
- 如果需要访问 HTTP 网站，允许 `CONNECT 目标IP:80`。
- 如果启用了认证，认证方式受 redsocks 支持。

以下情况可能无法直接使用经典 redsocks：

- 统一代理只接受目标域名，不接受目标 IP。
- 使用 NTLM、Kerberos 或 PAC 自动代理脚本。
- 上游代理本身要求 HTTPS/TLS 连接。
- 上游代理不允许通过 CONNECT 访问端口 80。

这类场景可能需要使用 `cntlm`、`sing-box`、`gost` 等中间组件，或者为 Smokescreen 实现原生上游代理支持。

## 14. smokescreen-repo

项目中的 `smokescreen-repo` 也监听端口 `4750`，因此不能与普通 Smokescreen 共用一个网络命名空间，否则会发生端口冲突。

如果读代码服务也要使用统一代理，建议使用独立链路：

```text
repo
  → smokescreen-repo
  → repo-egress-gateway
  → 统一代理
```

`repo-egress-gateway` 可以复用相同的镜像和上游代理配置，但应使用独立网络命名空间，并继续保留 `smokescreen-repo` 的托管站域名白名单。

## 15. 上线检查清单

- [ ] `docker compose config` 校验通过。
- [ ] Smokescreen UID 与 `SMOKESCREEN_UID` 一致。
- [ ] redsocks 监听 `127.0.0.1:12345`。
- [ ] Smokescreen 仍监听 `4750`。
- [ ] `web` 和 Chromium 的代理地址保持不变。
- [ ] iptables 只拦截 Smokescreen 的 UID。
- [ ] redsocks 自身流量没有形成重定向死循环。
- [ ] 公网出口 IP 与统一代理出口一致。
- [ ] 统一代理日志能看到对应连接。
- [ ] `127.0.0.1` 和 `169.254.169.254` 仍被 Smokescreen 拒绝。
- [ ] 上游代理不可用时请求失败，不能回退直连。
- [ ] DNS 使用真实 DNS，不返回 fake-ip。
- [ ] 代理密码没有提交到代码仓库。

