# 双节点 Smokescreen 使用 HTTP 上游代理

## 1. 方案说明

本文只说明一种部署方式：node1、node2 各自运行本机 Smokescreen，并分别通过本机透明出口网关连接同一个无需认证的 HTTP 上游代理。

```text
node1: web / Chromium -> Smokescreen-1 -> egress-gateway-1 -> HTTP 上游代理 -> Internet
node2: web / Chromium -> Smokescreen-2 -> egress-gateway-2 -> HTTP 上游代理 -> Internet
```

固定原则：

- web 和 Chromium 仍然只连接本机 Smokescreen；
- node1 不向 node2 提供 Smokescreen，node2 也不访问 node1 的 `4750`；
- 两个节点使用完全相同的透明转发配置；
- 上游代理不需要用户名和密码；
- 不修改 PlatCap、Smokescreen、web 或 Chromium 的代码；
- 只增加 Docker Compose 部署层的 `egress-gateway`、配置文件和启动脚本；
- Smokescreen 仍负责目标端口限制、私网地址拒绝和 SSRF 防护；
- 只有 Smokescreen 发出的目标端口为 `80`、`443` 的 TCP 连接会被透明转发到上游代理。

> Docker Compose 的 `networks` 没有 HTTP 上游代理配置项，当前 Smokescreen 也没有上游代理参数。因此不能只设置 `HTTP_PROXY` 或 `HTTPS_PROXY`。这里使用透明出口网关接管 Smokescreen 的出口连接。

## 2. 部署前准备

假设上游代理为：

```text
10.20.30.40:3128
```

部署前在 node1、node2 分别验证：

```bash
curl -I -x http://10.20.30.40:3128 https://example.com
curl -I -x http://10.20.30.40:3128 http://example.com
```

两条命令都应成功。第二条失败通常表示上游代理不允许访问 HTTP 80 端口，需要先调整上游代理策略。

如果上游代理填写的是域名，建议先解析为固定内网 IP。透明转发配置应使用 IP，避免网关启动时受 DNS 状态影响。

## 3. 创建无需认证的 redsocks 配置

在两个节点的项目目录中创建：

```text
deploy/secrets/redsocks.conf
```

内容如下，只需要替换 `ip` 和 `port`：

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
}
```

本方案没有 `login` 和 `password`。

限制文件权限：

```bash
chmod 600 deploy/secrets/redsocks.conf
```

建议将实际配置加入 `.gitignore`，只在仓库中保留不含真实地址的示例文件。

## 4. 创建透明出口网关脚本

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

# 只接管 Smokescreen 发出的 HTTP/HTTPS TCP 连接。
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

# Fail closed：Smokescreen 只能响应已有连接、访问本机 redsocks 和查询指定 DNS。
iptables -N PLATCAP_SMOKESCREEN_OUT 2>/dev/null || true
iptables -F PLATCAP_SMOKESCREEN_OUT

iptables -C OUTPUT \
    -m owner --uid-owner "${SMOKESCREEN_UID}" \
    -j PLATCAP_SMOKESCREEN_OUT 2>/dev/null ||
iptables -A OUTPUT \
    -m owner --uid-owner "${SMOKESCREEN_UID}" \
    -j PLATCAP_SMOKESCREEN_OUT

iptables -A PLATCAP_SMOKESCREEN_OUT \
    -m conntrack --ctstate ESTABLISHED,RELATED \
    -j ACCEPT

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

增加执行权限：

```bash
chmod 755 deploy/egress-gateway.sh
```

这里按当前 Smokescreen 镜像的 `nobody` 用户使用 UID `65534`。网关只拦截该 UID 的连接，因此 redsocks 连接上游代理时不会再次被重定向，也不会形成循环。

Smokescreen 必须自行解析目标域名后才能检查目标 IP 是否属于私网或保留地址，所以 DNS 查询不能通过普通 HTTP 代理转发。上面的规则仅允许它访问指定 DNS；生产环境有可信内网 DNS 时，应把 `PLATCAP_DNS_SERVER` 设置为不带端口的 DNS IP，同时把现有 `PLATCAP_DEV_DNS` 设置为 `同一IP:53`。

## 5. 创建出口网关镜像

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

以上属于部署镜像，不修改任何业务代码或 Smokescreen 代码。

## 6. 修改两个节点的 Compose

node1 修改当前实际使用的 `deploy/compose.yaml`，或者部署时使用的 `deploy/compose.two-node.node1.yaml`。

node2 修改 `deploy/compose.two-node.node2.yaml`。

两个节点都执行相同修改。

### 6.1 增加 egress-gateway

在 `services` 下增加：

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
      DNS_SERVER: ${PLATCAP_DNS_SERVER:-223.5.5.5}

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

`egress-gateway` 接管原来属于 Smokescreen 的以下内容：

- `egress_c`、`egress_l`、`outside` 和 `default` 网络；
- 固定地址 `172.31.250.10`、`172.31.252.10`；
- 宿主机调试端口 `127.0.0.1:18320`。

不要给 Smokescreen 增加 `NET_ADMIN`。

### 6.2 修改现有 smokescreen

将现有 `smokescreen` 服务改为：

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

必须从 `smokescreen` 服务中删除原有的：

```yaml
networks:
ports:
```

`network_mode: "service:egress-gateway"` 使 Smokescreen 与出口网关共享网络命名空间。Smokescreen 仍监听 `4750`，原有 web、Chromium 地址不需要改变。

### 6.3 web 和 Chromium 保持不变

每台机器的 web 继续使用本机 Smokescreen：

```yaml
environment:
  PLATCAP_EGRESS_PROXY_URL: http://172.31.250.10:4750
```

每台机器的 Chromium 继续使用本机 Smokescreen：

```yaml
environment:
  PROXY_URL: http://172.31.250.10:4750
```

不要把这两个值改成上游代理地址，否则 web/Chromium 会绕过 Smokescreen。

node2 即使连接 node1 的 PostgreSQL、Valkey 和 MinIO，网页出网仍使用 node2 自己的 `172.31.250.10:4750`。两台机器可以使用相同的 Docker 子网和容器 IP，因为它们属于不同的 Docker Engine。

### 6.4 增加顶层 secret

在 Compose 文件中增加与 `services`、`networks`、`volumes` 同级的配置：

```yaml
secrets:
  upstream_redsocks_conf:
    file: ./secrets/redsocks.conf
```

目录结构应为：

```text
deploy/
├── compose.yaml
├── compose.two-node.node1.yaml
├── compose.two-node.node2.yaml
├── egress-gateway.Dockerfile
├── egress-gateway.sh
└── secrets/
    └── redsocks.conf
```

实际只需要保留正在使用的 Compose 文件。

## 7. 可选 repo 服务

如果没有启用 `repo` profile，本节不需要配置。

`smokescreen-repo` 也没有上游代理参数。如果启用 repo，并要求其流量也通过上游代理，不能让它与网页 Smokescreen 共用同一个 `egress-gateway`，因为两个 Smokescreen 都监听 `4750`，共享网络命名空间会端口冲突。

应复制一套独立服务：

```text
repo -> smokescreen-repo -> egress-gateway-repo -> HTTP 上游代理
```

`egress-gateway-repo` 只连接 `egress_r`、`outside` 网络，接管原来的 `172.31.253.10`；`smokescreen-repo` 使用：

```yaml
network_mode: "service:egress-gateway-repo"
```

repo 中的地址仍然保持：

```yaml
PLATCAP_EGRESS_PROXY_URL: http://172.31.253.10:4750
```

网页 Smokescreen 和 repo Smokescreen 可以复用同一个 `redsocks.conf`，但不能复用同一个网络命名空间。

## 8. 校验 Compose

node1 当前使用 `deploy/compose.yaml` 时：

```bash
docker compose -f deploy/compose.yaml config --quiet
```

如果 node1 已切换到专用文件：

```bash
docker compose \
  --env-file deploy/env/node1.env \
  -f deploy/compose.two-node.node1.yaml \
  config --quiet
```

node2：

```bash
docker compose \
  --env-file deploy/env/node2.env \
  -f deploy/compose.two-node.node2.yaml \
  config --quiet
```

确认 Smokescreen UID。node1 示例：

```bash
docker compose -f deploy/compose.yaml run --rm \
  --entrypoint id \
  smokescreen
```

预期包含：

```text
uid=65534(nobody)
```

如果实际 UID 不是 `65534`，将 `egress-gateway.environment.SMOKESCREEN_UID` 改为实际值。

## 9. 构建与启动

### 9.1 node1

当前使用 `deploy/compose.yaml` 时：

```bash
docker compose -f deploy/compose.yaml build \
  egress-gateway smokescreen

docker compose -f deploy/compose.yaml up -d \
  --force-recreate \
  egress-gateway smokescreen chromium web gateway
```

如果使用 `deploy/compose.two-node.node1.yaml`，替换命令中的 Compose 文件，并增加对应的 `--env-file`。

### 9.2 node2

```bash
docker compose \
  --env-file deploy/env/node2.env \
  -f deploy/compose.two-node.node2.yaml \
  build egress-gateway smokescreen

docker compose \
  --env-file deploy/env/node2.env \
  -f deploy/compose.two-node.node2.yaml \
  up -d --force-recreate \
  egress-gateway smokescreen chromium web gateway
```

如果镜像由 node1 构建后通过 `docker save/load` 分发到 node2，应在 Compose 中给 `egress-gateway` 和 `smokescreen`设置固定 `image:` 名称；node2 加载镜像后执行 `up -d`，不执行 `build`。

不要在 node2 执行当前的 `make up`，因为当前 Makefile 固定使用单机 `deploy/compose.yaml`。

## 10. 验证

以下命令先以 node1 的 `deploy/compose.yaml` 为例。node2 使用相同方法，只需替换 Compose 参数。

### 10.1 查看状态和日志

```bash
docker compose -f deploy/compose.yaml ps

docker compose -f deploy/compose.yaml logs \
  --tail=200 \
  egress-gateway smokescreen chromium web
```

`egress-gateway` 和 `smokescreen` 应保持运行，日志中不应反复出现连接上游代理失败。

### 10.2 通过本机 Smokescreen 测试公网

```bash
curl -I \
  -x http://127.0.0.1:18320 \
  https://example.com

curl -sS \
  -x http://127.0.0.1:18320 \
  https://api.ipify.org
```

请求应成功，查询到的出口 IP 应符合上游代理的出口策略。

### 10.3 验证 Smokescreen 仍然生效

```bash
curl -v \
  -x http://127.0.0.1:18320 \
  http://127.0.0.1

curl -v \
  -x http://127.0.0.1:18320 \
  http://169.254.169.254
```

两个请求都必须由 Smokescreen 拒绝，不能到达上游代理。

### 10.4 查看透明转发计数

```bash
docker compose -f deploy/compose.yaml exec \
  egress-gateway \
  iptables -t nat -L PLATCAP_UPSTREAM -n -v
```

执行网页抓取或前面的 `curl` 后，数据包和字节计数应增加。

### 10.5 验证上游代理不可用时禁止直连

临时在网络侧阻断上游代理，或在维护窗口停止上游代理后，再执行：

```bash
curl -I --max-time 15 \
  -x http://127.0.0.1:18320 \
  https://example.com
```

请求必须失败，不能自动绕过上游代理直接访问 Internet。验证后恢复上游代理。

## 11. 常用运维命令

仅重新加载出口链路：

```bash
docker compose -f deploy/compose.yaml up -d \
  --force-recreate \
  egress-gateway smokescreen
```

修改 `redsocks.conf` 后，建议同时重建 `egress-gateway` 和 `smokescreen`，确保重新读取配置并重新建立共享网络命名空间和转发规则：

```bash
docker compose -f deploy/compose.yaml up -d \
  --force-recreate \
  egress-gateway smokescreen chromium web
```

查看出口日志：

```bash
docker compose -f deploy/compose.yaml logs -f \
  egress-gateway smokescreen
```

不要执行：

```bash
docker compose down -v
```

`-v` 会删除 PostgreSQL、MinIO/Silo、web 存储等命名卷数据。

## 12. 最终检查清单

- node1、node2 都存在自己的 `egress-gateway` 和 `smokescreen`；
- 两台机器的 `redsocks.conf` 都指向正确的无需认证 HTTP 上游代理；
- web 的 `PLATCAP_EGRESS_PROXY_URL` 仍指向本机 `172.31.250.10:4750`；
- Chromium 的 `PROXY_URL` 仍指向本机 `172.31.250.10:4750`；
- Smokescreen 使用 `network_mode: "service:egress-gateway"`；
- Smokescreen 自身不再配置 `networks` 和 `ports`；
- `egress-gateway` 持有原 Smokescreen 的网络、固定 IP 和调试端口；
- 上游代理不可用时，网页抓取失败而不是回退直连；
- `127.0.0.1`、`169.254.169.254` 等地址仍被 Smokescreen 拒绝；
- node2 使用专用 Compose 文件启动，没有执行当前单机版 `make up`。
