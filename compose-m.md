# 基于现有 Compose 的双节点修改说明

本文以 [`deploy/compose.yaml`](../../deploy/compose.yaml) 为基础，说明 node1 和 node2 分别需要修改的内容。

建议复制成两个文件，不直接覆盖原文件：

```text
deploy/compose.node1.yaml
deploy/compose.node2.yaml
```

两台主机可以继续使用 `name: platcap`，因为两台机器上的 Docker 资源彼此独立。

## 1. 服务分配

| 服务 | node1 | node2 |
|---|---:|---:|
| PostgreSQL | 保留 | 删除 |
| Valkey | 保留 | 删除 |
| MinIO | 新增 | 不运行 |
| gateway | 保留 | 保留 |
| web | 保留 | 保留 |
| Chromium | 保留 | 保留 |
| Smokescreen | 保留 | 保留 |
| HAProxy | 新增 | 不运行 |
| repo/Smokescreen-repo | 可选 | 可选 |
| test/bench/canary | 不部署 | 不部署 |

## 2. node1 修改

### 2.1 PostgreSQL、Valkey 开放到内网

只修改端口绑定，不修改 PostgreSQL 密码、Valkey 配置和原有数据卷：

```yaml
postgres:
  ports:
    - "10.0.1.11:18310:5432"

valkey:
  ports:
    - "10.0.1.11:18311:6379"
```

PostgreSQL 以下配置保持不变：

```yaml
environment:
  POSTGRES_USER: platcap
  POSTGRES_PASSWORD: platcap
  POSTGRES_DB: platcap
volumes:
  - pgdata:/var/lib/postgresql/data
```

node1 gateway 继续使用容器内部地址：

```yaml
environment:
  PLATCAP_DATABASE_URL: postgresql://platcap:platcap@postgres:5432/platcap
  PLATCAP_VALKEY_URL: redis://172.31.251.5:6379/0
```

### 2.2 新增 MinIO

在 `services` 下增加：

```yaml
minio:
  image: <固定版本的MinIO镜像>
  restart: unless-stopped
  command: server /data --console-address ":9001"
  environment:
    MINIO_ROOT_USER: ${MINIO_ROOT_USER}
    MINIO_ROOT_PASSWORD: ${MINIO_ROOT_PASSWORD}
  volumes:
    - miniodata:/data
  ports:
    - "10.0.1.11:19000:9000"
    - "127.0.0.1:19001:9001"
  networks:
    backend: {}
```

在顶层 `volumes` 下增加：

```yaml
volumes:
  miniodata:
```

MinIO 中创建两个 bucket：

```text
platcap-snapshots
platcap-files
```

同时创建 web 使用的 AccessKey 和 SecretKey。

### 2.3 修改 node1 web

删除本地存储环境变量：

```yaml
PLATCAP_STORAGE_DIR: /data/store
PLATCAP_STORAGE_DIR_MODE: single
```

删除 web 的本地 store 挂载：

```yaml
volumes:
  - store:/data/store
```

增加 MinIO 配置：

```yaml
environment:
  PLATCAP_SNAPSHOT_S3_ENDPOINT: http://minio:9000
  PLATCAP_SNAPSHOT_S3_REGION: us-east-1
  PLATCAP_SNAPSHOT_S3_BUCKET: platcap-snapshots
  PLATCAP_WEB_FILE_S3_BUCKET: platcap-files
  PLATCAP_SNAPSHOT_S3_ACCESS_KEY: ${MINIO_WEB_ACCESS_KEY}
  PLATCAP_SNAPSHOT_S3_SECRET_KEY: ${MINIO_WEB_SECRET_KEY}
```

增加 MinIO 启动依赖：

```yaml
depends_on:
  minio:
    condition: service_started
```

原有 Valkey、Chromium 和 Smokescreen 地址保持不变。

### 2.4 修改 node1 gateway

如果 HAProxy 部署在 node1，删除 gateway 当前的宿主机端口映射：

```yaml
ports:
  - "127.0.0.1:18300:18300"
```

HAProxy 通过 Compose 网络直接访问：

```text
gateway:18300
```

下载地址改成统一入口：

```yaml
environment:
  PLATCAP_PUBLIC_BASE_URL: http://10.0.1.11:18300
```

### 2.5 新增 HAProxy

HAProxy 对外占用 node1 的 `18300` 端口：

```yaml
haproxy:
  image: <固定版本的HAProxy镜像>
  restart: unless-stopped
  ports:
    - "10.0.1.11:18300:18300"
  volumes:
    - ./haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro
  networks:
    default: {}
  depends_on:
    gateway:
      condition: service_healthy
```

`haproxy.cfg` 配置两个 gateway 后端：

```haproxy
frontend platcap
    bind *:18300
    default_backend gateways

backend gateways
    balance roundrobin
    option httpchk GET /healthz
    server node1 gateway:18300 check
    server node2 10.0.1.12:18300 check
```

## 3. node2 修改

### 3.1 删除状态服务

从 node2 Compose 删除以下服务：

```yaml
postgres:
valkey:
```

从顶层 `volumes` 删除：

```yaml
volumes:
  pgdata:
  store:
```

node2 不创建 PostgreSQL、Valkey 和本地 store。

### 3.2 修改 node2 web

Valkey 改为访问 node1：

```yaml
environment:
  PLATCAP_VALKEY_URL: redis://10.0.1.11:18311/0
```

MinIO 改为访问 node1 的宿主机端口：

```yaml
environment:
  PLATCAP_SNAPSHOT_S3_ENDPOINT: http://10.0.1.11:19000
  PLATCAP_SNAPSHOT_S3_REGION: us-east-1
  PLATCAP_SNAPSHOT_S3_BUCKET: platcap-snapshots
  PLATCAP_WEB_FILE_S3_BUCKET: platcap-files
  PLATCAP_SNAPSHOT_S3_ACCESS_KEY: ${MINIO_WEB_ACCESS_KEY}
  PLATCAP_SNAPSHOT_S3_SECRET_KEY: ${MINIO_WEB_SECRET_KEY}
```

删除：

```yaml
PLATCAP_STORAGE_DIR: /data/store
PLATCAP_STORAGE_DIR_MODE: single
```

以及：

```yaml
volumes:
  - store:/data/store
```

原有 Chromium 和 Smokescreen 地址保持为 node2 本机容器地址：

```yaml
environment:
  PLATCAP_EGRESS_PROXY_URL: http://172.31.250.10:4750
  PLATCAP_CHROMIUM_CDP_URL: http://172.31.250.20:9222
```

当前 web 只连接了 `internal: true` 的网络，无法访问 node1，因此 node2 web 必须增加 `default` 网络：

```yaml
networks:
  default: {}
  backend:
    ipv4_address: 172.31.251.30
  egress_c:
    ipv4_address: 172.31.250.30
  egress_l:
    ipv4_address: 172.31.252.30
  tunnels:
    ipv4_address: 172.31.255.30
```

删除 web 对本地 Valkey 的依赖：

```yaml
depends_on:
  smokescreen:
    condition: service_started
  chromium:
    condition: service_started
```

### 3.3 修改 node2 gateway

数据库和 Valkey 改为访问 node1：

```yaml
environment:
  PLATCAP_DATABASE_URL: postgresql://platcap:platcap@10.0.1.11:18310/platcap
  PLATCAP_VALKEY_URL: redis://10.0.1.11:18311/0
  PLATCAP_PUBLIC_BASE_URL: http://10.0.1.11:18300
```

web 仍然调用 node2 本机实例，无需修改：

```yaml
environment:
  PLATCAP_WEB_URL: http://172.31.251.30:18301
```

删除 gateway 对 node2 本地 PostgreSQL 和 Valkey 的依赖：

```yaml
depends_on:
  web:
    condition: service_healthy
  repo:
    condition: service_healthy
    required: false
```

将 gateway 发布到 node2 内网 IP，供 node1 HAProxy 访问：

```yaml
ports:
  - "10.0.1.12:18300:18300"
```

### 3.4 node2 repo（可选）

repo 改为使用 node1 Valkey：

```yaml
environment:
  PLATCAP_VALKEY_URL: redis://10.0.1.11:18311/0
```

删除对本地 Valkey 的 `depends_on`，并增加 `default` 网络：

```yaml
networks:
  default: {}
  backend:
    ipv4_address: 172.31.251.60
  egress_r:
    ipv4_address: 172.31.253.20
```

最简单的方式是两个 gateway 分别调用所在机器上的本地 repo：

```yaml
environment:
  PLATCAP_REPO_URLS: '["http://172.31.251.60:18302"]'
```

这种方式不需要跨机器开放 repo 的 `18302` 端口，但两台机器会分别维护一份代码缓存。

## 4. 两台机器的环境变量

以下配置必须保持相同：

```env
PLATCAP_WEB_INTERNAL_TOKEN=...
PLATCAP_REPO_INTERNAL_TOKEN=...
PLATCAP_TENANT_NETWORK_SECRET=...

MINIO_WEB_ACCESS_KEY=platcap-web
MINIO_WEB_SECRET_KEY=...
```

只有 node1 需要：

```env
MINIO_ROOT_USER=minio-root
MINIO_ROOT_PASSWORD=...
```

真实 `.env` 文件不要提交到 Git。

## 5. 启动顺序

### 5.1 启动 node1 基础服务

```bash
docker compose -f deploy/compose.node1.yaml up -d postgres valkey minio
```

完成 MinIO bucket 和业务账号初始化后，启动 node1 其余服务：

```bash
docker compose -f deploy/compose.node1.yaml up -d
```

### 5.2 启动 node2

```bash
docker compose -f deploy/compose.node2.yaml up -d
```

如果启用 repo：

```bash
docker compose --profile repo -f deploy/compose.node2.yaml up -d
```

## 6. 跨机器端口

最终只需要跨机器访问以下端口：

| 目标机器 | 端口 | 服务 | 访问方 |
|---|---:|---|---|
| node1 | 18310 | PostgreSQL | node2 gateway |
| node1 | 18311 | Valkey | node2 gateway/web/repo |
| node1 | 19000 | MinIO | node2 web |
| node2 | 18300 | gateway | node1 HAProxy |

MinIO Console 的 `19001` 只绑定 node1 的 `127.0.0.1`，不需要跨机器开放。

## 7. 回滚注意事项

不要执行：

```bash
docker compose down -v
docker volume prune
```

node1 原有的 `platcap_pgdata` 和 `platcap_store` volume 应保留。新 web 不再挂载旧 store，但旧 store 可以用于回滚。

