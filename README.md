# NodeWe

NodeWe 是一个面向受控服务器、工作站和实验设备的 AI 节点控制面。它让 AI
工具通过明确授权的 Node 访问数据和设备所在的网络，同时把身份、权限、任务、
审批、结果和审计集中到一个可验证的控制面中。

## 术语和部署边界

本项目中的 **Node** 是一个受控主机（服务器、工作站或实验设备）的逻辑身份；
**Node Runtime** 是安装在该主机上的执行进程。NodeWe 的用户只需要安装 Node Runtime
并完成授权；Control Plane 可以由 NodeWe 托管，也可以随桌面版或用户自己的内网部署。
Node Runtime 只建立出站连接，不要求目标主机开放公网入站端口。

## 核心架构

```text
AI 工具 / CI / 用户
        │ CLI、SDK、HTTP/MCP 适配器
        ▼
Control Plane
身份 · 注册 · 路由 · 策略 · 审批 · 任务 · 审计
        │ 出站 TLS/WSS 或短连接 polling
        ▼
Node Runtime
节点凭据 · 能力声明 · Scope 边界 · 命令/文件/任务执行
        ▼
服务器、工作站、GPU、实验设备和其可达的内网资源
```

### 组件

- `control-plane/`：Node 目录、Grant、Policy、Approval、Task、Activity 和持久化。
- `node-runtime/`：安装在目标节点上的最小执行运行时，负责连接、心跳、能力协商和受限执行。
- `cli/`：`nodewe` 命令行客户端，支持本地开发和远程 Control Plane。
- `sdk/`：稳定的 NodeWe 协议对象和领域标识符。
- `spec/`：产品边界、API、协议、授权和状态机。
- `deploy/`：systemd、TLS、升级/回滚和预发布部署模板。
- `adapters/`：可选的外部集成边界，不改变核心 NodeWe 协议。
- `provenance/`：依赖、许可证、发布物和审查记录。

## 当前版本能力

- Node 一次性 Grant 注册、凭据轮换和撤销；
- polling 与 TLS/WebSocket 两种 Node Runtime 传输；
- Node 能力声明和显式 `node_id` 路由；
- Scope 内文件读取/写入、允许命令执行和后台 Task；
- 超时、取消、输出上限、脱敏和短时 dispatch lease；
- Node Group 的安全标签筛选与固化目标集合；
- `task.exec` 审批、幂等键、Activity 哈希链和审计导出；
- OIDC/OAuth2 会话校验、策略文件、加密快照和单写入者保护；
- 非 root systemd 单元、生产配置 preflight、SHA-256 发布校验和原子升级/回滚。

## 快速开始（本地开发）

```bash
export NODEWE_HOME="$(pwd)/.nodewe-dev"
cargo run -p node-control-cli --bin nodewe -- auth login
cargo run -p node-control-cli --bin nodewe -- node pair --id lab-a --name "Lab A"
cargo run -p node-control-cli --bin nodewe -- task run --node lab-a --scope . -- echo hello-nodewe
cargo run -p node-control-cli --bin nodewe -- audit list
```

启动本地 Control Plane：

```bash
NODEWE_ADMIN_TOKEN="dev-only" \
NODEWE_GRANT_SECRET="dev-only-grant-secret" \
NODEWE_DATA_DIR="$(pwd)/.nodewe-control-plane" \
cargo run -p node-control-plane
```

开发环境可切换到事务性 SQLite 存储：

```bash
NODEWE_STORAGE_BACKEND=sqlite \
NODEWE_DATA_DIR="$(pwd)/.nodewe-control-plane" \
NODEWE_ADMIN_TOKEN="dev-only" NODEWE_GRANT_SECRET="dev-only-grant-secret" \
cargo run -p node-control-plane
```

远程客户端使用 `NODEWE_CONTROL_PLANE=host:port` 和 `NODEWE_TOKEN_FILE`。非
loopback 地址必须启用 TLS；生产节点应使用一次性 `grant create` 后在节点上运行
`node-runtime enroll`，节点只接收自己的凭据，不接收管理员令牌。

生产环境的 Node Runtime 建议使用：

```bash
NODEWE_AGENT_TRANSPORT=websocket node-runtime connect \
  --endpoint control.example:443 --node-id lab-a --scope /srv/lab \
  --transport websocket
```

## 预发布和生产

预发布操作请参阅[预发布验收手册](deploy/pre-release-runbook.md)。生产部署至少需要
加密持久化、受管 TLS/mTLS、OIDC、签名 Grant、审批记录、外部密钥生命周期和审计留存。
当前版本的限制和上线阻断项记录在[生产就绪清单](spec/production-readiness.md)中。

## 开发与验证

```bash
RUSTUP_TOOLCHAIN=1.95 cargo fmt --all -- --check
RUSTUP_TOOLCHAIN=1.95 cargo test --workspace --locked --offline
RUSTUP_TOOLCHAIN=1.95 cargo clippy --workspace --all-targets --all-features -- -D warnings
```

发布前还应运行 `scripts/smoke.sh`、`scripts/check-deploy-units.sh`、部署脚本语法检查和
发布包 SHA-256 校验。

本地进程级验收可运行 `NODEWE_BIN_DIR=target/debug bash scripts/integration.sh`。
该脚本会启动 Control Plane 和 Node Runtime，验证 heartbeat、任务执行、输出哈希、
节点 TTL、Polling 重连、WebSocket 任务和节点撤销。TLS/mTLS 证书轮换仍需按预发布
手册单独演练。

本地三节点并发验收可运行 `NODEWE_BIN_DIR=target/debug bash scripts/multi-node-integration.sh`，
验证 3 个独立 Node Runtime 的并行路由、Scope 隔离、节点撤销和其他节点继续执行。
