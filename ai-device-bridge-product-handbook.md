# NodeWe 产品与架构手册

版本：v1.0（以当前实现为准）  
状态：预发布候选版

本文档描述 NodeWe 当前产品边界、领域模型、组件职责、运行流程和交付标准。文档中的
术语与代码、CLI 和协议保持一致；未实现的能力不会作为现有功能对外承诺。

## 1. 产品定义

NodeWe 是面向受控服务器、工作站、GPU 主机和实验设备的 AI 节点控制面。AI 工具通过
CLI、SDK 或上层适配器提交 Task，Control Plane 负责身份、路由、策略、审批和审计，
Node Runtime 在目标节点的本地 Scope 内执行实际操作。

### 术语约定

Node 表示受控主机在控制面的身份，Node Runtime 表示运行在该主机上的执行进程。
产品的核心价值是让
AI 在明确授权、可撤销、可审计的边界内操作已有主机和内网资源，而不是要求用户购买
专用硬件或先建设一套公网设备网络。

核心原则：

1. 节点主动建立出站连接，不要求节点开放公网入站端口；
2. 每项执行都绑定明确的 `node_id`、`scope_id`、能力和权限主体；
3. 默认拒绝越界文件访问、未允许命令、未知能力和未授权节点；

对用户而言，推荐形态是由 NodeWe 托管 Control Plane，用户在需要被控制的主机上安装
Node Runtime 并授权。桌面版可以把 Control Plane 和 Node Runtime 打包在一起，供不需要
远程协作的个人使用；企业也可以把 Control Plane 部署到自己的内网。无论采用哪种形态，
目标主机都只建立出站连接，不要求暴露公网入站端口。
4. 长任务独立于调用方会话，具备状态、租约、超时、取消和受限输出；
5. 关键操作生成可验证的 Activity 哈希链，可导出到外部留存系统。

## 2. 用户和场景

- 研究团队：从 AI 工具操作只能通过 VPN 访问的计算节点，数据保留在原位置。
- 企业研发团队：统一管理多台 GPU、构建机和内网工作站，保留审批和责任链。
- 平台管理员：注册、分组、授权、撤销节点，并配置能力、命令和路径策略。
- AI 应用开发者：使用稳定的 Node/Task/Grant 契约，而不是为每台设备维护专用连接。

NodeWe 不替代 VPN、IAM、堡垒机、EDR、SIEM 或组织的密钥管理系统；它也不默认提供
任意端口转发、全盘代理、隐蔽持久化、桌面控制或屏幕共享。

## 3. 总体架构

```text
┌──────────────────────────┐
│ AI 工具 / CI / 用户       │
│ CLI、SDK、HTTP/MCP 适配器 │
└────────────┬─────────────┘
             │ authenticated API
             ▼
┌──────────────────────────┐
│ Control Plane             │
│ identity · routing        │
│ policy · approval · task  │
│ activity · persistence    │
└────────────┬─────────────┘
             │ TLS/WSS 或 polling
             ▼
┌──────────────────────────┐
│ Node Runtime                │
│ credential · heartbeat    │
│ capability · Scope guard  │
│ file/task execution       │
└────────────┬─────────────┘
             ▼
      本地文件系统、进程和内网资源
```

### 3.1 Control Plane

Control Plane 是当前版本的单实例服务，负责：

- Node 目录、Grant 兑换、凭据校验、在线状态和撤销；
- Node Group 标签筛选，并在执行前固化为明确的 Node ID 集合；
- Policy、Approval、Task 状态机、幂等键和 dispatch lease；
- Agent heartbeat、任务领取、结果回传和断线恢复；
- Activity 记录、哈希链、分页导出和加密快照。

当前存储使用加密快照和单写入者锁，适合预发布与单实例部署；高可用生产部署必须替换
为组织批准的事务型共享存储和故障转移方案。

### 3.2 Node Runtime

Node Runtime 是部署在目标节点上的最小运行时，负责：

- 使用 Node 凭据连接 Control Plane，发送 heartbeat 和能力集合；
- 只在配置的 Scope 内读取/写入文件；
- 只执行策略允许的命令，支持 `task.exec` 超时和输出上限；
- 领取带租约的 Task，返回状态、退出码、摘要和受限输出；
- 在连接中断、能力协商失败、凭据撤销或协议不支持时安全失败。

Agent 不保存 AI 对话，不接收管理员令牌，也不主动扫描 Scope 外数据。

### 3.3 CLI 与 SDK

`nodewe` CLI 提供登录、Node 管理、Grant、Group、Scope、Task 和审计命令，并支持机器
可读 JSON 输出。`nodewe-sdk` 只暴露稳定的协议 Envelope、Node/Task/Grant 标识符和
领域结构，不依赖 Control Plane 存储或 Agent 实现。

## 4. 领域模型

| 对象 | 责任 |
|---|---|
| Node | 受控设备的稳定身份、标签、能力和健康状态 |
| Scope | 节点上的资源根目录和可访问边界 |
| Grant | 一次性、短时有效的节点注册授权 |
| Credential | 节点连接 Control Plane 的独立凭据 |
| Policy | 能力、命令、路径、数据分类和主体限制 |
| Approval | 与 Node、能力、命令和主体绑定的一次性确认 |
| Task | 在指定 Node/Scope 上执行的可审计工作单元 |
| Activity | 对管理和执行事件的不可变审计记录 |
| Node Group | 由安全标签或明确 Node 集合形成的固化目标集合 |

## 5. 关键流程

### 5.1 节点注册

1. 管理员创建一次性 Grant；
2. 在目标节点执行 `node-runtime enroll`，只提交 Grant code/signature；
3. Control Plane 校验 Grant、Node ID、标签和能力；
4. Agent 将返回的 Credential 原子写入权限为 0600 的新文件；
5. Agent 使用 Credential 建立 polling 或 WSS 会话并发送 heartbeat。

管理员 Token 不进入节点注册命令，也不会写入 Agent 凭据文件。

### 5.2 任务提交与执行

任务必须包含明确的 Node、Scope、能力、参数和幂等键。Control Plane 依次执行身份、
Policy、Approval、Node 在线状态和租约检查，再将任务派发给匹配的 Agent。Agent 在
Scope 内执行并返回状态；Control Plane 持久化 4 KiB 预览和 SHA-256 摘要，完整输出不
默认长期存储。

`task.exec` 默认要求 Approval 或显式预授权。Node Group 只负责生成稳定 Node 集合，
不会因名称相似、标签相似或某个节点离线而隐式广播或切换目标。

### 5.3 撤销与恢复

撤销 Node Credential 后，新任务立即拒绝，排队任务按策略取消；运行中任务在下一次
心跳或结果回传时重新校验。Agent 使用有上限的指数退避重连，旧租约结果会因 fencing
token 不匹配而被拒绝。

## 6. 安全基线

- 非 loopback CLI/Agent 连接拒绝明文传输；
- 原生 TLS 1.2/1.3、可选 mTLS 和 WSS；
- OIDC issuer、audience、时间窗、subject 和管理员组校验；
- AES-256-GCM 加密快照、原子写入、备份和启动完整性检查；
- 命令基名、Scope 相对路径、能力、数据分类和 actor allowlist；
- 非 root systemd 单元、资源限制、私有临时目录和只读系统路径；
- 输出脱敏、大小限制、UTF-8 安全截断和敏感字段不落盘。

`NODEWE_ENV=production` 会强制检查生产所需的加密存储、签名 Grant、Approval、OIDC
和 TLS/mTLS（或批准代理）配置；不满足条件时服务拒绝启动。

## 7. API 与协议约定

公共 API 只使用 `node_id`、`scope_id`、`grant_id`、`task_id`、`activity_id`、`ability`
和 `request_id`。Envelope 统一携带协议版本、消息类型和请求标识；Agent heartbeat
声明能力，Control Plane 返回协商结果。未知字段、错误 JSON 类型、未知能力和不支持的
协议版本均按 fail-closed 处理。

详细定义：

- [Control Plane API](spec/control-plane-api.md)
- [Node 协议](spec/node-protocol.md)
- [CLI 契约](spec/cli-contract.md)
- [Task 状态机](spec/task-state-machine.md)
- [多节点编排](spec/multi-node-orchestration.md)

## 8. 部署与版本策略

预发布使用[预发布验收手册](deploy/pre-release-runbook.md)。生产部署使用专用非 root
账户、受管证书和密钥、OIDC、加密持久化、外部审计留存及 systemd preflight。升级工具
先校验 `SHA256SUMS`，再以原子方式切换 `current`，保留上一版本并支持 rollback。

当前版本的已实现项、限制和生产阻断项以[生产就绪清单](spec/production-readiness.md)
为准。

## 9. 研发与交付要求

- 新能力先更新 `spec/`、错误码和状态机，再实现代码；
- 每个协议或权限变化必须有单元/集成测试和可审计的发布记录；
- 依赖、许可证、SBOM、密钥、配置和发布包在交付前完成审查；
- 不把未实现的适配器、桌面能力或高可用特性写入当前版本承诺。
