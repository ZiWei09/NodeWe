# Node protocol

协议使用公开的 TLS/WebSocket 与 JSON 标准，并拥有独立版本号。领域对象不暴露旧聊天或私有路由概念。
0.1.0 的可交付实现同时支持短连接 TLS/HTTP polling 和持久 TLS/WebSocket
（WSS）会话；通过 `--transport websocket` 或
`NODEWE_AGENT_TRANSPORT=websocket` 启用后者，二者共用同一 Envelope 契约。

```json
{
  "protocol_version": 1,
  "agent_version": "0.1.0",
  "node_id": "node_123",
  "request_id": "req_123",
  "type": "task.start",
  "payload": {}
}
```

所有消息必须可关联 `request_id`。Node 心跳报告版本、能力和健康摘要，不上传敏感拓扑。能力必须显式协商；未知能力和未知协议版本安全失败。

首次安装可通过 `POST /v1/grants/redeem` 完成 Grant-only enrollment：Node Runtime
提交一次性 `grant_code`/`grant_signature`、自身 `node_id` 和能力元数据，不发送
管理员凭据；成功响应中的 Node Credential 必须写入权限受限的本地 token 文件。

心跳成功响应包含 `protocol_version` 和 `negotiated_abilities`。Control Plane
只返回双方都支持的能力；若 Agent 声明未知能力或不支持的协议版本，连接以
结构化错误拒绝。Agent 必须校验响应中的协议版本和自身所需能力集合，协商不完整
时不得继续拉取或执行 Task。

Agent 使用 WebSocket 会话或短连接请求承载心跳、任务拉取和结果回传；Control
Plane 暂时不可达时，Agent 不会切换到其他 Node，而是使用 1 秒起始、指数退避、
30 秒上限的重连策略。结果回传失败不会终止 Agent 进程，下一轮会继续恢复连接并
依靠 lease/reclaim 机制处理未完成任务。

Heartbeat 只允许 Node 更新能力协商和运行时平台信息。`labels`、`region`、
`data_class`、`capacity` 等调度与数据分类元数据由管理员在注册或 enrollment 时
写入；如果 Node 在 heartbeat 中提交这些字段，Control Plane 必须拒绝并返回
`immutable_node_metadata`，避免凭据持有者自行提升分组或数据权限。

对于 `task.exec`，命令 basename 和命令参数都必须符合 Agent 的 allowlist。
`cat`、`ls` 等带路径参数的命令，其每个路径参数必须通过同一 Scope 的
containment 校验；Agent 不接受通过命令参数读取或列出 Scope 外的文件。
