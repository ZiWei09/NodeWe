# Control Plane API v1

当前实现使用 JSON over HTTP；也支持通过 `NODEWE_TLS_CERT`、
`NODEWE_TLS_KEY`、`NODEWE_TLS_CLIENT_CA` 启用原生 TLS/mTLS。未启用原生 TLS
时，部署必须由 TLS/mTLS 反向代理承载；Node Runtime 不得直接暴露到公网。

## Authentication

本地开发可使用 `Authorization: Bearer <NODEWE_ADMIN_TOKEN>`。部署启用
`NODEWE_OIDC_REQUIRED=1` 后，Control Plane 使用配置的 issuer/audience 和
secret-file 校验 OIDC/OAuth2 HS256 JWT 的签名、issuer、audience、`exp`、`nbf`
和 `sub`；`NODEWE_OIDC_ADMIN_GROUP`（默认 `nodewe-admin`）控制管理路由，
验证后的 `sub` 绑定到 Task/Approval 的 actor，客户端不能冒用另一个 actor。
Node Runtime 仍使用独立 Node Credential 和短时 Task lease。OIDC secret 的
签发、托管和轮换必须由批准的身份系统/KMS 负责。

## Endpoints

### `GET /health`

无需认证，只返回服务状态和 `protocol_version`。

### `GET /v1/nodes`

返回节点目录。节点包含 `node_id`、显示名称、`online`、`revoked`、已声明能力，以及用于显式调度的 `platform`、`architecture`、`version`、`labels`、`region`、`data_class` 和 `capacity` 属性。`online` 只有在最近一次 heartbeat 未超过 `NODEWE_NODE_ONLINE_TTL_MS`（默认 30 秒）时才为 true。

节点目录、节点创建/撤销/轮换、Grant、Task 查询/提交/取消和 Activity 查询
均要求 Control Plane 管理员会话；Node Credential 只用于本节点的 heartbeat、
Task 拉取和结果回传。

### `POST /v1/nodes`

请求：

```json
{"node_id":"lab-a","name":"GPU Lab A","platform":"linux","architecture":"aarch64","version":"0.1.0","labels":"gpu,lab","region":"cn-east","data_class":"research","capacity":"gpu=1;ram_gb=64"}
```

重复 `node_id` 返回 `node_exists`。`labels` 只能包含逗号分隔的字母、数字、`_`、`-`、`.`、`+` 标签，单个标签最多 64 个字符；不符合时返回 `invalid_labels`。成功响应会返回一次性节点凭据；真实 enrollment 应改用一次性
Pairing Grant，而不是直接创建节点。

### `POST /v1/nodes/{node_id}/revoke`

立即将节点标记为 `revoked=true, online=false`，并取消该节点尚未完成的 queued/dispatched Task。后续 Task 提交和心跳均被拒绝。

### `POST /v1/nodes/{node_id}/rotate`

为未撤销节点生成新的随机凭据；旧凭据立即失效。新凭据只在本次响应返回，轮换操作写入 Activity Record。生产环境应由密钥管理系统托管轮换与分发。

### `POST /v1/grants`

管理员创建一个默认 5 分钟、只能使用一次的配对码。配置
`NODEWE_GRANT_SIGNING_KEY` 时，`grant_signature` 使用 Ed25519 PKCS#8 密钥签名；
未配置时仅允许本地开发使用 HMAC fallback：

```json
{"grant_code":"…","grant_signature":"…","expires_at":1730000000000}
```

### `GET /v1/grants`

管理员查询配对 Grant 的状态（`used`、`revoked` 和过期时间）。响应不会包含
节点凭据。

### `POST /v1/grants/{grant_code}/revoke`

管理员立即撤销尚未兑换的 Grant。撤销是幂等的；之后的兑换请求统一返回
`grant_invalid_or_expired`。

### `POST /v1/grants/redeem`

节点安装流程使用配对码换取节点凭据：

```json
{"grant_code":"…","grant_signature":"…","node_id":"lab-a","name":"GPU Lab A"}
```

响应只在兑换时返回凭据。节点之后使用该凭据发送 heartbeat；管理员 token
不应被写入 Node Runtime 配置文件。

### `POST /v1/agent/heartbeat`

请求：`{"protocol_version":1,"node_id":"lab-a","abilities":"file.read,task.exec"}`。节点必须已经注册且未撤销；成功后恢复在线状态并更新能力声明。响应包含 `protocol_version` 和 `negotiated_abilities`；未知能力或不支持的协议版本会以结构化错误拒绝。

### `POST /v1/tasks`

请求至少包含 `request_id`、`node_id`、`ability`，以及用于本地 MVP 的结构化 `program`、`argument` 和可选 `idempotency_key`；可选 `actor` 会被记录到 Task（默认 `admin`），`timeout_ms` 默认为 30 秒且最大 5 分钟，`output_limit` 默认为 1 MiB 且必须为 1–1 MiB 的整数。Control Plane 会把这些值写入 Task 并扩展 lease 窗口，Agent 按任务值执行。同一幂等键重复提交返回已有 Task，不创建第二个 Task。Agent 只会执行自己的目标 Node 任务，并在结果回传后进入终态；结果必须回传同一 `request_id`。

生产环境开启 `NODEWE_REQUIRE_APPROVAL_RECORDS=1` 后，`task.exec` 还必须携带
由管理员创建的 `approval_id`。审批记录绑定目标 Node、能力、程序和参数，成功消费后不可重用。

能力为 `file.read` 时，`program` 表示 Scope 内路径；能力为 `file.write` 时，
`program` 表示 Scope 内路径、`argument` 表示待写入内容。Agent 会执行 Scope
边界校验、大小限制和输出脱敏，写入结果只返回字节数，不回显文件内容。

本地策略文件还可配置 `allowed_commands` 和 `allowed_paths`。前者只允许指定
的命令 basename，后者只允许 Scope-relative 路径前缀；Control Plane 在提交
时 fail-closed 检查，Agent 执行时再次执行 Scope 校验。

### `POST /v1/approvals`

管理员创建一次性审批记录：

```json
{"node_id":"lab-a","ability":"task.exec","program":"echo","argument":"ok","actor":"operator"}
```

响应包含 `approval_id` 和过期时间；审批的 `actor` 必须与提交任务的
authenticated actor 相同，不能跨操作主体转用；创建与消费均写入 Activity Record。

### `GET /v1/agent/tasks?node_id={node_id}`

使用节点凭据取回该 Node 的 queued Task；取回时任务转为 `dispatched` 并获得短时 `lease_until` 与随机 `lease_token`，不会返回其他 Node 的任务。lease 过期后任务可重新领取并获得新的 fencing token。

### `POST /v1/agent/tasks/{task_id}/result`

节点回传 `node_id`、`request_id`、本次派发的 `lease_token`、终态 `state`、输出摘要和退出码。Control Plane 会校验 Task、Node 与当前 lease token 的绑定关系；过期或旧 Agent 的结果会被拒绝。

### `GET /v1/tasks`、`GET /v1/tasks/{task_id}`、`GET /v1/audit`

分别返回任务摘要、单个后台任务（含最多 4 KiB 的输出预览、Agent 传输结果的
`output_sha256` 和 `output_truncated` 标记）和 Activity Record。Control Plane
不会默认持久化完整任务输出。
审计记录包含 `actor`、`prev_hash`/`hash` 链字段；新记录会把 actor 纳入哈希，
日志正文不应默认进入 Control Plane。旧版本没有 actor 的记录可继续按兼容格式校验。

### `GET /v1/audit/export?from={offset}&limit={n}`

管理员可分页导出审计链。`limit` 默认 1000，最大 10000；响应包含 `from`、`count`、`next` 和带完整 `prev_hash`/`hash` 的 `records`，可由外部留存系统按 `next` 继续读取。非法分页参数会被拒绝。

### `POST /v1/tasks/{task_id}/cancel`

管理员可以取消任意 queued/dispatched Task；启用 OIDC 时，普通操作员只能取消
自己作为 actor 创建的 Task，否则返回 `actor_forbidden`。终态 Task 返回
`task_terminal`。取消会清除 lease，Agent 不会继续领取该任务。

## Error response

```json
{"code":"node_unavailable"}
```

错误码详见 `spec/error-codes.md`。客户端应依据 `code` 而非自由文本判断行为。
