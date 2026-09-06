# CLI contract

命令名、错误码和机器可读输出是独立产品契约，不沿用旧 CLI 的命令或文案。

```text
nodewe auth login|logout|status
nodewe node list|show|pair|enroll|revoke [--labels a,b]
nodewe group create|list|show|run
nodewe scope list|inspect <path>
nodewe task run|show|logs|cancel
nodewe grant create|list|revoke
nodewe audit list|show
nodewe doctor
```

`nodewe group run --group <id> --scope <path> [--max-concurrency N] -- <program> [args...]`
只针对组内明确列出的 Node 执行；`--failure-policy stop|continue` 控制部分失败时是否继续。

`nodewe node pair --labels a,b` 记录节点标签；`nodewe group create --id <id>
--label <label>` 按标签筛选节点并把匹配结果固化为显式 Node 集合。也可以使用
`--nodes a,b --label <label>` 做交集筛选；空集合和非法 Node/标签会 fail-closed。

执行类命令要求显式 `--node <node-id>` 或显式的目标 Node 集合。批量执行必须同时声明最大并发、失败策略和结果汇总方式。

默认成功输出为 JSON 摘要；`--output json`（或 `--json`）同时将错误输出为稳定的版本化 JSON。错误至少包含 `code`、`message`、`request_id`，不得泄露凭据或完整敏感输出。

所有命令还接受 `--non-interactive`、`--timeout MS`（等价于
`--timeout-ms`）和 `--profile NAME`。Profile 数据隔离存放在本地 NodeWe
状态目录下。

设置 `NODEWE_CONTROL_PLANE=<host:port>` 后，`node` 和 `grant` 命令改为调用
远程 Control Plane；使用 `NODEWE_TOKEN_FILE`（0600/0400）可避免把管理令牌放在
进程参数中。远程 `node pair` 仅限管理员直连创建，生产安装流程应使用
`node enroll --id ... --grant-code ... --grant-signature ...` 兑换一次性 Grant；
`enroll` 兑换请求不需要管理员令牌，成功后只把新 Node 凭据写入本地受限文件。

远程 CLI 连接非 loopback Control Plane 时必须启用 TLS：设置
`NODEWE_CLI_TLS_CA`，并按 mTLS 要求同时设置 `NODEWE_CLI_TLS_CERT`、
`NODEWE_CLI_TLS_KEY`；`NODEWE_CLI_TLS_SERVER_NAME` 用于覆盖证书主机名。未启用
TLS 时，客户端只允许 loopback，或显式设置仅用于开发的
`NODEWE_ALLOW_INSECURE_HTTP=1`。
