# Task state machine

```text
Pending → Approved → Running → Succeeded
                           ├→ Failed
                           ├→ Cancelled
                           └→ TimedOut
Pending/Approved/Running → CancelRequested → Cancelled
```

- `task_id` 全局唯一，和 AI 会话生命周期解耦；每个 Task 同时绑定调用方生成的 `request_id`，结果回传必须匹配。
- 启动请求必须包含 Node、Scope、操作类别、超时、输出上限和幂等键；NodeWe API
  的 `output_limit` 默认为 1 MiB，Agent 和 Control Plane 都会再次执行上限。
- 状态迁移单向且可审计；重复提交同一幂等键不得创建第二个 Task。
- `dispatched` Task 获得短时 lease 和随机 fencing token；结果回传必须携带当前
  token。lease 过期重新派发时生成新 token，旧 Agent 的迟到结果必须被拒绝。
- Node 重启后的任务处理由策略决定，首版默认清理未完成任务。
