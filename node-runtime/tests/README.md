# Agent acceptance tests

这些测试围绕 NodeWe 的公开规格编写，验证节点运行时的边界和故障行为：

- `task_lifecycle.rs`：合法状态迁移、超时和取消
- `scope_policy.rs`：路径规范化、Scope 外拒绝和输出限制
- `node_reconnect.rs`：断线重连、撤销感知和无隐式切换
- `multi_node_routing.rs`：显式 Node 路由和来源隔离
- `task_idempotency.rs`：重复幂等键不创建第二个 Task
- `approval_flow.rs`：高风险操作确认和拒绝
- `revoke_propagation.rs`：撤销传播到新请求和运行中 Task
