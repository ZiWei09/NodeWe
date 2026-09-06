# Multi-node orchestration

Node Group 只是显式目标集合，不是任意 shell 广播。编排请求必须声明目标 Node、依赖关系、最大并发、失败策略、结果汇总方式和成本上限。调度筛选必须使用 Node 的 Ability、平台、架构、标签、地域、数据分类和容量属性，不能只看在线状态。

验收要求：

- Node A 与 Node B 不得串路由。
- Node A 离线时不得自动切到 Node B。
- 并行 Task 不得超过声明的并发上限。
- 撤销一个 Node 不影响其他 Node。
- 每个结果都带来源 `node_id`、`task_id` 和 `request_id`。
