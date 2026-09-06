# Product boundary

## 目标

Node Control 让获得授权的 AI 会话通过 Control Plane 调用明确指定的 Node。Node Runtime 只执行策略允许的操作，不保存 AI 对话，也不提供隐式设备切换。

## 首版范围

- Node 身份、一次性配对、凭据撤销和健康状态
- 出站加密连接、心跳和能力声明
- 显式 `node_id` 路由
- Scope 文件访问、命令执行、后台 Task、日志流和取消
- 操作策略、人工确认和 Activity Record

## 非目标

不替代 VPN、IAM、堡垒机、EDR 或 SIEM；不默认提供任意端口转发、全盘代理、隐蔽持久化、桌面控制、屏幕共享或仪器控制。后者只能作为 `adapters/` 中的独立能力包。

## 关键不变量

1. 每个执行请求必须携带一个明确且唯一的 Node 标识。
2. Node 离线时请求失败，不能静默切换到其他 Node。
3. Scope 外访问默认拒绝；高风险操作需要确认或预授权。
4. 撤销 Node 后，新的请求必须失败，运行中的 Task 按策略终止。
5. 公共 API 只使用 Node、Scope、Task、Grant、Policy 和 Activity 等领域词汇。
