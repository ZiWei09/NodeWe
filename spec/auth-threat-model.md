# Auth and threat model

## 身份

- 每个 Node 有独立密钥，使用一次性、短时 Pairing Grant 完成 enrollment。
- Control Plane 与 Node 使用 TLS；高安全部署可选 mTLS。
- 会话凭据短期有效，并绑定 actor、项目、Node、Scope 和能力。
- 支持密钥轮换和立即撤销；不使用长期共享 token。

## 授权

授权由 `actor/team × node × scope × operation` 四个维度组成。默认拒绝任意 Node、任意路径和任意网络。删除、`sudo`、权限修改、凭据读取和服务重启等操作默认需要确认。

## 威胁与控制

| 威胁 | 控制 |
| --- | --- |
| 凭据泄露 | 短期凭据、独立 Node 密钥、轮换、撤销 |
| 错误设备执行 | 强制显式 Node 路由，禁止 offline fallback |
| Scope 穿越 | 规范化路径、allowlist、策略决策审计 |
| 敏感输出外发 | 输出大小限制、脱敏、保留级别 |
| 重放请求 | request id、过期时间和幂等键 |
| 审计被篡改 | append-only Activity、`prev_hash`/`hash` 哈希链、启动时链完整性校验 |
