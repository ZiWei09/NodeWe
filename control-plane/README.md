# Control Plane

The `node-control-plane` binary is the first local control-plane implementation. It exposes authenticated JSON endpoints for node registration, explicit node revocation, task acceptance and activity records.

```bash
NODEWE_ADMIN_TOKEN='change-me' \
NODEWE_GRANT_SECRET='change-me-too' \
NODEWE_DATA_DIR=/var/lib/nodewe \
NODEWE_BIND='127.0.0.1:8787' \
cargo run -p node-control-plane
```

设置 `NODEWE_STORAGE_BACKEND=sqlite` 可使用事务性 SQLite 存储，数据库文件位于
`NODEWE_DATA_DIR/nodewe.sqlite3`；默认值 `snapshot` 保持兼容的加密快照存储。

For deployments, `NODEWE_ADMIN_TOKEN_FILE` may be used instead of the token
environment variable. Secret files must be mode 0600; an explicitly supplied
environment value takes precedence.
`NODEWE_GRANT_SECRET_FILE` provides the same injection path for the grant
secret used by the development fallback.

Set `NODEWE_ENV=production` in the service environment. In that mode the
binary itself requires encrypted storage, signed grants, durable approval
records, OIDC operator authentication, an explicit data directory, and either
native mTLS or an attested approved TLS proxy; this remains enforced even if a
supervisor bypasses the deployment preflight script.

The server intentionally does not execute commands. Node Runtimes are the execution boundary. Persistence supports an encrypted atomic snapshot/backup backend and a transactional SQLite backend; the single-writer lock remains enabled for this release. Clients fail closed for non-loopback plaintext endpoints unless `NODEWE_ALLOW_INSECURE_HTTP=1` is explicitly set for development.

JSON request bodies and persisted Activity records are parsed with strict
`serde_json` value/type checks; malformed payloads and non-object request bodies
are rejected before routing.
Task results expose only a bounded 4 KiB preview in the Control Plane, plus an
`output_sha256` digest supplied by the Agent for the transmitted result and verified by
the Control Plane against the received bytes, plus an
`output_truncated` flag; complete command output is not written to the default
snapshot store.

Native TLS/mTLS can be enabled without a reverse proxy by setting
`NODEWE_TLS_CERT`, `NODEWE_TLS_KEY` and `NODEWE_TLS_CLIENT_CA` together. The
server requires a client certificate signed by the configured CA. Certificate
rotation remains an operational responsibility and must be tested before
production rollout.

Each accepted connection has a 15-second read/write deadline and the process
caps concurrent connections at 256. These limits are protective defaults, not
a substitute for proxy rate limiting and capacity planning.

Agents can use the authenticated persistent WebSocket endpoint
`/v1/agent/ws?node_id=...` by setting `NODEWE_AGENT_TRANSPORT=websocket`; the
short-connection polling endpoints remain available for compatibility.

For encrypted local persistence, set `NODEWE_STORE_KEY` to a 32-byte key
encoded as 64 hexadecimal characters, or mount that value in a mode-0600 file
and set `NODEWE_STORE_KEY_FILE`. The environment variable takes precedence.
Set `NODEWE_REQUIRE_ENCRYPTED_STORE=1`
in production so the service refuses to start if the key is absent or any
existing state file is still plaintext. New writes use AES-256-GCM and an
atomic `store.snapshot` with a previous snapshot backup; transactional
database/HA migration is still a separate release gate.

For signed production enrollment grants, set `NODEWE_GRANT_SIGNING_KEY` to an
Ed25519 PKCS#8 private key encoded as hex, or use the mode-0600
`NODEWE_GRANT_SIGNING_KEY_FILE` secret file. The environment value takes
precedence. Inject either from a key-management system. The development HMAC
grant fallback is retained only for local tests;
production must use the approved asymmetric key lifecycle and rotation process.
Set `NODEWE_REQUIRE_SIGNED_GRANTS=1` so startup fails closed if the signing key
is absent.
During a signing-key rotation, `NODEWE_GRANT_SIGNING_KEY_PREVIOUS_FILE` (or
its environment counterpart) keeps the previous key available for verification
until outstanding grants expire; new grants always use the active key.

Set `NODEWE_REQUIRE_APPROVAL_RECORDS=1` to require an administrator-created,
single-use approval record for every `task.exec` request. The record is bound to
the Node, ability, program and argument and is persisted with the control-plane
snapshot.

Human/CLI authentication can be backed by a pinned OIDC/OAuth2 JWT profile.
Set `NODEWE_OIDC_ISSUER`, `NODEWE_OIDC_AUDIENCE` and a mode-0600
`NODEWE_OIDC_HS256_SECRET_FILE` (or the equivalent secret environment variable),
then set `NODEWE_OIDC_REQUIRED=1`. The control plane verifies the compact JWT
signature, issuer, audience, expiry and subject locally; membership in
`NODEWE_OIDC_ADMIN_GROUP` (default `nodewe-admin`) is required for administrative
routes, and the verified `sub` is bound to the Task/Approval actor. Keep the
verification secret in the approved identity gateway/KMS rotation process.

The control plane also accepts an optional fail-closed policy file through
`NODEWE_POLICY_FILE`. It is a small line-oriented configuration with
`allowed_abilities=...`, `approval_required=...`, `allowed_data_classes=...`,
`allowed_actors=...`, `allowed_commands=...` and `allowed_paths=...` keys.
Unknown keys, unsupported abilities, unsafe commands/paths and an empty allowlist
prevent startup. Every accepted task emits a `policy.allowed` Activity Record;
actor/team authorization still belongs to the production OIDC integration.

API routes are specified in `../spec/control-plane-api.md`:

- `GET /health`
- `GET|POST /v1/nodes`
- `POST /v1/nodes/{node_id}/revoke`
- `POST /v1/nodes/{node_id}/rotate`
- `POST /v1/grants`
- `GET /v1/grants`
- `POST /v1/grants/{grant_code}/revoke`
- `POST /v1/grants/redeem`
- `GET|POST /v1/approvals`
- `GET|POST /v1/tasks`
- `GET /v1/tasks/{task_id}`
- `POST /v1/tasks/{task_id}/cancel`
- `POST /v1/agent/heartbeat`
- `GET /v1/agent/tasks?node_id=...`
- `POST /v1/agent/tasks/{task_id}/result`
- `GET /v1/agent/ws?node_id=...` (WebSocket upgrade)
- `GET /v1/audit`
- `GET /v1/audit/export?from={offset}&limit={n}`
