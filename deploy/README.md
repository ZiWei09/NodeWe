# NodeWe deployment

For a copy-paste local and staging walkthrough, see
[`pre-release-runbook.md`](pre-release-runbook.md).

The checked-in service is intentionally bound to loopback by default. A
production deployment must:

1. run `node-control-plane` as the dedicated `nodewe` non-root account;
2. set `NODEWE_ENV=production`; the binary refuses to start with the local
   development security profile when this mode is selected;
3. keep `NODEWE_DATA_DIR` on an encrypted, backed-up volume;
4. inject `NODEWE_ADMIN_TOKEN`, `NODEWE_GRANT_SECRET` and `NODEWE_STORE_KEY`
   from a secret manager, never from shell history;
5. enable `NODEWE_OIDC_REQUIRED=1` with a pinned issuer/audience and inject
   `NODEWE_OIDC_HS256_SECRET_FILE`; use the configured admin group for control
   plane operators and keep the secret in the approved IdP/KMS rotation path;
6. optionally install `policy.conf.example` as a reviewed
   `/etc/nodewe/policy.conf` and set `NODEWE_POLICY_FILE`;
7. terminate HTTPS at an approved reverse proxy using the example Nginx config;
8. use a separate mTLS listener or proxy policy for Agent endpoints;
9. expose no inbound listener on the Node host; Agents connect outward only;
10. restrict the Control Plane port with firewall rules and monitor audit output.

For Linux Agents, use `nodewe-agent.service` with a dedicated `nodewe-agent`
account and an `/etc/nodewe/agent.env` readable only by that account. The unit
applies non-root execution, private devices/tmp, read-only system paths,
namespace restrictions, kernel/clock isolation and CPU/memory/process limits.
The Agent scope must be
an explicit data directory; do not grant it a home directory or Docker socket.
The credential is read from `NODEWE_NODE_TOKEN` or a mode-0600
`NODEWE_NODE_TOKEN_FILE` in the environment file and is deliberately not
expanded into the service process command line.

For first-time installation, use `node-runtime enroll` with a one-time Grant and
write its result directly to `NODEWE_NODE_TOKEN_FILE`; the enrollment command
does not require or accept the Control Plane administrator token.

The `node-runtime` and `nodewe` clients refuse to send credentials to a
non-loopback plaintext endpoint by default. In staging, set
`NODEWE_ALLOW_INSECURE_HTTP=1` only when a local test explicitly requires it;
production traffic must terminate TLS/mTLS at the approved local proxy, or use
the Control Plane's native TLS/mTLS configuration (`NODEWE_TLS_CERT`,
`NODEWE_TLS_KEY`, `NODEWE_TLS_CLIENT_CA`).

For a persistent outbound session, set `NODEWE_AGENT_TRANSPORT=websocket` (or
pass `--transport websocket`) on the Agent. This uses the Control Plane's
authenticated `/v1/agent/ws` endpoint; `polling` remains available for
compatibility and diagnostics.

The example files are templates, not generated certificates or a complete
hardening profile. They run as dedicated non-root users, hide other processes,
restrict the visible process tree to PIDs, and cap CPU, memory and task count.
Security review must approve the final proxy, cipher suite, certificate
rotation and backup policy before production use; verify the installed systemd
version supports `ProtectProc` and `ProcSubset` before rollout.

Certificate rotation can be validated without changing the active files, then
installed atomically with:

```bash
deploy/rotate-tls.sh --tls-dir /etc/nodewe/tls \
  --cert /run/secrets/nodewe-server-chain.pem \
  --key /run/secrets/nodewe-server-key.pem \
  --client-ca /run/secrets/nodewe-agent-ca.pem --dry-run
```

Remove `--dry-run` only after the staged certificate/key pair and CA have been
approved. The script keeps a timestamped previous copy and reloads the service
when systemd is available; retain and protect those backups according to the
organization's key-retention policy.

The Control Plane unit executes `/opt/nodewe/current/node-control-plane` and
runs `/opt/nodewe/current/scripts/preflight-production.sh` before startup.
Install the verified release as the `current` symlink before enabling the
unit; an incomplete or non-production configuration therefore fails closed.

For upgrades, place a verified release directory beside the existing install
and run `deploy/upgrade-nodewe.sh --install-root /opt/nodewe RELEASE_DIR`.
The helper uses an atomic POSIX `rename(2)` replacement for the live symlink
(GNU `mv -T` or the system Perl runtime is required); it never removes the
active link before the replacement is ready.
The script verifies `SHA256SUMS`, switches the `current` symlink atomically,
keeps the previous target, and supports `--rollback`. It restarts the systemd
unit when available; set `NODEWE_SKIP_RESTART=1` for a controlled dry run.

Run `scripts/preflight-production.sh` in the deployment environment before
starting the service. It fails closed when production-only secret, encryption,
approval, signature or OIDC settings are missing. TLS/mTLS must either be configured
with all three native files, or be explicitly attested with
`NODEWE_TLS_PROXY_APPROVED=1` when an approved reverse proxy terminates and
authenticates traffic; the script prints a warning for that proxy path.

Export the tamper-evident Activity chain to an external retention system with
`scripts/export-audit.sh`. It paginates the authenticated API, verifies every
  `prev_hash`/`hash` link before writing, and stores each run in a new archive
  directory with page files plus SHA-256 sidecars and restrictive permissions.
  The verifier accepts historical records without an actor and current records
  whose hash covers the authenticated `actor` field:

```bash
scripts/export-audit.sh --endpoint https://control.example.invalid \
  --output-dir /var/lib/nodewe/audit-export \
  --token-file /run/secrets/nodewe-audit-token
```
