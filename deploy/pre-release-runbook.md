# NodeWe 0.1.0 pre-release runbook

This runbook exercises one Control Plane and one or more Node Runtimes without
using production credentials. The commands below use the release directory;
replace `PKG` with the absolute path to
`dist/nodewe-0.1.0-aarch64-apple-darwin`.

## Local single-machine smoke

Use a temporary data directory and leave `NODEWE_ENV` unset. This is the only
mode in which the development HMAC grant fallback and loopback plaintext are
acceptable.

```bash
PKG=/absolute/path/to/nodewe-0.1.0-aarch64-apple-darwin
CP_DATA=$(mktemp -d /tmp/nodewe-cp.XXXXXX)
NODEWE_ADMIN_TOKEN='dev-admin-only' \
NODEWE_GRANT_SECRET='dev-grant-only' \
NODEWE_DATA_DIR="$CP_DATA" \
NODEWE_BIND=127.0.0.1:8787 \
"$PKG/node-control-plane"
```

In a second terminal, create a short-lived Grant with the administrator
token. Keep this terminal separate from the Node terminal.

```bash
export PKG=/absolute/path/to/nodewe-0.1.0-aarch64-apple-darwin
export NODEWE_CONTROL_PLANE=127.0.0.1:8787
export NODEWE_TOKEN=dev-admin-only
export NODEWE_HOME=$(mktemp -d /tmp/nodewe-cli.XXXXXX)
"$PKG/nodewe" grant create
```

Copy `grant_code` and `grant_signature` from the JSON response. On the Node
side, redeem the Grant without sending the administrator token, then start the
outbound Agent session:

```bash
NODE_SCOPE=$(mktemp -d /tmp/nodewe-node-scope.XXXXXX)
"$PKG/node-runtime" enroll \
  --endpoint 127.0.0.1:8787 \
  --node-id lab-a \
  --grant-code GRANT_CODE \
  --grant-signature GRANT_SIGNATURE \
  --token-file "$NODE_SCOPE/node.token"

NODEWE_NODE_TOKEN_FILE="$NODE_SCOPE/node.token" \
"$PKG/node-runtime" connect \
  --endpoint 127.0.0.1:8787 \
  --node-id lab-a \
  --scope "$NODE_SCOPE" \
  --transport polling
```

Back in the administrator terminal, verify the node and submit a manually
confirmed task. `task.exec` is approval-gated by default, even in local mode.

```bash
"$PKG/nodewe" node list
TASK_JSON=$("$PKG/nodewe" task submit \
  --node lab-a --ability task.exec \
  --program echo --argument 'hello from NodeWe' \
  --approved --output-limit 4096)
printf '%s\n' "$TASK_JSON"
TASK_ID=$(printf '%s' "$TASK_JSON" | jq -r .task_id)
"$PKG/nodewe" task show "$TASK_ID"
"$PKG/nodewe" task logs "$TASK_ID"
"$PKG/nodewe" audit list
```

## Production-like staging

For a staging host or any non-loopback endpoint, do not use plaintext. Provision
the native TLS/mTLS files or an approved TLS/mTLS proxy, set
`NODEWE_ENV=production`, and provide mode-0600 secret files. The binary and
`scripts/preflight-production.sh` both fail closed if encrypted storage,
signed Grants, approval records, OIDC, or TLS are missing.

Use the checked-in templates as the starting point:

```bash
cp "$PKG/deploy/control-plane.env.example" /etc/nodewe/control-plane.env
cp "$PKG/deploy/agent.env.example" /etc/nodewe/agent.env
```

After replacing every placeholder and installing the certificates, run the
preflight as the service account, then install the systemd units. The Control
Plane unit executes the SHA-verified `/opt/nodewe/current` symlink and runs
preflight again before startup.

```bash
NODEWE_ENV=production \
  NODEWE_ADMIN_TOKEN_FILE=/run/secrets/nodewe-admin-token \
  NODEWE_GRANT_SECRET_FILE=/run/secrets/nodewe-grant-secret \
  NODEWE_DATA_DIR=/var/lib/nodewe \
  NODEWE_STORE_KEY_FILE=/run/secrets/nodewe-store-key \
  NODEWE_GRANT_SIGNING_KEY_FILE=/run/secrets/nodewe-grant-signing-key \
  NODEWE_REQUIRE_ENCRYPTED_STORE=1 \
  NODEWE_REQUIRE_SIGNED_GRANTS=1 \
  NODEWE_REQUIRE_APPROVAL_RECORDS=1 \
  NODEWE_OIDC_REQUIRED=1 \
  NODEWE_OIDC_ISSUER=https://id.example.invalid/ \
  NODEWE_OIDC_AUDIENCE=nodewe-cli \
  NODEWE_OIDC_HS256_SECRET_FILE=/run/secrets/nodewe-oidc-hs256 \
  NODEWE_TLS_PROXY_APPROVED=1 \
  "$PKG/scripts/preflight-production.sh"
```

For production-like approval flow, create an Approval Record first and pass
its ID to `task submit`:

```bash
APPROVAL_JSON=$("$PKG/nodewe" approval create \
  --node lab-a --program echo --argument 'approved staging task')
APPROVAL_ID=$(printf '%s' "$APPROVAL_JSON" | jq -r .approval_id)
"$PKG/nodewe" task submit \
  --node lab-a --ability task.exec \
  --program echo --argument 'approved staging task' \
  --approval-id "$APPROVAL_ID" --output-limit 4096
```

## Shutdown and cleanup

Stop the Agent with Ctrl-C. Stop the local Control Plane with Ctrl-C, then
remove only the temporary directories created for the run. Never reuse staging
tokens or copy them into an Agent environment file; use Grant-only enrollment
and a mode-0600 Node credential file.

The current 0.1.0 CLI has local group orchestration for explicit Node sets and
labels. For Control Plane-backed staging, submit each target Node explicitly;
do not infer a target from a similar name or label.
