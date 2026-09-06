#!/usr/bin/env bash
set -euo pipefail

root_dir=$(cd "$(dirname "$0")/.." && pwd)
bin_dir=${NODEWE_BIN_DIR:-"$root_dir/target/debug"}
admin_token=${NODEWE_TEST_ADMIN_TOKEN:-nodewe-integration-admin}
grant_secret=${NODEWE_TEST_GRANT_SECRET:-nodewe-integration-grant}
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/nodewe-integration.XXXXXX")
port=$((18000 + ($$ % 1000)))
endpoint="127.0.0.1:$port"
cp_pid=""
agent_pid=""

cleanup() {
  if [[ -n "$agent_pid" ]]; then kill "$agent_pid" 2>/dev/null || true; wait "$agent_pid" 2>/dev/null || true; fi
  if [[ -n "$cp_pid" ]]; then kill "$cp_pid" 2>/dev/null || true; wait "$cp_pid" 2>/dev/null || true; fi
  if [[ "${NODEWE_KEEP_INTEGRATION_ARTIFACTS:-0}" == 1 ]]; then
    echo "integration artifacts: $test_dir" >&2
  else
    rm -rf "$test_dir"
  fi
}
trap cleanup EXIT

for binary in node-control-plane node-runtime; do
  [[ -x "$bin_dir/$binary" ]] || {
    echo "missing $bin_dir/$binary; build the workspace first or set NODEWE_BIN_DIR" >&2
    exit 1
  }
done
command -v curl >/dev/null || { echo "curl is required" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }

NODEWE_ADMIN_TOKEN="$admin_token" \
NODEWE_GRANT_SECRET="$grant_secret" \
NODEWE_DATA_DIR="$test_dir/control-plane" \
NODEWE_BIND="$endpoint" \
NODEWE_NODE_ONLINE_TTL_MS=1200 \
  "$bin_dir/node-control-plane" >"$test_dir/control-plane.log" 2>&1 &
cp_pid=$!

for _ in {1..50}; do
  curl -fsS "http://$endpoint/health" >/dev/null 2>&1 && break
  sleep 0.1
done
curl -fsS "http://$endpoint/health" | jq -e '.status == "ok"' >/dev/null

admin_header=( -H "Authorization: Bearer $admin_token" -H 'Content-Type: application/json' )
curl -fsS -X POST "http://$endpoint/v1/grants" "${admin_header[@]}" -d '{}' >"$test_dir/grant.json"
grant_code=$(jq -r .grant_code "$test_dir/grant.json")
grant_signature=$(jq -r .grant_signature "$test_dir/grant.json")
[[ -n "$grant_code" && "$grant_code" != null && -n "$grant_signature" && "$grant_signature" != null ]]
mkdir "$test_dir/scope"

"$bin_dir/node-runtime" enroll \
  --endpoint "$endpoint" \
  --node-id integration-a \
  --name "Integration A" \
  --labels lab \
  --grant-code "$grant_code" \
  --grant-signature "$grant_signature" \
  --token-file "$test_dir/node.token" \
  >"$test_dir/enroll.json"
jq -e '.node_id == "integration-a" and .enrolled == true' "$test_dir/enroll.json" >/dev/null
chmod 600 "$test_dir/node.token"
curl -fsS "http://$endpoint/v1/nodes" "${admin_header[@]}" >"$test_dir/node.json"
jq -e '.[0].node_id == "integration-a" and (.[0].credential | not)' "$test_dir/node.json" >/dev/null

NODEWE_NODE_TOKEN_FILE="$test_dir/node.token" \
  "$bin_dir/node-runtime" connect --endpoint "$endpoint" --node-id integration-a \
  --scope "$test_dir/scope" --transport polling --interval-ms 100 \
  >"$test_dir/agent.log" 2>&1 &
agent_pid=$!

for _ in {1..50}; do
  online=$(curl -fsS "http://$endpoint/v1/nodes" "${admin_header[@]}" | jq -r '.[0].online')
  [[ "$online" == true ]] && break
  sleep 0.1
done
[[ "$online" == true ]]

curl -fsS "http://$endpoint/v1/tasks" "${admin_header[@]}" \
  -d '{"request_id":"integration-request-1","node_id":"integration-a","ability":"task.exec","program":"printf","argument":"hello},{世界","approved":true,"output_limit":4096}' \
  >"$test_dir/task.json"
task_id=$(jq -r .task_id "$test_dir/task.json")
for _ in {1..50}; do
  curl -fsS "http://$endpoint/v1/tasks/$task_id" "${admin_header[@]}" >"$test_dir/task-status.json"
  state=$(jq -r .state "$test_dir/task-status.json")
  [[ "$state" == succeeded ]] && break
  sleep 0.1
done
jq -e '.state == "succeeded" and .output == "hello},{世界" and (.output_sha256 | length == 64)' "$test_dir/task-status.json" >/dev/null

kill "$agent_pid"
wait "$agent_pid" 2>/dev/null || true
agent_pid=""
sleep 1.5
if curl -sS "http://$endpoint/v1/tasks" "${admin_header[@]}" \
  -d '{"request_id":"integration-request-stale","node_id":"integration-a","ability":"task.exec","program":"echo","argument":"stale","approved":true}' \
  -o "$test_dir/stale.json" -w '%{http_code}' | grep -q '^409$'; then
  :
else
  echo "stale node accepted a new task" >&2
  exit 1
fi

NODEWE_NODE_TOKEN_FILE="$test_dir/node.token" \
  "$bin_dir/node-runtime" connect --endpoint "$endpoint" --node-id integration-a \
  --scope "$test_dir/scope" --transport websocket --interval-ms 100 \
  >"$test_dir/agent-reconnect.log" 2>&1 &
agent_pid=$!
for _ in {1..50}; do
  online=$(curl -fsS "http://$endpoint/v1/nodes" "${admin_header[@]}" | jq -r '.[0].online')
  [[ "$online" == true ]] && break
  sleep 0.1
done
[[ "$online" == true ]]

curl -fsS "http://$endpoint/v1/tasks" "${admin_header[@]}" \
  -d '{"request_id":"integration-request-websocket","node_id":"integration-a","ability":"task.exec","program":"printf","argument":"websocket-ok","approved":true,"output_limit":4096}' \
  >"$test_dir/websocket-task.json"
websocket_task_id=$(jq -r .task_id "$test_dir/websocket-task.json")
for _ in {1..50}; do
  curl -fsS "http://$endpoint/v1/tasks/$websocket_task_id" "${admin_header[@]}" >"$test_dir/websocket-status.json"
  websocket_state=$(jq -r .state "$test_dir/websocket-status.json")
  [[ "$websocket_state" == succeeded ]] && break
  sleep 0.1
done
jq -e '.state == "succeeded" and .output == "websocket-ok"' "$test_dir/websocket-status.json" >/dev/null

curl -fsS "http://$endpoint/v1/nodes/integration-a/revoke" "${admin_header[@]}" -d '{}' \
  | jq -e '.revoked == true' >/dev/null
if curl -sS "http://$endpoint/v1/tasks" "${admin_header[@]}" \
  -d '{"request_id":"integration-request-revoked","node_id":"integration-a","ability":"task.exec","program":"echo","argument":"revoked","approved":true}' \
  -o "$test_dir/revoked.json" -w '%{http_code}' | grep -q '^409$'; then
  :
else
  echo "revoked node accepted a new task" >&2
  exit 1
fi

echo "NodeWe integration test passed: heartbeat, task execution, output hash, TTL, reconnect, and revoke"
