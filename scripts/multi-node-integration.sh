#!/usr/bin/env bash
set -euo pipefail

root_dir=$(cd "$(dirname "$0")/.." && pwd)
bin_dir=${NODEWE_BIN_DIR:-"$root_dir/target/debug"}
admin_token=${NODEWE_TEST_ADMIN_TOKEN:-nodewe-multi-admin}
grant_secret=${NODEWE_TEST_GRANT_SECRET:-nodewe-multi-grant}
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/nodewe-multi.XXXXXX")
port=$((19000 + ($$ % 1000)))
endpoint="127.0.0.1:$port"
cp_pid=""
agent_pids=()

cleanup() {
  for pid in "${agent_pids[@]}"; do
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  if [[ -n "$cp_pid" ]]; then
    kill "$cp_pid" 2>/dev/null || true
    wait "$cp_pid" 2>/dev/null || true
  fi
  rm -rf "$test_dir"
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
  "$bin_dir/node-control-plane" >"$test_dir/control-plane.log" 2>&1 &
cp_pid=$!

for _ in {1..50}; do
  curl -fsS "http://$endpoint/health" >/dev/null 2>&1 && break
  sleep 0.1
done
curl -fsS "http://$endpoint/health" | jq -e '.status == "ok"' >/dev/null

admin_header=( -H "Authorization: Bearer $admin_token" -H 'Content-Type: application/json' )

task_pids=()
for node_id in node-a node-b node-c; do
  scope="$test_dir/$node_id"
  mkdir "$scope"
  curl -fsS -X POST "http://$endpoint/v1/grants" "${admin_header[@]}" -d '{}' >"$test_dir/$node_id.grant.json"
  grant_code=$(jq -r .grant_code "$test_dir/$node_id.grant.json")
  grant_signature=$(jq -r .grant_signature "$test_dir/$node_id.grant.json")
  "$bin_dir/node-runtime" enroll \
    --endpoint "$endpoint" \
    --node-id "$node_id" \
    --name "Local $node_id" \
    --labels lab \
    --grant-code "$grant_code" \
    --grant-signature "$grant_signature" \
    --token-file "$test_dir/$node_id.token" \
    >"$test_dir/$node_id.enroll.json"
  jq -e ".node_id == \"$node_id\" and .enrolled == true" "$test_dir/$node_id.enroll.json" >/dev/null
  NODEWE_NODE_TOKEN_FILE="$test_dir/$node_id.token" \
    "$bin_dir/node-runtime" connect \
      --endpoint "$endpoint" \
      --node-id "$node_id" \
      --scope "$scope" \
      --transport polling \
      --interval-ms 100 \
      >"$test_dir/$node_id.agent.log" 2>&1 &
  agent_pids+=("$!")
done

for node_id in node-a node-b node-c; do
  online=false
  for _ in {1..50}; do
    online=$(curl -fsS "http://$endpoint/v1/nodes" "${admin_header[@]}" | jq -r --arg id "$node_id" '.[] | select(.node_id == $id) | .online')
    [[ "$online" == true ]] && break
    sleep 0.1
  done
  [[ "$online" == true ]] || { echo "$node_id did not become online" >&2; exit 1; }
done

for node_id in node-a node-b node-c; do
  curl -fsS -X POST "http://$endpoint/v1/tasks" "${admin_header[@]}" \
    -d "{\"request_id\":\"multi-$node_id\",\"node_id\":\"$node_id\",\"ability\":\"task.exec\",\"program\":\"printf\",\"argument\":\"marker-$node_id\",\"approved\":true,\"output_limit\":4096}" \
    >"$test_dir/$node_id.task.json" &
  task_pids+=("$!")
done
for pid in "${task_pids[@]}"; do
  wait "$pid"
done

for node_id in node-a node-b node-c; do
  task_id=$(jq -r .task_id "$test_dir/$node_id.task.json")
  for _ in {1..50}; do
    curl -fsS "http://$endpoint/v1/tasks/$task_id" "${admin_header[@]}" >"$test_dir/$node_id.status.json"
    state=$(jq -r .state "$test_dir/$node_id.status.json")
    [[ "$state" == succeeded ]] && break
    sleep 0.1
  done
  jq -e --arg id "$node_id" --arg marker "marker-$node_id" \
    '.state == "succeeded" and .node_id == $id and .output == $marker' \
    "$test_dir/$node_id.status.json" >/dev/null
done

curl -fsS -X POST "http://$endpoint/v1/nodes/node-b/revoke" "${admin_header[@]}" -d '{}' \
  | jq -e '.revoked == true' >/dev/null
if curl -sS -X POST "http://$endpoint/v1/tasks" "${admin_header[@]}" \
  -d '{"request_id":"multi-revoked-b","node_id":"node-b","ability":"task.exec","program":"echo","argument":"must-fail","approved":true}' \
  -o "$test_dir/revoked.json" -w '%{http_code}' | grep -q '^409$'; then
  :
else
  echo "revoked node accepted a new task" >&2
  exit 1
fi

for node_id in node-a node-c; do
  curl -fsS -X POST "http://$endpoint/v1/tasks" "${admin_header[@]}" \
    -d "{\"request_id\":\"after-revoke-$node_id\",\"node_id\":\"$node_id\",\"ability\":\"task.exec\",\"program\":\"printf\",\"argument\":\"still-alive-$node_id\",\"approved\":true,\"output_limit\":4096}" \
    >"$test_dir/$node_id.after.json"
  task_id=$(jq -r .task_id "$test_dir/$node_id.after.json")
  for _ in {1..50}; do
    curl -fsS "http://$endpoint/v1/tasks/$task_id" "${admin_header[@]}" >"$test_dir/$node_id.after.status.json"
    state=$(jq -r .state "$test_dir/$node_id.after.status.json")
    [[ "$state" == succeeded ]] && break
    sleep 0.1
  done
  jq -e --arg id "$node_id" '.state == "succeeded" and .node_id == $id' "$test_dir/$node_id.after.status.json" >/dev/null
done

echo "NodeWe multi-node integration passed: 3-node parallel routing, isolation, revoke, and survivor execution"
