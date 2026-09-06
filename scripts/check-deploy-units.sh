#!/usr/bin/env bash
set -euo pipefail

root_dir=$(cd "$(dirname "$0")/.." && pwd)

check_unit() {
  local unit=$1
  local expected_user=$2
  local path="$root_dir/deploy/$unit"
  [[ -r "$path" ]] || { printf 'missing unit: %s\n' "$path" >&2; exit 1; }
  grep -Fxq "User=$expected_user" "$path" || { printf '%s must run as %s\n' "$unit" "$expected_user" >&2; exit 1; }
  grep -Fxq 'Group='$expected_user "$path" || { printf '%s must use group %s\n' "$unit" "$expected_user" >&2; exit 1; }
  for directive in \
    NoNewPrivileges=true PrivateTmp=true PrivateDevices=true ProtectSystem=strict \
    ProtectHome=true ProtectProc=invisible ProcSubset=pid RestrictNamespaces=true \
    LockPersonality=true MemoryDenyWriteExecute=true CapabilityBoundingSet= \
    AmbientCapabilities= UMask=0077; do
    grep -Fxq "$directive" "$path" || {
      printf '%s missing required hardening: %s\n' "$unit" "$directive" >&2
      exit 1
    }
  done
}

grep -Fxq 'ExecStartPre=/opt/nodewe/current/scripts/preflight-production.sh' \
  "$root_dir/deploy/nodewe-control-plane.service" || {
  printf 'control-plane unit must run the production preflight before startup\n' >&2
  exit 1
}
grep -Fxq 'ExecStart=/opt/nodewe/current/node-control-plane' \
  "$root_dir/deploy/nodewe-control-plane.service" || {
  printf 'control-plane unit must execute the SHA-verified current release symlink\n' >&2
  exit 1
}

check_unit nodewe-agent.service nodewe-agent
check_unit nodewe-control-plane.service nodewe
printf 'NodeWe systemd unit hardening checks passed.\n'
