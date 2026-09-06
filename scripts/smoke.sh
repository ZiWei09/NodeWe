#!/usr/bin/env bash
set -euo pipefail

root_dir=$(cd "$(dirname "$0")/.." && pwd)
toolchain=${RUSTUP_TOOLCHAIN:-1.95}
cargo_bin=${CARGO_BIN:-cargo}
smoke_dir=$(mktemp -d "${TMPDIR:-/tmp}/nodewe-smoke.XXXXXX")
trap 'rm -rf "$smoke_dir"' EXIT

run_cli() {
  NODEWE_HOME="$smoke_dir" RUSTUP_TOOLCHAIN="$toolchain" "$cargo_bin" \
    run --quiet --manifest-path "$root_dir/Cargo.toml" -p node-control-cli --bin nodewe -- "$@"
}

run_cli --version
run_cli --profile staging --output json --non-interactive auth login
run_cli --profile staging node pair --id smoke-a --name "Smoke A" --labels cpu,lab
run_cli --profile staging node pair --id smoke-b --name "Smoke B" --labels gpu,lab
run_cli --profile staging group create --id gpu-labs --label gpu
run_cli --profile staging group run --group gpu-labs --scope "$smoke_dir" -- echo group-ok
run_cli --profile staging task run --node smoke-a --scope "$smoke_dir" -- echo smoke-ok
run_cli --profile staging audit list

test -f "$smoke_dir/profiles/staging/session"
test -f "$smoke_dir/profiles/staging/audit.jsonl"
echo "NodeWe CLI smoke passed"
