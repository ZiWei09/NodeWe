#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf 'usage: %s --endpoint URL --output-dir DIR [--token-file FILE | --token TOKEN] [--page-size N]\n' "$0" >&2
  exit 2
}

endpoint=
output_dir=
token_file=
token_value=
page_size=1000
while (($#)); do
  case "$1" in
    --endpoint) [[ $# -ge 2 ]] || usage; endpoint=$2; shift 2 ;;
    --output-dir) [[ $# -ge 2 ]] || usage; output_dir=$2; shift 2 ;;
    --token-file) [[ $# -ge 2 ]] || usage; token_file=$2; shift 2 ;;
    --token) [[ $# -ge 2 ]] || usage; token_value=$2; shift 2 ;;
    --page-size) [[ $# -ge 2 ]] || usage; page_size=$2; shift 2 ;;
    *) usage ;;
  esac
done

[[ -n "$endpoint" && -n "$output_dir" ]] || usage
[[ -z "$token_file" || -z "$token_value" ]] || {
  printf 'choose --token-file or --token, not both\n' >&2
  exit 2
}
if [[ -n "$token_file" ]]; then
  [[ -r "$token_file" ]] || { printf 'token file is not readable: %s\n' "$token_file" >&2; exit 1; }
  token_value=$(tr -d '[:space:]' < "$token_file")
  mode=$(stat -f '%Lp' "$token_file" 2>/dev/null || stat -c '%a' "$token_file" 2>/dev/null || true)
  [[ "$mode" == 600 || "$mode" == 400 ]] || {
    printf 'token file must be mode 0600 or 0400 (got %s)\n' "$mode" >&2
    exit 1
  }
fi
[[ -n "$token_value" ]] || { printf 'a non-empty token is required\n' >&2; exit 1; }
[[ "$token_value" != *$'\r'* && "$token_value" != *$'\n'* && "$token_value" != *'"'* && "$token_value" != *'\\'* ]] || {
  printf 'token contains an unsafe HTTP/config character\n' >&2
  exit 1
}
[[ "$page_size" =~ ^[1-9][0-9]*$ && "$page_size" -le 10000 ]] || {
  printf '--page-size must be between 1 and 10000\n' >&2
  exit 1
}
case "$endpoint" in
  https://*) curl_proto=(--proto '=https' --tlsv1.2) ;;
  http://127.0.0.1:*|http://localhost:*|http://\[::1\]:*)
    [[ "${NODEWE_ALLOW_INSECURE_HTTP:-0}" == 1 ]] || {
      printf 'refusing plaintext audit export; use HTTPS or explicitly enable loopback development HTTP\n' >&2
      exit 1
    }
    curl_proto=()
    ;;
  *)
    printf 'audit export endpoint must use https:// (or explicitly allowed loopback http://)\n' >&2
    exit 1
    ;;
esac
command -v curl >/dev/null 2>&1 || { printf 'curl is required\n' >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { printf 'jq is required for audit validation\n' >&2; exit 1; }
command -v shasum >/dev/null 2>&1 || { printf 'shasum is required\n' >&2; exit 1; }

mkdir -p "$output_dir"
chmod 700 "$output_dir"
run_stamp=$(date +%Y%m%d%H%M%S)
export_dir="$output_dir/export-$run_stamp-$$"
mkdir "$export_dir"
chmod 700 "$export_dir"
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/nodewe-audit-export.XXXXXX")
trap 'rm -rf "$work_dir"' EXIT
curl_config="$work_dir/curl.conf"
printf 'header = "Authorization: Bearer %s"\n' "$token_value" > "$curl_config"
chmod 600 "$curl_config"

from=0
page=0
previous_hash=GENESIS
while :; do
  response="$work_dir/page.json"
  curl --fail --silent --show-error --config "$curl_config" "${curl_proto[@]}" \
    "$endpoint/v1/audit/export?from=$from&limit=$page_size" > "$response"
  jq -e '(.protocol_version == 1) and (.records | type == "array") and (.count == (.records | length))' "$response" >/dev/null
  while IFS=$'\t' read -r activity_id event node_id task_id actor timestamp prev_hash hash; do
    [[ "$node_id" == __NODEWE_NULL__ ]] && node_id=
    [[ "$task_id" == __NODEWE_NULL__ ]] && task_id=
    [[ "$actor" == __NODEWE_NULL__ ]] && actor=
    [[ "$prev_hash" == "$previous_hash" ]] || {
      printf 'audit chain discontinuity at activity %s\n' "$activity_id" >&2
      exit 1
    }
    if [[ -n "$actor" ]]; then
      expected=$(printf '%s\n%s\n%s\n%s\n%s\n%s\n%s' "$activity_id" "$event" "$node_id" "$task_id" "$actor" "$timestamp" "$previous_hash" | shasum -a 256 | awk '{print $1}')
    else
      # Records created before actor binding used the original six-field
      # canonical form and remain verifiable after upgrade.
      expected=$(printf '%s\n%s\n%s\n%s\n%s\n%s' "$activity_id" "$event" "$node_id" "$task_id" "$timestamp" "$previous_hash" | shasum -a 256 | awk '{print $1}')
    fi
    [[ "$hash" == "$expected" ]] || {
      printf 'audit hash mismatch at activity %s\n' "$activity_id" >&2
      exit 1
    }
    previous_hash=$hash
  done < <(jq -r '.records[] | [(.activity_id // "__NODEWE_NULL__"),(.event // "__NODEWE_NULL__"),(.node_id // "__NODEWE_NULL__"),(.task_id // "__NODEWE_NULL__"),(.actor // "__NODEWE_NULL__"),(.timestamp|tostring),(.prev_hash // "__NODEWE_NULL__"),(.hash // "__NODEWE_NULL__")] | @tsv' "$response")

  target="$export_dir/audit-$(printf '%06d' "$page").json"
  temporary="$target.tmp.$$"
  cp "$response" "$temporary"
  chmod 600 "$temporary"
  mv "$temporary" "$target"
  shasum -a 256 "$target" > "$target.sha256"
  chmod 600 "$target.sha256"

  next=$(jq -r '.next // empty' "$response")
  if [[ -z "$next" || "$next" == "null" ]]; then
    break
  fi
  [[ "$next" =~ ^[0-9]+$ && "$next" -gt "$from" ]] || {
    printf 'invalid audit pagination cursor: %s\n' "$next" >&2
    exit 1
  }
  from=$next
  page=$((page + 1))
done
printf 'NodeWe audit export verified: %d page(s), final hash %s; archive=%s\n' "$((page + 1))" "$previous_hash" "$export_dir"
