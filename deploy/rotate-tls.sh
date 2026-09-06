#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf 'usage: %s --tls-dir DIR --cert FILE --key FILE --client-ca FILE [--service NAME] [--dry-run]\n' "$0" >&2
  exit 2
}

tls_dir=
cert=
key=
client_ca=
service_name=nodewe-control-plane
dry_run=0
while (($#)); do
  case "$1" in
    --tls-dir) [[ $# -ge 2 ]] || usage; tls_dir=$2; shift 2 ;;
    --cert) [[ $# -ge 2 ]] || usage; cert=$2; shift 2 ;;
    --key) [[ $# -ge 2 ]] || usage; key=$2; shift 2 ;;
    --client-ca) [[ $# -ge 2 ]] || usage; client_ca=$2; shift 2 ;;
    --service) [[ $# -ge 2 ]] || usage; service_name=$2; shift 2 ;;
    --dry-run) dry_run=1; shift ;;
    *) usage ;;
  esac
done

[[ -n "$tls_dir" && -n "$cert" && -n "$key" && -n "$client_ca" ]] || usage
for input in "$cert" "$key" "$client_ca"; do
  [[ -f "$input" && -r "$input" ]] || {
    printf 'TLS rotation input is not a readable file: %s\n' "$input" >&2
    exit 1
  }
done
command -v openssl >/dev/null 2>&1 || {
  printf 'openssl is required for certificate validation\n' >&2
  exit 1
}
openssl x509 -in "$cert" -noout -checkend 0 >/dev/null
cert_pub=$(openssl x509 -in "$cert" -pubkey -noout | openssl pkey -pubin -outform DER | shasum -a 256 | awk '{print $1}')
key_pub=$(openssl pkey -in "$key" -pubout 2>/dev/null | openssl pkey -pubin -outform DER | shasum -a 256 | awk '{print $1}')
[[ -n "$cert_pub" && "$cert_pub" == "$key_pub" ]] || {
  printf 'TLS certificate and private key do not match\n' >&2
  exit 1
}
openssl x509 -in "$client_ca" -noout -subject >/dev/null

mkdir -p "$tls_dir"
chmod 700 "$tls_dir"
stamp=$(date +%Y%m%d%H%M%S)
stage="$tls_dir/.rotation.$stamp.$$"
backup="$tls_dir/previous.$stamp"
mkdir "$stage"
trap 'rm -rf "$stage"' EXIT
install -m 0644 "$cert" "$stage/server-chain.pem"
install -m 0600 "$key" "$stage/server-key.pem"
install -m 0644 "$client_ca" "$stage/agent-ca.pem"

if ((dry_run)); then
  printf 'TLS rotation validated (dry-run); would install into %s\n' "$tls_dir"
  exit 0
fi

if [[ -e "$tls_dir/server-chain.pem" || -e "$tls_dir/server-key.pem" || -e "$tls_dir/agent-ca.pem" ]]; then
  mkdir "$backup"
  for name in server-chain.pem server-key.pem agent-ca.pem; do
    [[ -e "$tls_dir/$name" ]] && mv "$tls_dir/$name" "$backup/$name"
  done
  chmod 700 "$backup"
fi
for name in server-chain.pem server-key.pem agent-ca.pem; do
  mv "$stage/$name" "$tls_dir/$name"
done
rmdir "$stage"
trap - EXIT

if [[ "${NODEWE_SKIP_RESTART:-0}" != 1 ]] && command -v systemctl >/dev/null 2>&1; then
  systemctl reload-or-restart "$service_name"
fi
printf 'NodeWe TLS material rotated in %s; previous material: %s\n' "$tls_dir" "$backup"
