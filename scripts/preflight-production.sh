#!/usr/bin/env bash
set -euo pipefail

errors=0
fail() {
  printf 'ERROR: %s\n' "$1" >&2
  errors=$((errors + 1))
}

if [[ "${NODEWE_ENV:-}" != production ]]; then
  fail 'NODEWE_ENV=production is required for the production preflight'
fi

require_value() {
  local name=$1
  local file_name="${name}_FILE"
  if [[ -n "${!file_name:-}" ]]; then
    if [[ ! -r "${!file_name}" ]]; then
      fail "$file_name must point to a readable secret file"
    else
      local mode
      mode=$(stat -f '%Lp' "${!file_name}" 2>/dev/null || stat -c '%a' "${!file_name}" 2>/dev/null || true)
      if [[ -n "$mode" && "$mode" != 600 && "$mode" != 400 ]]; then
        fail "$file_name must be mode 0600 or 0400 (got $mode)"
      fi
    fi
    return
  fi
  if [[ -z "${!name:-}" || "${!name}" == replace-with-* || "${!name}" == change-me* ]]; then
    fail "$name must be supplied by the deployment secret manager"
  fi
}
require_file() {
  local name=$1
  local path=${!name:-}
  if [[ -z "$path" || ! -r "$path" ]]; then
    fail "$name must point to a readable certificate/key file"
  fi
}

require_value NODEWE_ADMIN_TOKEN
require_value NODEWE_GRANT_SECRET
require_value NODEWE_DATA_DIR
require_value NODEWE_STORE_KEY
require_value NODEWE_GRANT_SIGNING_KEY

bind_host=${NODEWE_BIND:-127.0.0.1:8787}
bind_host=${bind_host%:*}
case "$bind_host" in
  127.*|localhost|::1|'[::1]') ;;
  *)
    if [[ "${NODEWE_ALLOW_PRIVATE_BIND:-0}" != 1 ]]; then
      fail 'NODEWE_BIND is not loopback; set NODEWE_ALLOW_PRIVATE_BIND=1 only for an approved private deployment'
    fi
    ;;
esac

if [[ "${NODEWE_REQUIRE_ENCRYPTED_STORE:-0}" != 1 ]]; then
  fail 'NODEWE_REQUIRE_ENCRYPTED_STORE=1 is required'
fi
if [[ "${NODEWE_REQUIRE_SIGNED_GRANTS:-0}" != 1 ]]; then
  fail 'NODEWE_REQUIRE_SIGNED_GRANTS=1 is required'
fi
if [[ "${NODEWE_REQUIRE_APPROVAL_RECORDS:-0}" != 1 ]]; then
  fail 'NODEWE_REQUIRE_APPROVAL_RECORDS=1 is required'
fi
auth_mode=${NODEWE_AUTH_MODE:-}
if [[ -z "$auth_mode" ]]; then
  if [[ "${NODEWE_OIDC_REQUIRED:-0}" == 1 ]]; then auth_mode=oidc; else auth_mode=token; fi
fi
if [[ "$auth_mode" != token && "$auth_mode" != oidc ]]; then
  fail 'NODEWE_AUTH_MODE must be token or oidc'
fi
if [[ "$auth_mode" == oidc && "${NODEWE_OIDC_REQUIRED:-0}" != 1 ]]; then
  fail 'NODEWE_OIDC_REQUIRED=1 is required when NODEWE_AUTH_MODE=oidc'
fi

oidc_configured=0
if [[ -n "${NODEWE_OIDC_ISSUER:-}" || -n "${NODEWE_OIDC_AUDIENCE:-}" || -n "${NODEWE_OIDC_HS256_SECRET:-}" || -n "${NODEWE_OIDC_HS256_SECRET_FILE:-}" ]]; then
  oidc_configured=1
fi
if [[ "$auth_mode" == oidc || "$oidc_configured" == 1 ]]; then
  if [[ -z "${NODEWE_OIDC_ISSUER:-}" ]]; then
    fail 'NODEWE_OIDC_ISSUER is required when OIDC is configured'
  fi
  if [[ -z "${NODEWE_OIDC_AUDIENCE:-}" ]]; then
    fail 'NODEWE_OIDC_AUDIENCE is required when OIDC is configured'
  fi
  if [[ -n "${NODEWE_OIDC_ISSUER:-}" && ! "${NODEWE_OIDC_ISSUER}" =~ ^https:// ]]; then
    fail 'NODEWE_OIDC_ISSUER must use https:// in production'
  fi
  require_value NODEWE_OIDC_HS256_SECRET
  if [[ -n "${NODEWE_OIDC_HS256_SECRET_FILE:-}" ]]; then
    oidc_secret_value=$(tr -d '[:space:]' < "$NODEWE_OIDC_HS256_SECRET_FILE" 2>/dev/null || true)
  else
    oidc_secret_value=${NODEWE_OIDC_HS256_SECRET:-}
  fi
  if [[ ${#oidc_secret_value} -lt 32 ]]; then
    fail 'NODEWE_OIDC_HS256_SECRET must contain at least 32 bytes'
  fi
  oidc_admin_group=${NODEWE_OIDC_ADMIN_GROUP:-nodewe-admin}
  oidc_group_claim=${NODEWE_OIDC_GROUP_CLAIM:-groups}
  if [[ ! "$oidc_admin_group" =~ ^[A-Za-z0-9_.-]{1,128}$ || ! "$oidc_group_claim" =~ ^[A-Za-z0-9_.-]{1,128}$ ]]; then
    fail 'NODEWE_OIDC_ADMIN_GROUP and NODEWE_OIDC_GROUP_CLAIM must be safe claim names'
  fi
fi

if [[ -n "${NODEWE_STORE_KEY_FILE:-}" ]]; then
  store_key_value=$(tr -d '[:space:]' < "$NODEWE_STORE_KEY_FILE" 2>/dev/null || true)
else
  store_key_value=${NODEWE_STORE_KEY:-}
fi
if [[ ! "$store_key_value" =~ ^[0-9a-fA-F]{64}$ ]]; then
  fail 'NODEWE_STORE_KEY must be exactly 32 bytes encoded as 64 hex characters'
fi
if [[ -n "${NODEWE_GRANT_SIGNING_KEY_FILE:-}" ]]; then
  grant_key_value=$(tr -d '[:space:]' < "$NODEWE_GRANT_SIGNING_KEY_FILE" 2>/dev/null || true)
else
  grant_key_value=${NODEWE_GRANT_SIGNING_KEY:-}
fi
if [[ -n "$grant_key_value" && ! "$grant_key_value" =~ ^[0-9a-fA-F]+$ ]]; then
  fail 'NODEWE_GRANT_SIGNING_KEY must be PKCS#8 bytes encoded as hex'
fi
if [[ -n "$grant_key_value" && "$grant_key_value" =~ ^[0-9a-fA-F]+$ ]]; then
  if ! command -v xxd >/dev/null 2>&1 || ! printf '%s' "$grant_key_value" | xxd -r -p | openssl pkey -inform DER -text -noout 2>/dev/null | grep -qi ed25519; then
    fail 'NODEWE_GRANT_SIGNING_KEY is not a valid Ed25519 PKCS#8 private key'
  fi
fi
if [[ -n "${NODEWE_GRANT_SIGNING_KEY_PREVIOUS_FILE:-}" ]]; then
  previous_key_value=$(tr -d '[:space:]' < "$NODEWE_GRANT_SIGNING_KEY_PREVIOUS_FILE" 2>/dev/null || true)
else
  previous_key_value=${NODEWE_GRANT_SIGNING_KEY_PREVIOUS:-}
fi
if [[ -n "$previous_key_value" && ! "$previous_key_value" =~ ^[0-9a-fA-F]+$ ]]; then
  fail 'NODEWE_GRANT_SIGNING_KEY_PREVIOUS must be PKCS#8 bytes encoded as hex'
fi

if [[ -z "${NODEWE_TLS_CERT:-}" && -z "${NODEWE_TLS_KEY:-}" && -z "${NODEWE_TLS_CLIENT_CA:-}" ]]; then
  if [[ "${NODEWE_TLS_PROXY_APPROVED:-0}" != 1 ]]; then
    fail 'native TLS/mTLS files are required unless NODEWE_TLS_PROXY_APPROVED=1 documents an approved TLS/mTLS proxy'
  else
    printf 'WARNING: relying on an approved external TLS/mTLS proxy; verify its config and rotation policy separately.\n' >&2
  fi
else
  require_file NODEWE_TLS_CERT
  require_file NODEWE_TLS_KEY
  require_file NODEWE_TLS_CLIENT_CA
fi

if [[ -n "${NODEWE_DATA_DIR:-}" ]]; then
  if [[ ! -d "$NODEWE_DATA_DIR" ]]; then
    fail "NODEWE_DATA_DIR does not exist: $NODEWE_DATA_DIR"
  elif [[ ! -w "$NODEWE_DATA_DIR" ]]; then
    fail "NODEWE_DATA_DIR is not writable by the service account: $NODEWE_DATA_DIR"
  fi
fi

if [[ -n "${NODEWE_POLICY_FILE:-}" && ! -r "${NODEWE_POLICY_FILE}" ]]; then
  fail "NODEWE_POLICY_FILE must point to a readable policy file"
fi

if (( errors > 0 )); then
  printf 'NodeWe production preflight failed with %d error(s).\n' "$errors" >&2
  exit 1
fi
printf 'NodeWe production preflight passed.\n'
