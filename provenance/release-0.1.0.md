# NodeWe 0.1.0 release record

- Source: NodeWe implementation in this repository and its reviewed dependencies.
- Toolchain: Rust 1.95.0.
- Runtime dependencies: rustls 0.23.43 with rustls-pki-types 1.15.1 and ring
  0.17.14 for native TLS/mTLS, plus serde_json 1.0.151 for strict Control Plane
  request parsing; the application layer remains dependency-light.
- Binaries: `node-runtime`, `nodewe`, `node-control-plane`.
- Verification: `cargo fmt --all -- --check`, `cargo clippy --all-targets --locked -- -D warnings`,
  `cargo test --locked --offline`, `cargo build --release --bins --locked --offline`,
  `./scripts/check-deploy-units.sh`, `./scripts/smoke.sh`, `./scripts/preflight-production.sh` (with staging
  secrets), release SHA-256 verification, and local native WSS+mTLS
  Runtime↔Control Plane heartbeat/task smoke all pass in the build environment.
  The 68-test suite also covers RFC 6455 accept-key validation, Scope-bound
  file read/write behavior, Ed25519 grant
  verification, encrypted snapshot tamper rejection, audit hash-chain
  recovery, credential rotation, protocol/capability negotiation, and
  reconnect backoff behavior. Dispatch lease fencing tests prove a stale
  Agent result is rejected after reclaim, policy tests prove data-class and
  ability restrictions fail closed, and audit export tests prove bounded
  pagination with chain-preserving records, bounded task timeout/lease
  propagation, idempotency binding to actor and timeout, OIDC HS256 claim
  verification and actor binding, actor-bound Activity hash records,
  single-writer snapshot locking, and
  mode-restricted Node/CLI token-file injection.
  The verification set also includes native CLI mTLS, Grant-only enrollment,
  Scope metadata listing, bounded Control Plane connection handling, bounded
  client response readers, strict Content-Length parsing, and verified
  external audit archive export.
  Control Plane task results are persisted as a 4 KiB preview plus a
  SHA-256 digest, not complete command output.
- Artifact directory: `dist/nodewe-0.1.0-aarch64-apple-darwin/` (binaries plus the
  `deploy/`, `scripts/` and `spec/` operational kit).
- SHA-256: `nodewe` = `47907491a345dab08db5264a7ea462799de74cec625c933c35a96a041b07dfec`;
  `node-runtime` = `4ba3f475d14df2ebb14b67bcc7dbd413ba0c89265d524797c0577a5767d69901`;
  `node-control-plane` = `6c95bdcb5599cc14fda5d939e6ec604797c872942978d46006c87fc848042234`.
- Archive SHA-256: `nodewe-0.1.0-aarch64-apple-darwin.tar.gz` = `821c710b30b01a2679defec1c318cf240bcfc4efdd6a3486d0f232fa1127025c`.
- Deployment constraint: Control Plane must be bound to loopback or a private
  network and placed behind an approved TLS/mTLS proxy.
- Security status: production gates in `spec/production-readiness.md` remain
  open until OIDC/team authorization, external KMS key lifecycle, durable
  transactional storage/HA, OS sandboxing and independent security review are
  complete.
