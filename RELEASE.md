# NodeWe release checklist

## Build

Every push and pull request is expected to pass the checked-in
`.github/workflows/ci.yml` workflow before a release artifact is promoted.
The workflow runs formatting, the full locked workspace test suite, Clippy
with warnings denied, a release build, and dependency review for pull requests.

```bash
RUSTUP_TOOLCHAIN=1.95 cargo fmt --all -- --check
RUSTUP_TOOLCHAIN=1.95 cargo test --locked
RUSTUP_TOOLCHAIN=1.95 cargo build --release --bins --locked
bash scripts/check-deploy-units.sh
NODEWE_BIN_DIR=target/release bash scripts/integration.sh
```

Artifacts are `node-runtime`, `nodewe`, and `node-control-plane`. Record the
commit, toolchain, target triple and SHA-256 hashes in the release record.

## Before production

- review every item in `spec/production-readiness.md`;
- run dependency/SBOM/license/secret scans in CI;
- run `./scripts/smoke.sh` against the release checkout;
- provision a non-root `nodewe` service account;
- place the Control Plane behind TLS (and mTLS for Node Runtime traffic);
- set a random `NODEWE_ADMIN_TOKEN` through a secret manager;
- configure `NODEWE_OIDC_REQUIRED=1` with a pinned issuer/audience and a
  mode-0600 HS256 verification secret; verify the configured admin group and
  subject-to-actor binding against the staging identity provider;
- configure an encrypted, backed-up `NODEWE_DATA_DIR`;
- verify revoke, reconnect, timeout, output-limit and multi-Node tests against
  a staging Control Plane;
- obtain human security, IP and deployment approval.
- run `./scripts/preflight-production.sh` with production environment secrets;
  the script must pass before service startup (including OIDC operator
  authentication).
- exercise `deploy/upgrade-nodewe.sh` in staging, verify the SHA-checked
  symlink switch and complete one rollback before production rollout.
- exercise `deploy/rotate-tls.sh --dry-run` with the issued server certificate,
  private key and Agent CA, then perform one staged rotation and rollback test.
- run `scripts/export-audit.sh` against staging and verify the exported pages
  and SHA-256 sidecars are retained by the external audit store.

The current Control Plane keeps a fail-closed single-writer lock around a
single-instance snapshot store. It is suitable for a single-instance staging
deployment only until a shared transactional database and HA strategy are
implemented.
