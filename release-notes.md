# NodeWe 0.1.1 — Ubuntu 22.04 compatibility fix

This release fixes the Linux packaging baseline. Version 0.1.0 was built on
`ubuntu-latest` and its Node Runtime could require GLIBC 2.39, preventing it
from starting on Ubuntu 22.04 (GLIBC 2.35).

- Build and CI now use Ubuntu 22.04 x86_64 explicitly.
- Every binary is checked for GLIBC symbol requirements no newer than 2.35.
- The extracted archive must pass checksum, deployment-unit, single-node and
  three-node integration checks on Ubuntu 22.04 before publication.
- Binary version output follows the Cargo package version.
- Archive sidecar checksums use the downloaded basename; the internal manifest
  covers binaries and deployment scripts/configuration templates.

No state format or protocol change is introduced. Keep existing credentials,
certificates, policy and database when upgrading; do not overwrite them with
the example files. Back up state before switching the release directory.

This is a compatibility fix, not a production security certification. The
production-readiness gates still apply. Production mode requires OIDC; the
packaged integration scripts test an isolated local instance, not your live
TLS, identity-provider or PostgreSQL deployment. Do not expose the service
unrestricted to the public internet based on these tests alone.
