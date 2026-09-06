# NodeWe production reference architecture

The reference deployment uses PostgreSQL 16 for shared state, Keycloak for OIDC,
and AWS KMS for grant and storage key protection. The Control Plane runs at
least two instances behind a TLS-terminating load balancer; mTLS between Agent
and Control Plane remains end-to-end at the application tier.

Agents are supported on macOS, Windows, and Linux. The Agent keeps the same
least-privilege model on every platform: a non-administrator service account,
explicit Scope roots, an executable allowlist, bounded output, and per-node
credentials. Platform installers must provision the service account and token
file with OS-native restricted permissions.

The implementation order is:

1. PostgreSQL schema and transactional backend, including lease fencing.
2. OIDC discovery/JWKS validation with Keycloak group mapping.
3. AWS KMS envelope encryption and key rotation windows.
4. CA rollover and fleet certificate rotation.
5. S3-compatible audit export with chain verification and retry.
6. macOS launchd, Windows Service, and Linux systemd packaging.

A deployment is production-ready only after the corresponding acceptance
scripts pass against real services. Local SQLite, development JWT secrets, and
filesystem audit output remain supported for development only.
