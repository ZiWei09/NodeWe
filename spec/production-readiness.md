# NodeWe production-readiness gates

This document is intentionally explicit about what the current repository does
and does not prove.

## Implemented in the current MVP

- Node/Scope/Task domain types and state transitions;
- path containment and command allowlist checks; path-taking allowlisted
  commands such as `cat` and `ls` are additionally constrained to Scope paths;
- local CLI node pairing, revocation, task execution, timeout and audit output;
- Control Plane API for health, node registration, revocation, task acceptance,
  Agent heartbeat and audit listing;
- bounded HTTP request parsing, explicit NodeWe CLI naming, fail-closed
  plaintext transport checks for non-loopback Agent/CLI endpoints, and
  restrictive permissions on local state files; Control Plane connections
  have bounded read/write timeouts and a fail-closed concurrent-connection
  ceiling;
- Control Plane request, JWT and persisted audit parsing uses strict JSON value
  types instead of substring scanning, with malformed and non-object payloads
  rejected;
- URL-safe Node identifiers are validated consistently by Agent, SDK and
  Control Plane, and administrative API routes reject Node Credentials;
- optional native TLS 1.2/1.3 with mandatory client-certificate verification
  when `NODEWE_TLS_CERT`, `NODEWE_TLS_KEY` and `NODEWE_TLS_CLIENT_CA` are set;
- native TLS short-connection shutdown sends `close_notify`, with a local
  release-binary mTLS handshake, unauthenticated-client rejection and Agent
  heartbeat smoke test;
- optional RFC 6455 WebSocket/WSS transport with masked client frames,
  bounded payloads, ping/pong and close handling, shared protocol envelopes,
  and a local release-binary WebSocket heartbeat smoke test;
- optional AES-256-GCM authenticated-at-rest state files with atomic rename,
  snapshot backup, startup integrity checks, and fail-closed enforcement via
  `NODEWE_REQUIRE_ENCRYPTED_STORE=1`;
- a fail-closed data-directory writer lock that prevents two Control Plane
  processes from concurrently mutating the snapshot; this is a safety guard,
  not a substitute for shared transactional storage in an HA deployment;
- optional Ed25519-signed enrollment grants with verification at redemption and
  `NODEWE_REQUIRE_SIGNED_GRANTS=1` fail-closed startup enforcement; production
  accepts environment or mode-0600 secret-file injection, but still requires
  an external KMS-backed key lifecycle and rotation runbook; an optional
  previous-key verification window is supported during rotation;
- one-time pairing grants, per-node credential rotation, constant-time
  credential checks, and cancellation/audit of queued work when a node is
  revoked;
- basic capability allowlists, approval gating for `task.exec`, idempotency
  conflict detection, expiring dispatch leases, output redaction and bounded
  task output; the Control Plane persists only a 4 KiB preview plus a SHA-256
  digest; `file.read`, `file.write`, `task.exec` and `system.inspect` have
  distinct Agent execution paths;
- fail-closed policy configuration for allowed abilities, approval-required
  abilities, Node data classes, actor identities, command basenames and
  Scope-relative path prefixes; accepted tasks retain the actor and emit a
  `policy.allowed` Activity Record;
- optional pinned OIDC/OAuth2 HS256 JWT verification with issuer/audience,
  expiry/not-before, subject and group checks; administrative routes require
  the configured admin group, the verified subject is bound to actor fields,
  and actor identifiers accept common IdP subjects such as `provider|user`;
- optional durable, single-use Approval Records bound to Node, ability and
  command payload, enforced with `NODEWE_REQUIRE_APPROVAL_RECORDS=1`;
- checked-in non-root systemd units with namespace/resource hardening and a
  SHA-verified atomic upgrade/rollback helper;
- audit records expose the authenticated `actor` plus a deterministic
  `prev_hash`/`hash` chain (new records bind actor into the hash), and the
  startup snapshot loader rejects tampered chain contents;
- Agent polling and WebSocket session reconnects use bounded exponential
  backoff and keep the process alive across transient Control Plane failures;
- Node heartbeats refresh a persisted `last_seen` timestamp; stale nodes are
  treated as offline after the online TTL and cannot receive new tasks;
- transactional SQLite persistence is available with `NODEWE_STORAGE_BACKEND=sqlite`
  and stores the canonical encrypted snapshot in a single ACID row; snapshot mode
  remains the compatibility default;
- protocol and capability negotiation: Agent heartbeats declare protocol version
  and abilities, Control Plane returns the negotiated set, rejects unknown
  abilities and unsupported protocol versions, and the Agent fails closed when
  required abilities are not negotiated;
- explicit CLI Node Groups support safe labels and label/Node-set intersection;
  group membership is materialized to stable Node IDs before execution, so
  names and labels cannot cause implicit broadcast;
- remote enrollment and node-directory APIs validate label syntax and the
  deployment kit includes an atomic TLS/mTLS certificate rotation and backup
  procedure with key-pair validation;
- Node Runtime can perform Grant-only enrollment over the authenticated TLS/mTLS
  channel and writes the returned credential atomically to a new 0600 token
  file without accepting an administrator token;
- the deployment kit includes a paginated audit exporter that verifies the
  Activity hash chain before writing page files and SHA-256 sidecars;
- unit and integration tests for state transitions, Scope boundaries and
  revoked-node routing.

## Release blockers before production

- complete the shared-database HA strategy and multi-instance coordination; the
  transactional SQLite backend is suitable for a single Control Plane host, while
  PostgreSQL or another shared database is still required for active-active writes;
- complete authenticated TLS/WSS rollout and fleet-wide certificate rotation
  operations between Agent and Control Plane (native TLS/mTLS, WSS, and a
  validated atomic rotation procedure are available; CA rollout, fleet
  coordination and external certificate authority ownership remain operational
  gates);
- replace the development HMAC fallback with an approved KMS-backed grant key
  lifecycle, protected per-Node key material and rotation; keep revocation
  propagation end-to-end;
- complete cross-instance clock/lease tests and operational lease tuning
  (dispatch fencing tokens now prevent stale Agent results after reclaim;
  basic Agent heartbeat, queue dispatch, result callback and reclaim-on-expiry
  are implemented);
- integrate the OIDC verifier with the production identity provider and team
  lifecycle, then add an approval UI/workflow and external policy decision
  records; local subject/group checks, durable single-use approvals and
  idempotency are implemented;
- complete OS-level sandbox review and enforce the approved profile in each
  target environment (non-root service packaging and SHA-verified upgrade /
  rollback helper are implemented);
- complete multi-Node failure, reconnect and load tests, plus integrate the
  verified audit exporter with the organization's external retention and
  alerting controls;
- perform SBOM, license, secret, dependency, penetration and deployment review.

The MVP binaries must not be exposed directly to the public internet or used
with production credentials until every blocker above has an owner and an
acceptance test.
