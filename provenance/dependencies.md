# NodeWe dependency provenance

The native TLS/mTLS transport uses the following reviewed upstream crates.

| Crate | Version | Source | License |
|---|---:|---|---|
| rustls | 0.23.43 | https://crates.io/crates/rustls/0.23.43 | Apache-2.0 OR ISC OR MIT |
| rustls-pki-types | 1.15.1 | https://crates.io/crates/rustls-pki-types/1.15.1 | MIT OR Apache-2.0 |
| ring | 0.17.14 | https://crates.io/crates/ring/0.17.14 | ISC |
| serde_json | 1.0.151 | https://crates.io/crates/serde_json/1.0.151 | Apache-2.0 OR MIT |

The exact transitive graph and checksums are pinned in `Cargo.lock`. Human
license, NOTICE, dependency and security review remains a release gate.
