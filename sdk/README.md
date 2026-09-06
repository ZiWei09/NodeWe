# NodeWe SDK

`nodewe-sdk` is the dependency-free, versioned contract crate for integrations.
It exposes protocol envelopes and stable Node, Scope, Task, Grant and Activity
identifiers without exposing Control Plane storage or Agent implementation
details.

The crate is transport-neutral. HTTP/TLS clients and optional adapters can
depend on these contracts while preserving the authorization and state-machine
rules defined in `spec/`.
