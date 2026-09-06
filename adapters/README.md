# Adapters

Optional capabilities live here and are not part of the Node Runtime core:

- `computer-use`
- `screen-stream`
- `osdl`

The `nodewe-adapters` crate now provides a transport-neutral `Adapter` trait and
an explicitly allowlisted `ComputerUseAdapter` baseline. Adapters must translate
requests into existing NodeWe abilities; they cannot bypass Scope, approval,
lease, persistence, or audit enforcement.
