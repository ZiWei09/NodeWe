# Stable error codes

CLI and Control Plane clients should preserve these codes across releases:

| Code | Meaning | Typical exit status |
| --- | --- | ---: |
| `unauthenticated` | missing or expired identity | 10 |
| `forbidden` | identity lacks Node/Scope/Ability access | 11 |
| `node_not_found` | requested Node does not exist | 12 |
| `node_unavailable` | Node offline or revoked | 13 |
| `scope_denied` | path or operation is outside Scope policy | 14 |
| `approval_required` | operation needs human approval | 15 |
| `task_timeout` | execution exceeded its lease | 16 |
| `task_cancelled` | task was cancelled | 17 |
| `idempotency_conflict` | same key used with different input | 18 |
| `file_output_too_large` | Scope file content exceeds the output limit | 19 |
| `file_input_too_large` | Scope file write content exceeds the input limit | 20 |
| `ability_not_implemented` | requested capability is not enabled on this Agent | 21 |
| `invalid_labels` | node labels contain an unsafe or oversized value | 22 |
| `actor_forbidden` | authenticated operator cannot modify another actor's task | 11 |
| `immutable_node_metadata` | Node heartbeat attempted to change administrator-owned scheduling metadata | 11 |
| `invalid_json_type` | A request field has an unexpected JSON type | 10 |
| `internal` | unexpected service failure | 70 |
