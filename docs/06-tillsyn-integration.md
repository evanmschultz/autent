# tillsyn Integration Notes

`tillsyn` is one of the first intended consumers of `autent`.

## What `tillsyn` Should Use `autent` For

- user, agent, and client identity
- session issuance and validation
- generic authorization decisions for reads and mutations
- grant-style escalation where useful
- audit recording

## What `tillsyn` Should Keep Local

- project, branch, phase, task, and subtask hierarchy
- hierarchy-derived capability logic
- consumer DTOs and request envelopes
- TUI and HTTP behavior
- local work-item guardrails

## Suggested First Seam

Use `autent` for session and decisioning first, not for hierarchy modeling.

Flow:

1. `tillsyn` resolves caller, client, and session
2. `tillsyn` derives a generic resource from local hierarchy state
3. `tillsyn` derives an action such as `read`, `mutate`, `archive`, or `restore`
4. `tillsyn` asks `autent` for a decision
5. `tillsyn` keeps hierarchy-aware downstream behavior local

## Example Resource Mappings

Examples for `tillsyn`:

- `resource_type=project`, `resource_id=proj_123`, `namespace=tillsyn`
- `resource_type=task`, `resource_id=task_456`, `namespace=project:proj_123`
- `resource_type=comment`, `resource_id=comment_789`, `namespace=project:proj_123`

## Why This Matters

`tillsyn` already has real enforcement behavior, but its auth-like semantics are tightly coupled to its own hierarchy.
`autent` should absorb the generic session/authz/grant/audit foundation while leaving hierarchy-specific scope derivation inside `tillsyn`.
