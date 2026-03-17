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

For operator or admin views, `tillsyn` can use `autent` to list sessions, grants, and audit events.
Generic filters exist today for sessions and audit events, and `tillsyn` can apply project or hierarchy-specific filtering inside `tillsyn`.
`tillsyn` should still treat those views as privileged operator capabilities and authorize them explicitly.

## Example Resource Mappings

Examples for `tillsyn`:

- `resource_type=project`, `resource_id=proj_123`, `namespace=tillsyn`
- `resource_type=task`, `resource_id=task_456`, `namespace=project:proj_123`
- `resource_type=comment`, `resource_id=comment_789`, `namespace=project:proj_123`

## Why This Matters

`tillsyn` already has real enforcement behavior, but its auth-like semantics are tightly coupled to its own hierarchy.
`autent` should absorb the generic session/authz/grant/audit foundation while leaving hierarchy-specific scope derivation inside `tillsyn`.

## Storage and Listing Choices To Confirm

Before wiring `tillsyn` to `autent`, confirm these choices with the user:

- whether auth state should live in a dedicated `autent` database or inside `tillsyn`'s existing database
- whether that storage should be scoped per project, per branch or workspace, or shared more broadly
- which operator-facing views should exist for active sessions, pending grants, and audit history

`autent` should not choose those storage boundaries for `tillsyn`.
It should provide generic auth-owned list primitives plus generic filters where they make sense.
`tillsyn` should decide how those primitives map onto its own hierarchy and project views.
