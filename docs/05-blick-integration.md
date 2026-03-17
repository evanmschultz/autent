# blick Integration Notes

`blick` is one of the first intended consumers of `autent`.

## What `blick` Should Use `autent` For

- caller identity
- client identity
- authenticated session binding
- generic authz decisions over resources and actions
- grant request and resolution lifecycle
- audit recording

## What `blick` Should Keep Local

- MCP wrapper behavior
- tool/runtime envelopes
- path normalization
- project/resource classification
- access-profile authoring and presentation
- consumer-specific approval UX

## Suggested First Seam

Use `autent` before the MCP wrapper actually invokes the requested tool or workflow.

Flow:

1. `blick` resolves caller, client, and session data
2. `blick` canonicalizes the target resource
3. `blick` maps the request to:
   - `resource`
   - `action`
   - optional context
4. `blick` asks `autent` for a decision
5. `blick` maps the decision to runtime behavior

For operator or admin views, `blick` can also use `autent` to list sessions, grants, and audit events.
Generic filters exist today for sessions and audit events, and `blick` can apply its own project or orchestrator-specific filtering on top.
`blick` should still treat those views as privileged operator capabilities and authorize them explicitly.

## Example Resource Mappings

Examples for `blick`:

- `resource_type=tool`, `resource_id=gopls.go_diagnostics`, `namespace=server:gopls`
- `resource_type=path`, `resource_id=/Users/.../repo/file.go`, `namespace=project:repo-123`
- `resource_type=workflow`, `resource_id=fmt-lint-test`, `namespace=project:repo-123`

## Why This Matters

`blick` is exactly the kind of project where auth and tool/runtime behavior can accidentally collapse into one thing.
`autent` should prevent that by giving `blick` a reusable session/authz/grant/audit core without taking over MCP or wrapper semantics.

## Storage and Listing Choices To Confirm

Before wiring `blick` to `autent`, confirm these choices with the user:

- whether auth state should live in a dedicated `autent` database or inside `blick`'s existing database
- whether that storage should be scoped per workspace, per project, or shared more broadly
- which operator-facing views should exist for active sessions, pending grants, and audit history

`autent` should not choose those topology boundaries for `blick`.
It should provide generic auth-owned list primitives plus generic filters where they make sense.
`blick` should decide how those primitives map onto its own projects, workspaces, orchestrators, and tool surfaces.
