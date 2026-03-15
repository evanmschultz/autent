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

## Example Resource Mappings

Examples for `blick`:

- `resource_type=tool`, `resource_id=gopls.go_diagnostics`, `namespace=server:gopls`
- `resource_type=path`, `resource_id=/Users/.../repo/file.go`, `namespace=project:repo-123`
- `resource_type=workflow`, `resource_id=fmt-lint-test`, `namespace=project:repo-123`

## Why This Matters

`blick` is exactly the kind of project where auth and tool/runtime behavior can accidentally collapse into one thing.
`autent` should prevent that by giving `blick` a reusable session/authz/grant/audit core without taking over MCP or wrapper semantics.
