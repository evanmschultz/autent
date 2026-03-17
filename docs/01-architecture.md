# Architecture

`autent` is a transport-neutral Go auth library for agentic systems.

It is designed around a simple rule:

- keep auth semantics in the core
- keep transport and consumer semantics outside the core

## Layers

### `domain`

The `domain` layer owns:

- principals
- clients
- caller-safe sessions and verifier-side stored sessions
- resources
- actions
- policy rules
- grants
- decisions
- audit event types
- typed errors

`domain` should be pure.
It should not know about:

- SQLite
- HTTP
- MCP
- logging
- external runtime state

### `app`

The `app` layer owns use-cases and orchestration:

- register principal
- register client
- issue session
- validate session
- revoke session
- authorize request
- request grant
- resolve grant
- list audit events

`app` depends on `domain` plus abstract ports only.

### Adapter contracts

The adapter contracts live in:

- `store`
- `token`
- `audit` as a reserved namespace for audit-facing docs and future sink helpers

`store` and `token` define the current extension points needed by the library without forcing a storage or runtime model.

### Concrete adapters

Current adapters:

- `inmem`
- `sqlite`

These packages depend inward on the core.

## Public Shape

The intended developer experience is:

1. import `autent` plus one adapter such as `sqlite` or `inmem`
2. choose or implement a store adapter
3. construct the service
4. issue and validate sessions
5. ask for authz decisions
6. manage grants
7. read audit records

The root `autent` package exposes a thin façade over the primary app service types.
Consumers still choose adapters explicitly; the library does not become a service product.

## What Stays Outside

Consumers should keep these concerns locally:

- HTTP routing
- MCP request envelopes
- path normalization
- project/task hierarchy semantics
- approval UI
- workflow chaining

For example:

- `blick` should map MCP/tool access requests into generic `resource` and `action` values
- `tillsyn` should map hierarchy-derived scope into generic `resource` and `action` values

## Security Defaults

The architecture assumes these defaults:

- opaque session secrets
- hashed secrets at rest
- caller-safe session views at the service boundary
- constant-time secret verification
- deny by default
- explicit grants
- explicit audit events

## Why This Shape

This is the smallest shape that still supports:

- real session auth
- revocation
- grant escalation
- auditability
- embeddability into other Go projects

If `autent` becomes transport-aware or consumer-hierarchy-aware in the core, it stops being a reusable auth foundation and starts becoming an application framework.
