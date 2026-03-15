# autent Worklog

Status: active MVP completion
Audience: maintainers of `autent` and first consumers `blick` and `tillsyn`

## Mission

Build `autent` as a small Go auth library for agentic systems.

`autent` owns:

- principal and client identity
- session lifecycle
- authorization decisions over generic resources and actions
- explicit grant escalation
- audit events
- storage and secret-handling adapter contracts

`autent` does not own:

- MCP runtime behavior
- HTTP server behavior
- consumer hierarchy modeling
- approval UI
- workflow orchestration
- consumer-specific terminology

## Final MVP Package Target

Stable MVP package set:

- `autent`
- `domain`
- `app`
- `store`
- `token`
- `audit`
- `inmem`
- `sqlite`

Not part of the MVP surface:

- HTTP helpers
- MCP transport wrappers
- consumer-specific adapters with product semantics

## Acceptance Criteria

1. Hexagonal boundaries are explicit and respected.
2. Core flows exist: principal/client registration, session issue/validate/revoke, authz, grant request/resolve, audit append.
3. `inmem` and `sqlite` adapters both work.
4. Example CLI exists for human testing.
5. `just check` and `just ci` pass.
6. Tests maintain at least 70% package coverage where applicable.
7. Top-level declarations have Go doc comments.
8. Documentation clearly explains trust model, SQLite integration modes, and first-consumer mapping.

## MVP Completion Lanes

1. keep the core library small and transport-neutral
2. keep storage optional at the interface level
3. make SQLite easy to use in both dedicated-DB and shared-DB project setups
4. tighten operator-facing surfaces so verifier-side data is never treated as caller-facing API
5. document orchestrator and subagent trust boundaries clearly

## Execution Log

### 2026-03-14 bootstrap audit

Objective:

- inspect current scaffold
- compare local sibling repos
- decide final package boundary before implementation

Findings:

- `blick` documents trust and access concepts but still needs a reusable session/authz core
- `tillsyn` has real enforcement logic but it is tightly coupled to its own hierarchy
- `autent` should stay transport-neutral and consumer-neutral

Decision:

- drop transport-helper packages from the MVP target
- keep MCP as an important consumer use case, not a core package boundary

### 2026-03-14 implementation checkpoint

Completed:

- domain model and typed errors
- session lifecycle
- rule-based authz
- grant lifecycle
- audit recording
- `inmem` adapter
- SQLite adapter
- example CLI
- CI and coverage gates

Quality gates reached:

- `just check`
- `just ci`
- all exercised Go packages at or above the 70% package threshold

### 2026-03-15 documentation and release-shape checkpoint

Objective:

- align project branding to `autent`
- complete MVP docs
- make contributor/legal material explicit

Completed in this lane:

- top-level user-facing docs rebranded to `autent`
- README expanded into a real project overview
- architecture, trust model, SQLite integration, human-testing, and first-consumer docs added
- contributor guide added
- Apache 2.0 license added

## Remaining MVP Focus

The remaining engineering work should stay narrow:

- keep the public developer surface small
- support existing project SQLite setups cleanly
- preserve generic auth primitives over consumer semantics
- tighten any remaining operator-facing data exposure
