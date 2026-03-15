# Contributing to autent

Thanks for contributing to `autent`.

`autent` is intentionally small.
Please optimize for clarity, boring behavior, and reuse in other Go projects over cleverness or framework sprawl.

## First Principles

- keep the core library transport-neutral
- keep consumer-specific semantics out of the core
- prefer explicit session and authz behavior over hidden convenience
- preserve deny-by-default behavior
- treat audit and grant handling as first-class behavior, not bolt-ons

## Repository Layout

Main package responsibilities:

- `domain`: pure types, invariants, matchers, typed errors
- `app`: use-cases and orchestration over ports
- `store`, `token`, `audit`: shared contracts
- `inmem`, `sqlite`: concrete adapters

User-facing docs live in:

- `README.md`
- `PLAN.md`
- `WORKLOG.md`
- `docs/`

## Local Setup

Required local tools are driven by the `Justfile`.
The main local gates are:

```bash
just check
just ci
```

For faster loops, prefer package-scoped tests:

```bash
just test-pkg ./app
just test-pkg ./domain
just test-pkg ./sqlite
```

## Coding Expectations

- write idiomatic Go
- keep interfaces small
- wrap errors with `%w`
- add Go doc comments for top-level declarations
- avoid consumer product terminology in the core
- keep comments short and only where behavior is non-obvious

## Documentation Expectations

When behavior changes, update the docs in the same change.
At minimum, consider whether the change affects:

- `README.md`
- `PLAN.md`
- `docs/01-architecture.md`
- `docs/02-trust-model.md`
- `docs/03-sqlite-integration.md`
- `docs/04-human-testing.md`

## CI and Release Expectations

Before asking for review:

- run `just check`
- run `just ci` when practical
- keep GitHub Actions and `Justfile` behavior aligned

The release workflow exists to validate and publish tagged releases.
Do not add unrelated packaging or deployment behavior into the core library CI path.

## Scope Discipline

Please do not turn `autent` into:

- an HTTP auth service framework
- an MCP framework
- a workflow engine
- a consumer-specific access-policy UI

If a feature only makes sense for one consumer, it probably belongs in that consumer.
