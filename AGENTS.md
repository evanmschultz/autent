# Authent Agent Guide

This file defines required behavior for coding agents working in the `authent` repository.
Scope: this repository root and every child path beneath it.

## 1) Mission and Boundaries

`authent` is a small Go auth foundation for agentic systems.
It should provide reusable primitives for:

- authentication,
- session management,
- authorization,
- explicit grant escalation,
- audit.

`authent` is not:

- an MCP wrapper,
- a workflow engine,
- a TUI framework,
- a dumping ground for consumer-specific semantics.

First consumers are expected to be `blick` and `tillsyn`, but the core must stay product-neutral.

## 2) Core Terminology

Use these core terms consistently in code and docs:

- `principal`
- `client`
- `session`
- `resource`
- `action`
- `policy`
- `grant`
- `decision`
- `audit`

Do not rename `grant` to consumer-specific terms in core packages.
Do not move `blick` `access profile` or `tillsyn` `capability lease` terminology into `authent` core APIs unless a dedicated consumer integration adapter explicitly needs translation.

## 3) Architecture Rules

`authent` uses explicit layered boundaries:

- `domain`: pure types, invariants, matching logic, and typed errors.
- `app`: use-cases and orchestration over ports.
- `adapters`: storage, tokens, clocks, randomness, audit sinks.
- `integration`: small optional helpers for consumers such as HTTP or MCP context wiring.

Rules:

- `domain` must not depend on adapters, logging, HTTP, or storage.
- `app` depends on `domain` and abstract ports only.
- adapters depend inward on `app` and `domain`.
- integration helpers stay small and optional.
- keep consumer resource normalization in consumers, not in `authent`.

## 4) Security and Behavior Expectations

Preserve these default positions unless the user explicitly changes direction:

- opaque session secrets by default,
- hashed secrets at rest,
- constant-time secret verification,
- deny by default,
- explicit audit for important mutations and decisions,
- typed errors and stable decision codes,
- no implicit escalation,
- no hidden allow on parse or store errors.

When integrating consumer concepts, keep `authent` generic:

- `blick` should map access-profile and wrapper decisions into generic `resource` and `action` requests.
- `tillsyn` should map hierarchy-derived scope into generic `resource` and `action` requests.

## 5) Engineering Standards

- Write idiomatic Go with clear names and small focused functions.
- Wrap errors with `%w` and useful context.
- Add idiomatic Go doc comments for top-level declarations in production and test code.
- Add short inline comments only for non-obvious behavior.
- Prefer semantic Go tooling when practical.
- Keep interfaces minimal and close to the consuming use-case.

## 6) Testing and Automation

- Use `just` recipes as the source of truth for local automation.
- During implementation, run `just check` after meaningful increments when practical.
- When Go code, `Justfile`, or workflow files change, finish with `just ci` before handoff if the environment supports it.
- Keep `just ci` aligned with the required GitHub Actions gate.
- Prefer package-scoped loops with `just test-pkg <pkg>` for fast iteration.

## 7) Repository Workflow

- Worktrees are supported but not required.
- Run commands from the exact repository path requested by the user.
- Do not push to remotes unless the user explicitly asks.
- The active design source of truth for this bootstrap phase is `PLAN.md`.
- The `.tmp/` directory is local research scratch space. Do not edit cloned sibling repos under `.tmp/` unless the user explicitly asks for changes there.

## 8) Current Bootstrap Direction

Current repository goals:

1. establish the repo bootstrap and contributor workflow,
2. define stable core package boundaries,
3. implement in-memory adapters first,
4. implement session lifecycle,
5. implement authz and grant lifecycle,
6. add SQLite and small consumer examples last.

If you find yourself recreating `blick` policy UX or `tillsyn` hierarchy logic inside `authent`, stop and simplify the design back to generic auth primitives.
