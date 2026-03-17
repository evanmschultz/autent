# Autent Agent Guide

This file defines required behavior for coding agents working in the `autent` repository.
Scope: this repository root and every child path beneath it.

## 1) Mission and Boundaries

`autent` is a small Go auth foundation for agentic systems.
It should provide reusable primitives for:

- authentication
- session management
- authorization
- explicit grant escalation
- audit

`autent` is not:

- an MCP wrapper
- a workflow engine
- a TUI framework
- a dumping ground for consumer-specific semantics

First consumers are expected to be `blick` and `tillsyn`, but the core must stay product-neutral.

## 2) Branding and Terminology

Project branding is `autent`.
Keep that spelling in:

- repository docs
- release notes
- user-facing examples
- contributor material

Normal auth terminology should still keep the `h` where it belongs:

- authentication
- authorization
- authenticated
- authz

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
Do not move `blick` `access profile` or `tillsyn` `capability lease` terminology into `autent` core APIs unless a dedicated consumer integration adapter explicitly needs translation.

## 3) Architecture Rules

`autent` uses explicit layered boundaries:

- `domain`: pure types, invariants, matching logic, and typed errors
- `app`: use-cases and orchestration over ports
- `adapters`: storage, tokens, clocks, randomness, audit sinks
- `integration`: small optional helpers for consumers such as HTTP or MCP context wiring

Rules:

- `domain` must not depend on adapters, logging, HTTP, or storage
- `app` depends on `domain` and abstract ports only
- adapters depend inward on `app` and `domain`
- integration helpers stay small and optional
- keep consumer resource normalization in consumers, not in `autent`

Use a hexagonal or ports-and-adapters style where it helps preserve those boundaries.
That is the preferred architecture shape for this repository.

Interpret that preference pragmatically:

- keep domain rules isolated from adapter concerns
- keep app services centered on use-cases and ports
- let adapters implement storage or integration details at the edge
- avoid framework-shaped abstractions that do not help the auth core stay small

## 4) Security and Behavior Expectations

Preserve these default positions unless the user explicitly changes direction:

- opaque session secrets by default
- hashed secrets at rest
- constant-time secret verification
- deny by default
- explicit audit for important mutations and decisions
- typed errors and stable decision codes
- no implicit escalation
- no hidden allow on parse or store errors

Runtime behavior expectations:

- expected auth outcomes should map to stable `Decision` values
- unexpected operational failures should bubble as errors
- do not hide adapter or persistence failures behind fake allow or deny results
- keep logging consumer-owned unless a user explicitly asks for internal logging hooks

When integrating consumer concepts, keep `autent` generic:

- `blick` should map access-profile and wrapper decisions into generic `resource` and `action` requests
- `tillsyn` should map hierarchy-derived scope into generic `resource` and `action` requests

## 5) Engineering Standards

- Write idiomatic Go with clear names and small focused functions
- Wrap errors with `%w` and useful context
- Add idiomatic Go doc comments for all top-level declarations in production and test code
- Keep comments complete enough that another engineer can read unfamiliar code without guesswork
- Add short inline comments anywhere behavior would otherwise be non-obvious, including tests when setup intent is not immediately clear
- Prefer semantic Go tooling when practical
- Keep interfaces minimal and close to the consuming use-case

## 6) Testing and Automation

- Use `just` recipes as the source of truth for local automation
- During implementation, run `just check` after meaningful increments when practical
- When Go code, `Justfile`, or workflow files change, finish with `just ci` before handoff if the environment supports it
- Keep `just ci` aligned with the required GitHub Actions gate
- Prefer package-scoped loops with `just test-pkg <pkg>` for fast iteration
- Keep at least 70% coverage for packages with substantive executable logic
- Do not add meaningless tests just to force doc-only or marker packages over the coverage threshold

For non-trivial changes, use subagents when they help parallelize bounded work.
Subagents are optional, not mandatory, for very small edits.

Required review flow for code changes:

- use at least two QA-style subagents before handoff
- both QA subagents are report-only reviewers; they should not edit files
- one QA reviewer should focus on code quality, regressions, tests, and behavior
- one QA reviewer should focus on architecture fit, consumer readiness, and completeness

Required review flow for docs and user-facing behavior:

- use at least one docs-checking subagent when behavior, examples, CI surface, or documentation changes
- the docs reviewer is report-only and should not fix docs directly
- after the docs review reports findings, fix them in the main thread if needed

Before handoff, summarize:

- what QA reviewers found
- what was fixed
- any remaining risks or open questions

## 7) Repository Workflow

- Worktrees are supported but not required
- Run commands from the exact repository path requested by the user
- Do not push to remotes unless the user explicitly asks
- The active design source of truth for this MVP phase is `PLAN.md`
- The `.tmp/` directory is local research scratch space. Do not edit cloned sibling repos under `.tmp/` unless the user explicitly asks for changes there

## 8) Current Direction

Current repository goals:

1. keep `autent` transport-neutral and library-first
2. keep auth core semantics generic across consumers
3. support optional adapters rather than forcing one deployment shape
4. keep the developer surface easy to embed into other Go projects

If you find yourself recreating `blick` policy UX or `tillsyn` hierarchy logic inside `autent`, stop and simplify the design back to generic auth primitives.

Ready-for-consumers expectations:

- keep `autent` ready for `blick`, `tillsyn`, and similar Go apps
- keep docs complete enough that a new adopter can understand trust model, storage options, and human test flow
- keep error behavior explicit enough that consumers can distinguish decisions from operational failures
