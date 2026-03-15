# authent

`authent` is a small Go library and runtime foundation for real authentication, session management, authorization, explicit grant escalation, and audit in agentic systems.

Status: active v0 implementation

First consumers:

- `blick`
- `tillsyn`

## Why This Exists

`authent` exists to stop app-local auth from collapsing into transport hacks, weak session semantics, product-specific scope names, and unauditable mutation paths.

It should answer four questions cleanly:

1. Who is calling?
2. What authenticated session are they operating under?
3. What resource and action are they requesting?
4. Is the result `allow`, `deny`, `grant_required`, or `session_required`?

## Product Position

`authent` should be:

- small,
- real,
- session-based,
- policy-driven,
- audit-friendly,
- generic at the resource/action layer,
- easy to embed.

`authent` should not be:

- an MCP framework,
- a workflow system,
- a consumer-specific policy UI,
- a side-channel for sandbox escape behavior.

## Architecture

The repo is structured around four layers:

- `domain`: pure types and invariants.
- `app`: use-cases and orchestration over ports.
- `store` / `token` / `audit`: shared adapter contracts.
- `sqlite`, `inmem`: concrete storage adapters.

Current package set:

- `github.com/evanmschultz/autent`
- `github.com/evanmschultz/autent/app`
- `github.com/evanmschultz/autent/domain`
- `github.com/evanmschultz/autent/store`
- `github.com/evanmschultz/autent/token`
- `github.com/evanmschultz/autent/audit`
- `github.com/evanmschultz/autent/sqlite`
- `github.com/evanmschultz/autent/inmem`

## Current Decisions

Recommended v0 defaults:

- opaque session secrets, not self-contained JWTs, by default,
- grants tied to principal plus bounded request context, not just raw session id,
- simple selectors plus minimal conditions for v0 policy,
- generic resource matching with exact, prefix, and basic glob-style support,
- synchronous audit by default,
- library-first delivery before any standalone service runtime.

## Local Commands

```bash
just run
just check
just ci
```

The example binary at `cmd/authent-example` is the human-test harness for the library.

## Human Test

Use one local SQLite file for the flow:

```bash
DB=.tmp/authent-demo.db

go run ./cmd/authent-example principal create --db "$DB" --id user-1 --type user --name "User One"
go run ./cmd/authent-example client create --db "$DB" --id cli-1 --type cli --name "CLI"
go run ./cmd/authent-example policy load-demo --db "$DB"
go run ./cmd/authent-example session issue --db "$DB" --principal user-1 --client cli-1
```

Take the returned `session_id` and `session_secret`, then drive the auth flow:

```bash
go run ./cmd/authent-example authz check --db "$DB" \
  --session <session_id> \
  --secret <session_secret> \
  --action read \
  --namespace project:demo \
  --resource-type task \
  --resource-id task-1

go run ./cmd/authent-example grant request --db "$DB" \
  --session <session_id> \
  --secret <session_secret> \
  --action mutate \
  --namespace project:demo \
  --resource-type task \
  --resource-id task-1 \
  --context scope=current \
  --reason "need one mutation"

go run ./cmd/authent-example grant approve --db "$DB" \
  --grant-id <grant_id> \
  --actor approver-1 \
  --note approved \
  --usage-limit 1

go run ./cmd/authent-example audit list --db "$DB"
```

Expected behavior:

- `read` returns `allow`
- `mutate` returns `grant_required` until approved
- one approved grant allows one retry, then requires a new grant
- `session revoke` makes later checks fail with a session-based denial

The built-in demo policy allows `read` on `project:demo/task:task-1` and requires an explicit one-time grant for `mutate` on the same resource when `scope=current`.

## Repository Bootstrap

This repository intentionally starts with a thin scaffold:

- `AGENTS.md` defines contributor and agent rules,
- `PLAN.md` captures the current v0 design and build order,
- `Justfile` is the command source of truth,
- `.github/workflows/` mirrors `just check` and `just ci`,
- `.tmp/` is ignored local scratch space for comparative research.

## Current Build Scope

Implemented and under test:

- principal and client registration,
- opaque session issue, validate, and revoke,
- rule-based authorization with explicit deny precedence,
- explicit grant request and resolution,
- append-only audit events,
- in-memory and SQLite persistence adapters.

Notably out of scope for v0:

- HTTP routing,
- MCP transport helpers,
- consumer-specific hierarchy logic,
- approval UI.
