# autent

`autent` is a small Go auth library for agentic systems.

The name is `autent`, not `authent`.
It is Swedish-flavored branding: close to "authentic" and also a slightly cheeky shortening inspired by `autentisering` ("authentication").

`autent` is meant to be embedded as a Go module inside another Go project.
It is not an HTTP server, not an MCP server, and not a standalone auth daemon by default.

## What It Does

`autent` answers four questions cleanly:

1. Who is calling?
2. What authenticated session are they operating under?
3. What resource and action are they requesting?
4. Is the result `allow`, `deny`, `grant_required`, `session_required`, `session_expired`, or `invalid`?

Core responsibilities:

- authentication
- session lifecycle
- authorization
- explicit grant escalation
- audit

Non-goals:

- HTTP routing
- MCP server behavior
- workflow orchestration
- consumer-specific hierarchy semantics
- approval UI

## Why It Exists

Local auth code in agent systems tends to decay into:

- transport-specific hacks
- context-only identity propagation
- weak session semantics
- app-specific scope names
- mixed auth and workflow behavior
- poor auditability

`autent` exists to give `blick`, `tillsyn`, and similar Go projects a reusable auth foundation without forcing them into a framework.

## Package Shape

Current packages:

- `github.com/evanmschultz/autent`
- `github.com/evanmschultz/autent/app`
- `github.com/evanmschultz/autent/domain`
- `github.com/evanmschultz/autent/store`
- `github.com/evanmschultz/autent/token`
- `github.com/evanmschultz/autent/audit`
- `github.com/evanmschultz/autent/inmem`
- `github.com/evanmschultz/autent/sqlite`

For embedders, the root `autent` package re-exports the primary service API so callers can start with `autent.NewService(...)` and then choose adapters explicitly.

Layering:

- `domain`: pure types, invariants, matching logic, typed errors
- `app`: use-cases and orchestration over ports
- `store` / `token`: primary adapter contracts
- `audit`: reserved namespace for audit-facing docs and future sink helpers
- `inmem` / `sqlite`: concrete adapters

## Current MVP Scope

Implemented:

- principal and client registration
- principal and client enable or disable flows
- opaque session issue, validate, and revoke
- caller-safe session views at the service boundary
- rule-based authorization with explicit deny precedence
- explicit grant request, approve, deny, and cancel flows
- append-only audit events
- in-memory and SQLite adapters
- versioned SQLite schema management with prefixed shared-DB support
- example CLI for human testing

Recommended defaults:

- opaque session secrets, not self-contained JWTs
- hashed secrets at rest
- deny by default
- explicit grants
- synchronous audit
- library-first embedding

## Local Commands

```bash
just check
just ci
```

## SQLite Integration Modes

`autent` can be embedded in two ways:

- dedicated `autent.db` style file for auth state
- shared application database with a configurable table prefix

Examples:

```go
repo, err := sqlite.Open("autent.db")
```

```go
repo, err := sqlite.OpenDB(existingDB, sqlite.Options{
    TablePrefix: "autent_",
})
```

```go
repo, err := sqlite.OpenWithOptions("app.db", sqlite.Options{
    TablePrefix: "autent_",
})
```

The SQLite adapter records a schema version and applies numbered migrations internally.

## Human Testing

Use one local SQLite file for the full demo flow:

```bash
DB=.tmp/autent-demo.db

go run ./cmd/autent-example principal create --db "$DB" --id user-1 --type user --name "User One"
go run ./cmd/autent-example client create --db "$DB" --id cli-1 --type cli --name "CLI"
go run ./cmd/autent-example policy load-demo --db "$DB"
go run ./cmd/autent-example session issue --db "$DB" --principal user-1 --client cli-1
```

Take the returned `session_id` and `session_secret`, then:

```bash
SESSION_ID='paste-session-id-here'
SESSION_SECRET='paste-session-secret-here'

go run ./cmd/autent-example authz check --db "$DB" \
  --session "$SESSION_ID" \
  --secret "$SESSION_SECRET" \
  --action read \
  --namespace project:demo \
  --resource-type task \
  --resource-id task-1

go run ./cmd/autent-example authz check --db "$DB" \
  --session "$SESSION_ID" \
  --secret "$SESSION_SECRET" \
  --action mutate \
  --namespace project:demo \
  --resource-type task \
  --resource-id task-1 \
  --context scope=current

go run ./cmd/autent-example grant request --db "$DB" \
  --session "$SESSION_ID" \
  --secret "$SESSION_SECRET" \
  --action mutate \
  --namespace project:demo \
  --resource-type task \
  --resource-id task-1 \
  --context scope=current \
  --reason "need one mutation"

GRANT_ID='paste-grant-id-here'

go run ./cmd/autent-example grant approve --db "$DB" \
  --grant-id "$GRANT_ID" \
  --actor approver-1 \
  --note approved \
  --usage-limit 1

go run ./cmd/autent-example authz check --db "$DB" \
  --session "$SESSION_ID" \
  --secret "$SESSION_SECRET" \
  --action mutate \
  --namespace project:demo \
  --resource-type task \
  --resource-id task-1 \
  --context scope=current

go run ./cmd/autent-example authz check --db "$DB" \
  --session "$SESSION_ID" \
  --secret "$SESSION_SECRET" \
  --action mutate \
  --namespace project:demo \
  --resource-type task \
  --resource-id task-1 \
  --context scope=current

go run ./cmd/autent-example audit list --db "$DB"

go run ./cmd/autent-example session revoke --db "$DB" \
  --session "$SESSION_ID" \
  --reason done

go run ./cmd/autent-example authz check --db "$DB" \
  --session "$SESSION_ID" \
  --secret "$SESSION_SECRET" \
  --action read \
  --namespace project:demo \
  --resource-type task \
  --resource-id task-1
```

Expected behavior:

- `read` returns `allow`
- `mutate` returns `grant_required` until approved
- one approved grant allows one retry, then requires a new grant
- the post-revoke `authz check` returns `invalid`

## Documentation

Detailed docs live under [`docs/`](./docs):

- [Architecture](./docs/01-architecture.md)
- [Trust Model](./docs/02-trust-model.md)
- [SQLite Integration Modes](./docs/03-sqlite-integration.md)
- [Human Testing](./docs/04-human-testing.md)
- [blick Integration Notes](./docs/05-blick-integration.md)
- [tillsyn Integration Notes](./docs/06-tillsyn-integration.md)
- [MVP Completion Notes](./docs/07-mvp-completion.md)

Contributor and process guidance:

- [CONTRIBUTING.md](./CONTRIBUTING.md)
- [PLAN.md](./PLAN.md)
- [WORKLOG.md](./WORKLOG.md)
- [AGENTS.md](./AGENTS.md)

## License

`autent` is licensed under the Apache License 2.0.
See [LICENSE](./LICENSE).
