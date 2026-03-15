# authent Worklog

Status: in progress
Audience: implementers of `authent` and first consumers `blick` and `tillsyn`

## Mission

Build `authent` as a small Go auth library for agentic systems.

`authent` owns:

- principal and client identity,
- session lifecycle,
- authorization decisions over generic resources and actions,
- explicit grant escalation,
- audit events,
- storage and secret-handling adapter contracts.

`authent` does not own:

- MCP runtime behavior,
- HTTP server behavior,
- consumer hierarchy modeling,
- approval UI,
- workflow orchestration,
- product-specific terminology.

## Final Package Target

Stable v0 package set:

- `authent`
- `domain`
- `app`
- `store`
- `token`
- `audit`
- `inmem`
- `sqlite`

Removed from v0 target:

- `httpx`
- `mcpx`

Reason:

- transport-specific glue should stay in consumers until repeated patterns prove a shared helper is warranted,
- this keeps the library transport-neutral and more Go-idiomatic.

## Acceptance Criteria

1. Hexagonal boundaries are explicit and respected.
2. Core flows exist: principal/client registration, session issue/validate/revoke, authz, grant request/resolve, audit append.
3. `inmem` and `sqlite` adapters both work.
4. Example CLI exists for human testing.
5. `just check` and `just ci` pass.
6. Tests maintain at least 70% package coverage where applicable.
7. Top-level declarations have Go doc comments.
8. Two independent QA subagents review quality and completeness before final handoff.

## Milestones

1. Rework bootstrap plan and repo shape for library-only delivery.
2. Implement `domain` types and typed errors with tests.
3. Implement `store` ports and `token` secret handling.
4. Implement `app` service flows with tests against fakes or `inmem`.
5. Implement `inmem` adapters.
6. Implement `sqlite` adapter and migrations.
7. Implement human-test CLI.
8. Run QA review, fix findings, commit, and push.

## Execution Log

### 2026-03-14 bootstrap audit

Objective:

- inspect current scaffold,
- compare local sibling repos,
- decide final package boundary before implementation.

Commands and outcomes:

- `find . -maxdepth 3 -type f | sort` -> confirmed repo was scaffold-only plus `.tmp/` research clones.
- `sed -n '1,260p' PLAN.md` -> confirmed initial plan still referenced transport helper packages.
- `git status --short` -> confirmed bootstrap files were uncommitted.

Findings:

- `blick` documents trust/authz concepts but does not yet implement real session auth.
- `tillsyn` implements scoped lease enforcement, but its auth logic is tightly coupled to project/task hierarchy.
- `authent` should remain transport-neutral and consumer-neutral.

Decision:

- drop `httpx` and `mcpx` from v0 target,
- keep MCP as an important consumer use case, not a core package boundary.

### 2026-03-14 implementation kickoff

Objective:

- start full v0 implementation under TDD and hexagonal boundaries,
- use worker and QA subagents,
- maintain this file as the live worklog.

Planned worker lanes:

- lane A: core domain and service API shape review,
- lane B: SQLite schema and adapter review,
- lane C: QA code review after implementation,
- lane D: QA completeness and human-test review after implementation.

Current status:

- in progress
- next step: finish the example CLI, run QA review, and close remaining workflow gaps.

### 2026-03-14 core implementation checkpoint

Objective:

- stabilize the core domain, app, and adapter APIs,
- restore transactional semantics in `inmem`,
- get library packages to the repo coverage target before CLI integration.

Commands and outcomes:

- `go test ./domain ./token ./app ./inmem` -> green after reconciling rule normalization and grant approval APIs.
- `go mod tidy` -> added `modernc.org/sqlite` and transitive SQLite dependencies.
- `go test ./sqlite` -> green after dependency fetch and stale test updates.
- `go test ./... -cover` -> exposed coverage gaps in `domain`, `inmem`, `sqlite`, and `token`.
- targeted package coverage loops for `domain`, `token`, `inmem`, and `sqlite` -> now all above 70%.

Implementation completed in this phase:

- added `domain.ValidateAndNormalizeRule`,
- tightened error semantics with `ErrInvalidSessionSecret` and `ErrInvalidConfig`,
- wired one-time grant redemption through `app.Service.Authorize`,
- fixed `app.ResolveGrant` to honor `UsageLimit`,
- fixed `inmem.WithinTx` to roll back on error instead of leaking partial state,
- expanded `domain`, `token`, `inmem`, and `sqlite` tests to cover normalization, transactionality, CRUD, and audit/filter behavior.

### 2026-03-14 CLI and workflow checkpoint

Objective:

- replace the placeholder example binary with a real human-test harness,
- align docs with the implemented package set and test flow,
- verify repository automation with the same `just` gates used in CI.

Commands and outcomes:

- `go test ./cmd/authent-example -cover` -> green with end-to-end CLI coverage above 80%.
- `go test ./... -cover` -> all covered Go packages now above the 70% package threshold.
- `just fmt` -> green.
- `just check` -> green, with `lint` intentionally skipped because the repo still has no git `HEAD`.
- `just ci` -> green, including coverage and `goreleaser check`.

Implementation completed in this phase:

- replaced the example placeholder with a real CLI for:
  - principal creation,
  - client creation,
  - demo policy loading,
  - session issue and revoke,
  - authz check,
  - grant request and approve,
  - audit listing,
- added CLI tests covering the full human acceptance flow,
- updated `README.md` with human-test commands and clarified current scope.

Remaining work:

- collect and address final QA subagent findings,
- commit and push.

### 2026-03-14 human-test CLI checkpoint

Objective:

- replace the placeholder example binary with a real manual test harness,
- keep the CLI narrow and standard-library-only,
- prove the intended acceptance flow end to end.

Commands and outcomes:

- `go test ./cmd/authent-example` -> green after replacing the placeholder entrypoint.
- `go test ./... -cover` -> green with every exercised package above the 70% threshold required by `just ci`.

Implementation completed in this phase:

- added `principal create`,
- added `client create`,
- added `policy load-demo`,
- added `session issue` and `session revoke`,
- added `authz check`,
- added `grant request` and `grant approve`,
- added `audit list`,
- added an end-to-end CLI test flow that exercises the demo policy, session lifecycle, grant approval, grant redemption, and audit listing.
