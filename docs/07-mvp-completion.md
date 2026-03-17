# MVP Completion Notes

This file records the checklist used to call the current `autent` bootstrap phase MVP-complete.

## Completed MVP Checklist

- define stable `domain`, `app`, adapter, and contract package boundaries
- keep the library transport-neutral and embedder-first
- support principal and client registration plus enable and disable lifecycle
- support opaque session issue, validate, expire, and revoke lifecycle
- keep verifier-side session state explicit through stored-session types
- return caller-safe session views from the service and CLI surfaces
- evaluate authz decisions with deny precedence and stable decision codes
- support grant request, approve, deny, cancel, and consume flows
- append audit events for key lifecycle and authz events
- provide `inmem` and `sqlite` adapters
- support dedicated SQLite files and shared SQLite handles with validated prefixes
- track SQLite schema version and apply numbered migrations
- provide a human-testable example CLI
- keep GitHub Actions aligned with `just ci`
- keep at least 70% coverage on packages with substantive executable logic
- document architecture, trust model, SQLite usage, and human testing

## What "MVP Complete" Means Here

For this repository, MVP-complete means:

- first consumers such as `blick` and `tillsyn` can embed `autent` without adding HTTP or MCP server behavior to the library
- consumers can distinguish expected auth decisions from unexpected operational failures
- verifier-side material stays on verifier-oriented code paths
- adopters have enough docs and examples to exercise the system end to end

## Post-MVP Hardening Ideas

These are useful follow-ups, but they are not required to call the current library MVP-complete:

- additional store adapters beyond SQLite and in-memory
- optional signed-token mode on top of the opaque-session default
- richer policy condition language
- migration upgrades beyond schema version `1`
- dedicated audit sink adapters or tracing hooks
