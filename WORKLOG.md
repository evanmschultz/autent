# Worklog

This file tracks the MVP completion scope for `autent`.

## MVP Goals

- keep `autent` library-first and transport-neutral
- provide real authentication, session lifecycle, authorization, grants, and audit
- support both in-memory use and SQLite-backed embedding
- keep the developer surface easy to adopt inside another Go project
- ship enough docs and examples for human testing and first integrations

## Completed

- repo bootstrap, CI, release workflow, and `Justfile`
- domain model for principals, clients, sessions, rules, grants, decisions, and audit
- app service for session issue, validation, revocation, authz, and grant lifecycle
- in-memory repository
- SQLite repository with dedicated-DB and shared-DB modes
- example CLI at `cmd/autent-example`
- architecture, trust-model, SQLite, human-testing, and consumer-integration docs
- Apache 2.0 licensing and contribution guidance

## Final MVP Tightening

- redact stored session verifier material from operator-facing CLI output
- support principal and client enable or disable flows
- support grant approve, deny, and cancel flows
- align `autent` branding across docs, binaries, and release artifacts
- keep Linux and macOS CI coverage aligned with first-consumer needs
