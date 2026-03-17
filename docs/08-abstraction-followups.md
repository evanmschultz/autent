# Abstraction Follow-Ups

`autent` is MVP-complete, but there are a few places where the abstraction can still become cleaner over time.

This document is intentionally a follow-up list, not an active roadmap commitment.

## 1. Session Store Shape

The low-level session store currently mixes:

- verifier-facing methods for create, get, and update
- caller-safe listing for enumeration

That is acceptable for the current MVP, but it is slightly asymmetrical.

Future cleanup options:

- keep it as-is and document the boundary clearly
- split verifier-facing session persistence from caller-safe session queries
- add a dedicated query interface for safe session enumeration

This is not a blocker today.

## 2. DB-Pushed Filtering For Large Shared Stores

Current session listing is safe and practical for local-first use, per-user use, and moderate dataset sizes.

It is not yet optimized as a large-scale query engine.

If a consumer eventually wants very large shared auth stores, likely next steps are:

- push more filters down into SQLite queries
- add extra indexed columns for high-value scoping fields
- revisit storage topology choices

This should be driven by real usage pressure, not speculative design.

## 3. Metadata-Aware Querying

Embedding apps may want to filter operator views by app-owned concepts such as:

- project
- workspace
- orchestrator
- tenant

Right now the idiomatic model is:

- stamp metadata where appropriate
- filter generically in `autent`
- narrow further in the embedding app

If repeated real consumers need more than that, `autent` could later add carefully bounded metadata-aware filtering.
That should only happen if the query shape proves generic across apps.

## 4. Clearer Operator/Admin Guidance

The core docs now explain trust, storage, integration, and human testing.

If the first consumers grow richer operator surfaces, future doc refinement may still be useful around:

- session lifecycle administration
- grant review workflows
- audit review patterns
- authorization requirements for privileged read-only operator screens

The new operator/admin patterns doc should cover the immediate need.

## 5. Persistence Contract Refinement

The verifier-side persistence model is now substantially safer than before:

- caller-safe service surfaces
- caller-safe session listing
- no public `SecretHash` field
- no generic JSON leak of stored session hashes

Still, persistence remains an intentionally advanced surface.

If more embedders implement custom repositories, it may eventually be worth tightening that contract further so the trust boundary is even more obvious to custom store authors.

## 6. Deliberately Not Follow-Ups

These are intentionally not on the abstraction cleanup list unless consumer needs change:

- adding an HTTP server to core
- switching the default session model to JWTs
- making `autent` choose app database topology automatically
- pushing project or hierarchy semantics into core filters
- turning `autent` into an admin dashboard framework

Those would weaken the current library-first boundary rather than improve it.
