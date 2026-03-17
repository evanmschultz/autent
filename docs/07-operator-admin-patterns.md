# Operator And Admin Patterns

`autent` now exposes enough listing and lifecycle surface for embedding apps to build operator or admin views.

This document explains what belongs in those views, what should stay outside `autent`, and what choices should still be confirmed with the user before an embedding app locks them in.

## What `autent` Can List

Today, `autent` can expose or help expose:

- principals
- clients
- sessions
- grants
- audit events
- rules

At the service layer, the most useful operator-facing listing methods are:

- `ListPrincipals`
- `ListClients`
- `ListSessions`
- `ListGrants`
- `ListAuditEvents`
- `ListRules`

The session-listing surface is caller-safe and does not expose verifier-side secret hashes.

## What Belongs In Operator Views

Reasonable operator or admin views include:

- active sessions
- revoked sessions
- expired sessions
- pending grants
- recent audit activity
- enabled or disabled principals and clients

These are all auth-owned records, so it makes sense for `autent` to provide the underlying list and lifecycle primitives for them.

## What Should Stay Outside `autent`

`autent` should not become a dashboard framework or product admin layer.

The embedding app should still own:

- who is allowed to use operator views at all
- page or TUI layout
- project, workspace, orchestrator, tenant, or hierarchy semantics
- routing and transport behavior
- any custom aggregate dashboards

In other words:

- `autent` owns auth record primitives
- the embedding app owns product-specific operator UX

## Operator Views Are Privileged

Listing sessions, grants, or audit history is an operator capability.
It should be authorized explicitly by the embedding app.

Do not treat these list methods as harmless just because they are read-only.
They expose operationally sensitive information such as:

- who is active
- which clients are in use
- what grants are pending
- what recent actions and denials occurred

## Filtering Model

`autent` should only provide generic filtering over auth-owned fields.

Current generic filtering is most developed for:

- sessions
- audit events

For sessions, that means generic fields such as:

- session id
- principal id
- client id
- state
- issued time bounds
- limit

That is the right boundary.
Do not push app-specific concepts like project id, orchestrator id, task scope, branch, path, or tool class directly into `autent` filters unless the auth core genuinely adopts them as generic concepts.

## Metadata And App-Specific Narrowing

Embedding apps can still stamp app-specific metadata on sessions, or use app-owned state alongside `autent` records where that is a better fit.

That is useful for values like:

- `project_id`
- `workspace_id`
- `orchestrator_id`
- `tenant_id`

For session-oriented operator views, the recommended pattern is:

1. use `autent`'s generic list filters first
2. apply app-specific metadata narrowing in the embedding app

That keeps the auth library generic while still making a shared database workable.

## Storage Topology Choices

`autent` intentionally does not choose database topology for embedding apps.

The embedding app should decide whether auth state is:

- per app instance
- per workspace
- per project
- globally shared

These choices matter because they affect operator views.

For example:

- a per-project or per-workspace database naturally keeps listings narrow
- a globally shared database makes generic list operations noisier and increases the need for app-side filtering

Before locking in one of those choices for `blick`, `tillsyn`, or another app, discuss it with the user.

## Recommended First Operator Screens

If an embedding app wants a very small operator surface first, start with:

1. active sessions
2. pending grants
3. recent audit events

That usually gives enough operational visibility without building a large admin subsystem.

## Scaling Guidance

For local-first and per-user or per-org embedding, the current generic list/filter model is appropriate.

For much larger shared stores, operator views may eventually need:

- more DB-pushed filtering
- extra indexed scoping fields
- narrower storage topology

That is optimization work, not an MVP requirement.
