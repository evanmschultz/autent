# Trust Model

`autent` is built for agentic systems where a human, orchestrator, service, or agent may be the caller.

The key trust boundary is simple:

- verifier-side material stays inside `autent`
- caller-facing session material is issued once and then presented back for validation

## Session Material

At issuance time, the caller receives:

- `session_id`
- `session_secret`

The store keeps:

- `session_id`
- `secret_hash`
- lifecycle metadata

`secret_hash` is verifier-side state.
It should not be treated as caller-facing API.

## Orchestrators and Subagents

The recommended default is:

- orchestrator holds the root session
- subagents do not all share the same root session secret by default

Safer patterns are:

1. mediated access
   The orchestrator remains the session holder and performs authz checks on behalf of subagents.

2. delegated access
   A subagent gets its own bounded session or grant scoped to its work.

Patterns to avoid by default:

- giving every subagent the same long-lived root session secret
- exposing verifier-side material such as stored secret hashes

## Decisions

Every authz request should resolve to an explicit result:

- `allow`
- `deny`
- `grant_required`
- `session_required`
- `session_expired`
- `invalid`

The point is to make agent behavior deterministic and auditable.

## Grants

Grants exist for requests that are not allowed by baseline policy but are explicitly eligible for escalation.

Important properties:

- grants are not implicit allow
- grants are auditable
- grants are bounded by scope and lifecycle

For orchestrators, a good default is:

- treat grants as delegated authority with explicit scope
- keep grant creation and resolution visible in audit

## Storage Trust Boundary

Because `autent` uses opaque sessions, it needs persistent verifier-side state for:

- sessions
- revocations
- grants
- audit

That does not mean `autent` must own a separate database process.
It does mean the caller must supply some trustworthy persistence model.

## First-Consumer Guidance

### `blick`

`blick` should keep transport handling and wrapper/runtime behavior local.
It should use `autent` for caller identity, sessions, authz decisions, grant flow, and audit.

### `tillsyn`

`tillsyn` should keep hierarchy-derived local semantics local.
It should use `autent` for session lifecycle, generic authz decisions, grant flow where appropriate, and audit.
