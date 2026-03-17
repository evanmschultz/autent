# Human Testing

The example CLI exists to make `autent` verifiable by a human without reading Go code.

## Example CLI

Use the example CLI from the repository root:

```bash
go run ./cmd/autent-example help
```

## Full Demo Flow

Create a local SQLite file and seed baseline data:

```bash
DB=.tmp/autent-demo.db

go run ./cmd/autent-example principal create --db "$DB" --id user-1 --type user --name "User One"
go run ./cmd/autent-example client create --db "$DB" --id cli-1 --type cli --name "CLI"
go run ./cmd/autent-example policy load-demo --db "$DB"
go run ./cmd/autent-example session issue --db "$DB" --principal user-1 --client cli-1
go run ./cmd/autent-example session list --db "$DB" --state active
```

To exercise shared-database mode, use the same SQLite file that already contains host-application tables and keep a dedicated `--db-prefix` such as `autent_` on every command.

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

## Expected Behavior

- `read` returns `allow`
- initial `mutate` returns `grant_required`
- `grant request` creates a pending grant
- `grant approve` resolves the grant
- next identical `mutate` returns `allow`
- next identical `mutate` again returns `grant_required` when the one-time grant is exhausted
- `session list --state active` returns the current caller-safe session metadata without verifier-side hashes
- the post-revoke `authz check` returns `invalid`

To test the rest of the grant lifecycle, create another pending grant request and then run either:

```bash
go run ./cmd/autent-example grant deny --db "$DB" \
  --grant-id 'paste-pending-grant-id-here' \
  --actor approver-1 \
  --note denied

go run ./cmd/autent-example grant cancel --db "$DB" \
  --grant-id 'paste-pending-grant-id-here' \
  --actor operator-1 \
  --note withdrawn
```

## What The Demo Policy Does

The built-in demo policy:

- allows `read` on `project:demo/task:task-1`
- requires a one-time explicit grant for `mutate` on the same resource when `scope=current`

## Why The CLI Matters

The CLI is not the product.
It is a manual validation harness for:

- sessions
- authz decisions
- grants
- audit

That keeps `autent` library-first while still making the behavior easy to verify.
