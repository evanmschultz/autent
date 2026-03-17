# SQLite Integration Modes

`autent` includes a SQLite adapter because first consumers are local-first Go tools with real session, grant, and audit state.

SQLite is an adapter, not a requirement of the core library.

## Why SQLite Exists Here

The core library needs persistence semantics for:

- opaque sessions
- revocation
- grants
- audit

`sqlite` is useful because it gives:

- durable state
- local-first deployment
- no extra service process
- easy embedding into Go projects
- one built-in schema version table with numbered migrations

## Two Integration Modes

There are two good ways to use SQLite with `autent`.

### 1. Dedicated auth database

Recommended default.

Example:

- `app.db` for the consumer
- `autent.db` for auth/session/grant/audit data

Benefits:

- simpler ownership boundary
- simpler migrations
- easier backup and reset behavior
- less chance of colliding with application tables

This is the best MVP default for most adopters.

### 2. Shared application database

Useful for projects that strongly prefer one SQLite file.

Requirements for this mode:

- caller-supplied database handle support
- clear table naming or prefixing
- versioned migration discipline
- validated table prefixes so SQL identifiers stay predictable

This mode is worth supporting because `autent` is meant to feel plugin-like for Go projects.

## Recommendation

The most practical shape is:

- keep storage interfaces in the core
- keep `sqlite` optional
- make dedicated auth DB the default documented path
- support shared-DB embedding as an advanced integration mode
- keep migrations explicit so future schema upgrades stay predictable

## Code Examples

Dedicated database file:

```go
repo, err := sqlite.Open("autent.db")
if err != nil {
    return err
}
defer repo.Close()
```

Caller-owned database handle:

```go
repo, err := sqlite.OpenDB(db, sqlite.Options{
    TablePrefix: "autent_",
})
if err != nil {
    return err
}
```

Separate SQLite file with prefixed tables:

```go
repo, err := sqlite.OpenWithOptions("app.db", sqlite.Options{
    TablePrefix: "autent_",
})
if err != nil {
    return err
}
defer repo.Close()
```

## What Not To Do

Do not make SQLite mandatory for the core library.

If a caller wants:

- PostgreSQL
- an existing project database handle
- a custom encrypted store
- a remote persistence layer

they should be able to implement the store ports without changing core auth behavior.

## Notes For First Consumers

### `blick`

`blick` is local-first and likely to benefit from a dedicated `autent` SQLite file at first because it keeps trust and approval data separated from wrapper/runtime tables.

### `tillsyn`

`tillsyn` already has an application database model.
It may eventually prefer a shared-DB mode, but a dedicated `autent` DB is still the simpler first integration path.
