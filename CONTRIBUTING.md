# Contributing to autent

Thanks for contributing to `autent`.

`autent` is intentionally small.
Please optimize for clarity, boring behavior, and reuse in other Go projects over cleverness or framework sprawl.

## First Principles

- keep the core library transport-neutral
- keep consumer-specific semantics out of the core
- prefer explicit session and authz behavior over hidden convenience
- preserve deny-by-default behavior
- treat audit and grant handling as first-class behavior, not bolt-ons

## Repository Layout

Main package responsibilities:

- `domain`: pure types, invariants, matchers, typed errors
- `app`: use-cases and orchestration over ports
- `store`, `token`: shared contracts
- `inmem`, `sqlite`: concrete adapters

User-facing docs live in:

- `README.md`
- `docs/`

## Local Setup

Required local tools are driven by `magefiles/`.
The main local gates are:

```bash
mage check
mage ci
```

Install Mage locally before using the repo targets:

```bash
go install github.com/magefile/mage@v1.17.0
```

Running `mage` from the repository root will auto-discover `magefiles/` and keep the repository root as the working directory.

`mage ci` includes release configuration validation.
Install GoReleaser locally if you do not already have it.
On macOS with Homebrew, for example:

```bash
brew install goreleaser
```

For faster loops, prefer package-scoped tests:

```bash
mage test-pkg ./app
mage test-pkg ./domain
mage test-pkg ./sqlite
```

## Coding Expectations

- write idiomatic Go
- keep interfaces small
- wrap errors with `%w`
- add Go doc comments for all top-level declarations in production and test code
- avoid consumer product terminology in the core
- keep comments short but complete wherever behavior or setup would otherwise be non-obvious

## Documentation Expectations

When behavior changes, update the docs in the same change.
At minimum, consider whether the change affects:

- `README.md`
- `docs/01-architecture.md`
- `docs/02-trust-model.md`
- `docs/03-sqlite-integration.md`
- `docs/04-human-testing.md`

## CI and Release Expectations

Before asking for review:

- run `mage check`
- run `mage ci` when practical
- keep GitHub Actions and `magefiles/` behavior aligned

The release workflow exists to validate and publish tagged releases.
Do not add unrelated packaging or deployment behavior into the core library CI path.

`autent` is currently pre-`v1`.
Use SemVer tags beginning with `v0.1.0`.

Normal release flow:

1. merge release-ready work to `main`
2. create an annotated tag locally
3. push the tag
4. let GitHub Actions publish the release through GoReleaser

Example:

```bash
git tag -a v0.1.0 -m "v0.1.0"
git push origin v0.1.0
```

## Pull Request Workflow

`main` should be treated as PR-only once repository protections are enabled.

Contributor flow:

1. create a branch from `main`
2. make the change
3. run `mage check`
4. run `mage ci` when practical
5. open a pull request with `gh pr create`

Example:

```bash
git switch -c your-branch
gh pr create --fill --base main
gh pr checks --watch
```

Because the repository currently has a single maintainer, the branch protection model should require pull requests and passing checks but not required approvals yet.
That avoids deadlocking solo-maintainer merges while still preventing casual direct pushes to `main`.
Contributors should still assume PRs are the normal path for all changes.

## Scope Discipline

Please do not turn `autent` into:

- an HTTP auth service framework
- an MCP framework
- a workflow engine
- a consumer-specific access-policy UI

If a feature only makes sense for one consumer, it probably belongs in that consumer.
