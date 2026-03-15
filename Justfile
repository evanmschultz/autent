set shell := ["bash", "-eu", "-o", "pipefail", "-c"]
set windows-shell := ["C:/Program Files/Git/bin/bash.exe", "-eu", "-o", "pipefail", "-c"]

[private]
verify-bootstrap:
  @test -f AGENTS.md
  @test -f README.md
  @test -f PLAN.md
  @test -f Justfile
  @test -f .goreleaser.yml
  @test -f .github/workflows/ci.yml
  @test -f .github/workflows/release.yml

fmt:
  @if [ ! -f go.mod ]; then \
    echo "skip fmt: go.mod not initialized yet"; \
  elif ! command -v gofumpt >/dev/null 2>&1; then \
    echo "fmt failed: gofumpt is not installed"; \
    echo "install: brew install gofumpt"; \
    exit 1; \
  elif ! find . -type f -name '*.go' -not -path './.git/*' -not -path './.tmp/*' -not -path './.cache/*' -print -quit | grep -q .; then \
    echo "skip fmt: no Go files found"; \
  else \
    find . -type f -name '*.go' -not -path './.git/*' -not -path './.tmp/*' -not -path './.cache/*' -print0 | xargs -0 gofumpt -w; \
  fi

[private]
fmt-check:
  @if [ ! -f go.mod ]; then \
    echo "skip fmt-check: go.mod not initialized yet"; \
  elif ! command -v gofumpt >/dev/null 2>&1; then \
    echo "fmt-check failed: gofumpt is not installed"; \
    echo "install: brew install gofumpt"; \
    exit 1; \
  elif ! find . -type f -name '*.go' -not -path './.git/*' -not -path './.tmp/*' -not -path './.cache/*' -print -quit | grep -q .; then \
    echo "skip fmt-check: no Go files found"; \
  else \
    out="$(find . -type f -name '*.go' -not -path './.git/*' -not -path './.tmp/*' -not -path './.cache/*' -print0 | xargs -0 gofumpt -l)"; \
    if [ -n "$out" ]; then \
      echo "gofumpt required for:"; \
      echo "$out"; \
      exit 1; \
    fi; \
  fi

test:
  @if [ ! -f go.mod ]; then \
    echo "skip test: go.mod not initialized yet"; \
  elif ! find . -type f -name '*.go' -not -path './.git/*' -not -path './.tmp/*' -not -path './.cache/*' -print -quit | grep -q .; then \
    echo "skip test: no Go files found"; \
  else \
    GOFLAGS="${GOFLAGS:+$GOFLAGS }-buildvcs=false" go test ./...; \
  fi

lint:
  @if [ ! -f go.mod ]; then \
    echo "skip lint: go.mod not initialized yet"; \
  elif ! command -v golangci-lint >/dev/null 2>&1; then \
    echo "lint failed: golangci-lint is not installed"; \
    echo "install: brew install golangci-lint"; \
    exit 1; \
  elif ! find . -type f -name '*.go' -not -path './.git/*' -not -path './.tmp/*' -not -path './.cache/*' -print -quit | grep -q .; then \
    echo "skip lint: no Go files found"; \
  elif ! git rev-parse --verify HEAD >/dev/null 2>&1; then \
    echo "skip lint: git HEAD is missing"; \
  else \
    GOFLAGS="${GOFLAGS:+$GOFLAGS }-buildvcs=false" golangci-lint run ./...; \
  fi

test-pkg pkg:
  @if [ ! -f go.mod ]; then \
    echo "skip test-pkg: go.mod not initialized yet"; \
  else \
    pkg="{{pkg}}"; \
    if [ -d "$pkg" ]; then \
      if ls "$pkg"/*.go >/dev/null 2>&1; then \
        GOFLAGS="${GOFLAGS:+$GOFLAGS }-buildvcs=false" go test "$pkg"; \
      else \
        GOFLAGS="${GOFLAGS:+$GOFLAGS }-buildvcs=false" go test "$pkg/..."; \
      fi; \
    else \
      GOFLAGS="${GOFLAGS:+$GOFLAGS }-buildvcs=false" go test "$pkg"; \
    fi; \
  fi

build:
  @if [ ! -f go.mod ]; then \
    echo "skip build: go.mod not initialized yet"; \
  elif [ ! -d ./cmd/autent-example ]; then \
    echo "skip build: ./cmd/autent-example not present"; \
  else \
    mkdir -p ./bin; \
    GOFLAGS="${GOFLAGS:+$GOFLAGS }-buildvcs=false" go build -o ./bin/autent-example ./cmd/autent-example; \
  fi

run:
  @if [ ! -f go.mod ]; then \
    echo "run failed: go.mod not initialized yet"; \
    exit 1; \
  elif [ ! -d ./cmd/autent-example ]; then \
    echo "run failed: expected ./cmd/autent-example to exist"; \
    exit 1; \
  else \
    GOFLAGS="${GOFLAGS:+$GOFLAGS }-buildvcs=false" go run ./cmd/autent-example; \
  fi

[private]
coverage:
  @if [ ! -f go.mod ]; then \
    echo "skip coverage: go.mod not initialized yet"; \
  elif ! find . -type f -name '*.go' -not -path './.git/*' -not -path './.tmp/*' -not -path './.cache/*' -print -quit | grep -q .; then \
    echo "skip coverage: no Go files found"; \
  else \
    tmp="$(mktemp)"; \
    GOFLAGS="${GOFLAGS:+$GOFLAGS }-buildvcs=false" go test ./... -cover | tee "$tmp"; \
    awk 'BEGIN {bad=0} \
      /^ok[[:space:]]/ && /coverage:/ { \
        covLine=$0; \
        sub(/^.*coverage:[[:space:]]*/, "", covLine); \
        sub(/%.*/, "", covLine); \
        cov=covLine+0; \
        if (cov < 70) { \
          print "coverage below 70%:", $2, covLine "%"; \
          bad=1; \
        } \
      } \
      END {exit bad}' "$tmp"; \
    rm -f "$tmp"; \
  fi

[private]
release-check:
  @if [ ! -f .goreleaser.yml ]; then \
    echo "release-check failed: .goreleaser.yml not found"; \
    exit 1; \
  elif ! command -v goreleaser >/dev/null 2>&1; then \
    echo "release-check failed: goreleaser is not installed"; \
    echo "install: brew install goreleaser"; \
    exit 1; \
  else \
    goreleaser check; \
  fi

check: verify-bootstrap fmt-check lint test build

ci: verify-bootstrap fmt-check lint test coverage build
