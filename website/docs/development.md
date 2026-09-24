# Development

The development guide is
[CLAUDE.md](https://github.com/hugr-lab/duckdb-acl/blob/main/CLAUDE.md) in the repository. It covers
the model, conventions, and what every spec added. This page covers building and testing.

## Build

```sh
git submodule update --init --recursive
GEN=ninja make                          # release build of duckdb + the extension
ACL_INTEGRATION=1 ACL_QUACK=1 GEN=ninja make   # also the scanners and quack, for the integration and door tests
```

The loadable extension is `build/release/extension/acl/acl.duckdb_extension`, and the CLI with acl
built in is `build/release/duckdb`. The scanners come from vcpkg; run `make vcpkg-setup` once.

## Test

```sh
build/release/test/unittest 'test/sql/*'   # the sqllogictest suite, what CI runs
GEN=ninja make test-cpp                    # standalone C++ invariant tests (test/cpp/)
test/harness/run.sh                        # the end-to-end demo
make test-flight                           # the Flight SQL door against real drivers
make test-e2e                              # the doors end to end
make docker-up && make test-integration    # against Postgres, MySQL, SQL Server, DuckLake
```

The policy schema is written once, in `schema/policy_schema.sql`. `make schema` renders everything
from it, and `make schema-check` fails if a rendered file is stale, or if a catalog migrated from the
previous version differs from a fresh one.

## Specs

Each feature gets one short spec under
[specs/](https://github.com/hugr-lab/duckdb-acl/tree/main/specs), before or alongside the code. A
spec covers the problem, the design, enforcement and security, tests and alternatives. It is set to
`implemented` when the feature lands, and superseded rather than rewritten when a decision changes.

## These docs

The site is built from `website/` with Docusaurus:

```sh
cd website && npm ci && npx docusaurus start   # live preview
npx docusaurus build                           # what the PR check runs (broken links fail it)
```

A link from one page to another is relative (`serving.md#the-quack-door`), never an absolute
site path. `scripts/ci/check_docs_links.py` enforces that.
