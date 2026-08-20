# Testing this extension
This directory contains all the tests for this extension. The `sql` directory holds tests that are written as [SQLLogicTests](https://duckdb.org/dev/sqllogictest/intro.html). DuckDB aims to have most its tests in this format as SQL statements, so for the quack extension, this should probably be the goal too.

The root makefile contains targets to build and run all of these tests. To run the SQLLogicTests:
```bash
make test
```
or 
```bash
make test_debug
```

The `cpp` directory holds standalone C++ tests for invariants SQL cannot express — prepared-statement
parameter passthrough and per-instance policy isolation (see `specs/002-cpp-invariant-tests/spec.md`).
Each `test_*.cpp` is its own program; build and run them with:
```bash
GEN=ninja make test-cpp
```
`make test` (the release CI target) runs them too on Linux/macOS. The `harness` directory is a runnable
end-to-end demo against the built loadable extension.

The `sql/integration` directory holds scenarios against live databases (PostgreSQL, MySQL, DuckLake —
see `specs/005-integration-env/spec.md`). They need the docker environment and an integration build:
```bash
cp .env.example .env
make docker-up
ACL_INTEGRATION=1 GEN=ninja make     # macOS: brew install libpq croaring first
make test-integration
```
Each scenario skips itself when its scanner or DSN is absent, so the plain suites stay runnable
without docker.