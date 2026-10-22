# Spec 141: re-pin duckdb to the v2.0.0 tag - the release, its own pins

- **Status**: implemented
- **Date**: 2026-10-21
- **Author**: the agent, at the owner's ask ("да можно сделать перепин всю семью")

## Problem

DuckDB v2.0.0 "Cyanoptera" was released on 2026-10-21. The tag is `d54cbbe3df17e8e5ce68312f483b4155836112aa`, checked
with `git ls-remote`. Our pin is f8f3f4d (spec 133), 77 commits before it on `v2.0-cyanoptera`. CLAUDE.md has said
"re-pin to the `v2.0.0` tag when it is cut" since 2026-09-08, and the branch has already moved past the tag (788cc8d).
The distribution build checks duckdb out at the branch name, so it would build an unreleased 2.0.1-dev from now on.

## Design

- **duckdb f8f3f4d → d54cbbe (v2.0.0)**: the tag commit, not the branch head. `.gitmodules` keeps
  `branch = v2.0-cyanoptera`, the line patch releases come from.
- **The distribution builds the tag**: `duckdb_version: v2.0.0`, as community-extensions builds for 2.0.0.
- **extension-ci-tools 39ffc46 → fe955ed**, main's head. Its `v2.0-cyanoptera` branch lacks #432 (clang-cl opt-in),
  so the reusable workflow stays `@main` (spec 110).
- **The release's own pins** of what we build from it:
  - quack e7a9be3 → f96420e (11 commits). duckdb builds it without patches now: its two went into quack itself. The
    client and the embedded server are the same commit, and `sync.py` copies an unpatched pin as it is when duckdb's
    `quack.cmake` applies none (it refused before). The generated copies are unchanged.
  - httpfs 77392a7 and mysql_scanner f7fc0d4: the submodule's own includes, unpatched now.
  - ducklake ca86db0 → 417a911, duckdb v2.0.0's own pin, 49 commits forward on ducklake's main.
  - duckdb-postgres c0f5a3c, which already is duckdb v2.0.0's pin.
  - mssql-extension 7e1bb1c → 6df11bc (addendum, 2026-10-22): its main re-pinned onto v2.0.0 (its #511; #512 labels
    a build on a release pin as that release). Its code is v0.3.0's, which since 7e1bb1c adds one fix (a PLP value
    that encodes to no payload, #496/#497). test-integration with the mssql leg built
    (`ACL_INTEGRATION_MSSQL=1`): 616 assertions in 21 files, the SQL Server scenarios included.
- **What the 77 commits change for us**:
  - `OperatorExpression` gets a custom serializer for array-slice bounds (storage before v2.0). It adds no field, so
    spec 139's sweep of expression-bearing fields finds nothing new.
  - `duckdb_settings(include_all := …)`;
  - `QueryProfiler::GetFinalizedProfileUnderLock`;
  - a C API v2 for query metrics.

- **The version a build claims.** duckdb 2.0 no longer reads `git describe`. A build is `v2.0.0-dev<commit count>`,
  and its extensions' folder is the commit (`d54cbbe3df`), unless the version is given: `DUCKDB_VERSION` in the
  environment, or `OVERRIDE_GIT_DESCRIBE`.
  - The distribution workflow sets `DUCKDB_VERSION` to its `duckdb_version` input, so it builds a real v2.0.0 that a
    stock DuckDB loads.
  - The local build and CI stay a dev build of the same commit, which is enough for the gate: one build, its own
    extensions.
  - hugr-node's release has to set it. Its node then is v2.0.0, and installs from repositories serving v2.0.0.

acl-otel, tresor (by its own session) and hugr-node follow. tresor's `ACL_COMMIT` waits for this spec's merge.

## Testing

The whole gate at the new pin, with `ACL_INTEGRATION=1 ACL_QUACK=1`:

- `test/sql/*`, test-cpp, harness;
- `test-integration`, against the docker databases;
- `test-flight`, `test-e2e`;
- CI, then main's distribution run on every platform.

Run on macOS, all green:

- `test/sql/*`: 9845 assertions in 109 files; the 13 skipped need a DSN, and the integration step runs them;
- test-cpp, the harness ("the four announced refusals and nothing else");
- test-integration: 570 assertions in 19 files;
- test-flight, test-e2e. The door's mssql leg skips locally (no SQL Server), as before.

## Follow-ups

- The extensions' submission to community-extensions, now that 2.0.0 is out (specs/045).
