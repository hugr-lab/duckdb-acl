# Spec 100: re-pin duckdb to eb0d9df - a parser is an object

- **Status**: implemented
- **Date**: 2026-10-05
- **Found by**: PR #179's distribution run (it builds the head of `v2.0-cyanoptera`): linux_arm64
  failed to compile `acl_policy.cpp`, `acl_rewriter.cpp`, `acl_catalog_admin.cpp`.

## Problem

duckdb a2af0a7 → eb0d9df (340 commits). One series changes the parser API:

- `ParserOptions()` is private - options without a client context come from
  `ParserOptions::Builtin()` (it carries the default grammar);
- `Parser::ParseExpressionList(text, options)` is gone: a parser is built from options and parses -
  `Parser(options).ParseExpressionList(text)`, with `ParseSingleExpression` / `ParseSelectNode` beside it.

Our code built `ParserOptions` by default construction in four places and called the static form in six.

## Design

- Every default-constructed `ParserOptions` is `ParserOptions::Builtin()`; the rewriter's
  `template_options` starts from it and is still overwritten with the statement's own options.
- Every `Parser::ParseExpressionList(x, o)` is `Parser(o).ParseExpressionList(x)`.
- The scanners come from the submodule's pins and patches as before: postgres/mysql/sqlite moved,
  each with a `builtin-parser` patch; ducklake keeps its commit with a new patch; quack keeps 974927a
  and gains `0003-builtin-parser.patch` (client storage only). `sync.py` applies it and regenerates
  the embedded server's files unchanged.

- The CLI gained an **agent mode**: with an AI coding agent's variable set (`AI_AGENT`, `CLAUDECODE`,
  `CODEX_*`, …) and stdout not a terminal it changes its output format. The two scripts that judge the
  CLI's text (`test/harness/run.sh`, `test/e2e/flight/tls.sh`) pass `-no-agent`; CI never sets the
  variables, a developer's agent does.

## Testing

The whole gate at eb0d9df: `test/sql/*`, test-cpp, harness, test-flight, test-e2e,
test-integration, schema-check, clang-format, the thread_local lint - all green locally; the
distribution build is dispatched on the PR. The mssql leg of `test/e2e/door/types.sh` needs an mssql
build of this pin (the one on hand is a2af0a7's) - it skips until one is built.

acl-otel pins the same duckdb and follows the same day (its own re-pin).
