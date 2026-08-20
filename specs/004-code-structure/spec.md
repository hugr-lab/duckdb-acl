# Spec 004: code structure and namespaces

- **Status**: implemented
- **Date**: 2026-08-19
- **Author**: hugr-lab

## Summary

Split the single ~1.2k-line `src/acl_extension.cpp` into per-concern modules and move the internals
into `namespace duckdb::acl`. No behavior change — a pure restructuring, proven by the unchanged test
suites.

## Problem

The whole extension lived in one translation unit inside an anonymous namespace. That blocked growth
(the next feature, the role-aware resolver, would land in the same file), made review diffs noisy,
and left nothing shareable across future TUs. Separately, our generic type names (`Principal`,
`TablePolicy`, `PolicyStore`, `TemplateCache`) sat bare in the file; once split across TUs they need
a named namespace, and putting them straight into `duckdb` risks collisions/ODR surprises when the
extension is statically linked next to the core and other extensions.

## Design

- **Namespace** — internals live in `duckdb::acl` (matching the `mssql-extension` house style of
  subsystem namespaces nested in `duckdb`: `duckdb::tds`, `duckdb::codec`, …). Only the
  `AclExtension : Extension` entry class stays directly in `duckdb`. TU-local code stays in anonymous
  namespaces inside `duckdb::acl`.
- **Modules** — headers in `src/include/`, one seam function per module:

  | Module | Contents | Exposes |
  | --- | --- | --- |
  | `acl_policy.{hpp,cpp}` | `Principal`, `TablePolicy`, `TemplateCache`, `PolicyStore` + resolver methods, `AclParserInfo`/`AclScalarInfo` | the store types (the production-resolver seam) |
  | `acl_rewriter.{hpp,cpp}` | the `AclRewriter` AST walker (class is TU-local) | `RewriteStatements(statements, principal, options, store)` |
  | `acl_parser_override.{hpp,cpp}` | `ACL` prefix scanner + `parser_override` entry (TU-local) | `RegisterAclParser(config, store)` |
  | `acl_admin_functions.{hpp,cpp}` | the 10 `acl_*` admin stubs (TU-local) | `RegisterAclAdminFunctions(loader, store)` |
  | `acl_extension.cpp` | model overview comment + entry: create the store, call the two registrations | extension entry points |

- **Interaction** — unchanged: the store is still created once per `DatabaseInstance` in the entry
  and handed to both registration seams; the rewriter still reaches it by reference per request.

## Enforcement & security

No enforcement change. The code moved verbatim (module boundaries follow the section comments the
file already had); the only new code is the two registration functions and the `RewriteStatements`
wrapper around the per-batch rewriter loop. Fail-closed behavior, the parameter golden rule, and the
per-instance store are re-proven by the existing suites.

## Testing

No new tests — the existing suites pass unchanged: `test/sql/acl.test` (134 assertions),
`GEN=ninja make test-cpp` (28 checks), and the `test/harness` demo output is intact.

## Alternatives considered

- **Everything straight into `namespace duckdb`** — works, but generic names next to the statically
  linked core and other extensions invite collisions; a nested namespace costs nothing (parent-name
  lookup still sees `duckdb` types).
- **A `src/<subsystem>/` directory tree** (full mssql layout) — premature at five TUs; flat files
  with an `acl_` prefix mirror its root-file convention and can grow into subdirectories later.
- **Keeping the rewriter class in a header** — nothing outside the TU needs the class; a single free
  function keeps the surface minimal.

## Follow-ups

- The role-aware resolver (next feature) lands as its own module behind the `PolicyStore` seam.
- `test/harness/run.sh` exits 1 because the demo contains intentional denials and the CLI exits
  non-zero if any batch statement errored (pre-existing); a future nit is asserting on expected
  output instead.
