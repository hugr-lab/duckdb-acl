# Spec 001: parser_override + AST rewrite (core model)

- **Status**: implemented
- **Date**: 2026-08-19
- **Author**: hugr-lab

## Summary

Enforce per-principal access control by rewriting the parsed query AST **before bind**, via DuckDB's
`parser_override` hook. A trusted gateway prepends an `ACL ROLE|TOKEN|ADMIN` prefix; the extension
verifies the principal, resolves virtual names to physical objects (with row-level security, column
masking, computed columns, virtual functions), gates dangerous functions, and returns real
`SQLStatement`s to the normal execution path. This is the seed feature; later features are refinements.

## Problem

Access control layered *after* binding (hooks/post-bind visitors, or a facade catalog) cannot cleanly
express DML: a table function can only return a relation, and DML is a statement root, so INSERT/UPDATE/
DELETE/MERGE against virtual objects don't work. We also want RLS and column masking to be structural
(the binder itself rejects a denied column) and claim values to be pool-safe, without a virtual catalog
that confuses tooling.

## Design

- **Input**: `ACL ROLE "<role>" <sql>`, `ACL TOKEN '<token>' <sql>`, `ACL ADMIN <sql>`. Exactly one
  prefix is stripped; the remainder is parsed natively; role/claims apply to the whole `;` batch.
- **Mode**: `allow_parser_override_extension='fallback'` — `ACL …` is rewritten, everything else is
  native. A recognized prefix that fails enforcement **throws** (a non-success result in FALLBACK is
  swallowed and re-parsed natively, so denials must throw).
- **Principal**: TOKEN verifies offline → role + claims; ROLE trusts the gateway (role + optional
  default claims).
- **Rewrite**: three mutually-recursive passes (`RewriteQueryNode ↔ RewriteTableRef ↔ RewriteExpr`)
  reach every position — SELECT/set-op/CTE/recursive-CTE, the unified DML query nodes (incl. merge
  actions), join/subquery/table-function refs, and subquery expressions (scalar/`EXISTS`/`IN`). A CTE
  scope stack prevents a CTE name from resolving as a catalog object.
- **Replacement forms** (resolver picks per object): **RENAME** (name → physical in place, writable) or
  **SUBQUERY** (wrap a SELECT with projection/masks/computed columns/RLS or view/vfunc SQL, read-only).
- **Virtual functions**: RENAME-alias of a physical/system function, or a template macro with `acl_arg(n)`
  argument substitution and `acl_claim('…')` claim baking.
- **Function gating seam** (`PolicyStore::FunctionAllowed`): denies data-readers / rights-bypass
  functions (`read_csv`, `postgres_query`, `getvariable`, …), passes the rest.
- **State**: per-instance `PolicyStore` (no globals), reached from the parser via `AclParserInfo` and
  from the admin functions via `AclScalarInfo` (`function_info`); parsed templates cached in a bounded
  LRU and copied per request.

## Enforcement & security

- Column/RLS enforcement is structural: a denied column is absent from the safe subquery, so the binder
  rejects it; RLS claim values are baked as constants (pool-safe, no session state).
- The rewriter adds **no query parameters** — a user's `$1`/`?` is the only parameter and binds
  normally, even as a virtual-function argument (spliced in as an AST node).
- `acl_arg`/`acl_claim` are not real functions ⇒ a missed marker fails closed at bind.
- An unknown/denied name is refused (never left for the binder to hit the real catalog). A direct
  physical name is not a mapped virtual name ⇒ denied.
- Trust: only the gateway connects to DuckDB; admin-supplied policy text (phys/cols/rls/templates) is
  trusted, user-supplied values are inserted as AST nodes (no text injection).

## Testing

`test/sql/acl.test` (126 assertions): ROLE/TOKEN RLS, column projection + masking, `SELECT *` narrowing,
computed columns, full-path/RENAME resolution, virtual views and table/scalar functions (incl. nested
and argument-as-expression), function gating (allow/deny + policy-driven flip), subquery/CTE/EXISTS/IN
traversal, CTE shadowing, and DML end-to-end (INSERT/UPDATE/DELETE/MERGE, read-only denial, capability
denial), plus a multi-statement batch. Parameter passthrough and per-instance isolation were proven with
C++ prepared-statement tests in the PoC tree (to be re-homed here — see follow-ups).

## Alternatives considered

- **Post-bind plan gate / hooks**: works for read gating but hits the DML wall.
- **Facade (virtual) catalog**: dynamic name→physical resolution, but confuses tooling and still can't
  make virtual-name DML natural.
- **`parse_function` (custom syntax)** instead of `parser_override`: only fires on PEG failure and
  produces a table function — DML wall again.
- **`$var` / session variables for claims**: parameter-namespace and pool-safety hazards; baked
  constants chosen instead.

## Follow-ups

- Re-home the C++ tests (parameter passthrough, per-instance isolation) into this repo.
- Replace the in-memory admin stubs with a read-only, role-aware resolver behind the `PolicyStore` seam
  (external policy source, `policy_version` cache, connection pool).
- Token masking in query logs (a gateway concern); schema-level DDL capability policy.
