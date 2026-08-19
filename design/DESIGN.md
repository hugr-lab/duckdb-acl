# Design

`duckdb-acl` enforces per-principal access control by **rewriting the parsed query AST before bind**,
using DuckDB's `parser_override` extension hook. It is the successor to an earlier post-bind/hook/facade
prototype; the AST-rewrite model was chosen because it makes DML/DDL/CTAS work as ordinary top-level
statements (the rewritten tree flows through the normal bind → optimize → execute path).

## Trust model

- **Gateway over a trusted channel.** Only the gateway connects to DuckDB (network/process isolation).
  A direct connection bypassing the gateway bypasses ACL — that is a deployment invariant.
- Mode is `FALLBACK`: a query with an `ACL` prefix is rewritten; anything else is parsed natively (so
  service/tooling traffic still works). Strict mode is not required under the gateway invariant.
- Resolvers and the token verifier are **read-only** — they never create or write.

## Input syntax

```
ACL ROLE  "<role>"   <sql> ; <sql> ; ...
ACL TOKEN '<token>'  <sql> ; <sql> ; ...
ACL ADMIN            <sql>            -- passthrough, no rewrite
```

Exactly one leading prefix is stripped; the remainder is parsed with the native parser. Role/claims
apply to the whole `;`-separated batch. An unrecognized second word leaves the query for the native
parser; a recognized prefix that fails enforcement throws (a non-success result in FALLBACK would be
swallowed and re-parsed natively, so denials must throw).

## Principal

```cpp
struct Principal { string role; case_insensitive_map_t<string> claims; }; // tenant, org, ...
```

`ACL TOKEN` verifies offline (signature check in production; a store hit in the PoC) → role + claims.
`ACL ROLE` trusts the gateway: role from the prefix, claims from an optional role default.

## Rewrite

Two mutually-recursive passes over the full AST (`RewriteQueryNode ↔ RewriteTableRef ↔ RewriteExpr`)
reach every position: `SELECT`/set-op/CTE/recursive-CTE nodes, the unified DML query nodes
(insert/update/delete/merge, including merge actions), join/subquery/table-function table refs, and
subquery expressions (scalar subqueries, `EXISTS`, `IN`). A scope stack of CTE names prevents a CTE from
being resolved as a catalog object.

### Replacement forms (resolver decides per object)

- **RENAME** — replace the name in place with its physical target (full path, any nesting depth). The
  ref stays a real table, so it is **writable**. Used when the whole physical object is exposed as-is.
- **SUBQUERY** — wrap a `SELECT`: allowed columns (with masks and computed columns as projection
  expressions), an RLS predicate, or a view/vfunc's full defining SQL. **Read-only by construction** —
  you cannot write through a subquery, so masked/RLS/view relations reject DML.

Default policy: no projection and no RLS → RENAME (writable); otherwise → read-only SUBQUERY.

### Virtual functions

A virtual **table function** or **scalar function** resolves to either a RENAME-alias (retarget the call
to a physical/system function, keep the arguments) or a template macro. The macro template refers to the
call arguments as `acl_arg(1)`, `acl_arg(2)`, … and to claims as `acl_claim('<name>')`; both are
replaced by copying the call-argument AST / baking the claim `Value` into the template copy.

### Function gating (the seam)

Every function reference not resolved as virtual flows through one seam. The stub denies only functions
that read external data or route queries past the ACL — source readers (`ST_Read`, `read_csv`, …),
cross-source scanners / SQL passthrough (`postgres_query`, `mssql_scan`, `query`, …), and session/secret
access (`getvariable`, `which_secret`, …). Everything else — the vast majority of extension functions,
which are pure transforms like `ST_AsGeoJSON` — passes. This is the plug-in point for the production
role-aware resolver.

### Claims and parameters

Claim values are baked in as **constants** (per-request, from the verified token): stateless and
pool-safe. The rewriter adds **no query parameters** — a user's `$1`/`?` is the only parameter and binds
normally, even when passed as a virtual-function argument (it is spliced in as an AST node). Markers
`acl_arg`/`acl_claim` are not registered as real functions, so a missed marker fails closed at bind.

## State

A `PolicyStore` lives **per database instance** (no process globals):

- carried to the parser override via `AclParserInfo : ParserExtensionInfo` on `parser_info`;
- shared with the admin setup functions via `AclScalarInfo : ScalarFunctionInfo` (`function_info`);
- holds the virtual-object/function/token maps and the resolver methods over them;
- caches parsed template prototypes in a bounded LRU (`TemplateCache`) — a template is parsed once and
  copied per request, with markers baked into the copy so the prototype stays pristine.

In production the `PolicyStore` resolver methods become the read-only, role-aware ACL callbacks, backed
by a policy source and a read-only connection pool.

## Not yet in the PoC

- A real (external) policy source + `policy_version`-keyed policy cache and lazy batch load.
- Token masking in query logs (a gateway concern — the query text is logged by the core).
- Schema-level DDL capability policy.
- The C++ tests for parameter passthrough and per-instance isolation (they live in the duckdb tree in
  the original prototype and need a C++ test target wired here).
