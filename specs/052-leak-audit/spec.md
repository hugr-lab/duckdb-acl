# Spec 052: the leak audit - what a gate cannot see, and EXPLAIN as a capability

- **Status**: implemented
- **Date**: 2026-08-30
- **Author**: hugr-lab

## Summary

Owed before a node serves anyone for real (design/ROADMAP, "After the servers land"): an inventory of
what DuckDB hands a principal *past* the rewriter, because the rewriter gates only what it walks. The
audit went surface by surface against a served principal; almost everything is already fail-closed -
the metadata table functions are denied by the function gate, the metadata *names* are replaced by the
principal's own filtered listings, binder errors under a projection name only the columns the role
reads. One surface leaks: **EXPLAIN prints physical names** - the scan of a RENAME-form virtual table
is `phys.schema.table`, and EXPLAIN ANALYZE runs the query besides. The decision (2026-08-30): that a
principal who may run a query also learns where it lands is acceptable *behavior*, but it belongs to a
role that was granted it - so EXPLAIN becomes an explicit `explain` capability, refused by default.

## Problem

The rewriter enforces on the AST it rewrites. Two classes escape that by construction: surfaces
answered *before* a statement is parsed (a server's own metadata), and text a statement *produces*
(plans, error messages). A served deployment is the first time either reaches an untrusted principal,
so each was probed against a live principal rather than reasoned about from its name.

## Design

### The inventory (probed 2026-08-30, catalog mode, a RENAME-form virtual table over a physical one)

| Surface | Who answers | What a principal gets | Verdict |
| --- | --- | --- | --- |
| `EXPLAIN [ANALYZE] <query>` | duckdb planner | `Table: phys.main.secret_orders` in the plan | **leaked → fixed here** |
| binder error, read path (SUBQUERY *or* RENAME) | rewriter | only the granted columns; the physical target is aliased to the virtual name, so a column-not-found error names the *alias* | safe |
| binder error, write path (INSERT/UPDATE names a column that does not exist) | duckdb binder | the physical **leaf** table name (`Table "orders_physical" does not have column …`) - duckdb's INSERT/UPDATE binder resolves columns by the target table, not its alias | **residual, low - see below** |
| `duckdb_tables()` (function form) | rewriter → filtered listing | the principal's own tables only | safe (spec 035) |
| `duckdb_settings/secrets/functions()` | function gate | "table function … is not allowed" | safe (denied) |
| `sqlite_master`, `pragma_table_info(...)` | rewriter / gate | "no access" / "not allowed" | safe |
| `current_setting()`, `getvariable` | function gate | denied | safe (spec 031) |
| runtime error (arithmetic, …) | duckdb | no object name cited | safe |
| Flight `GetSqlInfo` / `GetXdbcTypeInfo` | the door's SqlInfo registry | server capabilities, no data | out of scope: server metadata, not a principal's catalog (noted, not a leak) |
| Flight catalog RPCs (`GetTables`, …) | composed SQL under the prefix | the principal's own catalog | safe (spec 046) |
| `json_execute_serialized_sql(<serialized>)` | json extension, executes the statement | rows of any physical table - the statement is never parsed, so never rewritten | **bypass → fixed (addendum 2026-09-15)** |
| `json_serialize_plan('<sql>')` | json extension, binds against the physical catalog | table, column and type names no grant shows | **leaked → fixed (addendum 2026-09-15)** |

So the audit's yield is one finding fixed here (EXPLAIN) and one low residual accepted (below); the
rest is a record that the gate and the surface replacements already cover what they must - kept as a
table so the next surface added has a checklist.

**The write-path residual.** An `INSERT`/`UPDATE` that names a nonexistent column produces a duckdb
binder error citing the physical *leaf* table name - because duckdb resolves a DML target's columns
by the bound table, not by the `AS <virtual>` alias the rewriter attaches (the read path is aliased
and stays safe; this is why `MapTargetQualifier` exists for the write path). It is accepted, not
fixed, for the same reason EXPLAIN is a capability rather than a refusal: the principal already holds
a write capability on *this exact object*, learns only its unqualified leaf name (never the
catalog/schema/database), and only by deliberately naming a column that does not exist. Scrubbing
duckdb's own binder message is brittle and buys little. Recorded here so it is a known, bounded fact
rather than a surprise; a scrub could ride the write path later if a deployment needs it.

### EXPLAIN as the `explain` capability

- A new **explicit** capability, `explain`, on the MAIN catalog grant - never part of the
  unstated-caps default (spec 012's rule, exactly like `temp` and unlike the five data verbs).
- `RewriteStatement`'s `EXPLAIN_STATEMENT` case checks `PolicyStore::PrincipalMainCap(principal,
  "explain")` before it recurses; without it, `Deny`. With it, EXPLAIN proceeds as before - the inner
  statement is rewritten, the plan shows the physical objects it resolves to, and that is accepted as
  the point of holding the capability.
- Covers `EXPLAIN` and `EXPLAIN ANALYZE` alike (one statement type, one gate) - ANALYZE runs the
  query, so it is at least as sensitive and wants at least the same gate.
- The gate is at the outermost EXPLAIN, so it also covers `EXPLAIN` of a PRAGMA that spec 031 answers
  as a SELECT (whose plan would name the policy catalog's own tables) - one rule, no special cases.

### Addendum 2026-09-15 - two functions that take SQL past the parser override

The inventory above is a checklist of *surfaces*, and it missed a class: functions whose argument is
itself a statement. Found in a live check of the whole stack (both doors, acl_otel beside, the local
Grafana bench) by probing every table function a real node has - 148 with the extensions the build
links - under a principal holding one grant on an empty catalog.

- **`json_execute_serialized_sql`** executes a statement from its serialized JSON form. The parser
  override never sees it, so nothing rewrites it: under the principal it returned every row of a
  physical table no grant names. The whole model, gone in one call - and the serialized form is
  plain JSON anyone writes by hand, so `json_serialize_sql` being reachable is not the hole and
  denying it would guard nothing.
- **`json_serialize_plan`** binds its SQL against the physical catalog to build a plan, and the
  plan names tables, columns and types the principal was never shown. EXPLAIN by another name, and
  EXPLAIN is the explicit capability this spec made it.

Both are **hard-denied in `FunctionAllowed` ahead of the catalog gate**, beside `arrow_scan` and for
its reason: an `acl_allow_function` row must not be able to re-open them. The PRAGMA form of the
executor was already refused as a PRAGMA. `test/sql/acl_serialized_sql_gate.test` pins all of it,
including the allow-row attempt and the control that plain serialization still works; built without
the fix, its first assertion fails with the payroll rows in hand.

What the same probe says about the rest of the 63 table functions that pass the gate: 29 fail in the
binder on the empty argument list the probe used (`range`, `unnest`, `repeat`, `parquet_*`,
`read_duckdb`, the json readers - the file readers among them are the denylist's 2026-09-14 backlog
item, unchanged), 34 ran - the listings the rewriter substitutes (`duckdb_tables/columns/schemas/
databases`, spec 035), read-only node facts (`duckdb_keywords`, `pragma_platform`,
`icu_calendar_names`, `pg_timezone_names`), and three that act on the node rather than read it:
`enable_logging` / `disable_logging` / `truncate_duckdb_logs`, `enable_profiling` /
`disable_profiling`, and `checkpoint` / `force_checkpoint`. None of those reads data; each is a
principal reaching the operator's knobs, and they belong to the allowlist redesign in the backlog
rather than to this addendum - this one closes the two that read.

### Addendum 2026-09-17 - three expressions the walker did not visit

Found while probing the function surface for design 072, then by a probe over every position an
expression can sit in (`test/sql/acl_expression_positions.test` keeps that probe): the walker gates
what it visits, and three things sat where it did not look.

- **VALUES rows** - the serious one. `RewriteTableRef` treated an expression list as having nothing
  to rewrite, so `SELECT * FROM (VALUES (getvariable('x')))`, `INSERT INTO mine VALUES
  ((SELECT ssn FROM phys.main.secrets LIMIT 1))` and a multi-row list each passed a denied reader or
  a subquery over an ungranted physical table straight to the binder: the function gate and the
  "unknown object is refused" rule both stood only in the positions the walker reached. VALUES rows
  are now walked like a select list. The probe pinned the other forty positions - WHERE, ORDER/GROUP
  BY, HAVING, QUALIFY, window, LIMIT/OFFSET, DML SET/WHERE/RETURNING, ON CONFLICT, MERGE, `* REPLACE`,
  lambdas, CASE, IN, aggregate ORDER BY/FILTER, table-function arguments, CTEs, DISTINCT ON,
  UNION, join conditions, CTAS into a session temp - all refusing; PIVOT/UNPIVOT are refused as forms.
- **The keyword spelling of the session identity.** `SELECT current_catalog` - no parentheses - is a
  single-part column reference to the parser; the binder turns it into the call only when no column
  of that name binds (`Binder::GetSQLValueFunction`), after the rewrite, so the call it made was the
  physical one: under the principal it answered `memory`, the server's default database, where
  `current_catalog()` answered `sales`. Same for `current_schema`. The rewriter substitutes the
  keyword where it substitutes the call. A bare single-part name is the identity, as SQL reads it; a
  column that carries the name is reached qualified (`t.current_catalog`) and left to the binder,
  and the bare spelling never binds to a column under a principal - so a relation cannot shadow the
  keyword to reach the physical default either. The other SQL value keywords (`current_user`,
  `session_user`, `current_role`, `user`, the date/time ones) expand to duckdb's own constants or
  clocks, not to a physical name, and are left alone; when function categories (design 072) land,
  the keyword forms are converted to calls ahead of the gate so a keyword cannot bypass what its
  call is denied.
- **The header of the substituted call.** The substitution carried the caller's alias and nothing
  else, so `SELECT current_database()` under a principal named its column after the expression that
  replaced it - the whole listing query, policy tables and all, rendered into a column header. The
  select item now keeps the name duckdb gives the expression as written (`current_database()`,
  `current_schemas(true)`, `current_catalog`), so a client sees the same header prefixed or not.

`test/sql/acl_metadata_leak.test` pins the keyword forms and the headers; the positions probe pins
VALUES beside everything else.

## Enforcement & security

- Fail-closed: no `explain` capability → EXPLAIN refused, physical names and all. The capability is
  explicit and never inherited by omission, so no existing grant silently gains it.
- Nothing else in the inventory changed - the audit *confirmed* the existing gate and replacements;
  this spec adds one capability and one check, and touches no other surface.
- Memory mode (no policy catalog) has no MAIN grant to carry the capability, so EXPLAIN is refused
  there under a principal - consistent with memory mode being the dev-stub, not a served deployment.

## Testing

- `test/sql/acl_show_surface.test`: EXPLAIN refused for a role whose MAIN grant has the unstated
  default (no `explain`); granted `explain`, the existing EXPLAIN-of-a-rewritten-PRAGMA test passes.
- `test/sql/acl_show_surface.test` also pins `EXPLAIN ANALYZE` refused without the cap (it runs the
  query, so it wants at least the same gate, and the gate is ahead of bind/execute), and the audited
  leak itself permitted *with* the cap - a plain `EXPLAIN SELECT` rendering the physical name.
- `test/sql/acl.test`: memory mode has no MAIN grant to carry the capability, so a principal's
  EXPLAIN is refused there - pinned, since it is a deliberate consequence rather than an accident.
- `test/e2e/flight/run.sh`: the served `analyst` (granted `select, insert, temp`, not `explain`) is
  refused EXPLAIN through the real door with the capability's reason.
- The inventory rows that are already safe are pinned by their own specs (035 metadata, 031
  PRAGMA/SHOW, 046 catalog RPCs); this spec does not duplicate them.

## Alternatives considered

- **Refuse EXPLAIN outright under any principal** - rejected: a plan is a legitimate thing for a
  trusted analyst to want, and a capability prices it exactly instead of denying it to everyone.
- **Rewrite physical names out of the plan text** - rejected: the plan is rendered by duckdb, the
  physical name is genuinely what runs, and scrubbing rendered text is brittle. The decision was that
  physical names in a plan are acceptable *to a granted role*, which makes scrubbing unnecessary.

## Follow-ups

- `GetXdbcTypeInfo` (spec 046 follow-up) is still unimplemented; it describes types, not data.
- If a tool needs plans without the physical home, a plan-scrubbing mode could ride the same
  capability later - not built, not needed by the decision above.
