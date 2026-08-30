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
| binder error under a COLUMNS projection | rewriter (SUBQUERY form) | only the granted columns (`Candidate bindings: id`) | safe |
| `duckdb_tables()` (function form) | rewriter → filtered listing | the principal's own tables only | safe (spec 035) |
| `duckdb_settings/secrets/functions()` | function gate | "table function … is not allowed" | safe (denied) |
| `sqlite_master`, `pragma_table_info(...)` | rewriter / gate | "no access" / "not allowed" | safe |
| `current_setting()`, `getvariable` | function gate | denied | safe (spec 031) |
| runtime error (arithmetic, …) | duckdb | no object name cited | safe |
| Flight `GetSqlInfo` / `GetXdbcTypeInfo` | the door's SqlInfo registry | server capabilities, no data | out of scope: server metadata, not a principal's catalog (noted, not a leak) |
| Flight catalog RPCs (`GetTables`, …) | composed SQL under the prefix | the principal's own catalog | safe (spec 046) |

So the audit's yield is one finding, and the rest is a record that the gate and the surface
replacements already cover what they must - kept as a table so the next surface added has a checklist.

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
