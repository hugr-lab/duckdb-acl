# Spec 051: create and replace through the served door - and REPLACE is a drop

- **Status**: implemented
- **Date**: 2026-08-30
- **Author**: hugr-lab

## Summary

Two ends of the same capability question. First, a hole: `CREATE OR REPLACE` *drops* the object it
replaces, but the rewriter only asked for `create` - a role granted `create` without `drop` could
destroy any table its schema reaches (probed live: a create-only role replaced a physical table and
its data). The same seam, one step further: the catalog's record writes are upserts, so a principal's
`CREATE VIEW` over an existing name silently replaced the record with **no** `OR REPLACE` written at
all. Both are closed by making the conflict clause mean what it says: plain CREATE refuses an
existing name, `IF NOT EXISTS` skips it, `OR REPLACE` requires the `drop` capability as well.
Second, the completion those rules unlock: Flight ingest `mode=create` / `mode=replace` into a
physical home - the door composes `CREATE [OR REPLACE] TABLE <target> AS SELECT * FROM
arrow_scan($1,$2,$3)` under the `ACL INGEST` prefix, and the rewriter enforces it exactly like a
CREATE the principal typed, because it is one. This closes the refusal spec 049 left pointing here
("creating needs a create capability and a declared physical home").

## Problem

- `RewriteCreateStatement` resolved only the `create` capability; `info.on_conflict` was never read.
  `ACL ROLE r CREATE OR REPLACE TABLE vs.t(...)` under a create-only schema grant replaced physical
  `t` - a drop by another name, granted by omission.
- `RelationStatements` (the record writer) is DELETE-then-INSERT, so `acl_register_view` /
  `acl_register_existing` over an existing name silently overwrite. The admin surface guards this
  through `CatalogObjectExists` (spec 013); the principal DDL surface (spec 016) never did.
- Flight ingest refused `mode=create` and `mode=replace` outright, promising this spec.

## Design

### The conflict clause, enforced (rewriter)

In `RewriteCreateStatement` (tables) and `RewriteCreateView`, after the `create` capability resolves:

- **`OR REPLACE` requires `drop`** - `ResolveDdlTarget(principal, key, "drop", ...)` must succeed
  **and resolve to the same schema row that hosts the create**: a parent schema's `drop` must not
  price a REPLACE an explicit child grant withheld (spec 012's no-widening-by-omission, kept at
  every level of the path - the review's refinement finding, probed live). Replacing IS dropping;
  spec 016's capability split stays meaningful.
- **Every CREATE path checks the record** - views, `VIRTUAL ONLY`, and plain tables alike: a plain
  CREATE over an existing relation record is refused ("already exists"); `IF NOT EXISTS` becomes a
  no-op (the statement is dropped from the batch, nothing registered, the body discarded
  unvalidated - nothing of it ever runs); `OR REPLACE` (priced above) upserts, as the record writer
  always did. The table path needs this exactly as much as the view path, because a view record
  occupies a name with nothing physical behind it - "the physical CREATE fails natively on a
  duplicate" does not cover it (the review's finding: a plain `CREATE TABLE` clobbered a view
  record).
- `CREATE [OR REPLACE] TEMP TABLE` is untouched: the session's own object, spec 050's rule (the
  temp branch returns before any of this).

### Ingest into a physical home (door)

The non-temporary mode matrix in `DoPutCommandStatementIngest` becomes:

| mode (ADBC) | if_not_exist / if_exists | composed statement |
| --- | --- | --- |
| append | FAIL / APPEND | `INSERT INTO <target>(<cols>) SELECT <cols> FROM arrow_scan(...)` (unchanged) |
| create | CREATE / FAIL | `CREATE TABLE <target> AS SELECT * FROM arrow_scan(...)` |
| replace | * / REPLACE | `CREATE OR REPLACE TABLE <target> AS SELECT * FROM arrow_scan(...)` |
| create_append | CREATE / APPEND | refused as ambiguous (same as the temporary path) |

`<target>` is the identifier-quoted catalog/schema/table the client named, exactly as the append
path already composes it; the rewriter resolves it through `ResolveDdlTarget` like any written
CREATE, registers the record where the schema needs one (`acl_register_created` follow-up), and the
new REPLACE rule prices `mode=replace` at `create`+`drop`. The `ACL INGEST` prefix's shape check
widens from "one INSERT or one temporary CREATE TABLE" to "one INSERT or one CREATE TABLE" - still
exactly the statements the door composes, still unreachable for client text. The row-count
cross-check and the door-owned transaction wrap the CTAS exactly as they wrap the append.

## Enforcement & security

- Fail-closed throughout: no schema with `create` → refused; `OR REPLACE` without `drop` → refused;
  an existing view name without a conflict clause → refused. Nothing new is granted by omission -
  the change only *removes* two grants-by-omission.
- The CTAS body under `ACL INGEST` is server-composed `SELECT * FROM arrow_scan($1,$2,$3)` and the
  rewrite gates its read like any CTAS; the arrow_scan exemption still travels only with the prefix
  only the door composes.
- The golden rule stands: the three POINTER parameters are the door's own, on a statement that
  carries nobody else's.
- `CREATE OR REPLACE TEMP TABLE` stays priced by `temp` alone - deliberate, not an omission: the
  object is the session's own, nothing shared or granted is destroyed by replacing it.
- A REPLACE keeps the virtual name and therefore the grants on it: a grant projection or key probed
  against the old shape (spec 026) may describe the new object wrongly until
  `acl_refresh_schema()` - the same situation as altering a physical table under a standing grant,
  documented rather than blocked.

## Testing

- `test/sql/acl_ddl.test`: the probe as a pin - a create-only role's `CREATE OR REPLACE` is refused
  naming `drop`, and the physical table survives with its rows; with `drop` granted it replaces;
  `CREATE VIEW` over an existing name refused / `IF NOT EXISTS` no-op / `OR REPLACE` without `drop`
  refused, with it replaced.
- `test/e2e/flight/run.sh`: a staging schema granted `create`+`drop` - raw `mode=create` lands rows
  in a new physical table, reads back, `mode=replace` swaps it, `DROP TABLE` through the update wire
  removes it; the old refusal pins move to the rewriter's messages ("no schema of the catalog
  allows creating").
- `test/e2e/flight/adbc.sh`: the real driver's `adbc_ingest(mode="create")` refusal now carries the
  rewriter's reason.

## Alternatives considered

- **Typed CREATE from the Arrow schema** (compose `CREATE TABLE t(col TYPE, ...)` then append)
  instead of CTAS - rejected for now: CTAS gets duckdb's own types from the same scan that reads
  the stream, one statement stays atomic, and a declared-type mismatch surfaces at the same place.
  Revisit if a client needs NOT NULL/PK declarations at ingest time.
- **Refusing `OR REPLACE` outright** - rejected: replace is a real workflow (the staging swap), and
  `create`+`drop` prices it exactly.

## Follow-ups

- A uniqueness constraint on `relations(vcat, vname)` (schema migration): the existence check runs
  at rewrite time and the record write later in the batch, so two concurrent record-writing CREATEs
  on different connections could both pass and upsert last-writer-wins. Physical tables are guarded
  by duckdb's own catalog; the records deserve the same guard at write time.
- The single-node backlog review (after this spec): TLS on the node, pin-on-demand pooling,
  transactions on the held connection, temp columns surfaces. Sessions stay node-local by design -
  the shared-session-backend follow-up of spec 040 is dropped (2026-08-30): nodes know nothing of
  each other, stickiness is the front's cookie.
