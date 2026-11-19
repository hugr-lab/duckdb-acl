# Spec 173: a bulk load that merges or removes by the object's key

- **Status**: implemented
- **Date**: 2026-11-19
- **Author**: hugr-lab

## Summary

A Flight SQL bulk load (`DoPut(CommandStatementIngest)`, spec 049) appends, creates or replaces - what the protocol
names. A load that upserts (a CDC feed, a daily snapshot that corrects yesterday's rows) or deletes by key had to stage
into a session temp table and run a MERGE by hand (spec 050 / 172's e2e). The protocol leaves room for exactly this:
`CommandStatementIngest.options` is "backend-specific". An ingest that names `acl.mode = merge` upserts the stream by
the target's **declared PRIMARY KEY** (spec 048); `acl.mode = remove` deletes the rows whose key the stream carries.
And a bulk load is a right of its own: the explicit `ingest` capability, beside the operation's.

## Problem

- No upsert and no delete through ingest: the client stages, then writes the MERGE / DELETE itself - two round trips,
  a session cookie, a temp right (`temp`), and its own handling of duplicate keys.
- A bulk load is priced like one INSERT: whoever may insert a row may stream a billion. The owner wants the bulk path
  granted on its own (2026-11-17).

## Design

### The modes

The protocol's modes stay as `FlightSql.proto` defines them: `if_exists = APPEND` appends, `REPLACE` drops and
recreates the table, `if_not_exist = CREATE` creates it (specs 049-051). One backend option is added:

| `options["acl.mode"]` | what the load does                                             | the statement the door composes     |
|-----------------------|----------------------------------------------------------------|-------------------------------------|
| (absent)              | the protocol's mode                                            | `INSERT` / `CREATE TABLE AS`        |
| `merge`               | a row whose key exists updates it, any other row is inserted   | `MERGE INTO … USING … ON <key>`     |
| `remove`              | the rows whose key the stream carries are deleted              | `DELETE FROM … USING … WHERE <key>` |

`acl.mode` writes into a table that exists: with `merge` / `remove` the protocol's mode must be append (`if_not_exist
= FAIL`, `if_exists = APPEND` - what ADBC's `adbc.ingest.mode.append` sends), else the call is refused; a temporary
target is refused (a session temp declares no key). Any other `acl.*` option, or another value, is refused by name; an
option outside `acl.` is not ours and is left alone.

**The key** is the target's declared `PRIMARY KEY` (spec 048, `keys` rows of kind `relation`), in virtual names - the
stream's column names. A target without one is refused (`declare its key: ALTER VIRTUAL TABLE … SET PRIMARY KEY`). The
stream must carry every key column; a `merge` stream's other columns are what it updates and inserts (named, never
`SET *` - spec 172's rule), a `remove` stream's other columns are not read.

**Duplicate keys in one stream: the last row wins** (the owner, 2026-11-17). The door numbers the stream's rows as it
reads them (`__acl_ingest_row`, a column of its own appended to each batch - a stream that names it is refused), and
the merge source keeps, per key, the row with the highest number:

```sql
MERGE INTO <target> AS __acl_target
USING (SELECT <columns> FROM arrow_scan()
       QUALIFY row_number() OVER (PARTITION BY acl_ingest_key() ORDER BY "__acl_ingest_row" DESC) = 1) AS __acl_ingest
ON acl_ingest_key()
WHEN MATCHED THEN UPDATE SET <c> = __acl_ingest.<c>, …   -- the non-key columns
WHEN NOT MATCHED THEN INSERT (<columns>) VALUES (__acl_ingest.<c>, …)

DELETE FROM <target> AS __acl_target USING (SELECT <columns> FROM arrow_scan()) AS __acl_ingest
WHERE acl_ingest_key()
```

`acl_ingest_key()` is a marker the rewriter expands, under the `ACL INGEST` prefix only, from the resolved target's key:
in `ON` / `WHERE` to `__acl_target.k = __acl_ingest.k AND …`, in `PARTITION BY` to the key's columns. Anywhere else it
is an `acl_*` name - never set, refused by the gate - and a marker the rewriter missed fails at bind (it is never a
registered function). A key compares with `=`: a row whose key holds a NULL matches nothing (merge inserts it, remove
deletes nothing) - and the last-row rule keeps every such row (`QUALIFY … = 1 OR k IS NULL`: `PARTITION BY` would put
the NULLs together and keep one). A merge whose every column is a key column updates nothing (`WHEN MATCHED THEN DO
NOTHING`). Two `acl.mode` options (`options` is a map whose keys differ by case) are refused.

**The key is compared as stored.** A key column the role reads masked or not at all - or, for a merge, writes masked -
refuses the load: the read policy would put the mask into the `ON` / `WHERE`, so a merge matches by the mask's value
(none of the existing rows: a duplicate key) and a remove under a constant mask matches every row (the review's probe:
`MASK (id AS 'xx')`, a stream carrying `'xx'` deleted the object's every row).

The dedup reads the whole stream before the first write (a window); duckdb spills it like any sort.

### The count

The door checks an append by its count: the rows written equal the rows the stream delivered (spec 049). A merge
writes one row per distinct key (more where the target already holds duplicates - a declared key is never enforced),
and a remove deletes what it finds, so for these modes there is no count to check: the door reads to its end whatever
of the stream the statement left (a join that needed no more of it), so `acl_max_ingest_rows`, a cancel and a broken
stream still fail the load, and answers the rows the statement affected (`DoPut`'s `record_count`).

### The `ingest` capability

`ingest` is explicit-only, never in the unstated default (`select, insert, update, delete, merge`) - like `temp`,
`explain`, `secrets` and `lineage`. It is judged on top of the operation's own capability, wherever a door streams
rows into a table:

| the load                                    | judged on                         | capabilities      |
|---------------------------------------------|-----------------------------------|-------------------|
| Flight append                               | the target object                 | `ingest` + `insert` |
| Flight `acl.mode = merge`                   | the target object                 | `ingest` + `merge` |
| Flight `acl.mode = remove`                  | the target object                 | `ingest` + `delete` |
| Flight create / replace                     | the home schema (spec 051)        | `ingest` + `create` (+ `drop`) |
| Flight temporary (spec 050)                 | the MAIN catalog grant            | `ingest` + `temp` |
| quack `SEND_DATA` drain (spec 042)          | the INSERT's target               | `ingest` + `insert` |

The owner's "merge = insert + update" is the MERGE verb's own capability here: spec 003 prices a MERGE at `merge`,
and a composed MERGE is one - kept by the owner (2026-11-19). A catalog grant's `ingest` reaches its objects as its other caps do; `CAPS` written on an
object without it withholds it. A create's `ingest` and `create` are judged as two lookups on the home - roles unite
per capability there as everywhere (spec 145).

**A quack client streams every insert.** quack plans each INSERT into an attached quack table - `VALUES (1)` included -
as a `SEND_DATA` stream and a drain, so on that door `ingest` is needed for any write of rows, one or a billion; the
door cannot tell them apart - kept by the owner (2026-11-19): the by-key modes are Flight's alone anyway. And the drain is admitted only as the direct source of an INSERT (`INSERT INTO t SELECT *
FROM <drain>`, what the client composes): a stream read in the INSERT's own `WITH`, as a MERGE's source, in a CTAS or
an UPDATE's FROM judged no target's `ingest` - such a statement is refused (the review's finding).

`ingest` gates the streaming paths. A client's own SQL - `INSERT … VALUES` with many rows, a prepared INSERT executed
with many parameter sets (`DoPutPreparedStatementUpdate`, at most 65,536 a call) - is the verb's alone.

## Enforcement & security

- The composed statements are the door's (the `ACL INGEST` prefix only the door composes, spec 049), now four shapes:
  INSERT, CREATE TABLE, MERGE, DELETE - one statement, nothing else under the prefix. Each goes through the same
  rewriter as a client's: RLS joins the ON / WHERE (a row outside the grant is never matched), spec 024's check
  confines what a merge writes, spec 172's values are computed on both branches, the key's columns are read under the
  read policy (a key column the grant hides refuses the load).
- `acl_ingest_key()` expands only under the prefix and only from the resolved target's declared key; the rewriter adds
  no parameter (the golden rule).
- The row number is the door's column, named so no client column can stand in for it (a stream naming
  `__acl_ingest_row` is refused before anything runs).
- The load runs in a transaction the door owns (spec 049): a refusal, a cancelled stream or an incomplete read rolls
  everything back.

## Testing

- `test/cpp/test_acl_ingest_prefix.cpp`: the prefix admits MERGE and DELETE (an UPDATE stays refused);
  `acl_ingest_key()` expands from the declared key (the composed shapes reach duckdb's own `ArrowScanFactory` check),
  a target without a key and a masked key refuse, the marker under `ACL SESSION` is refused, `ingest` missing refuses
  merge / remove / append and the home's create.
- `test/cpp/test_acl_session.cpp`: a hand-composed drain in an INSERT's `WITH` or as a MERGE's source is refused.
- `test/sql/integration/acl_quack_ingest.test`: a drain without `ingest` is refused, with it lands;
  `platform_views.test`: the caps STRUCT has `ingest`.
- e2e `test/e2e/flight/run.sh` + `client.py`'s `@ingest` (a raw `DoPut(CommandStatementIngest)` carrying `options`,
  since ADBC's driver sends none): merge with a duplicate key (the last row wins) and an existing key (updated), two
  NULL keys (both kept), RLS (a row of another tenant refused; a remove of another tenant's key deletes nothing), remove,
  `acl.mode` under mode create, twice, or an unknown `acl.` option refused, a merge into an object with no key refused,
  a role without `ingest` refused.

## Alternatives considered

- **New protocol modes.** `TableExistsOption` is an enum of the protocol's; a value of ours breaks every other
  server and client. `options` is the protocol's own extension point.
- **Stage, then MERGE in SQL** (what 172's e2e does). Works today; two round trips, a temp right and duplicates left to
  the client.
- **Dedup by `row_number() OVER ()` without a column of ours.** The scan's order is not a promise a window keeps; the
  door's own number is.
- **`IS NOT DISTINCT FROM` on the key.** A NULL is no key value; matching NULLs would merge unrelated rows.

## Follow-ups

- ADBC's Flight SQL driver passes no `options` (1.12). Our JDBC driver carries them (the owner, 2026-11-19):
  acl-clients spec 009, `connection.unwrap(AclIngest.class).ingest(…, Mode.MERGE | REMOVE)` on Arrow's own Flight SQL
  client. An ADBC driver option stays upstream's.
