# Spec 157: a write binds the role's read of its target

- **Status**: implemented
- **Date**: 2026-11-13
- **Author**: hugr lab (spec 156's open item; the owner's decision 2026-11-13)

## Summary

A `DELETE`, an `UPDATE` or a `MERGE` now first binds the SELECT the role reads its target through, at query time.
When that read does not bind, the statement refuses. The usual cause is that the columns the grants name are gone
from the object or its source. Before, the statement deleted or updated every row its filter reached.
`acl_check_catalog` names a role whose object grant leaves it no column.

## Problem

Spec 156 refuses a role whose grants narrow an object's DECLARED list to none, and that is decided from the policy
alone. Two cases are known only when the statement binds:

- **An object without a declared list** (it exposes every source column). A catalog grant's `COLUMNS (id)` is
  accepted when some object of the catalog has `id`. A read of an object without `id` fails at bind, on the empty
  `COLUMNS(lambda …)`. But a plain `DELETE FROM logs`, or a `MERGE … WHEN MATCHED THEN DELETE`, names no column. It
  bound, and deleted every row the grant's filter reached. The role could not add a condition of its own, because it
  reads no column.
- **The source changes after the grant was written** (`ALTER TABLE … DROP COLUMN`), whether the object has a list or
  not. The read fails at bind; the `DELETE` still ran. So did an `UPDATE` that named a column still there.

The write-time checks judge the object and its source as they were when the grant was written. They are spec 037's
`NormaliseGrantColumns` for an object grant and `ValidateGrantColumns` for a catalog grant. They cannot hold after a
change.

## Design

The rewriter notes the role's read of a `DELETE`, `UPDATE` or `MERGE` target on the statement (`NoteReadableGuard`,
acl_rewriter.cpp). The read is physical SQL with its markers baked: `TableReadSql`, the SQL `BuildTableSubquery` reads
the object through, taken under the verb's policy (spec 145). For a renamed or cast-only read (spec 099) it is `SELECT
* RENAME / REPLACE … FROM` the source. A read that is the source's every column notes nothing. A declared list counts
as a column policy even without a grant list: a declared column the source dropped refuses the write too.

The rewriter gives each statement with noted reads a random token and keeps the reads under it
(`PolicyStore::write_guards`, 65536 tokens, least recently used). It appends a line `/* acl:guard:<token> */` to the
statement's text, which a prepared statement keeps for each of its executions. `AclProfileState::QueryBegin` takes
the token off the running statement's text. Before duckdb optimizes the statement, `WriteGuardPreOptimize`
(acl_profile.cpp, an optimizer extension) binds each read with a binder of its own, in the statement's context and
transaction:

- **The read binds.** Nothing happens. The write is never changed for the guard, and nothing is executed.
- **The read does not bind.** The statement fails before anything is written, with the read's own error as spec 155
  cuts it, without the read's position (an offset into the read's SQL, not into the client's text). For an object
  without a list that is "a star in this statement selects no column it may read"; for a declared list, "a column this
  statement reads does not exist in its source".

Any read failure blocks the write, not only "no column": a mask that no longer binds (spec 038's `mask_broken`)
blocks it too. So does a `MERGE` that only inserts. One rule covers all of it: a role writes only through a read it
can make.

Every execution of a prepared write is checked: duckdb plans an EXECUTE through the optimizer. A marked text whose
token is gone (evicted, another instance) refuses: "this write's decision is no longer known - run it again". The
token belongs to one decision. Another principal's identical text gets a token of its own, and a statement nobody
marked is not looked up: an operator's statement, `ACL NATIVE`, a read. `Connection::ExtractPlan` runs no
QueryBegin, so it has no token. A statement duckdb runs as several (an implicit PIVOT: a `MultiStatement`) gets
the marked text on each part, since each part runs under its own text. The registry is bounded by count; a read is
its SQL, usually well under a kilobyte.

**Why bound apart, not added to the write.** Two forms were tried and dropped:

- A guard inside the statement (`NOT EXISTS (<read> LIMIT 0)`) is bypassed by correlation. A subquery binds a name
  its own source lacks to the outer statement: the target's alias (`DELETE FROM ed AS v`), a `USING` relation, a
  `MERGE` source or a CTE of the principal's. Such a guard bound, and deleted every row.
- A statement-level CTE closes that hole, but a scanner that pushes a write down whole cannot write it. mysql_scanner
  refused every guarded `DELETE` / `UPDATE` ("DELETE syntax not supported"), and the mssql writer drops its pushdown
  for a `WITH`.

A read bound as its own statement has no outer scope, and the write reaches the scanner with only a comment added.
A first version kept the reads by the hash of the statement's text in spec 155's registry. Its re-review found that
fails open: another principal's identical text replaced the entry, flooding evicted it, and an operator's identical
text picked up a principal's reads.

**The check: `grant_exposes_nothing`.** It applies to a role's OBJECT grant that lists columns, when the role's grants
leave it no column of that object:

- the levels intersect to nothing (a catalog grant's list and the object grant's);
- the object's list changed under the grant (`SET COLUMNS`);
- for an object without a list, the names kept are missing from the source as it binds now.

The role is judged by the resolver itself, under a capability it holds: `select`, else its first write verb. The
finding replaces that grant's `grant_column_missing` rows, because the role reads nothing, not merely less. The repair
re-grants with a `'<columns>'` placeholder, which is refused if pasted as is. A catalog-wide list that names nothing of
some object hides that object from the role by design (spec 038), so it is not a finding.

## Enforcement & security

Fails closed: a marked write runs only after its reads bind, or refuses when its token is gone. The reads are bound in
the statement's own transaction, before anything runs. Nothing is executed for them, and the binder reads the catalog
the write's bind reads anyway. An `INSERT` names its columns, so it fails at bind when a named column is gone. Under
a column policy an `INSERT` must name them (`INSERT DEFAULT VALUES` refuses).

Known limit: the check is an optimizer extension. `SET enable_optimizer = false` or `disabled_optimizers` naming
`extension` skips it. A principal can set neither (spec 068). They are the node operator's and the gateway's, like
`allow_parser_override_extension`, which turns the whole gate off.

## Testing

`test/sql/acl_no_column_at_query.test`:

- **An object without a list under a catalog grant.** The read, a plain `DELETE` and a `MERGE` refuse; no row goes.
  A role without a list still deletes.
- **An object grant that matched, then the source dropped the column.** The role deletes before the drop and refuses
  after.
- **A renaming declared list whose source column was dropped.** The `DELETE` refuses, and so do the correlated forms:
  the target's alias, `USING`, a CTE, a `MERGE` source, a `MERGE` alias.
- **An `UPDATE` naming a column that is still there.** It refuses after the drop.
- **A cast-only read.** It refuses after the drop.
- **Write-time refusals of a source's name** (spec 037).
- **The check.** It finds drift, `SET COLUMNS`, a delete-only role and two levels intersecting to nothing, each with
  its repair.

The `DELETE`s ran without the guard, and the correlated forms ran with a subquery guard. By hand against MySQL
(`acl-mysql`): a column-policy role's `DELETE` and `UPDATE` push down as before, and refuse once the columns are
dropped. The re-reviews' probes are now refused: a prepared write after another principal's identical text,
after 65,600 other statements and after a source change; a write carrying an implicit PIVOT (in the test).

## Alternatives considered

- **A guard in the statement** (a subquery, then a CTE): bypassed by correlation, then refused by pushdown
  scanners, as above.
- **Qualifying the read's names with an alias only the read has**: a walk over every policy text. It is spec 159's,
  for reads; binding the read apart closes the writes without it.
- **Probing the source in the rewriter**: spec 065 keeps the query path off the source.
- **A write-time check only**: does not hold after a change. The owner (2026-11-13): compare at query time.

## Follow-ups

- **Spec 159: policy texts bind only to their own source.** The same correlation reaches READS. An RLS whose column
  the source lost binds, through duckdb's implicit lateral join, to a column of a relation the principal puts before
  the object: `SELECT logs.* FROM (SELECT 'eu' AS region) s, logs` returns the rows the RLS hid. A projection item
  does the same. On a `DELETE`, the RLS predicate (outside the guard) binds to the target's alias row.
- **The check skips object grants under a live schema alias.** The guard covers them; the check does not (BACKLOG).
- **A broken projection's errors name physical columns.** Examples: duckdb's REPLACE-list error, and a `DELETE …
  RETURNING k` headed `id`. These are spec 155's (BACKLOG).
