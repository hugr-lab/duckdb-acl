# Spec 154: a principal's catalog record follows the client's ROLLBACK

- **Status**: implemented
- **Date**: 2026-11-05
- **Author**: hugr lab (found by spec 151's reviews; the owner's order: after spec 153)

## Summary

A principal's DDL in a schema that records its objects writes a catalog record. The record is written on the policy
store's own connection, so the client's transaction does not reach it: spec 113 chose that, because dbt swaps tables
inside one transaction. Spec 113 gave a RENAME an undo at ROLLBACK; nothing else had one. Now every record write
inside a client's transaction can be taken back. The write keeps what it did - the names' rows before and after it,
read in its own transaction, and the store version it committed. A ROLLBACK takes the writes back newest first, each
in one write of the store, by a rule per kind that never undoes over somebody else's write.

## Problem

- **A rolled-back CREATE left its record.** `BEGIN; CREATE TABLE vs.payroll(x INT); ROLLBACK` kept the record
  `vs.payroll → phys.lake.payroll` without a table. Any physical table of that name made later was read through the
  record:
  - one the operator creates;
  - one another role creates in another schema over the same home.
  The role read `ceo | 999`.
- **A rolled-back DROP lost the record and its grants.** `BEGIN; DROP TABLE vs.keep; ROLLBACK` brought the table
  back, but its record, its object grants (RLS, columns), references and comments were gone, and the name was marked
  dropped. The table no longer showed.
- **A rolled-back `CREATE VIEW` kept the view**, and a rolled-back `CREATE OR REPLACE VIEW` kept the new body.
- **dbt's swap rolled back left a record**: `CREATE m__tmp …; ALTER … RENAME TO m; ROLLBACK`.

## Design

- **One name's rows** (`PolicyStore::RelationRows`, read by `ReadRelationRows`) are its rows in the tables a record
  writes and `CatalogDropRelation` clears: relations, object columns, relation columns, type facts, column comments,
  keys, the object grants and their projections, the references naming it and their columns, and its
  `schema_dropped` mark. `RelationRowSources` lists them once; the drop builds its deletes from that list, so the two
  cannot drift apart. Each row is kept as its values' SQL (a NULL bare), sorted, with the table's column names; the
  record's own form, physical name and body are kept beside them.
- **A record write keeps what it did** (`RecordWrite`): the names it changed - one, or a rename's old and new name -
  each with its rows before and after, the store it wrote and the policy version it committed. The writers
  (`CatalogRegisterCreated`, `CatalogRegisterView`, `CatalogDropRelation`, `CatalogRenameRelation`) take an optional
  `RecordWrite`. They read the before-images where their `WriteWithReads` body starts and the after-images once its
  statements ran (`WriteWithReads`' new `after_writes`), in the same transaction: nobody's write lands between an image
  and the write.
- **The undo** (`CatalogUndoRecordWrite`) runs in one `WriteWithReads` and re-reads the names there. By kind:
  - **a record the write created** goes, as a drop takes a record - a grant, a comment or a reference written on it
    meanwhile goes too (an object that never committed holds nothing; a same-named function keeps the shared grant
    rows, a reference to a table function of that name stays) - but unmarked: the before-image's mark comes back.
    Only while it is still that record (`SameRecord`: its form, physical name and body, and the facts probed from its
    source - type facts, its columns' schema): one written again meanwhile (another node's after its commit's
    probes) is not ours; an operator's declaration on it (a key, a comment, a grant) is not a reason to keep it. A
    rename of such a record (`takes_created`, tracked as the steps are queued) is taken where it is, the same way,
    and goes back to its old name only while that is free (the create's undo then takes it there) - a touched dbt
    swap, or the old name taken by the principal's own other session, would leave a record of nothing otherwise.
    What is put back after a take is only what the write itself changed (its mark): a grant a dropped same-named
    function shared stays gone.
  - **a record the write dropped** comes back only when every store version after the drop's is this transaction's
    own (its record writes and the undo's so far). A cascade elsewhere - a role, a schema or a catalog dropped, a
    catalog grant revoked - deletes nothing of the name, whose rows the drop already took, so the images cannot see
    it; the version chain does, and a role dropped and made again does not fool it. The rows must still be the
    after-image too.
  - **anything else** - a replaced view, a rename - is put back while every name's rows are the after-image.
  - Only the tables the write changed are written; a write that changed nothing is not written again. A store that
    `acl_use_db` switched since is not the one written, and nothing is done there.
- **The undo queue** (`RecordUndo`, a `ClientContextState` that replaces spec 113's `RecordRenameUndo`) holds one step
  per record write of the transaction and the versions they committed. A ROLLBACK replays it newest first. A COMMIT
  clears it, and so does the next transaction's begin (a step never outlives its transaction, whatever else ended it).
  In autocommit nothing is queued: the DDL committed before its record ran.
- **Only a record**: a step is queued only while `RunRecord` runs the record's scalar (the rewriter's `PRAGMA
  acl_…`). An operator's own `ACL ADMIN DROP RELATION` or `acl_*` call is the operator's write. It commits at once,
  whatever the operator's transaction does, as every management write.
- **Conflicts**: every store write moves the version, so two concurrent writes conflict. An undo that conflicts (a
  duckdb conflict, a REPEATABLE READ store's serialization failure, a deadlock) is tried again - five times, 20, 40,
  60 and 80 ms apart, at most 200 ms a step on the client's thread - each time judging afresh.
- **A step not undone** stays as the write left it: a `policy` event `record_not_undone` (allowed, at the `denied`
  level, a fixed sentence - never a value) and the counter `acl.policy.records_not_undone{reason}` - `changed_since`,
  `written_since`, `other_store`, `name_taken` (spec 116: the name came back in another case), `refused` (the store
  refused the write). A created record left so is `acl_check_catalog`'s `source_missing`; a drop that stands is
  named only by the event (its mark stays: a REFRESH would bring the object back without the grants that narrowed
  it).
- A record write that commits and then throws (its lineage note) still queues its step.
- **Lineage** (spec 107): a drop sends its `DATASET` `DROP` and a rename its `DROP` + `CREATE` when written; a register
  sends none. The undo writes send nothing; after the replay each name the transaction touched is told what the
  catalog holds when that differs from what lineage was last told (`NoteDefinitionLineageIfChanged`).

## Enforcement & security

- The rolled-back CREATE no longer leaves a record that would hand a role a table nobody granted it. This is the same
  class of leak as spec 151's `IF NOT EXISTS`. Its undo only removes, so it is applied even over what an operator
  wrote on the phantom meanwhile.
- **An undo never puts back what somebody else took away.** A dropped record's rows come back only into a store no
  other writer touched since the DROP: an operator's `REVOKE CATALOG`, `DROP ROLE` (and a new role of that name), a
  dropped schema or catalog, a reference name reused, a same-named function - each moves the version, and the drop
  then stands (fail closed: the object is invisible until the operator adds it back). A replace or a rename someone
  else touched is skipped. A principal holding a transaction open cannot arm a ROLLBACK (or a disconnect, or a killed
  session) that brings back a grant the operator revoked.
- An undo writes only rows the write's own images read from the store. No principal input reaches it: the names are
  the record's own. Values go back as `Value::ToSQLString` (quotes doubled); the test's column comment holds `'`,
  `--`, `;` and `%s`.
- The policy version moves with each undo (`WriteWithReads`), so the caches drop what the transaction wrote.

## Testing

`test/sql/acl_record_rollback.test`:
- a rolled-back CREATE leaves no record, and a physical table of that name made later is still "no access";
- a rolled-back DROP keeps the record and its column grant. So does a DROP plus a re-CREATE of the same name in one
  transaction;
- a rolled-back DROP brings back the reference naming it with its columns, a virtual column comment and an ENUM
  column's type facts;
- a rolled-back `CREATE OR REPLACE VIEW` keeps the old body, and a new view goes;
- dbt's swap rolled back leaves neither name; the hand-written swap (`DROP target; RENAME staging TO target`) rolled
  back brings both back, the target with its column grant;
- a rolled-back VIRTUAL ONLY register leaves no record, and the name's `schema_dropped` mark is back;
- a name that needs quoting (`vs."a.b"`) goes at ROLLBACK;
- a reference to a table function of the created table's name stays;
- a touched rename left in place is `acl_check_catalog`'s `source_missing`;
- two connections:
  - **an operator's REVOKE** while a view's replace is open stays revoked, and the view stays as the client's write
    made it;
  - **a cascade** - `REVOKE CATALOG`, `DROP ROLE`, a new role of that name with a catalog grant - while a DROP is
    open: the drop stands, no grant comes back, the new role reads nothing;
  - **an operator's COMMENT** on a renamed record: the rename is not moved back;
  - **an operator's GRANT and COMMENT** on a created record: the record goes, the grant with it - and so on a record
    the transaction created and renamed (a touched swap), and when the old name was taken meanwhile by the
    principal's own other session;
  - **an operator's PRIMARY KEY** on a created record: the record and the key go;
  - **a same-named table function dropped meanwhile**: the grant it shared is not put back;
  - **any other write** (a `CREATE ROLE`) while a DROP is open: the drop stands, its mark stays, the event says so;
  - each skip's event and the counter by reason;
- an operator's own `DROP RELATION` and `CREATE VIRTUAL TABLE` inside the operator's transaction stay after its
  ROLLBACK;
- a failed statement aborts the transaction: its COMMIT rolls back, and the record goes;
- a COMMIT keeps what the transaction wrote, and a later ROLLBACK does not replay it;
- lineage (last, `require json`): a view made and dropped in a rolled-back transaction ends `DROP`; a dropped table
  that came back ends `CREATE`.

The first cases failed before this spec: the record of a rolled-back CREATE stayed, and a rolled-back DROP answered
"no access". The REVOKE, cascade, swap, rename and lineage cases failed against this spec's earlier cuts (the rows
restored whole; an undo guarded by the name's own rows only; an unguarded rename; a `CREATE` sent for a view that
never was). `acl_ddl_dbt.test` keeps spec 113's rename rollback.

## Alternatives considered

- **Write the record in the client's transaction** (the store is often an attached database the client could
  write): it would roll back with it. But spec 113 kept the store's writes on its own connection on purpose. Among
  the reasons: the store may live in another engine, other sessions must see a committed policy, and a concurrent
  write conflicts at commit.
- **Defer a DROP's record removal to the COMMIT**: no images needed. But inside the transaction the name still has
  a record, so `DROP TABLE t; CREATE TABLE t` in one transaction would be refused as "already exists".
- **Guard a dropped record's return by the rows it depends on** (the catalog, the schemas on its path, each granted
  role and its catalog grant) instead of the store's version: fewer skips on a busy store, but a list to keep in step
  with every table that gates access, and a role dropped and made again with the same rows passes it.

## Follow-ups

- A record write that fails after its DDL committed (autocommit) still leaves the object without a record.
  `acl_check_catalog` reports it (`expansion_stale`).
- **Nothing is taken back without a ROLLBACK on the node that wrote**: a node that crashes, a process that exits with
  a door's connections open (spec 084), a session moved to another node (spec 135) until its old node ends it. A
  CREATE's record then stays; `acl_check_catalog` reports `source_missing`. A provisional record confirmed at commit
  would close it.
- A home whose DDL is not transactional (MySQL commits DDL implicitly) is undone as if its DDL had rolled back.
- **A rolled-back DROP stands after any other write to the store** (one `CREATE ROLE` is enough; a shared store's
  parallel dbt threads write records all the time). Fail closed, but the drop is named only by the event. Stock dbt
  is not affected: its swap renames inside the transaction and drops the backup after the COMMIT, and renames are
  judged by their rows. The owner's model (a finding and an explicit command) would keep the drop's before-image
  durably, report it in `acl_check_catalog` and restore it on an operator's command - a schema step and a statement,
  proposed, not built. A guard by the rows a restore depends on was rejected: a role dropped and made again with
  the same rows passes it.
- Each record write inside a transaction reads 2 × 12 images (a round trip each on a remote store), and each undo 12
  more; one query per image would cut them.
- A Flight session that ends with a transaction open is destroyed under the door's lock (`DropConn`), so its undo
  writes hold the other calls of the door.
