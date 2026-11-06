# Spec 155: a principal's error suggests nothing it was not shown

- **Status**: implemented
- **Date**: 2026-11-06
- **Author**: hugr lab (found by spec 151's reviews; the owner's order: after spec 154)

## Summary

duckdb's errors name what it found and what it looked for:
- a catalog miss names the closest entries in the lookup's schemas and in every attached database, the policy store's
  own tables among them;
- a binding's candidates are, inside a rewritten read, the source's physical columns;
- a write's errors name the physical table it wrote, and a constraint's columns and expression;
- a star that expanded to nothing prints the list it expanded (the source's every column).

Under a principal those are names the role was never shown. Spec 057's rule is that a refusal never carries a
physical name the role cannot see. A principal's error is now rewritten where the client reads it:
- suggestions and candidates go;
- a substituted physical name reads as the virtual one;
- a constraint error says its kind;
- a catalog error or a missing column keeps its sentence only when the client wrote the names it carries.

## Problem

Probed on the build of 2026-11-05 (the principal `wide` holds `select, create, drop` on the expansion `vs`), and by
this spec's reviews:

- `DROP TABLE vs.hidden_thin` answered `Did you mean "hidden_thing"?`. That table was dropped from the expansion, so
  the role cannot see it.
- `DROP TABLE vs.relation` answered `Did you mean "aclcat.acl.relations"?`, the policy store's table.
- A record over `phys.lake.salaries_2024` answered `Table with name salaries_2024 does not exist!` once its table was
  gone. Over a DETACHed database it answered the full physical path.
- A declared column whose source column was dropped answered `Referenced column "ssn_raw" not found … Candidate
  bindings: "internal_note"`. Spec 065's probe A had accepted this as a name leak.
- A grant whose column list meets nothing answered `Star expression "COLUMNS(list_filter(['id', 'tenant', 'amount'],
  …` with every physical column and the rewriter's lambda (spec 065's probe B).
- Writes to a writable object over a source named otherwise answered:
  - `Table "wpay" does not have a column with name "nope"`;
  - `table "wpay" has 3 columns but 4 values were supplied`;
  - `NOT NULL constraint failed: wpay.who`;
  - `CHECK constraint failed on table "wpay" with expression CHECK((amount > 0))`.

These were already refused by the rewriter in its own words, and stay so:
- an unknown virtual name (`no access to object`);
- a column the role may not write;
- a type (spec 099);
- a function (spec 072).

`CREATE TABLE vs.hidden_thing` still answers `already exists`. The role shares the physical namespace of its create
home (spec 151), so this is not a name the role was denied.

## Design

- **One seam: the result's own error, at `QueryEnd`.** `ClientContext::EndQueryInternal` hands every registered state
  the error of the result the client will read: `QueryEnd(context, previous_error)`, where `previous_error` is
  `result->GetErrorObject()`.
  - A `Prepare` runs as a `PREPARE` statement and throws its result's error (`PrepareInternal` →
    `RunStatementInternal` → `ThrowIfError`).
  - So the seam covers the gateway's queries and prepared statements, quack's statements, the Flight door's Prepare
    and its DDL as text (spec 153), every execution and a stream's failure.
- **Whose statement** (`AclProfileState`): the decided statement's note (spec 074) is matched by its text's hash and
  is lost easily. The next parse drops it, and a refused batch leaves stale notes on the thread. So the connection
  remembers the hashes of the texts it ran for a principal (`principal_texts`, at most 4096, the oldest forgotten
  first), together with the physical names each text's rewrite substituted.
  - A principal is anything but `native` and the anonymous operator.
  - An execution of such a text is a principal's statement whether or not its note is still there: a gateway's
    prepared statement executed after other work.
  - An implicit PIVOT's parts carry the statement's own text (`RewriteMultiStatement`), because duckdb runs them as
    one query under the first part's text.
  - An operator's statement of an identical text is treated the same way. That only removes text from its error.
- **The rewrite** (`ScrubPrincipalError`):
  - every `Did you mean`, `Candidate bindings` and `Candidate tables` line is cut;
  - each physical leaf the rewrite substituted for a virtual name of another spelling (`renamed`, noted by
    `NotePhysical`) reads as that virtual name, in the text and in the error's `name`;
  - a `CONSTRAINT` error becomes `acl: the write breaks a <NOT NULL | CHECK | PRIMARY KEY | UNIQUE | FOREIGN KEY>
    constraint of the table it writes`;
  - a `BINDER` star error (`Star expression "…"`) becomes `acl: a star in this statement selects no column it may
    read`;
  - a `CATALOG` error keeps its sentence only when the client wrote the names it carries. For `MISSING_ENTRY` /
    `ENTRY_ALREADY_EXISTS` that is the entry's name; for any other catalog error, every name it writes in double
    quotes, part by part. Otherwise it becomes `acl: the <type> this statement names does not exist`, `acl: an object
    this statement names does not exist`, or `acl: the catalog refused this statement`;
  - a `BINDER` `COLUMN_NOT_FOUND` whose name the client did not write becomes `acl: a column this statement reads does
    not exist in its source`;
  - "The client wrote it" means an identifier or keyword token of the client's text (duckdb's tokenizer), never a
    string constant or a comment, compared in the ASCII fold;
  - the location duckdb appended (`LINE 1: …`) is the client's own text and stays. Under `errors_as_json` the JSON is
    read, rewritten and written again;
  - a rewrite that throws fails closed: `acl: the statement failed`, of the error's type.
- **The text**: `QueryEnd` may run when duckdb holds no active query (`GetCurrentQuery` dereferences a null), so the
  state copies a principal statement's text at `QueryBegin` and drops the copy at `QueryEnd`.

## Enforcement & security

- No name the principal was not shown reaches it through a catalog miss, a binding's candidates, a write's table name
  or a constraint. This holds whatever `catalog_error_max_schemas` says and on every door.
- A guess cannot be confirmed. A physical name the rewrite substituted always reads as the virtual one, whatever the
  client wrote. A name in a string or a comment does not count as written.
- **Residual**: the "client wrote it" test for a missing column is a token test. An alias written as the guess
  (`SELECT 1 AS ssn_raw …`) keeps a drifted source column's name, so a principal can confirm a guessed name of a
  column that no longer exists. A constraint is still an oracle: whether a write breaks a CHECK over a hidden column,
  or a key the RLS hides, says something about rows the role cannot read. That is the operator's to weigh when
  granting writes (security.md).
- The rewrite only removes text or replaces it with a fixed sentence, and fails closed.

## Testing

- `test/sql/acl_principal_errors.test`:
  - `DROP` near a hidden table, and near the store's table, says the client's name with no suggestion;
  - `IF EXISTS` stays a no-op;
  - a record of nothing;
  - a record whose source is named otherwise reads as itself, even with the guess written as a string or an alias;
  - JSON errors;
  - a record over a DETACHed database;
  - a declared column whose source column is gone;
  - a missing column the client wrote, without candidates;
  - an implicit PIVOT;
  - write errors to a renamed writable object: an unknown column, a value count, NOT NULL, CHECK;
  - an empty star;
  - the operator's SQL and `ACL NATIVE` keep duckdb's text.
- `test/cpp/test_acl_principal_errors.cpp`:
  - the `Prepare` path;
  - a gateway's prepared statement executed after an interleaved statement, and after a refused batch;
  - JSON errors;
  - the absence of every suggestion and candidate line.
- `acl_catalog_maintenance.test` (spec 039 / 065 probe A): the drifted declared column now reads the sentence.
- `test_acl_session_use.cpp` (spec 114): its "does not exist" refusals still carry the client's name.

## Alternatives considered

- **`catalog_error_max_schemas = 0` for a principal's statements**: a GLOBAL setting, which a gateway's shared
  connection cannot change per statement. It also bounds only the other databases.
- **Attach the policy store's database HIDDEN**: visibility is set at ATTACH, and the operator would lose it from
  `duckdb_databases()`.
- **The rewriter checks a DDL target before bind**: it runs where the client's own transaction cannot be seen, and it
  cannot cover reads (spec 065: nothing on the query path looks at the source).
- **`ClientContextState::OnPlanningError`**: it sees the error but rethrows the original exception.
- **Judge "the client wrote it" by substring**: a comment, a string or a longer name holding the guess confirms it.

## Follow-ups

- Errors raised before duckdb begins the query (preprocessing, the parser override's own messages that wrap a
  probe's text) do not pass through `QueryEnd`. None was principal-reachable in the reviews' probes; the source gate
  refuses first.
