# Spec 155: a principal's error suggests nothing it was not shown

- **Status**: implemented
- **Date**: 2026-11-06
- **Author**: hugr lab (found by spec 151's reviews; the owner's order: after spec 154)

## Summary

duckdb answers a missing catalog entry with the closest names it can find. It looks in the lookup's own schemas and
in up to `catalog_error_max_schemas` schemas of every attached database, and names the physical object it looked
for. Under a principal those names belong to objects the role was never shown, the policy store's own tables among
them. A principal's error now loses every "Did you mean" line. A missing entry keeps its name only when the client
wrote that name; otherwise it becomes a sentence that names nothing.

## Problem

Probed on the build of 2026-11-05. The principal `wide` holds `select, create, drop` on the expansion `vs` and
`COLUMNS (who)` on `vs.payroll`:

- `DROP TABLE vs.hidden_thin` answered `Table with name hidden_thin does not exist! Did you mean "hidden_thing"?`.
  `hidden_thing` is a table the operator dropped from the expansion, so the role cannot see it.
- `DROP TABLE vs.relation` answered `Did you mean "aclcat.acl.relations"?`. That is the policy store's table.
- A record whose source is named differently from the record (`sales.pay AS phys.lake.salaries_2024`) answered with
  the physical name `salaries_2024` once its table was gone. Spec 057's rule is that a refusal never carries a
  physical name the role cannot see.

These answers were already refused by the rewriter, in its own words, and stay as they were:
- an unknown virtual name (`no access to object`);
- a column the role may not write;
- a type (spec 099);
- a function (spec 072).

Two answers are left as they are on purpose:
- a column of the role's own read keeps its candidates (`Candidate bindings: "who"`), which list only what the read
  exposes;
- `CREATE TABLE vs.hidden_thing` still answers `already exists`. That reveals a hidden table in the role's create
  home, but the role shares the physical namespace there; spec 151 decided this.

## Design

- **One place: the result's own error, at `QueryEnd`.** `ClientContext::EndQueryInternal` hands every registered
  state the error of the result the client will read: `QueryEnd(context, previous_error)`, where `previous_error`
  is `result->GetErrorObject()`, a mutable pointer.
  - A `Prepare` runs as a `PREPARE` statement and throws its result's error (`PrepareInternal` →
    `RunStatementInternal` → `ThrowIfError`), so that error passes through the same place.
  - So the one seam covers the gateway's queries, quack's statements, the Flight door's Prepare and its DDL as text
    (spec 153), and every execution.
- **Whose statement**: spec 074's `AclProfileState` holds the decided statement's note. The error is rewritten only
  when a note exists, the statement is not `native` and the principal is not the anonymous operator. NATIVE is
  break-glass and keeps duckdb's text, and so does the operator's own SQL.
- **The rewrite** (`ScrubPrincipalError`):
  - every `\nDid you mean …` line is cut;
  - a `CATALOG` error of subtype `MISSING_ENTRY` keeps duckdb's sentence when the entry's name occurs in the
    client's text (the client's own word, e.g. `DROP TABLE vs.relation` → `Table with name relation does not
    exist!`), and otherwise becomes `acl: the <type> this statement names does not exist`;
  - the extra info loses `candidates`, and `name` when the name was not the client's;
  - the error is rebuilt the way `ProcessError` built it (`FinalizeError`, then the location in the client's text,
    or JSON under `errors_as_json`).
- **The text**: `QueryEnd` may run when duckdb holds no active query (`GetCurrentQuery` would throw), so the state
  copies the decided statement's text at `QueryBegin`.

## Enforcement & security

- No name the principal was not shown reaches it through a catalog miss: neither a near name in another database
  (the policy store included, whatever `catalog_error_max_schemas` says), nor one in the same physical schema, nor
  the physical name of a record's source.
- The rewrite only removes text or replaces it with a fixed sentence, so it can hide nothing that matters. A
  failure inside it leaves duckdb's error as it was.
- The "client wrote it" test is a substring of the client's own text, case-insensitive. A physical name that happens
  to occur there is a name the client already wrote.

## Testing

- `test/sql/acl_principal_errors.test`:
  - `DROP` of a name near a hidden table, and near the store's table: duckdb's sentence with the client's name, no
    suggestion;
  - `IF EXISTS` stays a no-op;
  - a record of nothing: its name is said, without a suggestion;
  - a record whose source is named otherwise: the sentence that names nothing;
  - the role's own read keeps its candidate column;
  - the operator's SQL and `ACL NATIVE` keep duckdb's suggestion.
- `test/cpp/test_acl_principal_errors.cpp` covers the `Prepare` path, which sqllogictest cannot take, and the same
  query cases.
- `test_acl_session_use.cpp` (spec 114): its "does not exist" refusals still carry the client's name.

## Alternatives considered

- **`catalog_error_max_schemas = 0` for a principal's statements**: a GLOBAL setting, which a gateway's shared
  connection cannot change per statement. It also bounds only the other databases, and the near names in the
  lookup's own schema stay.
- **Attach the policy store's database HIDDEN**: visibility is set at ATTACH, and the operator would lose it from
  `duckdb_databases()`. It covers neither other catalogs nor a hidden table of an expansion.
- **The rewriter checks a DDL target's physical object before bind**: it runs where the client's own transaction
  cannot be seen (an in-transaction `CREATE` then `DROP` would be refused), and it cannot cover reads (spec 065:
  nothing on the query path looks at the source).
- **`ClientContextState::OnPlanningError`**: it sees the error but rethrows the original exception.

## Follow-ups

- An error other than a catalog miss that names a physical object (a constraint, a conversion) is left to duckdb;
  none was found carrying a name the role was not shown.
