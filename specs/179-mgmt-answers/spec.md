# Spec 179: what a management statement answers

- **Status**: implemented
- **Date**: 2026-11-20
- **Author**: Claude, from the owner's decision on hugr-node spec 035 (2026-11-20)

## Summary

A management statement answered whatever its `acl_*` call returned, under the call's name: mostly `true`, a count for
`DRAIN NODE` / `REPAIR` / `REFRESH`, a text for `MIGRATE`, a STRUCT for the platform part's `CLUSTER` forms. A client
had to know each form's answer, and a write had no place to say something beside it - hugr-node spec 035's hint that
a resource group's source set leaves out a source the granted role now reads. The owner: every management statement
answers two fields, `ok` and `message`.

## Design

- **The answer**: one row, `ok BOOLEAN` and `message VARCHAR`, for every compiled management statement (the grammar,
  under any prefix) and every top-level `platform.<op>(…)` call. Read from the call's value by `ManagementAnswer`
  (acl_mgmt_answer.cpp, pure):
  - a BOOLEAN is `ok`; a false says what did not happen (`RESUME NODE`: `the node was not draining`, `KILL SESSION`:
    `no session has that id`, else `nothing changed`);
  - a count is `ok` with its words (`DRAIN NODE`: `<n> sessions still open`, `REPAIR`: `<n> entries changed`,
    `REFRESH`: `<n> objects refreshed` / `<n> records added or removed`);
  - a text is the message (`MIGRATE`);
  - a STRUCT keeps its own fields after the pair, its `ok` / `message` fields read into them (the platform part's
    CLUSTER answer renames its `note` to `message` when it re-pins);
  - NULL is `ok = false`, `the call answered nothing`.
  A refusal stays an error.
- **The wrap**: `AnswerManagement`, in the override after every authorizer (`AuthorizeMgmt` … `AuthorizeSources`), so
  each of them still reads the compiled `SELECT acl_<fn>(…)`. The call becomes
  `SELECT __acl_answer.* FROM (SELECT acl_answer('<fn>', acl_<fn>(<args>), <args>…) AS __acl_answer)`: the struct's
  star reads the column once. `unnest(acl_answer(…))` was tried first and runs the call once per field (one
  `struct_extract` each) - a CREATE ROLE refused as its own duplicate; the test pins it. The statement keeps its text
  (the profile note's match, spec 074), location and parameters (a prepared call binds its `?` into both copies of
  the argument; both are the same parameter).
- **`acl_answer(function, value, args…)`**: an `acl_*` scalar (volatile, fallible, in the never set by its prefix),
  its return type bound from the value's (`AnswerBind`), NULL-tolerant.
- **The platform part's note**: `NodeTraits::management_note(context, function, args)` - called by acl_answer only
  after a call that succeeded, with the call's evaluated arguments; a non-empty note is added to the message (after
  the call's own, `; `). acl sets none. hugr-node's grant hint (its spec 035) is the first.
- **Unchanged**: a form that answers rows (`CHECK VIRTUAL CATALOG`, a platform read function in FROM), a direct
  `acl_*` call in the native context (the operator's scripts and tests), the secrets service's calls (tresor's
  answers). A column alias written on a `platform.<op>` call names nothing now.

- **Found by its review, fixed**: acl_answer runs after the write has committed on the store's own connection, so
  nothing in it may throw - a note that throws is dropped (the answer stays `ok`), a STRUCT's `ok` that is NULL or no
  BOOLEAN reads as not ok (`Truth`, a try-cast), a count past BIGINT is its text. The note's contract says it reads
  through the store's own connection, never the statement's `context` (a query on it deadlocks), and writes nothing.
  Only a constant or a parameter is copied for the note (all a form writes today); anything else reaches it as NULL,
  never evaluated twice.

## Enforcement & security

Nothing is admitted or refused differently: the wrap is applied to statements every authorizer has already judged,
and changes only their answer. `acl_answer` is never callable under a principal (`acl_`). The note is the platform
part's code; it reads what it likes on the context it is given and must not write.

## Tests

- `test/cpp/test_acl_mgmt_answer.cpp`: the grammar answers `(ok, message)` and runs the call once (fails with the
  `unnest` form); a false, a count; a direct call and CHECK answer as before; the note after a success with the
  call's arguments, none after a false, an empty note adds nothing; a prepared platform call answers the pair at each
  execution and writes once (the policy version moves by one); named arguments reach the note in the function's
  order; a throwing note leaves the grant standing and the answer ok; through SQL, a STRUCT's NULL or non-BOOLEAN `ok`
  is not ok and a count past BIGINT is its text; a STRUCT answer keeps its fields, NULL is not ok, a text is the
  message. Each of the review's cases fails on the code before its fix.
- `test/cpp/test_acl_params_passthrough.cpp`: a call and the grammar answer the same two columns.
- The suite's management answers (`acl_mgmt_grammar`, `platform_calls`, `node_operate`, `acl_profile`,
  `acl_catalog_maintenance`, `acl_empty_grant_projection`) and the Flight e2e (`admin.sh`, `drain.sh`) read the pair.

## Follow-ups

- hugr-node: re-pin; its CLUSTER answer's `note` becomes `message`; the grant's group-source hint through the trait.
- The clients: acl-clients editors, the DBeaver plugin, hugr-platform's console read `(ok, message)` and show the
  message.

## Alternatives

- A thread-local note the writers fill and acl_answer reads: a non-trivial `thread_local` breaks MinGW (spec 088), and
  the note would be a second channel beside the value the call already returns.
- Changing every `acl_*` function's return type: the operator's scripts and about 35 tests read the direct calls; the
  pair is the answer of the statements, not of the functions.
