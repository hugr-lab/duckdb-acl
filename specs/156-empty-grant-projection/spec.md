# Spec 156: a grant that leaves no column reads no column

- **Status**: implemented
- **Date**: 2026-11-12
- **Author**: hugr lab (found by spec 150 4f's re-review)

## Summary

A role whose grants narrow an object's declared columns to none read every physical column of the object's source
whenever a row filter applied, and - on a writable object - wrote, filtered on and returned every physical column
whatever filter applied. The read now refuses, as it already did without a row filter, and so does every write.

## Problem

`ApplyGrantPolicy` folds a grant's column list into the object's declared list (spec 038). When nothing the grants
list is a column of the object, the projection it builds is empty. `BuildTableSubquery` read an empty projection as
"the grant narrowed only the rows" (spec 011): with no RLS it refused (`exposes no readable columns`), but with an RLS
- the object's own, the catalog grant's or the object grant's - it emitted `SELECT * FROM <phys> WHERE <rls>` (or
`SELECT * RENAME (…)` for a rename-only object). The role then read columns neither the object nor its grant ever
exposed (`ssn` beside a declared `k = id, b`), while the listings showed none. Reachable by an admin's ordinary
writes: `ValidateGrantColumns` refuses only a list matching nothing anywhere in the catalog, so a catalog grant
`COLUMNS (id)` over objects of which only some declare `id`; an object grant written over a list it matched, then the
object's list changed by `SET COLUMNS` (nothing re-judges the grant).

Writes (found by this spec's review): on a writable object (a rename-only list, no RLS) every column set a write is
judged by - `visible_columns`, `write_columns` - was empty, and every DML site reads an empty set as "no column
policy" (`MapReadable`, `RequireWritableColumn`, `RequireReadableReturning`, `ApplyInsertPolicy`,
`ApplyMergeInsertPolicy`, `ConflictUpdatePolicy`): `UPDATE w SET ssn = … RETURNING *` wrote and returned the whole
physical row, `DELETE … WHERE ssn = …` read a hidden column. `VerbReadScope` (spec 145) skipped such a role as reading
"every column as stored".

From the review too: an object without a declared list whose catalog grant's and object grant's lists intersect to
nothing (the read failed on duckdb's empty `COLUMNS(...)`, a write again saw no column policy); `acl_check_catalog`'s
repair of a grant's last broken item was the list without it - an empty list, which is a row-only grant and reads
every column (`SELECT acl_grant_object(…, '')` after `DROP MISSING COLUMNS` took the only listed column); the lineage
tags (`RoleTags`) tagged every field `visible` for such a role.

## Design

`TablePolicy::exposes_nothing` (acl_policy.hpp): set by `ApplyGrantPolicy` when the narrowed projection over a declared
list is empty. `BuildTableSubquery` refuses on it, as on an empty projection without RLS; `ResolveDmlTarget` refuses
every verb on it (`<verb> on "w" is not allowed: it exposes no column`) - a plain `DELETE` too: an object of which the
principal's united grants read no column is not one it changes - and so does `ConflictUpdatePolicy` (`INSERT OR
REPLACE` / `ON CONFLICT DO UPDATE` update the row already there: the update's union read as "no column policy" and
overwrote it). `VerbReadScope` takes a role whose own grants leave no column as reading no column (spec 145's
intersection: it was skipped as "every column as stored"). The no-declared-list branch sets the flag when the lists
intersect to nothing (and the read refuses on it before a view's or the branch's query is used). The check's repair of
a grant's last item revokes the grant (`acl_revoke_object` / `REVOKE CATALOG`), never an empty list; `RoleTags`
gives such a role no field tag. An empty
projection beside an RLS keeps meaning a row-only grant (every column) - only where no grant narrows the columns.

## Enforcement & security

Fails closed: the read refuses with the existing `exposes no readable columns`, every write before anything is written.
The listings were right already (they never showed such columns); `effective_rights` says `writable = false`.

Visible changes beside the leak (the owner's to keep or reopen): a plain `DELETE` with no column refuses; a principal
whose verb role alone leaves no column has that role's `VerbReadScope` contribute nothing, so `UPDATE … WHERE k = …`
by a principal reading `k` through another role refuses (spec 145's rule, which the skip had let through); an ingest
role whose list names physical names (`COLUMNS (id, b)`) no longer inserts into an object renaming them (it wrote
every column unchecked). Unchanged (spec 146): a role whose own grants leave no column still contributes its ROWS to
a verb's union with other roles - BACKLOG. A grant written over a list it matched and left
narrowing to none by a later `SET COLUMNS` refuses the same way; `acl_check_catalog` does not name it yet.

## Tests

`test/sql/acl_empty_grant_projection.test`: the object's RLS, the catalog grant's RLS, a rename-only object, an object
grant left behind by `SET COLUMNS`, every verb on a writable object (UPDATE / DELETE / INSERT / INSERT OR REPLACE /
MERGE, with RETURNING), two lists intersecting to nothing over an object without a list, the check's revoke after
`DROP MISSING COLUMNS`; a row-only grant still reads every declared column, a list naming the object's column still
writes. Fails without the fix (the first read returns `id, ssn, b`).
