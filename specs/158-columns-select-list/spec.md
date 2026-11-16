# Spec 158: columns - the object's shape, the grant's visibility and masks

- **Status**: implemented (stages 1, 2 and 3 built)
- **Date**: 2026-11-16
- **Author**: duckdb-acl
- **Supersedes**: spec 011's column lists at the catalog level, spec 038's catalog-wide list, spec 102's field paths

## Summary

One place says what an object's columns are: the object. A grant says only which of them a role sees and how a
column is masked for it. Every list is read by duckdb's parser, never by a reader of ours.

## Problem

A column was shaped in five places: an object's list, a catalog grant's list, an object grant's list, a view's body,
a function's result. The lists combined:

- by levels (catalog ∩ object);
- by roles (a union, with masks that may conflict);
- by struct fields (spec 102's trees, intersected and united).

The rewriter (C++) and the listings (SQL, `MetadataListingSql`) each implemented that, and kept apart only by parity
tests (specs 144, 145, 147 found the drift). A mask was evaluated over the physical row, a grant could compute a
column, and the listing typed a column by folding every role's list (`acl_listed_type`).

## Design

The owner's decisions (2026-11-13 and 2026-11-16):

- the model below as a whole;
- no column list on a catalog grant, only on an object grant;
- a grant's list has no `AS name` and no masks, but takes `*` and `* EXCLUDE (…)`;
- a mask is a clause of its own, per role, on the object grant, as in Databricks' ABAC policies (`TO … EXCEPT …`);
- the `acl_has_role('r')` marker.

**The object** (a virtual table, a view, a table function) defines its columns.

- A virtual table's `COLUMNS` is a SELECT list over its source: `name`, `<expr> AS name`, `name: <expr>`, and `a.b`, a
  column of its own as in SELECT. No NULL marks: nullability is the source's.
- A view's columns are what its body returns; a table function's are its result.
- Read by duckdb's parser (`ReadSelectList`: `SELECT <list> FROM __acl_list`, refused when the text holds anything
  more, an expression without a name, or a positional reference).
- Stage 2: live stars in the object's list (`*`, `* EXCLUDE`, `* REPLACE`, `* RENAME`, `COLUMNS(…)`).

**An object grant** says what the role sees.

```sql
GRANT TABLE c.people TO ROLE analyst COLUMNS (* EXCLUDE (salary)) MASK (ssn AS '***-**-' || right(ssn, 4));
GRANT TABLE c.people TO ROLE hr COLUMNS (*);
```

- `COLUMNS` is one of three forms: names (`a, b`), every column (`*`, or none), or every column but some
  (`* EXCLUDE (a, b)`). Each form is a test on a column's name, never a list of new columns.
- `MASK (<column> AS <expr>, …)`: what the role reads in place of a column.
  - The expression reads the object's columns, not the physical row. Over an object with its own list it names them
    plainly (no subquery, star or field path - `struct_extract(c, 'f')`), since it is substituted onto the object's
    expressions (review).
  - It names a column the grant shows.
  - It is cast to the column's type where the grant is written, and a mask that does not cast is refused. So a
    column's type never depends on the role.
- A catalog grant takes no `COLUMNS` and no `MASK`.

**The union of roles**, per object (spec 145: the rows that hold the capability exercised):

- a column is visible when some role's test admits it;
- it reads unmasked when some role shows it without a mask;
- otherwise, when every role that shows it masks it the same way, it reads that mask;
- two different masks refuse the read, as before.

**Read.** The rewrite of a read under a grant is:

```sql
SELECT COLUMNS(lambda c: <the roles' tests OR-ed>)
  FROM (SELECT * REPLACE (<mask> AS <column>, …) FROM (<the object's read>))
```

- The object's read is its projection over the source, the casts and the RLS, as before.
- duckdb applies the test where it binds, in the object's column order.
- A column the source gained appears for `*` and `EXCLUDE`. A column it lost disappears (spec 038's rule).
- A mask of a column the object lost refuses at bind.
- Writes: a visible column of the object as it is stays writable; a masked one is assigned its mask (spec 024's
  injection), never the client's value, and is read-only when its mask reads the row.

**`acl_has_role('r')`** is a marker, like `acl_claim`: baked into a constant `true` / `false` from the principal's
roles where the statement is rewritten, never registered as a function, so a missed one fails closed at bind. It may
stand in an object's expression, an RLS or a mask.

**Listings** (information_schema.columns, `duckdb_columns()`, Flight, quack):

- an object's columns come from one snapshot, the object's read probed where it is written or analyzed
  (`object_columns`);
- the listing keeps the rows the roles' tests admit, with the snapshot's types: a mask never changes a type.

**Stored** (schema v25, `min_reader` 25: an older build would not read the masks):

- `role_object_caps.columns` holds the test as duckdb prints it (`a, b`, `*`, `* EXCLUDE (a, b)`);
- `role_object_caps.masks` holds the masks (`ssn AS <expr>, …`);
- a catalog grant's stored `columns` that is not empty refuses every read under that grant, and
  `acl_check_catalog` says so. Nothing is rewritten: there is no backward compatibility before the release
  (the owner, 2026-11-16).

## Enforcement & security

- A list or mask that does not read by duckdb's parser is refused where written, and a stored one refuses the read
  (`acl_check_catalog`: `columns_unreadable`).
- The union is monotone: a role adds what it sees, never takes away. The only refusal is two different masks.
- A mask is a cast-checked expression over the object's columns; it is judged by the author's function gate (spec 117)
  and its tables qualified (spec 160).

## Stage 2: a star in the object's list

An object's list may hold one star item, as SELECT writes it: `*`, `* EXCLUDE (…)`, `* REPLACE (<expr> AS c, …)`,
`* RENAME (a AS b, …)`, `COLUMNS('<regex>')`, `COLUMNS(lambda c: …)` - beside named items, anywhere in the list:

```sql
CREATE VIRTUAL TABLE c.people FROM pg.public.people
  COLUMNS (* EXCLUDE (ssn), '***-**-' || right(ssn, 4) AS ssn_tail);
```

- **One star, unqualified, standing alone.** Refused where written:
  - a second star;
  - `t.*`;
  - a star inside an expression (`upper(COLUMNS(*))`, `*COLUMNS(…)`), or a named star;
  - `* LIKE | GLOB | SIMILAR TO` (write `COLUMNS('<regex>')`);
  - a subquery, a qualified name or a field path inside the star (its `REPLACE` expressions, its `COLUMNS` selector, its
    `EXCLUDE` / `RENAME` names);
  - a marker (`acl_claim`, `acl_has_role`) in the `COLUMNS` selector: the object's columns are the object's, never the
    reader's (a marker in `REPLACE` is fine).
- **The read is live and as written**: `SELECT <list> FROM <source>`, so a column the source gains appears and one it
  loses goes, as for an object with no list.
- **No name twice.** A subquery suffixes a duplicate name (`ssn_1`), while a grant's test and masks name only the first,
  so a duplicate fails closed everywhere (review):
  - where the list or its source is written over a source that binds, the list must bind and read no name twice
    (`DuplicateName`, markers baked as in every probe);
  - every read binds `<the list's read> UNION ALL BY NAME …` alone first, at the version it reads (`DistinctNamesGuard`,
    a spec 157 / 159 guard; duckdb refuses a duplicate there), refused as "reads a column name twice";
  - `acl_check_catalog` says `column_duplicate`.

  So a source that comes to hold a column named like one of the list's makes the object refuse until the list is
  altered (`EXCLUDE` it from the star).
- **The grant** goes over the object's read as over an object with no list (`GrantOver`): duckdb applies the test and
  the masks over the object's columns, and a mask of a column the object lost refuses at bind. A mask is read as the
  type the object exposes its column as (spec 099), found by column: a column the star passes by its name, a RENAME's
  source, a named item by stage 1's rule; a computed one (a REPLACE, a named expression) is cast to nothing.
- **Listings** keep the snapshot every declared list has (`object_columns`, probed at write and at `ANALYZE`; the
  owner, 2026-11-16: renames and complex shapes are a view's job more than a list's, so the gap is small). The read
  follows the source at once, the listing at the next `ANALYZE`, and `acl_check_catalog`'s `schema_stale` says when
  the two part. A star written over a source that does not bind keeps its named items, marked derived so `ANALYZE`
  re-derives them. Expanding the star in the listing's SQL would be a second reader of duckdb's star rules (`REPLACE`,
  `RENAME`, a regex, a lambda): the drift spec 158 removed.
- **Read-only, whatever form is stored.** Which source columns the object writes is known only where duckdb binds it,
  and an INSERT that names no columns matches by position against a width nobody published.
- **Stored** as one `relation_columns` row with no name and the star as duckdb prints it; every reader by name skips
  it.
  - REMAP and `DROP MISSING COLUMNS` leave it as it is (it names no column of its own).
  - A column its REPLACE computes is computed to a key (spec 048) and masking to lineage (spec 129).
  - A column it passes carries its source column's tags (spec 143).
  - Its REPLACE expressions and its selector are a body like a computed column: the author's function gate (spec 117);
    no table to qualify (spec 160) or gate (spec 138).

## Known limits (stage 2)

- `acl_check_catalog`'s `column_duplicate` judges the current version; an older one a grant admits is judged where it
  is read. `ANALYZE` keeps the snapshot of a list every read refuses.
- A star that no longer binds over its source (an `EXCLUDE` of a dropped column) refuses every read and is the check's
  `column_missing`, but the listing's broken-list mark (spec 039) is computed only for named items.
- A `COLUMNS` selector may read the session (`current_setting('TimeZone')`), which a client sets (spec 068): the
  object's columns then differ by session, while the listing shows the snapshot's. The grants' tests still apply to
  what the read returns.
- A column a RENAME names carries the tags of a source column of the new name, if one exists (more tags, never fewer).

## Found by the reviews (stage 2)

- A duplicate name, whether a star's own (`RENAME (name AS ssn)`), a star's against an item, or one the source gained,
  was suffixed (`ssn_1`): the second column read raw past a grant's mask and `EXCLUDE`. It is now refused at write, at
  read and by the check (see "No name twice"). Reading the named items before the star (the first build) only moved
  the suffix onto the next column.
- An AT read (a client's under `VERSIONS ANY`, a grant's pinned one) bound the guard at the current version (re-review):
  it now carries the read's AT.
- A marker in the star made the write's probe fail, which skipped its checks: the probes now bake the markers.
- A mask over a star object was cast by the output name; it is now cast by the column it reads.
- The role-union audit (spec 146), lineage's per-role tags (spec 107), the key check (spec 048), the check under the
  exposed types (spec 099) and `enum_domain_exposed` now see the star's columns.

## Known limits (stage 1)

- A mask is cast to its column's type where the grant is written, and that the cast holds is judged where duckdb binds
  it: a mask duckdb binds but cannot cast at run time (`[1, 2]` to an INTEGER) refuses the read, not the write.
- A mask written while its object cannot be judged (a source not attached yet) is kept as written and cast when the
  object is analyzed (`ANALYZE VIRTUAL …`).
- A comment in any column list or mask is refused, written or stored (spec 148: a stored `a--b, c` read `a`).

## Stages

1. The grant model: COLUMNS forms, MASK, the union, `acl_has_role`, the listing's filter, schema v25; the object's
   list as a SELECT list without stars.
2. Live stars in the object's list - see the section above.
3. Spec 102's machinery removed (field trees, field writes, `acl_listed_type`, `grant_columns`) - built: none of it
   was reached since stage 1 (nothing filled `field_writes` / `narrowed_reads`, nothing wrote `grant_columns`). Schema
   v27, `min_reader` 27 (`grant_columns` dropped - a v26 build's listings still read it); `platform.grant_columns` and
   `acl_grant_columns()` go with it; `acl_field_paths.hpp` keeps only the reading of a stored list's names
   (`ParseFieldPath`, `ItemHead`, `ItemsCsv`, `QuotedName`). Two effects a client can see (review): a catalog migrated
   from v24 or older kept spec 026's projection rows, which the listings still read - a column the read no longer
   returns - and now no longer list; a principal's `information_schema.columns.ordinal_position` is INTEGER, as
   duckdb's own (the removed projection branch widened it to BIGINT; Flight's Arrow type int64 -> int32).

## Testing

`test/sql/acl_object_list_star.test`, `acl_object_list_star_versions.test` (stage 2): each star form, a grant over a star list, the source gaining and losing
columns (the read at once, the listing at ANALYZE, `schema_stale` between), a source column named like an item, the
forms refused where written, read-only, REPAIR keeping the star.

`test/sql/acl_grant_columns.test` (stage 1): every form and its union, masks and their union, a mask's cast, writes,
the listing's rows against the read's, `acl_has_role`, the catalog grant's refusal. The existing tests move to the new
forms.

## Alternatives considered

- **MASK on the object, UNMASK in the grant.** One mask per column and a monotone union, but the owner found it less
  obvious than a mask for a role.
- **A mask expression on the object with `acl_has_role` inside** (Snowflake, Dremio, Databricks' column masks). It
  stays possible with the marker, but it is not the grant's form.
- **Star expansion at read by the snapshot.** A union of names in C++, but a column the source gained waits for
  ANALYZE. The test on names gives duckdb the star itself.
