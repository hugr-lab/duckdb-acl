# Spec 160: a policy's tables are written whole

- **Status**: implemented
- **Date**: 2026-11-13
- **Author**: hugr lab (found by spec 159's review; the owner's decision 2026-11-13)

## Summary

A table that a policy text names is now stored as `<db>.<schema>.<table>`: the entry duckdb's binder resolves the name
to on a fresh connection of the writing node (its default database and search path, not the author's `USE`). That
covers an RLS, a mask, a computed column, a view's SQL and a function's template. The rest of the text is stored as
written. `acl_check_catalog` names a stored body that still names a table without its database.

## Problem

A policy text could name a table without its database: `RLS (id IN (SELECT k FROM tenants))`. Inside a principal's
statement that name resolves at bind, by duckdb's rules for the statement it sits in. A CTE of the principal's of that
name, or a temp table, takes precedence over the catalog's table. The policy then read the principal's rows instead of
its own. Two-part names that start with a schema (`main.tenants`) have the same problem: the temp catalog has a `main`
schema too.

## Design

`QualifyBodies` (acl_platform.cpp) runs on every compiled management call before the authorizers. It goes over the
bodies the call stores, as listed by `BodiesOf`: a SELECT, an expression, a grant's column list, an object's own list.
`QualifiedBodyTables` (acl_platform_rights.cpp) then works on each body:

- It parses the body (an expression or a list as a select list) and walks its table references CTE-scoped
  (spec 138's `ScopedReferences`, now with each name's location).
- It resolves each name to its entry with `ResolvedReference` (the binder's own reading, on one fresh connection of
  the store's database for the whole call).
- A name written with fewer parts than its entry has is replaced by the entry's parts, each quoted when it must be.
  Only the name's own tokens are replaced (`WrittenNameEnd`): a table reference's span also covers its alias, column
  aliases, sample and `AT`, which stay as written.
- A list that is no select list as a whole (a path `items[].price`, a NULL mark) has each item's expression qualified
  where it is written.

A name of the body's own CTE, a name written whole, a name of no object (a file) and a name that reads two ways are
left as written. The other checks judge them: a body that does not bind, spec 138's source gate. A table named in a
form not rewritten in place is refused where written ("write it as <db>.<schema>.<table>"): a string (`FROM 't'`),
backticks, a comment between the name's parts, the table of a `SUMMARIZE` / `DESCRIBE` / `SHOW`.

Stored rows are not rewritten. `acl_check_catalog`'s `body_table_unqualified` names each one: an RLS, a view, a
template, a declared column, a grant's RLS or list. The finding shows the body written whole and says to redefine it.
A body stored by the operator's own `acl_*` call, past the grammar, is kept as written and found the same way.

`platform.check_grant` (spec 122) answers the stored form the write would store.

The default database's name goes into the stored text (`memory.main.t`): every node of a deployment has the same
database names (the owner, 2026-11-13). Spec 137 kept a two-part default-database name as written for the opposite
assumption, for a relation's own physical name; a body's names are now whole.

Not covered: the memory store (no catalog, names kept as written), and a body written by the operator's own `acl_*`
call past the grammar. The check names the second.

Temp tables under a gateway's prefix stay as they are (the owner, 2026-11-13). Written whole, a policy's table is
never a temp table's or a CTE's.

## Enforcement & security

A table a policy names is bound by its whole name, so neither a principal's CTE (a one-part name) nor its temp table
(the `temp` catalog) can stand in for it. Error messages of the source gate (spec 138) name the table whole.

## Testing

`test/sql/acl_policy_tables_qualified.test`:

- **Stored whole.** A grant's RLS, a grant's mask, a view's SQL, a catalog grant's `ALTER … SET RLS` and a list with a
  path are stored with the table written whole. A name already written whole stays as written, and so do an alias, a
  column alias and a sample beside it. A name of the body's own CTE stays bare; a `SHOW` before another table keeps
  each name in its place.
- **Reads.** A principal's CTE named like the table, and its temp table, leave the RLS, the view and the mask reading
  the catalog's table.
- **Refused forms.** A string, backticks, a comment between the parts and a `SUMMARIZE` table are refused with the
  whole name to write; the same `SUMMARIZE` written whole is stored.
- **The check.** It names a body the operator's own call stored unqualified, with the whole form, and a principal's
  CTE does stand in for that body (the negative control).

`acl_source_gate_bodies.test`: the source gate's refusals now name the table whole.

## Alternatives considered

- **Refusing an unqualified table at write.** Explicit, but every admin and the DBeaver plugin would have to write
  `memory.main.t` by hand; the owner chose qualifying.
- **Hoisting the reads into root CTEs (spec 159).** It closes the CTE form only, and costs plans on remote sources.

## Follow-ups

- A principal's own view (spec 113), and `acl_arg`'s scope: BACKLOG.
