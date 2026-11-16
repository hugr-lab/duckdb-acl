# Spec 171: an object's list of bare names is writable

- **Status**: implemented
- **Date**: 2026-11-17
- **Author**: duckdb-acl

## Summary

The owner (2026-11-17): a virtual table whose own list only names and renames its source's columns (`COLUMNS (id,
amount AS total)`) is written through, as the docs said. Only a list made only of renames was; a bare name made the
object the read-only subquery form.

## Design

- **The form.** `RenameOnlyColumns` counts a bare name (no expression) as what it is, the source's column of its name:
  a list of bare names and renames is the alias form (writable), one with a computed item stays the subquery form.
  An object stored before keeps its form until it is written again (no backward compatibility before the release).
- **A listless INSERT** writes the columns the object shows, in its order: the alias form now supplies them
  (`write_order`), mapped onto the physical names as a client's own list is (`MapWrittenColumn` - a listless insert
  under a restrictive grant over a renaming list named the virtual names to the physical table before). A column the
  list leaves out is never written, nor read by a write's conditions; it takes its default.
- **The listing** describes every object that declares its columns from its snapshot (`object_columns`, spec 158),
  whatever its form - the source's row only for an object with no list (an alias, an RLS-only relation). A renaming
  list was read from the source's row before: the form now decides only writability. A column the list reads by name
  shows its own comment, else its source's (spec 143's rule: nothing shown is taken away - a bare-name list showed
  none of the source's before).
- **Ingest** (Flight, quack's SEND_DATA) into such an object writes the columns it shows.

## Tests

`test/sql/acl_bare_names_writable.test`; the form, comment and ingest expectations of `acl_introspection`,
`acl_virtual_schemas`, `acl_ddl_syntax`, `acl_column_comments`, `integration/acl_quack_serve` follow.
