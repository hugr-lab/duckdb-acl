# Spec 170: columns after spec 158 - the follow-ups

- **Status**: implemented
- **Date**: 2026-11-16
- **Author**: duckdb-acl

## Summary

Four follow-ups spec 158's stage 1 left in the BACKLOG, each small.

## Design

- **DROP RELATION keeps a live alias's grants.** A grant row is keyed by name. A relation of the same name as an
  object of a live schema alias (`c.raw.t` under `CREATE VIRTUAL SCHEMA c.raw AS phys.main`) shadows that object
  while it exists. Dropping the relation deleted the rows, so the alias's object was read by its catalog grant alone:
  its `COLUMNS` and `MASK` were gone and the role read it whole. The rows now stay, as they already did for a function
  of the same name (`GrantsSharedByName`; the drop and its undo, spec 154, share it).
- **`acl_object_grants()` shows `masks` and `versions`** (specs 158 / 167 store them); `acl_grants()` shows `versions`.
- **`platform.check_grant` with no caps** (`''`, as the platform form passes an omitted one) answers no `caps` row; it
  answered `caps ok NULL`.
- **A `COLUMNS` that leaves no column** (`* EXCLUDE (<every column>)`) is refused in the grant's words: "the grant's
  COLUMNS leaves no column of …". It used to be duckdb's message about the generated `COLUMNS(lambda …)` selector.

## Not done here

An object's list of bare names (`COLUMNS (id, x)`) is stored in the read-only subquery form. The docs say a list of
bare names and renames keeps the writable alias form, and the code gives it only to a list made only of renames. Making
it alias touches the listings' alias branch (it joins the list on its expressions) and makes such objects writable: a
decision, left in the BACKLOG.

## Tests

`test/sql/acl_columns_followups.test`; `platform_effective_rights.test` and `acl_empty_grant_projection.test` read the
new message.
