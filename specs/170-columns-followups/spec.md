# Spec 170: columns after spec 158 - the follow-ups

- **Status**: implemented
- **Date**: 2026-11-16
- **Author**: duckdb-acl

## Summary

Four follow-ups spec 158's stage 1 left in the BACKLOG, each small.

## Design

- **DROP RELATION of a name a live alias shares.** A grant row is keyed by name. A relation of the same name as an
  object of a live schema alias (`c.raw.t` under `CREATE VIRTUAL SCHEMA c.raw AS phys.main`) shadows that object while
  it exists. Dropping the relation deleted the rows, so the alias's object lost its `COLUMNS` and `MASK` and the role
  read it whole. Keeping them instead (the first build) hands a grant written for the relation (its caps, `VERSIONS`,
  RLS) to the alias's object: a role with no access read it, a write right or every version came with it (review).
  The row cannot say which of the two it was written for, so neither is for a drop to decide:
  - the operator's drop is refused while object grants are on the name and a live alias reaches it, naming the roles
    (`GrantsAnAliasTakesOver`): revoke, drop, then grant the alias's object;
  - a principal's own record (`DROP TABLE | VIEW`, spec 151) and its undo (spec 154) take the grants with them, as
    before - the reader's grant on a principal's view never lands on what its author makes next under the name;
  - a function of the same name keeps the rows, as before (`SameNamedFunction`).
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

- The usage of a refused GRANT form names `MASK` for an object grant and no `COLUMNS` for a catalog grant.

## Tests

`test/sql/acl_columns_followups.test`; `platform_effective_rights.test` and `acl_empty_grant_projection.test` read the
new message; `acl_listing_read_parity.test` revokes before its drop.
