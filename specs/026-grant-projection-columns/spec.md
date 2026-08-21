# Spec 026: a grant's projection is probed where it is written

- **Status**: implemented
- **Date**: 2026-08-21
- **Author**: hugr-lab

## Summary

An object's columns are probed when the object is defined (spec 010). A **grant** may project
differently — mask a column into another type, or compute one the object never had — and none of that
reached the metadata. The grant's projection is now probed when the grant is written, so
`information_schema.columns` describes what the role reads.

## Problem

Two surfaces answered "what columns does this role see", and they disagreed. For a grant
`COLUMNS (id, ssn = NULL, label = coalesce(tenant, 'none'))`:

| | id | ssn | label |
| --- | --- | --- | --- |
| what `SELECT *` returns | INTEGER | NULL | 'acme' |
| `DESCRIBE` (binds the rewritten relation) | INTEGER | `"NULL"` | VARCHAR |
| `information_schema.columns` (before) | INTEGER | **VARCHAR** | **absent** |

The listing built its rows from the object's probe and then narrowed them by the grant's column list
(spec 022). Narrowing can only remove: a column the *grant* introduces has no row to keep, and a
column the grant masks keeps the physical type it no longer has.

Spec 021 recorded this as a follow-up; spec 025 made it visible from two sides at once, because
`DESCRIBE` answers from the read path and the listing does not.

## Design

**Probe the projection where it is written**, exactly as spec 010 probes an object's own and spec 021
binds a predicate: when a grant states columns, bind `SELECT <items> FROM <the object>` and store the
resulting names and types in `grant_columns(role, vcat, vname, pos, name, type)`.

**The two levels are folded the way the resolver folds them.** A bare name in a grant is the *object's*
column, which the object's own projection may have renamed (`order_id` where the table has `id`); an
expression in a grant is evaluated over the *physical* row, where a column the object's projection
hides still is (`marker = coalesce(tenant, …)` on an object that does not expose `tenant`). The probe
builds exactly that, so it describes what the role will get rather than one level of it.

**A projection that cannot bind is refused where it is written**, the same rule spec 021 applies to a
predicate — and the same two steps: the object is bound first, so a source that is not attached yet
leaves the projection accepted unchecked rather than blamed for something it cannot be judged on.

**The listing prefers the grant's rows for the names they define** and adds the ones the object never
had. A name the grant does not mention still comes from the object's own probe and is still narrowed
by the grant's column list, so nothing that used to be hidden becomes visible.

**Across roles the rows union**, like everything else a principal's roles carry. Two roles that mask
the same column differently were already refused (spec 011), so there is no ambiguity about which type
a name has.

## Enforcement & security

- **Nothing becomes visible that was not readable.** The rows describe a projection the role already
  had; the change is that the description is now accurate rather than borrowed from the physical
  table. The test asserts that a column the grant does not project appears in neither surface.
- **The probe binds, it does not read**: `WHERE false` on top, as everywhere else.
- **The rows are grant-scoped and go with the grant**: revoking a catalog from a role, or dropping the
  object, deletes them. A stale row would describe a projection nobody has.
- A `grant_columns()` listing is added for operators, beside the other introspection surfaces.

## Testing

`test/sql/acl_grant_projection.test` (61 assertions): a grant projecting one column as-is, one masked
to `NULL` and one computed from a column the role cannot see; `DESCRIBE` and
`information_schema.columns` agreeing on all three, and agreeing with what `SELECT *` returns; columns
the grant omits absent from both; the operator's listing showing what was probed; the two levels folded together on a renamed object, where a bare name and a computed one land side by
side and both surfaces agree; a projection that cannot bind refused, and one whose source is not
attached accepted; a role without a projection of its own unaffected; rewriting a grant rewriting its rows; and revoking the grant or
dropping the object clearing them.

## Alternatives considered

- **Emit the grant's column names with an unknown type.** The name is the more useful half, but a
  typeless column in `information_schema.columns` is a lie of a different shape, and a client that
  reads types would break on it.
- **Have the listing bind the effective relation per principal.** Exact by construction, but it is a
  bind per listing per role, on a read path, for something that changes only when a grant does.
- **Drop `information_schema.columns` in favour of `DESCRIBE`.** They answer different questions: one
  enumerates a catalog, the other describes one relation. Tools use both.

## Follow-ups

- **A catalog-level grant's column list** is not probed: it applies to every object in the catalog, so
  a projection there would have to be probed per object. Its practical use is narrowing, which the
  listing already handles; a computed column at that level is not expressible today.
- **`acl_refresh_schema` should re-probe grant projections too**, alongside the objects' own — a source
  that changes a column's type leaves both stale.
