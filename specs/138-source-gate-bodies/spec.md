# Spec 138: the source gate judges what a body really reads

- **Status**: draft (the owner, 2026-10-19: «138 да» - the gaps close before the release)
- **Date**: 2026-10-19
- **Author**: Claude (with the owner)

## Summary

A catalog admin builds only over the sources granted to it (spec 118.3). For a stored body - a view's SQL, an RLS
predicate, a mask, a computed column - the gate judges the table names that duckdb's name extraction reports. Review
137 found that this is not what the body reads, in three ways. From now on the gate judges the **catalog entries**:
each reference as duckdb resolves it, and each table the bound body really scans, by its exact
`<database>.<schema>.<object>`.

## Problem

`AuthorizeSources` (`src/acl_platform.cpp`) takes a body's names from `Connection::GetTableNames(probe, true)` and
judges each with `SourceGranted`. In the name-extraction mode, duckdb's binder records a reference **as written**
and expands a physical view into its body. Review 137 found three gaps:

1. **A physical view's own name is never judged.**
   - Extraction does not record a view, only the references inside it, as written in the view.
   - Those names bind in the view's own catalog: `main.secret` in a view of `sec` is `sec.main.secret`.
   - So a body reading a view of an ungranted source passes whenever the view's inner names look granted. In the
     probe, a view over `vconst`, a constant, passed; so did one over `read_csv('<file>')`, which read the file's
     rows.
2. **A one-part name is matched against a database granted whole.**
   - `SELECT * FROM g` reads the table `g` of the node's default database.
   - The gate treats the name `g` as the database `g`.
3. **The policy store's two-part branch assumes `main`.**
   - `NamesPolicyStore` refuses `<db>.<table>` only when the policy lives in `<db>.main`.
   - A policy catalog in Postgres (`public`) is not covered for a body's `pol.admins`.

Spec 137 closed the case of a two-part name (`pg.t` under a `pg.main` grant). These three are older.

## Design

### Two judgments, both by catalog entry

For each body a catalog admin (neither policy nor passthrough) writes, on the fresh connection the gate already
probes with:

1. **Every reference as written resolves to an entry**, and the entry's source must be granted.
   - The references come from the body's own parse: `BodyTables`, the walk spec 120.2's exposures and the check
     already use.
   - Each is resolved the way the binder resolves it: catalog-or-schema, the search path, the default database and
     its default schema. That gives the exact entry: a table, a view or a missing name.
   - This judges a physical view by **its own** catalog and schema, and a one-part name by the default database it
     reads.
   - A name that resolves to nothing, or to two entries (ambiguous), is refused. The body must bind anyway.
2. **Every table the bound body scans**, after views are expanded, must be in a granted source.
   - The body is bound normally, not in name-extraction mode. The plan is walked for its `LogicalGet`s, and each
     scan's `TableCatalogEntry` gives the exact catalog and schema (the walk lineage's binding already does).
   - So a view of a granted source that reads an ungranted one is refused, as today, but by the exact entry and
     no longer by its inner text.
   - **Pending Q1:** a table function scanned only inside a physical view (`read_csv`, a scanner call).

The gate's `SourceGranted` takes three-part entries only; the plain two-part `main` reading goes away for bodies.
`acl_check_catalog`'s `source_not_granted` judges stored bodies the same way, so the gate and the check agree.

### The policy store, by entry

`RequireNotPolicyStore` for a body checks the same entries. A reference or a scan in the policy store's database and
schema is refused, whatever the policy's schema. The text check (`TextNamesPolicyStore`) stays in front: it is cheap,
and it covers a body that does not bind.

## Enforcement & security

- **Fail closed:** a reference that does not resolve, resolves ambiguously, or whose lookup throws is refused.
- **What changes for a catalog admin:**
  - A body naming a physical view of an ungranted source is refused, even when the view's inner names look
    granted.
  - `SELECT * FROM g` is judged as the default database's table `g`.
  - A view of a granted source whose inner `main.x` binds in that same source, which today is refused by its text,
    is admitted.
- **Policy and passthrough** are not judged by the source gate, as today.
- **Nothing stored is taken back.** Bodies stored before this spec are reported by `acl_check_catalog`
  (`source_not_granted`) when they fail the new judgment, and never rewritten. This is the owner's rule.

## Testing

- **sqllogictest gate coverage probes** for a catalog admin granted one source:
  - a view of an ungranted source over a constant: refused;
  - a view of an ungranted source over `read_csv`: refused;
  - a one-part name of the default database while a database of that name is granted: refused;
  - a view of the granted source whose inner `main.x` stays inside it: admitted;
  - a view of the granted source reading an ungranted one: refused.
- **The policy store:** a policy catalog in a schema other than `main` (Postgres integration) refuses a body over
  `pol.admins`.
- **The check:** a body stored before this spec, through `UPDATE`, is reported by `acl_check_catalog`.

## Open questions

- **Q1. A table function reached only through a physical view.** A view of a granted source may call `read_csv` or a
  scanner function. *Recommendation:* refuse it unless the function gate admits that function to the body's author
  (spec 117's `AuthorizeBodies`). A function the author could not call directly should not be reachable through a
  view the gate otherwise admits.

## Alternatives considered

- **Keep name extraction and add the view names.** Extraction does not record views, and it gives inner names
  without their catalog. Fixing that means resolving in each view's own context, which is what binding already
  does.
- **Refuse every physical view in a catalog admin's body.** Simple and closed, but it takes away a use that works:
  a view inside a granted source.
