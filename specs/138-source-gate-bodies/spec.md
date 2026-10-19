# Spec 138: the source gate judges what a body names, by catalog entry

- **Status**: draft (the owner, 2026-10-19: «138 да» - the gaps close before the release)
- **Date**: 2026-10-19
- **Author**: Claude (with the owner)

## Summary

A catalog admin builds only over the sources granted to it (spec 118.3). For a stored body - a view's SQL, an RLS
predicate, a mask, a computed column - the gate judges the table names that duckdb's name extraction reports. Review
137 found that this is not what the body names, in three ways. From now on the gate judges the **catalog entries**
the body names - each reference as duckdb resolves it, by its exact `<database>.<schema>.<object>` - and, by the
owner's rule, never what a granted view or function reads inside.

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

### One judgment, by catalog entry: what the body names, never what a granted object reads inside

The owner, 2026-10-19 (Q1): a table function the principal holds a right on is allowed, whatever its own query
reads inside. The same holds for a physical view of a granted source: the right on the source is the right on its
objects. The gate judges **what the body names**, each reference resolved to its exact entry, and never looks into
a granted view's or function's definition.

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
2. **The body must bind** (as today): it is bound normally on the probe connection, and a body that does not
   bind is refused - nothing judged by name is then left unread.
3. **What a granted view or function reads inside is not judged.**
   - A view of a granted source that reads another source is admitted. Today its inner text was judged, and
     wrongly (`main.x` read in the default database).
   - A table function the author may call is admitted whatever it scans: the function gate (spec 072, judged per
     body by `AuthorizeBodies`) decides the call, the source gate does not look inside.

The gate's `SourceGranted` takes three-part entries only; the plain two-part `main` reading goes away for bodies.
`acl_check_catalog`'s `source_not_granted` judges stored bodies the same way, so the gate and the check agree.

### The policy store, by entry

`RequireNotPolicyStore` for a body checks the same entries. A reference resolving into the policy store's database
and schema is refused, whatever the policy's schema. The text check (`TextNamesPolicyStore`) stays in front: it is cheap,
and it covers a body that does not bind.

## Enforcement & security

- **Fail closed:** a reference that does not resolve, resolves ambiguously, or whose lookup throws is refused.
- **What changes for a catalog admin:**
  - A body naming a physical view of an ungranted source is refused, even when the view's inner names look
    granted (the gap).
  - `SELECT * FROM g` is judged as the default database's table `g` (the gap).
  - A view of a granted source is admitted whatever it reads inside - the owner's rule (Q1). Today its inner text
    was judged; this is the one place the gate admits more than before, and it is the operator's own view in a
    source the operator granted.
- **Policy and passthrough** are not judged by the source gate, as today.
- **Nothing stored is taken back.** Bodies stored before this spec are reported by `acl_check_catalog`
  (`source_not_granted`) when they fail the new judgment, and never rewritten. This is the owner's rule.

## Testing

- **sqllogictest gate coverage probes** for a catalog admin granted one source:
  - a view of an ungranted source over a constant: refused;
  - a view of an ungranted source over `read_csv`: refused;
  - a one-part name of the default database while a database of that name is granted: refused;
  - a view of the granted source whose inner `main.x` stays inside it: admitted;
  - a view of the granted source reading an ungranted one: admitted (Q1 - the right on the object).
- **The policy store:** a policy catalog in a schema other than `main` (Postgres integration) refuses a body over
  `pol.admins`.
- **The check:** a body stored before this spec, through `UPDATE`, is reported by `acl_check_catalog`.

## Decisions

- **Q1 (the owner, 2026-10-19):** «если дали права на табличную функцию то ее разрешаем независимо от того что
  разрешено внутри ее запроса» - a right on the object is enough; what its definition reads is not judged. Applied
  to a physical view of a granted source the same way (to be confirmed with the owner with the spec's acceptance).

## Alternatives considered

- **Keep name extraction and add the view names.** Extraction does not record views, and it gives inner names
  without their catalog. Fixing that means resolving in each view's own context, which is what binding already
  does.
- **Refuse every physical view in a catalog admin's body.** Simple and closed, but it takes away a use that works:
  a view inside a granted source.
- **Also judge every table the bound body scans** (through views). Stricter, but against the owner's rule (Q1):
  the right on a view or a function is the right to what it reads.
