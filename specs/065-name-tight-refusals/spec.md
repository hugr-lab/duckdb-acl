# Spec 065: refusals and listings that keep the source's names

- **Status**: draft
- **Date**: 2026-09-01
- **Author**: hugr-lab

## Summary

The release-blocker family from the backlog: when an object cannot be read — a grant's column list
intersects to nothing, or a mask's source column no longer exists — the refusal today is **duckdb's
binder error over the SQL we generated**, and it names what the principal must never see: physical
column names, the object's full physical column list, and our rewrite machinery. The listings have
the mirror problem: an object no query returns is still listed, described, and (for a quack client)
carries a NULL `sql` that breaks catalog parsing. This spec makes every such refusal name **virtual
facts only**, and makes the listings tell the truth about what resolves.

## Problem — probed on the current build (2026-09-01)

**A. The dead object leaks the source's naming.** `c.customers AS phys.main.customers COLUMNS
(id = pk, tenant = internal_tenant, ssn = ssn_raw)`; then the source drops `ssn_raw`. The
principal — who has only ever been shown `id, tenant, ssn` — gets:

```
Binder Error: Referenced column "ssn_raw" not found in FROM clause!
Candidate bindings: "internal_tenant"
```

Two physical names, from an ordinary `SELECT *`.

**B. An empty grant intersection leaks the object's whole physical shape.** A catalog grant
`COLUMNS (nothing_here)` over a bare alias:

```
Binder Error: Star expression "COLUMNS(list_filter(['id', 'tenant', 'amount'],
(lambda __acl_col: (lower(__acl_col) IN ('nothing_here')))))" resulted in an empty set of columns
```

Every physical column of the object, plus the rewriter's internals. duckdb renders the error by
expanding our lambda over the *actual* column list, so the disclosure is in the engine's error
formatting, not in text we control. `DESCRIBE` leaks identically (spec 025 routes it through the
same rewritten SELECT).

**C. The unreadable object is still listed.** After A or B — and equally for spec 037's
two-roles-mask-one-column-differently conflict — `SHOW TABLES` lists the object,
`duckdb_tables()` describes it, and no query returns. `duckdb_tables().sql` is NULL there, and a
quack client parses that string to build its catalog: it fails on the whole catalog, not the one
object (spec 035). `is_insertable_into` is borrowed from the physical row, so a read-only virtual
object answers `YES` (spec 035).

**D. Adjacent grammar defect (same code path):** a quoted identifier in a management grant's
`COLUMNS ("odd name")` is stored verbatim with its quotes and never matches (the function form
works). Needs per-item unquoting and a decision on what `"a b"` means.

## Design (directions — to be settled while implementing)

1. **Refuse emptiness where the resolver can know it.** Spec 026 probes grant projections where
   they are written (`grant_columns`); where the effective projection of (grant, object) is known
   at rewrite time, an empty intersection refuses in the resolver with virtual facts only:
   `acl: no column of "orders" is granted to this principal`. The engine's error is never reached.
2. **Where the columns are honestly unknowable** (spec 038's deliberate no-probe branch; every
   table function), the generated SQL must be shaped so the failure is OUR message: a sentinel the
   projection keeps non-empty whose evaluation raises the acl refusal, or a pre-flight the wrapped
   query runs before the star expands. The constraint: a successful read must stay byte-identical
   (no extra column, no extra scan).
3. **The dead mapping (A) refuses with the virtual name** and points at the repair procedure
   (spec 039's `acl_check_catalog`). Where: validating stored physical references against the live
   source belongs at template-cache fill, not per query; what a schema change after caching does is
   part of the design work.
4. **Listings ask "does it resolve"**, not only which columns pass: an object in state A/B/C is
   either excluded or marked (spec 039 prefers marked — an admin must be able to see it), and
   `duckdb_tables().sql` always carries a string a client can parse. `is_insertable_into` follows
   the grant's capabilities.
5. **The grammar unquotes `COLUMNS` items** (D), matching the function form.

## Enforcement & security

The whole spec is enforcement: an error message is an output channel, and today it carries names
the projection exists to hide. The rule this spec pins: **every message a principal can provoke
names only what the principal's own catalog shows** — virtual names, virtual columns, the acl
prefix. Tests grep refusals for the physical fixtures' names, the way spec 046's leak tests do.

## Tests

- Probes A and B above as sqllogictests: the refusal matches `acl:` and does NOT match any of
  `ssn_raw|internal_tenant|list_filter|__acl_col` (and for B, none of the physical column names).
- `DESCRIBE`/`SHOW TABLES`/`duckdb_tables()` over an object in each state: listed-and-marked or
  absent (per the settled direction), `sql` never NULL, `is_insertable_into` follows caps.
- The 037 conflict (two roles, one column, different masks) lands in the same refusal shape.
- Quoted `COLUMNS ("odd name")` matches the column it names.

## Alternatives considered

(to be filled as the directions settle)
