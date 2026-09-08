# Spec 065: refusals and listings that keep the source's names

- **Status**: implemented
- **Date**: 2026-09-01
- **Author**: hugr-lab

## Summary

Reclassified with the user (2026-09-01): **development, not a release blocker** — what leaks is
names-never-data, provokable only by an already-granted principal, so this hardens rather than
gates. The family: when an object cannot be read — a grant's column list
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

## Design — no probing, anywhere (user, 2026-09-01)

The constraint that shapes everything: **the resolver never probes the source** — not on the query
path (latency), not by re-checking at read (a snapshot taken at create time guarantees nothing
later), and a table function cannot be probed at all. What the catalog *knows at write time* is the
whole truth the refusals may use. From that:

1. **The declared-shape branch is already right.** An object with a declared `COLUMNS` list folds
   its projection in the resolver, and an empty intersection already refuses with virtual facts
   only (`acl_rewrite: object "orders" exposes no readable columns` — probed 2026-09-01). Tests pin
   it; nothing to build. A declared list IS the opt-in to clean refusals, per object, at zero
   query-path cost — the operational guidance for sensitive objects.
2. **The grant's list is judged where it is written** (returned to scope by the user: "тоже можно,
   но только там где возможно — без пробы"). Only the **bare** items are judged — a `name = expr`
   entry defines its own column (a mask, a computed column, spec 026) and owes nothing to existing
   names; on a declared object the computed case keeps spec 037's own richer refusal. A bare list
   that matches no column of any *known-shape* object of the grant's scope is refused at write,
   naming the list. The judgment fires only when it can be right: a scope with nothing declared yet
   (a fresh catalog, a grant written before its objects), one shape-less relation, one undeclared
   table function, or any alias schema, and the write is allowed — the list may match there. It
   judges only where the list itself is being written: `ALTER GRANT SET MAIN/CAPS/RLS` never
   re-judges a stored list against a catalog that has moved. Shapes come from `relation_columns`
   and `object_columns`, read with the same `ParseColumnList` the read path uses; nothing is probed.
3. **`duckdb_tables()` never answers a NULL `sql`** (a quack client builds its catalog from it and
   failed on the whole catalog): an object whose visible column set is empty has no DDL to
   synthesize — `CREATE TABLE t();` does not even parse — so the row is not listed there at all,
   judged from the same `vcolumns` fold every other answer uses. The filter is the tables branch's
   own: `duckdb_views` keeps every readable view (its `sql` is NULL by design there, and a view
   whose shape was never probed still answers reads), and `information_schema.tables` /
   `SHOW TABLES` still list the object (nothing there synthesizes DDL).
4. **`is_insertable_into` follows the grant**, not the physical row: the effective caps chain
   (object → schema → catalog, spec 012's unstated-default read textually, like the rest of the
   listing SQL) and the relation's **stored form** — `form = 'alias'` is writable, everything else
   (a mask, an RLS'd relation, a view) is the read-only SUBQUERY form. The form was decided where
   the object was written (`RenameOnlyColumns`), so the listing and the write path cannot disagree;
   the lookup keys by the stored vname, so a `main.`-qualified object judges its own rows.
5. **The management grammar unquotes `COLUMNS` items**, so `COLUMNS ("odd name")` matches the
   column it names, like the function form does — including a quoted name followed by spec 048's
   nullability suffix (`"odd name" NOT NULL`). The stored csv form splits on `,` and `=`, so a
   quoted name containing either is refused where written rather than silently re-split into
   columns the admin never named. The emitters quote the bare stored name back (`Ident`) wherever
   it re-enters generated SQL — stored verbatim WITH quotes, the old form only accidentally
   composed valid SQL on that path.

### Accepted risk — written down, not wished away

Where the shape is honestly unknowable at write time (a bare alias, every table function), a
misconfigured grant or a drifted source mapping still surfaces **duckdb's** binder error, which
names physical columns (probes A and B). What leaks is *names, never data*: RLS and masks are not
bypassed, and only a principal already holding a grant on that object can provoke it — an
admin-misconfiguration surface, not an outsider's. Compensations: direction 2 stops most of B at
grant write; spec 039's admin-run `acl_check_catalog` (off the query path) detects A; declaring
the shape upgrades any given object to clean refusals. A future write-time parse+PREPARE of views
and table functions (backlog) would let those object kinds infer their shape at save and join
branch 1 without hand-typed lists.

## Enforcement & security

The whole spec is enforcement: an error message is an output channel, and today it carries names
the projection exists to hide. The rule this spec pins: **every message a principal can provoke
names only what the principal's own catalog shows** — virtual names, virtual columns, the acl
prefix. Tests grep refusals for the physical fixtures' names, the way spec 046's leak tests do.

## Tests

- The declared-shape refusal pinned: empty intersection over a declared object answers `acl_rewrite:
  ... exposes no readable columns` and matches none of the physical fixtures' names.
- A grant whose `COLUMNS` list matches nothing on any known-shape object is refused at write,
  naming the list; the same list is accepted when an unknown-shape object could still match.
- `duckdb_tables().sql` is non-NULL and parses for every listed object, including one no query
  returns; `is_insertable_into` follows caps (a read-only virtual object answers NO).
- Quoted `COLUMNS ("odd name")` matches the column it names, in both grammar and function forms.
- The accepted-risk probes (A, B on a bare alias) stay as documentation in this spec, not tests -
  they assert duckdb's message, which is not ours to pin.

## Alternatives considered

- **Probing the source** (at read, at listing, or re-validating at template-cache fill): rejected
  by the user - query-path latency, a create-time snapshot guarantees nothing later, and a table
  function cannot be probed at all. Write-time judgment over cataloged facts is the whole budget.
- **A sentinel column keeping the star expansion non-empty** so the empty-set error becomes ours:
  the sentinel is matched by the projection lambda on every read, so a successful read stops being
  byte-identical - rejected.
- **Excluding unreadable objects from listings**: deciding "unreadable" needs resolution = probing;
  and an admin must be able to see the object to repair it (spec 039 prefers marked over hidden).
