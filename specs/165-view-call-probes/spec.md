# Spec 165: a call in a principal's view keeps its probe

- **Status**: implemented
- **Date**: 2026-11-15
- **Author**: hugr lab (spec 164's BACKLOG item)

## Summary

A virtual table function called with the body's columns inside a principal's view (spec 113) now keeps its probe
(spec 164) with the stored body. The probe is a root CTE `__acl_probe_<n>` that nothing references. The view's reader
takes it off the body and binds it alone, so a name the call's template or grant lost refuses. It no longer binds to
a relation of the body.

## Problem

Spec 164 binds such a call alone, with its arguments NULL, before a statement is optimized, but not in a view body:
the body is stored and read later, so a probe noted at its creation would bind once, not at every read. Spec 162
hoists a view's closed reads to the body's root, but a call with the body's columns cannot move there.

In `SELECT f.id FROM (SELECT 'k' AS key, 'eu' AS region) s, tfa(s.key) f`, after the source dropped `region`, the
grant's `RLS (region = 'eu')` over the call bound to the body's `s.region` and the view returned every row. This held
for a template call and for an alias of a table macro.

## Design

- **At creation**: in a view body (`view_reads` set) `NoteProbe` keeps the probe `ProbeCall` builds (now an AST, not
  text) in `view_probes`. `AttachViewReads` puts each one at the body's root as a `NOT MATERIALIZED` CTE
  `__acl_probe_<n>`, after the reads. duckdb binds a CTE only when it is referenced, so a probe costs the view's
  readers nothing.
- **At read**: the resolver splits the root CTEs with the prefix off the stored body (`SplitViewProbes`, in
  `LookupRelation`) into `TablePolicy::probes`. This happens before a grant wraps the body
  (`SELECT … FROM (<body>) AS __acl_granted`: an object grant's RLS or COLUMNS, a catalog or schema grant's
  predicate), which would leave the CTEs inside a subquery. `BuildTableSubquery` of a view adds each probe to the
  statement's guards with `WRITE_GUARD_NAMES_ONLY`, as spec 164 does for a statement. When the read is itself in a
  principal's view body, the probes go to that body's root instead, so a view over the view carries them.
- **Reserved**: a principal's view body CTE named with the `__acl_probe_` prefix is refused at any level, as spec 162
  refuses `__acl_read_`. An operator's view body (`CREATE VIRTUAL VIEW`, `ALTER VIRTUAL VIEW … SET AS`) with such a
  root CTE is refused where written (`RequireNoProbeCte`): its readers would take the CTE off.

Not covered: a view a principal stored before this spec keeps its body without probes until it is created again (as
spec 162's reads).

## Enforcement & security

Fails closed: a principal's view with such a call is read only after the call, its arguments NULL, binds alone,
whichever grant wraps the reader's read.

## Testing

`test/sql/acl_view_call_probes.test`:
- **Before the source drops the RLS column:** views over a template call and a macro alias, called with the body's
  column, read the policy's rows, as does a view over such a view.
- **After the drop:** all three refuse. Before the fix the first two returned every row.
- **A grant wraps the read:** an object grant's RLS, an object grant's COLUMNS, a view over such a view, and a reader
  whose catalog grant carries a predicate all refuse after the drop (found by the review: the wrap hid the probes).
- **No false refusal:** a view over a template whose untyped NULL leaves `date_trunc` without an overload reads as
  before.
- **Reserved:** a principal's body CTE named `__acl_probe_1` is refused, and so is an operator's in CREATE and ALTER.

Not covered (BACKLOG): `acl_check_catalog` binds a view's SQL, where nothing references a probe, so a broken probe has
no finding of the view's own.
