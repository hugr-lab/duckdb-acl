# Spec 164: a call with the caller's arguments is bound alone too

- **Status**: implemented
- **Date**: 2026-11-14
- **Author**: hugr lab (found by spec 163's review)

## Summary

A virtual table function called with arguments that name the caller's query (spec 163's carrier) is now bound alone
before the statement is optimized, as a closed call is (spec 159). The probe uses the call with those arguments
NULL. A name its template or its grant's policy lost then refuses. It no longer binds to a column of the caller's
query.

## Problem

Spec 159 binds a closed call's read alone, one whose arguments are all constants. A call with the caller's columns,
`FROM (SELECT 'eu' AS region, 'k' AS key) s, f(s.key)`, could not be bound alone as it stands, so it was not bound
at all.

After the source dropped `region`, the grant's `RLS (region = 'eu')` over the call's result therefore bound to the
caller's `s.region`, and the call returned every row. This held for a template call and for an alias of a table macro.

## Design

`ProbeCall` (acl_rewriter.cpp) copies the call and replaces each argument that is not spliceable (spec 163's
allowlist, without parameters) with an untyped NULL. It then builds the copy the way the call itself is built:

- the template, or the alias's target written whole;
- the grant's wrapper around it.

The result is added to the statement's guards, marked to refuse only a name it cannot resolve
(`WRITE_GUARD_NAMES_ONLY`: a catalog error, `COLUMN_NOT_FOUND`, a binder "not found"). An untyped NULL may leave an
overload or an UNNEST without a type (`date_trunc('day', NULL)`), and such an error says nothing about scope. A call
of a system table function (an alias of `range`, `unnest`) is not probed: its columns are fixed, and nothing of it
can be lost. The call itself is built as before (spec 163), so plans are unchanged.

Not covered: a non-closed call inside a principal's view body (spec 162). The stored body is bound alone as one read,
and a relation of the body itself can carry the lost name (BACKLOG).

## Enforcement & security

Fails closed: a non-closed call's statement runs only after the call, its arguments NULL, binds alone.

## Testing

`test/sql/acl_call_bound_alone.test`:
- **Before the source drops the RLS column:** a template call and a macro alias, both called with the caller's
  column, read the policy's rows.
- **After the drop:** both refuse, and so does a grant's mask over a dropped column.
- **No false refusal:** a template over `date_trunc` (an overload) and one over `unnest`, and an alias of `unnest`,
  each called with the caller's column, read as before.

The refusals returned every row before.
