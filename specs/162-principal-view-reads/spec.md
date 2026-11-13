# Spec 162: a principal's view reads its policies at its root

- **Status**: implemented
- **Date**: 2026-11-13
- **Author**: hugr lab (found by spec 159's review)

## Summary

A principal's own view (spec 113: `CREATE VIEW` in a home its role may create in) stores its body rewritten with
its author's policies. Each policy read in that body is now a `NOT MATERIALIZED` CTE at the body's root, instead of a
subquery in place. A policy name its source lost then refuses when the view is read. It no longer binds to a relation
of the body.

## Problem

Spec 159 binds every policy read alone before a statement is optimized. A principal's view is one read when it is
read later: its stored body is bound alone as a whole. The policy reads inside that body were subqueries in place.
A policy name its source lost could therefore still bind to a relation of the body: an earlier item of the body's
FROM (an implicit LATERAL join), or a correlated query. The check of the whole body could not see that, because the
relation it bound to is inside the body too.

## Design

`RewriteCreateView` collects the body's policy reads (`ReadRef` with `view_reads` set): a relation's, and a table
function's called with constant arguments (spec 159's closed calls). Each read becomes
`__acl_read_<n> AS NOT MATERIALIZED (<read>)`, and the object's place holds a reference to it with the object's alias,
column aliases and sample. `AttachViewReads` puts these CTEs ahead of the body's own CTEs at its root. A CTE body at
the root sees none of the body's FROM, and the whole view is bound alone when read (spec 159). So every name of a
read resolves in its own source, or the read refuses.

A CTE of the body's own whose name has the reads' prefix (`__acl_read_`) is refused where the view is created, at
any level of the body: a nested one would shadow a read inside its scope.

The read of the root's first FROM item stays in place: nothing is before it and no query is around it, so no name of
the body can reach it, and the whole view is bound alone when read. A CTE there would hold a reader's filters back
from the source: duckdb keeps a `NOT MATERIALIZED` CTE materialized under a correlated or LATERAL join over a source
whose scan cannot be copied (Postgres, MySQL; spec 159's alternatives). Measured: a `WHERE id = 42` reader read 50,000
rows instead of 1. Other hoisted reads can still meet that cost when the body joins them so.

Views stored before this spec keep their bodies until they are created again. A table function called with the
principal's columns stays in place (`acl_arg`'s scope, BACKLOG).

## Enforcement & security

A principal's view refuses when a policy read inside it does not bind in its own source. A statement that reads
policies directly (spec 159) is unchanged.

## Testing

`test/sql/acl_principal_view_reads.test`:

- **The stored body** begins with the read's CTE for a read after another FROM item; the root's first item's read
  stays in place, and refuses as well after the drop.
- **Before the source drops the RLS column:** a view joining a relation that carries the name, and a view counting
  through a correlated subquery, read only the policy's rows.
- **After the drop:** both views refuse.
- **A table function called with constant arguments** in the body refuses after the drop as well.
- **A CTE named like a read** is refused, at the root and nested.

The full suite is unchanged.

## Alternatives considered

- **Storing the reads' guards with the view.** It needs a schema step, and the registry is in memory.
- **Rewriting the stored body at each read.** That changes spec 113's model: the body is decided with its author's
  rights where it is created.
