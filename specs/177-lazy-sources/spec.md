# Spec 177: a source attached on demand

- **Status**: implemented
- **Date**: 2026-11-20
- **Author**: the owner (hugr-node spec 035, 2026-11-16: only the sources marked `LAZY`; `LAZY` without `IDLE` is never
  detached)

## Summary

hugr-node spec 035 stage 2 lets a cluster mark a source `LAZY`: a node does not attach it at bootstrap. It attaches it
on the first statement that reads it, and detaches it after an idle time. Detaching is the platform part's (its tick).
The attach on demand must happen before the statement binds, and only the rewrite knows which databases a principal's
statement reads. This spec is that seam.

## Design

- `PolicyStore::NodeTraits` gains two traits, both set by the platform part at load; an open node has neither:
  - `lazy_sources` (`vector<string>()`) answers the aliases the node keeps lazy;
  - `attach_on_demand(alias)` attaches one if it is not attached and notes its use. It throws when it cannot, naming the
    source and its error class, never the error's text.

  `PolicyStore::LazySources()` reads the first, and is empty unless both are set.
- **The rewrite.** `RewriteStatements` reads the lazy aliases once per batch. When there are any, it walks each
  rewritten statement with `StatementDatabases` (acl_platform_rights.cpp, spec 138's scoped walk). The walk covers a
  SELECT, the DML nodes, a CREATE's query and target catalog, and a DROP's target. Every first part of a table name of
  two parts or more, and every target catalog, that is a lazy alias is attached (`NoteDatabase`, once per statement)
  and noted on the statement's trail.
  - What the policy's texts read is in the rewritten statement: a relation's physical name, a live alias's source, an
    operator's view SQL, an RLS subquery, a template. The walk sees all of them.
  - A principal's own names are virtual, and one that is not is refused before the walk. So a statement wakes only a
    source its policy reaches.
  - A failed attach refuses the statement with the trait's message, reason `source_error`.
- **Each execution.** The lazy sources a statement read go into its principal text (spec 155's registry, keyed by the
  text's hash). `QueryBegin`, which runs before the bind, asks for them again. That covers a source that went idle
  between the decision and an execution: a prepared statement, or a later statement of its batch behind a long one.
  A failure there is left to the bind, which names a database that is not there.
- **The policy's own probes.** A management call that probes the sources has every lazy source attached first, best
  effort (`WakeLazySources`). These are the calls that write the policy, every right but OPERATE / OPEN /
  INFRASTRUCTURE, beside spec 176's refusal. `platform.check_catalog` / `check_grant` do the same. A source that does
  not attach is the probe's to report, as one that is down.
- **Listings never wake a source.** They read the physical facts through `acl_physical_*` with the keys as constants,
  and a database that is not attached is `not attached` (spec 136).
- **Not covered.** `ACL NATIVE` and the operator's own unprefixed SQL are not rewritten; they ATTACH by hand. A virtual
  function in a lazy database is not covered either: the walk reads tables, and the scanners such sources use define
  no functions.

## Enforcement & security

Nothing new is readable. An attach follows the policy's resolution of an object the principal reached, and the source
gate (specs 118.3, 138) is unchanged. Detaching under a reader is safe by duckdb's rule: a transaction keeps every
database it used (`MetaTransaction::referenced_databases`), finds it by name first, and the database closes at its last
reference.

## Tests

`test/cpp/test_acl_lazy_sources.cpp`, with the traits set by hand over a file database:
- reads that attach the lazy source when it is detached:
  - a read of a relation in it;
  - a read of an operator's view whose SQL names it;
  - a read through a live schema alias over it;
- a read of another source asks nothing, and the tables listing and `SHOW TABLES` wake nothing;
- a prepared statement executed after the source was detached attaches it again (QueryBegin);
- a source that does not attach refuses the statement with the trait's message;
- a relation written over the lazy source, and the catalog's check, have it attached first;
- without the traits, nothing is attached.

Each seam is checked by removing it: the walk (every read fails at bind), QueryBegin (the prepared execution), the
policy's wake (the check).
