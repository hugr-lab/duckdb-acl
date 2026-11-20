# Spec 176: a node with part of the sources writes no policy

- **Status**: implemented
- **Date**: 2026-11-20
- **Author**: the owner (hugr-node spec 035, 2026-11-16: the checks against the sources never run on a partial node)

## Summary

hugr-node spec 035 lets a resource group declare the sources its nodes attach: only part of the cluster's. A node with
such a set must not write the policy, nor check the stored facts against the sources. Either would be judged against
sources it lacks: a `source_missing` for a source the group never attaches, a grant's predicate refused because its
table is not there. This spec is the seam: the platform part says the node is partial, and acl refuses those calls,
naming where to run them.

## Design

- `PolicyStore::NodeTraits::partial_sources` (a `std::function<string()>`, set by the platform part at load) answers
  the group whose declared source set is all the node attaches, or `''` (every source). `PartialSourcesGroup()` reads
  it, and an open node has none.
- `RefuseWritesOnPartialNode(statements, store)` (acl_platform.cpp) runs beside the one authorizer (`AuthorizeMgmt`)
  at both management seams, the gateway's `ACL ADMIN` and a principal's statements. It refuses every compiled call
  except those whose right is `OPERATE` (the node's runtime: sessions, drain / resume), `OPEN` (`console_info`), and
  view-as (`SET / RESET SESSION VIEW AS`, which sets the session's mode and never the policy; a session already in the
  mode must be able to leave it). The refusal reads `acl: this node attaches the sources of group "etl" only - run it
  on a node of a group that attaches every source`. That covers the policy's writes and the cluster profile's.
- The exempt calls are judged first, and the trait is read only for a batch holding a call that writes. The node's
  operation therefore never depends on reading the policy catalog: during an incident the catalog may be unreachable,
  and a `DRAIN NODE` must still run.
- The read functions that probe the stored facts against the sources (`platform.check_catalog`,
  `platform.check_grant`) are refused there the same way. The policy's reads (the `platform.*` views, the listings)
  and the group's queries run.
- A principal's own DDL keeps its record (spec 113 / 151: `acl_register_*`, `acl_rename_relation`,
  `acl_drop_relation`). The record names an object in a source the node holds, because the DDL ran there.
- `ACL NATIVE` (the break-glass) and the operator's own SQL on the node (its bootstrap's direct `acl_*` calls) are
  unchanged: they are not the management grammar's, and NATIVE is never refused. A cluster whose every group declares
  a source set therefore writes its policy only through them; the ordinary place is a node of a group without a set.

## Enforcement & security

Only refusals are added, whoever the principal is (passthrough included): a write judged against missing sources
never lands in the catalog. A trait that throws (the profile not readable) fails the call.

## Tests

`test/cpp/test_acl_partial_sources.cpp`:
- with every source, a gateway write and a principal's write run;
- with the trait set, the gateway's write, a principal's write, a grant and `platform.check_catalog` are refused with
  the message, and nothing is written;
- a platform call (`SELECT platform.create_role(…)`), `platform.check_grant`, the check read inside a query (the
  rewriter's path) and a batch with one write among exempt calls are refused;
- `RESUME NODE`, `KILL SESSION`, `console_info`, a read of `platform.roles`, and `SET` / `RESET SESSION VIEW AS` run;
- with a trait that throws (an unreachable catalog), `RESUME NODE` still runs, and a write fails with the trait's
  error;
- the trait cleared, writes run again.

It fails without the refusal.
