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
  but those whose right is `OPERATE` (the node's runtime: sessions, drain / resume) or `OPEN` (`console_info`):
  `acl: this node attaches the sources of group "etl" only - run it on a node of a group that attaches every source`.
  That covers the policy's writes and the cluster profile's.
- The read functions that probe the stored facts against the sources (`platform.check_catalog`,
  `platform.check_grant`) are refused there the same way. The policy's reads (the `platform.*` views, the listings)
  and the group's queries run.
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
- `RESUME NODE`, `console_info` and a read of `platform.roles` run;
- the trait cleared, writes run again.

It fails without the refusal.
