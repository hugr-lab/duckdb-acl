# Spec 178: the platform part's never set

- **Status**: implemented
- **Date**: 2026-11-20
- **Author**: Claude, from the review of hugr-node spec 035 stage 3

## Summary

The never set (spec 072/092) is code: names no grant reopens. Its prefixes are acl's own (`acl_`, `ducklake_`, `quack_`,
`uc_`, `__internal_`). The platform part linked into the extension (hugr-node) registers operator-only table functions
of its own: `hugr_node_profile_statements`, `hugr_node_bootstrap_plan` and others. Until now a `policy` administrator
could open one to a principal with `GRANT FUNCTION … TABLE`. The rows then answered the profile's `ATTACH` statements,
which hold paths and hosts, never credentials.

## Design

- `RegisterNeverCallablePrefix(prefix)` (acl_function_categories.hpp) lets a module add a prefix at load, before the
  first statement. It is idempotent and process-wide, like the platform registry, and `FunctionNeverCallable` reads
  it beside acl's own prefixes. Everything that judges the never set reads it the same way:
  - the function gate, at a call;
  - the grant and category writers, at a write;
  - `acl_function_status`.
- `ClusterAuditObject` reads a compiled `acl_cluster_*` call's item from its arguments. A table-function form
  (`SELECT * FROM acl_cluster_…(…)`, the platform part's `platform.group_sources`) writes no item, and is audited by its
  name. It used to throw an INTERNAL error on that form.

## Enforcement & security

Only refusals are added. A grant written before the registration no longer admits the call, because the never set is
judged at every call. The operator's own SQL is unchanged.

## Tests

`test/cpp/test_acl_never_set_prefix.cpp`:
- before the registration the name is not in the set; registered (twice), a grant by name is refused as the never
  set's;
- any name of the prefix is in the set, and a name that merely starts alike is not;
- the operator's own call runs.

The principal-level negatives for the real functions (`hugr_node_*`, `platform.group_sources` under each bundle) are
hugr-node's.
