# Spec 126: the split's seams - where the platform part plugs into acl

- **Status**: accepted (owner, 2026-10-13)
- **Date**: 2026-10-13
- **Author**: the agent, at the owner's ask (design/080, variant 2: `hugr_node` builds duckdb-acl in as a submodule;
  step 2 - the seams; step 3 moves the code)

## Summary

The platform part of today's acl (design/080 group A: the cluster profile, node groups, drift, `acl_deployment` and
the mandatory secrets service, the `cluster` bundle) plugs into acl through a handful of **in-process registration
points**, and acl's own cluster code is moved onto them first - still in this repository - so step 3 can lift it
into `hugr-node` without touching acl again. Variant 2 compiles both into one artifact, so a seam is a C++
registration call, not a versioned contract; each has the shape a duckdb-ext-common contract would have, so
variant 3 stays open.

## Problem

Group A is woven into the core at six places (design/080 §2D "no seam for"):

1. the `platform` registry is two static tables (`PlatformViews()` / `PlatformFunctions()`, acl_platform.cpp);
2. the management grammar's `CLUSTER …` branch is hardcoded (`IsMgmtStart`, `ParseCluster` in acl_admin_sql.cpp);
3. the `cluster` scope is an `AdminScope` value with its right classes (INFRASTRUCTURE, the CLUSTER view class) and
   the authorizer calls `ClusterBundleMaySet`;
4. node placement is inside `SessionOpenBody` (spec 096's refusal, `ResourceLimitsOf(…, node_group)`);
5. the load report writes `group` / `group_known` / `config.{target,applied}` itself (acl_node_load.cpp);
6. the rewriter asks `ClusterNode()` whether secrets may be kept locally (spec 118.1).

## Design

One header, `acl_extension_points.hpp`, in namespace `duckdb::acl`, reached through the `PolicyStore` the
co-linked module gets at load (`RegisterAcl…` seams take it already). Every point is registered at load, before
the first statement; none is a process global (state per instance, as everything in acl).

| # | Point | What acl keeps | What a module registers |
| --- | --- | --- | --- |
| 1 | **Platform registry** | the registry and the ONE authorizer that judges every entry by its right / view class | views and functions (`PlatformView`, `PlatformFunction`, as today's entries) |
| 2 | **Management grammar** | the override, the prefix scan, the authorizer and the audit of every compiled call | a keyword (`CLUSTER`) and a parser: text → the compiled call(s), as `ParseCluster` returns today |
| 3 | **Admin scopes** | `AdminRights` as a set, the parse of `admins` rows (an unknown scope stays privileged and grants nothing - spec 097), `GrantableAdminScopes()` | a scope (`cluster`), what it implies (`operate`), the right classes it opens, and a rule for its settings (`ClusterBundleMaySet`) |
| 4 | **Session admission** | the refusal at `SessionOpenBody` (every door; reason, audit, the Flight / quack answers) | a placement rule: principal → admit or refuse with the groups that serve it, and the limits to use |
| 5 | **Load report sections** | the report, its endpoints and their auth (spec 097) | a JSON section (`group`, `group_known`, `config`) |
| 6 | **Node traits** | the rewriter's secret rule | "secrets only in the service" (today `ClusterNode()`) |

- **Order of work**: the points land with acl's own group A registering through them (a `RegisterAclCluster` that
  calls the points instead of being called from the core). The core then has no reference to group A: a build
  without `acl_cluster.cpp` (a CMake option) links and passes every test that is not group A's - that is the proof
  step 3 needs.
- **The catalog tables stay in acl's schema** (`cluster_items`, `cluster_deps` - v16; `resource_groups.is_default` -
  v18): steps are history and nothing is undone by itself (owner's rule). An open node never reads them; the
  module reads and writes them through `CatalogBackend` as today. New platform-only tables would need a schema point
  - not needed for this split, left for when one appears.
- **Settings** `acl_deployment` and `acl_node_group` are registered by the module (step 3); until then by acl's own
  group A through the same load path.

## No code is lost (owner, 2026-10-13)

Step 3 moves group A out; nothing of it may be lost on the way:

- **A tag first**: `pre-platform-split` on the last duckdb-acl commit that still holds group A.
- **Moved with its history**: group A's files and their tests go into `hugr-node` by a history-preserving
  extraction (`git filter-repo` on those paths), not by a copy.
- **The removal merges last**: the duckdb-acl PR that deletes group A merges only after `hugr-node` builds with
  duckdb-acl as a submodule and passes every group-A test (the same files, moved).
- **acl's history keeps it too**: the removal is an ordinary commit; nothing is rewritten.

## Enforcement & security

The authorizer, the audit and every refusal stay in acl: a module adds entries the ONE authorizer judges by class,
never a second gate; a grammar parser only compiles text into calls the authorizer then judges (spec 117: grammar
and call are judged alike). A module registering nothing leaves an open node: the scope list, the registry and the
grammar simply lack the platform's parts - `cluster` in an old `admins` row grants nothing (spec 097's unknown
scope). Registration happens only at load, in-process, from a co-linked module - no SQL can register anything.

## Tests

- The whole gate unchanged with group A registered through the points (behaviour identical).
- A build without group A (`-DACL_NO_CLUSTER=ON`): it links; the suite minus group A's files (`acl_cluster_profile`,
  `node_cluster`, `acl_node_group`, `test_acl_cluster_install`, `test_acl_placement`, the group-A blocks of
  `platform_*`) passes; `console_info` lists no `cluster` scope, no `cluster_*`, no `drift`; `ACL CLUSTER …` is an
  unknown management statement; a grant row `cluster` grants nothing.
- C++: a test module registering one view, one function, a grammar keyword, a scope and an admission rule - each
  judged by acl's authorizer and audited.

## Alternatives considered

- **Contracts in duckdb-ext-common now (variant 3)**: versioned layouts and RTLD_LOCAL rules for six seams within the
  release window - the owner chose variant 2; the points keep the contract's shape for later.
- **Leave the core calling group A by name** and only move the files: the core would not link without the platform
  part, so the open node could not be built - the split would be in name only.
