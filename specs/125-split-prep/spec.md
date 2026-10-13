# Spec 125: before the split - the core out of the cluster file, the node says what it is

- **Status**: implemented (accepted by the owner 2026-10-13)
- **Date**: 2026-10-13
- **Author**: the agent, at the owner's ask (design/080: the open duckdb-acl and the hugr platform split before the
  acl release; this is step 1, the same whichever variant the split takes)

## Summary

The cluster parts (profile, node groups, drift, `acl_deployment`, the `cluster` bundle) are to leave duckdb-acl for
`hugr_node` (BUSL). Before anything moves, two things that are not the cluster's leave its file, and the node tells
a client what it is, so one DBeaver plugin serves an open node and a platform node by what the server says, not by
what the plugin assumes. No behaviour of a statement changes.

## Problem

- `src/acl_cluster.cpp` holds core code the cluster does not own: `PolicyStore::MetadataMaxRows()` (spec 119, read
  by the rewriter for every listing) and `SqlNamesSource` (spec 118's text check, used by spec 120.2's
  `platform.exposures`). Moving the file would take them along.
- `platform.console_info()` answers the views and functions a principal may use and its bundles, but not the
  deployment: the plugin learns "standalone" from the text of a refusal (`this node is standalone`), and on a
  standalone node a `cluster` holder is offered the profile's writes (`cluster_extension/_attach/_detach/_setting`)
  and `drift`, which the node then refuses.
- The plugin's admin-scope picker hardcodes the scopes (`observe, operate, cluster, policy, manage, passthrough`):
  a node without the cluster part would still be offered `cluster`.

## Design

- **Core out of `acl_cluster.cpp`**: `MetadataMaxRows()` moves to `acl_policy.cpp`; `SqlNamesSource` to its own
  small unit (`acl_sql_text.{hpp,cpp}`), and `acl_platform_rights.cpp` stops including `acl_cluster.hpp`. What stays
  in the file is exactly design/080's group A (the authorizer's `ClusterBundleMaySet` call is the `cluster` bundle's
  own rule and moves with it in step 2).
- **`platform.console_info()` adds two columns** (at the end, so a reader by name is unaffected):
  - `deployment` - `standalone` | `cluster` (the node's `acl_deployment`);
  - `scopes` - the admin scopes this node grants (`GRANT ADMIN <scope>`), in the order a picker shows them. Today
    the fixed six; after the split, an open node lists none of the cluster's.
- **On a standalone node**, `my_functions` leaves out the profile's writes and `my_views` leaves out `drift`: the
  calls they name are refused there (`RequireClusterDeployment`, spec 118.2), so the listing says what works. The
  profile's reads (`cluster_items`, `cluster_effective`) stay - they read on any node.
- **The plugin** (acl-clients): the admin-scope picker reads `scopes`; "standalone" is `deployment`, not an error
  text; `console_info` is read again on Refresh (a node whose parts change - `hugr_node` loaded later - is seen
  without a reconnect); the resource group's DEFAULT toggle (spec 096 - a node-group concept) is offered only on a
  cluster node.

## Enforcement & security

Nothing is admitted or refused differently: the moved code is moved, not changed; the listing only stops naming
calls the node refuses anyway. `console_info` stays what each caller may see - `deployment` is a node fact an admin
of any kind may read (the same as the schema fields it already carries), `scopes` is the node's vocabulary, not a
grant.

## Tests

- `test/sql/platform_views.test` (or `platform_calls.test`): `console_info` carries `deployment` and `scopes`; on a
  standalone node a `cluster` holder's `my_functions` has no `cluster_*` write and `my_views` no `drift`, on a cluster
  node both are there.
- The whole gate unchanged (the moves are moves): `test/sql/*`, test-cpp, integration, test-flight, test-e2e.
- acl-clients: `ConsoleInfo` unit test for the new columns (an older node without them falls back to today's
  behaviour); the live tests against a standalone and a cluster dev node (`dev/node.sh`, `ACL_CLUSTER=1`).

## Alternatives considered

- **Leave the plugin's hardcoded scopes**: one plugin for both sides needs the node's vocabulary from the node.
- **Hide the profile's reads on a standalone node too**: they work there (a standalone node reads a shared profile
  it does not apply); hiding them would be a behaviour change for no gain.

## As built (2026-10-13)

- `src/acl_sql_text.{hpp,cpp}` holds `SqlNamesSource` (the cluster's DETACH and `platform.exposures` call it);
  `MetadataMaxRows()` is in `acl_policy.cpp`; `acl_platform_rights.cpp` no longer includes `acl_cluster.hpp`.
- `console_info` (`acl_platform.cpp`): `deployment` from `ClusterNode()`, `scopes` = `GrantableAdminScopes()`
  (`acl_policy.cpp`, the enum's order); on a standalone node `drift` leaves `my_views` and the
  `PlatformRight::INFRASTRUCTURE` functions (the four `cluster_*` writes) leave `my_functions`.
- Tests: `node_cluster.test` (both deployments: the columns, what is offered); the plugin's `ConsoleTest` (the
  columns, an older node's fallback) and `LiveOperateTest.theNodeSaysWhatItIs` / `LiveAccessControlTest`
  (Drift only on a cluster node), run against a standalone and a cluster dev node.
- Docs: `platform-catalog.md`.
