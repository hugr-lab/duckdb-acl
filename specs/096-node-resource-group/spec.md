# Spec 096: a node's resource group - placement and the group's part of the profile

- **Status**: implemented (owner, 2026-10-01: Q1 and Q2 as proposed, Q3 - a default group)
- **Date**: 2026-10-01
- **Design**: design/017-hugr-platform §3.1a ("the node's resource group", the owner's proposal)
- **Follows**: spec 085 (resource groups bound to roles), spec 093 (the cluster profile, `IN GROUP`),
  spec 079 (the load report), spec 066 (drain)

## Summary

Spec 085's resource groups limit a role's *sessions*. This spec makes a group also a **set of nodes**:

- A node **belongs to at most one group**. The deployment says which, in the node's local part
  (`acl_node_group`); the policy catalog does not.
- **Placement**: `GRANT RESOURCE GROUP g TO ROLE r` now also means "sessions of `r` are served by the
  nodes of `g`". A node of `g` refuses a session whose principal does not hold `g`, with the reason
  `wrong_resource_group`, so a front can send the client to the right node. Enforcement stays on the
  node.
- **The group's part of the profile** is spec 093's items with `IN GROUP g`. A node applies the
  cluster's items and its own group's, never another group's - including the live apply on the node
  that writes the item, which today ignores the scope.
- **The default group** (`CREATE RESOURCE GROUP g … DEFAULT`): a principal that holds no group is a
  member of it. So once groups exist, the roles nobody bound still land somewhere - on the default
  group's nodes, with its limits.
- **The load report** says which group the node is in and which profile version it targets, so a
  front and an agent can route and converge without reading anything else.

**A single node needs none of this.** A node without `acl_node_group` serves every principal exactly
as before 096, and an installation that never creates a group never sees placement at all.

Nothing here distributes a query. A group is an isolation unit - Snowflake's warehouse, not a cluster
of shards.

## Problem

- Every node serves every role. A team that needs its workload isolated (a heavy ETL next to
  interactive dashboards) can only get that from a separate deployment with a separate catalog.
- Spec 093 already stores items `IN GROUP g`, but nothing says which nodes `g` is, so the scope only
  sorts rows. Worse, the node that writes `ACL CLUSTER ATTACH … IN GROUP g` (or `INSTALL EXTENSION …
  IN GROUP g`) applies it to itself whatever group it is in.
- A front that routes sessions has nothing to route by: it cannot tell which nodes serve a role, and a
  node that refuses gives no reason it could act on.

## Design

### 1. Membership: `acl_node_group`

```sql
SET GLOBAL acl_node_group = 'analytics-large';   -- in the node's bootstrap, from its environment
```

- **A GLOBAL setting**, default `''` (no group). It is part of the node's local configuration -
  where the deployment (Helm values, Bicep parameters) also puts the catalog pointer and the ports -
  because it is what the node needs before it can choose which part of the shared profile is its own.
  `SET` under a principal is refused as for every `acl_*` setting (spec 068).
- **It names a resource group** (spec 085). While the group does not exist in the policy catalog, the
  node serves nobody new: every session open is refused with `wrong_resource_group` ("this node's
  group g is not a resource group"). Failing closed is deliberate - a node that silently served
  everyone because its group was misspelled or dropped would defeat the isolation.
- **Changing it at runtime** takes effect for new sessions; sessions already open keep working, like
  a drain (spec 066). The node agent restarts a node to move it between groups anyway, since the
  group's settings are mostly restart class.
- **Memory mode and the function-driver source** have no groups (spec 085); a node there with a
  group set refuses sessions, saying the source has no resource groups.

### 2. Placement: who a node of `g` serves

Judged once, in `SessionOpenBody`, where spec 085 resolves the principal's groups - so every door
(Flight, quack, `acl_session_open`) applies it the same way:

A principal's groups are spec 085's - the groups bound to its roles - or, when that is none, the
default group (§2a) if there is one.

| node group | principal's groups | the session |
| --- | --- | --- |
| `''` (none) | any, or none | admitted, limits as in 085 (most generous across the principal's groups) |
| `g` | holds `g` (bound, or `g` is the default and it holds none) | admitted, **limits of `g` only** - the node serves it as a member of `g` |
| `g` | holds others, not `g` | refused: `wrong_resource_group`, naming the groups that would serve it |
| `g` | none, and no default group | refused: `wrong_resource_group` ("no resource group serves this principal") |

- **The refusal says where to go**, to the front and not the client: the session event carries
  `reason_code` `wrong_resource_group` and the principal's groups; the door answers the client
  `acl: this node serves resource group "g" - your roles are served by "h", "k"` (the group names
  are operator vocabulary, already shown by the load report - spec 085 says not to name them after
  anything secret). Flight answers `UNAVAILABLE` (a retry elsewhere is the right reaction, as for
  `draining`), quack refuses the connect.
- **Limits on a grouped node are the node group's.** A principal that also holds a more generous
  group is still served within `g` here: the group is the unit of capacity the operator sized the node
  for. `max_sessions` is charged to `g`.
- **The gateway path** (`ACL TOKEN` / `ACL ROLE` prefixes, no session) is not placed (owner, Q1): the
  gateway is the trusted router of its own traffic, and judging every statement would put a policy
  read on the hot path.
- **Administration is placed like any session** (owner, Q2): an operator's own principal holds the
  group of the nodes it administers (or the default group covers it), or administers through
  `ACL ADMIN` on the gateway path. `manage` and `passthrough` do not pass placement.

### 2a. The default group

```sql
CREATE [OR REPLACE] RESOURCE GROUP general [WITH] (max_sessions 200) DEFAULT [COMMENT '…'];
ALTER RESOURCE GROUP general SET DEFAULT | DROP DEFAULT;
```

- **At most one** group is the default. Marking a second one is refused, naming the current default
  (`ALTER RESOURCE GROUP old DROP DEFAULT` first) - silently moving every ungrouped principal is a
  change an operator makes on purpose.
- **A principal holding no group is its member** - for placement (§2) and for its session limits,
  on every node, grouped or not. A principal with groups is never a member of the default by
  implication; it is bound to it or it is not.
- **Without a default group**, an ungrouped principal is served by ungrouped nodes only.
- Dropping the default group leaves no default. `acl_resource_groups()` shows `is_default`.
- **Storage**: `resource_groups` gains `"is_default" BOOLEAN` - schema v18, `-- min_reader: 17`: a
  v17 build ignoring it has no placement at all, so it cannot admit more than it already did. The
  admin function `acl_create_resource_group(group, limits, comment[, is_default])` and a new
  `acl_alter_resource_group(group, 'default', 'true' | 'false')`.

### 3. The group's part of the profile

- **Which items a node takes**: the cluster's (`scope = ''`) and its group's (`scope = acl_node_group`).
  A group item overrides the cluster item of the same kind and name (a group's `memory_limit` beats
  the cluster's), which is the order the agent applies them in.
- **The live apply** (spec 093's `before_commit`) runs only when the item is in effect on the writing
  node: its scope is the node's own group, or the cluster's and the node's group has no item of that
  kind and name. Otherwise the write commits and answers `applied_here = false` with the note "item of
  resource group g - this node is in group h (or: in no group); the group's nodes roll it out", or
  "cluster item overridden by resource group h's own on this node - not applied here". Settings say it
  too, although a setting is restart class anywhere.
- **A group's source named like a cluster's** is a re-point on the group's nodes: written where the
  cluster's is attached, it answers drain class (the agent re-points through drain); detached, the
  cluster's comes back in effect there - re-pointed, never `DETACH`ed - and nothing that depends on
  that name has to go with it.
- **`DETACH` follows the scope.** An edge (`DEPENDS ON`) belongs to its dependent's scope and names a
  source of that scope, else the cluster's: a group's item depends on the cluster's source of a name
  only while the group has none of its own, a cluster item never on a group's. The dependents found,
  the edges deleted and the `CASCADE` walk are of those items only; on this node only what is in
  effect here is detached (a cascade from a cluster source this node's group overrides still detaches
  the cluster's dependents that are in effect here). The walk runs to a fixpoint: a group's source that
  fell back to the cluster's of its name stops falling back once the cascade reaches the cluster's.
- **A group with profile items is not dropped** (`DROP RESOURCE GROUP g` names them): its items are its
  nodes' bootstrap, and orphaned they would be a scope nothing can write to, revived by any later
  group of the same name.
- **`acl_cluster_items([scope])`** keeps listing what is stored; a new `acl_cluster_effective()` lists
  what applies to *this* node - the cluster's items with its group's overrides folded in, one row per
  kind and name, with the scope each came from, in the profile's order (settings, extensions, sources;
  a group's own item sorts by its kind, not after the cluster's). It is what the node agent diffs the
  node against.

### 4. What the node reports

`acl_node_load()` (and `/.well-known/acl-node`, the Flight `node-load` payload, behind
`acl_metrics_endpoint` as today) gains:

```json
{"group": "analytics-large", "group_known": true,
 "config": {"target": 42, "applied": 41}, …}
```

- `group` is `acl_node_group` (`null` without one); `group_known` whether the catalog has it.
- `config.target` is the catalog's `config_version` (spec 093). `config.applied` is what the node
  agent last reported with `acl_cluster_applied(version)` - acl does not converge a node, the agent
  (`hugr_node`, design/017) does, and says so through this call. A node is ready for traffic when the
  two match; the readiness probe reads the report.
- `admit.new_session` turns false while `group_known` is false.
- What the report reads from the catalog (`group_known`, `config.target`) is cached for 2 s - the
  endpoint is unauthenticated and polled - and dropped at once by a write this node commits; the
  catalog is judged first (spec 094), so a node outside the schema window reports neither.
- `acl_cluster_applied(version)` is the operator's (denied to a principal, like every `acl_*`); a
  version above the target is refused.

### 5. What a front reads

The front routes a principal to a node of one of its groups. It needs the role → group mapping:
`acl_role_resource_groups()` on any node (a read of the catalog, the operator's surface), or the table
itself. It holds no policy of its own; the node's refusal (§2) is the backstop when its copy is stale.

## Enforcement & security

- **The node decides.** A front that routes wrongly gets a refusal, never a session in the wrong
  group; the check is in `SessionOpenBody`, the one seam every door crosses.
- **Fail closed on a group the catalog does not know** - a typo or a dropped group stops new sessions
  instead of opening the node to everyone.
- **Placement changes where, never what.** A group grants no data access and no capability; the
  rewriter and the gate never see it.
- **The membership is the deployment's.** No SQL a principal can write sets it; the catalog cannot set
  it either, so a catalog write cannot move a node between groups.
- **A refusal names groups**, which the load report already shows to its readers; nothing else about
  the principal is in the door's answer.

## Known limitations

- **Two defaults under a race on a READ COMMITTED backend.** "At most one default" is checked inside the
  write's transaction, and the version bump serializes writers on duckdb and on postgres (the scanner
  runs REPEATABLE READ); MySQL / SQL Server under read committed could commit two concurrent `SET
  DEFAULT`s on different groups - the same exposure every check-then-write path of the catalog has.
  Placement then takes the first by name; `acl_resource_groups()` shows both.
- **A Flight session swap is not undone.** A client that presents a new token on a durable session
  (spec 050) has the old one closed before the new one is opened; if placement refuses the new one,
  the client has neither and retries elsewhere - which is what `UNAVAILABLE` tells it to do.
- **Mid-rollout limits.** A v17 build reads a v18 catalog (the window) but knows no default group: it
  serves ungrouped principals without the default group's limits, while v18 nodes apply them. A v17
  build cannot be set to a group either (it has no `acl_node_group`), so it never misplaces anyone.
- **The `DEPENDS ON` cycle check reads every scope's edges by name.** It cannot miss a cycle (the union
  of names is a superset of every node's graph) but refuses some that no node could have - g's `a`
  on `b` while h's `b` is on `a`. Fails safe; scope it when someone needs that shape.
- **The load report reads the backend as every reader does** - without the store's lock, so
  `acl_use_db` / `acl_use_functions` belong to the bootstrap, as they always have; a switch drops the
  report's cache.
- **Session opens read the catalog once** (all groups, the principal's bindings, the default, the node's
  own group, in one query), uncached like the rest of spec 085's resolution: an open is once per
  connection, not per statement.

## Testing

- **`test/sql/acl_node_group.test`** (sessions through `acl_session_open`):
  - memory mode with a group refuses; without one serves;
  - an ungrouped node serves every principal, and the report says `"group":null,"group_known":true`;
  - a node of `interactive`: its member admitted; a member of `etl` refused naming `"etl"`; an
    ungrouped principal refused (no default) - both as `wrong_resource_group` session events with the
    sentence; a principal in both groups admitted and charged to `interactive`, not the more generous
    `etl`;
  - the default group: marked, a second refused naming the first; an ungrouped principal refused on
    `interactive`'s node, admitted and charged on `general`'s; a principal with a group is not a
    default member by implication; a re-create keeps the mark, `DROP DEFAULT` removes it;
  - an unknown node group refuses everyone, `group_known` false and `admit.new_session` false;
  - `SET` without GLOBAL refused; `SET GLOBAL` under a principal refused;
  - the profile: an `IN GROUP etl` source written from an `interactive` node is not attached here
    (the note), one of `interactive` is; `acl_cluster_effective()` folds the group's `threads` over
    the cluster's; `acl_cluster_applied` and the report's `config`; a version past the target refused;
    the function denied to a principal;
  - a setting of another group answers the note; `acl_cluster_effective()` in kind order (a group-only
    setting before the cluster's source);
  - a group's source over the cluster's: drain class where the cluster's is attached; detached, the
    cluster's is re-pointed (both still attached); `DETACH` of the cluster's refused by its own
    dependent; `CASCADE` removes the cluster's dependent and another group's (`src3 (group etl)`),
    detaches only the cluster's dependent on this node, deletes their edges;
  - the quack door: `acl_quack_authenticate` refuses a principal of another group with the sentence and
    admits the group's own;
  - `DETACH`'s scope rules: a group edge over its own source of the name is no dependent of the
    cluster's; a group source without fallback is refused by its group's dependent, cascaded with it;
    a cascade to a fixpoint (etl's `a` stops falling back when the cluster's `a` goes, and etl's `c` on
    it goes too); `DROP RESOURCE GROUP` refused while the group has items, naming them;
  - grammar and functions: `ALTER RESOURCE GROUP` without `DEFAULT`, on a missing group, a duplicate
    `DEFAULT`, a bad property, a bad `is_default`, a name in another case.
- **`test/cpp/test_acl_placement.cpp`**: every row of §2's table against `Place()`.
- **`test/e2e/flight/run.sh`**: a node joined to a group the token's roles are not in answers
  `UNAVAILABLE` with the sentence; back without a group, it serves again.
- `wrong_resource_group` is in the `Reason` enum and spec 069's taxonomy (acl-otel takes reason codes
  from it).
- `acl_resource_groups.test` (the listing's `is_default`), `acl_schema_window.test` (build 18, window
  19/18, migration 16 → 18), `make schema-check`.

## Alternatives considered

- **Membership in the catalog** (`ACL CLUSTER ASSIGN NODE n TO GROUP g`). Rejected: a node must know
  its group before it can choose its part of the profile, a catalog write could move a node, and the
  node would need a stable identity the catalog trusts - the deployment already has both.
- **A node in several groups.** Rejected for now: the group is the unit the node is sized for, and
  two groups' settings conflict. A front spreads a role over several groups' nodes instead.
- **Placement in the front only.** Rejected: the front is a router, not an enforcer (design/017), and
  a stale or bypassed front would put a team's load on another team's nodes.
- **Placing the gateway path too.** Rejected (owner): a per-statement read for a router that is
  trusted by the deployment invariant.
- **Refusing ungrouped principals on every grouped node.** Rejected (owner): an installation that
  adds groups for some teams must not have to bind every other role; the default group serves them.
