# Spec 085: resource groups - named limits bound to roles

- **Status**: implemented
- **Date**: 2026-09-24
- **Design**: `design/076-node-capacity/DESIGN.md` §3.4 and §7 (P3). The owner took decisions 1-4 on
  2026-09-24.
- **Follows**: specs 077 (the fetch window), 079 (seats), 080 (the stream budget), 070 (the Flight
  row cap)

## Problem

The door's stream limits are the node's alone: the fetch window, the batch target, the stream-budget
line and the Flight row cap. An ETL role that needs wide windows and big batches, and an interactive
role that should get small first answers and a row cap, share one setting. An orchestrator also has no
per-tenant session limit to route by.

## Design

**A group** is named and bound to roles. It may state any of six limits:

- `window_start`
- `window_max`
- `batch_bytes`
- `max_result_rows`
- `queue_priority`
- `max_sessions`

A limit it does not state (NULL) is the node's setting.

- **Storage.** Two tables, `resource_groups` and `role_resource_groups`, make schema v15. The
  migration is `schema/migrations/v15.sql`, and the check is `make schema-check`. Memory mode and the
  function-driver source have no groups.
- **Surface.**
  - Statements: `CREATE [OR REPLACE] RESOURCE GROUP g [WITH] (limit value, …) [COMMENT …]`,
    `DROP RESOURCE GROUP [IF EXISTS] g`, `GRANT | REVOKE RESOURCE GROUP g TO | FROM ROLE r`.
  - Admin functions: `acl_create_resource_group`, `acl_drop_resource_group`,
    `acl_grant_resource_group`, `acl_revoke_resource_group`. They need an unrestricted `manage`.
  - Listings: `acl_resource_groups()` and `acl_role_resource_groups()`.
  - A limit name outside the six is refused, because a misspelled limit would limit nothing. A
    negative value is refused except for `queue_priority`, and so is `window_start > window_max`.
  - `batch_bytes` takes a size such as `'32MiB'`.
  - Dropping a group or a role removes its bindings.
- **Resolution** (`ResolveResourceLimits`) runs once, in `SessionOpenBody`, before the lock. The
  result is kept on the session record (`ResourceLimits`), and a statement never looks it up again.
  - **Decision 1:** each limit takes the most generous value across the principal's groups. Where 0
    means unlimited or off, 0 wins; otherwise the largest wins.
  - `max_sessions` is charged to the one group that allows the most. A group that states none leaves
    the session uncharged.
- **Node capacity** (decision 2). A group may exceed the node's settings, but not the node's capacity
  bounds: `acl_node_stream_budget`, the seats and `acl_max_sessions`.
- **`max_sessions`** (decision 3) is checked in the same critical section as `acl_max_sessions`. A
  session over it is refused with `at_capacity`, and no existing session is ended.
- **quack.**
  - `AclQuackStatementStarting` puts the session's limits on the server connection
    (`AclQuackSessionLimits`, a ClientContextState). It sets the connection's session-scoped
    `acl_quack_target_batch_bytes`, or clears it when no group names one. The connection is the
    door's, and a client cannot SET there (spec 068).
  - `AclQuackFetchWindowFor` reads the window from that state.
  - `AclQuackStreamSlot` prices the reservation with the group's window and batch, and passes the
    priority.
- **The queue** (decision 4). `StreamBudget` orders its line by priority, then by arrival. A waiting
  statement gains one level per `age_step` (5 s), so no priority waits past the 25 s timeout because
  of priority alone. The single queue with ticket skipping is gone: the line is the waiters
  themselves.
- **Flight.** The reader's cap is `MaxResultRowsFor(handle)`.
- **Reported in:**
  - the load report, as `sessions.by_group` (`{group: {live, max}}`, charged sessions only);
  - `acl_sessions()`, as `groups` and `charged_group`.

## Enforcement & security

- **Only the operator sets a limit.** A principal names no group and cannot SET the batch on the
  door's connection. The listings and the admin functions are `acl_*`, which is the never set under a
  principal.
- **Groups change the shape of streams, never access.** No limit reaches the rewriter or the gate.
- **The load report names the groups** (`by_group`) to whoever may read it (`acl_metrics_endpoint`).
  So a group should not be named after anything secret. The docs say so.

## Tests

- **`test/sql/acl_resource_groups.test`**
  - the statements and functions, and the listings;
  - every validation;
  - the unrestricted-manage gate;
  - `max_sessions` refused at open while the first session keeps working;
  - `by_group` in the load report, and `groups` / `charged_group` in `acl_sessions()`;
  - the most generous merge: a second group that limits no sessions uncharges the principal;
  - drop cascades, from a group and from a role.
- **`test/sql/integration/acl_quack_resource_groups.test`**
  - a group's `window_start 0` gives its sessions quack's own FETCH count against the node's fixed
    window of 2;
  - its `batch_bytes` is the door connection's batch while the node's own connection keeps 16384;
  - without the connection hook the test fails (checked).
- **`test/cpp/test_acl_stream_budget.cpp`**
  - a later, higher priority is served first;
  - a long waiter ages past a fresh higher priority.
- **`test/e2e/flight/stream.sh`**: a group's `max_result_rows 500` hands out exactly 500 rows, then the
  refusal, and the audit records `stream_capped,500`.

## Follow-ups

- **acl-otel's `SessionPolicy` answering a group per session** (a token claim → group). This is a
  change to `acl_audit.hpp`, so a contract bump.
- **P2, the server-announced read-ahead** (duckdb-quack #277). After it, a group's `window_max` becomes
  the seat reservation too.
