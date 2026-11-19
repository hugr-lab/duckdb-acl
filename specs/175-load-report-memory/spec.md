# Spec 175: the load report's memory, its critical level, and the node's idle time

- **Status**: implemented
- **Date**: 2026-11-19
- **Author**: the owner (hugr-platform spec 011, autoscaling - 2026-11-16 / 2026-11-18; working memory 2026-11-19)

## Summary

`acl_node_load()` (spec 079) gains what hugr-platform's autoscaler (its spec 011) decides with: the node's memory in
its two parts - RAM and the spill - against their limits, a critical level past which the report admits no new work,
and since when the node has had no live session.

## Problem

The load report counted seats and stream budget only. CPU is no signal (duckdb takes every thread it is given), so
an orchestrator had no way to see that a node is short of memory - neither of RAM, nor of the temp directory a query
spills to, whose own limit fails a query with RAM to spare (and past the volume's `sizeLimit` the kubelet evicts the
pod with every session on it). Nor could it tell an idle node from a busy one to stop it.

## Design

- **`memory`**: `used` = `BufferManager::GetUsedMemory()`, `limit` = `GetMaxMemory()` (`memory_limit`), `temp_used` =
  `GetUsedSwap()`, `temp_limit` = `GetMaxSwap()`, and `critical`. A limit is `null` when there is none: duckdb keeps
  `-1` (and a disk it could not size) as the largest index less one - read as a number it is a size no consumer can
  hold (`platform.node_load` showed -1 / -2, the review) - and `temp_limit` is `null` too until duckdb opens its temp
  directory (nothing spilled). No limit, no share: never critical by it.
- **Working memory** (the owner, 2026-11-19): `working` = `used` less the memory tags `BASE_TABLE`,
  `EXTERNAL_FILE_CACHE` and `OBJECT_CACHE` (`GetMemoryUsageInfo`; the object cache - parquet metadata, a lake's
  snapshots - is the pool's first to evict, the review) - the cache duckdb drops whenever it needs room. Measured: after one
  scan of a 2M-row persistent table the node reported 60 MB used with nothing running and 40 KB working; a read-heavy
  node would sit at its limit for good. An in-memory table (`IN_MEMORY_TABLE`: a session's temp, staging) is working
  memory - it leaves RAM only for the spill, which `temp_used` counts. So a node whose temp tables fill its RAM stays
  critical with nothing running until they go: the front seats elsewhere, which is the point.
- **The critical level** (the owner, 2026-11-18): `acl_node_admit_memory` (GLOBAL DOUBLE, 0.95; 0 = never; outside
  0..1, NaN included, refused where set). Past that
  share of `limit` by `working`, or of `temp_limit` by `temp_used`, `critical` is true and `admit.new_session`,
  `admit.new_quack_client` and `admit.new_stream` are false: the front seats a new client on another node of the group,
  the running queries keep what is left. The report only says it - `SessionOpen` does not refuse (a node with no front
  keeps serving; spec 011's front and autoscaler act on it).
- **`sessions.idle_since`**: `null` while a session is live (the calling call's own per-call session left out, as the
  counts do); otherwise the latest of the store's `sessions_quiet_since` (its creation, then every session's end -
  `SessionClosed`, every removal's seam - a record swept as idle or expired stamps its `last_used`, not the sweep's
  moment: a sweep is no activity, the review) and the `last_used` of a record not yet swept (`SessionTally::last_used`),
  in unix seconds. An autoscaler stops a node idle past its group's `idle`. Known: a reader's own cookie-less session is
  left out of `live` but its end is a session's end - an observer that polls by SQL (the console's `platform.node_load`
  over Flight) keeps moving `idle_since`; the console should read the report through the Flight Handshake / the
  well-known route, which open no session (a hugr-platform follow-up).
- `platform.node_load` gains `sessions_idle_since` (TIMESTAMP), `memory_used`, `memory_working`, `memory_limit`,
  `temp_used`, `temp_limit`, `memory_critical`.

## Enforcement & security

Read-only numbers behind the same gates as the rest of the report (spec 097's `observe`, `acl_metrics_endpoint`). No
statement text, no names - sizes and a time. Nothing is refused by them on the node.

## Tests

`test/sql/acl_node_load_memory.test`: `idle_since` set with no session, `null` with one, later after its close, a
record swept as idle stamped before the sweep (fails without the fix); the setting refused outside 0..1; no limit
reads `null`, never critical;
the memory fields; a persistent table read leaves `used` well above `working`; an in-memory table larger than a
100 MB limit spills (`temp_used` > 0, `temp_limit` = `max_temp_directory_size`); `acl_node_admit_memory` 0.01 -
critical, no new session or stream; 0 - admitted; the default 0.95 - critical by RAM (the in-memory table fills it)
with the spill far below. `platform_views.test`: the view's new columns.

## Alternatives considered

- **`used` as is** (spec 011 as first written): a node that read a lot is critical with nothing running.
- **Only the spill for the critical level**: misses a node whose working memory is pinned by running queries.
- **Refusing new sessions at the node**: spec 011 leaves seating to the front; a single node without one would
  refuse its own clients.
