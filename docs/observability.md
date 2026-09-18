# Observability: the audit, the metrics and the execution profile

Three questions an operator asks about a node, and the signal that answers each:

| question | signal | where it comes from |
| --- | --- | --- |
| *what was decided* about a statement, and why | the **audit** (spec 069): one event per decision, refusal, session, ingest, door, policy and keys occurrence | the parser override, after the decision |
| *how much* of everything is happening | the **metrics** (spec 069): counters derived from the events, gauges the owners register | `acl_metrics()`, `GET /metrics` on the quack listener |
| *what then happened* when the statement ran, and where the time went | the **execution profile** (spec 074): one `profile` event per decided statement executed | a per-connection hook duckdb calls when the query ends |

All three are the operator's. No function hands any of it to a principal; the ring, the file sink and
the registered sinks (acl_otel) are the only readers. This page is about the third signal and how
it fits the first two; the audit and the metrics themselves are described in
[serving.md](serving.md#audit-and-metrics-spec-069).

## What a profile is

The base decides a statement, hands it to duckdb, and duckdb runs it. duckdb's own profiler measures
that run, per connection, and throws the measurement away when the query ends. The base keeps it:
a `ClientContextState` on every connection of the instance reads the profiler's tree in `QueryEnd`
once and emits one event, kind `profile`, through the same bounded audit pipeline as every other
event. Nothing on the decision path changes; the walk runs after the query, on the ending thread,
and a failure in it never fails the statement.

The event carries:

- `decision_seq` - the `seq` of the statement event whose execution this is. The two are one
  statement: the decision says what was allowed and what it cost to decide, the profile says what
  it cost to run.
- `exec_us` - wall time, the statement's begin to its end. The one interval duckdb measures.
- `cpu_us` - thread time summed over the operators. A scan on eight threads for one second is
  eight seconds here; the number may exceed the wall time and that is not a bug, it is what the
  number is.
- `rows_scanned`, `rows_out`, `bytes_read`, `bytes_written` - the statement's totals.
- `peak_memory` - the buffer pool's peak while the statement ran; `memory_allocated` - what it
  allocated in total; `blocked_us` - thread time spent blocked.
- `sources[]` - one entry per attached source the statement read, rolled up over its scans:
  `source` (the attached database the rewrite resolved the scan to: `pg`, `lake`, `memory`),
  `kind` (the scanner: `postgres_scan`, `ducklake_scan`, `table_scan`, `read_parquet`, ...),
  `scans`, `rows`, `rows_scanned`, `timing_us`, `bytes`, and the **shape of the pushdown**:
  `filters` (how many predicates the scanner took on itself), `projections` (how many columns),
  `dynamic_filters` (a join filter reached the scan). A file scan has no catalog: `source` is
  empty, `kind` says the format, `scans` counts the files.
- `plan[]` - the whole tree, preorder, each node with `id`, `parent`, `depth`, `type` (duckdb's
  operator type), the same numbers, and `peak_memory_observed` - the pool's peak seen while that
  operator ran, named so because it is not the operator's own allocation.
- `truncated` - the plan was cut at the base's limits (256 nodes, depth 32); the rollup is always
  over the whole tree.
- `error` - the execution failed; `detail` carries the error's **class** (`Conversion`, `Binder`,
  `IO`, ...), never its text.

How a scan is attributed to a source: duckdb's scanners write a table name into the profile, never
the attached database. The rewriter knows the database, because it resolved every virtual name to a
physical one before the statement ran; the profile matches the scanner's table name against the
tail of a physical name the rewrite resolved. No scanner-specific string is parsed.

### What never leaves

The rules of the audit hold (spec 069): no statement text, no literal, no path, no claim value, no
session handle. The profiler's `query.sql` is never read. The texts of `Filters`, `Projections`,
`Conditions` and `Aggregates` carry the literals of a row-level-security predicate and the claim
values baked into it, so they are **counted**, never quoted; `Filename(s)` carries presigned query
strings, so it is ignored. What is read: the operator type, the scanner's function name, the table
name for attribution only, the numbers. The tests pin it: an RLS predicate with a literal and
`acl_claim('tenant')` appears in no byte of any event.

### What duckdb does on a failure

An execution that fails still profiles: outcome, class, wall time, linked to its decision. Whether
the tree is there is duckdb's: in autocommit the rollback at the statement's end resets the profiler
before any hook runs, so the tree is gone; inside a transaction the client owns nothing is rolled
back there and the tree of the failed execution is in the event. A failure at bind - an allowed
statement duckdb then refused - has no tree either way, and is the one place the audit records that
the allowed statement did not run.

## Switching it on

Profiling costs the profiler's own bookkeeping per chunk, measured as noise on a 30M-row join and a
400M-row pipeline, and one event per statement into the bounded pipeline. It is off by default: a
node produces nothing nobody asked for.

The level in force for a statement is decided by whoever runs it, before it runs, first answer
wins:

1. **The operator's switch on the session** - `acl_session_profile(<ops id>, 'off' | 'sampled' |
   'all')` (`''` clears), or the management form `PROFILE SESSION CURRENT | '<ops id>' ON | ALL |
   SAMPLED | OFF` under an unrestricted `manage` scope. `CURRENT` is the session the statement runs
   under, so an administrator connected through a door switches their own session; another session
   is named by its ops id from `acl_sessions()`. In force from the session's next statement.
2. **A registered policy's rule** - `SessionPolicy::ProfileFor` (acl_otel answers it from its
   level rules, JSON or the central table, with a `profile` field beside `level`).
3. **The connection's own setting** - `SET SESSION acl_profile_level` on an operator's own
   connection (no session), which outranks the node's GLOBAL there. A principal cannot SET it.
4. **The node** - `SET GLOBAL acl_profile_level = 'off' | 'sampled' | 'all'`.

`sampled` profiles the statements whose trace context carries the sampled flag - the `TRACE ...
PARENT '<traceparent>'` markers every door composes, or the session's `acl_traceparent` - so the
caller's tracer decides, the OpenTelemetry way. `acl_sessions()` shows, per live session, the level
in force (`profile_level`) and which of the four decided it (`profile_source` = `override` /
`policy` / `instance`).

A statement nobody decided - the operator's own reads, a door's `BEGIN` - is never profiled, so
`acl_audit_events()` cannot feed itself and a gateway's unprefixed traffic costs nothing.

## Where it goes

- **The ring**: `acl_audit_events()` carries the profile's numbers as columns (`decision_seq`,
  `exec_us`, `cpu_us`, `rows_scanned`, `rows_out`, `bytes_read`, `bytes_written`, `peak_memory`,
  `memory_allocated`, `blocked_us`, `truncated`) and `sources` / `plan` as JSON columns; the
  `verdict` of a profile reads `ok` / `error`. NULL on every other kind.
- **The file sink** (`acl_audit_sink`): the event as it is, one JSON line, the profile fields
  present on `profile` records only.
- **The counters**: `acl.exec.statements{door,statement,result}`, `acl.exec.rows{source,kind}`,
  `acl.exec.time_us{source,kind}` - derived from the events, whatever the level records, with
  attribute sets bounded by the doors, the statement classes, the attached catalogs and the
  scanners.
- **acl_otel** (its spec 009): the execution span beside the decision span under the caller's
  request, linked to it; the sources and the operators as span events; a log record whose body is
  the profile whole; histograms per source. Its README says how.

### Reading the numbers honestly

- `exec_us` is the only interval. Operator times are thread time, cumulative, not intervals: two
  operators' times can add up to more than the statement's wall time, and a waterfall drawn from
  them would lie. acl_otel draws operator spans only when asked to, and labels them.
- `peak_memory` is the statement's; `peak_memory_observed` on a node is what the pool showed while
  that node ran, which includes everything else running then.
- "Which source is slow" is a question over nodes as well as over time: catalog names are the same
  across a fleet, so read the per-source numbers beside the node (`node` on every event; the
  resource in OTLP).

## Examples

```sql
-- the node profiles every decided statement
SET GLOBAL acl_profile_level = 'all';

-- the newest profile: how long, how many rows, and which source took the time
SELECT decision_seq, exec_us, cpu_us, rows_out, sources
FROM acl_audit_events() WHERE kind = 'profile' ORDER BY seq DESC LIMIT 1;

-- the decision it belongs to
SELECT p.exec_us, s.statement, s.objects, s.rewrite_us
FROM acl_audit_events() p JOIN acl_audit_events() s ON s.seq = p.decision_seq
WHERE p.kind = 'profile' ORDER BY p.seq DESC LIMIT 5;

-- one session, switched on by the operator, off again when done
SELECT acl_session_profile('62F31C2A7615', 'all');
SELECT acl_session_profile('62F31C2A7615', '');

-- the same, by an administrator connected through a door, for their own session
ACL SESSION 'h…' ACL PROFILE SESSION CURRENT ON;

-- the operator's own connection, without touching the node
SET SESSION acl_profile_level = 'all';
```
