# Spec 074: the execution profile - what went to which source, and what it cost

- **Status**: implemented (slice 1: the base, contract v2)
- **Date**: 2026-09-18
- **Author**: hugr lab

## Summary

The audit (spec 069) says what was *decided* about a statement; nothing says what then *happened*:
how long it ran, how many rows each attached source produced, how much of the work the scanners
took on themselves (pushdown), what memory it peaked at. duckdb measures all of that in its own
profiler, per connection, and throws it away with the connection. This spec turns it into one more
audit event, `profile`, emitted when the statement's execution ends - off by default, sampled or
full per node, per session (a follow-up slice) and per statement (the caller's trace flag) - and
shipped like every other event: the ring, the file, the counters, and through acl_otel (spec 009
there) as an execution span, span events per operator, a log record with the plan tree, and
histograms per source. Cost: measured as noise. Content: numbers and structure, never the
statement's text, a literal, a path or a claim value.

## Problem

- **A slow request, and no way to say whose fault.** The decision span (acl_otel spec 008) shows
  the gate took 0.3 ms; the request took 4 s; between them nothing. An operator wants: 3.7 s in
  `postgres_scan` of `pg.public.payroll`, 2 filters pushed, 12M rows scanned, 40k returned.
- **A fleet of nodes with the same catalogs.** "Which source is slow" is a question over time and
  over nodes: catalog names are identical fleet-wide (the owner's rule), so per-source metrics
  must carry the node.
- **The contract said it could not be done.** `specs/069-audit/extension-requirements.md` §3 lists
  traces per statement as a non-requirement "because the base has no execution hook". That was
  true of `parser_override` and false of `ClientContextState`: duckdb calls a registered state's
  `QueryEnd(context, error)` from `EndQueryInternal`, *after* `profiler->EndQuery()`, for every
  statement - including a streamed one, at its end (`CleanupInternal`), and a prepared one, per
  execution.

## Design

### What duckdb gives (measured 2026-09-17 at 09ba309, re-read at the 62ee922 pin)

- **The profiler is per connection.** `ClientConfig::enable_profiler`, `profiler_print_format`
  (`no_output` renders nothing) and `profiling_coverage` (`SELECT` by default - DML would be
  skipped - so `ALL`) are session-local. `QueryProfiler::StartQuery` returns early unless enabled,
  and is called at parse: profiling is decided **before** a statement, per connection - by a door
  around `Query()`, never by the override for the statement it is rewriting.
- **Metrics are string-keyed, by group** (`GatheredMetrics`, `tracked_metrics` globs): query-level
  `query.total_time` (wall), `query.cpu_time` (sum of operator thread time), rows scanned, bytes
  read/written, `system.peak_buffer_memory`, `system.total_memory_allocated`,
  `system.blocked_thread_time`, the parser/planner/optimizer phases - and `query.sql`, which is
  never read. Per operator: cumulative thread `time`, `elements_returned` (cardinality),
  `rows_scanned`, `intermediate_size_bytes`, the node's peak buffer-manager memory **observed
  while the operator ran**, and `extra_info` (a string map).
- **Who the source is, is in `extra_info`.** A local table scan writes `Table: memory.main.t`;
  parquet/csv write `Function` and `Filename(s)`; `postgres_scan`, `mysql_scan`, ducklake write
  `Table: <table_name>`. `Projections`, `Filters` and `Dynamic Filters` are written by
  `PhysicalTableScan::ParamsToString` for **every** table function with `filter_pushdown` - so the
  pushdown's shape is visible for remote scanners, not only for parquet. Which attached catalog a
  scan hit, no scanner writes - but the rewriter knows: it resolved `phys` (`pg.public.payroll`) for
  every object the statement touched. Attribution is `Table` from the profile matched against the
  tail of a physical name the rewrite resolved - never a parse of scanner-specific strings.
- **Operators have no wall intervals.** Chunks of one operator run interleaved on many threads;
  the profiler sums time, it keeps no begin/end. `OnTaskStart/Stop` carry no operator id. The only
  measured interval is the statement's - which fixes what a trace may honestly show (§ acl_otel).
- **Cost** (release, this machine): a 30M×1K join with LIKE and an aggregate, 13-17 ms off vs
  14-15 ms with `no_output`; a 400M-row pipeline, 7.50-7.62 s vs 7.52-7.61 s. Noise. Per chunk a
  timer and two buffer-pool reads; the tree is built once per statement, O(operators), never
  rendered. Our addition: one tree walk and one `AuditPipeline::Emit` on the ending thread -
  microseconds; the pipeline's queue is bounded and drained on its own thread (spec 069).
  Selectivity is for the telemetry volume on the way out, not the node's CPU - and the default
  stays `off` (the owner's decision): a node produces nothing nobody asked for.

### The event: kind `profile`

One event per executed statement (success or error), emitted from `QueryEnd`. A statement that
failed carries its outcome, the error's class and the wall time; whether it also carries the tree
is duckdb's: in autocommit the rollback at the statement's end resets the profiler
(`TransactionContext::Rollback`, before any state hook), so the tree is gone - inside a
transaction the client owns, nothing is rolled back there and the tree of the failed execution is
in the event. A failure at bind (an allowed statement duckdb then refused) has no tree either
way, and is the one place the audit records that the allowed statement did not run.

| field | meaning |
| --- | --- |
| `ts_us, seq, node, door, session, correlation_id, traceparent` | as on every event (spec 069) |
| `decision_seq` | `seq` of the statement event whose execution this is (§ correlation); -1 when unknown |
| `statement` | the class, as on the decision event |
| `error` | `true` when the execution failed; the error's class rides in `detail`, never its text (as ingest does) |
| `exec_us` | `query.total_time` - the one wall interval duckdb measures |
| `cpu_us` | `query.cpu_time` - thread time summed over operators; may exceed `exec_us` |
| `rows_scanned`, `rows_out`, `bytes_read`, `bytes_written` | query-level |
| `peak_memory`, `memory_allocated`, `blocked_us` | `system.peak_buffer_memory`, `system.total_memory_allocated`, `system.blocked_thread_time` |
| `sources[]` | the rollup per source: `{source, kind, scans, rows, rows_scanned, timing_us, bytes, filters, projections, dynamic_filters}` |
| `plan[]` | the whole tree (the owner's decision), preorder: `{id, parent, depth, type, kind, source, rows, rows_scanned, timing_us, bytes, peak_memory_observed, filters, projections, dynamic_filters}` |
| `truncated` | `plan` was cut at a limit |

- `source` is the **database** of the physical name the rewriter resolved for the scan (`pg`,
  `lake`, `memory`); `kind` is the scanner (`postgres_scan`, `ducklake_scan`, `table_scan`, `parquet_scan`,
  `read_csv`, ...). File scans have no catalog: `source` is empty, `kind` says the format and `scans`
  counts the files read. `sources[]` is what the owner asked for and it is small: bounded by the
  number of attached catalogs plus the file formats.
- **The pushdown's shape, never its text** (the owner's decision): `filters` = the number of
  conjuncts in `Filters` (split on ` AND ` at bracket depth zero), `projections` = the number of
  names in `Projections`, `dynamic_filters` = whether `Dynamic Filters` is present (a join filter
  reached the source). For a remote source that is "what went there": how many predicates and
  columns the scanner took, against what was pulled here.
- `plan[]` carries `id`/`parent` so a consumer rebuilds the tree without nesting in the contract.
  Limits are constants: ≤ 256 nodes, depth ≤ 32, strings ≤ 128 bytes; past them `truncated = true`
  and the tail is dropped - `sources[]` is rolled up over the **full** tree before the cut.
- **What never leaves** (spec 069's rules hold): `query.sql`; from `extra_info` the texts of
  `Filters`, `Dynamic Filters`, `Conditions`, `Aggregates`, `Projections` (their literals are RLS
  constants and claim values), `Filename(s)` (paths carry presigned query strings). What is read:
  `Function`, `Table` (attribution only; the event carries `source`), `Type`, `Join Type`,
  `Total Files Read`.
- Memory is labelled honestly: query-level peaks are the statement's; an operator's
  `peak_memory_observed` is the node's pool peak seen while it ran, and is named so. Operator time
  is cumulative thread time and is named so.

### Correlation with the decision

The statement event is emitted after the rewrite, before execution; `profile` after. They meet
on `decision_seq`:

- **Gateway prefix, quack**: parse and execution are one `Query()` on one thread. The override
  leaves one thread-local note per decided statement `{seq, the hash of the statement's text,
  statement class, objects, resolved physical names}` (the `Reason` note's mechanism); the first
  `QueryBegin` after the parse - the batch's first statement, on the connection that parsed it,
  before anything it runs on another connection of the thread - takes the whole queue onto the
  connection. Each statement then takes the queue's front note **only if the text matches**
  (`SQLStatement::query`, what duckdb reports as the current query): a follow-up the rewrite
  appended, a nested query, another connection's statement take none. `AuditPipeline::Emit`
  (acl-internal) returns the `seq` it assigned, so the override can note it.
- **A statement nobody decided has no profile**: the gateway's own reads (`acl_audit_events()`
  itself - which would otherwise profile its own reading), a door's `BEGIN`. The override marks an
  unprefixed parse with a boundary note, so a note kept on the connection cannot outlive it.
- **Prepared, then executed** (Flight's reservation; a gateway's `Prepare` + `Execute`): the
  PREPARE's own tree is skipped and its note **kept** on the connection; an execution takes it when
  its text is the prepared one (an EXECUTE reports the prepared text) - every execution of the
  prepared statement is linked to the one decision, and a statement of another text drops it. The
  Flight door takes the note into the reservation after the Prepare and gives it back before each
  execution, so another Prepare on the same session cannot replace it in between.

### Switching it on: three layers, as the audit has

| layer | knob | who decides |
| --- | --- | --- |
| node | `acl_profile_level` = **`off`** (default) \| `sampled` \| `all` (GLOBAL) | the operator |
| session | `SessionPolicy::ProfileFor(principal, door, out)` - the spec 069 hook, extended (acl_otel specs 004/007: rules per role, per door); ops: a column in `acl_sessions()`, `acl_session_profile(id, on\|off)` | rules / the operator (slice 3) |
| statement | `sampled` = the sampled flag of the caller's `traceparent` - already on every statement (`TRACE ... PARENT` from the doors, Flight's headers, `acl_traceparent` on a session) | the caller, the OTel way |

The mechanism is one (`ProfileConnectionFor`): `enable_profiler = true`, `profiler_print_format =
'no_output'`, `profiling_coverage = ALL` on the connection, switched off again only by the one who
switched it on - a connection whose client or gateway enabled profiling itself is left alone, both
ways. A door decides before each execution it runs (Flight before an execute, quack's driver
before it submits). On the gateway path the state's own `QueryBegin` decides, per decided
statement, from the level and the note's trace: duckdb starts the profiler at plan, after
`QueryBegin`, so the decision is in time for the statement itself. acl_otel's sampler (spec 005)
applies to `profile` as to the decision: sampled together, by one `decision_seq`.

### Where it goes

- **The base** (no acl_otel): the ring `acl_audit_events()` gains `decision_seq`, `exec_us`,
  `cpu_us`, `rows_scanned`, `rows_out`, `bytes_read`, `bytes_written`, `peak_memory`,
  `memory_allocated`, `blocked_us`, `truncated`, and two JSON columns `sources`, `plan` (the ring
  keeps the event whole; the limits above keep it small). The file sink writes the event as it is.
  Counters derived from events: `acl.exec.statements{door,statement,result}`,
  `acl.exec.rows{source,kind}`, `acl.exec.time_us{source,kind}` - attribute sets bounded by the
  attached catalogs and the scanners. The ring's `verdict` reads `ok` / `error` for a profile. No histograms in the
  base (spec 003 is acl_otel's).
- **acl_otel spec 009** (the owner accepted this shape, 2026-09-17): the **execution span**
  `[ts_us - exec_us, ts_us]` - both ends measured - linked (an OTel span link, not only an
  attribute) to the decision span through `decision_seq`, with `acl.exec.*` attributes and the
  error class; **span events** per operator (`sources[]` and `plan[]`; the event's time is the
  moment the profile was collected, which is true; TraceQL finds `event.acl.source = "pg"`); a
  **log record** with the tree as a nested body - the one signal where a tree stays a tree; and
  **histograms** `acl.exec.duration{node,door,statement}`,
  `acl.exec.source.duration{node,kind,source}`, `acl.exec.source.rows{node,kind,source}`,
  `acl.exec.source.pushdown_filters{node,kind,source}`, `acl.exec.peak_memory{node}` - `node` on
  every per-source series, because catalog names are the same across the fleet and a slow node is
  a particular node. Child spans per operator are **opt-in only** (`acl_otel_profile_spans`),
  labelled `acl.timing_kind = cumulative_thread_time`: a scan on 8 threads is 8 s under a 1 s
  statement, and a waterfall reader reads intervals we do not have. The condition for revisiting
  is duckdb measuring per-operator (or per-pipeline) wall intervals.

### The contract

`acl_audit.hpp` gains the `profile` fields and the `profile` kind → `AuditHooks::CONTRACT_VERSION`
1 → 2; acl_otel bumps the same day (the CLAUDE.md rule). A registry from another revision is refused
on both sides, as today.

## Enforcement & security

- The profile is the operator's. No function hands it to a principal (`acl_audit_events()` is
  denied already); the profile shows only in the ring, the file, the sinks.
- No statement text, no literal, no path, no claim value (§ the event). Test: an RLS predicate
  with a literal and `acl_claim('tenant')` - neither string appears in any byte of the event; the
  counts of filters and projections carry no names.
- The size limits are constants; the tree walk in `QueryEnd` runs in try/catch: a failure there
  never fails the statement and never loses the decision event.
- `enable_profiler` / `profiling_coverage` are set only on connections a door owns; a client's or a
  gateway's own settings are never overwritten, in either direction.
- Nothing here changes a decision: the profile is emitted after the fact, off the decision path,
  through the same bounded pipeline.
- A principal cannot switch the profiler (`SET enable_profiling` is refused under a principal,
  spec 068) and cannot read a profile. Under `sampled` a client that marks every trace sampled
  has every statement of its own profiled: the cost is the profiler's (measured above, noise) and
  one event per statement into the bounded queue - what the operator chose over `off`.
- A statement nobody decided is never profiled, so the ring's own reads (`acl_audit_events()`)
  cannot feed themselves, and a gateway's unprefixed traffic costs nothing.

## Testing

`test/sql/acl_profile.test` (memory mode, an attached `pg` catalog under RLS joined to a local
table):

1. `off` emits nothing; `all` emits one `profile` per decided statement, `decision_seq` = the
   statement event's `seq`, `rows_out` the top operator's rows, `sources` = the attached database
   the rewrite resolved (`pg`) and the local one, `plan` a tree (one root, `HASH_JOIN` in it, not
   truncated), the pushdown counted (`filters`: the RLS predicate on `pg`, the WHERE on `memory`;
   `dynamic_filters` where the join filter reached the scan).
2. Redaction: the claim value, the predicate's column name and the WHERE's literal appear in no
   byte of `sources` or `plan`.
3. Failures: a run-time error (autocommit: outcome, class, wall time, no tree - duckdb's reset at
   rollback), a bind error (allowed, then refused by duckdb: no tree), a run-time error inside a
   client-owned transaction (the tree, with its scans); never the error's text.
4. A batch: one profile per statement, each linked to its own decision, in order.
5. A statement nobody decided (the gateway's own read) leaves no event.
6. `sampled`: of three statements only the one whose `traceparent` has the sampled flag profiles,
   and it carries its trace.
7. Truncation: a UNION ALL of 300 scans → `truncated`, `plan` ≤ 256 nodes, `sources` counts all
   300 scans.
8. The level is validated where it is set.

Flight e2e (`stream.sh`): a consumed stream's profile arrives when the stream ends, under
`door = flight`, linked to its decision, with `rows_out` = the rows sent. `acl_session_profile`
(slice 3) and the cost note above (numbers) are not tests.

## Alternatives considered

- **Parse the scanners' strings for the source** - `Table`, `Filename(s)` - rejected: every scanner
  writes its own, none writes the attached database, and the rewriter already knows the physical
  name it resolved.
- **A JSON attribute with the tree on the span** - rejected for the tree as span events plus a log
  record: the attribute offers neither search nor aggregation.
- **Child spans per operator by default** - rejected: cumulative thread time is not an interval;
  a span that reads as one lies where people read latency (spec 008's own rule). Opt-in, labelled.
- **Profiling toggled by the override for the current statement** - impossible: `StartQuery` is
  gated at parse. Per connection, by the door, is the only place.
- **Sampling in the base** - rejected: acl_otel already owns sampling and rules (specs 005, 007);
  the base offers the levels and the trace flag, nothing more.

## Follow-ups (the slices)

1. **The base (this spec)**: the per-connection state, the `profile` event with `sources` and
   `plan`, the pushdown shape, levels `off | sampled | all`, ring / file / counters, redaction, the
   limits. Contract v2.
2. **acl_otel spec 009**: the execution span, span events, the log record with the tree, the
   histograms; `sampled` through the trace flag; opt-in operator spans.
3. **Per-session rules**: `SessionPolicy::ProfileFor`, `acl_session_profile`, the `acl_sessions()`
   column.
4. **Docs**: `docs/observability.md` - cumulative time, "observed" memory, three signals for three
   questions.

## Implementation notes (at pin 62ee922)

- The state: an `ExtensionCallback` registered by the extension whose `OnConnectionOpened(context)`
  inserts an `AclProfileState : ClientContextState` into `context.registered_state`; its
  `QueryEnd(ClientContext &, optional_ptr<ErrorData>)` reads `QueryProfiler::Get(context)` -
  `IsEnabled()`, `GetQueryMetrics()` (`QueryMetrics`: the peaks, `blocked_thread_time`,
  `bytes_read/written`, `total_memory_allocated`; `query_sql` is never read), and the tree through
  `ProfilingNode` (`children`, `depth`, `GetExtraInfo()`, `GetMetrics(const GatheredMetrics &)`),
  reached with a `TreeRenderer` subclass whose `Render(const ProfilingNode &, ...)` sees every node,
  or the root's children directly. Metrics are string-keyed (`GatheredMetrics::GetMetrics()`,
  `profiler_metrics_t`); `tracked_metrics` is set to the keys read.
- `QueryEnd` runs on the ending thread inside `EndQueryInternal`, after `profiler->EndQuery()`:
  for `Query()` at completion, for a `QueryResultStream` at `Close()`/end (spec 070's slot ends it
  explicitly), for a prepared statement per execution.
- `AuditPipeline::Emit` returns the assigned `seq` (a signature change of an acl-internal class);
  the override notes it beside the reason note.
- Profiling coverage and format are set through `ClientConfig::GetConfig(context)`
  (`ProfileConnectionFor`): the Flight door's `ArmProfile` before every execution (`StreamStatement`,
  the executemany loop, the direct update's and the ingest's Prepare) and `AclQuackStatementStarting`
  in quack's `DriveQuery` (the `sync.py` patch) are the sites; the gateway path is `QueryBegin`.
- Connections open before the load (the one loading, a gateway's pool) get their state at
  registration (`ConnectionManager::GetConnectionList`); `OnConnectionOpened` covers the rest.
- `TransactionContext::Rollback` calls `profiler->Reset()` before the state hooks run: an
  autocommit statement that failed has no tree at `QueryEnd` (the event still says it failed, its
  class and its wall time). An upstream question for later - the hooks after the reset.
- The scanner's name in `sources[].kind` is the operator's (`PhysicalTableScan::GetName()`, the
  function's name lower-cased): `table_scan` for a duckdb table, `postgres_scan`, `read_parquet`.
