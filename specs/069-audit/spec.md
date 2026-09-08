# Spec 069: Audit and observability - the base mechanism here, the rest through public hooks

- **Status**: implemented (the base; the extended extension `acl_otel` is a separate repo - see
  [extension-requirements.md](extension-requirements.md))
- **Date**: 2026-09-04
- **Author**: hugr-lab

## Summary

Every decision the ACL makes about a principal - a statement admitted or refused, a session opened
or refused, a management statement authorized or refused, an ingest accepted - becomes one event:
who, what kind of statement, which virtual objects with which capability, the verdict and its
reason, the caller's correlation and trace ids, at which audit level. **Never data**: no statement
text, no parameter values, no rows; the base sinks store no claim values either.

The work is split in two layers, and the split is the design:

| layer | where | what |
| --- | --- | --- |
| **base** | this extension | the event model and levels; the decision points that emit; a per-instance **hook registry** other extensions reach through duckdb's `ObjectCache`; two built-in sinks (an in-process ring, a JSON-lines file); the counters (`acl_metrics()`); per-session levels the door or the operator sets; correlation/trace ids in |
| **extended** | a separate extension (`acl_otel`, its own repo), compiled against `acl_audit.hpp` | OpenTelemetry **logs** (an `AuditSink`), OpenTelemetry **metrics** (a scraper of the counters), audit and logging **levels per role and per user** (a `SessionPolicy`), enabling on a connection by rule, enrichment (claim values where they are not personal data), sampling, strict mode |

The base is dependency-free and always there; what a deployment exports, to where, at which level
and for whom is the extended extension's, and the orchestrator's, business. The cluster repo depends
on the base existing; it cannot reconstruct what the node decided.

## Problem

Today the only trace of a decision is the error the client got, or did not get. Nobody can answer
"who read `orders` yesterday", "which statements did role `analyst` have refused this week", "did
principal P ever reach `sales.ssn_backup`", or "the front saw request R fail - what did the node
decide". A gateway can log what it *sent*; it cannot log what the node *decided* - the objects a
rewrite resolved, the capability it judged, the reason of a refusal.

And a fleet in a cloud does not want a file: it wants OTel logs and metrics, levels that differ per
role (everything for a contractor's role, refusals only for the batch job), logging switched on for
one connection while an incident is chased, and none of that baked into the enforcement extension,
where it would drag the OTel SDK (gRPC, protobuf) into every build and every decision about
exporting into this repo.

## Design

### The event

One record per decision:

| field | type | what |
| --- | --- | --- |
| `ts` | TIMESTAMPTZ | when the decision was made |
| `seq` | BIGINT | monotonic per instance; a gap is a dropped event |
| `node` | VARCHAR | `acl_node_id` when set, else `<hostname>:<pid>` |
| `level` | VARCHAR | the level this event belongs to (below) |
| `door` | VARCHAR | `flight`, `quack`, `gateway` (a prefix on a plain connection), `admin` (a bare `ACL ADMIN`) |
| `session` | VARCHAR | the ops id `acl_sessions()` shows - never the handle - or NULL |
| `subject`, `issuer`, `roles` | VARCHAR, VARCHAR, VARCHAR[] | the principal; the `ROLE` form has roles only |
| `kind` | VARCHAR | `statement`, `admin`, `session`, `ingest`, `door`, `policy`, `keys` |
| `statement` | VARCHAR | the class, duckdb's statement type lowercased (`select`, `insert`, `create`, `set`, …), or `manage` / `native` for the two admin forms - never the text |
| `objects` | STRUCT(name VARCHAR, capability VARCHAR)[] | every virtual object the resolution touched, with the capability judged for it |
| `verdict` | VARCHAR | `allowed` or `denied` |
| `reason_code` | VARCHAR | on `denied`: one of a bounded set (below) - the dimension a metric can carry |
| `reason` | VARCHAR | on `denied`: our refusal, prefix included; NULL on `allowed` |
| `correlation_id` | VARCHAR | what the caller supplied (below), else NULL |
| `traceparent` | VARCHAR | the W3C trace context the caller supplied, else NULL - what an OTel exporter needs to attach the event to a trace |
| `rewrite_us` | INTEGER | the decision's own cost |
| `rows` | BIGINT | `ingest` only: rows the completed drain wrote (a number, not data); NULL elsewhere |
| `duration_us` | BIGINT | `session` close events only: how long the session lived; NULL elsewhere |
| `detail` | VARCHAR | a bounded word for `policy` / `keys` / `session` events: `reloaded`, `source_error`, `refreshed`, `refresh_failed`, `idle`, `expired`, `killed`, `door_stopped`, `client` |

**Reason codes** (the taxonomy every `Deny` site names; the text after the prefix stays free):
`no_access`, `capability`, `read_only`, `function_denied`, `statement_type`, `unchecked_predicate`,
`setting_denied`, `parse`, `principal` (a token, role or session that did not verify),
`mgmt_unauthorized`, `ddl_home`, `draining`, `at_capacity`, `source_error` (the policy source or an
issuer's keys did not answer), `unavailable`, `write_policy` (a row refused where it is written,
spec 024, or by the door's own load check), `policy_error` (a template or a policy row the rewriter
could not use - the operator's, not the principal's; also the fallback for a failure under the
rewrite that named no code).

**What a reason may carry.** The `reason` is our own refusal text, which names virtual objects,
capabilities, functions and settings and nothing else - with three exceptions the audit closes
itself: a `parse` refusal echoes the statement's text at or near the error (a literal in it could be
a secret), so it is replaced by a fixed sentence; a `principal` refusal may echo a claim of a token
nobody verified (its issuer, its algorithm), so every quoted value is blanked; an `ingest` failure
that is the physical source's carries the row it refused, so only the error's class is kept. Every
reason is cut to 512 bytes, every trace id to 128, on a character boundary.

**The stream is sufficient by design**: everything a consumer might count is in the events - a
decision with its code, a session's open and close with how and how long, an ingest with its rows, a
policy reload or source error, a keys refresh. Only what is not an occurrence but a state (live
sessions, queue fill, policy staleness, JWKS age) is a gauge the base exposes instead.

Deliberately **not** in the stored event: the statement text, parameter values, anything read or
written, physical names (the reason is our refusal text, which names virtual facts only - spec 065).
Claim values are not in the base sinks either; a sink in process receives the whole `Principal`
(below) and decides for itself. An error duckdb raises later, at bind or execution, is not our
decision and is not recorded by us.

### Levels

Four, ordered; an event carries the lowest level that includes it, a level records every event at
or below itself:

| level | records |
| --- | --- |
| `off` | nothing |
| `denied` | refusals only - every `denied` verdict of every kind |
| `decisions` | every statement, admin and ingest decision, allowed or denied |
| `all` | `decisions` plus the session and door lifecycle (opened, refused, expired, killed, drained) |

`SET GLOBAL acl_audit_level` (default `decisions`) is the instance's level. **A session may have its
own** - that is the "logging on a connection" the owner asked for - set by the door when the session
opens (the `SessionPolicy` hook answers a level for the principal; unset means the instance's) or by
the operator afterwards: `acl_session_audit_level('<ops id>', 'all')`, denied to a principal like the
rest of the ops surface. A client never lowers its own level: `acl_audit_level` is not on spec 068's
client-local allowlist.

### Where decisions are made - the seams that emit

- **The rewriter** (`RewriteStatements`): one event per statement of the batch. The walker records
  every `TablePolicy` it resolves and the capability it checked into an `AuditTrail` carried through
  the walk (as `Principal` is), and the override emits when the rewrite returns or throws - `allowed`
  with the objects, or `denied` with the refusal. One event covers a whole batch only when it is
  refused before any statement is walked (a prefix that does not parse, a principal that does not
  verify).
- **`AuthorizeMgmt`**: kind `admin`, `statement` = `manage`, one event per compiled call with the
  admin function it is (`objects` = `[{acl_add_relation, manage}]`), `detail` = the scope it ran under
  (anonymous / manage / passthrough); a refused batch is one event naming every call in it (a
  management batch is authorized as one - spec 009). `ACL NATIVE` is kind `admin`, `statement` =
  `native`.
- **`SessionOpen`** and the doors: kind `session` at level `all` - opened, refused with the reason a
  client never sees (`token rejected: …`, `draining`, `at acl_max_sessions`), expired, killed. Kind
  `door` for the password handshake and its refusals (spec 064).
- **Ingest** (specs 042/049): kind `ingest`, emitted **when the drain completes**, not when it is
  admitted - both doors run the ingest INSERT themselves, so the row count is theirs to know and no
  duckdb execution hook is needed: the target with `insert`, `allowed` with `rows`, or `denied`
  with the reason (a client that died mid-stream leaves a denied `ingest` with `rows` NULL).
- **The policy source**: kind `policy` at level `all` - `reloaded` when a version bump clears the
  caches, `source_error` when a catalog read fails and the resolver refuses closed (the denial that
  follows carries `reason_code = source_error` too). Kind `keys` at level `all`: a JWKS document
  `refreshed` or `refresh_failed`, with the issuer in `objects[0].name`.

### The hooks - the base's public C++ surface

One header, `src/include/acl_audit.hpp`, is what an extended extension compiles against. It carries
no duckdb-internal types beyond `string`, `vector`, `shared_ptr` and our own `Principal`:

```cpp
namespace duckdb { namespace acl {

enum class AuditLevel : uint8_t { OFF, DENIED, DECISIONS, ALL };

struct AuditObject { string name; string capability; };

struct AuditEvent {
	int64_t ts_us; int64_t seq; string node; AuditLevel level;
	string door; string session;
	Principal principal;                 // subject, issuer, roles, claims - in memory, the sink's to filter
	string kind; string statement; vector<AuditObject> objects;
	bool allowed; string reason_code; string reason;
	string correlation_id; string traceparent;
	int64_t rewrite_us;                  // the decision's own cost
	int64_t rows;                        // ingest: rows written by the completed drain; else -1
	int64_t duration_us;                 // session close: how long it lived; else -1
	string detail;                       // policy / keys / session: the bounded word of the table above
};

//! A consumer of events. Called on the audit thread, never on the decision path.
struct AuditSink {
	virtual ~AuditSink() = default;
	virtual void OnEvent(const AuditEvent &event) = 0;
	virtual void Flush() {}
};

//! Decides a session's level when it opens: the extended extension's "per role, per user" rule.
struct SessionPolicy {
	virtual ~SessionPolicy() = default;
	virtual bool LevelFor(const Principal &principal, const string &door, AuditLevel &out) = 0;
};

//! The counters and gauges an exporter scrapes - the tables of the *Metrics* section, one atomic
//! per (name, attribute-tuple); the base increments, nobody else writes. `Snapshot()` copies them
//! under no lock into plain integers with their names and attributes, which is what a scrape wants.
struct AuditMetric { string name; string kind; vector<pair<string, string>> attributes; int64_t value; string unit; };
struct AuditCounters { /* atomics behind the counter table */ vector<AuditMetric> Snapshot() const; };
struct AuditGauges   { /* atomics behind the gauge table   */ vector<AuditMetric> Snapshot() const; };

//! Per DatabaseInstance. Reached from ANY extension through duckdb's object cache:
//!   auto hooks = db.GetObjectCache().GetOrCreate<AuditHooks>("acl_audit_hooks");
//! GetOrCreate on both sides makes the load order irrelevant: whoever comes first creates it,
//! acl adopts it when it loads.
class AuditHooks : public ObjectCacheEntry {
public:
	void AddSink(shared_ptr<AuditSink> sink);
	void RemoveSink(const shared_ptr<AuditSink> &sink);
	void SetSessionPolicy(shared_ptr<SessionPolicy> policy);
	const AuditCounters &Counters() const;
	const AuditGauges &Gauges() const;
	static string ObjectType();  // "acl_audit_hooks"
};

}} // namespace duckdb::acl
```

Delivery is decoupled from the decision: the emitting seam composes the event and pushes it onto
one bounded queue (`acl_audit_queue`, default 10 000); **the audit thread** pops and hands each event
to every registered sink in turn, then to the base sinks. A slow sink costs drops (counted in
`events_dropped`, visible in `acl_audit_dropped()` and the counters), never latency on a statement; a
sink that throws is counted in `sink_errors` and skipped for that event. This is the whole
availability argument: nothing an exporter does can take the node down or slow a decision.

### The base sinks

- **The ring**, always on: the newest `acl_audit_buffer` events (default 10 000, `0` = off), read by
  `acl_audit_events()` - a table function of the operator's, denied to a principal.
- **A file**, `SET GLOBAL acl_audit_sink = '<path or URI>'`: one JSON line per event through
  duckdb's own filesystem (a local file works out of the box; an object store rides httpfs - the
  spec-023 pattern). Claim values are not written. Rotation is the operator's; the writer reopens the
  file when the setting changes. An unwritable path counts drops and the node keeps deciding.

### Metrics

The base keeps **counters and gauges only** - no histograms, no per-role or per-object dimensions:
every distribution (rewrite latency, session duration, rows per ingest) and every high-cardinality
breakdown is the extension's, derived from the event stream, with the buckets and the limits of its
own choosing (the owner's decision, 2026-09-04). What the base counts it counts with attributes
from bounded sets only: `door` ∈ {flight, quack, gateway, admin, session (a session minted through
`acl_session_open` by a gateway)}, `kind`, `verdict`, the statement class, `reason_code`, `result`,
the issuer.

`acl_metrics()` is a table function over `AuditHooks::Counters()` and `Gauges()`:
`name`, `kind` (`counter` / `gauge`), `attributes` (a JSON object), `value`, `unit`, `description`.
The OTel extension reads the same two structs directly in C++ on its own scrape interval.

| counter | attributes |
| --- | --- |
| `acl.decisions` | `verdict`, `kind`, `door`, `statement` |
| `acl.denials` | `reason_code`, `door` |
| `acl.sessions.opened`, `acl.sessions.refused` (`reason_code`), `acl.sessions.closed` (`how`) | `door` |
| `acl.door.handshakes` (`result`), `acl.door.tickets` (`outcome`: issued / redeemed / expired / foreign) | `door` |
| `acl.ingest.statements` | `door`, `verdict` |
| `acl.admin.statements` | `verdict`, `scope`: anonymous / manage / passthrough |
| `acl.policy.reloads`, `acl.policy.source_errors`, `acl.policy.writes` | - |
| `acl.jwt.verifications` | `result`: ok / failed (why it failed is the refusal's `reason_code` on the session or statement event) |
| `acl.jwks.refreshes` | `issuer`, `result`: refreshed / refresh_failed |
| `acl.audit.events`, `acl.audit.dropped` (`where`: queue / ring / sink / rate_limit), `acl.audit.sink_errors` (`sink`) | - |

(A cache hit/miss counter for the catalog backend's caches was considered and left out of the base:
the version gauge and the reload counter say when the caches were rebuilt, which is what an incident
needs; a hit ratio is a tuning figure the extension can derive if it ever wants one.)

| gauge | what |
| --- | --- |
| `acl.sessions.live` (`door`), `acl.sessions.max` | the session map against its cap |
| `acl.door.state` (`door`) | listeners of this instance serving right now (a uri is not a bounded set) |
| `acl.node.draining`, `acl.node.uptime`, `acl.node.info` (=1; attribute: the acl build version) | the node; the node id is on every row already |
| `acl.policy.version` | the policy version the caches are keyed by - to correlate an incident with a change |
| `acl.policy.staleness` | seconds since the last successful version check: it grows when the source is unreachable |
| `acl.jwks.age` (`issuer`) | seconds since the issuer's keys were last read successfully |
| `acl.audit.queue_fill`, `acl.audit.ring_fill` | the pipeline's own health |

Every counter above is also derivable from the events (a consumer that only listens loses nothing);
the gauges are states, not occurrences, and exist only here.

### Looking at it without the extension

Three ways, none needing OTel, all of them what the tests use:

- **SQL**: `acl_metrics()` and `acl_audit_events()` on a local connection or through the operator's
  `ACL … ACL NATIVE` passthrough over a door - the way `acl_sessions()` is read today. A dashboard
  is one query; a test is one `query` block.
- **The file**: the JSON-lines sink read back with `read_json_auto(...)` - every field a column, so
  "who read what yesterday" is a `GROUP BY` in duckdb itself.
- **A Prometheus endpoint, opt-in**: `SET GLOBAL acl_metrics_endpoint = true` adds `GET /metrics`
  (the text exposition format, ~50 lines to render, no dependency) to the embedded listener the
  quack door already runs beside `/.well-known/quack-auth` - and to a `plain`-mode listener started
  for nothing else where only the Flight door serves. Off by default; when on, it is what a
  Prometheus, an OpenTelemetry Collector's `prometheus` receiver or Azure Monitor's managed
  Prometheus scrape. The endpoint is a rendering of `acl_metrics()`, so the two can never disagree.

The extension is for exporting; looking is free.

### In a fleet (the cluster repo, later)

A node decides alone and reports alone; nothing in the audit shares state across nodes, exactly as
sessions do not (spec 040's follow-up stands). What the fleet needs from each node is already in
the design:

- **identity**: `acl_node_id` set by the orchestrator (else `<hostname>:<pid>`) is on every event
  and every metric (`node`, and `service.instance.id` once exported); `(node, seq)` is a global
  order key with no coordination.
- **correlation**: the front mints the trace and passes `traceparent` / `x-correlation-id` through
  the door's metadata or the `TRACE … PARENT …` marker; a request in the front's telemetry and the
  node's decision meet in the backend by those ids, not by clocks.
- **aggregation**: across nodes it happens in the backend (the Collector, App Insights, Prometheus),
  never in a node; per-node counters roll up because their attributes are bounded and identical.
- **central rules**: the policy catalog is the fleet's shared configuration channel already; the
  extension's level rules live there as a read-only consumer's table (requirements R3 and §5),
  written by the fleet, read by every node on its own interval.
- **health**: `acl.door.state`, `acl.policy.staleness`, `acl.jwks.age` and the extension's
  `acl_otel.healthy` are what the orchestrator drains a node on (`acl_drain()`, spec 066) and what
  readiness reads; the file sink is for a single node with a disk, the fleet exports.

### Correlation and trace ids

The caller supplies them; the node never invents one. Three ways in, two fields out:

- a **prefix marker** for a gateway, which shares a connection between principals and cannot afford
  a `SET` per statement: `ACL TOKEN '…' TRACE '<correlation>' [PARENT '<traceparent>'] <sql>` (and
  after `ROLE`/`SESSION`), each up to 128 printable bytes, single quotes doubled, each marker at
  most once - a second one written in the SQL text behind a door's prefix is a parse refusal, not
  a replacement;
- a **client-local setting** for a served session (spec 068's allowlist grows by two):
  `SET acl_correlation_id = '…'` and `SET acl_traceparent = '…'`, stamped on every statement of that
  session until changed;
- the **Flight door** also reads the gRPC metadata keys `x-correlation-id` and `traceparent` on each
  call - what ADBC/JDBC clients and an OTel-instrumented front set without touching SQL.

### What the extended extension does with this

Its requirements are a document of their own, beside this spec:
[`extension-requirements.md`](extension-requirements.md) - the contract it consumes, the OTel
logs and metrics it produces (every histogram and every per-role / per-object / per-tenant series is
derived there, from the events), the level rules per role, user and door, per-connection logging,
enrichment, sampling, its own health and settings. In one line: `LOAD acl; LOAD acl_otel;` in either
order, both call `GetOrCreate<AuditHooks>`, the registry is per `DatabaseInstance`, and nothing the
extension does can slow or stop a decision.

### What it costs

Composing an event is a handful of small strings and one queue push under a mutex; everything else
is on the audit thread. Against the 25–70 µs the rewrite itself costs (spec 043's measurement) this
is noise at `decisions`; `test/bench/rewrite_cost.py` gets a column for "with audit" to keep it
honest. A level of `off` still composes and counts (the counters are a state of the node whatever
the level) - it records nothing.

**One source cannot drown the others.** A refusal is cheap to cause and an event each, so a
principal - or an unauthenticated client presenting refused tokens - could push everybody else's
records out of the ring, the queue and every sink. The base records at most
`acl_audit_denials_per_second` (default 100) denials per second per source - a session, else a
principal, else a door; the rest are counted exactly like the recorded ones (`acl.denials` stays
true) and reported as `acl.audit.dropped{where=rate_limit}`. Allowed decisions are bounded by the
work they cost and are not limited.

### What it is not

Not a query log (no text). Not row-level access logging (no rows). Not tamper-evident (that is a
sink's property - the fleet's). Not consulted by enforcement - nothing decides differently because
of what was recorded. Not an OTel SDK dependency in this repo.

## Enforcement & security

- **Never data** is structural: the event is built from the decision's own facts - `TablePolicy`
  names, the capability, the verdict, our refusal text - and the code path never sees the statement
  text as a value to record. A reviewer can check the one constructor.
- The audit surface is the operator's. `acl_audit_events()`, `acl_metrics()`, `acl_audit_dropped()`,
  `acl_session_audit_level()` and the settings are unreachable under a principal (the function gate
  and spec 068's settings gate); a principal cannot raise, lower or read its own audit.
- A hook is in-process C++ registered by an extension the operator loaded: trusted by definition,
  like any extension. It sees claim values in memory; what it stores or exports is its own contract.
- Fail-open by design in the base: a dropped event is counted, never a refused statement. A strict
  mode is a sink's policy, not the base's.
- The correlation and trace ids are the caller's strings, untrusted: bounded in length (128 bytes,
  cut on a character boundary, control characters dropped), JSON-escaped on the way out
  (`JsonQuote`), never interpreted. On quack the client's `SET acl_correlation_id` lands on the
  session's record (the server evaluates the composition on a connection of its own), on Flight the
  headers win over the session's settings.

## Testing

- sqllogictest: after a handful of prefixed statements at each level, `acl_audit_events()` shows
  exactly what the level admits - an allowed `SELECT` with `[{orders, select}]` at `decisions` and
  not at `denied`, a refused `INSERT` with its reason at both, a session refused for a bad token
  only at `all`; a `TRACE`/`PARENT` marker and the two settings arriving in their fields; a
  principal calling `acl_audit_events()`, `acl_metrics()` or the level function refused; a buffer of
  5 after 10 events holds the last 5 and reports 5 dropped; `acl_session_audit_level` on a live
  session changes what that session's next statements record.
- The file sink: set to a temp path, run statements, `read_json_auto` reads them back with the same
  fields and no claim values; an unwritable path counts drops and the statements still run.
- Metrics, in sqllogictest over `acl_metrics()`: after N allowed and M denied statements the
  `acl.decisions` rows by `verdict` read N and M and `acl.denials` by `reason_code` reads each code
  once; `acl.sessions.live` follows `acl_session_open` / `acl_session_close`; `acl.policy.version`
  follows a management write; every row's `attributes` keys are from the bounded sets and nothing
  else (a row with a role or an object name is a failed test). The Prometheus endpoint, in the
  embedded-door C++ test: `GET /metrics` renders exactly the rows of `acl_metrics()` (same names,
  same values, `# TYPE` lines), answers 404 while the setting is off, and never lists a session
  handle. The door harness asserts `acl.sessions.opened` = the clients it started and
  `acl.ingest.statements` = the loads, read through the endpoint.
- C++ (`make test-cpp`): `test_acl_audit_hooks.cpp` registers a sink and a session policy through
  `GetObjectCache().GetOrCreate<AuditHooks>` from a translation unit that includes only
  `acl_audit.hpp` - the extension contract proven without a second extension; a sink that blocks
  costs drops, never a slower statement (bounded by time); a sink that throws is counted and the
  next event still arrives; the policy's level lands on the session's events.
  `test_acl_concurrency.cpp` grows a tally: every writer's decisions are present or counted as
  dropped, never silently lost.
- The door harness: one `session` event per client connection at `all`.

## Alternatives considered

- **OTel in the base.** Pulls the OTel C++ SDK (protobuf, the OTLP exporters) into every build and
  every decision about exporting into this repo; the hooks give the same result with the dependency
  in the extension that wants it.
- **A table in the policy catalog as the sink.** Every statement becomes a write into the database
  the resolver reads from, shared by every node - latency on the hot path and contention for the one
  thing that must stay fast. A deployment that wants durability tails the file or exports.
- **duckdb's own logger** (`duckdb_logs`). A log of strings, not a record with our fields; a
  principal can read `duckdb_logs` unless denied. At most one more sink later.
- **Calling sinks on the decision path.** Simpler, and it hands every exporter a veto over latency.
  The audit thread is what keeps "an exporter can never slow or stop a decision" true.
- **Auditing at the gateway.** It knows what it sent, not what the node decided.

## Follow-ups

- OTel trace *spans* per statement (needs an execution hook; the base emits at decision time).
- Row counts of executed statements, once an execution hook exists.
- A `RemoveSink`-on-unload guarantee (an extension unloading with a sink registered) - duckdb has no
  unload today; noted for when it does.
