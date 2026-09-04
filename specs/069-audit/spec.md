# Spec 069: Audit and observability - the base mechanism here, the rest through public hooks

- **Status**: draft (revised 2026-09-04 after the owner's direction; nothing implemented)
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
| `kind` | VARCHAR | `statement`, `admin`, `session`, `ingest`, `door` |
| `statement` | VARCHAR | the class: `SELECT`, `INSERT`, `CREATE TABLE`, `MANAGEMENT`, `NATIVE`, … - never the text |
| `objects` | STRUCT(name VARCHAR, capability VARCHAR)[] | every virtual object the resolution touched, with the capability judged for it |
| `verdict` | VARCHAR | `allowed` or `denied` |
| `reason` | VARCHAR | on `denied`: our refusal, prefix included; NULL on `allowed` |
| `correlation_id` | VARCHAR | what the caller supplied (below), else NULL |
| `traceparent` | VARCHAR | the W3C trace context the caller supplied, else NULL - what an OTel exporter needs to attach the event to a trace |
| `rewrite_us` | INTEGER | the decision's own cost |

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
- **`AuthorizeMgmt`**: kind `admin`, `statement` = `MANAGEMENT`, objects = the catalogs targeted,
  verdict per batch (a management batch is authorized as one - spec 009).
- **`SessionOpen`** and the doors: kind `session` at level `all` - opened, refused with the reason a
  client never sees (`token rejected: …`, `draining`, `at acl_max_sessions`), expired, killed. Kind
  `door` for the password handshake and its refusals (spec 064).
- **Ingest** (specs 042/049): kind `ingest`, the target with `insert`, the verdict.

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
	bool allowed; string reason;
	string correlation_id; string traceparent;
	int64_t rewrite_us;
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

//! The counters an exporter scrapes; every field is an atomic the base increments.
struct AuditCounters {
	std::atomic<int64_t> allowed, denied, sessions_opened, sessions_refused, sessions_live,
	    events_emitted, events_dropped, sink_errors;
};

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

`acl_metrics()` is a table function over `AuditCounters` plus the gauges the store already knows
(live sessions, drain state, ring fill, queue fill) - `name`, `value`, `kind` (`counter`/`gauge`).
The OTel extension reads `AuditHooks::Counters()` directly in C++ on its own scrape interval and
maps them to OTel instruments; per-role or per-object aggregates it derives from the event stream it
already receives. The base publishes no protocol.

### Correlation and trace ids

The caller supplies them; the node never invents one. Three ways in, two fields out:

- a **prefix marker** for a gateway, which shares a connection between principals and cannot afford
  a `SET` per statement: `ACL TOKEN '…' TRACE '<correlation>' [PARENT '<traceparent>'] <sql>` (and
  after `ROLE`/`SESSION`), each up to 128 printable bytes, single quotes doubled;
- a **client-local setting** for a served session (spec 068's allowlist grows by two):
  `SET acl_correlation_id = '…'` and `SET acl_traceparent = '…'`, stamped on every statement of that
  session until changed;
- the **Flight door** also reads the gRPC metadata keys `x-correlation-id` and `traceparent` on each
  call - what ADBC/JDBC clients and an OTel-instrumented front set without touching SQL.

### What the extended extension does with this (for the record; its own repo)

- `OtelLogSink : AuditSink` - maps an event to an OTel LogRecord (severity from `verdict`, the trace
  context from `traceparent`, attributes from the fields), batches, exports over OTLP.
- An OTel metrics exporter reading `Counters()` on a timer; the per-role/per-object counters it keeps
  from the events.
- `RolePolicy : SessionPolicy` - the level per role/user/door from its own configuration (an
  `acl_otel_*` setting or a table), which is "logging on a connection" decided by rule rather than by
  hand.
- Enrichment (claim values where the deployment says they are not personal data), sampling of
  `allowed` events under load, a strict mode that fails the statement when its event cannot be
  exported (the base stays fail-open).

Loading: `LOAD acl; LOAD acl_otel;` in either order. Both call `GetOrCreate<AuditHooks>`; the
registry is per `DatabaseInstance`, so two instances in one process never share sinks.

### What it costs

Composing an event is a handful of small strings and one queue push under a mutex; everything else
is on the audit thread. Against the 25–70 µs the rewrite itself costs (spec 043's measurement) this
is noise at `decisions`; `test/bench/rewrite_cost.py` gets a column for "with audit" to keep it
honest, and a level of `off` removes even the composition.

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
- The correlation and trace ids are the caller's strings, untrusted: bounded in length,
  JSON-escaped on the way out (`JsonQuote`), never interpreted.

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
