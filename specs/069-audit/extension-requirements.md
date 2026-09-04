# Requirements for the observability extension (`acl_otel`)

- **Status**: draft, 2026-09-04 - the contract an extension built on spec 069's hooks has to meet.
  It lives here, beside the spec, because the base is what defines the contract; the extension itself
  is its own repository.
- **Reads**: [spec.md](spec.md) first - the event, the levels, the hooks header, the base sinks.

## 0. What it is, in one paragraph

A separate duckdb extension, loaded beside `acl` on the same instance, that turns the base's audit
events and counters into OpenTelemetry **logs** and **metrics**, decides the audit level **per role,
per user and per door** (which is how logging gets switched on for a connection by rule), enriches,
samples, and reports its own health. It compiles against one header, `acl_audit.hpp`, and reaches
the base through duckdb's object cache. It contains no enforcement, changes no decision, and can
never slow or stop one.

## 1. The contract it consumes (the base's promises)

| promise | detail |
| --- | --- |
| **C1 one header** | `acl_audit.hpp`: `AuditLevel`, `AuditObject`, `AuditEvent`, `AuditSink`, `SessionPolicy`, `AuditCounters`, `AuditGauges`, `AuditHooks`, plus `Principal` from `acl_policy.hpp`. Same duckdb pin as the base it is loaded with. |
| **C2 the registry** | `db.GetObjectCache().GetOrCreate<AuditHooks>("acl_audit_hooks")` from either extension, in either load order; one registry per `DatabaseInstance`. |
| **C3 delivery** | `AuditSink::OnEvent` is called on the base's single audit thread, in `seq` order, never on the decision path; a sink that blocks costs dropped events (counted), a sink that throws is counted in `sink_errors` and skipped for that event. `Flush()` is called when the level or a setting changes and at shutdown. |
| **C4 the stream is sufficient** | every countable occurrence is an event (decisions with `reason_code`, session open/close with `how` and `duration_us`, ingest completion with `rows`, policy reloads and source errors, keys refreshes); only states are gauges. |
| **C5 the event is safe** | no statement text, parameters, rows or physical names; claim values are present **in memory only** (`principal.claims`) and never in a base sink. |
| **C6 levels** | an instance level and a per-session level; `SessionPolicy::LevelFor` is asked once, when a session opens, and its answer becomes the session's level unless the operator overrides it later (`acl_session_audit_level`). Precedence: operator override > policy answer > instance level. |
| **C7 counters and gauges** | `Counters().Snapshot()` / `Gauges().Snapshot()` return plain values with names, attributes and units at any time, lock-free for the writer. |
| **C8 naming** | everything the extension registers in SQL is `acl_otel_*`; the base's function gate denies every `acl_`-prefixed function to a principal, so the extension's surface is the operator's by construction. |

## 2. Functional requirements

### R1 - OpenTelemetry logs

- R1.1 Every event the sink receives becomes one OTel `LogRecord`. Mapping: `ts` → timestamp;
  severity `INFO` for `allowed`, `WARN` for `denied`, `ERROR` for `source_error` / `refresh_failed`;
  body = `<kind> <verdict>` plus the reason; every event field an attribute under the `acl.` prefix
  (`acl.kind`, `acl.statement`, `acl.verdict`, `acl.reason_code`, `acl.door`, `acl.session`,
  `acl.subject`, `acl.issuer`, `acl.roles`, `acl.objects` as a JSON array, `acl.correlation_id`,
  `acl.rewrite_us`, `acl.rows`, `acl.duration_us`, `acl.detail`).
- R1.2 `traceparent`, when present, sets the record's trace and span ids (W3C parsing; a malformed
  value is dropped, not exported).
- R1.3 Resource attributes: `service.name` (configurable, default `duckdb-acl`), `service.instance.id`
  = the node id, `acl.version`, `duckdb.version`, plus what the operator adds through
  `acl_otel_resource_attributes`.
- R1.4 Batched export over OTLP (gRPC and HTTP/protobuf), endpoint, headers and TLS from the standard
  `OTEL_EXPORTER_OTLP_*` environment and from `acl_otel_*` settings (settings win).
- R1.5 Its own bounded queue between `OnEvent` and the exporter: `OnEvent` never blocks on the
  network; an overflow drops and counts (R6).

### R2 - OpenTelemetry metrics

- R2.1 Every base counter and gauge (spec 069, *Metrics*) is exported under its base name with its
  attributes, scraped from `Snapshot()` on `acl_otel_metrics_interval` (default 15 s); counters as
  monotonic sums, gauges as gauges.
- R2.2 The **histograms are the extension's**, built from events (the base ships none): `acl.rewrite.duration`
  (from `rewrite_us`; attributes `kind`, `verdict`), `acl.session.duration` (from session close
  events, by `door` and `how`), `acl.ingest.rows` (from ingest completions, by `door`). Bucket
  boundaries are configurable (`acl_otel_histogram_buckets.<name>`); defaults: rewrite 25 µs …
  10 ms log-spaced, session 1 s … 1 d, rows 100 … 10 M.
- R2.3 **High-cardinality series are opt-in and bounded**: `acl.decisions.by_role` (by `role`),
  `acl.decisions.by_object` (by `object`, `capability`), `acl.decisions.by_subject`,
  `acl.decisions.by_claim` (by one claim named in configuration, e.g. `tenant`) - each behind its own
  switch, each with a cap on distinct label values (`acl_otel_max_series`, default 1000) beyond which
  new values fold into `other`, and an allowlist of roles/objects where the operator wants exactness.
- R2.4 Nothing here re-counts what the base counts differently: a base counter and its exported
  series agree, by construction of R2.1.

### R3 - levels per role, per user, per door

- R3.1 A `SessionPolicy` whose rules are ordered and first-match: each rule names any of `role`,
  `subject`, `issuer`, `door` (exact or `*`) and a level; a final default. Configured through
  `acl_otel_level_rules` (a JSON document) and reloadable at runtime without a restart.
- R3.2 `LevelFor` answers in constant time and never touches the network or the policy catalog: it
  is on the session-open path.
- R3.3 The operator's per-session override (base, `acl_session_audit_level`) is respected: the
  extension never re-applies its rule to a session the operator touched (C6).

### R4 - logging on a connection

- R4.1 "Enable logging for this connection" is R3 applied at open, plus the operator's override for
  a session already open; the extension exposes both in one place: `acl_otel_session_level(<ops
  id>, <level>)` delegating to the base, and `acl_otel_sessions()` listing sessions with their
  effective level and where it came from (rule / override / instance).
- R4.2 A level change takes effect on the session's next statement.

### R5 - enrichment

- R5.1 Claim values are exported only for claim names on `acl_otel_claim_attributes` (default
  empty), as `acl.claim.<name>`; everything else in `principal.claims` is dropped before export.
- R5.2 No enrichment reads the policy catalog or any table; what is not in the event or in the
  extension's own configuration is not added.

### R6 - sampling and drops

- R6.1 `allowed` events may be sampled (`acl_otel_sample_allowed`, a ratio per level or per role);
  `denied` events, session and door events, policy and keys events are never sampled.
- R6.2 Every drop - sampling, queue overflow, export failure after retries - is counted in the
  extension's own metrics (`acl_otel.dropped` by `why`) and never silent.

### R7 - health and its own metrics

- R7.1 `acl_otel_status()` reports: sink registered, exporter endpoint, last successful export, queue
  fill, events exported / dropped / failed, the policy rule count.
- R7.2 Exported self-metrics: `acl_otel.exported`, `acl_otel.dropped` (`why`), `acl_otel.export_errors`,
  `acl_otel.queue_fill`; a `acl_otel.healthy` gauge (0/1) an orchestrator can drain a node on.
- R7.3 Strict mode is **not** refusing statements (the base emits after the decision; nothing can be
  refused post hoc): `acl_otel_strict = true` makes `healthy` drop to 0 while events are being lost,
  which is the signal a deployment that prefers unavailability to unrecorded decisions acts on.

### R8 - lifecycle

- R8.1 `LOAD acl_otel` before or after `LOAD acl`; the sink and the policy are registered at load
  through C2; exporting starts when the endpoint is configured.
- R8.2 `acl_otel_stop()` flushes, detaches the sink and the policy (`RemoveSink` /
  `SetSessionPolicy(nullptr)`), and is idempotent; `acl_otel_start()` re-attaches. duckdb has no
  extension unload, so this is the only way out.
- R8.3 Two `DatabaseInstance`s in one process are two registries, two sinks, two exporters.

### R9 - configuration and security

- R9.1 All settings are `SetScope::GLOBAL`, named `acl_otel_*`, and unreachable under a principal
  (C8 plus the base's settings gate of spec 068).
- R9.2 Secrets (OTLP headers with tokens) are read from the environment or from duckdb secrets,
  never from a setting a `SELECT current_setting()` could show - and `current_setting` is on the
  base's denylist anyway.
- R9.3 The extension never writes to the policy catalog and never calls an `acl_*` function that
  changes policy.

### R10 - performance envelope

- R10.1 `OnEvent`: O(1) work, no allocation beyond the queue push, no I/O; measured under
  `test/bench/rewrite_cost.py`'s "with audit" column the extension must not move it.
- R10.2 `LevelFor`: O(rules), rules bounded (`acl_otel_max_rules`, default 100).
- R10.3 The exporter's queue and batch sizes are settings with sane defaults (10 000 events, 512 per
  batch, 5 s flush).

## 3. Non-requirements (out of scope, deliberately)

- Traces / spans per statement: the base emits at decision time and has no execution hook; a span
  needs both ends. Follow-up in spec 069.
- Reading or altering policy; any enforcement.
- Durable storage of events (the base's file sink or the OTel backend is the durability).
- Windows/wasm parity beyond what the base offers: the extension ships where the base does.

## 4. Testing the extension must carry

- A fake OTLP receiver (gRPC and HTTP) in its C++ tests: every field mapped per R1.1, the trace
  context per R1.2, resource attributes per R1.3.
- The histogram and series derivations (R2.2, R2.3) checked against a synthetic event stream with
  known counts, including the `other` fold and the allowlist.
- The level rules (R3): first-match order, `*`, the operator override precedence, hot reload.
- Sampling and drop accounting (R6): every dropped event visible in `acl_otel.dropped`.
- A blocking exporter never slowing a decision (R10.1): bounded by time, like the base's own test.
- The contract test in **this** repo, `test/cpp/test_acl_audit_hooks.cpp`, is the reference: the
  extension's sink registration is the same code path.

## 5. Open questions for the extension's repo

- The name: `acl_otel`, or the more general `acl_observe` (a Prometheus scrape endpoint would fit
  the same shape and the same hooks).
- Whether the OTel C++ SDK is vendored or taken from vcpkg (the base's vcpkg manifests are the
  precedent).
- Whether `acl_otel_level_rules` also lives as a table in the policy catalog for the fleet to manage
  centrally - a read-only consumer of the base's catalog is allowed by R9.3; a writer is not.
