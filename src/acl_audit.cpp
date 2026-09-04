// The audit pipeline (spec 069): one bounded queue, one thread, every registered sink, then the
// base's own ring and JSON-lines file; the counters derived from the events on that thread; the
// gauges read from their owners at snapshot time. The contract a consumer sees is acl_audit.hpp
// (header-only); this is acl's side of it.

#include "acl_audit_pipeline.hpp"

#include "acl_door_common.hpp"

#include "duckdb/common/string_util.hpp"
#include "duckdb/common/types/value.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/planner/expression/bound_function_expression.hpp"

#include <algorithm>
#include <chrono>

#ifdef _WIN32
#include <process.h>
#include <winsock2.h>
#else
#include <unistd.h>
#endif

namespace duckdb {
namespace acl {

namespace {

int64_t NowMicros() {
	return std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now().time_since_epoch())
	    .count();
}

string HostPid() {
	char host[256];
	host[0] = '\0';
#ifdef _WIN32
	DWORD size = sizeof(host);
	if (!GetComputerNameA(host, &size)) {
		host[0] = '\0';
	}
	auto pid = _getpid();
#else
	if (gethostname(host, sizeof(host)) != 0) {
		host[0] = '\0';
	}
	auto pid = getpid();
#endif
	host[sizeof(host) - 1] = '\0';
	return string(host[0] ? host : "unknown") + ":" + std::to_string(pid);
}

} // namespace

//===--------------------------------------------------------------------===//
// The pipeline
//===--------------------------------------------------------------------===//

AuditPipeline::AuditPipeline(shared_ptr<AuditHooks> hooks_p) : hooks(std::move(hooks_p)) {
	hooks->Gauges().Register("acl.audit.queue_fill", {}, "1", "events waiting on the audit thread", [this]() {
		std::lock_guard<std::mutex> guard(queue_lock);
		return int64_t(queue.size());
	});
	hooks->Gauges().Register("acl.audit.ring_fill", {}, "1", "events held in the ring", [this]() {
		std::lock_guard<std::mutex> guard(ring_lock);
		return int64_t(ring.size());
	});
}

AuditPipeline::~AuditPipeline() {
	Stop();
}

void AuditPipeline::Attach(DatabaseInstance &db_p) {
	db = db_p.shared_from_this();
	node = HostPid(); // the fallback; acl_node_id is read per event, so a SET after load takes effect
}

string AuditPipeline::Setting(const char *name, const string &fallback) {
	auto instance = db.lock();
	if (!instance) {
		return fallback;
	}
	Value value;
	if (!instance->TryGetCurrentSetting(name, value) || value.IsNull()) {
		return fallback;
	}
	return value.ToString();
}

int64_t AuditPipeline::SettingInt(const char *name, int64_t fallback) {
	auto instance = db.lock();
	if (!instance) {
		return fallback;
	}
	Value value;
	if (!instance->TryGetCurrentSetting(name, value) || value.IsNull()) {
		return fallback;
	}
	return value.GetValue<int64_t>();
}

AuditLevel AuditPipeline::InstanceLevel() {
	// read every time: a setting lookup is a map read under the config lock, and a SET must take
	// effect on the next statement, not later (a test sets levels back to back)
	AuditLevel parsed;
	if (ParseAuditLevel(Setting("acl_audit_level", "decisions"), parsed)) {
		return parsed;
	}
	return AuditLevel::DECISIONS;
}

bool AuditPipeline::Records(AuditLevel level, int8_t session_level) {
	auto effective = session_level >= 0 ? static_cast<AuditLevel>(session_level) : InstanceLevel();
	return effective != AuditLevel::OFF && static_cast<uint8_t>(level) <= static_cast<uint8_t>(effective);
}

bool AuditPipeline::LevelForSession(const Principal &principal, const string &door, AuditLevel &out) {
	auto policy = hooks->Policy();
	if (!policy) {
		return false;
	}
	try {
		return policy->LevelFor(principal, door, out);
	} catch (...) {
		hooks->Counters().Add("acl.audit.sink_errors", {{"sink", "policy"}});
		return false;
	}
}

void AuditPipeline::Emit(AuditEvent event) {
	event.ts_us = NowMicros();
	event.seq = ++seq;
	auto configured = Setting("acl_node_id", "");
	event.node = configured.empty() ? node : configured;
	auto cap = SettingInt("acl_audit_queue", 10000);
	{
		std::lock_guard<std::mutex> guard(queue_lock);
		if (stopping) {
			return;
		}
		if (cap > 0 && int64_t(queue.size()) >= cap) {
			dropped++;
			hooks->Counters().Add("acl.audit.dropped", {{"where", "queue"}});
			return;
		}
		queue.push_back(std::move(event));
		enqueued++;
		if (!worker.joinable()) {
			worker = std::thread([this]() { Run(); });
		}
	}
	queue_cv.notify_one();
}

void AuditPipeline::Run() {
	while (true) {
		AuditEvent event;
		{
			std::unique_lock<std::mutex> guard(queue_lock);
			queue_cv.wait(guard, [this]() { return !queue.empty() || stopping; });
			if (queue.empty()) {
				return; // stopping, and nothing left
			}
			event = std::move(queue.front());
			queue.pop_front();
		}
		Handle(event);
		{
			std::lock_guard<std::mutex> guard(queue_lock);
			handled++;
		}
		drained_cv.notify_all();
	}
}

void AuditPipeline::Count(const AuditEvent &event) {
	auto &counters = hooks->Counters();
	counters.Add("acl.audit.events", {});
	auto verdict = event.allowed ? "allowed" : "denied";
	if (event.kind == "statement" || event.kind == "admin" || event.kind == "ingest") {
		counters.Add(
		    "acl.decisions",
		    {{"verdict", verdict}, {"kind", event.kind}, {"door", event.door}, {"statement", event.statement}});
		if (!event.allowed) {
			counters.Add("acl.denials", {{"reason_code", event.reason_code}, {"door", event.door}});
		}
		if (event.kind == "admin") {
			counters.Add("acl.admin.statements", {{"verdict", verdict}, {"scope", event.detail}});
		}
		if (event.kind == "ingest") {
			counters.Add("acl.ingest.statements", {{"door", event.door}, {"verdict", verdict}});
		}
	} else if (event.kind == "session") {
		if (event.detail == "opened") {
			counters.Add("acl.sessions.opened", {{"door", event.door}});
		} else if (event.detail == "refused") {
			counters.Add("acl.sessions.refused", {{"door", event.door}, {"reason_code", event.reason_code}});
		} else {
			counters.Add("acl.sessions.closed", {{"door", event.door}, {"how", event.detail}});
		}
	} else if (event.kind == "door") {
		counters.Add("acl.door.handshakes", {{"door", event.door}, {"result", verdict}});
	} else if (event.kind == "policy") {
		if (event.detail == "reloaded") {
			counters.Add("acl.policy.reloads", {});
		} else if (event.detail == "source_error") {
			counters.Add("acl.policy.source_errors", {});
		} else if (event.detail == "written") {
			counters.Add("acl.policy.writes", {});
		}
	} else if (event.kind == "keys") {
		string issuer = event.objects.empty() ? "" : event.objects[0].name;
		counters.Add("acl.jwks.refreshes", {{"issuer", issuer}, {"result", event.detail}});
	}
}

void AuditPipeline::Handle(const AuditEvent &event) {
	// counted whatever the level: metrics are a state of the node, audit is a record of it
	Count(event);
	// the level decided what is recorded where the event was emitted (the session's own level is
	// known there); an unrecorded event stops here - no sink, no ring, no file
	if (!event.recorded) {
		return;
	}
	for (auto &sink : hooks->Sinks()) {
		try {
			sink->OnEvent(event);
		} catch (...) {
			hooks->Counters().Add("acl.audit.sink_errors", {{"sink", "extension"}});
		}
	}
	auto ring_cap = SettingInt("acl_audit_buffer", 10000);
	if (ring_cap > 0) {
		std::lock_guard<std::mutex> guard(ring_lock);
		ring.push_back(event);
		while (int64_t(ring.size()) > ring_cap) {
			ring.pop_front();
			dropped++;
			hooks->Counters().Add("acl.audit.dropped", {{"where", "ring"}});
		}
	}
	WriteFile(event);
}

void AuditPipeline::WriteFile(const AuditEvent &event) {
	auto path = Setting("acl_audit_sink", "");
	std::lock_guard<std::mutex> guard(file_lock);
	if (path != file_path) {
		file.reset();
		file_path = path;
	}
	if (path.empty()) {
		return;
	}
	auto instance = db.lock();
	if (!instance) {
		return;
	}
	try {
		if (!file) {
			auto &fs = FileSystem::GetFileSystem(*instance);
			file = fs.OpenFile(path, FileFlags::FILE_FLAGS_WRITE | FileFlags::FILE_FLAGS_APPEND |
			                             FileFlags::FILE_FLAGS_FILE_CREATE);
		}
		auto line = AuditEventJson(event) + "\n";
		file->Write(const_cast<char *>(line.data()), NumericCast<int64_t>(line.size()));
		file->Sync();
	} catch (std::exception &) {
		file.reset();
		dropped++;
		hooks->Counters().Add("acl.audit.dropped", {{"where", "sink"}});
		hooks->Counters().Add("acl.audit.sink_errors", {{"sink", "file"}});
	}
}

vector<AuditEvent> AuditPipeline::Ring() {
	std::lock_guard<std::mutex> guard(ring_lock);
	return vector<AuditEvent>(ring.begin(), ring.end());
}

int64_t AuditPipeline::Dropped() const {
	return dropped.load();
}

void AuditPipeline::Flush() {
	{
		std::unique_lock<std::mutex> guard(queue_lock);
		auto target = enqueued;
		drained_cv.wait(guard, [&]() { return handled >= target || stopping; });
	}
	for (auto &sink : hooks->Sinks()) {
		try {
			sink->Flush();
		} catch (...) {
			hooks->Counters().Add("acl.audit.sink_errors", {{"sink", "extension"}});
		}
	}
}

void AuditPipeline::Stop() {
	{
		std::lock_guard<std::mutex> guard(queue_lock);
		stopping = true;
	}
	queue_cv.notify_all();
	if (worker.joinable()) {
		worker.join();
	}
	std::lock_guard<std::mutex> guard(file_lock);
	file.reset();
}

//===--------------------------------------------------------------------===//
// JSON lines
//===--------------------------------------------------------------------===//

string AuditEventJson(const AuditEvent &event) {
	string out = "{";
	auto field = [&](const char *name, const string &value, bool quoted = true) {
		if (out.size() > 1) {
			out += ",";
		}
		out += string("\"") + name + "\":" + (quoted ? JsonQuote(value) : value);
	};
	field("ts_us", std::to_string(event.ts_us), false);
	field("seq", std::to_string(event.seq), false);
	field("node", event.node);
	field("level", AuditLevelName(event.level));
	field("door", event.door);
	field("session", event.session);
	field("subject", event.principal.subject);
	string roles = "[";
	for (idx_t i = 0; i < event.principal.roles.size(); i++) {
		roles += (i ? "," : "") + JsonQuote(event.principal.roles[i]);
	}
	roles += "]";
	field("roles", roles, false);
	field("kind", event.kind);
	field("statement", event.statement);
	string objects = "[";
	for (idx_t i = 0; i < event.objects.size(); i++) {
		objects += string(i ? "," : "") + "{\"name\":" + JsonQuote(event.objects[i].name) +
		           ",\"capability\":" + JsonQuote(event.objects[i].capability) + "}";
	}
	objects += "]";
	field("objects", objects, false);
	field("verdict", event.allowed ? "allowed" : "denied");
	field("reason_code", event.reason_code);
	field("reason", event.reason);
	field("correlation_id", event.correlation_id);
	field("traceparent", event.traceparent);
	field("rewrite_us", std::to_string(event.rewrite_us), false);
	field("rows", std::to_string(event.rows), false);
	field("duration_us", std::to_string(event.duration_us), false);
	field("detail", event.detail);
	out += "}";
	return out;
}

//===--------------------------------------------------------------------===//
// The SQL surface
//===--------------------------------------------------------------------===//

namespace {

//! Carried on the scalar functions that need the pipeline and nothing else
struct AuditPipelineInfo : ScalarFunctionInfo {
	explicit AuditPipelineInfo(shared_ptr<AuditPipeline> pipeline_p) : pipeline(std::move(pipeline_p)) {
	}
	shared_ptr<AuditPipeline> pipeline;
};

struct AuditFunctionInfo : TableFunctionInfo {
	explicit AuditFunctionInfo(shared_ptr<AuditPipeline> pipeline_p) : pipeline(std::move(pipeline_p)) {
	}
	shared_ptr<AuditPipeline> pipeline;
};

struct AuditBindData : TableFunctionData {
	explicit AuditBindData(shared_ptr<AuditPipeline> pipeline_p) : pipeline(std::move(pipeline_p)) {
	}
	shared_ptr<AuditPipeline> pipeline;
};

struct AuditEventsState : GlobalTableFunctionState {
	vector<AuditEvent> events;
	idx_t emitted = 0;
};

AuditPipeline &PipelineOf(ExpressionState &state) {
	return *state.expr.Cast<BoundFunctionExpression>()
	            .Function()
	            .GetExtraFunctionInfo()
	            .Cast<AuditPipelineInfo>()
	            .pipeline;
}

unique_ptr<FunctionData> AuditEventsBind(ClientContext &, TableFunctionBindInput &input,
                                         vector<LogicalType> &return_types, vector<Identifier> &names) {
	auto &info = input.info->Cast<AuditFunctionInfo>();
	auto column = [&](const char *name, const LogicalType &type) {
		names.push_back(Identifier(name));
		return_types.push_back(type);
	};
	column("ts", LogicalType::TIMESTAMP_TZ);
	column("seq", LogicalType::BIGINT);
	column("node", LogicalType::VARCHAR);
	column("level", LogicalType::VARCHAR);
	column("door", LogicalType::VARCHAR);
	column("session", LogicalType::VARCHAR);
	column("subject", LogicalType::VARCHAR);
	column("issuer", LogicalType::VARCHAR);
	column("roles", LogicalType::LIST(LogicalType::VARCHAR));
	column("kind", LogicalType::VARCHAR);
	column("statement", LogicalType::VARCHAR);
	column("objects", LogicalType::LIST(
	                      LogicalType::STRUCT({{"name", LogicalType::VARCHAR}, {"capability", LogicalType::VARCHAR}})));
	column("verdict", LogicalType::VARCHAR);
	column("reason_code", LogicalType::VARCHAR);
	column("reason", LogicalType::VARCHAR);
	column("correlation_id", LogicalType::VARCHAR);
	column("traceparent", LogicalType::VARCHAR);
	column("rewrite_us", LogicalType::INTEGER);
	column("rows", LogicalType::BIGINT);
	column("duration_us", LogicalType::BIGINT);
	column("detail", LogicalType::VARCHAR);
	return make_uniq<AuditBindData>(info.pipeline);
}

unique_ptr<GlobalTableFunctionState> AuditEventsInit(ClientContext &, TableFunctionInitInput &input) {
	auto state = make_uniq<AuditEventsState>();
	state->events = input.bind_data->Cast<AuditBindData>().pipeline->Ring();
	return std::move(state);
}

Value NullableVarchar(const string &value) {
	return value.empty() ? Value(LogicalType::VARCHAR) : Value(value);
}

Value NullableBigint(int64_t value) {
	return value < 0 ? Value(LogicalType::BIGINT) : Value::BIGINT(value);
}

void AuditEventsScan(ClientContext &, TableFunctionInput &data, DataChunk &output) {
	auto &state = data.global_state->Cast<AuditEventsState>();
	auto object_type = LogicalType::STRUCT({{"name", LogicalType::VARCHAR}, {"capability", LogicalType::VARCHAR}});
	idx_t count = 0;
	while (state.emitted < state.events.size() && count < STANDARD_VECTOR_SIZE) {
		auto &event = state.events[state.emitted++];
		idx_t col = 0;
		output.data[col++].SetValue(count, Value::TIMESTAMPTZ(timestamp_tz_t(event.ts_us)));
		output.data[col++].SetValue(count, Value::BIGINT(event.seq));
		output.data[col++].SetValue(count, Value(event.node));
		output.data[col++].SetValue(count, Value(AuditLevelName(event.level)));
		output.data[col++].SetValue(count, NullableVarchar(event.door));
		output.data[col++].SetValue(count, NullableVarchar(event.session));
		output.data[col++].SetValue(count, NullableVarchar(event.principal.subject));
		auto issuer = event.principal.claims.find("iss");
		output.data[col++].SetValue(count,
		                            NullableVarchar(issuer == event.principal.claims.end() ? "" : issuer->second));
		vector<Value> roles;
		for (auto &role : event.principal.roles) {
			roles.emplace_back(role);
		}
		output.data[col++].SetValue(count, Value::LIST(LogicalType::VARCHAR, std::move(roles)));
		output.data[col++].SetValue(count, Value(event.kind));
		output.data[col++].SetValue(count, NullableVarchar(event.statement));
		vector<Value> objects;
		for (auto &object : event.objects) {
			child_list_t<Value> fields;
			fields.emplace_back("name", Value(object.name));
			fields.emplace_back("capability", Value(object.capability));
			objects.push_back(Value::STRUCT(std::move(fields)));
		}
		output.data[col++].SetValue(count, Value::LIST(object_type, std::move(objects)));
		output.data[col++].SetValue(count, Value(event.allowed ? "allowed" : "denied"));
		output.data[col++].SetValue(count, NullableVarchar(event.reason_code));
		output.data[col++].SetValue(count, NullableVarchar(event.reason));
		output.data[col++].SetValue(count, NullableVarchar(event.correlation_id));
		output.data[col++].SetValue(count, NullableVarchar(event.traceparent));
		output.data[col++].SetValue(count, event.rewrite_us < 0
		                                       ? Value(LogicalType::INTEGER)
		                                       : Value::INTEGER(NumericCast<int32_t>(event.rewrite_us)));
		output.data[col++].SetValue(count, NullableBigint(event.rows));
		output.data[col++].SetValue(count, NullableBigint(event.duration_us));
		output.data[col++].SetValue(count, NullableVarchar(event.detail));
		count++;
	}
	output.SetChildCardinality(count);
}

struct MetricsState : GlobalTableFunctionState {
	vector<AuditMetric> metrics;
	idx_t emitted = 0;
};

unique_ptr<FunctionData> MetricsBind(ClientContext &, TableFunctionBindInput &input, vector<LogicalType> &return_types,
                                     vector<Identifier> &names) {
	auto &info = input.info->Cast<AuditFunctionInfo>();
	auto column = [&](const char *name, const LogicalType &type) {
		names.push_back(Identifier(name));
		return_types.push_back(type);
	};
	column("name", LogicalType::VARCHAR);
	column("kind", LogicalType::VARCHAR);
	column("attributes", LogicalType::VARCHAR);
	column("value", LogicalType::BIGINT);
	column("unit", LogicalType::VARCHAR);
	column("description", LogicalType::VARCHAR);
	return make_uniq<AuditBindData>(info.pipeline);
}

unique_ptr<GlobalTableFunctionState> MetricsInit(ClientContext &, TableFunctionInitInput &input) {
	auto state = make_uniq<MetricsState>();
	auto &hooks = input.bind_data->Cast<AuditBindData>().pipeline->Hooks();
	state->metrics = hooks.Counters().Snapshot();
	auto gauges = hooks.Gauges().Snapshot();
	state->metrics.insert(state->metrics.end(), gauges.begin(), gauges.end());
	std::sort(state->metrics.begin(), state->metrics.end(), [](const AuditMetric &a, const AuditMetric &b) {
		return a.name == b.name ? AuditAttributesKey(a.attributes) < AuditAttributesKey(b.attributes) : a.name < b.name;
	});
	return std::move(state);
}

void MetricsScan(ClientContext &, TableFunctionInput &data, DataChunk &output) {
	auto &state = data.global_state->Cast<MetricsState>();
	idx_t count = 0;
	while (state.emitted < state.metrics.size() && count < STANDARD_VECTOR_SIZE) {
		auto &metric = state.metrics[state.emitted++];
		string attributes = "{";
		for (auto &attribute : metric.attributes) {
			if (attributes.size() > 1) {
				attributes += ",";
			}
			attributes += JsonQuote(attribute.first) + ":" + JsonQuote(attribute.second);
		}
		attributes += "}";
		output.data[0].SetValue(count, Value(metric.name));
		output.data[1].SetValue(count, Value(metric.kind));
		output.data[2].SetValue(count, Value(attributes));
		output.data[3].SetValue(count, Value::BIGINT(metric.value));
		output.data[4].SetValue(count, Value(metric.unit));
		output.data[5].SetValue(count, NullableVarchar(metric.description));
		count++;
	}
	output.SetChildCardinality(count);
}

//! acl_audit_dropped(): how many events the queue, the ring or a sink lost since load
void AuditDroppedFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	result.Reference(Value::BIGINT(PipelineOf(state).Dropped()), count_t(args.size()));
}

//! acl_audit_flush(): wait until everything enqueued so far reached every sink (tests, shutdown)
void AuditFlushFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	PipelineOf(state).Flush();
	result.Reference(Value::BOOLEAN(true), count_t(args.size()));
}

//! acl_session_audit_level(id, level): the operator's per-session level (spec 069); '' inherits
void SessionAuditLevelFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	result.SetVectorType(VectorType::FLAT_VECTOR);
	for (idx_t row = 0; row < args.size(); row++) {
		auto id = RequiredArg(args, 0, row, "acl_session_audit_level", "session id");
		auto text = RequiredArg(args, 1, row, "acl_session_audit_level", "level");
		int8_t level = -1;
		if (!Trimmed(text).empty()) {
			AuditLevel parsed;
			if (!ParseAuditLevel(text, parsed)) {
				throw InvalidInputException(
				    "acl_session_audit_level: unknown level \"%s\" (off, denied, decisions, all)", text);
			}
			level = static_cast<int8_t>(parsed);
		}
		result.SetValue(row, Value::BOOLEAN(StoreOf(state).SetSessionAuditLevel(id, level)));
	}
}

} // namespace

void RegisterAclAudit(ExtensionLoader &loader, shared_ptr<PolicyStore> store, shared_ptr<AuditPipeline> pipeline) {
	// the states the store owns, read at snapshot time (spec 069: a gauge is a state, never an event)
	auto &gauges = pipeline->Hooks().Gauges();
	weak_ptr<PolicyStore> weak_store = store;
	auto with_store = [weak_store](const std::function<int64_t(PolicyStore &)> &read) {
		return [weak_store, read]() -> int64_t {
			auto locked = weak_store.lock();
			return locked ? read(*locked) : -1;
		};
	};
	gauges.Register("acl.sessions.live", {}, "1", "sessions alive right now",
	                with_store([](PolicyStore &s) { return int64_t(s.SessionCount()); }));
	gauges.Register("acl.sessions.max", {}, "1", "acl_max_sessions",
	                with_store([](PolicyStore &s) { return s.MaxSessions(); }));
	gauges.Register("acl.node.draining", {}, "1", "1 while acl_drain() is in effect",
	                with_store([](PolicyStore &s) { return int64_t(s.Draining() ? 1 : 0); }));
	gauges.Register("acl.policy.version", {}, "1", "the policy version the caches are keyed by (-1: no catalog)",
	                with_store([](PolicyStore &s) { return s.PolicyVersion(); }));
	gauges.Register("acl.policy.staleness", {}, "s",
	                "seconds since the last successful policy version check (-1: never)",
	                with_store([](PolicyStore &s) { return s.PolicyStalenessSeconds(); }));
	gauges.RegisterDynamic(
	    "acl.jwks.age", "s", "seconds since an issuer's keys were last read (-1: never)", [weak_store]() {
		    vector<std::pair<vector<std::pair<string, string>>, int64_t>> out;
		    auto locked = weak_store.lock();
		    if (!locked) {
			    return out;
		    }
		    for (auto &age : locked->JwksAges()) {
			    out.emplace_back(vector<std::pair<string, string>> {{"issuer", age.first}}, age.second);
		    }
		    return out;
	    });

	auto info = make_shared_ptr<AuditFunctionInfo>(pipeline);
	{
		TableFunction events(Identifier("acl_audit_events"), {}, AuditEventsScan, AuditEventsBind, AuditEventsInit);
		events.function_info = info;
		loader.RegisterFunction(events);
	}
	{
		TableFunction metrics(Identifier("acl_metrics"), {}, MetricsScan, MetricsBind, MetricsInit);
		metrics.function_info = info;
		loader.RegisterFunction(metrics);
	}
	auto pipeline_info = make_shared_ptr<AuditPipelineInfo>(pipeline);
	{
		ScalarFunction dropped(Identifier("acl_audit_dropped"), {}, LogicalType::BIGINT, AuditDroppedFunc);
		dropped.SetExtraFunctionInfo(pipeline_info);
		dropped.SetFallible();
		dropped.SetVolatile();
		loader.RegisterFunction(dropped);
	}
	{
		ScalarFunction flush(Identifier("acl_audit_flush"), {}, LogicalType::BOOLEAN, AuditFlushFunc);
		flush.SetExtraFunctionInfo(pipeline_info);
		flush.SetFallible();
		flush.SetVolatile();
		loader.RegisterFunction(flush);
	}
	{
		ScalarFunction level(Identifier("acl_session_audit_level"), {LogicalType::VARCHAR, LogicalType::VARCHAR},
		                     LogicalType::BOOLEAN, SessionAuditLevelFunc);
		MarkAclScalar(level, store);
		loader.RegisterFunction(level);
	}
}

} // namespace acl
} // namespace duckdb
