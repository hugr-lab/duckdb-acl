// spec 107: lineage facts for OpenLineage - see acl_lineage.hpp.
#include "acl_lineage.hpp"

#include "acl_audit_pipeline.hpp"
#include "acl_door_common.hpp"

#include "duckdb/common/types/uuid.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/extension/extension_loader.hpp"

namespace duckdb {
namespace acl {

namespace {

string InstanceSetting(DatabaseInstance &db, const char *name, const string &fallback) {
	Value value;
	if (!db.TryGetCurrentSetting(name, value) || value.IsNull()) {
		return fallback;
	}
	return value.ToString();
}

//! A GLOBAL option whose value is one of a fixed set (lower-cased on the way in). A callback is a plain
//! function pointer, so each choice has its own.
void RequireChoice(const char *option, SetScope scope, Value &value, std::initializer_list<const char *> allowed) {
	if (scope != SetScope::GLOBAL) {
		throw InvalidInputException("%s is global - use SET GLOBAL", option);
	}
	auto lowered = value.IsNull() ? string() : StringUtil::Lower(value.ToString());
	string listed;
	for (auto candidate : allowed) {
		if (lowered == candidate) {
			value = Value(lowered);
			return;
		}
		listed += (listed.empty() ? "" : ", ") + string(candidate);
	}
	throw InvalidInputException("%s is one of %s, not \"%s\"", option, listed,
	                            value.IsNull() ? "NULL" : value.ToString());
}

void RequireGlobal(const char *option, SetScope scope) {
	if (scope != SetScope::GLOBAL) {
		throw InvalidInputException("%s is global - use SET GLOBAL", option);
	}
}

void CheckLevel(ClientContext &, SetScope scope, Value &value) {
	RequireChoice("acl_lineage_level", scope, value, {"off", "on"});
}
void CheckIdentity(ClientContext &, SetScope scope, Value &value) {
	RequireChoice("acl_lineage_identity", scope, value, {"none", "client", "subject"});
}
void CheckSql(ClientContext &, SetScope scope, Value &value) {
	RequireChoice("acl_lineage_sql", scope, value, {"off", "normalized"});
}
void CheckRoles(ClientContext &, SetScope scope, Value &value) {
	RequireChoice("acl_lineage_roles", scope, value, {"tags", "datasets"});
}
void CheckBuffer(ClientContext &, SetScope scope, Value &) {
	RequireGlobal("acl_lineage_buffer", scope);
}
void CheckNamespace(ClientContext &, SetScope scope, Value &) {
	RequireGlobal("acl_lineage_namespace", scope);
}
void CheckPhysical(ClientContext &, SetScope scope, Value &) {
	RequireGlobal("acl_lineage_physical", scope);
}
void CheckMaxEdges(ClientContext &, SetScope scope, Value &) {
	RequireGlobal("acl_lineage_max_edges", scope);
}

} // namespace

LineageSettings LineageSettings::Read(DatabaseInstance &db) {
	LineageSettings settings;
	settings.on = InstanceSetting(db, "acl_lineage_level", "off") == "on";
	settings.ns = InstanceSetting(db, "acl_lineage_namespace", "");
	if (settings.ns.empty()) {
		auto group = InstanceSetting(db, "acl_node_group", "");
		settings.ns = "acl://" + (group.empty() ? string("default") : group);
	}
	settings.identity = InstanceSetting(db, "acl_lineage_identity", "client");
	settings.sql = InstanceSetting(db, "acl_lineage_sql", "off") == "normalized";
	settings.role_datasets = InstanceSetting(db, "acl_lineage_roles", "tags") == "datasets";
	settings.physical = StringUtil::Lower(InstanceSetting(db, "acl_lineage_physical", "true")) == "true";
	auto max_edges = InstanceSetting(db, "acl_lineage_max_edges", "4096");
	try {
		auto parsed = std::stoll(max_edges);
		settings.max_edges = parsed > 0 ? idx_t(parsed) : idx_t(4096);
	} catch (...) {
		settings.max_edges = 4096;
	}
	return settings;
}

void AddLineageOptions(DBConfig &config) {
	config.AddExtensionOption("acl_lineage_level",
	                          "acl: emit lineage facts (spec 107) - what the node defines and what it writes - for "
	                          "OpenLineage: off (default) or on",
	                          LogicalType::VARCHAR, Value("off"), CheckLevel, SetScope::GLOBAL);
	config.AddExtensionOption("acl_lineage_buffer",
	                          "acl: how many of the newest lineage events acl_lineage_events() holds",
	                          LogicalType::BIGINT, Value::BIGINT(1000), CheckBuffer, SetScope::GLOBAL);
	config.AddExtensionOption(
	    "acl_lineage_namespace",
	    "acl: the OpenLineage namespace prefix of this node's datasets ('' = acl://<acl_node_group "
	    "or default>)",
	    LogicalType::VARCHAR, Value(""), CheckNamespace, SetScope::GLOBAL);
	config.AddExtensionOption("acl_lineage_identity",
	                          "acl: who a lineage run names - none, client (the client, issuer, roles, door, node "
	                          "group; default) or subject (plus the token's sub)",
	                          LogicalType::VARCHAR, Value("client"), CheckIdentity, SetScope::GLOBAL);
	config.AddExtensionOption("acl_lineage_sql",
	                          "acl: the SQL facet - off (default) or normalized (the statement as written, every "
	                          "constant a ?)",
	                          LogicalType::VARCHAR, Value("off"), CheckSql, SetScope::GLOBAL);
	config.AddExtensionOption(
	    "acl_lineage_roles", "acl: per-role visibility - tags on the canonical dataset (default) or a dataset per role",
	    LogicalType::VARCHAR, Value("tags"), CheckRoles, SetScope::GLOBAL);
	config.AddExtensionOption(
	    "acl_lineage_physical",
	    "acl: lineage may name physical datasets (default true; false drops them and their edges)",
	    LogicalType::BOOLEAN, Value::BOOLEAN(true), CheckPhysical, SetScope::GLOBAL);
	config.AddExtensionOption("acl_lineage_max_edges", "acl: edges per lineage event before it is truncated",
	                          LogicalType::BIGINT, Value::BIGINT(4096), CheckMaxEdges, SetScope::GLOBAL);
	// spec 107 + 068: the client's lineage context - session scope, SET only on a session of its own
	config.AddExtensionOption(
	    "acl_lineage_parent",
	    "acl: the OpenLineage parent run of this session's statements (<namespace>/<job>/<runId>)",
	    LogicalType::VARCHAR, Value(""));
	config.AddExtensionOption("acl_lineage_root_parent",
	                          "acl: the OpenLineage root parent run of this session's statements", LogicalType::VARCHAR,
	                          Value(""));
	config.AddExtensionOption("acl_lineage_job", "acl: the OpenLineage job name of this session's statements",
	                          LogicalType::VARCHAR, Value(""));
}

bool LineageClientSetting(const string &name) {
	return StringUtil::CIEquals(name, "acl_lineage_parent") || StringUtil::CIEquals(name, "acl_lineage_root_parent") ||
	       StringUtil::CIEquals(name, "acl_lineage_job");
}

AuditLineageDataset LineageDatasetFor(const LineageDatasetKey &key, const LineageSettings &settings) {
	AuditLineageDataset dataset;
	if (key.kind == "virtual") {
		dataset.ns = settings.ns + "/" + key.catalog;
		dataset.name = key.schema.empty() ? key.name : key.schema + "." + key.name;
		dataset.dataset_type = "TABLE";
	} else if (key.kind == "physical") {
		dataset.ns = settings.ns + "/source/" + key.catalog;
		dataset.name = key.schema.empty() ? key.name : key.schema + "." + key.name;
		dataset.dataset_type = "TABLE";
		dataset.physical = true;
	} else if (key.kind == "file") {
		dataset.ns = "file";
		dataset.name = key.name;
		dataset.dataset_type = "FILE";
		dataset.physical = true;
	} else {
		dataset.ns = settings.ns + "/function";
		dataset.name = key.catalog.empty() ? key.name : key.catalog + "." + key.name;
		dataset.dataset_type = "FUNCTION";
	}
	return dataset;
}

AuditLineageRunRef ParseLineageRunRef(const string &text) {
	AuditLineageRunRef ref;
	auto last = text.rfind('/');
	if (last == string::npos || last == 0 || last + 1 >= text.size()) {
		return ref;
	}
	auto middle = text.rfind('/', last - 1);
	if (middle == string::npos || middle == 0) {
		return ref;
	}
	ref.ns = text.substr(0, middle);
	ref.job = text.substr(middle + 1, last - middle - 1);
	ref.run_id = text.substr(last + 1);
	if (ref.job.empty()) {
		return AuditLineageRunRef();
	}
	return ref;
}

shared_ptr<AuditLineage> LineageFromWalk(const LineageWalk &walk, const LineageSettings &settings) {
	auto lineage = make_shared_ptr<AuditLineage>();
	vector<int32_t> index(walk.datasets.size(), -1);
	for (idx_t i = 0; i < walk.datasets.size(); i++) {
		auto dataset = LineageDatasetFor(walk.datasets[i], settings);
		if (dataset.physical && !settings.physical) {
			continue;
		}
		index[i] = int32_t(lineage->datasets.size());
		lineage->datasets.push_back(std::move(dataset));
		lineage->inputs.push_back(index[i]);
	}
	int32_t target = -1;
	if (walk.has_target) {
		auto dataset = LineageDatasetFor(walk.target, settings);
		if (!dataset.physical || settings.physical) {
			target = int32_t(lineage->datasets.size());
			lineage->datasets.push_back(std::move(dataset));
			lineage->outputs.push_back(target);
		}
	}
	auto add_edge = [&](const string &field, const LineageContribution &source) {
		if (source.dataset >= index.size() || index[source.dataset] < 0 || target < 0) {
			return;
		}
		AuditLineageEdge edge;
		edge.target = target;
		edge.target_field = field;
		edge.source = index[source.dataset];
		edge.source_field = source.field;
		edge.type = source.type;
		edge.subtype = source.subtype;
		edge.masking = source.masking;
		lineage->edges.push_back(std::move(edge));
	};
	for (auto &output : walk.outputs) {
		for (auto &source : output.sources) {
			add_edge(output.name, source);
		}
	}
	for (auto &source : walk.whole_target) {
		add_edge(string(), source);
	}
	lineage->approximate = walk.approximate;
	lineage->truncated = walk.truncated;
	return lineage;
}

namespace {

string JsonFields(const vector<AuditLineageField> &fields) {
	string out = "[";
	for (idx_t i = 0; i < fields.size(); i++) {
		out +=
		    string(i ? "," : "") + "{\"name\":" + JsonQuote(fields[i].name) + ",\"type\":" + JsonQuote(fields[i].type);
		if (!fields[i].fields.empty()) {
			out += ",\"fields\":" + JsonFields(fields[i].fields);
		}
		out += "}";
	}
	return out + "]";
}

string JsonRunRef(const AuditLineageRunRef &ref) {
	if (ref.Empty()) {
		return "null";
	}
	return "{\"namespace\":" + JsonQuote(ref.ns) + ",\"job\":" + JsonQuote(ref.job) +
	       ",\"run_id\":" + JsonQuote(ref.run_id) + "}";
}

string JsonIndices(const vector<int32_t> &indices) {
	string out = "[";
	for (idx_t i = 0; i < indices.size(); i++) {
		out += (i ? "," : "") + std::to_string(indices[i]);
	}
	return out + "]";
}

} // namespace

string AuditLineageJson(const AuditLineage &lineage) {
	string out = "{\"event_type\":" + JsonQuote(lineage.event_type);
	out += ",\"run_id\":" + JsonQuote(lineage.run_id);
	out += ",\"job\":{\"namespace\":" + JsonQuote(lineage.job_ns) + ",\"name\":" + JsonQuote(lineage.job_name) + "}";
	out += ",\"parent\":" + JsonRunRef(lineage.parent);
	out += ",\"root_parent\":" + JsonRunRef(lineage.root_parent);
	out += ",\"datasets\":[";
	for (idx_t i = 0; i < lineage.datasets.size(); i++) {
		auto &dataset = lineage.datasets[i];
		out += string(i ? "," : "") + "{\"namespace\":" + JsonQuote(dataset.ns) +
		       ",\"name\":" + JsonQuote(dataset.name) + ",\"type\":" + JsonQuote(dataset.dataset_type) +
		       ",\"physical\":" + (dataset.physical ? "true" : "false");
		if (!dataset.lifecycle.empty()) {
			out += ",\"lifecycle\":" + JsonQuote(dataset.lifecycle);
		}
		if (!dataset.schema.empty()) {
			out += ",\"schema\":" + JsonFields(dataset.schema);
		}
		if (!dataset.symlinks.empty()) {
			out += ",\"symlinks\":[";
			for (idx_t s = 0; s < dataset.symlinks.size(); s++) {
				out += string(s ? "," : "") + "{\"namespace\":" + JsonQuote(dataset.symlinks[s].ns) +
				       ",\"name\":" + JsonQuote(dataset.symlinks[s].name) +
				       ",\"type\":" + JsonQuote(dataset.symlinks[s].type) + "}";
			}
			out += "]";
		}
		if (!dataset.tags.empty()) {
			out += ",\"tags\":[";
			for (idx_t t = 0; t < dataset.tags.size(); t++) {
				out += string(t ? "," : "") + "{\"key\":" + JsonQuote(dataset.tags[t].key) +
				       ",\"value\":" + JsonQuote(dataset.tags[t].value);
				if (!dataset.tags[t].field.empty()) {
					out += ",\"field\":" + JsonQuote(dataset.tags[t].field);
				}
				out += "}";
			}
			out += "]";
		}
		out += "}";
	}
	out += "],\"inputs\":" + JsonIndices(lineage.inputs) + ",\"outputs\":" + JsonIndices(lineage.outputs);
	out += ",\"edges\":[";
	for (idx_t i = 0; i < lineage.edges.size(); i++) {
		auto &edge = lineage.edges[i];
		out += string(i ? "," : "") + "{\"target\":" + std::to_string(edge.target) +
		       ",\"target_field\":" + JsonQuote(edge.target_field) + ",\"source\":" + std::to_string(edge.source) +
		       ",\"source_field\":" + JsonQuote(edge.source_field) + ",\"type\":" + JsonQuote(edge.type) +
		       ",\"subtype\":" + JsonQuote(edge.subtype) + ",\"masking\":" + (edge.masking ? "true" : "false") + "}";
	}
	out += "]";
	if (!lineage.sql.empty()) {
		out += ",\"sql\":" + JsonQuote(lineage.sql) + ",\"dialect\":" + JsonQuote(lineage.dialect);
	}
	auto optional = [&](const char *name, const string &value) {
		if (!value.empty()) {
			out += string(",\"") + name + "\":" + JsonQuote(value);
		}
	};
	optional("client", lineage.client);
	optional("issuer", lineage.issuer);
	optional("subject", lineage.subject);
	optional("node_group", lineage.node_group);
	if (!lineage.roles.empty()) {
		out += ",\"roles\":[";
		for (idx_t i = 0; i < lineage.roles.size(); i++) {
			out += (i ? "," : "") + JsonQuote(lineage.roles[i]);
		}
		out += "]";
	}
	out += string(",\"approximate\":") + (lineage.approximate ? "true" : "false");
	out += string(",\"truncated\":") + (lineage.truncated ? "true" : "false");
	if (lineage.dropped >= 0) {
		out += ",\"dropped\":" + std::to_string(lineage.dropped);
	}
	return out + "}";
}

string LineageRunId() {
	return UUID::ToString(UUID::GenerateRandomUUID());
}

namespace {

struct LineageFunctionInfo : TableFunctionInfo {
	explicit LineageFunctionInfo(shared_ptr<AuditPipeline> pipeline_p) : pipeline(std::move(pipeline_p)) {
	}
	shared_ptr<AuditPipeline> pipeline;
};

struct LineageBindData : TableFunctionData {
	explicit LineageBindData(shared_ptr<AuditPipeline> pipeline_p) : pipeline(std::move(pipeline_p)) {
	}
	shared_ptr<AuditPipeline> pipeline;
};

struct LineageEventsState : GlobalTableFunctionState {
	vector<AuditEvent> events;
	idx_t emitted = 0;
};

unique_ptr<FunctionData> LineageEventsBind(ClientContext &, TableFunctionBindInput &input,
                                           vector<LogicalType> &return_types, vector<Identifier> &names) {
	auto column = [&](const char *name, const LogicalType &type) {
		names.push_back(Identifier(name));
		return_types.push_back(type);
	};
	column("ts", LogicalType::TIMESTAMP_TZ);
	column("seq", LogicalType::BIGINT);
	column("node", LogicalType::VARCHAR);
	column("event_type", LogicalType::VARCHAR);
	column("job_namespace", LogicalType::VARCHAR);
	column("job_name", LogicalType::VARCHAR);
	column("run_id", LogicalType::VARCHAR);
	column("parent", LogicalType::VARCHAR);
	column("approximate", LogicalType::BOOLEAN);
	column("truncated", LogicalType::BOOLEAN);
	column("payload", LogicalType::JSON());
	return make_uniq<LineageBindData>(input.info->Cast<LineageFunctionInfo>().pipeline);
}

unique_ptr<GlobalTableFunctionState> LineageEventsInit(ClientContext &, TableFunctionInitInput &input) {
	auto state = make_uniq<LineageEventsState>();
	state->events = input.bind_data->Cast<LineageBindData>().pipeline->LineageRing();
	return std::move(state);
}

Value OrNull(const string &value) {
	return value.empty() ? Value(LogicalType::VARCHAR) : Value(value);
}

void LineageEventsScan(ClientContext &, TableFunctionInput &data, DataChunk &output) {
	auto &state = data.global_state->Cast<LineageEventsState>();
	idx_t count = 0;
	while (state.emitted < state.events.size() && count < STANDARD_VECTOR_SIZE) {
		auto &event = state.events[state.emitted++];
		if (!event.lineage) {
			continue;
		}
		auto &lineage = *event.lineage;
		idx_t col = 0;
		output.data[col++].SetValue(count, Value::TIMESTAMPTZ(timestamp_tz_t(event.ts_us)));
		output.data[col++].SetValue(count, Value::BIGINT(event.seq));
		output.data[col++].SetValue(count, Value(event.node));
		output.data[col++].SetValue(count, Value(lineage.event_type));
		output.data[col++].SetValue(count, OrNull(lineage.job_ns));
		output.data[col++].SetValue(count, OrNull(lineage.job_name));
		output.data[col++].SetValue(count, OrNull(lineage.run_id));
		output.data[col++].SetValue(count, lineage.parent.Empty() ? Value(LogicalType::VARCHAR)
		                                                          : Value(lineage.parent.ns + "/" + lineage.parent.job +
		                                                                  "/" + lineage.parent.run_id));
		output.data[col++].SetValue(count, Value::BOOLEAN(lineage.approximate));
		output.data[col++].SetValue(count, Value::BOOLEAN(lineage.truncated));
		output.data[col++].SetValue(count, Value(AuditLineageJson(lineage)));
		count++;
	}
	output.SetChildCardinality(count);
}

} // namespace

void RegisterAclLineage(ExtensionLoader &loader, const shared_ptr<AuditPipeline> &pipeline) {
	TableFunction events(Identifier("acl_lineage_events"), {}, LineageEventsScan, LineageEventsBind, LineageEventsInit);
	events.function_info = make_shared_ptr<LineageFunctionInfo>(pipeline);
	loader.RegisterFunction(events);
}

} // namespace acl
} // namespace duckdb
