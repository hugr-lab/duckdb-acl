// spec 107: lineage facts for OpenLineage - see acl_lineage.hpp.
#include "acl_lineage.hpp"

#include "acl_audit_pipeline.hpp"
#include "acl_door_common.hpp"
#include "acl_policy.hpp"
#include "acl_policy_catalog.hpp"
#include "acl_lineage_sources.hpp"

#include "duckdb/common/types/uuid.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/planner/expression/bound_function_expression.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/catalog/catalog.hpp"
#include "duckdb/main/attached_database.hpp"
#include "duckdb/main/database_manager.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/connection.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/catalog/catalog_entry/table_catalog_entry.hpp"
#include "duckdb/parser/parser.hpp"
#include "duckdb/planner/operator/logical_get.hpp"
#include "duckdb/planner/planner.hpp"

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
void CheckRunRef(const char *name, const Value &value) {
	string error;
	if (!value.IsNull() && !LineageRunRefCheck(value.ToString(), error)) {
		throw InvalidInputException("%s: %s", name, error);
	}
}
void CheckParent(ClientContext &, SetScope, Value &value) {
	CheckRunRef("acl_lineage_parent", value);
}
void CheckRootParent(ClientContext &, SetScope, Value &value) {
	CheckRunRef("acl_lineage_root_parent", value);
}

} // namespace

bool LineageOn(DatabaseInstance &db) {
	// spec 112: the namespace is the cluster's, and there is no default - without it nothing is sent
	return InstanceSetting(db, "acl_lineage_level", "off") == "on" &&
	       !InstanceSetting(db, "acl_lineage_namespace", "").empty();
}

string LineageStatus(DatabaseInstance &db) {
	if (InstanceSetting(db, "acl_lineage_level", "off") != "on") {
		return "off";
	}
	if (InstanceSetting(db, "acl_lineage_namespace", "").empty()) {
		return "no namespace: set acl_lineage_namespace (the cluster's, e.g. ACL CLUSTER SET acl_lineage_namespace = "
		       "'acl://prod')";
	}
	return "on";
}

LineageSettings LineageSettings::Read(DatabaseInstance &db) {
	LineageSettings settings;
	settings.db = &db;
	settings.ns = InstanceSetting(db, "acl_lineage_namespace", "");
	settings.on = InstanceSetting(db, "acl_lineage_level", "off") == "on" && !settings.ns.empty();
	settings.identity = InstanceSetting(db, "acl_lineage_identity", "client");
	settings.sql = InstanceSetting(db, "acl_lineage_sql", "off") == "normalized";
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
	    "acl_lineage_physical",
	    "acl: lineage may name physical datasets (default true; false drops them and their edges)",
	    LogicalType::BOOLEAN, Value::BOOLEAN(true), CheckPhysical, SetScope::GLOBAL);
	config.AddExtensionOption("acl_lineage_max_edges", "acl: edges per lineage event before it is truncated",
	                          LogicalType::BIGINT, Value::BIGINT(4096), CheckMaxEdges, SetScope::GLOBAL);
	// spec 107 + 068: the client's lineage context - session scope, SET only on a session of its own;
	// spec 109: a parent is checked at the SET, so a client wired up wrong learns it at once
	config.AddExtensionOption(
	    "acl_lineage_parent",
	    "acl: the OpenLineage parent run of this session's statements (<namespace>/<job>/<runId>, a UUID runId)",
	    LogicalType::VARCHAR, Value(""), CheckParent);
	config.AddExtensionOption("acl_lineage_root_parent",
	                          "acl: the OpenLineage root parent run of this session's statements (the same form)",
	                          LogicalType::VARCHAR, Value(""), CheckRootParent);
	config.AddExtensionOption("acl_lineage_job", "acl: the OpenLineage job name of this session's statements",
	                          LogicalType::VARCHAR, Value(""));
}

bool LineageClientSetting(const string &name) {
	return StringUtil::CIEquals(name, "acl_lineage_parent") || StringUtil::CIEquals(name, "acl_lineage_root_parent") ||
	       StringUtil::CIEquals(name, "acl_lineage_job");
}

bool LineageIdentityClean(const string &identity) {
	auto scheme = identity.find("://");
	auto start = scheme == string::npos ? 0 : scheme + 3;
	auto end = identity.find_first_of("/?#", start);
	auto at = identity.find('@', start);
	return at == string::npos || (end != string::npos && at > end);
}

bool LineageSourceNameFor(DatabaseInstance &db, const string &catalog, const string &schema, const string &name,
                          string &out_ns, string &out_name, const string &declared) {
	auto attached = DatabaseManager::Get(db).GetDatabase(Identifier(catalog));
	// 1. a provider that owns the source (hugr_node: the platform's real addresses, a federated cluster)
	string why;
	auto sources = AclLineageSources::Reach(db.GetObjectCache(), why);
	if (sources) {
		LineageSourceDataset query;
		query.catalog = catalog;
		query.schema = schema;
		query.name = name;
		if (attached) {
			query.catalog_type = attached->GetCatalog().GetCatalogType();
		}
		LineageSourceName answer;
		if (sources->Name(query, answer) && LineageIdentityClean(answer.ns)) {
			out_ns = answer.ns;
			out_name = answer.name;
			return true;
		}
	}
	// 2. the identity the operator declared for the alias: `<scheme>://<host:port>[/<prefix>]`
	auto store = PolicyStore::Of(db);
	string identity;
	if (store && attached) {
		lock_guard<mutex> guard(store->lineage_sources_lock);
		auto entry = store->lineage_sources.find(catalog);
		if (entry != store->lineage_sources.end()) {
			if (!entry->second.bound) {
				entry->second.bound = true; // declared before its ATTACH: this is the attachment it meant
				entry->second.attached = attached;
			}
			auto declared_for = entry->second.attached.lock();
			if (declared_for.get() == attached.get()) {
				identity = entry->second.identity;
			} else {
				store->lineage_sources.erase(entry); // declared for an attachment that is gone
			}
		}
	}
	if (identity.empty() && LineageIdentityClean(declared) && declared.find("://") != string::npos) {
		identity = declared; // the ATTACH … LINEAGE being executed, its declaring call still to come
	}
	if (identity.empty()) {
		return false;
	}
	auto scheme = identity.find("://");
	auto path = identity.find('/', scheme == string::npos ? 0 : scheme + 3);
	out_ns = path == string::npos ? identity : identity.substr(0, path);
	auto prefix = path == string::npos ? string() : identity.substr(path + 1);
	while (!prefix.empty() && prefix.back() == '/') {
		prefix.pop_back();
	}
	prefix = StringUtil::Replace(prefix, "/", ".");
	vector<string> parts;
	for (auto &part : {prefix, schema, name}) {
		if (!part.empty()) {
			parts.push_back(part);
		}
	}
	out_name = StringUtil::Join(parts, ".");
	return true;
}

AuditLineageDataset LineageDatasetFor(const LineageDatasetKey &key, const LineageSettings &settings) {
	AuditLineageDataset dataset;
	if (key.kind == "virtual") {
		// spec 112: the cluster's namespace, the object as `<vcat>.<schema>.<object>` - OpenLineage's own
		// convention for a SQL endpoint, the schema always written
		string schema = key.schema;
		string object = key.name;
		if (schema.empty()) {
			auto dot = object.find('.');
			if (dot != string::npos) {
				schema = object.substr(0, dot);
				object = object.substr(dot + 1);
			}
		}
		dataset.ns = settings.ns;
		dataset.name = key.catalog + "." + (schema.empty() ? string("main") : schema) + "." + object;
		dataset.dataset_type = "TABLE";
	} else if (key.kind == "physical") {
		dataset.ns = settings.ns + "/source/" + key.catalog;
		dataset.name = key.schema.empty() ? key.name : key.schema + "." + key.name;
		auto db = settings.db; // the settings are const; the instance they were read from is not
		if (db) {
			// spec 112 §9: the source's identity, when its provider or its operator gave one
			string ns, name;
			if (LineageSourceNameFor(*db, key.catalog, key.schema, key.name, ns, name)) {
				dataset.ns = ns;
				dataset.name = name;
			}
		}
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

bool LineageRunRefCheck(const string &text, string &error) {
	if (text.empty()) {
		return true;
	}
	if (text.size() > 512) {
		// the bound every channel applies after this check: a longer value would lose its runId there
		error = "expected <namespace>/<job>/<runId>, the runId a UUID, at most 512 bytes";
		return false;
	}
	auto ref = ParseLineageRunRef(text);
	bool uuid = ref.run_id.size() == 36;
	for (idx_t i = 0; uuid && i < ref.run_id.size(); i++) {
		auto c = ref.run_id[i];
		uuid = (i == 8 || i == 13 || i == 18 || i == 23) ? c == '-' : isxdigit((unsigned char)c) != 0;
	}
	if (ref.ns.empty() || ref.job.empty() || !uuid) {
		error = "expected <namespace>/<job>/<runId>, the runId a UUID (OPENLINEAGE_PARENT_ID's form)";
		return false;
	}
	return true;
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
			if (dataset.schema.empty()) {
				// the fields written - one written from constants or from the client's stream has no
				// edge, and is written all the same
				for (auto &output : walk.outputs) {
					AuditLineageField field;
					field.name = output.name;
					dataset.schema.push_back(std::move(field));
				}
			}
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

bool WalkDefinition(DatabaseInstance &db, const string &sql, idx_t max_edges, LineageWalk &out) {
	try {
		Parser parser(ParserOptions::Builtin());
		parser.ParseQuery(sql);
		if (parser.statements.size() != 1) {
			return false;
		}
		Connection con(db);
		LineageWalkOptions options;
		options.max_edges = max_edges;
		options.classify = [](LogicalGet &get, LineageDatasetKey &key) {
			auto table = get.GetTable();
			if (!table) {
				return false;
			}
			key.kind = "physical";
			key.catalog = table->ParentCatalog().GetName().GetIdentifierName();
			key.schema = table->ParentSchema().name.GetIdentifierName();
			key.name = table->name.GetIdentifierName();
			return true;
		};
		bool walked = false;
		con.context->RunFunctionInTransaction([&]() {
			Planner planner(*con.context);
			planner.CreatePlan(std::move(parser.statements[0]));
			for (auto &name : planner.names) {
				options.output_names.push_back(name.GetIdentifierName());
			}
			out = WalkLineage(*planner.plan, options);
			walked = true;
		});
		return walked;
	} catch (std::exception &) {
		return false;
	}
}

void EmitDefinitionLineage(AuditPipeline &pipeline, DatabaseInstance &db, const string &vcat, const string &vname,
                           const string &dataset_type, const string &lifecycle, const LineageWalk *walk,
                           const vector<AuditLineageTag> &tags) {
	auto settings = LineageSettings::Read(db);
	if (!settings.on) {
		return;
	}
	LineageWalk defined;
	if (walk) {
		defined = *walk;
	} else {
		defined.approximate = lifecycle != "DROP";
	}
	// the object is the walk's target: its fields are the definition's outputs
	defined.has_target = true;
	defined.target.kind = "virtual";
	defined.target.catalog = vcat;
	defined.target.name = vname;
	defined.target_operation = lifecycle;
	auto lineage = LineageFromWalk(defined, settings);
	lineage->event_type = "DATASET";
	auto defined_as = LineageDatasetFor(defined.target, settings);
	for (auto &dataset : lineage->datasets) {
		if (!dataset.physical && dataset.ns == defined_as.ns && dataset.name == defined_as.name) {
			dataset.lifecycle = lifecycle;
			dataset.dataset_type = dataset_type;
			dataset.tags = tags; // its schema is the definition's outputs, filled by LineageFromWalk
		}
	}
	AuditEvent event;
	event.kind = "lineage";
	event.door = "admin";
	event.level = AuditLevel::ALL;
	event.recorded = true;
	event.lineage = std::move(lineage);
	pipeline.Emit(std::move(event));
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

struct LineageFlushInfo : ScalarFunctionInfo {
	LineageFlushInfo(weak_ptr<PolicyStore> store_p, shared_ptr<AuditPipeline> pipeline_p)
	    : store(std::move(store_p)), pipeline(std::move(pipeline_p)) {
	}
	weak_ptr<PolicyStore> store;
	shared_ptr<AuditPipeline> pipeline;
};

void LineageFlushFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &info = state.expr.Cast<BoundFunctionExpression>().Function().GetExtraFunctionInfo().Cast<LineageFlushInfo>();
	bool drained = true;
	auto store = info.store.lock();
	if (store && store->lineage_worker) {
		drained = FlushLineageWorker(*store->lineage_worker);
	}
	drained = info.pipeline->Flush() && drained;
	result.Reference(Value::BOOLEAN(drained), count_t(args.size()));
}

//! acl_lineage_resend([vcat]): every virtual object of a catalog (all catalogs without one) sent again
//! as its DatasetEvent - what a transport that starts on an empty catalog asks for. Answers the count.
void LineageResendFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &info = state.expr.Cast<BoundFunctionExpression>().Function().GetExtraFunctionInfo().Cast<LineageFlushInfo>();
	auto store = info.store.lock();
	if (!store || !store->catalog) {
		throw InvalidInputException("acl_lineage_resend needs a policy catalog (acl_use_db)");
	}
	string only =
	    args.ColumnCount() > 0 && !args.data[0].GetValue(0).IsNull() ? args.data[0].GetValue(0).ToString() : string();
	auto filter = only.empty() ? string() : " AND \"vcat\" = '" + StringUtil::Replace(only, "'", "''") + "'";
	// every virtual table and view, and every table function
	auto objects_sql = "SELECT \"vcat\" FROM " + store->catalog->Tbl("relations") + " WHERE true" + filter +
	                   " UNION ALL SELECT \"vcat\" FROM " + store->catalog->Tbl("functions") +
	                   " WHERE \"kind\" = 'table'" + filter;
	auto rows = store->catalog->Query("SELECT \"vcat\", count(*) FROM (" + objects_sql + ") GROUP BY 1 ORDER BY 1");
	int64_t count = 0;
	for (idx_t i = 0; i < rows->RowCount(); i++) {
		auto vcat = rows->Collection().GetValue(0, i).ToString();
		count += rows->Collection().GetValue(1, i).GetValue<int64_t>();
		store->NoteGrantLineage(vcat); // queued: acl_lineage_flush() waits for it
	}
	result.Reference(Value::BIGINT(count), count_t(args.size()));
}

//! acl_lineage_status(): why lineage is or is not sent (spec 112) - the operator's
void LineageStatusFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &context = state.GetContext();
	result.Reference(Value(LineageStatus(*context.db)), count_t(args.size()));
}

//! acl_lineage_source(alias, identity): the identity the operator declares for an attached source
//! (spec 112 §9) - `<scheme>://<host:port>[/<prefix>]`, the name everyone else knows it by; NULL
//! clears it. Kept in the instance's memory, like the ATTACH it describes. Answers the identity now
//! in force for the alias ('' for none).
void LineageSourceFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &info = state.expr.Cast<BoundFunctionExpression>().Function().GetExtraFunctionInfo().Cast<LineageFlushInfo>();
	auto store = info.store.lock();
	if (!store) {
		throw InvalidInputException("acl_lineage_source: the policy store is gone");
	}
	for (idx_t row = 0; row < args.size(); row++) {
		auto alias_value = args.data[0].GetValue(row);
		if (alias_value.IsNull() || alias_value.ToString().empty()) {
			throw InvalidInputException("acl_lineage_source: the alias of an attached source is required");
		}
		auto alias = alias_value.ToString();
		// may come before its ATTACH (a bootstrap's order is its own); never names the node's own catalogs
		auto attached = DatabaseManager::Get(*state.GetContext().db).GetDatabase(Identifier(alias));
		if (attached && (attached->IsSystem() || attached->IsTemporary())) {
			throw InvalidInputException("acl_lineage_source: '%s' is no attached source", alias);
		}
		auto identity_value = args.data[1].GetValue(row);
		string identity = identity_value.IsNull() ? string() : identity_value.ToString();
		StringUtil::Trim(identity);
		if (!identity.empty()) {
			if (identity.find("://") == string::npos) {
				throw InvalidInputException("acl_lineage_source: the identity is a source's address, "
				                            "<scheme>://<host:port>[/<database>] (OpenLineage's naming)");
			}
			if (!LineageIdentityClean(identity)) {
				throw InvalidInputException("acl_lineage_source: the identity names a source, never a credential - "
				                            "no user:password@ in it");
			}
		}
		{
			lock_guard<mutex> guard(store->lineage_sources_lock);
			if (identity.empty()) {
				store->lineage_sources.erase(alias);
			} else {
				PolicyStore::LineageSourceIdentity declared;
				declared.identity = identity;
				declared.bound = attached != nullptr;
				declared.attached = attached;
				store->lineage_sources[alias] = std::move(declared);
			}
		}
		result.SetValue(row, Value(identity));
	}
}

void RegisterAclLineage(ExtensionLoader &loader, const shared_ptr<PolicyStore> &store,
                        const shared_ptr<AuditPipeline> &pipeline) {
	{
		ScalarFunction status(Identifier("acl_lineage_status"), {}, LogicalType::VARCHAR, LineageStatusFunc);
		status.SetFallible();
		status.SetVolatile();
		loader.RegisterFunction(status);
	}
	{
		ScalarFunction source(Identifier("acl_lineage_source"), {LogicalType::VARCHAR, LogicalType::VARCHAR},
		                      LogicalType::VARCHAR, LineageSourceFunc);
		source.SetExtraFunctionInfo(make_shared_ptr<LineageFlushInfo>(store, pipeline));
		source.SetFallible();
		source.SetVolatile();
		source.SetNullHandling(FunctionNullHandling::SPECIAL_HANDLING);
		loader.RegisterFunction(source);
	}
	for (auto arity : {0, 1}) {
		vector<LogicalType> arguments;
		if (arity == 1) {
			arguments.push_back(LogicalType::VARCHAR);
		}
		ScalarFunction resend(Identifier("acl_lineage_resend"), arguments, LogicalType::BIGINT, LineageResendFunc);
		resend.SetExtraFunctionInfo(make_shared_ptr<LineageFlushInfo>(store, pipeline));
		resend.SetFallible();
		resend.SetVolatile();
		loader.RegisterFunction(resend);
	}
	{
		ScalarFunction flush(Identifier("acl_lineage_flush"), {}, LogicalType::BOOLEAN, LineageFlushFunc);
		flush.SetExtraFunctionInfo(make_shared_ptr<LineageFlushInfo>(store, pipeline));
		flush.SetFallible();
		flush.SetVolatile();
		loader.RegisterFunction(flush);
	}
	TableFunction events(Identifier("acl_lineage_events"), {}, LineageEventsScan, LineageEventsBind, LineageEventsInit);
	events.function_info = make_shared_ptr<LineageFunctionInfo>(pipeline);
	loader.RegisterFunction(events);
}

} // namespace acl
} // namespace duckdb
