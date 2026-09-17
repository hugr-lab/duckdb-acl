// Introspection over the active policy source (spec 010 part 3): `acl_*` table functions that answer
// "what does this policy source hold?" for an operator. They read the *active* source, so the same
// call works whichever backend is configured, and they refuse rather than return an empty set when a
// source cannot enumerate - on an admin surface, silence reads as "nothing is configured".
//
// The shape of a listing follows the source: the bind step reads the rows and takes the column names
// and types from the result, so nothing here declares a schema that could drift from the storage.
//
// Reachability: every `acl_*` name is denied inside a principal's query (spec 009), so these are for
// the native context and for the gateway's own connection.

#include "acl_introspection.hpp"

#include "acl_door_common.hpp"
#include "duckdb/common/types/timestamp.hpp"
#include "duckdb/execution/expression_executor_state.hpp"
#include "duckdb/function/function_set.hpp"
#include "duckdb/planner/expression/bound_function_expression.hpp"

#include "duckdb/common/exception/binder_exception.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/main/connection.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/extension/extension_loader.hpp"

#include <chrono>
#include <set>

namespace duckdb {
namespace acl {
namespace {

struct AclIntrospectionInfo : TableFunctionInfo {
	AclIntrospectionInfo(shared_ptr<PolicyStore> store_p, string listing_p)
	    : store(std::move(store_p)), listing(std::move(listing_p)) {
	}
	shared_ptr<PolicyStore> store;
	string listing;
};

struct AclIntrospectionBindData : TableFunctionData {
	AclIntrospectionBindData(shared_ptr<PolicyStore> store_p, string listing_p)
	    : store(std::move(store_p)), listing(std::move(listing_p)) {
	}
	shared_ptr<PolicyStore> store;
	string listing;
};

struct AclIntrospectionState : GlobalTableFunctionState {
	explicit AclIntrospectionState(IntrospectionRows rows_p) : rows(std::move(rows_p)) {
	}
	IntrospectionRows rows;
	idx_t emitted = 0;
};

//! Bind asks the source for the listing's *shape* only: the column names and types come from the
//! result, so nothing here declares a schema that could drift from the storage.
unique_ptr<FunctionData> AclIntrospectionBind(ClientContext &, TableFunctionBindInput &input,
                                              vector<LogicalType> &return_types, vector<Identifier> &names) {
	if (!input.info) {
		throw BinderException("acl: introspection function without its policy store");
	}
	auto &info = input.info->Cast<AclIntrospectionInfo>();
	auto shape = info.store->Introspect(info.listing);
	return_types = shape.types;
	for (auto &name : shape.names) {
		names.push_back(Identifier(name));
	}
	return make_uniq<AclIntrospectionBindData>(info.store, info.listing);
}

//! The rows are read per execution, not at bind: a policy read through a prepared statement must
//! show the policy as it is now, and binding once would freeze it at the moment of preparation.
unique_ptr<GlobalTableFunctionState> AclIntrospectionInit(ClientContext &, TableFunctionInitInput &input) {
	auto &bind_data = input.bind_data->Cast<AclIntrospectionBindData>();
	return make_uniq<AclIntrospectionState>(bind_data.store->Introspect(bind_data.listing));
}

void AclIntrospectionScan(ClientContext &, TableFunctionInput &data, DataChunk &output) {
	auto &state = data.global_state->Cast<AclIntrospectionState>();
	idx_t count = 0;
	while (state.emitted < state.rows.rows.size() && count < STANDARD_VECTOR_SIZE) {
		auto &row = state.rows.rows[state.emitted++];
		for (idx_t col = 0; col < row.size() && col < output.ColumnCount(); col++) {
			output.data[col].SetValue(count, row[col]);
		}
		count++;
	}
	output.SetChildCardinality(count);
}

//! spec 071: acl_jwks_cache() - what the node trusts right now, one row per issuer that reads its
//! keys from a location: the location, whether it is allowed on this node now, when it was read,
//! what the last attempt said, and the public names of the keys (never the keys)
struct JwksCacheBindData : FunctionData {
	shared_ptr<PolicyStore> store;
	unique_ptr<FunctionData> Copy() const override {
		auto copy = make_uniq<JwksCacheBindData>();
		copy->store = store;
		return std::move(copy);
	}
	bool Equals(const FunctionData &) const override {
		return true;
	}
};

struct JwksCacheState : GlobalTableFunctionState {
	vector<PolicyStore::JwksCacheRow> rows;
	idx_t next = 0;
};

unique_ptr<FunctionData> JwksCacheBind(ClientContext &, TableFunctionBindInput &input,
                                       vector<LogicalType> &return_types, vector<Identifier> &names) {
	auto column = [&](const char *name, const LogicalType &type) {
		names.push_back(Identifier(name));
		return_types.push_back(type);
	};
	column("issuer", LogicalType::VARCHAR);
	column("location", LogicalType::VARCHAR);
	column("allowed", LogicalType::BOOLEAN);
	column("fetched_at", LogicalType::TIMESTAMP);
	column("age_seconds", LogicalType::BIGINT);
	column("last_tried_at", LogicalType::TIMESTAMP);
	column("error", LogicalType::VARCHAR);
	column("keys", LogicalType::BIGINT);
	column("kids", LogicalType::LIST(LogicalType::VARCHAR));
	auto bind = make_uniq<JwksCacheBindData>();
	bind->store = input.info->Cast<AclIntrospectionInfo>().store;
	return std::move(bind);
}

unique_ptr<GlobalTableFunctionState> JwksCacheInit(ClientContext &, TableFunctionInitInput &input) {
	auto state = make_uniq<JwksCacheState>();
	state->rows = input.bind_data->Cast<JwksCacheBindData>().store->JwksCacheRows();
	return std::move(state);
}

void JwksCacheScan(ClientContext &, TableFunctionInput &data, DataChunk &output) {
	auto &state = data.global_state->Cast<JwksCacheState>();
	auto now =
	    std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
	auto stamp = [](int64_t seconds) {
		return seconds > 0 ? Value::TIMESTAMP(Timestamp::FromEpochSeconds(seconds)) : Value(LogicalType::TIMESTAMP);
	};
	idx_t count = 0;
	while (state.next < state.rows.size() && count < STANDARD_VECTOR_SIZE) {
		auto &row = state.rows[state.next++];
		output.data[0].SetValue(count, Value(row.issuer));
		output.data[1].SetValue(count, Value(row.location));
		output.data[2].SetValue(count, Value::BOOLEAN(row.allowed));
		output.data[3].SetValue(count, stamp(row.fetched_at));
		output.data[4].SetValue(count,
		                        row.fetched_at > 0 ? Value::BIGINT(now - row.fetched_at) : Value(LogicalType::BIGINT));
		output.data[5].SetValue(count, stamp(row.tried_at));
		output.data[6].SetValue(count, row.error.empty() ? Value(LogicalType::VARCHAR) : Value(row.error));
		output.data[7].SetValue(count, row.keys < 0 ? Value(LogicalType::BIGINT) : Value::BIGINT(row.keys));
		vector<Value> kids;
		for (auto &kid : row.kids) {
			kids.emplace_back(kid);
		}
		output.data[8].SetValue(count, Value::LIST(LogicalType::VARCHAR, std::move(kids)));
		count++;
	}
	output.SetChildCardinality(count);
}

//! acl_jwks_refresh([issuer]) -> the cached documents dropped; the next token re-reads
void JwksRefreshFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	vector<Value> counts;
	for (idx_t row = 0; row < args.size(); row++) {
		counts.push_back(Value::BIGINT(StoreOf(state).JwksDropCache(OptionalArg(args, 0, row, ""))));
	}
	for (idx_t row = 0; row < args.size(); row++) {
		result.SetValue(row, counts[row]);
	}
}

} // namespace

//! spec 072: acl_function_status([role]) - the node's functions beside the categories: every key of
//! duckdb_functions() (pragmas aside, which are statements) with the categories it sits in and its
//! status - `never`, `categorized`, `uncategorized` - plus the members no function on this node
//! carries (present = false). With a role: whether that role may call it and what decided. The
//! screen after LOAD is `WHERE status = 'uncategorized'`.
struct AclFunctionsBindData : TableFunctionData {
	shared_ptr<PolicyStore> store;
	string role;
	bool with_role = false;
};

struct AclFunctionsState : GlobalTableFunctionState {
	vector<vector<Value>> rows;
	idx_t emitted = 0;
};

unique_ptr<FunctionData> AclFunctionsBind(ClientContext &, TableFunctionBindInput &input,
                                          vector<LogicalType> &return_types, vector<Identifier> &names) {
	if (!input.info) {
		throw BinderException("acl: acl_function_status without its policy store");
	}
	auto bind = make_uniq<AclFunctionsBindData>();
	bind->store = input.info->Cast<AclIntrospectionInfo>().store;
	if (!input.inputs.empty() && !input.inputs[0].IsNull()) {
		bind->role = input.inputs[0].ToString();
		bind->with_role = true;
	}
	const char *column_names[] = {"database",   "schema", "name",    "kind",    "function_type",
	                              "categories", "status", "present", "allowed", "decided_by"};
	vector<LogicalType> column_types = {LogicalType::VARCHAR, LogicalType::VARCHAR,
	                                    LogicalType::VARCHAR, LogicalType::VARCHAR,
	                                    LogicalType::VARCHAR, LogicalType::LIST(LogicalType::VARCHAR),
	                                    LogicalType::VARCHAR, LogicalType::BOOLEAN,
	                                    LogicalType::BOOLEAN, LogicalType::VARCHAR};
	for (idx_t i = 0; i < column_types.size(); i++) {
		names.push_back(Identifier(column_names[i]));
		return_types.push_back(column_types[i]);
	}
	return std::move(bind);
}

unique_ptr<GlobalTableFunctionState> AclFunctionsInit(ClientContext &context, TableFunctionInitInput &input) {
	auto &bind = input.bind_data->Cast<AclFunctionsBindData>();
	auto state = make_uniq<AclFunctionsState>();
	auto model = bind.store->FunctionModel();
	vector<string> roles;
	if (bind.with_role) {
		roles.push_back(bind.role);
	}
	std::set<string> seen;
	auto emit = [&](const FunctionKey &key, const Value &function_type, bool present) {
		auto categories = model->CategoriesOf(key);
		vector<Value> category_values;
		for (auto &category : categories) {
			category_values.emplace_back(category);
		}
		string status =
		    FunctionNeverCallable(key.name) ? "never" : (categories.empty() ? "uncategorized" : "categorized");
		Value allowed;
		Value decided_by;
		if (bind.with_role) {
			auto decision = model->Resolve(
			    roles, QualifiedName(Identifier(key.database), Identifier(key.schema), Identifier(key.name)), key.kind);
			allowed = Value::BOOLEAN(decision.verdict == FunctionVerdict::ADMITTED);
			decided_by = Value(decision.decided_by);
		}
		state->rows.push_back({Value(key.database), Value(key.schema), Value(key.name),
		                       Value(FunctionKindName(key.kind)), function_type,
		                       Value::LIST(LogicalType::VARCHAR, std::move(category_values)), Value(status),
		                       Value::BOOLEAN(present), allowed, decided_by});
		seen.insert(key.Serialize());
	};
	// the node's functions, on a connection of their own: a query inside a table function's init runs
	// beside the statement that called it, never on its context
	Connection con(DatabaseInstance::GetDatabase(context));
	auto result =
	    con.Query("SELECT database_name, schema_name, function_name, "
	              "CASE WHEN function_type IN ('table', 'table_macro') THEN 'table' ELSE 'scalar' END AS kind, "
	              "string_agg(DISTINCT function_type, ',' ORDER BY function_type) AS types "
	              "FROM duckdb_functions() WHERE function_type <> 'pragma' GROUP BY ALL ORDER BY ALL");
	if (result->HasError()) {
		result->ThrowError("acl_function_status: ");
	}
	for (idx_t row = 0; row < result->RowCount(); row++) {
		FunctionKey key;
		key.database = result->GetValue(0, row).ToString();
		key.schema = result->GetValue(1, row).ToString();
		key.name = StringUtil::Lower(result->GetValue(2, row).ToString());
		ParseFunctionKind(result->GetValue(3, row).ToString(), key.kind);
		emit(key, result->GetValue(4, row), true);
	}
	// members this node has no function for: an extension not loaded here, or a name the seed
	// carries for a node that has it
	for (auto &member : model->Members()) {
		if (!seen.count(member.second.Serialize())) {
			emit(member.second, Value(LogicalType::VARCHAR), false);
		}
	}
	return std::move(state);
}

void AclFunctionsScan(ClientContext &, TableFunctionInput &data, DataChunk &output) {
	auto &state = data.global_state->Cast<AclFunctionsState>();
	idx_t count = 0;
	while (state.emitted < state.rows.size() && count < STANDARD_VECTOR_SIZE) {
		auto &row = state.rows[state.emitted++];
		for (idx_t col = 0; col < row.size() && col < output.ColumnCount(); col++) {
			output.data[col].SetValue(count, row[col]);
		}
		count++;
	}
	output.SetChildCardinality(count);
}

void RegisterAclIntrospection(ExtensionLoader &loader, const shared_ptr<PolicyStore> &store) {
	{
		// spec 072: acl_function_status() / acl_function_status(role) - acl_functions() is the virtual functions
		// listing
		TableFunctionSet set((Identifier("acl_function_status")));
		for (auto &arguments : vector<vector<LogicalType>> {{}, {LogicalType::VARCHAR}}) {
			TableFunction function(Identifier("acl_function_status"), arguments, AclFunctionsScan, AclFunctionsBind,
			                       AclFunctionsInit);
			function.function_info = make_shared_ptr<AclIntrospectionInfo>(store, "functions");
			set.AddFunction(function);
		}
		loader.RegisterFunction(set);
	}
	{
		TableFunction cache(Identifier("acl_jwks_cache"), {}, JwksCacheScan, JwksCacheBind, JwksCacheInit);
		cache.function_info = make_shared_ptr<AclIntrospectionInfo>(store, "jwks_cache");
		loader.RegisterFunction(cache);
		ScalarFunctionSet refresh((Identifier("acl_jwks_refresh")));
		for (auto &arguments : {vector<LogicalType> {}, vector<LogicalType> {LogicalType::VARCHAR}}) {
			ScalarFunction function(Identifier("acl_jwks_refresh"), arguments, LogicalType::BIGINT, JwksRefreshFunc);
			MarkAclScalar(function, store);
			refresh.AddFunction(function);
		}
		loader.RegisterFunction(refresh);
	}
	// one function per listing of the policy model, plus the status of the source itself
	static const char *LISTINGS[] = {"catalogs",
	                                 "schemas",
	                                 "relations",
	                                 "relation_columns",
	                                 "object_columns",
	                                 "functions",
	                                 "references",
	                                 "reference_columns",
	                                 "roles",
	                                 "role_claims",
	                                 "grants",
	                                 "schema_grants",
	                                 "object_grants",
	                                 "grant_columns",
	                                 "admins",
	                                 "issuers",
	                                 "role_mappings",
	                                 "function_categories",
	                                 "function_category_members",
	                                 "function_grants",
	                                 "status"};
	for (auto listing : LISTINGS) {
		TableFunction function(Identifier(string("acl_") + listing), {}, AclIntrospectionScan, AclIntrospectionBind,
		                       AclIntrospectionInit);
		function.function_info = make_shared_ptr<AclIntrospectionInfo>(store, listing);
		loader.RegisterFunction(function);
	}
}

} // namespace acl
} // namespace duckdb
