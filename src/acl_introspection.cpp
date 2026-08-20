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

#include "duckdb/common/exception/binder_exception.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/main/extension/extension_loader.hpp"

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
	explicit AclIntrospectionBindData(IntrospectionRows rows_p) : rows(std::move(rows_p)) {
	}
	IntrospectionRows rows;
};

struct AclIntrospectionState : GlobalTableFunctionState {
	idx_t emitted = 0;
};

//! Read the listing here, at bind: the shape of the result is the shape of the function, so the
//! storage stays the single source of truth for both.
unique_ptr<FunctionData> AclIntrospectionBind(ClientContext &, TableFunctionBindInput &input,
                                              vector<LogicalType> &return_types, vector<Identifier> &names) {
	if (!input.info) {
		throw BinderException("acl: introspection function without its policy store");
	}
	auto &info = input.info->Cast<AclIntrospectionInfo>();
	auto rows = info.store->Introspect(info.listing);
	return_types = rows.types;
	for (auto &name : rows.names) {
		names.push_back(Identifier(name));
	}
	return make_uniq<AclIntrospectionBindData>(std::move(rows));
}

unique_ptr<GlobalTableFunctionState> AclIntrospectionInit(ClientContext &, TableFunctionInitInput &) {
	return make_uniq<AclIntrospectionState>();
}

void AclIntrospectionScan(ClientContext &, TableFunctionInput &data, DataChunk &output) {
	auto &bind_data = data.bind_data->Cast<AclIntrospectionBindData>();
	auto &state = data.global_state->Cast<AclIntrospectionState>();
	idx_t count = 0;
	while (state.emitted < bind_data.rows.rows.size() && count < STANDARD_VECTOR_SIZE) {
		auto &row = bind_data.rows.rows[state.emitted++];
		for (idx_t col = 0; col < row.size() && col < output.ColumnCount(); col++) {
			output.data[col].SetValue(count, row[col]);
		}
		count++;
	}
	output.SetChildCardinality(count);
}

} // namespace

void RegisterAclIntrospection(ExtensionLoader &loader, shared_ptr<PolicyStore> store) {
	// one function per listing of the policy model, plus the status of the source itself
	static const char *LISTINGS[] = {"catalogs",       "schemas",       "relations",     "relation_columns",
	                                 "object_columns", "functions",     "roles",         "role_claims",
	                                 "grants",         "schema_grants", "object_grants", "admins",
	                                 "issuers",        "role_mappings", "function_gate", "status"};
	for (auto listing : LISTINGS) {
		TableFunction function(Identifier(string("acl_") + listing), {}, AclIntrospectionScan, AclIntrospectionBind,
		                       AclIntrospectionInit);
		function.function_info = make_shared_ptr<AclIntrospectionInfo>(store, listing);
		loader.RegisterFunction(function);
	}
}

} // namespace acl
} // namespace duckdb
