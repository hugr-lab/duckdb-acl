//===----------------------------------------------------------------------===//
// acl_platform_sources.cpp — spec 118.3: the physical tree under `platform.attached`
//
// An administrator sees the node's physical sources as METADATA: `platform.attached.<alias>.<schema>`
// schemas holding the source's tables and views (names, column types, comments - never a view's SQL, a
// column default, a row). Who sees what: passthrough, policy and the cluster bundle every source; a
// catalog admin only the sources granted to it (`GRANT SOURCE <alias>[.<schema>] TO ROLE r`, kind
// `source` in platform_grants) - and it may build only over those (AuthorizeSources, acl_platform.cpp).
// One attached catalog is read at a time, through its own schema set - never duckdb_tables() /
// duckdb_columns(), which walk every database.
//===----------------------------------------------------------------------===//

#include "acl_platform.hpp"
#include "acl_door_common.hpp"
#include "acl_name_path.hpp"
#include "acl_policy_catalog.hpp"

#include "duckdb/catalog/catalog.hpp"
#include "duckdb/catalog/catalog_entry/schema_catalog_entry.hpp"
#include "duckdb/catalog/catalog_entry/table_catalog_entry.hpp"
#include "duckdb/catalog/catalog_entry/view_catalog_entry.hpp"
#include "duckdb/common/exception/binder_exception.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/main/attached_database.hpp"
#include "duckdb/main/database_manager.hpp"
#include "duckdb/main/extension/extension_loader.hpp"

namespace duckdb {
namespace acl {

namespace {

//! The databases whose metadata the tree may show: not the system / temp ones, not the policy store's
//! database, not a secrets service
vector<shared_ptr<AttachedDatabase>> SourceDatabases(ClientContext &context, PolicyStore &store) {
	vector<shared_ptr<AttachedDatabase>> out;
	for (auto &db : DatabaseManager::Get(context).GetDatabases(context)) {
		if (db->IsSystem() || db->IsTemporary() || db->GetVisibility() == AttachVisibility::HIDDEN) {
			continue; // a hidden database is another catalog's internals (ducklake's metadata), never a source
		}
		auto name = db->GetName().GetIdentifierName();
		if (store.catalog && StringUtil::CIEquals(name, store.catalog->db_name)) {
			continue;
		}
		if (StringUtil::CIEquals(db->GetCatalog().GetCatalogType(), "tresor")) {
			continue;
		}
		out.push_back(db);
	}
	return out;
}

//! A source key `alias[.schema]` as (alias, schema-or-empty)
std::pair<string, string> SplitSource(const string &key) {
	NamePath path;
	string error;
	if (!NamePath::TryFromKey(key, path, error) || path.Parts().empty() || path.Parts().size() > 2) {
		return {key, string()};
	}
	return {path.Parts()[0], path.Parts().size() > 1 ? path.Parts()[1] : string()};
}

//! Whether (alias, first schema part) is inside one of `sources` (none listed = every source)
bool InSources(const vector<string> *sources, const string &alias, const string &schema) {
	if (!sources) {
		return true;
	}
	for (auto &source : *sources) {
		auto parts = SplitSource(source);
		if (StringUtil::CIEquals(parts.first, alias) &&
		    (parts.second.empty() || StringUtil::CIEquals(parts.second, schema))) {
			return true;
		}
	}
	return false;
}

bool NamesDatabase(const vector<string> &sources, const string &alias) {
	for (auto &source : sources) {
		if (StringUtil::CIEquals(SplitSource(source).first, alias)) {
			return true;
		}
	}
	return false;
}

struct SourcesInfo : TableFunctionInfo {
	explicit SourcesInfo(shared_ptr<PolicyStore> store_p, bool columns_p)
	    : store(std::move(store_p)), columns(columns_p) {
	}
	shared_ptr<PolicyStore> store;
	bool columns;
};

struct SourcesBind : TableFunctionData {
	shared_ptr<PolicyStore> store;
	bool columns = false;
	bool all = true;
	vector<string> sources;
};

struct SourcesState : GlobalTableFunctionState {
	vector<vector<Value>> rows;
	idx_t next = 0;
};

unique_ptr<FunctionData> SourcesBindFn(ClientContext &, TableFunctionBindInput &input, vector<LogicalType> &types,
                                       vector<Identifier> &names) {
	auto &info = input.info->Cast<SourcesInfo>();
	auto bind = make_uniq<SourcesBind>();
	bind->store = info.store;
	bind->columns = info.columns;
	if (!input.inputs.empty() && !input.inputs[0].IsNull()) {
		bind->all = false;
		for (auto &value : ListValue::GetChildren(input.inputs[0])) {
			if (!value.IsNull()) {
				bind->sources.push_back(value.ToString());
			}
		}
	}
	auto column = [&](const char *name, const LogicalType &type) {
		names.push_back(Identifier(name));
		types.push_back(type);
	};
	column("path", LogicalType::VARCHAR); // the schema's key under platform: attached.<alias>.<schema…>
	if (info.columns) {
		column("vname", LogicalType::VARCHAR);
		column("pos", LogicalType::BIGINT);
		column("name", LogicalType::VARCHAR);
		column("type", LogicalType::VARCHAR);
	} else {
		column("vname", LogicalType::VARCHAR); // NULL: the schema itself (an empty schema is a node too)
		column("comment", LogicalType::VARCHAR);
		column("type", LogicalType::VARCHAR);
	}
	return std::move(bind);
}

unique_ptr<GlobalTableFunctionState> SourcesInit(ClientContext &context, TableFunctionInitInput &input) {
	auto &bind = input.bind_data->Cast<SourcesBind>();
	auto state = make_uniq<SourcesState>();
	auto *only = bind.all ? nullptr : &bind.sources;
	for (auto &db : SourceDatabases(context, *bind.store)) {
		auto alias = db->GetName().GetIdentifierName();
		if (only && !NamesDatabase(*only, alias)) {
			continue; // no grant names this database: its catalog is not even read
		}
		// one source that cannot answer (a postgres down, a ducklake whose metadata went away) drops out of
		// the tree - its rows are rolled back - never the whole listing every admin's console reads
		auto mark = state->rows.size();
		try {
			for (auto &schema_ref : db->GetCatalog().GetSchemas(context)) {
				auto &schema = schema_ref.get();
				vector<string> parts {"attached", alias};
				for (auto &part : schema.GetSchemaPath()) {
					parts.push_back(part.GetIdentifierName());
				}
				if (parts.size() < 3 || !InSources(only, alias, parts[2])) {
					continue;
				}
				auto path = NamePath(parts).ToKey();
				if (!bind.columns) {
					state->rows.push_back(
					    {Value(path), Value(LogicalType::VARCHAR), Value(LogicalType::VARCHAR), Value("SCHEMA")});
				}
				schema.Scan(context, CatalogType::TABLE_ENTRY, [&](CatalogEntry &entry) {
					auto name = Value(entry.name.GetIdentifierName());
					auto comment =
					    entry.comment.IsNull() ? Value(LogicalType::VARCHAR) : Value(entry.comment.ToString());
					if (entry.type == CatalogType::TABLE_ENTRY) {
						auto &table = entry.Cast<TableCatalogEntry>();
						if (!bind.columns) {
							state->rows.push_back({Value(path), name, comment, Value("BASE TABLE")});
							return;
						}
						int64_t pos = 0;
						for (auto &col : table.GetColumns().Logical()) {
							state->rows.push_back({Value(path), name, Value::BIGINT(++pos),
							                       Value(col.Name().GetIdentifierName()),
							                       Value(col.Type().ToString())});
						}
					} else if (entry.type == CatalogType::VIEW_ENTRY) {
						auto &view = entry.Cast<ViewCatalogEntry>();
						if (!bind.columns) {
							state->rows.push_back({Value(path), name, comment, Value("VIEW")});
							return;
						}
						try {
							view.BindView(context);
						} catch (std::exception &) { // NOLINT: an unbound view lists no columns
						}
						auto info = view.GetColumnInfo();
						if (!info) {
							return;
						}
						for (idx_t i = 0; i < info->names.size() && i < info->types.size(); i++) {
							state->rows.push_back({Value(path), name, Value::BIGINT(NumericCast<int64_t>(i + 1)),
							                       Value(info->names[i].GetIdentifierName()),
							                       Value(info->types[i].ToString())});
						}
					}
				});
			}
		} catch (std::exception &) { // NOLINT: the source is left out, the rest of the tree stands
			state->rows.resize(mark);
		}
	}
	return std::move(state);
}

void SourcesScan(ClientContext &, TableFunctionInput &data, DataChunk &output) {
	auto &state = data.global_state->Cast<SourcesState>();
	idx_t count = 0;
	while (state.next < state.rows.size() && count < STANDARD_VECTOR_SIZE) {
		auto &row = state.rows[state.next++];
		for (idx_t c = 0; c < row.size(); c++) {
			output.data[c].SetValue(count, row[c]);
		}
		count++;
	}
	output.SetChildCardinality(count);
}

//! acl_grant_source(role, source) / acl_revoke_source(role, source): a source granted to a role - a
//! database of this node, or one schema of it; never the policy store's database nor a secrets service
void SourceGrantFunc(DataChunk &args, ExpressionState &state, Vector &result, bool grant) {
	const char *fn = grant ? "acl_grant_source" : "acl_revoke_source";
	auto &store = StoreOf(state);
	auto &context = state.GetContext();
	for (idx_t row = 0; row < args.size(); row++) {
		auto role = OptionalArg(args, 0, row, "");
		if (role.empty()) {
			throw BinderException("%s: a source is granted to one role - never to every role ('')", fn);
		}
		auto source = RequiredArg(args, 1, row, fn, "source");
		NamePath path;
		string error;
		if (!NamePath::TryFromKey(source, path, error) || path.Parts().empty() || path.Parts().size() > 2) {
			throw BinderException("%s: a source is <database> or <database>.<schema>, not \"%s\"", fn, source);
		}
		auto &parts = path.Parts();
		if (grant) {
			shared_ptr<AttachedDatabase> found;
			for (auto &db : SourceDatabases(context, store)) {
				if (StringUtil::CIEquals(db->GetName().GetIdentifierName(), parts[0])) {
					found = db;
				}
			}
			if (!found) {
				throw BinderException("%s: \"%s\" is no source of this node - an attached database (never the "
				                      "policy store's, never a secrets service)",
				                      fn, parts[0]);
			}
			if (parts.size() == 2) {
				bool has = false;
				for (auto &schema : found->GetCatalog().GetSchemas(context)) {
					auto schema_path = schema.get().GetSchemaPath();
					has = has ||
					      (!schema_path.empty() && StringUtil::CIEquals(schema_path[0].GetIdentifierName(), parts[1]));
				}
				if (!has) {
					throw BinderException("%s: source \"%s\" has no schema \"%s\"", fn, parts[0], parts[1]);
				}
			}
		}
		if (grant) {
			store.GrantPlatform(role, "source", path.ToKey(), true);
		} else {
			store.RevokePlatform(role, "source", path.ToKey());
		}
	}
	result.Reference(Value::BOOLEAN(true), count_t(args.size()));
}

void GrantSourceFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	SourceGrantFunc(args, state, result, true);
}

void RevokeSourceFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	SourceGrantFunc(args, state, result, false);
}

} // namespace

vector<string> GrantedSources(const PolicyStore::AdminRights &rights) {
	vector<string> out;
	for (auto &grant : rights.platform) {
		if (grant.second && StringUtil::StartsWith(grant.first, "source:")) {
			out.push_back(grant.first.substr(7));
		}
	}
	return out;
}

bool SeesAllSources(const PolicyStore::AdminRights &rights) {
	return rights.passthrough || rights.unrestricted_manage || rights.cluster;
}

bool SourceGranted(const vector<string> &sources, const vector<string> &parts, bool schema_path) {
	if (parts.empty()) {
		return false;
	}
	for (auto &source : sources) {
		auto granted = SplitSource(source);
		if (!StringUtil::CIEquals(granted.first, parts[0])) {
			continue;
		}
		if (granted.second.empty()) {
			return true; // the whole database
		}
		// a schema grant: the name must reach into that schema - `<db>.<schema>[.…]`, or `<db>.<t>` in main
		if (schema_path ? parts.size() >= 2 && StringUtil::CIEquals(parts[1], granted.second)
		                : (parts.size() >= 3 && StringUtil::CIEquals(parts[1], granted.second)) ||
		                      (parts.size() == 2 && StringUtil::CIEquals(granted.second, "main"))) {
			return true;
		}
	}
	return false;
}

void RegisterAclPlatformSources(ExtensionLoader &loader, const shared_ptr<PolicyStore> &store) {
	for (auto columns : {false, true}) {
		auto name = string(columns ? "acl_platform_attached_columns" : "acl_platform_attached");
		TableFunctionSet set((Identifier(name)));
		for (auto &arguments :
		     {vector<LogicalType> {}, vector<LogicalType> {LogicalType::LIST(LogicalType::VARCHAR)}}) {
			TableFunction function(Identifier(name), arguments, SourcesScan, SourcesBindFn, SourcesInit);
			function.function_info = make_shared_ptr<SourcesInfo>(store, columns);
			set.AddFunction(function);
		}
		loader.RegisterFunction(set);
	}
	for (auto grant : {true, false}) {
		auto name = grant ? "acl_grant_source" : "acl_revoke_source";
		ScalarFunction function(Identifier(name), {LogicalType::VARCHAR, LogicalType::VARCHAR}, LogicalType::BOOLEAN,
		                        grant ? GrantSourceFunc : RevokeSourceFunc);
		MarkAclScalar(function, store);
		loader.RegisterFunction(function);
	}
}

} // namespace acl
} // namespace duckdb
