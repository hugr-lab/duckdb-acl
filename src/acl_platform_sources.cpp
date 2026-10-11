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
#include "duckdb/catalog/entry_lookup_info.hpp"
#include "duckdb/parser/constraints/not_null_constraint.hpp"
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

//! acl_physical_tables(keys) / acl_physical_columns(keys) (spec 119): duckdb_tables / duckdb_views /
//! duckdb_columns' rows - only of the named physical schemas (`<db>.<schema>`) and objects
//! (`<db>.<schema>.<object>`), each read directly: a listing reads the sources it answers about, never a
//! walk of every attached database. A key that does not resolve answers nothing; a source that fails is
//! left out, never the listing failed.
struct PhysicalBind : TableFunctionData {
	vector<string> keys;
	bool columns = false;
};

struct PhysicalInfo : TableFunctionInfo {
	explicit PhysicalInfo(bool columns_p) : columns(columns_p) {
	}
	bool columns;
};

unique_ptr<FunctionData> PhysicalBindFn(ClientContext &, TableFunctionBindInput &input, vector<LogicalType> &types,
                                        vector<Identifier> &names) {
	auto bind = make_uniq<PhysicalBind>();
	bind->columns = input.info->Cast<PhysicalInfo>().columns;
	if (!input.inputs.empty() && !input.inputs[0].IsNull()) {
		for (auto &value : ListValue::GetChildren(input.inputs[0])) {
			if (!value.IsNull()) {
				bind->keys.push_back(value.ToString());
			}
		}
	}
	auto column = [&](const char *name, const LogicalType &type) {
		names.push_back(Identifier(name));
		types.push_back(type);
	};
	column("database_name", LogicalType::VARCHAR);
	column("schema_name", LogicalType::VARCHAR);
	column("table_name", LogicalType::VARCHAR);
	if (bind->columns) {
		column("column_name", LogicalType::VARCHAR);
		column("column_index", LogicalType::INTEGER);
		column("column_default", LogicalType::VARCHAR);
		column("is_nullable", LogicalType::BOOLEAN);
		column("data_type", LogicalType::VARCHAR);
		column("character_maximum_length", LogicalType::INTEGER);
		column("numeric_precision", LogicalType::INTEGER);
		column("numeric_precision_radix", LogicalType::INTEGER);
		column("numeric_scale", LogicalType::INTEGER);
		column("is_generated", LogicalType::BOOLEAN);
		column("generation_expression", LogicalType::VARCHAR);
		column("comment", LogicalType::VARCHAR);
	} else {
		column("is_view", LogicalType::BOOLEAN);
		column("temporary", LogicalType::BOOLEAN);
		column("comment", LogicalType::VARCHAR);
	}
	return std::move(bind);
}

//! duckdb_columns' numeric facts of a type
void NumericFacts(const LogicalType &type, Value &precision, Value &radix, Value &scale) {
	int32_t bits = 0;
	switch (type.id()) {
	case LogicalTypeId::DECIMAL:
		precision = Value::INTEGER(DecimalType::GetWidth(type));
		scale = Value::INTEGER(DecimalType::GetScale(type));
		radix = Value::INTEGER(10);
		return;
	case LogicalTypeId::HUGEINT:
		bits = 128;
		break;
	case LogicalTypeId::BIGINT:
		bits = 64;
		break;
	case LogicalTypeId::INTEGER:
		bits = 32;
		break;
	case LogicalTypeId::SMALLINT:
		bits = 16;
		break;
	case LogicalTypeId::TINYINT:
		bits = 8;
		break;
	case LogicalTypeId::FLOAT:
		bits = 24;
		break;
	case LogicalTypeId::DOUBLE:
		bits = 53;
		break;
	default:
		precision = Value(LogicalType::INTEGER);
		scale = Value(LogicalType::INTEGER);
		radix = Value(LogicalType::INTEGER);
		return;
	}
	precision = Value::INTEGER(bits);
	scale = Value::INTEGER(0);
	radix = Value::INTEGER(2);
}

void PhysicalRows(ClientContext &context, const PhysicalBind &bind, SourcesState &state, const string &db_name,
                  const string &schema_name, CatalogEntry &entry) {
	auto text = [](const Value &value) {
		return value.IsNull() ? Value(LogicalType::VARCHAR) : Value(value.ToString());
	};
	auto comment = text(entry.comment);
	auto table = Value(entry.name.GetIdentifierName());
	bool is_view = entry.type == CatalogType::VIEW_ENTRY;
	if (!bind.columns) {
		state.rows.push_back({Value(db_name), Value(schema_name), table, Value::BOOLEAN(is_view),
		                      Value::BOOLEAN(entry.temporary), comment});
		return;
	}
	auto push = [&](const string &column, int32_t index, const Value &column_default, bool nullable,
	                const LogicalType &type, bool generated, const Value &generation, const Value &column_comment) {
		Value precision, radix, scale;
		NumericFacts(type, precision, radix, scale);
		state.rows.push_back(
		    {Value(db_name), Value(schema_name), table, Value(column), Value::INTEGER(index), column_default,
		     Value::BOOLEAN(nullable),
		     type.id() == LogicalTypeId::INVALID ? Value(LogicalType::VARCHAR) : Value(type.ToString()),
		     Value(LogicalType::INTEGER), precision, radix, scale, Value::BOOLEAN(generated), generation,
		     text(column_comment)});
	};
	if (!is_view) {
		auto &table_entry = entry.Cast<TableCatalogEntry>();
		std::set<idx_t> not_null;
		for (auto &constraint : table_entry.GetConstraints()) {
			if (constraint->type == ConstraintType::NOT_NULL) {
				not_null.insert(constraint->Cast<NotNullConstraint>().index.index);
			}
		}
		auto &columns = table_entry.GetColumns();
		for (idx_t i = 0; i < columns.LogicalColumnCount(); i++) {
			auto &col = columns.GetColumn(LogicalIndex(i));
			Value column_default(LogicalType::VARCHAR), generation(LogicalType::VARCHAR);
			if (col.Generated()) {
				column_default = Value(col.GeneratedExpression().ToString());
				generation = column_default;
			} else if (col.HasDefaultValue()) {
				column_default = Value(col.DefaultValue().ToString());
			}
			push(col.Name().GetIdentifierName(), NumericCast<int32_t>(i + 1), column_default, !not_null.count(i),
			     col.Type(), col.Generated(), generation, col.Comment());
		}
		return;
	}
	auto &view = entry.Cast<ViewCatalogEntry>();
	try {
		view.BindView(context);
	} catch (std::exception &) { // NOLINT: an unbound view answers no columns
	}
	auto info = view.GetColumnInfo();
	for (idx_t i = 0; info && i < info->names.size() && i < info->types.size(); i++) {
		push(info->names[i].GetIdentifierName(), NumericCast<int32_t>(i + 1), Value(LogicalType::VARCHAR), true,
		     info->types[i], false, Value(LogicalType::VARCHAR), view.GetColumnComment(i));
	}
}

unique_ptr<GlobalTableFunctionState> PhysicalInit(ClientContext &context, TableFunctionInitInput &input) {
	auto &bind = input.bind_data->Cast<PhysicalBind>();
	auto state = make_uniq<SourcesState>();
	auto &manager = DatabaseManager::Get(context);
	std::set<string> seen;
	for (auto &key : bind.keys) {
		NamePath path;
		string error;
		if (!NamePath::TryFromKey(key, path, error) || path.Parts().size() < 2 || path.Parts().size() > 3 ||
		    !seen.insert(StringUtil::Lower(path.ToKey())).second) {
			continue;
		}
		auto &parts = path.Parts();
		auto mark = state->rows.size();
		try {
			auto db = manager.GetDatabase(context, Identifier(parts[0]));
			if (!db || db->GetVisibility() == AttachVisibility::HIDDEN) {
				continue;
			}
			auto db_name = db->GetName().GetIdentifierName();
			auto &catalog = db->GetCatalog();
			if (parts.size() == 3) {
				auto entry = catalog.GetEntry(context, CatalogType::TABLE_ENTRY, Identifier(parts[1]),
				                              Identifier(parts[2]), OnEntryNotFound::RETURN_NULL);
				if (entry) {
					PhysicalRows(context, bind, *state, db_name, parts[1], *entry);
				}
				continue;
			}
			EntryLookupInfo schema_lookup(CatalogType::SCHEMA_ENTRY, QualifiedName(Identifier(parts[1])));
			auto schema = catalog.GetSchema(context, schema_lookup, OnEntryNotFound::RETURN_NULL);
			if (!schema) {
				continue;
			}
			auto schema_name = schema->name.GetIdentifierName();
			schema->Scan(context, CatalogType::TABLE_ENTRY, [&](CatalogEntry &entry) {
				PhysicalRows(context, bind, *state, db_name, schema_name, entry);
			});
		} catch (std::exception &) { // NOLINT: a source that cannot answer is left out
			state->rows.resize(mark);
		}
	}
	return std::move(state);
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
	for (auto columns : {false, true}) {
		auto name = columns ? "acl_physical_columns" : "acl_physical_tables";
		TableFunction physical(Identifier(name), {LogicalType::LIST(LogicalType::VARCHAR)}, SourcesScan, PhysicalBindFn,
		                       PhysicalInit);
		physical.function_info = make_shared_ptr<PhysicalInfo>(columns);
		loader.RegisterFunction(physical);
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
