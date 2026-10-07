// spec 099: the type a column is exposed as - the rule (ExposedType), the node's settings, and the
// listings' spelling of it (acl_exposed_type).

#include "acl_types.hpp"

#include "acl_policy_catalog.hpp"

#include "acl_result_rows.hpp"
#include "duckdb/common/error_data.hpp"
#include "duckdb/main/connection.hpp"
#include "duckdb/main/database.hpp"

namespace duckdb {
namespace acl {

namespace {

//! The base type of a leaf that carries an alias: its id, with the parameters the id needs
LogicalType BaseOf(const LogicalType &type) {
	switch (type.id()) {
	case LogicalTypeId::DECIMAL:
		return LogicalType::DECIMAL(DecimalType::GetWidth(type), DecimalType::GetScale(type));
	case LogicalTypeId::ENUM:
		return type.WithAlias(string());
	default:
		return LogicalType(type.id());
	}
}

bool SettingIs(DatabaseInstance &db, const char *name, const char *value) {
	Value current;
	if (!db.TryGetCurrentSetting(name, current) || current.IsNull()) {
		return false;
	}
	return StringUtil::CIEquals(current.ToString(), value);
}

//! acl_exposed_type(type_text, strip_alias, enums_to_varchar): the text a listing shows. A text that
//! does not bind (an extension unloaded since) is answered as it is - the read was cast from the facts
//! written with the object, never from this.
void ExposedTypeFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &context = state.GetContext();
	// a listing repeats few types over many rows: each spelling is bound once per chunk
	unordered_map<string, string> answered;
	for (idx_t row = 0; row < args.size(); row++) {
		auto text = args.data[0].GetValue(row);
		if (text.IsNull()) {
			result.SetValue(row, Value());
			continue;
		}
		auto strip = args.data[1].GetValue(row);
		auto enums = args.data[2].GetValue(row);
		bool strip_alias = !strip.IsNull() && strip.GetValue<bool>();
		bool enums_to_varchar = !enums.IsNull() && enums.GetValue<bool>();
		auto spelled = text.ToString();
		if (!strip_alias && !enums_to_varchar) {
			result.SetValue(row, Value(spelled));
			continue;
		}
		auto key = spelled + "\x1f" + string(strip_alias ? "b" : "k") + (enums_to_varchar ? "v" : "k");
		auto known = answered.find(key);
		if (known != answered.end()) {
			result.SetValue(row, Value(known->second));
			continue;
		}
		string answer = spelled;
		try {
			auto type = TransformStringToLogicalType(spelled, context);
			auto exposed = ExposedType(type, strip_alias, enums_to_varchar);
			if (exposed.ToString() != type.ToString()) {
				answer = exposed.ToString();
			}
		} catch (std::exception &ex) {
			// a spelling that does not bind is answered as it is; an interrupt is not swallowed
			ErrorData error(ex);
			if (error.Type() == ExceptionType::INTERRUPT || error.Type() == ExceptionType::FATAL ||
			    error.Type() == ExceptionType::INTERNAL) {
				throw;
			}
		}
		answered[key] = answer;
		result.SetValue(row, Value(answer));
	}
}

//! The node of `tree` at `path` (`""`, `.city`, `.items[]`), or nothing
optional_ptr<const acl_detail::FieldNode> NodeAt(const acl_detail::FieldNode &tree, const string &path) {
	acl_detail::FieldPath parsed;
	string error;
	if (!acl_detail::ParseFieldPath("x" + path, parsed, error)) {
		return nullptr;
	}
	optional_ptr<const acl_detail::FieldNode> node = &tree;
	for (auto &step : parsed.steps) {
		if (step.empty()) {
			node = node->element.get();
		} else {
			node = node->Find(step).get();
		}
		if (!node) {
			return nullptr;
		}
	}
	return node;
}

//! acl_listed_type(source_type, column, roles) - spec 102: the type a principal reads of one column,
//! computed as the read path computes it. `roles` is one STRUCT(cat, obj, probed) per role, in the
//! order the resolver unites them (role name): the role's catalog and object column lists, and the
//! type its own projection was probed to (spec 026) - where a mask's type comes from.
void ListedTypeFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &context = state.GetContext();
	for (idx_t row = 0; row < args.size(); row++) {
		auto source_text = args.data[0].GetValue(row);
		auto column = args.data[1].GetValue(row);
		auto roles = args.data[2].GetValue(row);
		if (source_text.IsNull() || column.IsNull() || roles.IsNull()) {
			result.SetValue(row, source_text);
			continue;
		}
		try {
			auto source = TransformStringToLogicalType(source_text.ToString(), context);
			auto name = column.ToString();
			acl_detail::GrantUnion grants;
			vector<std::pair<unique_ptr<acl_detail::FieldNode>, string>> own; // each role's tree, its probe
			for (auto &role : ListValue::GetChildren(roles)) {
				auto &fields = StructValue::GetChildren(role);
				auto text = [&](idx_t i) {
					return fields[i].IsNull() ? string() : fields[i].ToString();
				};
				acl_detail::GrantPolicy policy;
				policy.Narrow(string(), text(0));
				policy.Narrow(string(), text(1));
				grants.Add(policy);
				auto trees = acl_detail::ColumnTrees::From(policy.columns);
				auto node = trees.Find(name);
				own.emplace_back(node ? node->Clone() : nullptr, text(2));
			}
			if (!grants.Restricts()) {
				result.SetValue(row, source_text);
				continue;
			}
			auto united = acl_detail::ColumnTrees::From(grants.columns);
			auto node = united.Find(name);
			if (!node) {
				result.SetValue(row, Value());
				continue;
			}
			auto mask_type = [&](const string &path) -> LogicalType {
				for (auto &entry : own) {
					auto at = entry.first ? NodeAt(*entry.first, path) : nullptr;
					if (at && at->masked && !entry.second.empty()) {
						LogicalType probed;
						if (acl_detail::TypeAtPath(TransformStringToLogicalType(entry.second, context), path, probed)) {
							return probed;
						}
					}
				}
				return LogicalType::SQLNULL;
			};
			auto type = acl_detail::ProjectedType(*node, source, string(), mask_type);
			result.SetValue(row, Value(type.ToString()));
		} catch (std::exception &ex) {
			ErrorData error(ex);
			if (error.Type() == ExceptionType::INTERRUPT || error.Type() == ExceptionType::FATAL ||
			    error.Type() == ExceptionType::INTERNAL) {
				throw;
			}
			// fail closed: the read refuses this principal (two roles masking one field differently, a
			// list that does not parse) - the listing must not answer the source's full type instead
			result.SetValue(row, Value(LogicalType(LogicalTypeId::SQLNULL).ToString()));
		}
	}
}

} // namespace

LogicalType ExposedType(const LogicalType &type, bool strip_alias, bool enums_to_varchar) {
	switch (type.id()) {
	case LogicalTypeId::ENUM:
		if (enums_to_varchar) {
			return LogicalType::VARCHAR;
		}
		break;
	case LogicalTypeId::STRUCT: {
		child_list_t<LogicalType> children;
		bool changed = false;
		for (auto &child : StructType::GetChildTypes(type)) {
			auto exposed = ExposedType(child.second, strip_alias, enums_to_varchar);
			changed = changed || exposed.ToString() != child.second.ToString();
			children.emplace_back(child.first, std::move(exposed));
		}
		if (changed) {
			return LogicalType::STRUCT(std::move(children));
		}
		break;
	}
	case LogicalTypeId::UNION: {
		child_list_t<LogicalType> members;
		bool changed = false;
		for (auto &member : UnionType::CopyMemberTypes(type)) {
			auto exposed = ExposedType(member.second, strip_alias, enums_to_varchar);
			changed = changed || exposed.ToString() != member.second.ToString();
			members.emplace_back(member.first, std::move(exposed));
		}
		if (changed) {
			return LogicalType::UNION(std::move(members));
		}
		break;
	}
	case LogicalTypeId::MAP: {
		auto &key = MapType::KeyType(type);
		auto &value = MapType::ValueType(type);
		auto exposed_key = ExposedType(key, strip_alias, enums_to_varchar);
		auto exposed_value = ExposedType(value, strip_alias, enums_to_varchar);
		if (exposed_key.ToString() != key.ToString() || exposed_value.ToString() != value.ToString()) {
			return LogicalType::MAP(std::move(exposed_key), std::move(exposed_value));
		}
		break;
	}
	case LogicalTypeId::LIST: {
		auto &child = ListType::GetChildType(type);
		auto exposed = ExposedType(child, strip_alias, enums_to_varchar);
		if (exposed.ToString() != child.ToString()) {
			return LogicalType::LIST(exposed);
		}
		break;
	}
	case LogicalTypeId::ARRAY: {
		auto &child = ArrayType::GetChildType(type);
		auto exposed = ExposedType(child, strip_alias, enums_to_varchar);
		if (exposed.ToString() != child.ToString()) {
			return LogicalType::ARRAY(exposed, ArrayType::GetSize(type));
		}
		break;
	}
	default:
		break;
	}
	// a nested type rebuilt above lost its own alias with it - right, since the name no longer describes
	// it; one left alone keeps it unless the alias is what is being stripped
	if (strip_alias && type.HasAlias() && !type.IsJSONType()) {
		switch (type.id()) {
		case LogicalTypeId::STRUCT:
		case LogicalTypeId::UNION:
		case LogicalTypeId::MAP:
		case LogicalTypeId::LIST:
		case LogicalTypeId::ARRAY:
			return type.WithAlias(string());
		default:
			return BaseOf(type);
		}
	}
	return type;
}

bool PolicyStore::SystemTypeExists(const string &name) {
	{
		lock_guard<mutex> guard(system_types_lock);
		if (system_types.count(name)) {
			return true;
		}
	}
	auto db = instance.lock();
	if (!db) {
		return false;
	}
	Connection con(*db);
	auto result = con.Query("SELECT DISTINCT type_name FROM system.main.duckdb_types() WHERE database_name = 'system'");
	if (result->HasError()) {
		return false;
	}
	ResultRows rows(*result);
	lock_guard<mutex> guard(system_types_lock);
	for (idx_t row = 0; row < rows.Count(); row++) {
		system_types.insert(rows.GetValue(0, row).ToString());
	}
	return system_types.count(name) > 0;
}

bool NodeStripsAliases(DatabaseInstance &db) {
	return !SettingIs(db, "acl_alias_types", "keep");
}

bool NodeEnumsToVarchar(DatabaseInstance &db) {
	return SettingIs(db, "acl_enum_types", "varchar");
}

void RegisterAclTypes(ExtensionLoader &loader, const shared_ptr<PolicyStore> &store) {
	ScalarFunction function(Identifier("acl_exposed_type"),
	                        {LogicalType::VARCHAR, LogicalType::BOOLEAN, LogicalType::BOOLEAN}, LogicalType::VARCHAR,
	                        ExposedTypeFunc);
	MarkAclScalar(function, store);
	function.SetNullHandling(FunctionNullHandling::SPECIAL_HANDLING);
	loader.RegisterFunction(function);
	auto role_type = LogicalType::LIST(LogicalType::STRUCT({{Identifier("cat"), LogicalType::VARCHAR},
	                                                        {Identifier("obj"), LogicalType::VARCHAR},
	                                                        {Identifier("probed"), LogicalType::VARCHAR}}));
	ScalarFunction listed(Identifier("acl_listed_type"), {LogicalType::VARCHAR, LogicalType::VARCHAR, role_type},
	                      LogicalType::VARCHAR, ListedTypeFunc);
	MarkAclScalar(listed, store);
	listed.SetNullHandling(FunctionNullHandling::SPECIAL_HANDLING);
	loader.RegisterFunction(listed);
}

} // namespace acl
} // namespace duckdb
