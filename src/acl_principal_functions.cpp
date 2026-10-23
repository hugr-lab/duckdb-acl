//===----------------------------------------------------------------------===//
// acl_principal_functions.cpp — a principal's `duckdb_functions()` (spec 098)
//
// Under a principal, `duckdb_functions()` is substituted (before the function gate, like every
// metadata surface of spec 035) by this listing, in duckdb's own shape:
//  (a) the engine's functions the spec 072 model admits for the principal's roles - the gate's own
//      judgement, enumerated from the model, never a SQL re-implementation of its rules; a function
//      outside the system catalog keeps no database, schema, definition or oid (a macro of an
//      attached catalog names physical objects);
//  (b) the virtual functions a call of the principal reaches - each resolved the way a call is, and
//      kept only with `select` (a call is a read) - with their parameters and comment and no
//      definition (a template is physical SQL).
// The admitted keys are constants this code writes into the SQL - never a parameter (the golden rule).
//===----------------------------------------------------------------------===//

#include "acl_policy.hpp"
#include "acl_result_rows.hpp"
#include "acl_policy_catalog.hpp"
#include "acl_platform.hpp"
#include "duckdb/common/types/hash.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/main/connection.hpp"
#include "duckdb/parser/expression/cast_expression.hpp"
#include "duckdb/parser/expression/constant_expression.hpp"
#include "duckdb/parser/parser.hpp"
#include "duckdb/main/extension/extension_loader.hpp"

#include <set>
#include <unordered_map>

namespace duckdb {
namespace acl {

namespace {

string Quote(const string &value) {
	return "'" + StringUtil::Replace(value, "'", "''") + "'";
}

string QuoteOrNull(const Value &value) {
	return value.IsNull() ? "NULL" : Quote(value.ToString());
}

//! a VARCHAR[] literal; an empty item is NULL (a parameter declared without a type)
string ListLiteral(const vector<string> &items) {
	if (items.empty()) {
		return "[]::VARCHAR[]";
	}
	vector<string> quoted;
	for (auto &item : items) {
		quoted.push_back(item.empty() ? string("NULL") : Quote(item));
	}
	return "[" + StringUtil::Join(quoted, ", ") + "]::VARCHAR[]";
}

//! `threshold INTEGER, amount DECIMAL(10, 2)` -> names and types: split at the commas outside
//! parentheses, brackets and quotes; the first word of each part is the name, the rest its type
void SplitParams(const string &text, vector<string> &names, vector<string> &types) {
	vector<string> parts;
	string current;
	int depth = 0;
	char quote = 0;
	for (auto c : text) {
		if (quote) {
			// a doubled quote inside a quoted part is the quote itself: it closes and reopens at once,
			// which leaves the scan inside the quotes
			if (c == quote) {
				quote = 0;
			}
			current += c;
			continue;
		}
		if (!current.empty() && c == current.back() && (c == '"' || c == '\'') && current.size() >= 2) {
			// `"x""y"`: the second of a doubled quote reopens the quoted part
			quote = c;
			current += c;
			continue;
		}
		if (c == '"' || c == '\'') {
			quote = c;
		} else if (c == '(' || c == '[') {
			depth++;
		} else if ((c == ')' || c == ']') && depth > 0) {
			depth--;
		} else if (c == ',' && depth == 0) {
			parts.push_back(current);
			current.clear();
			continue;
		}
		current += c;
	}
	parts.push_back(current);
	for (auto &part : parts) {
		auto item = part;
		StringUtil::Trim(item);
		if (item.empty()) {
			continue;
		}
		string name;
		string type;
		if (item[0] == '"') {
			// a quoted name ends at a quote that is not doubled; `""` inside it is one quote
			idx_t end = 1;
			while (end < item.size()) {
				if (item[end] == '"') {
					if (end + 1 < item.size() && item[end + 1] == '"') {
						name += '"';
						end += 2;
						continue;
					}
					break;
				}
				name += item[end++];
			}
			type = end < item.size() ? item.substr(end + 1) : string();
		} else {
			auto space = item.find_first_of(" \t");
			name = space == string::npos ? item : item.substr(0, space);
			type = space == string::npos ? string() : item.substr(space + 1);
		}
		// a default (`x INTEGER := 5`, `x INTEGER DEFAULT 5`) is not part of the type
		auto lowered = StringUtil::Lower(type);
		auto assign = type.find(":=");
		auto keyword = lowered.find(" default ");
		if (StringUtil::StartsWith(lowered, "default ")) {
			keyword = 0;
		}
		auto cut = MinValue(assign, keyword);
		if (cut != string::npos) {
			type = type.substr(0, cut);
		}
		StringUtil::Trim(type);
		names.push_back(name);
		types.push_back(type);
	}
}

//! The oid a virtual object gets on every surface (spec 035 addendum): stable, derived from the
//! virtual name, unrelated to any physical catalog - quack reads oids as int64 and cannot take NULL
string OidOf(const string &kind, const string &name) {
	return "(hash(" + Quote(kind) + " || chr(31) || " + Quote(name) + ") >> 1)::BIGINT";
}

//! a declared column name as the operator wrote it (`"Name"`) -> the name itself (`Name`)
string Unquoted(const string &name) {
	if (name.size() >= 2 && name.front() == '"' && name.back() == '"') {
		return StringUtil::Replace(name.substr(1, name.size() - 2), "\"\"", "\"");
	}
	return name;
}

//! a column name as SQL writes it: bare when it is a plain lower-case identifier, else quoted
string QuoteIdentifier(const string &name) {
	bool plain = !name.empty() && (StringUtil::CharacterIsAlpha(name[0]) || name[0] == '_');
	for (auto c : name) {
		plain = plain && (StringUtil::CharacterIsAlphaNumeric(c) || c == '_') && !(c >= 'A' && c <= 'Z');
	}
	return plain ? name : "\"" + StringUtil::Replace(name, "\"", "\"\"") + "\"";
}

//! The result columns a call returns to this principal: the declared ones, narrowed by the grant's
//! projection the way the read narrows them (spec 011 - WrapWithGrantPolicy). The projection is bound,
//! on the node's own connection, over an empty relation of the declared columns, so names and types are
//! the binder's - a mask's included. A projection that does not bind here (a claim marker, a call the
//! node lacks) withholds the list: nothing rather than more than the call returns.
vector<acl_detail::CatalogBackend::VisibleFunction::Column>
NarrowedColumns(DatabaseInstance *db, const TablePolicy &policy,
                const vector<acl_detail::CatalogBackend::VisibleFunction::Column> &declared,
                std::unordered_map<string, string> &mask_types) {
	using Column = acl_detail::CatalogBackend::VisibleFunction::Column;
	if (policy.wrap_sql.empty() && policy.projection.empty()) {
		return declared;
	}
	if (!db || declared.empty() || policy.granted_items.empty()) {
		return vector<Column>();
	}
	// spec 147: what the read's wrap keeps (ApplyFunctionGrantPolicy), decided from the stored facts - the declared
	// columns, in their order, whose name the united list names; a mask's type from its text where it says it (a
	// constant, a cast), else bound once per mask and shape. A mask naming no declared column refuses the read
	// (REPLACE), and nothing is listed then. The row filter is not judged here, as a relation's listing does not.
	case_insensitive_map_t<string> kept; // name -> mask ('' = as it is)
	for (auto &item : policy.granted_items) {
		auto name = item.first;
		StringUtil::Trim(name);
		kept[name] = item.second;
	}
	string inner;
	for (auto &column : declared) {
		if (column.type.empty()) {
			return vector<Column>();
		}
		inner += (inner.empty() ? "" : ", ") + string("NULL::") + column.type + " AS " +
		         QuoteIdentifier(Unquoted(column.name));
	}
	for (auto &item : kept) {
		if (item.second.empty()) {
			continue;
		}
		bool returned = false;
		for (auto &column : declared) {
			returned = returned || StringUtil::CIEquals(Unquoted(column.name), item.first);
		}
		if (!returned) {
			return vector<Column>();
		}
	}
	auto mask_type = [&](const string &mask, string &type) {
		try {
			auto parsed = Parser(ParserOptions::Builtin()).ParseExpressionList(mask);
			if (parsed.size() == 1 && parsed[0]->GetExpressionClass() == ExpressionClass::CONSTANT) {
				type = LogicalType::NormalizeType(parsed[0]->Cast<ConstantExpression>().GetLiteral().ToValue().type())
				           .ToString();
				return true;
			}
			if (parsed.size() == 1 && parsed[0]->GetExpressionClass() == ExpressionClass::CAST) {
				type = parsed[0]->Cast<CastExpression>().TargetType().ToString();
				return true;
			}
		} catch (std::exception &) {
			return false;
		}
		auto key = mask + "\x1f" + inner;
		auto entry = mask_types.find(key);
		if (entry == mask_types.end()) {
			string bound;
			try {
				Connection con(*db);
				auto described = con.Query("DESCRIBE SELECT " + mask + " AS m FROM (SELECT " + inner + " WHERE false)");
				if (!described->HasError() && described->RowCount() == 1) {
					bound = described->Collection().GetValue(1, 0).ToString();
				}
			} catch (std::exception &) {
				bound.clear();
			}
			entry = mask_types.emplace(key, bound).first;
		}
		type = entry->second;
		return !type.empty();
	};
	vector<Column> out;
	for (auto &candidate : declared) {
		auto name = Unquoted(candidate.name);
		auto entry = kept.find(name);
		if (entry == kept.end()) {
			continue;
		}
		Column column;
		column.name = name;
		column.type = candidate.type;
		column.comment = candidate.comment;
		if (!entry->second.empty() && !mask_type(entry->second, column.type)) {
			return vector<Column>(); // a mask that does not bind refuses the read
		}
		out.push_back(std::move(column));
	}
	return out;
}

//! The virtual functions a call of this principal reaches, in every catalog it holds (spec 115), each
//! resolved the way a call is - by the qualified name it can always be called with - and kept only with
//! `select` (a call is a read)
vector<acl_detail::CatalogBackend::VisibleFunction>
CallableFunctions(PolicyStore &store, acl_detail::CatalogBackend *catalog, const Principal &principal) {
	vector<acl_detail::CatalogBackend::VisibleFunction> out;
	if (!catalog) {
		return out;
	}
	// spec 147: kept whole per role set and policy version (a listing computes it twice, a tool lists again)
	catalog->EnsureFresh();
	auto cache_key = catalog->RoleSig(principal);
	{
		lock_guard<mutex> guard(catalog->lock);
		auto entry = catalog->callable_cache.find(cache_key);
		if (entry != catalog->callable_cache.end()) {
			return *entry->second;
		}
	}
	auto db = store.instance.lock();
	auto visible = catalog->VisibleFunctions(principal);
	// spec 147: resolved together - one query a chunk, not one per function (minutes over 10,000 functions)
	vector<acl_detail::CatalogBackend::VirtualFunctionKey> keys;
	for (auto &function : visible) {
		keys.push_back({function.vcat, function.vname, function.kind == "table"});
	}
	vector<acl_detail::CatalogBackend::ResolvedVirtualFunction> resolved;
	catalog->ResolveFunctions(principal, keys, resolved);
	std::unordered_map<string, string> mask_types; // spec 147: a mask that reads columns, bound once per shape
	for (idx_t i = 0; i < visible.size(); i++) {
		// what refuses the call (a scalar under a grant that carries a policy) keeps it out of the listing - never
		// the whole listing out with it
		if (resolved[i].refused || !resolved[i].found || !resolved[i].policy.caps.count("select")) {
			continue; // a call needs select (spec 012)
		}
		auto function = std::move(visible[i]);
		function.columns = NarrowedColumns(db.get(), resolved[i].policy, function.columns, mask_types);
		out.push_back(std::move(function));
	}
	lock_guard<mutex> guard(catalog->lock);
	if (catalog->callable_cache.size() >= 64) {
		catalog->callable_cache.clear(); // bounded: a role set's listing, not every role set's
	}
	catalog->callable_cache[cache_key] =
	    make_shared_ptr<const vector<acl_detail::CatalogBackend::VisibleFunction>>(out);
	return out;
}

//! spec 117: the platform functions a principal may call, none on the quack door
vector<PlatformFunctionRow> PlatformRowsFor(PolicyStore &store, const Principal &principal, bool quack_door) {
	if (quack_door) {
		return {};
	}
	return PlatformFunctionRows(store.AdminRightsOf(principal));
}

//! the door a principal's session came through, as the rows below need it
bool QuackDoor(PolicyStore &store, const Principal &principal) {
	return !principal.session.empty() && store.SessionDoorOf(principal.session) == "quack";
}

//! spec 147: the oid OidOf writes as SQL (`(hash(kind || chr(31) || name) >> 1)::BIGINT`), computed here - duckdb's
//! own string hash, so a surface that writes the SQL and one that answers rows agree
int64_t OidValue(const string &kind, const string &name) {
	auto text = kind + '\x1f' + name;
	return int64_t(Hash<string_t>(string_t(text.c_str(), UnsafeNumericCast<uint32_t>(text.size()))) >> 1);
}

Value TextOrNull(const Value &value) {
	return value.IsNull() ? Value(LogicalType::VARCHAR) : Value(value.ToString());
}

//! a VARCHAR[] value; an empty item is NULL (a parameter declared without a type), as ListLiteral writes it
Value ListOf(const vector<string> &items) {
	vector<Value> values;
	for (auto &item : items) {
		values.push_back(item.empty() ? Value(LogicalType::VARCHAR) : Value(item));
	}
	return Value::LIST(LogicalType::VARCHAR, std::move(values));
}

//! spec 147: the rows of (b) - the virtual functions a call reaches and the platform's - as values: answered by a
//! table function a chunk at a time, never written into the listing's SQL (ten thousand UNION branches planned for
//! minutes, one VALUES of ten thousand rows took 8 s and 3 GiB to parse and bind)
vector<vector<Value>> FunctionRows(PolicyStore &store, acl_detail::CatalogBackend *catalog, const Principal &principal,
                                   bool quack_door) {
	vector<vector<Value>> rows;
	auto empty_map = Value::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR, vector<Value>(), vector<Value>());
	auto no_items = Value::LIST(LogicalType::VARCHAR, vector<Value>());
	auto null_text = Value(LogicalType::VARCHAR);
	for (auto &function : CallableFunctions(store, catalog, principal)) {
		string parent, leaf;
		NamePath::SplitLeaf(function.vname, parent, leaf);
		auto schema = parent.empty() ? string("main") : NamePath::Display(parent);
		vector<string> names;
		vector<string> types;
		SplitParams(function.params, names, types);
		// spec 115: a table function's declared result columns are its result type
		Value returns = function.returns;
		if (function.kind == "table" && !function.columns.empty()) {
			vector<string> items;
			for (auto &column : function.columns) {
				items.push_back(QuoteIdentifier(Unquoted(column.name)) +
				                (column.type.empty() ? "" : " " + column.type));
			}
			returns = Value("TABLE(" + StringUtil::Join(items, ", ") + ")");
		}
		rows.push_back(
		    {Value(NamePath::Unquote(function.vcat)),
		     Value(std::to_string(OidValue("database", function.vcat))),
		     Value(schema),
		     Value(leaf),
		     null_text,
		     Value(function.kind),
		     null_text,
		     TextOrNull(function.comment),
		     empty_map,
		     TextOrNull(returns),
		     ListOf(names),
		     ListOf(types),
		     null_text,
		     null_text,
		     Value(LogicalType::BOOLEAN),
		     Value::BOOLEAN(false),
		     null_text,
		     Value::BIGINT(OidValue("function", function.vcat + "\x1f" + function.vname + "\x1f" + function.kind)),
		     no_items,
		     null_text,
		     no_items});
	}
	// spec 117: the platform catalog's functions this principal may call - absent on the quack door
	for (auto &function : PlatformRowsFor(store, principal, quack_door)) {
		rows.push_back({Value("platform"),
		                Value(std::to_string(OidValue("database", "platform"))),
		                Value("main"),
		                Value(function.name),
		                null_text,
		                Value(function.kind),
		                null_text,
		                Value(function.comment),
		                empty_map,
		                Value(function.returns),
		                ListOf(function.parameters),
		                ListOf(function.parameter_types),
		                null_text,
		                null_text,
		                Value::BOOLEAN(function.kind != "table"),
		                Value::BOOLEAN(false),
		                null_text,
		                Value::BIGINT(OidValue("function", "platform\x1fmain\x1f" + function.name)),
		                no_items,
		                null_text,
		                no_items});
	}
	return rows;
}

//! spec 115's rows of acl_function_columns: one per parameter and per declared result column of every function the
//! principal can call, and each scalar's return
vector<vector<Value>> FunctionColumnRows(PolicyStore &store, acl_detail::CatalogBackend *catalog,
                                         const Principal &principal, bool quack_door) {
	vector<vector<Value>> rows;
	auto null_text = Value(LogicalType::VARCHAR);
	auto null_bool = Value(LogicalType::BOOLEAN);
	for (auto &function : CallableFunctions(store, catalog, principal)) {
		// spec 116: each name as a listing shows it - the catalog and the function unquoted, the schema
		// unquoted unless it is a path
		string parent, leaf;
		NamePath::SplitLeaf(function.vname, parent, leaf);
		auto schema = parent.empty() ? string("main") : NamePath::Display(parent);
		vector<Value> head = {Value(NamePath::Unquote(function.vcat)), Value(schema), Value(leaf),
		                      Value(function.kind)};
		auto row = [&](const char *kind, int32_t position, Value name, Value type, Value nullable, Value comment) {
			auto values = head;
			values.insert(values.end(), {Value(kind), Value::INTEGER(position), std::move(name), std::move(type),
			                             std::move(nullable), std::move(comment)});
			rows.push_back(std::move(values));
		};
		vector<string> names;
		vector<string> types;
		SplitParams(function.params, names, types);
		for (idx_t i = 0; i < names.size(); i++) {
			row("param", int32_t(i + 1), Value(names[i]), types[i].empty() ? null_text : Value(types[i]), null_bool,
			    null_text);
		}
		for (idx_t i = 0; i < function.columns.size(); i++) {
			auto &column = function.columns[i];
			row("column", int32_t(i + 1), Value(Unquoted(column.name)),
			    column.type.empty() ? null_text : Value(column.type),
			    column.nullable.IsNull() ? null_bool : column.nullable.DefaultCastAs(LogicalType::BOOLEAN),
			    TextOrNull(column.comment));
		}
		if (function.kind == "scalar" && !function.returns.IsNull()) {
			row("return", 0, null_text, Value(function.returns.ToString()), null_bool, null_text);
		}
	}
	// spec 117: and the platform catalog's functions' parameters
	for (auto &function : PlatformRowsFor(store, principal, quack_door)) {
		vector<Value> head = {Value("platform"), Value("main"), Value(function.name), Value(function.kind)};
		for (idx_t i = 0; i < function.parameters.size(); i++) {
			auto values = head;
			values.insert(values.end(), {Value("param"), Value::INTEGER(int32_t(i + 1)), Value(function.parameters[i]),
			                             Value(function.parameter_types[i]), null_bool, null_text});
			rows.push_back(std::move(values));
		}
		if (function.kind == "scalar") {
			auto values = head;
			values.insert(values.end(), {Value("return"), Value::INTEGER(0), null_text, Value(function.returns),
			                             null_bool, null_text});
			rows.push_back(std::move(values));
		}
	}
	return rows;
}

//! acl_principal_function_rows(roles, quack_door, columns): (b)'s rows for the roles named - in the never set (an
//! acl_* name), reached only by the listing's substitution, which writes the principal's own roles
struct FunctionRowsInfo : TableFunctionInfo {
	explicit FunctionRowsInfo(shared_ptr<PolicyStore> store_p) : store(std::move(store_p)) {
	}
	shared_ptr<PolicyStore> store;
};

struct FunctionRowsBind : TableFunctionData {
	vector<vector<Value>> rows;
};

struct FunctionRowsState : GlobalTableFunctionState {
	idx_t offset = 0;
};

unique_ptr<FunctionData> FunctionRowsBindFn(ClientContext &, TableFunctionBindInput &input, vector<LogicalType> &types,
                                            vector<Identifier> &names) {
	auto bind = make_uniq<FunctionRowsBind>();
	auto &store = *input.info->Cast<FunctionRowsInfo>().store;
	Principal principal;
	if (!input.inputs[0].IsNull()) {
		for (auto &role : ListValue::GetChildren(input.inputs[0])) {
			if (!role.IsNull()) {
				principal.roles.push_back(role.ToString());
			}
		}
	}
	auto quack_door = !input.inputs[1].IsNull() && input.inputs[1].GetValue<bool>();
	auto columns = !input.inputs[2].IsNull() && input.inputs[2].GetValue<bool>();
	auto column = [&](const char *name, const LogicalType &type) {
		names.push_back(Identifier(name));
		types.push_back(type);
	};
	auto text = LogicalType::VARCHAR;
	auto list = LogicalType::LIST(LogicalType::VARCHAR);
	if (columns) {
		for (auto name : {"database_name", "schema_name", "function_name", "function_type", "column_kind"}) {
			column(name, text);
		}
		column("position", LogicalType::INTEGER);
		column("column_name", text);
		column("data_type", text);
		column("is_nullable", LogicalType::BOOLEAN);
		column("comment", text);
		bind->rows = FunctionColumnRows(store, store.catalog.get(), principal, quack_door);
		return std::move(bind);
	}
	for (auto name : {"database_name", "database_oid", "schema_name", "function_name", "alias_of", "function_type",
	                  "description", "comment"}) {
		column(name, text);
	}
	column("tags", LogicalType::MAP(text, text));
	column("return_type", text);
	column("parameters", list);
	column("parameter_types", list);
	column("varargs", text);
	column("macro_definition", text);
	column("has_side_effects", LogicalType::BOOLEAN);
	column("internal", LogicalType::BOOLEAN);
	column("extension_name", text);
	column("function_oid", LogicalType::BIGINT);
	column("examples", list);
	column("stability", text);
	column("categories", list);
	bind->rows = FunctionRows(store, store.catalog.get(), principal, quack_door);
	return std::move(bind);
}

unique_ptr<GlobalTableFunctionState> FunctionRowsInit(ClientContext &, TableFunctionInitInput &) {
	return make_uniq<FunctionRowsState>();
}

void FunctionRowsScan(ClientContext &, TableFunctionInput &input, DataChunk &output) {
	auto &bind = input.bind_data->Cast<FunctionRowsBind>();
	auto &state = input.global_state->Cast<FunctionRowsState>();
	idx_t count = 0;
	for (; state.offset < bind.rows.size() && count < STANDARD_VECTOR_SIZE; state.offset++, count++) {
		auto &row = bind.rows[state.offset];
		for (idx_t c = 0; c < row.size(); c++) {
			output.SetValue(c, count, row[c]);
		}
	}
	output.SetCardinality(count);
}

//! the roles and door as constants of the listing's SQL (the golden rule: no parameter added)
string FunctionRowsCall(PolicyStore &store, const Principal &principal, bool columns) {
	vector<string> roles;
	for (auto &role : principal.roles) {
		roles.push_back(Quote(role));
	}
	return "acl_principal_function_rows([" + StringUtil::Join(roles, ", ") + "]::VARCHAR[], " +
	       (QuackDoor(store, principal) ? "true" : "false") + ", " + (columns ? "true" : "false") + ")";
}

} // namespace

string PolicyStore::PrincipalFunctionColumnsSql(const Principal &principal) {
	// spec 115: one row per parameter and per declared result column of every function the principal
	// can call - what a JDBC driver's getFunctionColumns / getProcedureColumns read; spec 147: answered by
	// acl_principal_function_rows a chunk at a time
	if (!catalog && PlatformRowsFor(*this, principal, QuackDoor(*this, principal)).empty()) {
		return "SELECT NULL::VARCHAR AS database_name, NULL::VARCHAR AS schema_name, NULL::VARCHAR AS function_name, "
		       "NULL::VARCHAR AS function_type, NULL::VARCHAR AS column_kind, NULL::INTEGER AS position, NULL::VARCHAR "
		       "AS column_name, NULL::VARCHAR AS data_type, NULL::BOOLEAN AS is_nullable, NULL::VARCHAR AS comment "
		       "WHERE false";
	}
	return "SELECT * FROM " + FunctionRowsCall(*this, principal, true);
}

string PolicyStore::PrincipalFunctionsSql(const Principal &principal) {
	// (b) first: the virtual functions a call of this principal reaches, each resolved the way a call
	// is. A virtual function also takes the bare call of every engine function of its name and kind
	// (the rewriter resolves virtual functions first, by bare name), so those leave (a). Its rows come from
	// acl_principal_function_rows (spec 147); the resolutions here are the ones it reads back from the cache.
	std::set<string> shadowed; // kind \x1f name
	bool any = !PlatformRowsFor(*this, principal, QuackDoor(*this, principal)).empty();
	for (auto &function : CallableFunctions(*this, catalog.get(), principal)) {
		any = true;
		string parent, leaf;
		NamePath::SplitLeaf(function.vname, parent, leaf);
		if (function.bare) {
			shadowed.insert(function.kind + "\x1f" + StringUtil::Lower(leaf));
		}
	}

	// (a) the engine's functions the gate admits and a bare call reaches - one string key each,
	// `database \x1f schema \x1f name \x1f kind` (a row-value IN over a thousand tuples binds ~4x slower)
	vector<string> keys;
	for (auto &key : FunctionModel()->AdmittedKeys(principal.roles)) {
		auto kind = string(FunctionKindName(key.kind));
		if (shadowed.count(kind + "\x1f" + StringUtil::Lower(key.name))) {
			continue;
		}
		keys.push_back(Quote(StringUtil::Lower(key.database) + "\x1f" + StringUtil::Lower(key.schema) + "\x1f" +
		                     StringUtil::Lower(key.name) + "\x1f" + kind));
	}
	// a row outside the system catalog keeps its name and signature only: its database, schema, oids,
	// definition and the operator's prose about it may all name physical objects
	auto in_system = KeyFoldSql("database_name") + " = 'system'";
	auto only_system = [&](const char *column, const char *otherwise = "NULL") {
		return string("CASE WHEN ") + in_system + " THEN " + column + " ELSE " + otherwise + " END AS " + column;
	};
	string engine =
	    "SELECT " + only_system("database_name") + ", " + only_system("database_oid") + ", " +
	    only_system("schema_name") + ", function_name, alias_of, function_type, " + only_system("description") + ", " +
	    only_system("comment") + ", " + only_system("tags", "MAP {}::MAP(VARCHAR, VARCHAR)") +
	    ", return_type, parameters, parameter_types, varargs, " + only_system("macro_definition") +
	    ", has_side_effects, internal, extension_name, " + only_system("function_oid") + ", " +
	    only_system("examples", "[]::VARCHAR[]") +
	    ", stability, categories FROM system.main.duckdb_functions() WHERE function_type <> 'pragma' AND " +
	    (keys.empty() ? string("false")
	                  : "(" + KeyFoldSql("database_name") + " || chr(31) || " + KeyFoldSql("schema_name") +
	                        " || chr(31) || " + KeyFoldSql("function_name") +
	                        " || "
	                        "chr(31) || CASE WHEN function_type IN ('table', 'table_macro') THEN 'table' ELSE 'scalar' "
	                        "END) IN (" +
	                        StringUtil::Join(keys, ", ") + ")");
	if (!any) {
		return engine;
	}
	return "SELECT * FROM (" + engine + ") UNION ALL SELECT * FROM " + FunctionRowsCall(*this, principal, false);
}

void RegisterAclPrincipalFunctionRows(ExtensionLoader &loader, const shared_ptr<PolicyStore> &store) {
	TableFunction rows(Identifier("acl_principal_function_rows"),
	                   {LogicalType::LIST(LogicalType::VARCHAR), LogicalType::BOOLEAN, LogicalType::BOOLEAN},
	                   FunctionRowsScan, FunctionRowsBindFn, FunctionRowsInit);
	rows.function_info = make_shared_ptr<FunctionRowsInfo>(store);
	loader.RegisterFunction(rows);
}

} // namespace acl
} // namespace duckdb
