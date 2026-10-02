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
#include "acl_policy_catalog.hpp"

#include <set>

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

} // namespace

string PolicyStore::PrincipalFunctionsSql(const Principal &principal) {
	// (b) first: the virtual functions a call of this principal reaches, each resolved the way a call
	// is. A virtual function also takes the bare call of every engine function of its name and kind
	// (the rewriter resolves virtual functions first, by bare name), so those leave (a).
	vector<string> rows;
	std::set<string> shadowed; // kind \x1f name
	if (catalog) {
		for (auto &function : catalog->VisibleFunctions(principal)) {
			TablePolicy policy;
			bool resolved = false;
			try {
				resolved = function.kind == "table" ? ResolveTableFunction(principal, function.vname, policy)
				                                    : ResolveScalarFunction(principal, function.vname, policy);
			} catch (BinderException &) {
				// what refuses the call (a scalar under a grant that carries a policy) keeps it out of
				// the listing - never the whole listing out with it
				continue;
			}
			if (!resolved || !policy.caps.count("select")) {
				continue; // a call needs select (spec 012)
			}
			shadowed.insert(function.kind + "\x1f" + StringUtil::Lower(function.vname));
			vector<string> names;
			vector<string> types;
			SplitParams(function.params, names, types);
			rows.push_back("SELECT " + Quote(function.vcat) + "::VARCHAR, " + OidOf("database", function.vcat) +
			               "::VARCHAR, 'main'::VARCHAR, " + Quote(function.vname) + "::VARCHAR, NULL::VARCHAR, " +
			               Quote(function.kind) + "::VARCHAR, NULL::VARCHAR, " + QuoteOrNull(function.comment) +
			               "::VARCHAR, MAP {}::MAP(VARCHAR, VARCHAR), " + QuoteOrNull(function.returns) +
			               "::VARCHAR, " + ListLiteral(names) + ", " + ListLiteral(types) +
			               ", NULL::VARCHAR, NULL::VARCHAR, NULL::BOOLEAN, false, NULL::VARCHAR, " +
			               OidOf("function", function.vcat + "\x1f" + function.vname + "\x1f" + function.kind) +
			               ", []::VARCHAR[], NULL::VARCHAR, []::VARCHAR[]");
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
	auto in_system = string("lower(database_name) = 'system'");
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
	                  : "(lower(database_name) || chr(31) || lower(schema_name) || chr(31) || lower(function_name) || "
	                    "chr(31) || CASE WHEN function_type IN ('table', 'table_macro') THEN 'table' ELSE 'scalar' "
	                    "END) IN (" +
	                        StringUtil::Join(keys, ", ") + ")");
	if (rows.empty()) {
		return engine;
	}
	return "SELECT * FROM (" + engine + ") UNION ALL (" + StringUtil::Join(rows, " UNION ALL ") + ")";
}

} // namespace acl
} // namespace duckdb
