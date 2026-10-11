//===----------------------------------------------------------------------===//
// acl_platform_rights.cpp — spec 120.2: what a role gets, and who reads a physical object
//
// platform.effective_rights(role, catalog[, object]) - per object of a catalog: the capabilities the role holds
// and the grant level that decides them, read with the resolver's own expressions (CatalogBackend::GrantDecision),
// MAIN as the resolver judges it (the role's only MAIN catalog), and what a read as the role gets - the columns
// from the role's own columns listing (what DESCRIBE answers it), the masks its grants state, the RLS and
// whether it writes, from ResolveTable, or the resolver's refusal. platform.exposures(source[, schema[, object]])
// - per virtual object, relation body or grant reading a physical source, and per role holding a grant on its
// catalog: the deciding level and the capabilities. Policy facts only: a stored body is parsed, never bound.
//===----------------------------------------------------------------------===//

#include "acl_platform.hpp"
#include "acl_cluster.hpp"
#include "acl_door_common.hpp"
#include "acl_name_path.hpp"
#include "acl_policy_catalog.hpp"
#include "acl_result_rows.hpp"
#include "acl_rewriter.hpp"

#include "duckdb/catalog/catalog.hpp"
#include "duckdb/common/exception/binder_exception.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/main/attached_database.hpp"
#include "duckdb/main/database_manager.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/parser/expression/subquery_expression.hpp"
#include "duckdb/parser/parsed_expression_iterator.hpp"
#include "duckdb/parser/parser.hpp"
#include "duckdb/parser/statement/select_statement.hpp"
#include "duckdb/parser/tableref/basetableref.hpp"
#include "duckdb/parser/tableref/pivotref.hpp"

#include <algorithm>

namespace duckdb {
namespace acl {

using acl_detail::Lit;

namespace {

bool IsWriteCap(const string &cap) {
	return cap == "insert" || cap == "update" || cap == "delete" || cap == "merge";
}

//! What decides one role's caps on one object, as the platform shows it
struct Decision {
	string level; // object | schema <path> [(inherited)] | catalog | none
	vector<string> caps;
	bool main = false;
	acl_detail::CatalogBackend::GrantDecisionRow row;
};

Decision Decide(const acl_detail::CatalogBackend::GrantDecisionRow &row, bool view) {
	Decision out;
	out.row = row;
	if (!out.row.granted) {
		out.level = "none";
		return out;
	}
	out.level = out.row.level;
	if (out.level == "schema") {
		out.level =
		    "schema " + NamePath::Display(out.row.schema_path) + (out.row.schema_inherited ? " (inherited)" : "");
	}
	for (auto &cap : out.row.caps) {
		auto name = StringUtil::Lower(cap);
		// manage administers the catalog - not a right on the object (platform.admins shows it); a view is read,
		// so the grant's other caps reach nothing there
		if (name != "manage" && (!view || name == "select")) {
			out.caps.push_back(name);
		}
	}
	std::sort(out.caps.begin(), out.caps.end());
	out.main = out.row.main;
	return out;
}

void BodyTablesOfNode(QueryNode &node, vector<vector<string>> &tables);

void BodyTablesOfExpr(ParsedExpression &expr, vector<vector<string>> &tables) {
	if (expr.GetExpressionClass() == ExpressionClass::SUBQUERY) {
		auto &subquery = expr.Cast<SubqueryExpression>().SubqueryMutable();
		if (subquery && subquery->node) {
			BodyTablesOfNode(*subquery->node, tables);
		}
	}
	ParsedExpressionIterator::EnumerateChildren(expr,
	                                            [&](ParsedExpression &child) { BodyTablesOfExpr(child, tables); });
}

void BodyTablesOfNode(QueryNode &node, vector<vector<string>> &tables) {
	vector<QueryNode *> pivot_subqueries;
	ParsedExpressionIterator::EnumerateQueryNodeChildren(
	    node, [&](unique_ptr<ParsedExpression> &child) { BodyTablesOfExpr(*child, tables); },
	    [&](TableRef &ref) {
		    if (ref.type == TableReferenceType::BASE_TABLE) {
			    vector<string> parts;
			    for (auto &part : ref.Cast<BaseTableRef>().GetQualifiedName().Path()) {
				    parts.push_back(part.GetIdentifierName());
			    }
			    tables.push_back(std::move(parts));
		    } else if (ref.type == TableReferenceType::PIVOT) {
			    for (auto &column : ref.Cast<PivotRef>().pivots) {
				    if (column.subquery) {
					    pivot_subqueries.push_back(column.subquery.get());
				    }
			    }
		    }
	    });
	for (auto subquery : pivot_subqueries) {
		BodyTablesOfNode(*subquery, tables);
	}
}

//! The tables a stored body names, as written (a view's SELECT, a macro's expression)
void BodyTables(const string &body, bool expression, vector<vector<string>> &tables) {
	auto baked = BakeTemplateForProbe(body, ParserOptions::Builtin(), expression, {});
	Parser parser(ParserOptions::Builtin());
	if (expression) {
		for (auto &expr : parser.ParseExpressionList(baked)) {
			BodyTablesOfExpr(*expr, tables);
		}
		return;
	}
	parser.ParseQuery(baked);
	for (auto &statement : parser.statements) {
		if (statement->type == StatementType::SELECT_STATEMENT) {
			BodyTablesOfNode(*statement->Cast<SelectStatement>().node, tables);
		}
	}
}

Value TextList(const vector<string> &items) {
	vector<Value> values;
	for (auto &item : items) {
		values.emplace_back(item);
	}
	return Value::LIST(LogicalType::VARCHAR, std::move(values));
}

Value Nullable(const string &text) {
	return text.empty() ? Value(LogicalType::VARCHAR) : Value(text);
}

//! The items of a stored column list that compute something (`name = expr`, the grammar's `expr AS name`) - the
//! expressions a body check reads (AuthorizeSources' own split)
vector<string> ColumnExpressions(const string &list) {
	vector<string> out;
	for (auto &item : acl_detail::ParseColumnList(list)) {
		auto piece = item.second.empty() ? item.first : item.second;
		auto as_at = StringUtil::Lower(piece).rfind(" as ");
		if (item.second.empty()) {
			if (as_at == string::npos) {
				continue; // a column named as is reads no table
			}
			piece = piece.substr(0, as_at);
		}
		out.push_back(piece);
	}
	return out;
}

struct RightsInfo : TableFunctionInfo {
	RightsInfo(shared_ptr<PolicyStore> store_p, bool exposures_p) : store(std::move(store_p)), exposures(exposures_p) {
	}
	shared_ptr<PolicyStore> store;
	bool exposures;
};

struct RightsBind : TableFunctionData {
	shared_ptr<PolicyStore> store;
	bool exposures = false;
	vector<string> arguments;
};

struct RightsState : GlobalTableFunctionState {
	vector<vector<Value>> rows;
	idx_t next = 0;
};

unique_ptr<FunctionData> RightsBindFn(ClientContext &, TableFunctionBindInput &input, vector<LogicalType> &types,
                                      vector<Identifier> &names) {
	auto &info = input.info->Cast<RightsInfo>();
	auto bind = make_uniq<RightsBind>();
	bind->store = info.store;
	bind->exposures = info.exposures;
	for (auto &value : input.inputs) {
		bind->arguments.push_back(value.IsNull() ? string() : value.ToString());
	}
	auto column = [&](const char *name, const LogicalType &type) {
		names.push_back(Identifier(name));
		types.push_back(type);
	};
	if (info.exposures) {
		column("source", LogicalType::VARCHAR); // the physical object or schema read
		column("catalog", LogicalType::VARCHAR);
		column("object", LogicalType::VARCHAR); // the virtual object reading it (NULL: a catalog grant)
		column("kind", LogicalType::VARCHAR);   // relation | view | schema_alias | function | grant
		column("role", LogicalType::VARCHAR);
		column("decided_by", LogicalType::VARCHAR);
		column("caps", LogicalType::LIST(LogicalType::VARCHAR));
	} else {
		column("catalog", LogicalType::VARCHAR);
		column("object", LogicalType::VARCHAR);
		column("kind", LogicalType::VARCHAR); // relation | view | schema_alias
		column("decided_by", LogicalType::VARCHAR);
		column("caps", LogicalType::LIST(LogicalType::VARCHAR));
		column("main", LogicalType::BOOLEAN);
		column("rls", LogicalType::VARCHAR);
		column("columns", LogicalType::LIST(LogicalType::VARCHAR));
		column("masks", LogicalType::LIST(LogicalType::VARCHAR));
		column("writable", LogicalType::BOOLEAN);
		column("refused", LogicalType::VARCHAR);
	}
	return std::move(bind);
}

void EffectiveRights(PolicyStore &store, const vector<string> &arguments, RightsState &state) {
	if (arguments.size() < 2 || arguments.size() > 3) {
		throw BinderException("acl_effective_rights(role, catalog[, object])");
	}
	auto &catalog = *store.catalog;
	auto role = arguments[0];
	// the catalog and the object are written as keys, as every admin function reads them - the authorizer judged
	// the same text (review: a raw part here let `'"a.b"'` name another catalog than the one judged)
	auto vcat = store.SpellCatalog(CatalogKey(arguments[1], "acl_effective_rights", "catalog"));
	string only = arguments.size() == 3 && !arguments[2].empty()
	                  ? store.SpellName(vcat, NameKey(arguments[2], "acl_effective_rights", "object"))
	                  : string();
	auto only_eq = [&](const string &column) {
		return only.empty() ? string() : " AND " + KeyEqSql(column, Lit(only));
	};
	// the objects: relations, live aliases, and - under an alias - each object this role holds a grant on (the
	// resolver applies it there) and the one asked for
	auto rows = catalog.Query(
	    "SELECT \"vname\", coalesce(\"form\", '') FROM " + catalog.Tbl("relations") + " WHERE \"vcat\" = " + Lit(vcat) +
	    only_eq("\"vname\"") + " UNION ALL SELECT \"path\", 'schema_alias' FROM " + catalog.Tbl("schemas") +
	    " WHERE \"vcat\" = " + Lit(vcat) + " AND \"phys_path\" IS NOT NULL AND \"phys_path\" <> ''" +
	    only_eq("\"path\"") + " UNION ALL SELECT oc.\"vname\", 'alias_object' FROM " + catalog.Tbl("role_object_caps") +
	    " oc WHERE oc.\"role\" = " + Lit(role) + " AND oc.\"vcat\" = " + Lit(vcat) + only_eq("oc.\"vname\"") +
	    " AND NOT EXISTS (SELECT 1 FROM " + catalog.Tbl("relations") + " r WHERE r.\"vcat\" = oc.\"vcat\" AND " +
	    KeyEqSql("r.\"vname\"", "oc.\"vname\"") + ") AND NOT EXISTS (SELECT 1 FROM " + catalog.Tbl("schemas") +
	    " s WHERE s.\"vcat\" = oc.\"vcat\" AND " + KeyEqSql("s.\"path\"", "oc.\"vname\"") + ") ORDER BY 1");
	ResultRows objects(*rows);
	vector<std::pair<string, string>> listed;
	for (idx_t i = 0; i < objects.Count(); i++) {
		listed.emplace_back(objects.GetValue(0, i).ToString(), objects.GetValue(1, i).ToString());
	}
	if (!only.empty() && listed.empty()) {
		listed.emplace_back(only, "alias_object"); // an object under an alias nobody granted by name
	}
	Principal principal;
	principal.roles = {role};
	// what the role reads, column by column: its own columns listing - the surface DESCRIBE answers it from
	map<std::pair<string, string>, vector<string>> read_columns;
	string listing_error;
	try {
		ListingScope scope;
		scope.catalogs = {NamePath::Display(vcat)};
		if (!only.empty()) {
			string parent, leaf;
			NamePath::SplitLeaf(only, parent, leaf);
			scope.tables = {leaf}; // the listing narrows by name; the schema is matched below
		}
		auto sql = catalog.MetadataListingSql(principal, "columns", string(), string(), scope);
		auto listing = catalog.Query("SELECT table_catalog, table_schema, table_name, column_name FROM (" + sql +
		                             ") ORDER BY table_schema, table_name, ordinal_position");
		ResultRows columns(*listing);
		for (idx_t i = 0; i < columns.Count(); i++) {
			auto schema = StringUtil::Lower(columns.GetValue(1, i).ToString());
			auto table = StringUtil::Lower(columns.GetValue(2, i).ToString());
			read_columns[{schema, table}].push_back(columns.GetValue(3, i).ToString());
		}
	} catch (std::exception &ex) {
		listing_error = ErrorData(ex).RawMessage();
	}
	vector<string> names;
	for (auto &object : listed) {
		names.push_back(object.first);
	}
	auto decided = catalog.GrantDecisions(role, vcat, names);
	for (idx_t o = 0; o < listed.size(); o++) {
		auto &object = listed[o];
		auto &vname = object.first;
		auto kind = object.second == "schema_alias" ? "schema_alias" : object.second == "view" ? "view" : "relation";
		auto decision = Decide(decided[o], string(kind) == "view");
		Value rls(LogicalType::VARCHAR), columns(LogicalType::LIST(LogicalType::VARCHAR)),
		    masks(LogicalType::LIST(LogicalType::VARCHAR)), writable(false), refused(LogicalType::VARCHAR);
		if (string(kind) != "schema_alias" && decision.level != "none") {
			TablePolicy policy;
			bool resolved = false;
			try {
				resolved = store.ResolveTable(principal, vcat + "." + vname, policy);
			} catch (std::exception &ex) {
				refused = Value(ErrorData(ex).RawMessage()); // every read of it refuses with this
			}
			if (resolved) {
				// a view's grant predicates are folded into its query (ApplyGrantPolicy), a relation's into rls
				vector<string> predicates;
				for (auto &predicate : {decision.row.catalog_rls, decision.row.object_rls}) {
					auto trimmed = predicate;
					StringUtil::Trim(trimmed);
					if (!trimmed.empty()) {
						predicates.push_back("(" + trimmed + ")");
					}
				}
				rls = Nullable(policy.query.empty() || !policy.rls.empty() ? policy.rls
				                                                           : StringUtil::Join(predicates, " AND "));
				bool writes = false;
				for (auto &cap : decision.caps) {
					writes = writes || IsWriteCap(cap);
				}
				writable = Value::BOOLEAN(policy.writable && writes);
				string schema, leaf;
				NamePath::SplitLeaf(vname, schema, leaf);
				auto key =
				    std::make_pair(StringUtil::Lower(schema.empty() ? string("main") : NamePath::Display(schema)),
				                   StringUtil::Lower(leaf));
				auto found = read_columns.find(key);
				if (!listing_error.empty()) {
					refused = Value("the columns listing failed: " + listing_error);
				} else if (found == read_columns.end()) {
					columns = TextList({}); // the role reads none of its columns - a read of it fails
					masks = TextList({});
				} else {
					columns = TextList(found->second);
					// the masks the role's grants state, on the columns it reads
					vector<string> stated;
					for (auto &list : {decision.row.catalog_columns, decision.row.object_columns}) {
						for (auto &item : acl_detail::ParseColumnList(list)) {
							for (auto &name : found->second) {
								if (!item.second.empty() && StringUtil::CIEquals(item.first, name)) {
									stated.push_back(item.first + " = " + item.second);
								}
							}
						}
					}
					masks = TextList(stated);
				}
			}
		}
		state.rows.push_back({Value(NamePath::Display(vcat)), Value(NamePath::Display(vname)), Value(kind),
		                      Value(decision.level), TextList(decision.caps), Value::BOOLEAN(decision.main), rls,
		                      columns, masks, writable, refused});
	}
}

void Exposures(PolicyStore &store, const vector<string> &arguments, RightsState &state) {
	if (arguments.empty() || arguments.size() > 3 || arguments[0].empty()) {
		throw BinderException("acl_exposures(source[, schema[, object]])");
	}
	auto &catalog = *store.catalog;
	// positional: an empty schema with an object asks for that object in any schema
	vector<string> asked(arguments.begin(), arguments.end());
	while (!asked.empty() && asked.back().empty()) {
		asked.pop_back();
	}
	vector<string> leading;
	for (auto &part : asked) {
		if (part.empty()) {
			break;
		}
		leading.push_back(part);
	}
	auto prefix = NamePath(leading).ToKey();
	// how the node reads a short name: the default database, and each database's default schema (a postgres
	// catalog's is `public`) - `t` is `<default db>.<its schema>.t`, `x.t` is `x.<x's schema>.t` when x is a
	// database, else `<default db>.x.t`
	string default_db;
	case_insensitive_map_t<string> default_schema;
	{
		Connection con(*catalog.Db());
		con.context->RunFunctionInTransaction([&]() {
			auto &manager = DatabaseManager::Get(*con.context);
			default_db = DatabaseManager::TryGetDefaultDatabase(*con.context).GetIdentifierName();
			for (auto &db : manager.GetDatabases(*con.context)) {
				string schema = "main";
				try {
					auto stated = db->GetCatalog().GetDefaultSchema();
					if (stated) {
						schema = stated->GetIdentifierName();
					}
				} catch (std::exception &) {
				}
				default_schema[db->GetName().GetIdentifierName()] = schema;
			}
		});
	}
	auto schema_of = [&](const string &db) {
		auto found = default_schema.find(db);
		return found == default_schema.end() ? string("main") : found->second;
	};
	auto normalize = [&](vector<string> parts) {
		if (parts.size() == 1) {
			parts.insert(parts.begin(), {default_db, schema_of(default_db)});
		} else if (parts.size() == 2) {
			if (default_schema.count(parts[0])) {
				parts.insert(parts.begin() + 1, schema_of(parts[0]));
			} else {
				parts.insert(parts.begin(), default_db);
			}
		}
		return parts;
	};
	// a physical name within what is asked (or what is asked within a stored schema)
	auto within_parts = [&](const vector<string> &parts) {
		auto n = std::min(parts.size(), asked.size());
		for (idx_t i = 0; i < n; i++) {
			if (!asked[i].empty() && !StringUtil::CIEquals(parts[i], asked[i])) {
				return false;
			}
		}
		return n > 0;
	};
	auto key_parts = [&](const string &key, vector<string> &parts) {
		NamePath path;
		string error;
		if (!NamePath::TryFromKey(key, path, error)) {
			return false;
		}
		parts = path.Parts();
		return true;
	};
	// the tables a body names that lie within what is asked; a body that does not parse is judged by its text -
	// the database named anywhere in it - and shown under what was asked
	auto body_reads = [&](const string &body, bool expression) {
		vector<string> sources;
		vector<vector<string>> tables;
		try {
			BodyTables(body, expression, tables);
		} catch (std::exception &) {
			if (SqlNamesSourceOf(body, asked[0])) {
				sources.push_back(prefix);
			}
			return sources;
		}
		for (auto &table : tables) {
			auto parts = normalize(table);
			if (within_parts(parts)) {
				auto key = NamePath(parts).ToKey();
				if (std::find(sources.begin(), sources.end(), key) == sources.end()) {
					sources.push_back(key);
				}
			}
		}
		return sources;
	};
	struct Reader {
		string source, vcat, vname, kind;
		string role;          // a grant's body: that role only
		string decided_vname; // the name the resolver decides on (an object inside an alias)
	};
	vector<Reader> readers;
	auto add_bodies = [&](const vector<string> &sources, const Reader &base) {
		for (auto &source : sources) {
			auto reader = base;
			reader.source = source;
			readers.push_back(reader);
		}
	};
	auto text = [](const Value &value) {
		return value.IsNull() ? string() : value.ToString();
	};
	auto relations = catalog.Query("SELECT \"vcat\", \"vname\", \"phys\", coalesce(\"form\", ''), \"view_sql\", "
	                               "\"rls\" FROM " +
	                               catalog.Tbl("relations"));
	ResultRows relation_rows(*relations);
	for (idx_t i = 0; i < relation_rows.Count(); i++) {
		Reader base;
		base.vcat = relation_rows.GetValue(0, i).ToString();
		base.vname = relation_rows.GetValue(1, i).ToString();
		auto phys = text(relation_rows.GetValue(2, i));
		auto view_sql = text(relation_rows.GetValue(4, i));
		vector<string> parts;
		base.kind = view_sql.empty() ? "relation" : "view";
		if (!phys.empty() && key_parts(phys, parts) && within_parts(normalize(parts))) {
			add_bodies({NamePath(normalize(parts)).ToKey()}, base);
		}
		if (!view_sql.empty()) {
			add_bodies(body_reads(view_sql, false), base);
		}
		add_bodies(body_reads(text(relation_rows.GetValue(5, i)), true), base); // the relation's own RLS
	}
	auto columns = catalog.Query("SELECT \"vcat\", \"vname\", \"expr\" FROM " + catalog.Tbl("relation_columns") +
	                             " WHERE \"expr\" IS NOT NULL AND trim(\"expr\") <> ''");
	ResultRows column_rows(*columns);
	for (idx_t i = 0; i < column_rows.Count(); i++) {
		Reader base;
		base.vcat = column_rows.GetValue(0, i).ToString();
		base.vname = column_rows.GetValue(1, i).ToString();
		base.kind = "relation"; // a computed column
		add_bodies(body_reads(column_rows.GetValue(2, i).ToString(), true), base);
	}
	auto schemas = catalog.Query("SELECT \"vcat\", \"path\", \"phys_path\" FROM " + catalog.Tbl("schemas") +
	                             " WHERE \"phys_path\" IS NOT NULL AND \"phys_path\" <> ''");
	ResultRows schema_rows(*schemas);
	for (idx_t i = 0; i < schema_rows.Count(); i++) {
		auto phys_path = schema_rows.GetValue(2, i).ToString();
		vector<string> parts;
		if (!key_parts(phys_path, parts) || !within_parts(parts)) {
			continue;
		}
		bool wildcard_above = false; // `phys, NULL, t` over an alias of phys.raw: whether raw holds t is the source's
		for (idx_t p = 0; p < parts.size() && p < asked.size(); p++) {
			wildcard_above = wildcard_above || asked[p].empty();
		}
		if (wildcard_above && asked.size() > parts.size()) {
			continue;
		}
		Reader reader;
		reader.source = phys_path;
		reader.vcat = schema_rows.GetValue(0, i).ToString();
		reader.vname = schema_rows.GetValue(1, i).ToString();
		reader.kind = "schema_alias";
		// asked inside the alias: the object the resolver decides on is the alias path + the rest (an object
		// grant there applies to it)
		if (asked.size() > parts.size()) {
			auto inner = reader.vname;
			bool named = true;
			for (idx_t p = parts.size(); p < asked.size(); p++) {
				named = named && !asked[p].empty();
				inner = NamePath::ChildKey(inner, asked[p]);
			}
			if (named) {
				reader.decided_vname = inner;
				reader.source = NamePath(asked).ToKey();
			}
		}
		readers.push_back(reader);
	}
	auto functions = catalog.Query("SELECT \"vcat\", \"vname\", \"target\", \"template\", \"kind\" FROM " +
	                               catalog.Tbl("functions"));
	ResultRows function_rows(*functions);
	for (idx_t i = 0; i < function_rows.Count(); i++) {
		Reader base;
		base.vcat = function_rows.GetValue(0, i).ToString();
		base.vname = function_rows.GetValue(1, i).ToString();
		base.kind = "function";
		auto target = text(function_rows.GetValue(2, i));
		vector<string> parts;
		if (!target.empty() && key_parts(target, parts) && within_parts(normalize(parts))) {
			add_bodies({NamePath(normalize(parts)).ToKey()}, base); // an alias of a physical function
		}
		auto body = text(function_rows.GetValue(3, i));
		if (!body.empty()) {
			add_bodies(body_reads(body, function_rows.GetValue(4, i).ToString() == "scalar"), base);
		}
	}
	// a grant's own bodies (its RLS, its masks): they read for that role, on the catalog or on one object
	for (auto object_level : {false, true}) {
		auto grants = catalog.Query(string("SELECT \"role\", \"vcat\", ") + (object_level ? "\"vname\"" : "NULL") +
		                            ", \"rls\", \"columns\" FROM " +
		                            catalog.Tbl(object_level ? "role_object_caps" : "role_catalogs"));
		ResultRows grant_rows(*grants);
		for (idx_t i = 0; i < grant_rows.Count(); i++) {
			Reader base;
			base.role = grant_rows.GetValue(0, i).ToString();
			base.vcat = grant_rows.GetValue(1, i).ToString();
			base.vname = text(grant_rows.GetValue(2, i));
			base.kind = "grant";
			auto sources = body_reads(text(grant_rows.GetValue(3, i)), true);
			for (auto &expression : ColumnExpressions(text(grant_rows.GetValue(4, i)))) {
				for (auto &source : body_reads(expression, true)) {
					if (std::find(sources.begin(), sources.end(), source) == sources.end()) {
						sources.push_back(source);
					}
				}
			}
			add_bodies(sources, base);
		}
	}
	// the decisions, asked once per (catalog, role) for every name its readers need - a query per row was the cost
	map<string, vector<string>> catalog_roles;
	auto roles_of = [&](const Reader &reader) -> vector<string> {
		if (!reader.role.empty()) {
			return {reader.role};
		}
		auto found = catalog_roles.find(reader.vcat);
		if (found == catalog_roles.end()) {
			auto rows = catalog.Query("SELECT DISTINCT \"role\" FROM " + catalog.Tbl("role_catalogs") +
			                          " WHERE \"vcat\" = " + Lit(reader.vcat) + " ORDER BY 1");
			ResultRows role_rows(*rows);
			vector<string> roles;
			for (idx_t r = 0; r < role_rows.Count(); r++) {
				roles.push_back(role_rows.GetValue(0, r).ToString());
			}
			found = catalog_roles.emplace(reader.vcat, std::move(roles)).first;
		}
		return found->second;
	};
	auto decided_of = [](const Reader &reader) {
		return reader.decided_vname.empty() ? reader.vname : reader.decided_vname;
	};
	struct Asked {
		vector<string> names;
		map<string, idx_t> index;
		vector<acl_detail::CatalogBackend::GrantDecisionRow> rows;
	};
	map<std::pair<string, string>, Asked> asked_for;
	for (auto &reader : readers) {
		for (auto &role : roles_of(reader)) {
			auto &entry = asked_for[{reader.vcat, role}];
			auto name = decided_of(reader);
			if (entry.index.emplace(name, entry.names.size()).second) {
				entry.names.push_back(name);
			}
		}
	}
	for (auto &entry : asked_for) {
		entry.second.rows = catalog.GrantDecisions(entry.first.second, entry.first.first, entry.second.names);
	}
	for (auto &reader : readers) {
		auto decided = decided_of(reader);
		for (auto &role : roles_of(reader)) {
			auto &entry = asked_for[{reader.vcat, role}];
			auto decision = Decide(entry.rows[entry.index[decided]], reader.kind == "view");
			// a catalog grant's body reads wherever that grant reaches: its own caps, as stated
			auto level = reader.kind == "grant" && reader.vname.empty() ? string("catalog") : decision.level;
			state.rows.push_back(
			    {Value(reader.source), Value(NamePath::Display(reader.vcat)),
			     reader.vname.empty() ? Value(LogicalType::VARCHAR) : Value(NamePath::Display(decided)),
			     Value(reader.kind), Value(role), Value(level), TextList(decision.caps)});
		}
	}
}

unique_ptr<GlobalTableFunctionState> RightsInit(ClientContext &, TableFunctionInitInput &input) {
	auto &bind = input.bind_data->Cast<RightsBind>();
	auto state = make_uniq<RightsState>();
	if (!bind.store->catalog || bind.store->catalog->FunctionMode()) {
		throw BinderException("acl: %s needs a policy catalog (acl_use_db)",
		                      bind.exposures ? "acl_exposures" : "acl_effective_rights");
	}
	if (bind.exposures) {
		Exposures(*bind.store, bind.arguments, *state);
	} else {
		EffectiveRights(*bind.store, bind.arguments, *state);
	}
	return std::move(state);
}

void RightsScan(ClientContext &, TableFunctionInput &data, DataChunk &output) {
	auto &state = data.global_state->Cast<RightsState>();
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

} // namespace

void StoredBodyTables(const string &body, bool expression, vector<vector<string>> &tables) {
	BodyTables(body, expression, tables);
}

void RegisterAclPlatformRights(ExtensionLoader &loader, const shared_ptr<PolicyStore> &store) {
	const LogicalType &v = LogicalType::VARCHAR;
	for (auto exposures : {false, true}) {
		auto name = exposures ? "acl_exposures" : "acl_effective_rights";
		TableFunctionSet set((Identifier(name)));
		auto arities = exposures ? vector<idx_t> {1, 2, 3} : vector<idx_t> {2, 3};
		for (auto arity : arities) {
			TableFunction function(Identifier(name), vector<LogicalType>(arity, v), RightsScan, RightsBindFn,
			                       RightsInit);
			function.function_info = make_shared_ptr<RightsInfo>(store, exposures);
			set.AddFunction(function);
		}
		loader.RegisterFunction(set);
	}
}

} // namespace acl
} // namespace duckdb
