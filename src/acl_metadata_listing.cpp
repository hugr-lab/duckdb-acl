// The metadata surfaces of the catalog backend (specs 025/026/030/046): the SQL that answers a
// principal's information_schema / duckdb_* / SHOW listings from the policy it is granted, and the
// acl_* introspection rows an administrator reads. Split from acl_policy_catalog.cpp (plan 4.2).

#include "acl_result_rows.hpp"
#include "acl_policy_catalog.hpp"
#include "acl_platform.hpp"
#include "acl_types.hpp"

#include <map>

namespace duckdb {
namespace acl {
namespace acl_detail {

namespace {

//! Whether a caps chain admits `capability` the way the resolver's default reads it (spec 012: unstated = the data
//! capabilities, an explicit '{}' = none). A caps JSON is admin-written, so the true-flag test is textual.
string CapsAllowSql(const string &caps_expr, const char *capability) {
	return "(" + caps_expr + " IS NULL OR trim(" + caps_expr + ") = '' OR regexp_matches(" + caps_expr + ", '(?i)\"" +
	       capability + "\"\\s*:\\s*true'))";
}

} // namespace

vector<CatalogBackend::VisibleFunction> CatalogBackend::VisibleFunctions(const Principal &principal) {
	vector<VisibleFunction> out;
	if (function_mode || principal.roles.empty()) {
		return out; // a function driver enumerates no functions (spec 008); no role holds none
	}
	EnsureFresh();
	string oc_join = HasObjectCaps() ? " LEFT JOIN " + Tbl("role_object_caps") +
	                                       " oc ON oc.\"role\" = g.\"role\" AND oc.\"vcat\" = f.\"vcat\""
	                                       " AND oc.\"vname\" = f.\"vname\""
	                                 : string();
	// the same visibility a call resolves with: a grant on the catalog that is not an explicit nothing.
	// Every catalog the principal holds (spec 115): a call reaches any of them qualified; a flat name of
	// the one MAIN catalog is also reached bare
	// spec 147: which functions a row shows is decided per (function, role) pair - with only the levels the roles hold
	// (PrincipalCapsLevels) - and what is read of each function once, after: the pairs are functions x roles
	bool object_level, schema_level;
	PrincipalCapsLevels(principal, object_level, schema_level);
	string visible_oc_join = object_level ? oc_join : string();
	auto sql = GrantsCte(principal) +
	           ", vis AS (SELECT f.\"vcat\" AS vcat, f.\"vname\" AS vname, f.\"kind\" AS kind,"
	           " bool_or(g.\"is_main\" = true AND (SELECT unique_main FROM main_ok) AND NOT " +
	           KeyNestedSql("f.\"vname\"") + ") AS bare FROM " + Tbl("functions") +
	           " f JOIN grants g ON g.\"vcat\" = f.\"vcat\"" + visible_oc_join + " WHERE " +
	           FunctionVisibleExpr(object_level, schema_level) +
	           " GROUP BY 1, 2, 3)"
	           " SELECT v.vcat, v.vname, v.kind, any_value(f.\"params\"), any_value(f.\"comment\"),"
	           " (SELECT c.\"type\" FROM " +
	           Tbl("object_columns") +
	           " c WHERE c.\"vcat\" = v.vcat AND c.\"vname\" = v.vname AND c.\"kind\" = 'scalar'"
	           " ORDER BY c.\"pos\" LIMIT 1), any_value(v.bare) FROM vis v JOIN " +
	           Tbl("functions") +
	           " f ON f.\"vcat\" = v.vcat AND f.\"vname\" = v.vname AND f.\"kind\" = v.kind GROUP BY 1, 2, 3 ORDER BY"
	           " 1, 2, 3";
	auto result = Query(sql);
	ResultRows rows(*result);
	case_insensitive_map_t<idx_t> table_functions; // vcat \x1f vname -> index in out
	for (idx_t row = 0; row < rows.Count(); row++) {
		VisibleFunction function;
		function.vcat = rows.GetValue(0, row).ToString();
		function.vname = rows.GetValue(1, row).ToString();
		function.kind = rows.GetValue(2, row).ToString();
		auto params = rows.GetValue(3, row);
		function.params = params.IsNull() ? string() : params.ToString();
		function.comment = rows.GetValue(4, row);
		function.returns = function.kind == "scalar" ? rows.GetValue(5, row) : Value();
		auto bare = rows.GetValue(6, row);
		function.bare = !bare.IsNull() && bare.GetValue<bool>();
		if (function.kind == "table") {
			table_functions[function.vcat + "\x1f" + function.vname] = out.size();
		}
		out.push_back(std::move(function));
	}
	if (!table_functions.empty()) {
		// the declared result columns of the visible table functions - one read for all of them
		auto columns = Query("SELECT \"vcat\", \"vname\", \"name\", \"type\", \"nullable\", \"comment\" FROM " +
		                     Tbl("object_columns") + " WHERE \"kind\" = 'table' ORDER BY \"vcat\", \"vname\", \"pos\"");
		ResultRows column_rows(*columns);
		for (idx_t row = 0; row < column_rows.Count(); row++) {
			auto entry = table_functions.find(column_rows.GetValue(0, row).ToString() + "\x1f" +
			                                  column_rows.GetValue(1, row).ToString());
			if (entry == table_functions.end()) {
				continue;
			}
			VisibleFunction::Column column;
			column.name = column_rows.GetValue(2, row).ToString();
			auto type = column_rows.GetValue(3, row);
			column.type = type.IsNull() ? string() : type.ToString();
			column.nullable = column_rows.GetValue(4, row);
			column.comment = column_rows.GetValue(5, row);
			out[entry->second].columns.push_back(std::move(column));
		}
	}
	return out;
}

string CatalogBackend::MetadataListingSql(const Principal &principal, const string &surface,
                                          const string &platform_objects, const string &platform_columns,
                                          const ListingScope &asked) {
	// spec 121: objects named by key (the keys / references surfaces) become the schemas and tables to read - with,
	// for references, every object at a reference's other end (its columns decide whether the reference shows)
	ListingScope scope = asked;
	if (!asked.objects.empty() && asked.schemas.empty() && asked.tables.empty()) {
		vector<string> objects = asked.objects;
		if (surface == "references" && !function_mode) {
			vector<string> keys;
			for (auto &object : asked.objects) {
				keys.push_back(Lit(StringUtil::Lower(object)));
			}
			auto in_objects = " IN (" + StringUtil::Join(keys, ", ") + ")";
			auto ends =
			    Query("SELECT DISTINCT \"from_vname\", \"to_vname\" FROM " + Tbl("references") + " WHERE " +
			          KeyFoldSql("\"from_vname\"") + in_objects + " OR " + KeyFoldSql("\"to_vname\"") + in_objects);
			ResultRows end_rows(*ends);
			for (idx_t i = 0; i < end_rows.Count(); i++) {
				for (idx_t c = 0; c < 2; c++) {
					auto value = end_rows.GetValue(c, i);
					if (!value.IsNull()) {
						objects.push_back(StringUtil::Lower(value.ToString()));
					}
				}
			}
		}
		std::set<string> schemas, tables;
		for (auto &object : objects) {
			string parent, leaf;
			if (!NamePath::SplitLeaf(object, parent, leaf)) {
				scope = ListingScope(); // a name that is no key narrows nothing
				scope.catalogs = asked.catalogs;
				schemas.clear();
				tables.clear();
				break;
			}
			schemas.insert(parent.empty() ? string("main") : NamePath::Display(parent));
			tables.insert(leaf);
		}
		scope.schemas.assign(schemas.begin(), schemas.end());
		scope.tables.assign(tables.begin(), tables.end());
	}
	// spec 117: the system catalog's views this principal holds - constants, one `platform.main` schema
	bool platform = !platform_objects.empty();
	if (function_mode) {
		throw BinderException("acl: this policy source does not expose enumeration, so %s cannot be listed "
		                      "for a principal",
		                      surface);
	}
	// spec 147: a level of the caps chain no row of the principal's roles holds is no term - its join and its
	// correlated read per (object, role) pair were the listing's cost with many roles
	bool object_level, schema_level;
	PrincipalCapsLevels(principal, object_level, schema_level);
	auto caps_chain = [&](const string &name_expr, const string &vcat_expr) {
		return CapsExpr(name_expr, vcat_expr, object_level, schema_level);
	};
	// an object appears when the role holds something on it; '{}' is an explicit nothing (spec 012)
	auto relation_caps = caps_chain("r.\"vname\"", "r.\"vcat\"");
	auto visible =
	    "(" + relation_caps + " IS NULL OR trim(" + relation_caps + ") = '' OR trim(" + relation_caps + ") <> '{}')";
	string oc_join = object_level ? " LEFT JOIN " + Tbl("role_object_caps") +
	                                    " oc ON oc.\"role\" = g.\"role\" AND oc.\"vcat\" = r.\"vcat\""
	                                    " AND oc.\"vname\" = r.\"vname\""
	                              : string();
	// spec 039: a declared-list object whose source lost a column is MARKED, not narrowed. The
	// declared entries that read a bare source column (a name, or a quoted one - an expression is
	// not judged, and neither is a constant or one of SQL's bare-word functions) with no column of
	// that name in the physical table are what the mark names - a join over catalog facts and ONE
	// scan of the same information_schema the columns surface already reads, never a probe (spec
	// 065). The columns surface keeps the contract as written; the mark on the object says the read
	// will fail anyway, and acl_check_catalog (which probes) has the rest.
	// spec 119: the physical facts are read per source - the schemas the policy's objects and aliases name,
	// each read directly (acl_physical_tables / _columns) - never duckdb's information_schema, which walks
	// every attached database; the broken-list mark only over the relations that declare a list
	vector<string> source_keys, declared_phys, alias_keys;
	{
		// spec 119 §2: what the query asks about narrows which physical sources are read - the keys of the
		// shown names (a catalog / a table is one part; a schema as shown, a key when it is a path)
		auto in_list = [&](const vector<string> &values, const string &expr, bool schema) {
			vector<string> keys;
			for (auto &value : values) {
				keys.push_back(
				    Lit(StringUtil::Lower(schema ? NamePath::FromDisplay(value) : NamePath::QuotePart(value))));
			}
			return " AND " + KeyFoldSql(expr) + " IN (" + StringUtil::Join(keys, ", ") + ")";
		};
		string relation_scope, alias_scope;
		if (!scope.catalogs.empty()) {
			relation_scope += in_list(scope.catalogs, "\"vcat\"", false);
			alias_scope += in_list(scope.catalogs, "\"vcat\"", false);
		}
		if (!scope.schemas.empty()) {
			relation_scope +=
			    in_list(scope.schemas, "coalesce(nullif(" + KeyParentSql("\"vname\"") + ", ''), 'main')", true);
			alias_scope += in_list(scope.schemas, "\"path\"", true);
		}
		if (!scope.tables.empty()) {
			relation_scope += in_list(scope.tables, KeyLeafSql("\"vname\""), false);
		}
		bool narrowed = !scope.Empty();
		std::set<string> seen;
		std::set<string> alias_seen;
		auto add_key = [&](const vector<string> &parts, bool alias) {
			auto key = NamePath(parts).ToKey();
			if (seen.insert(StringUtil::Lower(key)).second) {
				source_keys.push_back(Lit(key));
			}
			if (alias && alias_seen.insert(StringUtil::Lower(key)).second) {
				alias_keys.push_back(Lit(key));
			}
		};
		// a relation: its physical object when the query narrows (a handful of rows), else its schema
		auto rows =
		    Query("SELECT DISTINCT \"phys\" FROM " + Tbl("relations") + " WHERE \"phys\" IS NOT NULL" + relation_scope);
		ResultRows phys_rows(*rows);
		for (idx_t i = 0; i < phys_rows.Count(); i++) {
			NamePath path;
			string error;
			if (!NamePath::TryFromKey(phys_rows.GetValue(0, i).ToString(), path, error) || path.Parts().size() < 2) {
				continue;
			}
			auto parts = path.Parts();
			if (parts.size() == 2) {
				parts.insert(parts.begin() + 1, "main"); // <db>.<table>: the database's main
			}
			add_key(narrowed ? parts : vector<string> {parts[0], parts[1]}, false);
		}
		// a schema alias: its physical schema - or, when the query names tables, those tables of it
		auto aliases_rows = Query("SELECT DISTINCT \"phys_path\" FROM " + Tbl("schemas") +
		                          " WHERE \"phys_path\" IS NOT NULL AND \"phys_path\" <> ''" + alias_scope);
		ResultRows alias_rows(*aliases_rows);
		for (idx_t i = 0; i < alias_rows.Count(); i++) {
			NamePath path;
			string error;
			if (!NamePath::TryFromKey(alias_rows.GetValue(0, i).ToString(), path, error) || path.Parts().size() != 2) {
				continue;
			}
			if (scope.tables.empty()) {
				add_key(path.Parts(), true);
				continue;
			}
			for (auto &table : scope.tables) {
				add_key({path.Parts()[0], path.Parts()[1], table}, true);
			}
		}
		auto declared_rows =
		    Query("SELECT DISTINCT r.\"phys\" FROM " + Tbl("relations") + " r JOIN " + Tbl("relation_columns") +
		          " dc ON dc.\"vcat\" = r.\"vcat\" AND dc.\"vname\" = r.\"vname\" WHERE r.\"form\" IN ('alias',"
		          " 'subquery') AND r.\"phys\" IS NOT NULL" +
		          StringUtil::Replace(StringUtil::Replace(relation_scope, "\"vcat\"", "r.\"vcat\""), "\"vname\"",
		                              "r.\"vname\""));
		ResultRows declared_phys_rows(*declared_rows);
		for (idx_t i = 0; i < declared_phys_rows.Count(); i++) {
			declared_phys.push_back(Lit(declared_phys_rows.GetValue(0, i).ToString()));
		}
	}
	auto keys_list = [](const vector<string> &keys) {
		return "[" + StringUtil::Join(keys, ", ") + "]::VARCHAR[]";
	};
	string physcols =
	    declared_phys.empty()
	        ? string("physcols AS (SELECT NULL::VARCHAR AS table_catalog, NULL::VARCHAR AS table_schema, NULL::VARCHAR"
	                 " AS table_name, NULL::VARCHAR[] AS cols WHERE false)")
	        : "physcols AS (SELECT database_name AS table_catalog, schema_name AS table_schema, table_name, list(" +
	              KeyFoldSql("column_name") + ") AS cols FROM acl_physical_columns(" + keys_list(declared_phys) +
	              ") GROUP BY 1, 2, 3)";
	// duckdb's own information_schema.tables / .columns views, over the per-source reader
	auto sources = keys_list(source_keys);
	// spec 136: the source schemas the readers could not read in this statement - each read once, whichever
	// reader came first (their per-statement cache) - and the exception's class, never its text. Only the
	// surfaces that show the mark ask: the tables surfaces over every source they read, duckdb_schemas over the
	// alias schemas it marks; any other (databases, schemata, columns, keys) reads no source it did not before
	bool tables_mark =
	    surface == "tables" || surface == "show_tables" || surface == "duckdb_tables" || surface == "duckdb_views";
	auto unread_keys = tables_mark ? source_keys : (surface == "duckdb_schemas" ? alias_keys : vector<string>());
	string unread = unread_keys.empty()
	                    ? string("unread AS (SELECT NULL::VARCHAR AS db, NULL::VARCHAR AS fdb, NULL::VARCHAR AS fsch,"
	                             " NULL::VARCHAR AS cls WHERE false)")
	                    : "unread AS (SELECT min(database_name) AS db, " + KeyFoldSql("database_name") + " AS fdb, " +
	                          KeyFoldSql("schema_name") +
	                          " AS fsch, min(error_class) AS cls FROM acl_physical_unread(" + keys_list(unread_keys) +
	                          ") GROUP BY 2, 3)";
	// inlined where they are joined, as duckdb's own views are - a CTE referenced from correlated
	// subqueries is materialized, and decorrelating over it blew the planner up (measured: minutes)
	string itables =
	    "(SELECT database_name table_catalog, schema_name table_schema, table_name, CASE WHEN is_view THEN"
	    " 'VIEW' WHEN temporary THEN 'LOCAL TEMPORARY' ELSE 'BASE TABLE' END table_type, NULL::VARCHAR"
	    " self_referencing_column_name, NULL::VARCHAR reference_generation, NULL::VARCHAR user_defined_type_catalog,"
	    " NULL::VARCHAR user_defined_type_schema, NULL::VARCHAR user_defined_type_name, CASE WHEN is_view THEN 'NO'"
	    " ELSE 'YES' END is_insertable_into, 'NO' is_typed, CASE WHEN temporary AND NOT is_view THEN 'PRESERVE' ELSE"
	    " NULL END commit_action, comment AS TABLE_COMMENT, tags AS acl_tags FROM acl_physical_tables(" +
	    sources + "))";
	string icolumns =
	    "(SELECT database_name table_catalog, schema_name table_schema, table_name, column_name,"
	    " column_index ordinal_position, column_default, CASE WHEN is_nullable THEN 'YES' ELSE 'NO' END is_nullable,"
	    " data_type, character_maximum_length, NULL::INT character_octet_length, numeric_precision,"
	    " numeric_precision_radix, numeric_scale, NULL::INT datetime_precision, NULL::VARCHAR interval_type, NULL::INT"
	    " interval_precision, NULL::VARCHAR character_set_catalog, NULL::VARCHAR character_set_schema, NULL::VARCHAR"
	    " character_set_name, NULL::VARCHAR collation_catalog, NULL::VARCHAR collation_schema, NULL::VARCHAR"
	    " collation_name, NULL::VARCHAR domain_catalog, NULL::VARCHAR domain_schema, NULL::VARCHAR domain_name,"
	    " NULL::VARCHAR udt_catalog, NULL::VARCHAR udt_schema, NULL::VARCHAR udt_name, NULL::VARCHAR scope_catalog,"
	    " NULL::VARCHAR scope_schema, NULL::VARCHAR scope_name, NULL::BIGINT maximum_cardinality, NULL::VARCHAR"
	    " dtd_identifier, NULL::BOOL is_self_referencing, NULL::BOOL is_identity, NULL::VARCHAR identity_generation,"
	    " NULL::VARCHAR identity_start, NULL::VARCHAR identity_increment, NULL::VARCHAR identity_maximum, NULL::VARCHAR"
	    " identity_minimum, NULL::BOOL identity_cycle, CASE WHEN is_generated THEN 'ALWAYS' ELSE 'NEVER' END"
	    " is_generated, generation_expression, NULL::BOOL is_updatable, comment AS COLUMN_COMMENT,"
	    " tags AS acl_tags FROM acl_physical_columns(" +
	    sources + "))";
	// a declared column that reads one source column by name - no expression, or a bare or quoted identifier
	// that is no special value - and the name it reads: spec 039's broken mark and spec 143's tags alike
	auto reads_by_name = [](const string &c) {
		return "(" + c + ".\"expr\" IS NULL OR " + c + ".\"expr\" = '' OR regexp_matches(" + c +
		       ".\"expr\", '^[A-Za-z_][A-Za-z0-9_]*$') OR regexp_matches(" + c +
		       ".\"expr\", '^\"[^\"]+\"$'))"
		       " AND " +
		       KeyFoldSql("coalesce(" + c + ".\"expr\", '')") +
		       " NOT IN ('null', 'true', 'false', 'current_catalog',"
		       " 'current_date', 'current_role', 'current_schema', 'current_time', 'current_timestamp',"
		       " 'current_user', 'localtime', 'localtimestamp', 'session_user', 'user')";
	};
	auto read_name = [](const string &c) {
		return "CASE WHEN " + c + ".\"expr\" IS NULL OR " + c + ".\"expr\" = '' THEN " + c + ".\"name\" WHEN " + c +
		       ".\"expr\" LIKE '\"%\"' THEN substr(" + c + ".\"expr\", 2, length(" + c + ".\"expr\") - 2) ELSE " + c +
		       ".\"expr\" END";
	};
	string declared = "declared AS (SELECT dc.\"vcat\" AS vcat, dc.\"vname\" AS vname,"
	                  " list(dc.\"name\" ORDER BY dc.\"pos\") AS names, list(" +
	                  KeyFoldSql(read_name("dc")) + " ORDER BY dc.\"pos\") AS reads FROM " + Tbl("relation_columns") +
	                  " dc WHERE " + reads_by_name("dc") + " GROUP BY 1, 2)";
	string missing =
	    "CASE WHEN r.\"form\" IN ('alias', 'subquery') AND len(" + KeyPartsSql("r.\"phys\"") +
	    ") = 3"
	    " AND d.names IS NOT NULL THEN nullif(array_to_string(list_transform(list_filter("
	    "range(1, len(d.names) + 1), lambda i: NOT list_contains(coalesce(p.cols, []::VARCHAR[]), d.reads[i])),"
	    " lambda i: d.names[i]), ', '), '') ELSE NULL END";
	string relations_marked = "(SELECT r.*, " + missing + " AS missing, u.db AS unread_db, u.cls AS unread_cls FROM " +
	                          Tbl("relations") +
	                          " r LEFT JOIN declared d ON d.vcat = r.\"vcat\" AND d.vname = r.\"vname\""
	                          " LEFT JOIN physcols p ON p.table_catalog = " +
	                          KeyPartsSql("r.\"phys\"") +
	                          "[1]"
	                          " AND p.table_schema = " +
	                          KeyPartsSql("r.\"phys\"") +
	                          "[2]"
	                          " AND p.table_name = " +
	                          KeyPartsSql("r.\"phys\"") +
	                          "[3] LEFT JOIN unread u ON u.fdb = " + KeyFoldSql(KeyPartsSql("r.\"phys\"") + "[1]") +
	                          " AND u.fsch = " + KeyFoldSql(KeyPartsSql("r.\"phys\"") + "[2]") + ")";
	// spec 136: a source that could not be read is said first - the broken mark needs its columns, so the
	// two never meet, and nothing is known of the declared list then
	string own_comment = "CASE WHEN r.\"comment\" IS NULL OR r.\"comment\" = '' THEN '' ELSE '; ' || r.\"comment\" END";
	// review 136: the physical database is named only to a principal that may read the object - its failed read
	// would say as much; one that only sees it (a grant without `select`) learns the class alone (spec 035)
	string may_read = "EXISTS (SELECT 1 FROM grants g" + oc_join + " WHERE g.\"vcat\" = r.\"vcat\" AND " +
	                  CapsAllowSql(relation_caps, "select") + ")";
	string marked = "CASE WHEN r.unread_cls IS NOT NULL THEN " +
	                UnreadSourceMarkSql("CASE WHEN " + may_read + " THEN r.unread_db END", "r.unread_cls") + " || " +
	                own_comment +
	                " WHEN r.missing IS NOT NULL THEN 'acl: broken - declared column(s) ' || r.missing ||"
	                " ' no longer exist in the source' || " +
	                own_comment + " ELSE r.\"comment\" END";
	// the written path splits into a virtual schema and a name; a bare name sits in `main`
	// spec 099: the type policy in force for the object - its own, else the node's - so every column
	// row below describes what the read casts it to. The read casts only what the object's type facts
	// name, so an object with none (its source unprobed since a migration, or nothing to cast) is
	// described as it is read: uncast.
	auto instance = Db();
	string has_facts = "EXISTS (SELECT 1 FROM " + Tbl("relation_types") +
	                   " t WHERE t.\"vcat\" = r.\"vcat\" AND t.\"vname\" = r.\"vname\")";
	string strip_alias = "(coalesce(r.\"alias_types\" = 'base', " +
	                     string(NodeStripsAliases(*instance) ? "true" : "false") + ") AND " + has_facts + ")";
	string enums_to_varchar = "(coalesce(r.\"enum_types\" = 'varchar', " +
	                          string(NodeEnumsToVarchar(*instance) ? "true" : "false") + ") AND " + has_facts + ")";
	string objects = "objects AS (SELECT DISTINCT r.\"vcat\" AS vcat,"
	                 " CASE WHEN " +
	                 KeyNestedSql("r.\"vname\"") + " THEN " + KeyParentSql("r.\"vname\"") +
	                 " ELSE 'main' END AS vschema, " + KeyLeafSql("r.\"vname\"") +
	                 " AS vname, r.\"vname\" AS stored_name,"
	                 " r.\"form\" AS form, " +
	                 strip_alias + " AS strip_alias, " + enums_to_varchar + " AS enums_to_varchar, " + marked +
	                 " AS comment, r.unread_cls IS NOT NULL AS unread,"
	                 " " +
	                 KeyPartsSql("r.\"phys\"") + " AS parts FROM " + relations_marked +
	                 // spec 147: visible for some role - a semi-join, so what is computed per object is computed once,
	                 // not per (object, role) pair before the DISTINCT
	                 " r WHERE EXISTS (SELECT 1 FROM grants g" + oc_join + " WHERE g.\"vcat\" = r.\"vcat\" AND " +
	                 visible + "))";
	// an alias schema shows the physical schema live, so its visibility is the role's capabilities
	// on that schema (its own grant if it has one, otherwise the catalog's) - without this filter a
	// role granted an explicit nothing would still read the names out of the source
	auto schema_caps = "coalesce(nullif(trim((SELECT sc.\"caps\" FROM " + Tbl("role_schemas") +
	                   " sc WHERE sc.\"role\" = g.\"role\" AND sc.\"vcat\" = s.\"vcat\""
	                   " AND sc.\"schema_path\" = s.\"path\")), ''), g.\"caps\")";
	auto schema_visible =
	    "(" + schema_caps + " IS NULL OR trim(" + schema_caps + ") = '' OR trim(" + schema_caps + ") <> '{}')";
	string aliases = "aliases AS (SELECT DISTINCT s.\"vcat\" AS vcat, s.\"path\" AS path,"
	                 " " +
	                 KeyPartsSql("s.\"phys_path\"") + " AS parts FROM " + Tbl("schemas") +
	                 " s JOIN grants g ON g.\"vcat\" = s.\"vcat\""
	                 " WHERE s.\"phys_path\" IS NOT NULL AND " +
	                 schema_visible + ")";
	// a schema exists for the principal when something inside it does - a relation, an alias, or a
	// function it can see (spec 115) - and so does every schema above a nested one, so a tool can build
	// the tree from the parents
	string function_schemas = "fschemas AS (SELECT DISTINCT f.\"vcat\" AS vcat,"
	                          " CASE WHEN " +
	                          KeyNestedSql("f.\"vname\"") + " THEN " + KeyParentSql("f.\"vname\"") +
	                          " ELSE 'main' END AS path FROM " + Tbl("functions") +
	                          " f JOIN grants g ON g.\"vcat\" = f.\"vcat\"" +
	                          (object_level ? " LEFT JOIN " + Tbl("role_object_caps") +
	                                              " oc ON oc.\"role\" = g.\"role\" AND oc.\"vcat\" = f.\"vcat\""
	                                              " AND oc.\"vname\" = f.\"vname\""
	                                        : string()) +
	                          " WHERE " + FunctionVisibleExpr(object_level, schema_level) + ")";
	string schemas = function_schemas +
	                 ", leafschemas AS (SELECT vcat, path FROM aliases UNION SELECT vcat, vschema FROM objects"
	                 " UNION SELECT vcat, path FROM fschemas" +
	                 string(platform ? " UNION SELECT 'platform' AS vcat, 'main' AS path UNION SELECT 'platform' AS"
	                                   " vcat, path FROM pobjects" // spec 118.3: platform.attached.<alias>.<schema>
	                                 : "") +
	                 "),"
	                 " vschemas AS (SELECT vcat, path FROM leafschemas UNION SELECT vcat, unnest(list_transform("
	                 "range(1, len(" +
	                 KeyTokensSql("path") + ")), lambda i: array_to_string(" + KeyTokensSql("path") +
	                 "[1:i], '.')))"
	                 " FROM leafschemas WHERE " +
	                 KeyNestedSql("path") + ")";
	// spec 011 narrows columns per grant level, and the listing has to narrow with it: the object
	// row is kept per role here (unlike `objects`, which collapses them) so that "visible for at
	// least one role" can be asked column by column.
	string vfunctions = "vfunctions AS (SELECT DISTINCT f.\"vcat\" AS vcat, f.\"vname\" AS vname FROM " +
	                    Tbl("functions") + " f JOIN grants g ON g.\"vcat\" = f.\"vcat\"" +
	                    (object_level ? " LEFT JOIN " + Tbl("role_object_caps") +
	                                        " oc ON oc.\"role\" = g.\"role\" AND oc.\"vcat\" = f.\"vcat\""
	                                        " AND oc.\"vname\" = f.\"vname\""
	                                  : string()) +
	                    " WHERE f.\"kind\" = 'table' AND " + FunctionVisibleExpr(object_level, schema_level) + ")";
	// spec 145: what narrows a listing is what narrows the read - the rows that hold `select` (the read unites their
	// policies alone); an object no row of the principal's may read (it only writes) keeps every visible row's lists,
	// as before - a role without `select` must not see the columns its own lists hide (the review's regression)
	string grant_columns =
	    "gcolumns_all AS (SELECT r.\"vcat\" AS vcat, r.\"vname\" AS vname, g.\"role\" AS role,"
	    " g.\"columns\" AS cat_columns, " +
	    string(object_level ? "oc.\"columns\"" : "NULL") + " AS obj_columns, " + CapsAllowSql(relation_caps, "select") +
	    " AS reads FROM " + Tbl("relations") + " r JOIN grants g ON g.\"vcat\" = r.\"vcat\"" + oc_join + " WHERE " +
	    visible +
	    // spec 147: the objects some row reads, once each - not a self-join of the pairs
	    "), greaders AS (SELECT DISTINCT vcat, vname FROM gcolumns_all WHERE reads)"
	    ", gcolumns AS (SELECT x.vcat, x.vname, x.role, x.cat_columns, x.obj_columns FROM gcolumns_all x"
	    " LEFT JOIN greaders y ON y.vcat = x.vcat AND y.vname = x.vname WHERE x.reads OR y.vcat IS NULL)"
	    // what a column's visibility reads: the distinct lists, not one row per role that holds them
	    ", glists AS (SELECT DISTINCT vcat, vname, cat_columns, obj_columns FROM gcolumns)";
	// The names a grant states, split where the read path splits them (ParseColumnList: at top level, so a mask's
	// own commas - `note = concat(id, amount)` - never make a name of its arguments; review 143: a SQL split on every
	// comma listed `amount` as kept) and each item's column - a masked item's left of '=', spec 102's path its head
	// (a quoted head unquoted, else the part before the first '.' or '['), folded. Read here, from the grants of the
	// principal's roles, and written as a constant CASE over the stored text: no subquery for the planner to
	// decorrelate under the listing's own
	std::map<string, vector<string>> stated_lists;
	// spec 144: the columns some list narrows by a path (spec 102) or masks - their type is the read's projection,
	// which nothing probed for a catalog grant (spec 026 probes an object grant's), folded
	std::set<string> path_heads;
	// spec 144: does any of the principal's roles hold a catalog grant's list, or an object grant's list on an object
	// no relation names (an object under a live alias)? Only then the alias leg narrows - and only then by that level
	bool catalog_lists = false, alias_object_lists = false;
	// spec 145 on the alias leg: the grant rows that read (`select`). Where only the catalog grants' caps decide it,
	// the rows are a constant (`alias_readers`, empty = every row reads); where an object or schema grant of the
	// principal's states caps, the caps chain is judged per alias object (`alias_caps_vary`)
	bool alias_caps_vary = false;
	string alias_readers;
	if (!function_mode) {
		auto lists_sql = "SELECT DISTINCT \"columns\" FROM " + Tbl("role_catalogs") + " WHERE \"role\" IN (" +
		                 LitList(principal.roles) + ") AND coalesce(trim(\"columns\"), '') <> ''";
		if (HasObjectCaps()) {
			lists_sql += " UNION SELECT DISTINCT \"columns\" FROM " + Tbl("role_object_caps") + " WHERE \"role\" IN (" +
			             LitList(principal.roles) + ") AND coalesce(trim(\"columns\"), '') <> ''";
		}
		auto lists = Query(lists_sql);
		ResultRows list_rows(*lists);
		for (idx_t i = 0; i < list_rows.Count(); i++) {
			auto text = list_rows.GetValue(0, i).ToString();
			vector<string> names;
			for (auto &item : ParseColumnList(text)) {
				auto name = item.first;
				StringUtil::Trim(name);
				string head;
				bool path = false;
				if (!name.empty() && name[0] == '"') {
					for (idx_t at = 1; at < name.size(); at++) {
						if (name[at] == '"') {
							if (at + 1 < name.size() && name[at + 1] == '"') {
								head += '"';
								at++;
								continue;
							}
							path = at + 1 < name.size();
							break;
						}
						head += name[at];
					}
				} else {
					auto cut = name.find_first_of(".[");
					head = name.substr(0, cut);
					path = cut != string::npos;
				}
				names.push_back(StringUtil::Lower(head));
				if (path || !item.second.empty()) {
					path_heads.insert(StringUtil::Lower(head));
				}
			}
			stated_lists[text] = std::move(names);
		}
		auto has = [&](const string &sql) {
			return Query(sql)->RowCount() > 0;
		};
		catalog_lists = has("SELECT 1 FROM " + Tbl("role_catalogs") + " WHERE \"role\" IN (" +
		                    LitList(principal.roles) + ") AND coalesce(trim(\"columns\"), '') <> '' LIMIT 1");
		alias_object_lists =
		    HasObjectCaps() &&
		    has("SELECT 1 FROM " + Tbl("role_object_caps") + " oc WHERE oc.\"role\" IN (" + LitList(principal.roles) +
		        ") AND coalesce(trim(oc.\"columns\"), '') <> '' AND NOT EXISTS (SELECT 1 FROM " + Tbl("relations") +
		        " r WHERE r.\"vcat\" = oc.\"vcat\" AND " + KeyFoldSql("r.\"vname\"") + " = " +
		        KeyFoldSql("oc.\"vname\"") + ") LIMIT 1");
		if (catalog_lists || alias_object_lists) {
			// a schema grant on a live alias or above one, or an object grant under one, that states caps
			string alias_schemas = "SELECT 1 FROM " + Tbl("schemas") + " s WHERE s.\"phys_path\" IS NOT NULL AND ";
			alias_caps_vary =
			    has("SELECT 1 FROM " + Tbl("role_schemas") + " sc WHERE sc.\"role\" IN (" + LitList(principal.roles) +
			        ") AND coalesce(trim(sc.\"caps\"), '') <> '' AND EXISTS (" + alias_schemas +
			        "s.\"vcat\" = sc.\"vcat\" AND (" + KeyFoldSql("s.\"path\"") + " = " +
			        KeyFoldSql("sc.\"schema_path\"") + " OR " + KeyPrefixSql("s.\"path\"", "sc.\"schema_path\"") +
			        ")) LIMIT 1") ||
			    (HasObjectCaps() &&
			     has("SELECT 1 FROM " + Tbl("role_object_caps") + " oc WHERE oc.\"role\" IN (" +
			         LitList(principal.roles) + ") AND coalesce(trim(oc.\"caps\"), '') <> '' AND EXISTS (" +
			         alias_schemas + "s.\"vcat\" = oc.\"vcat\" AND " + KeyPrefixSql("oc.\"vname\"", "s.\"path\"") +
			         ") AND NOT EXISTS (SELECT 1 FROM " + Tbl("relations") + " r WHERE r.\"vcat\" = oc.\"vcat\" AND " +
			         KeyFoldSql("r.\"vname\"") + " = " + KeyFoldSql("oc.\"vname\"") + ") LIMIT 1"));
		}
		if ((catalog_lists || alias_object_lists) && !alias_caps_vary) {
			auto grant_rows = Query(GrantsCte(principal) + "SELECT \"vcat\", \"role\", \"caps\" FROM grants");
			ResultRows rows(*grant_rows);
			struct GrantRow {
				string role;
				bool reads;
				bool holds; // any capability: an explicit '{}' lifts nothing, not even a write-only principal's list
			};
			std::map<string, vector<GrantRow>> by_catalog;
			for (idx_t i = 0; i < rows.Count(); i++) {
				auto caps = EffectiveCaps(rows.GetValue(2, i));
				by_catalog[rows.GetValue(0, i).ToString()].push_back(
				    GrantRow {rows.GetValue(1, i).ToString(), caps.count("select") > 0, !caps.empty()});
			}
			vector<string> narrowed, admitted;
			for (auto &catalog : by_catalog) {
				bool any_reads = false;
				for (auto &row : catalog.second) {
					any_reads = any_reads || row.reads;
				}
				// the rows that read, or - none does, a write-only principal - every row that holds anything
				vector<string> roles;
				for (auto &row : catalog.second) {
					if (any_reads ? row.reads : row.holds) {
						roles.push_back(Lit(row.role));
					}
				}
				if (roles.size() == catalog.second.size()) {
					continue; // every row counts: nothing to narrow
				}
				narrowed.push_back(Lit(catalog.first));
				if (!roles.empty()) {
					admitted.push_back("(g.\"vcat\" = " + Lit(catalog.first) + " AND g.\"role\" IN (" +
					                   StringUtil::Join(roles, ", ") + "))");
				}
			}
			if (!narrowed.empty()) {
				alias_readers = " AND (g.\"vcat\" NOT IN (" + StringUtil::Join(narrowed, ", ") + ")" +
				                (admitted.empty() ? string() : " OR " + StringUtil::Join(admitted, " OR ")) + ")";
			}
		}
	}
	auto stated = [&](const string &column_expr) {
		string cases;
		for (auto &list : stated_lists) {
			vector<string> names;
			for (auto &name : list.second) {
				names.push_back(Lit(name));
			}
			// a list of nothing but separators names no item: it narrows nothing, as the read reads it
			cases += " WHEN " + Lit(list.first) + " THEN " +
			         (names.empty() ? string("NULL") : "[" + StringUtil::Join(names, ", ") + "]") + "::VARCHAR[]";
		}
		// a list read after this text was composed matches nothing: nothing it names is kept (fail closed)
		return cases.empty() ? string("[]::VARCHAR[]") : "CASE " + column_expr + cases + " ELSE []::VARCHAR[] END";
	};
	auto keeps = [&](const string &column_expr, const string &name_expr) {
		return "(" + column_expr + " IS NULL OR trim(" + column_expr + ") = '' OR coalesce(list_contains(" +
		       stated(column_expr) + ", " + KeyFoldSql(name_expr) + "), true))";
	};
	// Visible for at least one role: a principal may read what any of its roles may (spec 011). A
	// row with no grant row at all is not an object of the catalog - it is a column of a live
	// schema alias, whose visibility is the schema's, decided in `aliases` - so it is left alone.
	auto column_visible = [&](const string &vcat_expr, const string &vname_expr, const string &name_expr) {
		string key = "gc.vcat = " + vcat_expr + " AND gc.vname = " + vname_expr;
		return "(NOT EXISTS (SELECT 1 FROM glists gc WHERE " + key + ")" +
		       " OR EXISTS (SELECT 1 FROM glists gc"
		       " WHERE " +
		       key + " AND " + keeps("gc.cat_columns", name_expr) + " AND " + keeps("gc.obj_columns", name_expr) + "))";
	};
	// spec 144: a column some list narrows by a path is listed as the read projects it - the roles' lists folded over
	// its type (spec 102's acl_listed_type, which the grant projection's rows already pass through); any other keeps
	// its listed type (a whole-column mask's is spec 026's probe or the source's)
	auto listed_type = [&](const string &type_expr, const string &name_expr, const string &roles_expr) {
		if (path_heads.empty()) {
			return type_expr;
		}
		vector<string> heads;
		for (auto &head : path_heads) {
			heads.push_back(Lit(head));
		}
		return "CASE WHEN " + KeyFoldSql(name_expr) + " IN (" + StringUtil::Join(heads, ", ") +
		       ") THEN acl_listed_type(" + type_expr + ", " + name_expr + ", " + roles_expr + ") ELSE " + type_expr +
		       " END";
	};
	// spec 026: what a grant's own projection produces - a mask that changes a column's type, or a
	// computed column the object never had. Probed when the grant is written, so a listing can
	// describe what the role reads rather than what the physical table holds.
	// A principal may hold several roles, and two of them may project the same name - at the same
	// position or at different ones. One row per name is the invariant every consumer depends on:
	// a duplicate makes `column_count` wrong and the synthesized DDL invalid SQL (spec 035).
	//
	// The order has to be the read path's, not merely stable, because a client may project by
	// position (spec 036). The read path merges roles in role-name order, appending each role's
	// list in its own order - so a column belongs where the first role that states it put it.
	// Ranking by `(role, pos)` and taking each name's first occurrence reproduces exactly that,
	// and the outer row_number closes the gaps a merged name leaves behind.
	string projected =
	    "gprojection AS (SELECT vcat, vname, name, type,"
	    " row_number() OVER (PARTITION BY vcat, vname ORDER BY rk) - 1 AS pos FROM"
	    " (SELECT vcat, vname, name, min_by(type, rk) AS type, min(rk) AS rk FROM"
	    " (SELECT vcat, vname, name, type,"
	    " row_number() OVER (PARTITION BY vcat, vname ORDER BY \"role\", \"pos\") AS rk FROM"
	    " (SELECT DISTINCT pc.\"vcat\" AS vcat, pc.\"vname\" AS vname, pc.\"name\" AS name,"
	    " pc.\"type\" AS type, pc.\"role\" AS \"role\", pc.\"pos\" AS \"pos\" FROM " +
	    Tbl("grant_columns") +
	    " pc JOIN grants g ON g.\"role\" = pc.\"role\" AND g.\"vcat\" = pc.\"vcat\""
	    // spec 145: a role's projection is listed only where the role reads the object
	    " JOIN gcolumns gr ON gr.vcat = pc.\"vcat\" AND gr.vname = pc.\"vname\" AND gr.role = pc.\"role\""
	    // One role whose chain states no column list lifts the restriction for the
	    // whole principal (spec 011: `Restricts()` is `any && !unrestricted`), and
	    // then the object's own columns are what it reads - so another role's
	    // projection must not be listed either, or the listing would advertise a
	    // column `SELECT *` never returns.
	    " WHERE NOT EXISTS (SELECT 1 FROM gcolumns gc WHERE gc.vcat = pc.\"vcat\""
	    " AND gc.vname = pc.\"vname\""
	    " AND (gc.cat_columns IS NULL OR trim(gc.cat_columns) = '')"
	    " AND (gc.obj_columns IS NULL OR trim(gc.obj_columns) = ''))"
	    // review 143: an object grant's list names what that level keeps - the catalog grant's may
	    // hide it, and then the read has no such column (nor its name, comment or tags a row);
	    // filtered before the positions are numbered, so they close up as the read's do (spec 036)
	    " AND " +
	    column_visible("pc.\"vcat\"", "pc.\"vname\"", "pc.\"name\"") +
	    "))"
	    " GROUP BY vcat, vname, name))";
	auto prelude =
	    GrantsCte(principal) + ", " +
	    (platform ? "pobjects AS (" + platform_objects + "), pcolumns AS (" + platform_columns + "), " : string()) +
	    physcols + ", " + unread + ", " + declared + ", " + objects + ", " + aliases + ", " + schemas + ", " +
	    grant_columns + ", " + vfunctions + ", " + projected + " ";
	// spec 035: each surface answers in its own standard shape, column for column and type for
	// type. A value that would describe the physical object rather than the virtual one is not
	// borrowed - an oid identifies a physical catalog entry, a path is the physical database.
	auto empty_map = "MAP {}::MAP(VARCHAR, VARCHAR)";
	// spec 116: the CTEs above work on stored keys (a part holding `.` or `"` quoted), which is what
	// every join and oid reads; what a surface answers is each name as duckdb shows one - a catalog and
	// an object unquoted (`Order Items`), a schema unquoted when it is one part (`Raw Data`) and its key
	// when it is a path (`a."b.c"`). `order` re-states the order the body asked for.
	enum class Shown { CATALOG, SCHEMA, NAME };
	auto named = [](const string &body, const vector<std::pair<const char *, Shown>> &columns,
	                const string &order = string()) {
		vector<string> items;
		for (auto &column : columns) {
			auto ref = string("\"") + column.first + "\"";
			auto shown = column.second == Shown::SCHEMA ? KeyDisplaySql(ref) : KeyUnquoteSql(ref);
			items.push_back(shown + " AS " + ref);
		}
		return "SELECT * REPLACE (" + StringUtil::Join(items, ", ") + ") FROM (" + body + ") __acl_named" +
		       (order.empty() ? string() : " ORDER BY " + order);
	};
	// An oid a client can key on, with nothing physical in it. Spec 035 answered every oid with
	// NULL - a physical catalog entry's identifier is not a fact about a virtual object - and that
	// held until quack started joining tables to schemas by oid and reading it as int64 (its
	// nested-schema catalog load, 2026-08-26): a NULL there is a client-side internal error, and an
	// ATTACH that never completes. So the ids are synthesized from the virtual name - stable
	// across calls, the same for the same object on every surface (a table's schema_oid *is* its
	// schema's oid, by construction), and unrelated to anything in a physical catalog. The kind is
	// salted in so a schema and a table can never share one; chr(31) keeps `a` + `b.c` apart from
	// `a.b` + `c`; the shift keeps a UBIGINT hash inside BIGINT.
	auto oid_of = [](const string &kind, const string &name_expr) {
		return "(hash('" + kind + "' || chr(31) || " + name_expr + ") >> 1)::BIGINT";
	};
	auto database_oid = [&](const string &vcat_expr) {
		return oid_of("database", vcat_expr);
	};
	auto schema_oid = [&](const string &vcat_expr, const string &path_expr) {
		return oid_of("schema", vcat_expr + " || chr(31) || " + path_expr);
	};
	auto object_oid = [&](const string &kind, const string &vcat_expr, const string &schema_expr,
	                      const string &name_expr) {
		return oid_of(kind, vcat_expr + " || chr(31) || " + schema_expr + " || chr(31) || " + name_expr);
	};
	if (surface == "databases") {
		// one row per granted catalog, and no physical database name ever appears
		// the catalog's own comment (spec 117 §7) - the system catalog's says what it is
		string catalog_comment =
		    "CASE WHEN d.vcat = 'platform' AND " + string(platform ? "true" : "false") +
		    " THEN 'the system catalog of administration (spec 117)' ELSE (SELECT nullif(max(c.\"comment\"), '') "
		    "FROM " +
		    Tbl("catalogs") + " c WHERE " + KeyFoldSql("c.\"vcat\"") + " = " + KeyFoldSql("d.vcat") + ") END";
		return prelude + named("SELECT vcat AS database_name, " + database_oid("vcat") +
		                           " AS database_oid, NULL::VARCHAR AS path, " + catalog_comment +
		                           "::VARCHAR AS comment, " + empty_map +
		                           " AS tags, false AS internal, NULL::VARCHAR AS type,"
		                           " false AS readonly, false AS encrypted, NULL::VARCHAR AS cipher, " +
		                           empty_map + " AS options FROM (SELECT DISTINCT vcat FROM vschemas) d",
		                       {{"database_name", Shown::CATALOG}});
	}
	if (surface == "schemata") {
		return prelude + named("SELECT DISTINCT vcat AS catalog_name, path AS schema_name,"
		                       " NULL::VARCHAR AS schema_owner, NULL::VARCHAR AS default_character_set_catalog,"
		                       " NULL::VARCHAR AS default_character_set_schema,"
		                       " NULL::VARCHAR AS default_character_set_name, NULL::VARCHAR AS sql_path"
		                       " FROM vschemas",
		                       {{"catalog_name", Shown::CATALOG}, {"schema_name", Shown::SCHEMA}});
	}
	if (surface == "duckdb_schemas") {
		// spec 115: duckdb's own shape for a nested schema - the leaf as schema_name, the parent's leaf as
		// parent_schema and its oid: a client (quack) builds the tree by the oids, and a full path there
		// doubled its levels (`raw` -> `raw.eu`). The oid stays the full path's, as every other surface's
		// schema_oid is.
		// (spec 116: the leaves unquoted - a part holding a dot is one schema, never two levels)
		// a schema's stored comment (an alias or an expansion carries one; spec 117 §7)
		string schema_comment = "(SELECT nullif(max(sc.\"comment\"), '') FROM " + Tbl("schemas") + " sc WHERE " +
		                        KeyFoldSql("sc.\"vcat\"") + " = " + KeyFoldSql("d.vcat") + " AND " +
		                        KeyFoldSql("sc.\"path\"") + " = " + KeyFoldSql("d.path") + ")";
		// spec 136: an alias schema over a source that could not be read lists nothing - it says why; so
		// does an admin's `platform.attached.<alias>` whose source failed (its reader's own row)
		// (the database named only where the schema's caps admit `select`, as on an object)
		string alias_caps =
		    "coalesce((SELECT nullif(trim(sc.\"caps\"), '') FROM " + Tbl("role_schemas") +
		    " sc WHERE sc.\"role\" = g.\"role\" AND sc.\"vcat\" = a.vcat AND sc.\"schema_path\" = a.path),"
		    " g.\"caps\")";
		string alias_may_read =
		    "EXISTS (SELECT 1 FROM grants g WHERE g.\"vcat\" = a.vcat AND " + CapsAllowSql(alias_caps, "select") + ")";
		string schema_marks =
		    "(SELECT mvcat, mpath, min(mark) AS mark FROM (SELECT a.vcat AS mvcat, a.path AS mpath, " +
		    UnreadSourceMarkSql("CASE WHEN " + alias_may_read + " THEN u.db END", "u.cls") +
		    " AS mark FROM aliases a JOIN unread u ON u.fdb = " + KeyFoldSql("a.parts[1]") +
		    " AND u.fsch = " + KeyFoldSql("a.parts[2]") + " WHERE len(a.parts) = 2" +
		    (platform ? string(" UNION ALL SELECT 'platform', path, comment FROM pobjects WHERE vname IS NULL AND"
		                       " comment IS NOT NULL")
		              : string()) +
		    ") GROUP BY ALL)";
		string comment = "CASE WHEN m.mark IS NULL THEN " + schema_comment + " ELSE m.mark || coalesce('; ' || " +
		                 schema_comment + ", '') END";
		// spec 143: a live alias schema carries its physical schema's tags (its comment stays the virtual one)
		string alias_tags =
		    alias_keys.empty()
		        ? string("(SELECT NULL::VARCHAR AS tvcat, NULL::VARCHAR AS tpath, ") + empty_map +
		              " AS tags WHERE false)"
		        : "(SELECT a.vcat AS tvcat, a.path AS tpath, ps.tags FROM aliases a JOIN acl_physical_schemas(" +
		              keys_list(alias_keys) + ") ps ON " + KeyFoldSql("ps.database_name") + " = " +
		              KeyFoldSql("a.parts[1]") + " AND " + KeyFoldSql("ps.schema_name") + " = " +
		              KeyFoldSql("a.parts[2]") + " WHERE len(a.parts) = 2)";
		return prelude +
		       named("SELECT " + schema_oid("vcat", "path") + " AS oid, vcat AS database_name, " +
		                 database_oid("vcat") + " AS database_oid, " + KeyUnquoteSql(KeyLeafSql("path")) +
		                 " AS schema_name, (" + comment + ")::VARCHAR AS comment, coalesce(t.tags, " + empty_map +
		                 ") AS tags, false AS internal, NULL::VARCHAR AS sql, " + KeyUnquoteSql(KeyLeafSql("parent")) +
		                 " AS parent_schema, CASE WHEN parent IS NULL THEN NULL ELSE " + schema_oid("vcat", "parent") +
		                 " END AS parent_schema_oid FROM (SELECT DISTINCT vcat, path, CASE WHEN " +
		                 KeyNestedSql("path") + " THEN " + KeyParentSql("path") + " END AS parent FROM vschemas) d" +
		                 " LEFT JOIN " + schema_marks + " m ON m.mvcat = d.vcat AND m.mpath = d.path LEFT JOIN " +
		                 alias_tags + " t ON t.tvcat = d.vcat AND t.tpath = d.path",
		             {{"database_name", Shown::CATALOG}});
	}
	// spec 031: the SHOW forms, each in the shape duckdb answers it with. They are the same catalog
	// the information_schema surfaces describe - only a client asking `SHOW DATABASES` wants one
	// column called `database_name`, not an information_schema row.
	if (surface == "show_databases") {
		return prelude +
		       named("SELECT DISTINCT vcat AS database_name FROM vschemas", {{"database_name", Shown::CATALOG}}, "1");
	}
	if (surface == "show_schemas") {
		// `current` is the schema an unqualified name resolves in: `main` of the catalog the
		// principal holds as MAIN, which is exactly what resolution falls back to
		return prelude + named("SELECT DISTINCT s.vcat AS database_name, s.path AS schema_name,"
		                       " (s.path = 'main' AND EXISTS (SELECT 1 FROM grants g WHERE g.\"vcat\" = s.vcat"
		                       " AND g.\"is_main\" = true)) AS \"current\" FROM vschemas s",
		                       {{"database_name", Shown::CATALOG}, {"schema_name", Shown::SCHEMA}}, "ALL");
	}
	auto physical = "i.\"table_catalog\" = o.parts[1] AND i.\"table_schema\" = o.parts[2]"
	                " AND i.\"table_name\" = o.parts[3]";
	// spec 065: is_insertable_into follows the grant, not the physical row - a capability the
	// principal does not hold, or a read-only (masked) relation, answers NO. The caps chain is
	// judged the way the resolver's default reads it (spec 012: unstated = the data capabilities,
	// an explicit '{}' = none); a caps JSON is admin-written, so the true-flag test is textual,
	// like the rest of this file's caps SQL. The listing is a hint - the write path stays the
	// authority - so a YES the write path would still refuse errs on the side it must.
	auto caps_allow_insert = [&](const string &caps_expr) {
		return CapsAllowSql(caps_expr, "insert");
	};
	string o_oc_join = object_level ? " LEFT JOIN " + Tbl("role_object_caps") +
	                                      " oc ON oc.\"role\" = g.\"role\" AND oc.\"vcat\" = o.vcat"
	                                      " AND oc.\"vname\" = o.stored_name"
	                                : string();
	// writability is the stored authority's verdict, not re-derived: the relation's form was
	// decided where it was written (RenameOnlyColumns) - only the plain alias form takes writes,
	// a mask or an RLS'd relation is the read-only SUBQUERY form
	string object_insertable = "CASE WHEN o.form = 'alias' AND EXISTS (SELECT 1 FROM grants g" + o_oc_join +
	                           " WHERE g.\"vcat\" = o.vcat AND " +
	                           caps_allow_insert(caps_chain("o.stored_name", "o.vcat")) +
	                           ") THEN 'YES' ELSE 'NO' END AS is_insertable_into";
	string alias_schema_caps = "coalesce((SELECT nullif(trim(sc.\"caps\"), '') FROM " + Tbl("role_schemas") +
	                           " sc WHERE sc.\"role\" = g.\"role\" AND sc.\"vcat\" = a.vcat"
	                           " AND sc.\"schema_path\" = a.path), g.\"caps\")";
	string alias_insertable = "CASE WHEN EXISTS (SELECT 1 FROM grants g WHERE g.\"vcat\" = a.vcat AND " +
	                          caps_allow_insert(alias_schema_caps) + ") THEN 'YES' ELSE 'NO' END AS is_insertable_into";
	// the comment is the virtual object's own: a physical comment describes the physical table, and
	// may say things about it the role is not reading (spec 035)
	// spec 136: an object over a source that could not be read stays listed - with no physical row, as a
	// table, its comment saying why - instead of vanishing
	string tables_sql =
	    string("SELECT i.* REPLACE (o.vcat AS table_catalog, o.vschema AS table_schema, o.vname AS table_name,"
	           " coalesce(i.table_type, 'BASE TABLE') AS table_type, o.comment AS \"TABLE_COMMENT\", ") +
	    object_insertable + ") FROM objects o LEFT JOIN " + itables + " i ON " + physical +
	    " WHERE len(o.parts) = 3 AND (i.table_name IS NOT NULL OR o.unread)"
	    " UNION ALL BY NAME"
	    // a view's own comment (spec 117 §7: it never reached duckdb_views / information_schema.tables)
	    " SELECT o.vcat AS table_catalog, o.vschema AS table_schema, o.vname AS table_name,"
	    " 'VIEW' AS table_type, 'NO' AS is_insertable_into, o.comment AS \"TABLE_COMMENT\" FROM objects o"
	    " WHERE o.form = 'view'"
	    " UNION ALL BY NAME"
	    " SELECT i.* REPLACE (a.vcat AS table_catalog, a.path AS table_schema, " +
	    KeyQuotePartSql("i.\"table_name\"") + " AS table_name, " + alias_insertable + ") FROM aliases a JOIN " +
	    itables +
	    " i ON i.\"table_catalog\" = a.parts[1] AND i.\"table_schema\" = a.parts[2]"
	    " WHERE len(a.parts) = 2"
	    // review 144: an object a relation of the catalog names is that relation's - the relation wins the read
	    " AND NOT EXISTS (SELECT 1 FROM " +
	    Tbl("relations") + " ar WHERE ar.\"vcat\" = a.vcat AND " + KeyFoldSql("ar.\"vname\"") + " = " +
	    KeyFoldSql("a.path || '.' || " + KeyQuotePartSql("i.\"table_name\"")) + ")" +
	    // spec 117: the system catalog's views the principal holds
	    string(platform ? " UNION ALL BY NAME SELECT 'platform' AS table_catalog, p.path AS table_schema,"
	                      " p.vname AS table_name, p.type AS table_type, 'NO' AS is_insertable_into,"
	                      " p.comment AS \"TABLE_COMMENT\" FROM pobjects p WHERE p.vname IS NOT NULL"
	                    : "");
	const vector<std::pair<const char *, Shown>> table_names = {
	    {"table_catalog", Shown::CATALOG}, {"table_schema", Shown::SCHEMA}, {"table_name", Shown::NAME}};
	if (surface == "tables") {
		return prelude + named("SELECT * EXCLUDE (acl_tags) FROM (" + tables_sql + ")", table_names);
	}
	if (surface == "tables_tagged") {
		// spec 143: information_schema.tables with the hidden acl_tags kept - DescribeObject's and ObjectTags'
		return prelude + named(tables_sql, table_names);
	}
	if (surface == "show_tables") {
		// a bare `SHOW TABLES` is the schema an unqualified name resolves in - `main` of the MAIN
		// catalog. Filtering on the schema alone listed the `main` of every granted catalog, whose
		// tables a bare name does not reach (spec 031).
		return prelude + named("SELECT t.table_name AS name FROM (" + tables_sql +
		                           ") t WHERE t.table_schema = 'main' AND EXISTS (SELECT 1 FROM grants g"
		                           " WHERE g.\"vcat\" = t.table_catalog AND g.\"is_main\" = true)",
		                       {{"name", Shown::NAME}}, "1");
	}
	if (surface != "columns" && surface != "columns_tagged" && surface != "references" && surface != "keys" &&
	    surface != "show_tables_expanded" && surface != "show_tables" && surface != "duckdb_tables" &&
	    surface != "duckdb_views" && surface != "duckdb_columns") {
		throw BinderException("acl: unknown metadata surface \"%s\"", surface);
	}
	// the columns a role actually sees: an object's own projection when it has one (its rows in
	// relation_columns name the visible columns, and for an alias form they map virtual -> physical)
	string projection = " LEFT JOIN " + Tbl("relation_columns") +
	                    " c ON c.\"vcat\" = o.vcat AND c.\"vname\" = CASE WHEN o.vschema = 'main' THEN o.vname"
	                    " ELSE o.vschema || '.' || o.vname END";
	// An `alias` relation is the physical table under a virtual name (possibly with renamed
	// columns), so its listing is the physical row with the identity columns replaced - the rich
	// shape, for free. So is a relation that only filters (an RLS predicate and no column list): its
	// shape IS the physical row's, and nothing was probed for it at write time. Anything else - a
	// projection, a view - is described by its own stored schema: a masked or computed column has no
	// physical row to borrow, and leaving it out would hide a column the role can read. (An RLS-only
	// relation once fell through both branches - listed as a table, with no columns at all, so a
	// client building its catalog from the columns could not see it: found by spec 043's
	// cross-source leg.)
	// spec 048: one nullability precedence everywhere - the declared mark wins, the physical
	// answer flows where nothing is declared, and a declared-key column reports NOT NULL
	auto pk_implies = [&](const string &vcat_expr, const string &vname_expr, const string &column_expr) {
		return "EXISTS (SELECT 1 FROM " + Tbl("keys") + " pk WHERE pk.\"vcat\" = " + vcat_expr +
		       " AND pk.\"vname\" = " + vname_expr + " AND pk.\"kind\" = 'relation'" + " AND " +
		       KeyFoldSql("pk.\"column\"") + " = " + KeyFoldSql(column_expr) + ")";
	};
	string alias_vname = "CASE WHEN o.vschema = 'main' THEN o.vname ELSE o.vschema || '.' || o.vname END";
	string alias_nullable = "CASE WHEN c.\"nullable\" IS NOT NULL THEN"
	                        " CASE WHEN c.\"nullable\" THEN 'YES' ELSE 'NO' END WHEN " +
	                        pk_implies("o.vcat", alias_vname, "coalesce(c.\"name\", i.\"column_name\")") +
	                        " THEN 'NO' ELSE i.\"is_nullable\" END";
	// spec 144: a live alias's object is read under the grants of its catalog, each role's two levels (RowPolicy): the
	// catalog grant's list and the role's object grant on the object, under the alias - a column the read does not
	// return is not listed. No list of the principal's names anything: nothing to narrow (the common case is free)
	string alias_object = "a.path || '.' || " + KeyQuotePartSql("i.\"table_name\"");
	string alias_object_join = alias_caps_vary || alias_object_lists
	                               ? " LEFT JOIN " + Tbl("role_object_caps") +
	                                     " aoc ON aoc.\"role\" = g.\"role\" AND aoc.\"vcat\" = g.\"vcat\" AND " +
	                                     KeyFoldSql("aoc.\"vname\"") + " = " + KeyFoldSql(alias_object)
	                               : string();
	string alias_object_columns = alias_object_lists ? string("aoc.\"columns\"") : string("NULL::VARCHAR");
	// spec 145: the levels of the roles that read the object, or - a write-only principal - of every role, as the
	// columns surface reads them (gcolumns): a constant where the catalog grants decide (alias_readers), else the
	// object's caps chain (object, schema, catalog) judged per row
	string alias_grants;
	if (alias_caps_vary) {
		string alias_caps = "coalesce(" + string(HasObjectCaps() ? "nullif(trim(aoc.\"caps\"), ''), " : "") +
		                    SchemaCapsExpr(alias_object, "a.vcat") + ", g.\"caps\")";
		string alias_reads = CapsAllowSql(alias_caps, "select");
		// an explicit '{}' holds nothing: it lifts no list, not even a write-only principal's
		string alias_holds = "(" + alias_caps + " IS NULL OR trim(" + alias_caps + ") = '' OR regexp_matches(" +
		                     alias_caps + ", ':\\s*true'))";
		alias_grants = "(SELECT g.\"role\" AS role, g.\"columns\" AS cat, " + alias_object_columns + " AS obj, " +
		               alias_reads + " AS reads, " + alias_holds + " AS holds, bool_or(" + alias_reads +
		               ") OVER () AS any_reads FROM grants g" + alias_object_join +
		               " WHERE g.\"vcat\" = a.vcat) ag WHERE (ag.reads OR (NOT ag.any_reads AND ag.holds))";
	} else {
		alias_grants = "(SELECT g.\"role\" AS role, g.\"columns\" AS cat, " + alias_object_columns +
		               " AS obj FROM grants g" + alias_object_join + " WHERE g.\"vcat\" = a.vcat" + alias_readers +
		               ") ag WHERE true";
	}
	string alias_roles = "(SELECT list(struct_pack(cat := ag.cat, obj := ag.obj, probed := NULL::VARCHAR) ORDER BY "
	                     "ag.role) FROM " +
	                     alias_grants + ")";
	string alias_visible =
	    !catalog_lists && !alias_object_lists
	        ? string()
	        : " AND EXISTS (SELECT 1 FROM " + alias_grants + " AND " + keeps("ag.cat", "i.\"column_name\"") +
	              (alias_object_lists ? " AND " + keeps("ag.obj", "i.\"column_name\"") : string()) + ")";
	// review 144: an object a relation of the catalog names is that relation's, read through it (LookupRelation wins
	// over an alias) - the alias leg leaves it alone
	alias_visible += " AND NOT EXISTS (SELECT 1 FROM " + Tbl("relations") + " ar WHERE ar.\"vcat\" = a.vcat AND " +
	                 KeyFoldSql("ar.\"vname\"") + " = " + KeyFoldSql(alias_object) + ")";
	// spec 143: an alias relation's column shows its virtual comment over its source's
	string columns_sql =
	    string("SELECT i.* REPLACE (o.vcat AS table_catalog, o.vschema AS table_schema, o.vname AS table_name,"
	           " coalesce(c.\"name\", i.\"column_name\") AS column_name,"
	           " acl_exposed_type(i.\"data_type\", o.strip_alias, o.enums_to_varchar) AS data_type, ") +
	    alias_nullable +
	    " AS is_nullable, coalesce(ocv.\"comment\", cc.\"comment\", i.\"COLUMN_COMMENT\") AS \"COLUMN_COMMENT\")" +
	    " FROM objects o JOIN " + icolumns + " i ON " + physical + projection +
	    // a renaming list keeps its columns' comments in object_columns (the writer's), under the virtual name
	    " AND c.\"expr\" = i.\"column_name\" LEFT JOIN " + Tbl("object_columns") +
	    " ocv ON c.\"name\" IS NOT NULL AND ocv.\"vcat\" = o.vcat AND ocv.\"kind\" = 'relation' AND ocv.\"vname\" = " +
	    alias_vname + " AND ocv.\"name\" = c.\"name\" LEFT JOIN " + Tbl("column_comments") +
	    " cc ON c.\"name\" IS NULL AND cc.\"vcat\" = o.vcat AND cc.\"vname\" = " + alias_vname +
	    " AND cc.\"column_name\" = i.\"column_name\""
	    " WHERE len(o.parts) = 3 AND (o.form = 'alias' OR (o.form = 'subquery' AND NOT EXISTS"
	    " (SELECT 1 FROM " +
	    Tbl("relation_columns") +
	    " c3 WHERE c3.\"vcat\" = o.vcat AND c3.\"vname\" = CASE WHEN o.vschema = 'main' THEN o.vname"
	    " ELSE o.vschema || '.' || o.vname END)))"
	    " AND (c.\"name\" IS NOT NULL OR NOT EXISTS"
	    " (SELECT 1 FROM " +
	    Tbl("relation_columns") +
	    " c2 WHERE c2.\"vcat\" = o.vcat AND c2.\"vname\" = CASE WHEN o.vschema = 'main' THEN o.vname"
	    " ELSE o.vschema || '.' || o.vname END))"
	    " UNION ALL BY NAME"
	    " SELECT o.vcat AS table_catalog, o.vschema AS table_schema, o.vname AS table_name,"
	    " oc.\"name\" AS column_name, oc.\"pos\" + 1 AS ordinal_position,"
	    " acl_exposed_type(oc.\"type\", o.strip_alias, o.enums_to_varchar) AS data_type," +
	    string(" CASE WHEN oc.\"nullable\" IS NOT NULL THEN CASE WHEN oc.\"nullable\" THEN 'YES'"
	           " ELSE 'NO' END WHEN ") +
	    pk_implies("o.vcat", alias_vname, "oc.\"name\"") +
	    " THEN 'NO' ELSE NULL END AS is_nullable,"
	    // `COLUMN_COMMENT` is what information_schema.columns calls it; a `comment` of our own
	    // added a 46th column to a surface whose shape is fixed (spec 035)
	    " oc.\"comment\" AS \"COLUMN_COMMENT\", ip.acl_tags AS acl_tags FROM objects o JOIN " +
	    Tbl("object_columns") +
	    " oc ON oc.\"vcat\" = o.vcat AND oc.\"kind\" = 'relation'"
	    " AND oc.\"vname\" = CASE WHEN o.vschema = 'main' THEN o.vname"
	    " ELSE o.vschema || '.' || o.vname END"
	    // spec 143: a declared list's column carries its source column's tags - a column it reads by name
	    " LEFT JOIN " +
	    Tbl("relation_columns") +
	    " rc ON o.form = 'subquery' AND rc.\"vcat\" = o.vcat AND rc.\"vname\" = " + alias_vname +
	    " AND rc.\"name\" = oc.\"name\" AND " + reads_by_name("rc") + " LEFT JOIN " + icolumns +
	    " ip ON rc.\"name\" IS NOT NULL AND len(o.parts) = 3 AND ip.\"table_catalog\" = o.parts[1]"
	    " AND ip.\"table_schema\" = o.parts[2] AND ip.\"table_name\" = o.parts[3] AND " +
	    KeyFoldSql("ip.\"column_name\"") + " = " + KeyFoldSql(read_name("rc")) +
	    " WHERE o.form <> 'alias'"
	    " UNION ALL BY NAME"
	    // a column whose levels' paths leave nothing of it (`addr.city` at one, `addr.secret` at the other) is no
	    // column of the read - acl_listed_type answers NULL for it
	    " SELECT * FROM (SELECT i.* REPLACE (a.vcat AS table_catalog, a.path AS table_schema, " +
	    KeyQuotePartSql("i.\"table_name\"") + " AS table_name, " +
	    listed_type("i.\"data_type\"", "i.\"column_name\"", alias_roles) +
	    " AS data_type)"
	    " FROM aliases a JOIN " +
	    icolumns +
	    " i ON i.\"table_catalog\" = a.parts[1] AND i.\"table_schema\" = a.parts[2]"
	    " WHERE len(a.parts) = 2" +
	    alias_visible + ") __acl_alias_columns WHERE data_type IS NOT NULL";
	auto path = [](const string &alias) {
		return "CASE WHEN " + alias + ".vschema = 'main' THEN " + alias + ".vname ELSE " + alias +
		       ".vschema || '.' || " + alias + ".vname END";
	};
	string listed_path = "CASE WHEN l.table_schema = 'main' THEN l.table_name"
	                     " ELSE l.table_schema || '.' || l.table_name END";
	// A grant's own projection wins over the object's row for the names it defines - it is what the
	// role actually reads - and adds the ones the object never had (spec 026).
	// the object's own column rows, read once: the listing itself, and - spec 102 - the source type a
	// grant's projection is computed over
	prelude += ", lcols AS (" + columns_sql + ") ";
	string source_path = "CASE WHEN s.table_schema = 'main' THEN s.table_name"
	                     " ELSE s.table_schema || '.' || s.table_name END";
	// spec 102: what a principal reads of a column its grants project is what the read path computes -
	// the roles' column lists folded and united, the tree applied to the source's type - never one
	// role's probed type: two roles narrowing a struct differently read the union of their fields
	string roles_of = "(SELECT list(struct_pack(cat := gc.cat_columns, obj := gc.obj_columns,"
	                  " probed := (SELECT max(pc.\"type\") FROM " +
	                  Tbl("grant_columns") +
	                  " pc WHERE pc.\"role\" = gc.\"role\" AND pc.\"vcat\" = gc.vcat AND pc.\"vname\" = gc.vname"
	                  " AND pc.\"name\" = gp.name)) ORDER BY gc.\"role\") FROM gcolumns gc"
	                  " WHERE gc.vcat = gp.vcat AND gc.vname = gp.vname)";
	string relation_roles = "(SELECT list(struct_pack(cat := gc.cat_columns, obj := gc.obj_columns, probed := "
	                        "NULL::VARCHAR) ORDER BY gc.\"role\") FROM gcolumns gc WHERE gc.vcat = l.table_catalog AND"
	                        " gc.vname = " +
	                        listed_path + ")";
	string effective_columns_body =
	    (path_heads.empty() ? string("SELECT * FROM lcols l WHERE ")
	                        : "SELECT * REPLACE (" + listed_type("l.data_type", "l.column_name", relation_roles) +
	                              " AS data_type) FROM lcols l WHERE ") +
	    column_visible("l.table_catalog", listed_path, "l.column_name") +
	    " AND NOT EXISTS (SELECT 1 FROM gprojection gp WHERE gp.vcat = l.table_catalog AND gp.vname = " + listed_path +
	    " AND gp.name = l.column_name)" +
	    " UNION ALL BY NAME"
	    " SELECT gp.vcat AS table_catalog,"
	    " CASE WHEN " +
	    KeyNestedSql("gp.vname") + " THEN " + KeyParentSql("gp.vname") + " ELSE 'main' END AS table_schema, " +
	    KeyLeafSql("gp.vname") +
	    " AS table_name,"
	    " gp.name AS column_name, gp.pos + 1 AS ordinal_position,"
	    // a column the source has is typed by the roles' union over it - NULL (dropped below) when the union leaves
	    // nothing of it, never one role's own probe, which may name a field another level hides (review 144)
	    " acl_exposed_type(CASE WHEN s.data_type IS NULL THEN gp.type ELSE acl_listed_type(s.data_type,"
	    " gp.name, " +
	    roles_of +
	    ") END, o.strip_alias, o.enums_to_varchar) AS data_type,"
	    // spec 143: a column the grant names (masked or not) is the object's column - its comment and tags with it
	    " s.\"COLUMN_COMMENT\" AS \"COLUMN_COMMENT\", s.acl_tags AS acl_tags"
	    " FROM gprojection gp JOIN objects o ON o.vcat = gp.vcat AND " +
	    path("o") + " = gp.vname LEFT JOIN lcols s ON s.table_catalog = gp.vcat AND " + source_path +
	    " = gp.vname AND " + KeyFoldSql("s.column_name") + " = " + KeyFoldSql("gp.name") +

	    // spec 117: the columns of the system catalog's views - the types each view declares
	    (platform ? " UNION ALL BY NAME SELECT 'platform' AS table_catalog, pc.path AS table_schema, pc.vname AS"
	                " table_name, pc.name AS column_name, pc.pos AS ordinal_position, pc.type AS data_type,"
	                " 'YES' AS is_nullable FROM pcolumns pc"
	              : string());
	// spec 144: a column the levels' union leaves nothing of drops out, and - where a list narrowed anything - the
	// positions close up per object, as the read's (spec 036: a consumer counts them)
	string effective_columns =
	    stated_lists.empty()
	        ? effective_columns_body
	        : "SELECT * REPLACE (CAST(row_number() OVER (PARTITION BY table_catalog, table_schema, table_name ORDER BY"
	          " ordinal_position, column_name) AS INTEGER) AS ordinal_position) FROM (" +
	              effective_columns_body + ") __acl_kept WHERE data_type IS NOT NULL";
	if (surface == "columns") {
		return prelude + named("SELECT * EXCLUDE (acl_tags) FROM (" + effective_columns + ")", table_names);
	}
	if (surface == "columns_tagged") {
		return prelude + named(effective_columns, table_names); // spec 143: DescribeObject's
	}
	if (surface == "duckdb_columns") {
		// the same rows as information_schema.columns, in duckdb's own shape. `is_nullable` and
		// `is_generated` are booleans there and strings here, and a synthesized row (a mask, a
		// computed column) has neither - duckdb always answers, so a default is closer than a NULL.
		return prelude +
		       named("SELECT c.table_catalog AS database_name, " + database_oid("c.table_catalog") +
		                 " AS database_oid, c.table_schema AS schema_name, " +
		                 schema_oid("c.table_catalog", "c.table_schema") +
		                 " AS schema_oid, c.table_name AS table_name, " +
		                 object_oid("table", "c.table_catalog", "c.table_schema", "c.table_name") + " AS table_oid," +
		                 " c.column_name AS column_name, c.ordinal_position::INTEGER AS column_index," +
		                 " c.\"COLUMN_COMMENT\" AS comment, false AS internal," +
		                 " c.column_default AS column_default," +
		                 " coalesce(c.is_nullable = 'YES', true) AS is_nullable," +
		                 " c.data_type AS data_type, NULL::BIGINT AS data_type_id," +
		                 " c.character_maximum_length::INTEGER AS character_maximum_length," +
		                 " c.numeric_precision::INTEGER AS numeric_precision," +
		                 " c.numeric_precision_radix::INTEGER AS numeric_precision_radix," +
		                 " c.numeric_scale::INTEGER AS numeric_scale, coalesce(c.acl_tags, " + empty_map +
		                 ") AS tags, coalesce(c.is_generated = 'YES', false) AS is_generated," +
		                 " c.generation_expression AS generation_expression FROM (" + effective_columns + ") c",
		             {{"database_name", Shown::CATALOG}, {"schema_name", Shown::SCHEMA}, {"table_name", Shown::NAME}});
	}
	if (surface == "duckdb_tables" || surface == "duckdb_views") {
		bool views = surface == "duckdb_views";
		// the columns the role reads, used for both the count and the synthesized DDL - so
		// `DESCRIBE`, the columns listing and `sql` cannot describe three different objects
		string of_this_table = " FROM vcolumns c WHERE c.table_catalog = t.table_catalog"
		                       " AND c.table_schema = t.table_schema AND c.table_name = t.table_name";
		string column_count = "(SELECT count(*)" + of_this_table + ")::BIGINT AS column_count";
		auto quoted = [](const string &expr) {
			return "'\"' || replace(" + expr + ", '\"', '\"\"') || '\"'";
		};
		// what the role reads, spelled as DDL a client can parse and bind - never the physical
		// `CREATE TABLE`, which names the physical object and its full set of columns
		string ddl = "(SELECT 'CREATE TABLE ' || " + quoted(KeyUnquoteSql("t.table_name")) + " || '(' || string_agg(" +
		             quoted("c.column_name") + " || ' ' || c.data_type, ', ' ORDER BY c.ordinal_position)" +
		             " || ');'" + of_this_table + ")";
		string head = string("SELECT t.table_catalog AS database_name, ") + database_oid("t.table_catalog") +
		              " AS database_oid, t.table_schema AS schema_name, " +
		              schema_oid("t.table_catalog", "t.table_schema") + " AS schema_oid, t.table_name AS " +
		              (views ? "view_name" : "table_name") + ", " +
		              object_oid("table", "t.table_catalog", "t.table_schema", "t.table_name") + " AS " +
		              (views ? "view_oid" : "table_oid") + ", t.\"TABLE_COMMENT\" AS comment, coalesce(t.acl_tags, " +
		              empty_map + ") AS tags, false AS internal, false AS temporary, ";
		// has_primary_key stops being a refused physical fact and reports the *declared* key
		// (spec 048) - the same rows acl_keys() answers with, so the two cannot disagree
		string key_path = "CASE WHEN t.table_schema = 'main' THEN t.table_name"
		                  " ELSE t.table_schema || '.' || t.table_name END";
		// the same rule as acl_keys(): a key over a hidden column is not this role's to see, so
		// has_primary_key and the keys listing cannot disagree under any grant
		string key_col_path = "CASE WHEN vc.table_schema = 'main' THEN vc.table_name"
		                      " ELSE vc.table_schema || '.' || vc.table_name END";
		string has_key = "EXISTS (SELECT 1 FROM " + Tbl("keys") +
		                 " k WHERE k.\"vcat\" = t.table_catalog AND k.\"vname\" = " + key_path +
		                 " AND k.\"kind\" = 'relation'"
		                 " AND NOT EXISTS (SELECT 1 FROM " +
		                 Tbl("keys") +
		                 " k2 WHERE k2.\"vcat\" = k.\"vcat\" AND k2.\"vname\" = k.\"vname\""
		                 " AND k2.\"kind\" = 'relation'"
		                 " AND NOT EXISTS (SELECT 1 FROM vcolumns vc WHERE vc.table_catalog = k.\"vcat\" AND " +
		                 key_col_path + " = k2.\"vname\" AND " + KeyFoldSql("vc.column_name") + " = " +
		                 KeyFoldSql("k2.\"column\"") + ")))";
		string tail = views ? column_count + ", NULL::VARCHAR AS sql, true AS is_bound"
		                    : has_key + " AS has_primary_key, NULL::BIGINT AS estimated_size, " + column_count +
		                          ", NULL::BIGINT AS index_count, NULL::BIGINT AS check_constraint_count, " + ddl +
		                          " AS sql";
		// spec 065: an object with no visible column has no DDL to synthesize - a NULL `sql` broke
		// a quack client on the whole catalog, so the row is not listed at all (catalog facts only:
		// vcolumns is the same fold every other answer here uses)
		// the filter is the tables branch's own: only there is `sql` synthesized from the columns,
		// and a view whose shape was never probed must stay listed (its read still answers)
		return prelude + ", vcolumns AS (" + effective_columns + ") " +
		       named(head + tail + " FROM (" + tables_sql + ") t WHERE t.table_type " + (views ? "=" : "<>") +
		                 " 'VIEW'" + (views ? string() : " AND EXISTS (SELECT 1" + of_this_table + ")"),
		             {{"database_name", Shown::CATALOG},
		              {"schema_name", Shown::SCHEMA},
		              {views ? "view_name" : "table_name", Shown::NAME}});
	}
	if (surface == "show_tables_expanded") {
		// `SHOW ALL TABLES`: every table of every catalog the principal holds, with the columns it
		// reads - the same fold duckdb does over duckdb_tables + duckdb_columns
		return prelude + ", vcolumns AS (" + effective_columns + ") " +
		       named("SELECT c.table_catalog AS database, c.table_schema AS schema, c.table_name AS name,"
		             " list(c.column_name ORDER BY c.ordinal_position) AS column_names,"
		             " list(c.data_type ORDER BY c.ordinal_position) AS column_types, false AS temporary"
		             " FROM vcolumns c GROUP BY ALL",
		             {{"database", Shown::CATALOG}, {"schema", Shown::SCHEMA}, {"name", Shown::NAME}}, "ALL");
	}
	// spec 048: the declared keys a principal may see - the object visible, and every column the
	// key names visible (a listed key over a hidden column describes what the role cannot read).
	// A grant's columns list narrows a table function's result exactly as it narrows a relation
	// (spec 011), so a function's key hides with any key column the narrowing takes away.
	if (surface == "keys") {
		string kcolumn_path = "CASE WHEN vc.table_schema = 'main' THEN vc.table_name"
		                      " ELSE vc.table_schema || '.' || vc.table_name END";
		// spec 145: as gcolumns - the rows that may call it (a call is a read), else every visible row's
		string gfcolumns = "gfcolumns_all AS (SELECT DISTINCT f.\"vcat\" AS vcat, f.\"vname\" AS vname,"
		                   " g.\"columns\" AS cat_columns, " +
		                   string(object_level ? "oc.\"columns\"" : "NULL") + " AS obj_columns, " +
		                   CapsAllowSql(caps_chain("f.\"vname\"", "f.\"vcat\""), "select") + " AS reads FROM " +
		                   Tbl("functions") + " f JOIN grants g ON g.\"vcat\" = f.\"vcat\"" +
		                   (object_level ? " LEFT JOIN " + Tbl("role_object_caps") +
		                                       " oc ON oc.\"role\" = g.\"role\" AND oc.\"vcat\" = f.\"vcat\""
		                                       " AND oc.\"vname\" = f.\"vname\""
		                                 : string()) +
		                   " WHERE f.\"kind\" = 'table' AND " + FunctionVisibleExpr(object_level, schema_level) +
		                   "), gfcolumns AS (SELECT vcat, vname, cat_columns, obj_columns FROM gfcolumns_all x WHERE"
		                   " x.reads OR NOT EXISTS (SELECT 1 FROM gfcolumns_all y WHERE y.vcat = x.vcat AND"
		                   " y.vname = x.vname AND y.reads))";
		string fkey = "gf.vcat = k.\"vcat\" AND gf.vname = k.\"vname\"";
		string fcolumn_visible = "(NOT EXISTS (SELECT 1 FROM gfcolumns gf WHERE " + fkey +
		                         ") OR EXISTS (SELECT 1 FROM gfcolumns gf WHERE " + fkey + " AND " +
		                         keeps("gf.cat_columns", "k2.\"column\"") + " AND " +
		                         keeps("gf.obj_columns", "k2.\"column\"") + "))";
		return prelude + ", vcolumns AS (" + effective_columns + "), " + gfcolumns + " " +
		       named("SELECT k.\"vcat\" AS vcat, k.\"vname\" AS object, k.\"kind\" AS kind,"
		             " k.\"pos\" + 1 AS key_sequence, k.\"column\" AS \"column\" FROM " +
		                 Tbl("keys") +
		                 " k WHERE (CASE WHEN k.\"kind\" = 'table'"
		                 " THEN EXISTS (SELECT 1 FROM vfunctions vf WHERE vf.vcat = k.\"vcat\""
		                 " AND vf.vname = k.\"vname\")"
		                 " ELSE EXISTS (SELECT 1 FROM objects o WHERE o.vcat = k.\"vcat\" AND " +
		                 path("o") +
		                 " = k.\"vname\") END)"
		                 " AND NOT EXISTS (SELECT 1 FROM " +
		                 Tbl("keys") +
		                 " k2 WHERE k2.\"vcat\" = k.\"vcat\" AND k2.\"vname\" = k.\"vname\""
		                 " AND k2.\"kind\" = k.\"kind\" AND NOT CASE WHEN k.\"kind\" = 'table' THEN " +
		                 fcolumn_visible +
		                 " ELSE EXISTS (SELECT 1 FROM vcolumns vc WHERE vc.table_catalog = k.\"vcat\" AND " +
		                 kcolumn_path + " = k2.\"vname\" AND " + KeyFoldSql("vc.column_name") + " = " +
		                 KeyFoldSql("k2.\"column\"") + ") END)",
		             {{"vcat", Shown::CATALOG}}, "vcat, object, key_sequence");
	}
	// spec 022: a reference is visible when both of its ends are, and when every column it names is
	// a column the role can see. Anything else would describe an object - or a column - the role
	// has no access to, which is what a listing must never do.
	string column_path = "CASE WHEN vc.table_schema = 'main' THEN vc.table_name"
	                     " ELSE vc.table_schema || '.' || vc.table_name END";
	return prelude + ", vcolumns AS (" + effective_columns + ") " +
	       named("SELECT r.\"vcat\" AS vcat, r.\"name\" AS name, r.\"from_vname\" AS from_object,"
	             " r.\"to_vname\" AS to_object,"
	             // the arguments a function end is called with, and - separately - the columns of the join
	             // condition: an argument's source column is a `from` column that also names a parameter
	             " (SELECT string_agg(rc.\"param\" || ' => ' || rc.\"column\", ', ' ORDER BY rc.\"pos\") FROM " +
	                 Tbl("reference_columns") +
	                 " rc WHERE rc.\"vcat\" = r.\"vcat\" AND rc.\"name\" = r.\"name\" AND rc.\"param\" IS NOT NULL)"
	                 " AS arguments,"
	                 " (SELECT string_agg(rc.\"column\", ', ' ORDER BY rc.\"pos\") FROM " +
	                 Tbl("reference_columns") +
	                 " rc WHERE rc.\"vcat\" = r.\"vcat\" AND rc.\"name\" = r.\"name\" AND rc.\"side\" = 'from'"
	                 " AND rc.\"param\" IS NULL)"
	                 " AS from_columns,"
	                 " (SELECT string_agg(rc.\"column\", ', ' ORDER BY rc.\"pos\") FROM " +
	                 Tbl("reference_columns") +
	                 " rc WHERE rc.\"vcat\" = r.\"vcat\" AND rc.\"name\" = r.\"name\" AND rc.\"side\" = 'to')"
	                 " AS to_columns,"
	                 // The same two, as lists. `string_agg` reads well for a human and for an agent, but a
	                 // consumer that has to *pair* the sides by position cannot get there from a joined
	                 // string - splitting on ', ' breaks on a column name containing one. Flight SQL's
	                 // key RPCs need exactly that pairing (spec 046), so the lists are published beside the
	                 // strings rather than instead of them.
	                 " (SELECT list(rc.\"column\" ORDER BY rc.\"pos\") FROM " +
	                 Tbl("reference_columns") +
	                 " rc WHERE rc.\"vcat\" = r.\"vcat\" AND rc.\"name\" = r.\"name\" AND rc.\"side\" = 'from'"
	                 " AND rc.\"param\" IS NULL)"
	                 " AS from_column_list,"
	                 " (SELECT list(rc.\"column\" ORDER BY rc.\"pos\") FROM " +
	                 Tbl("reference_columns") +
	                 " rc WHERE rc.\"vcat\" = r.\"vcat\" AND rc.\"name\" = r.\"name\" AND rc.\"side\" = 'to')"
	                 " AS to_column_list,"
	                 // spec 121: whether the far end declares a key the role sees (all its columns visible) - what a
	                 // tool's foreign-key listing names, without a second listing of every key
	                 " (r.\"to_kind\" = 'relation' AND EXISTS (SELECT 1 FROM " +
	                 Tbl("keys") +
	                 " k WHERE k.\"vcat\" = r.\"vcat\" AND k.\"vname\" = r.\"to_vname\" AND k.\"kind\" = 'relation')"
	                 " AND NOT EXISTS (SELECT 1 FROM " +
	                 Tbl("keys") +
	                 " k2 WHERE k2.\"vcat\" = r.\"vcat\" AND k2.\"vname\" = r.\"to_vname\" AND k2.\"kind\" = 'relation'"
	                 " AND NOT EXISTS (SELECT 1 FROM vcolumns vc WHERE vc.table_catalog = r.\"vcat\" AND " +
	                 column_path + " = r.\"to_vname\" AND " + KeyFoldSql("vc.column_name") + " = " +
	                 KeyFoldSql("k2.\"column\"") +
	                 "))) AS to_has_key,"
	                 " r.\"to_kind\" AS to_kind, r.\"expr\" AS expression, r.\"cardinality\" AS cardinality,"
	                 " r.\"optional\" AS optional, r.\"join_method\" AS join_method, r.\"comment\" AS comment FROM " +
	                 Tbl("references") + " r WHERE EXISTS (SELECT 1 FROM objects o WHERE o.vcat = r.\"vcat\" AND " +
	                 path("o") + " = r.\"from_vname\")" +
	                 // the far end is an object, or - for a lateral call - a table function the role may use
	                 " AND (CASE WHEN r.\"to_kind\" = 'function'"
	                 " THEN EXISTS (SELECT 1 FROM vfunctions vf WHERE vf.vcat = r.\"vcat\""
	                 " AND vf.vname = r.\"to_vname\")"
	                 " ELSE EXISTS (SELECT 1 FROM objects o WHERE o.vcat = r.\"vcat\" AND " +
	                 path("o") + " = r.\"to_vname\") END)" +
	                 // every column it names must be one the role sees. The `to` side of a lateral call names
	                 // parameters, not columns, so there is nothing there to hide or to check.
	                 " AND NOT EXISTS (SELECT 1 FROM " + Tbl("reference_columns") +
	                 " rc WHERE rc.\"vcat\" = r.\"vcat\" AND rc.\"name\" = r.\"name\""
	                 " AND NOT (r.\"to_kind\" = 'function' AND rc.\"side\" = 'to')"
	                 " AND NOT EXISTS (SELECT 1 FROM vcolumns vc WHERE vc.table_catalog = r.\"vcat\" AND " +
	                 column_path +
	                 " = CASE WHEN rc.\"side\" = 'from' THEN r.\"from_vname\" ELSE r.\"to_vname\" END"
	                 " AND vc.column_name = rc.\"column\"))",
	             {{"vcat", Shown::CATALOG}});
}

} // namespace acl_detail

using acl_detail::CatalogBackend;
using acl_detail::Lit;

namespace {

//! The three category listings answered from a model rather than from tables (spec 072)
IntrospectionRows FunctionListing(const string &listing, const FunctionCategoryModel &model) {
	IntrospectionRows out;
	if (StringUtil::CIEquals(listing, "function_categories")) {
		out.names = {"category", "comment", "builtin"};
		out.types = {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::BOOLEAN};
		for (auto &row : model.Categories()) {
			out.rows.push_back({Value(row.name), Value(row.comment), Value::BOOLEAN(row.builtin)});
		}
		return out;
	}
	if (StringUtil::CIEquals(listing, "function_category_members")) {
		out.names = {"category", "database", "schema", "name", "kind"};
		out.types = {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR,
		             LogicalType::VARCHAR};
		for (auto &member : model.Members()) {
			out.rows.push_back({Value(member.first), Value(member.second.database), Value(member.second.schema),
			                    Value(member.second.name), Value(FunctionKindName(member.second.kind))});
		}
		return out;
	}
	out.names = {"role", "category", "database", "schema", "name", "kind", "allowed"};
	out.types = {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR,
	             LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::BOOLEAN};
	for (auto &grant : model.Grants()) {
		if (grant.IsCategory()) {
			out.rows.push_back({Value(grant.role), Value(grant.category), Value(""), Value(""), Value(""), Value(""),
			                    Value::BOOLEAN(grant.allowed)});
		} else {
			out.rows.push_back({Value(grant.role), Value(""), Value(grant.key.database), Value(grant.key.schema),
			                    Value(grant.key.name), Value(FunctionKindName(grant.key.kind)),
			                    Value::BOOLEAN(grant.allowed)});
		}
	}
	return out;
}

} // namespace

IntrospectionRows PolicyStore::Introspect(const string &listing) {
	// what an operator may read of the policy source itself. No key and no credential is in it to begin
	// with (spec 095: they live in the secrets service).
	static const case_insensitive_map_t<string> LISTINGS = {
	    {"catalogs", "SELECT \"vcat\", \"comment\" FROM %s"},
	    {"schemas", "SELECT \"vcat\", \"path\", \"phys_path\", \"origin\", \"comment\" FROM %s"},
	    {"relations", "SELECT \"vcat\", \"vname\", \"form\", \"phys\", \"view_sql\", \"rls\", \"rls_checked\","
	                  " \"origin\", \"comment\" FROM %s"},
	    {"relation_columns", "SELECT \"vcat\", \"vname\", \"pos\", \"name\", \"expr\", \"nullable\" FROM %s"},
	    {"object_columns", "SELECT \"vcat\", \"vname\", \"kind\", \"pos\", \"name\", \"type\", \"comment\","
	                       " \"derived\", \"nullable\" FROM %s"},
	    {"functions", "SELECT \"vcat\", \"vname\", \"kind\", \"form\", \"target\", \"template\", \"params\","
	                  " \"comment\" FROM %s"},
	    {"references", "SELECT \"vcat\", \"name\", \"from_vname\", \"to_vname\", \"to_kind\", \"expr\","
	                   " \"cardinality\", \"optional\", \"join_method\", \"comment\" FROM %s"},
	    {"reference_columns", "SELECT \"vcat\", \"name\", \"pos\", \"side\", \"column\", \"param\" FROM %s"},
	    {"keys", "SELECT \"vcat\", \"vname\", \"kind\", \"pos\", \"column\" FROM %s"},
	    {"roles", "SELECT \"role\", \"comment\" FROM %s"},
	    {"role_claims", "SELECT \"role\", \"claim\", \"value\" FROM %s"},
	    {"grants", "SELECT \"role\", \"vcat\", \"is_main\", \"caps\", \"rls\", \"rls_checked\", \"columns\""
	               " FROM %s"},
	    {"schema_grants", "SELECT \"role\", \"vcat\", \"schema_path\", \"caps\", \"inherited\", \"into\","
	                      " \"virtual_only\", \"comment\" FROM %s"},
	    {"object_grants", "SELECT \"role\", \"vcat\", \"vname\", \"caps\", \"rls\", \"rls_checked\", \"columns\""
	                      " FROM %s"},
	    {"grant_columns", "SELECT \"role\", \"vcat\", \"vname\", \"pos\", \"name\", \"type\" FROM %s"},
	    {"admins", "SELECT \"role\", \"scope\", \"vcat\" FROM %s"},
	    // spec 095: what is stored - a value kept in a secret is NULL here, beside the secret's name;
	    // nothing in these tables is a key or a credential
	    {"issuers", "SELECT \"name\", \"url\", \"secret_service\", \"secret\" FROM %s ORDER BY \"name\""},
	    {"clients", "SELECT \"name\", \"issuer\", \"audiences\", \"azp\", \"requires\", \"roles_from\","
	                " \"roles_constant\", \"unmapped\", \"attributes\", \"subject\", \"token_type\", \"client_id\","
	                " \"flows\", \"secret_service\", \"secret\", \"implicit\" FROM %s ORDER BY \"issuer\", \"name\""},
	    {"role_mappings", "SELECT \"scope_kind\", \"scope_name\", \"source\", \"external_value\", \"role\" FROM %s"},
	    {"function_categories", "SELECT \"category\", \"comment\", \"builtin\" FROM %s"},
	    {"function_category_members", "SELECT \"category\", \"database\", \"schema\", \"name\", \"kind\" FROM %s"},
	    {"function_grants",
	     "SELECT \"role\", \"category\", \"database\", \"schema\", \"name\", \"kind\", \"allowed\" FROM %s"},
	    {"resource_groups",
	     "SELECT \"group\", \"window_start\", \"window_max\", \"batch_bytes\", "
	     "\"max_result_rows\", \"queue_priority\", \"max_sessions\", \"comment\", \"is_default\" FROM %s"},
	    {"role_resource_groups", "SELECT \"role\", \"group\" FROM %s"},
	};
	static const case_insensitive_map_t<string> TABLES = {
	    {"catalogs", "catalogs"},
	    {"schemas", "schemas"},
	    {"relations", "relations"},
	    {"relation_columns", "relation_columns"},
	    {"object_columns", "object_columns"},
	    {"functions", "functions"},
	    {"references", "references"},
	    {"reference_columns", "reference_columns"},
	    {"keys", "keys"},
	    {"roles", "roles"},
	    {"role_claims", "role_claims"},
	    {"grants", "role_catalogs"},
	    {"schema_grants", "role_schemas"},
	    {"object_grants", "role_object_caps"},
	    {"grant_columns", "grant_columns"},
	    {"admins", "admins"},
	    {"issuers", "issuers"},
	    {"clients", "clients"},
	    {"role_mappings", "role_mappings"},
	    {"function_categories", "function_categories"},
	    {"function_category_members", "function_category_members"},
	    {"function_grants", "function_grants"},
	    {"resource_groups", "resource_groups"},
	    {"role_resource_groups", "role_resource_groups"},
	};
	IntrospectionRows out;
	if (StringUtil::CIEquals(listing, "status")) {
		out.names = {"backend", "schema_version", "policy_version", "version_check_interval", "enumerates"};
		out.types = {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::BIGINT,
		             LogicalType::BOOLEAN};
		string backend = catalog ? (catalog->FunctionMode() ? "functions" : "catalog") : "memory";
		Value schema_version, policy_version;
		int64_t interval = 0;
		if (catalog && !catalog->FunctionMode()) {
			schema_version = Value(catalog->MetaValue("schema_version"));
			policy_version = Value(catalog->MetaValue("policy_version"));
			interval = catalog->SettingInt64("acl_version_check_interval", 1000);
		}
		out.rows.push_back({Value(backend), schema_version, policy_version, Value::BIGINT(interval),
		                    Value::BOOLEAN(catalog && !catalog->FunctionMode())});
		return out;
	}
	auto entry = LISTINGS.find(listing);
	if (entry == LISTINGS.end()) {
		throw BinderException("acl: there is no listing called \"%s\"", listing);
	}
	if (!catalog || catalog->FunctionMode()) {
		// spec 072: the function categories exist in every mode - the seed in memory and behind a
		// function-driver source without the slots - so these three answer from the model itself
		if (StringUtil::CIEquals(listing, "function_categories") ||
		    StringUtil::CIEquals(listing, "function_category_members") ||
		    StringUtil::CIEquals(listing, "function_grants")) {
			return FunctionListing(listing, *FunctionModel());
		}
	}
	if (!catalog) {
		throw BinderException("acl: no policy source is active, so there is nothing to list - run acl_use_db() or "
		                      "acl_use_functions() first (the in-memory store is a dev stub and does not enumerate)");
	}
	if (catalog->FunctionMode()) {
		throw BinderException("acl: this policy source does not expose enumeration, so \"%s\" cannot be listed - "
		                      "the driver contract is keyed lookup, and an empty answer would read as \"nothing is "
		                      "configured\"",
		                      listing);
	}
	auto table = TABLES.find(listing)->second;
	auto result = catalog->Query(StringUtil::Replace(entry->second, "%s", catalog->Tbl(table.c_str())));
	ResultRows result_rows(*result);
	for (auto &name : result->GetNames()) {
		out.names.push_back(name.GetIdentifierName());
	}
	out.types = result->GetTypes();
	for (idx_t row = 0; row < result->RowCount(); row++) {
		vector<Value> values;
		for (idx_t col = 0; col < result->ColumnCount(); col++) {
			values.push_back(result_rows.GetValue(col, row));
		}
		out.rows.push_back(std::move(values));
	}
	return out;
}

bool PolicyStore::MetadataListing(const Principal &principal, const string &surface, string &sql,
                                  const ListingScope &scope) {
	if (surface == "duckdb_functions") {
		sql = PrincipalFunctionsSql(principal); // spec 098: every mode answers the engine's half
		return true;
	}
	if (surface == "duckdb_types") {
		// spec 099: the built-ins and the loaded extensions' types, once - never another database's
		// name, a user type or an ENUM's labels; every mode, no policy needed
		sql = "SELECT * FROM system.main.duckdb_types() WHERE database_name = 'system'";
		return true;
	}
	if (!catalog) {
		return false; // the memory store has no catalog to list; the surface stays denied
	}
	// spec 117: the platform catalog's share - absent on the quack door (quack loads a catalog whole and
	// the console is Flight / JDBC), and for a principal holding nothing on it
	string platform_objects, platform_columns;
	if (principal.session.empty() || SessionDoorOf(principal.session) != "quack") {
		PlatformListingCtes(AdminRightsOf(principal), platform_objects, platform_columns, scope);
	}
	sql = catalog->MetadataListingSql(principal, surface, platform_objects, platform_columns, scope);
	return true;
}

namespace {

//! What a listing shows depends on the roles alone (the claims narrow rows, never columns)
string RoleSetKey(const Principal &principal) {
	auto roles = principal.roles;
	std::sort(roles.begin(), roles.end());
	return StringUtil::Join(roles, "\x1f");
}

//! The principal without its session: a session's temps and the platform's share are no virtual object's, so a
//! description kept per role set holds for every session of it
Principal Listed(const Principal &principal) {
	Principal listed = principal;
	listed.session.clear();
	return listed;
}

} // namespace

shared_ptr<const PolicyStore::ObjectDescription> PolicyStore::DescribeObject(const Principal &principal,
                                                                             const string &catalog_name,
                                                                             const string &schema,
                                                                             const string &table) {
	if (!catalog) {
		return nullptr; // the memory store lists nothing
	}
	string key = RoleSetKey(principal) + "\x1e" + StringUtil::Lower(catalog_name) + "\x1e" + StringUtil::Lower(schema) +
	             "\x1e" + StringUtil::Lower(table);
	auto version = PolicyVersion();
	auto now = std::chrono::steady_clock::now();
	{
		std::lock_guard<std::mutex> guard(descriptions_lock);
		auto found = descriptions.find(key);
		if (found != descriptions.end() && found->second.version == version &&
		    now - found->second.read < std::chrono::minutes(10)) {
			return found->second.description;
		}
	}
	// information_schema's two surfaces with their tags kept - the listing's cheap bodies (duckdb_tables'
	// shape costs a planner pass over its per-table subqueries), narrowed to the object
	ListingScope scope;
	scope.catalogs = {catalog_name};
	scope.schemas = {schema};
	scope.tables = {table};
	string tables_sql, columns_sql;
	auto listed = Listed(principal);
	MetadataListing(listed, "tables_tagged", tables_sql, scope);
	MetadataListing(listed, "columns_tagged", columns_sql, scope);
	// names compare as the catalog compares them (one ASCII fold, spec 116): a name written in another case than the
	// object's - a live alias schema's object keeps the spelling it was read under - is the same object
	auto where = " WHERE " + KeyFoldSql("table_catalog") + " = " + KeyFoldSql(Lit(catalog_name)) + " AND " +
	             KeyFoldSql("table_schema") + " = " + KeyFoldSql(Lit(schema)) + " AND " + KeyFoldSql("table_name") +
	             " = " + KeyFoldSql(Lit(table));
	shared_ptr<ObjectDescription> description;
	auto objects = catalog->Query("SELECT \"TABLE_COMMENT\", acl_tags, table_catalog, table_schema, table_name FROM (" +
	                              tables_sql + ")" + where);
	ResultRows object_rows(*objects);
	if (object_rows.Count() == 1) {
		description = make_shared_ptr<ObjectDescription>();
		description->comment = object_rows.GetValue(0, 0);
		description->tags = object_rows.GetValue(1, 0);
		description->catalog = object_rows.GetValue(2, 0).ToString();
		description->schema = object_rows.GetValue(3, 0).ToString();
		description->table = object_rows.GetValue(4, 0).ToString();
		auto columns =
		    catalog->Query("SELECT column_name, \"COLUMN_COMMENT\", acl_tags FROM (" + columns_sql + ")" + where);
		ResultRows column_rows(*columns);
		for (idx_t i = 0; i < column_rows.Count(); i++) {
			description->columns.emplace(column_rows.GetValue(0, i).ToString(),
			                             std::make_pair(column_rows.GetValue(1, i), column_rows.GetValue(2, i)));
		}
	}
	// kept whatever it says - none (an object the listings do not show) included, so a statement over one does not
	// pay for the listing again
	std::lock_guard<std::mutex> guard(descriptions_lock);
	if (descriptions.size() >= 4096) {
		descriptions.clear(); // a cache, not a record: past its bound it starts over
	}
	descriptions[key] = CachedDescription {version, now, description};
	return description;
}

std::map<std::tuple<string, string, string>, Value>
PolicyStore::ObjectTags(const Principal &principal, const vector<std::tuple<string, string, string>> &objects) {
	std::map<std::tuple<string, string, string>, Value> out;
	if (!catalog || objects.empty()) {
		return out;
	}
	ListingScope scope;
	std::set<string> catalogs, schemas, tables;
	for (auto &object : objects) {
		catalogs.insert(std::get<0>(object));
		schemas.insert(std::get<1>(object));
		tables.insert(std::get<2>(object));
	}
	scope.catalogs.assign(catalogs.begin(), catalogs.end());
	scope.schemas.assign(schemas.begin(), schemas.end());
	scope.tables.assign(tables.begin(), tables.end());
	string sql;
	MetadataListing(Listed(principal), "tables_tagged", sql, scope);
	auto rows = catalog->Query("SELECT table_catalog, table_schema, table_name, acl_tags FROM (" + sql +
	                           ") WHERE acl_tags IS NOT NULL AND cardinality(acl_tags) > 0");
	ResultRows tagged(*rows);
	for (idx_t i = 0; i < tagged.Count(); i++) {
		out.emplace(std::make_tuple(tagged.GetValue(0, i).ToString(), tagged.GetValue(1, i).ToString(),
		                            tagged.GetValue(2, i).ToString()),
		            tagged.GetValue(3, i));
	}
	return out;
}

} // namespace acl
} // namespace duckdb
