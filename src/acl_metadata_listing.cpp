// The metadata surfaces of the catalog backend (specs 025/026/030/046): the SQL that answers a
// principal's information_schema / duckdb_* / SHOW listings from the policy it is granted, and the
// acl_* introspection rows an administrator reads. Split from acl_policy_catalog.cpp (plan 4.2).

#include "acl_policy_catalog.hpp"

namespace duckdb {
namespace acl {
namespace acl_detail {

string CatalogBackend::MetadataListingSql(const Principal &principal, const string &surface) {
	if (function_mode) {
		throw BinderException("acl: this policy source does not expose enumeration, so %s cannot be listed "
		                      "for a principal",
		                      surface);
	}
	// an object appears when the role holds something on it; '{}' is an explicit nothing (spec 012)
	auto visible = "(" + CapsExpr() + " IS NULL OR trim(" + CapsExpr() + ") = '' OR trim(" + CapsExpr() + ") <> '{}')";
	string oc_join = HasObjectCaps() ? " LEFT JOIN " + Tbl("role_object_caps") +
	                                       " oc ON oc.\"role\" = g.\"role\" AND oc.\"vcat\" = r.\"vcat\""
	                                       " AND oc.\"vname\" = r.\"vname\""
	                                 : string();
	// the written path splits into a virtual schema and a name; a bare name sits in `main`
	string objects = "objects AS (SELECT DISTINCT r.\"vcat\" AS vcat,"
	                 " CASE WHEN position('.' IN r.\"vname\") > 0"
	                 " THEN regexp_extract(r.\"vname\", '^(.*)[.][^.]*$', 1) ELSE 'main' END AS vschema,"
	                 " regexp_extract(r.\"vname\", '([^.]*)$', 1) AS vname, r.\"vname\" AS stored_name,"
	                 " r.\"form\" AS form, r.\"comment\" AS comment,"
	                 " str_split(r.\"phys\", '.') AS parts FROM " +
	                 Tbl("relations") + " r JOIN grants g ON g.\"vcat\" = r.\"vcat\"" + oc_join + " WHERE " + visible +
	                 ")";
	// an alias schema shows the physical schema live, so its visibility is the role's capabilities
	// on that schema (its own grant if it has one, otherwise the catalog's) - without this filter a
	// role granted an explicit nothing would still read the names out of the source
	auto schema_caps = "coalesce(nullif(trim((SELECT sc.\"caps\" FROM " + Tbl("role_schemas") +
	                   " sc WHERE sc.\"role\" = g.\"role\" AND sc.\"vcat\" = s.\"vcat\""
	                   " AND sc.\"schema_path\" = s.\"path\")), ''), g.\"caps\")";
	auto schema_visible =
	    "(" + schema_caps + " IS NULL OR trim(" + schema_caps + ") = '' OR trim(" + schema_caps + ") <> '{}')";
	string aliases = "aliases AS (SELECT DISTINCT s.\"vcat\" AS vcat, s.\"path\" AS path,"
	                 " str_split(s.\"phys_path\", '.') AS parts FROM " +
	                 Tbl("schemas") +
	                 " s JOIN grants g ON g.\"vcat\" = s.\"vcat\""
	                 " WHERE s.\"phys_path\" IS NOT NULL AND " +
	                 schema_visible + ")";
	// a schema exists for the principal when something inside it does
	string schemas = "vschemas AS (SELECT vcat, path FROM aliases UNION SELECT vcat, vschema FROM objects)";
	// spec 011 narrows columns per grant level, and the listing has to narrow with it: the object
	// row is kept per role here (unlike `objects`, which collapses them) so that "visible for at
	// least one role" can be asked column by column.
	string vfunctions = "vfunctions AS (SELECT DISTINCT f.\"vcat\" AS vcat, f.\"vname\" AS vname FROM " +
	                    Tbl("functions") + " f JOIN grants g ON g.\"vcat\" = f.\"vcat\"" +
	                    (HasObjectCaps() ? " LEFT JOIN " + Tbl("role_object_caps") +
	                                           " oc ON oc.\"role\" = g.\"role\" AND oc.\"vcat\" = f.\"vcat\""
	                                           " AND oc.\"vname\" = f.\"vname\""
	                                     : string()) +
	                    " WHERE f.\"kind\" = 'table' AND " + FunctionVisibleExpr() + ")";
	string grant_columns = "gcolumns AS (SELECT r.\"vcat\" AS vcat, r.\"vname\" AS vname, g.\"role\" AS role,"
	                       " g.\"columns\" AS cat_columns, " +
	                       string(HasObjectCaps() ? "oc.\"columns\"" : "NULL") + " AS obj_columns FROM " +
	                       Tbl("relations") + " r JOIN grants g ON g.\"vcat\" = r.\"vcat\"" + oc_join + " WHERE " +
	                       visible + ")";
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
	string projected = "gprojection AS (SELECT vcat, vname, name, type,"
	                   " row_number() OVER (PARTITION BY vcat, vname ORDER BY rk) - 1 AS pos FROM"
	                   " (SELECT vcat, vname, name, min_by(type, rk) AS type, min(rk) AS rk FROM"
	                   " (SELECT vcat, vname, name, type,"
	                   " row_number() OVER (PARTITION BY vcat, vname ORDER BY \"role\", \"pos\") AS rk FROM"
	                   " (SELECT DISTINCT pc.\"vcat\" AS vcat, pc.\"vname\" AS vname, pc.\"name\" AS name,"
	                   " pc.\"type\" AS type, pc.\"role\" AS \"role\", pc.\"pos\" AS \"pos\" FROM " +
	                   Tbl("grant_columns") +
	                   " pc JOIN grants g ON g.\"role\" = pc.\"role\" AND g.\"vcat\" = pc.\"vcat\""
	                   // One role whose chain states no column list lifts the restriction for the
	                   // whole principal (spec 011: `Restricts()` is `any && !unrestricted`), and
	                   // then the object's own columns are what it reads - so another role's
	                   // projection must not be listed either, or the listing would advertise a
	                   // column `SELECT *` never returns.
	                   " WHERE NOT EXISTS (SELECT 1 FROM gcolumns gc WHERE gc.vcat = pc.\"vcat\""
	                   " AND gc.vname = pc.\"vname\""
	                   " AND (gc.cat_columns IS NULL OR trim(gc.cat_columns) = '')"
	                   " AND (gc.obj_columns IS NULL OR trim(gc.obj_columns) = ''))))"
	                   " GROUP BY vcat, vname, name))";
	auto prelude = GrantsCte(principal) + ", " + objects + ", " + aliases + ", " + schemas + ", " + grant_columns +
	               ", " + vfunctions + ", " + projected + " ";
	// spec 035: each surface answers in its own standard shape, column for column and type for
	// type. A value that would describe the physical object rather than the virtual one is not
	// borrowed - an oid identifies a physical catalog entry, a path is the physical database.
	auto empty_map = "MAP {}::MAP(VARCHAR, VARCHAR)";
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
		return prelude + "SELECT vcat AS database_name, " + database_oid("vcat") +
		       " AS database_oid, NULL::VARCHAR AS path,"
		       " NULL::VARCHAR AS comment, " +
		       empty_map +
		       " AS tags, false AS internal, NULL::VARCHAR AS type,"
		       " false AS readonly, false AS encrypted, NULL::VARCHAR AS cipher, " +
		       empty_map + " AS options FROM (SELECT DISTINCT vcat FROM vschemas)";
	}
	if (surface == "schemata") {
		return prelude + "SELECT DISTINCT vcat AS catalog_name, path AS schema_name,"
		                 " NULL::VARCHAR AS schema_owner, NULL::VARCHAR AS default_character_set_catalog,"
		                 " NULL::VARCHAR AS default_character_set_schema,"
		                 " NULL::VARCHAR AS default_character_set_name, NULL::VARCHAR AS sql_path"
		                 " FROM vschemas";
	}
	if (surface == "duckdb_schemas") {
		return prelude + "SELECT " + schema_oid("vcat", "path") + " AS oid, vcat AS database_name, " +
		       database_oid("vcat") + " AS database_oid, path AS schema_name, NULL::VARCHAR AS comment, " + empty_map +
		       " AS tags, false AS internal, NULL::VARCHAR AS sql,"
		       " NULL::VARCHAR AS parent_schema, NULL::BIGINT AS parent_schema_oid"
		       " FROM (SELECT DISTINCT vcat, path FROM vschemas)";
	}
	// spec 031: the SHOW forms, each in the shape duckdb answers it with. They are the same catalog
	// the information_schema surfaces describe - only a client asking `SHOW DATABASES` wants one
	// column called `database_name`, not an information_schema row.
	if (surface == "show_databases") {
		return prelude + "SELECT DISTINCT vcat AS database_name FROM vschemas ORDER BY 1";
	}
	if (surface == "show_schemas") {
		// `current` is the schema an unqualified name resolves in: `main` of the catalog the
		// principal holds as MAIN, which is exactly what resolution falls back to
		return prelude + "SELECT DISTINCT s.vcat AS database_name, s.path AS schema_name,"
		                 " (s.path = 'main' AND EXISTS (SELECT 1 FROM grants g WHERE g.\"vcat\" = s.vcat"
		                 " AND g.\"is_main\" = true)) AS \"current\" FROM vschemas s ORDER BY ALL";
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
		return "(" + caps_expr + " IS NULL OR trim(" + caps_expr + ") = '' OR regexp_matches(" + caps_expr +
		       ", '(?i)\"insert\"\\s*:\\s*true'))";
	};
	string o_oc_join = HasObjectCaps() ? " LEFT JOIN " + Tbl("role_object_caps") +
	                                         " oc ON oc.\"role\" = g.\"role\" AND oc.\"vcat\" = o.vcat"
	                                         " AND oc.\"vname\" = o.stored_name"
	                                   : string();
	// writability is the stored authority's verdict, not re-derived: the relation's form was
	// decided where it was written (RenameOnlyColumns) - only the plain alias form takes writes,
	// a mask or an RLS'd relation is the read-only SUBQUERY form
	string object_insertable = "CASE WHEN o.form = 'alias' AND EXISTS (SELECT 1 FROM grants g" + o_oc_join +
	                           " WHERE g.\"vcat\" = o.vcat AND " +
	                           caps_allow_insert(CapsExpr("o.stored_name", "o.vcat")) +
	                           ") THEN 'YES' ELSE 'NO' END AS is_insertable_into";
	string alias_schema_caps = "coalesce((SELECT nullif(trim(sc.\"caps\"), '') FROM " + Tbl("role_schemas") +
	                           " sc WHERE sc.\"role\" = g.\"role\" AND sc.\"vcat\" = a.vcat"
	                           " AND sc.\"schema_path\" = a.path), g.\"caps\")";
	string alias_insertable = "CASE WHEN EXISTS (SELECT 1 FROM grants g WHERE g.\"vcat\" = a.vcat AND " +
	                          caps_allow_insert(alias_schema_caps) + ") THEN 'YES' ELSE 'NO' END AS is_insertable_into";
	// the comment is the virtual object's own: a physical comment describes the physical table, and
	// may say things about it the role is not reading (spec 035)
	string tables_sql =
	    string("SELECT i.* REPLACE (o.vcat AS table_catalog, o.vschema AS table_schema, o.vname AS table_name,"
	           " o.comment AS \"TABLE_COMMENT\", ") +
	    object_insertable + ") FROM objects o JOIN information_schema.tables i ON " + physical +
	    " WHERE len(o.parts) = 3"
	    " UNION ALL BY NAME"
	    " SELECT o.vcat AS table_catalog, o.vschema AS table_schema, o.vname AS table_name,"
	    " 'VIEW' AS table_type, 'NO' AS is_insertable_into FROM objects o WHERE o.form = 'view'"
	    " UNION ALL BY NAME"
	    " SELECT i.* REPLACE (a.vcat AS table_catalog, a.path AS table_schema, " +
	    alias_insertable +
	    ") FROM aliases a JOIN information_schema.tables i"
	    " ON i.\"table_catalog\" = a.parts[1] AND i.\"table_schema\" = a.parts[2]"
	    " WHERE len(a.parts) = 2";
	if (surface == "tables") {
		return prelude + tables_sql;
	}
	if (surface == "show_tables") {
		// a bare `SHOW TABLES` is the schema an unqualified name resolves in - `main` of the MAIN
		// catalog. Filtering on the schema alone listed the `main` of every granted catalog, whose
		// tables a bare name does not reach (spec 031).
		return prelude + "SELECT t.table_name AS name FROM (" + tables_sql +
		       ") t WHERE t.table_schema = 'main' AND EXISTS (SELECT 1 FROM grants g"
		       " WHERE g.\"vcat\" = t.table_catalog AND g.\"is_main\" = true) ORDER BY 1";
	}
	if (surface != "columns" && surface != "references" && surface != "keys" && surface != "show_tables_expanded" &&
	    surface != "show_tables" && surface != "duckdb_tables" && surface != "duckdb_views" &&
	    surface != "duckdb_columns") {
		throw BinderException("acl: unknown metadata surface \"%s\"", surface);
	}
	// the columns a role actually sees: an object's own projection when it has one (its rows in
	// relation_columns name the visible columns, and for an alias form they map virtual -> physical)
	string projection = " LEFT JOIN " + Tbl("relation_columns") +
	                    " c ON c.\"vcat\" = o.vcat AND c.\"vname\" = CASE WHEN o.vschema = 'main' THEN o.vname"
	                    " ELSE o.vschema || '.' || o.vname END";
	// An `alias` relation is the physical table under a virtual name (possibly with renamed
	// columns), so its listing is the physical row with the identity columns replaced - the rich
	// shape, for free. Anything else - a projection, a view - is described by its own stored
	// schema: a masked or computed column has no physical row to borrow, and leaving it out would
	// hide a column the role can read.
	// spec 048: one nullability precedence everywhere - the declared mark wins, the physical
	// answer flows where nothing is declared, and a declared-key column reports NOT NULL
	auto pk_implies = [&](const string &vcat_expr, const string &vname_expr, const string &column_expr) {
		return "EXISTS (SELECT 1 FROM " + Tbl("keys") + " pk WHERE pk.\"vcat\" = " + vcat_expr +
		       " AND pk.\"vname\" = " + vname_expr + " AND pk.\"kind\" = 'relation'" +
		       " AND lower(pk.\"column\") = lower(" + column_expr + "))";
	};
	string alias_vname = "CASE WHEN o.vschema = 'main' THEN o.vname ELSE o.vschema || '.' || o.vname END";
	string alias_nullable = "CASE WHEN c.\"nullable\" IS NOT NULL THEN"
	                        " CASE WHEN c.\"nullable\" THEN 'YES' ELSE 'NO' END WHEN " +
	                        pk_implies("o.vcat", alias_vname, "coalesce(c.\"name\", i.\"column_name\")") +
	                        " THEN 'NO' ELSE i.\"is_nullable\" END";
	string columns_sql =
	    string("SELECT i.* REPLACE (o.vcat AS table_catalog, o.vschema AS table_schema, o.vname AS table_name,"
	           " coalesce(c.\"name\", i.\"column_name\") AS column_name, ") +
	    alias_nullable +
	    string(" AS is_nullable)"
	           " FROM objects o JOIN information_schema.columns i ON ") +
	    physical + projection +
	    " AND c.\"expr\" = i.\"column_name\""
	    " WHERE len(o.parts) = 3 AND o.form = 'alias'"
	    " AND (c.\"name\" IS NOT NULL OR NOT EXISTS"
	    " (SELECT 1 FROM " +
	    Tbl("relation_columns") +
	    " c2 WHERE c2.\"vcat\" = o.vcat AND c2.\"vname\" = CASE WHEN o.vschema = 'main' THEN o.vname"
	    " ELSE o.vschema || '.' || o.vname END))"
	    " UNION ALL BY NAME"
	    " SELECT o.vcat AS table_catalog, o.vschema AS table_schema, o.vname AS table_name,"
	    " oc.\"name\" AS column_name, oc.\"pos\" + 1 AS ordinal_position, oc.\"type\" AS data_type," +
	    string(" CASE WHEN oc.\"nullable\" IS NOT NULL THEN CASE WHEN oc.\"nullable\" THEN 'YES'"
	           " ELSE 'NO' END WHEN ") +
	    pk_implies("o.vcat", alias_vname, "oc.\"name\"") +
	    " THEN 'NO' ELSE NULL END AS is_nullable,"
	    // `COLUMN_COMMENT` is what information_schema.columns calls it; a `comment` of our own
	    // added a 46th column to a surface whose shape is fixed (spec 035)
	    " oc.\"comment\" AS \"COLUMN_COMMENT\" FROM objects o JOIN " +
	    Tbl("object_columns") +
	    " oc ON oc.\"vcat\" = o.vcat AND oc.\"kind\" = 'relation'"
	    " AND oc.\"vname\" = CASE WHEN o.vschema = 'main' THEN o.vname"
	    " ELSE o.vschema || '.' || o.vname END WHERE o.form <> 'alias'"
	    " UNION ALL BY NAME"
	    " SELECT i.* REPLACE (a.vcat AS table_catalog, a.path AS table_schema)"
	    " FROM aliases a JOIN information_schema.columns i"
	    " ON i.\"table_catalog\" = a.parts[1] AND i.\"table_schema\" = a.parts[2]"
	    " WHERE len(a.parts) = 2";
	// The names a grant states: split the list and take the part before '=' of a masked item. A
	// mask's expression may itself contain a comma, which splits into a fragment that matches no
	// column - harmless, since only the names on the left of '=' can ever match one.
	auto stated = [](const string &column_expr) {
		return "list_transform(str_split(" + column_expr +
		       ", ','), lambda y: lower(trim(CASE WHEN position('=' IN y) > 0"
		       " THEN regexp_extract(y, '^([^=]*)=', 1) ELSE y END)))";
	};
	auto keeps = [&](const string &column_expr, const string &name_expr) {
		return "(" + column_expr + " IS NULL OR trim(" + column_expr + ") = '' OR list_contains(" +
		       stated(column_expr) + ", lower(" + name_expr + ")))";
	};
	// Visible for at least one role: a principal may read what any of its roles may (spec 011). A
	// row with no grant row at all is not an object of the catalog - it is a column of a live
	// schema alias, whose visibility is the schema's, decided in `aliases` - so it is left alone.
	auto column_visible = [&](const string &vcat_expr, const string &vname_expr, const string &name_expr) {
		string key = "gc.vcat = " + vcat_expr + " AND gc.vname = " + vname_expr;
		return "(NOT EXISTS (SELECT 1 FROM gcolumns gc WHERE " + key + ")" +
		       " OR EXISTS (SELECT 1 FROM gcolumns gc"
		       " WHERE " +
		       key + " AND " + keeps("gc.cat_columns", name_expr) + " AND " + keeps("gc.obj_columns", name_expr) + "))";
	};
	auto path = [](const string &alias) {
		return "CASE WHEN " + alias + ".vschema = 'main' THEN " + alias + ".vname ELSE " + alias +
		       ".vschema || '.' || " + alias + ".vname END";
	};
	string listed_path = "CASE WHEN l.table_schema = 'main' THEN l.table_name"
	                     " ELSE l.table_schema || '.' || l.table_name END";
	// A grant's own projection wins over the object's row for the names it defines - it is what the
	// role actually reads - and adds the ones the object never had (spec 026).
	string effective_columns =
	    "SELECT * FROM (" + columns_sql + ") l WHERE " +
	    column_visible("l.table_catalog", listed_path, "l.column_name") +
	    " AND NOT EXISTS (SELECT 1 FROM gprojection gp WHERE gp.vcat = l.table_catalog AND gp.vname = " + listed_path +
	    " AND gp.name = l.column_name)" +
	    " UNION ALL BY NAME"
	    " SELECT gp.vcat AS table_catalog,"
	    " CASE WHEN position('.' IN gp.vname) > 0 THEN regexp_extract(gp.vname, '^(.*)[.][^.]*$', 1)"
	    " ELSE 'main' END AS table_schema,"
	    " regexp_extract(gp.vname, '([^.]*)$', 1) AS table_name,"
	    " gp.name AS column_name, gp.pos + 1 AS ordinal_position, gp.type AS data_type"
	    " FROM gprojection gp WHERE EXISTS (SELECT 1 FROM objects o WHERE o.vcat = gp.vcat AND " +
	    path("o") + " = gp.vname)";
	if (surface == "columns") {
		return prelude + effective_columns;
	}
	if (surface == "duckdb_columns") {
		// the same rows as information_schema.columns, in duckdb's own shape. `is_nullable` and
		// `is_generated` are booleans there and strings here, and a synthesized row (a mask, a
		// computed column) has neither - duckdb always answers, so a default is closer than a NULL.
		return prelude + "SELECT c.table_catalog AS database_name, " + database_oid("c.table_catalog") +
		       " AS database_oid, c.table_schema AS schema_name, " + schema_oid("c.table_catalog", "c.table_schema") +
		       " AS schema_oid, c.table_name AS table_name, " +
		       object_oid("table", "c.table_catalog", "c.table_schema", "c.table_name") + " AS table_oid," +
		       " c.column_name AS column_name, c.ordinal_position::INTEGER AS column_index," +
		       " c.\"COLUMN_COMMENT\" AS comment, false AS internal," + " c.column_default AS column_default," +
		       " coalesce(c.is_nullable = 'YES', true) AS is_nullable," +
		       " c.data_type AS data_type, NULL::BIGINT AS data_type_id," +
		       " c.character_maximum_length::INTEGER AS character_maximum_length," +
		       " c.numeric_precision::INTEGER AS numeric_precision," +
		       " c.numeric_precision_radix::INTEGER AS numeric_precision_radix," +
		       " c.numeric_scale::INTEGER AS numeric_scale, " + empty_map +
		       " AS tags, coalesce(c.is_generated = 'YES', false) AS is_generated," +
		       " c.generation_expression AS generation_expression FROM (" + effective_columns + ") c";
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
		string ddl = "(SELECT 'CREATE TABLE ' || " + quoted("t.table_name") + " || '(' || string_agg(" +
		             quoted("c.column_name") + " || ' ' || c.data_type, ', ' ORDER BY c.ordinal_position)" +
		             " || ');'" + of_this_table + ")";
		string head = string("SELECT t.table_catalog AS database_name, ") + database_oid("t.table_catalog") +
		              " AS database_oid, t.table_schema AS schema_name, " +
		              schema_oid("t.table_catalog", "t.table_schema") + " AS schema_oid, t.table_name AS " +
		              (views ? "view_name" : "table_name") + ", " +
		              object_oid("table", "t.table_catalog", "t.table_schema", "t.table_name") + " AS " +
		              (views ? "view_oid" : "table_oid") + ", t.\"TABLE_COMMENT\" AS comment, " + empty_map +
		              " AS tags, false AS internal, false AS temporary, ";
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
		                 key_col_path + " = k2.\"vname\" AND lower(vc.column_name) = lower(k2.\"column\"))))";
		string tail = views ? column_count + ", NULL::VARCHAR AS sql, true AS is_bound"
		                    : has_key + " AS has_primary_key, NULL::BIGINT AS estimated_size, " + column_count +
		                          ", NULL::BIGINT AS index_count, NULL::BIGINT AS check_constraint_count, " + ddl +
		                          " AS sql";
		// spec 065: an object with no visible column has no DDL to synthesize - a NULL `sql` broke
		// a quack client on the whole catalog, so the row is not listed at all (catalog facts only:
		// vcolumns is the same fold every other answer here uses)
		// the filter is the tables branch's own: only there is `sql` synthesized from the columns,
		// and a view whose shape was never probed must stay listed (its read still answers)
		return prelude + ", vcolumns AS (" + effective_columns + ") " + head + tail + " FROM (" + tables_sql +
		       ") t WHERE t.table_type " + (views ? "=" : "<>") + " 'VIEW'" +
		       (views ? string() : " AND EXISTS (SELECT 1" + of_this_table + ")");
	}
	if (surface == "show_tables_expanded") {
		// `SHOW ALL TABLES`: every table of every catalog the principal holds, with the columns it
		// reads - the same fold duckdb does over duckdb_tables + duckdb_columns
		return prelude + ", vcolumns AS (" + effective_columns +
		       ") SELECT c.table_catalog AS database, c.table_schema AS schema, c.table_name AS name,"
		       " list(c.column_name ORDER BY c.ordinal_position) AS column_names,"
		       " list(c.data_type ORDER BY c.ordinal_position) AS column_types, false AS temporary"
		       " FROM vcolumns c GROUP BY ALL ORDER BY ALL";
	}
	// spec 048: the declared keys a principal may see - the object visible, and every column the
	// key names visible (a listed key over a hidden column describes what the role cannot read).
	// A grant's columns list narrows a table function's result exactly as it narrows a relation
	// (spec 011), so a function's key hides with any key column the narrowing takes away.
	if (surface == "keys") {
		string kcolumn_path = "CASE WHEN vc.table_schema = 'main' THEN vc.table_name"
		                      " ELSE vc.table_schema || '.' || vc.table_name END";
		string gfcolumns = "gfcolumns AS (SELECT DISTINCT f.\"vcat\" AS vcat, f.\"vname\" AS vname,"
		                   " g.\"columns\" AS cat_columns, " +
		                   string(HasObjectCaps() ? "oc.\"columns\"" : "NULL") + " AS obj_columns FROM " +
		                   Tbl("functions") + " f JOIN grants g ON g.\"vcat\" = f.\"vcat\"" +
		                   (HasObjectCaps() ? " LEFT JOIN " + Tbl("role_object_caps") +
		                                          " oc ON oc.\"role\" = g.\"role\" AND oc.\"vcat\" = f.\"vcat\""
		                                          " AND oc.\"vname\" = f.\"vname\""
		                                    : string()) +
		                   " WHERE f.\"kind\" = 'table' AND " + FunctionVisibleExpr() + ")";
		string fkey = "gf.vcat = k.\"vcat\" AND gf.vname = k.\"vname\"";
		string fcolumn_visible = "(NOT EXISTS (SELECT 1 FROM gfcolumns gf WHERE " + fkey +
		                         ") OR EXISTS (SELECT 1 FROM gfcolumns gf WHERE " + fkey + " AND " +
		                         keeps("gf.cat_columns", "k2.\"column\"") + " AND " +
		                         keeps("gf.obj_columns", "k2.\"column\"") + "))";
		return prelude + ", vcolumns AS (" + effective_columns + "), " + gfcolumns +
		       " SELECT k.\"vcat\" AS vcat, k.\"vname\" AS object, k.\"kind\" AS kind,"
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
		       fcolumn_visible + " ELSE EXISTS (SELECT 1 FROM vcolumns vc WHERE vc.table_catalog = k.\"vcat\" AND " +
		       kcolumn_path +
		       " = k2.\"vname\" AND lower(vc.column_name) = lower(k2.\"column\")) END)"
		       " ORDER BY vcat, object, key_sequence";
	}
	// spec 022: a reference is visible when both of its ends are, and when every column it names is
	// a column the role can see. Anything else would describe an object - or a column - the role
	// has no access to, which is what a listing must never do.
	string column_path = "CASE WHEN vc.table_schema = 'main' THEN vc.table_name"
	                     " ELSE vc.table_schema || '.' || vc.table_name END";
	return prelude + ", vcolumns AS (" + effective_columns + ") " +
	       "SELECT r.\"vcat\" AS vcat, r.\"name\" AS name, r.\"from_vname\" AS from_object,"
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
	       " r.\"to_kind\" AS to_kind, r.\"expr\" AS expression, r.\"cardinality\" AS cardinality,"
	       " r.\"optional\" AS optional, r.\"join_method\" AS join_method, r.\"comment\" AS comment FROM " +
	       Tbl("references") + " r WHERE EXISTS (SELECT 1 FROM objects o WHERE o.vcat = r.\"vcat\" AND " + path("o") +
	       " = r.\"from_vname\")" +
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
	       " AND vc.column_name = rc.\"column\"))";
}

} // namespace acl_detail

using acl_detail::CatalogBackend;
using acl_detail::Lit;

IntrospectionRows PolicyStore::Introspect(const string &listing) {
	// what an operator may read of the policy source itself. The issuer's keys are deliberately absent:
	// a listing describes the policy, and an HS256 key is a shared secret, not metadata.
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
	    {"issuers", "SELECT \"issuer\", \"audiences\", \"algs\", \"role_claim\", \"claim_map\", \"jwks_uri\","
	                " \"client_id\" FROM %s"},
	    {"role_mappings", "SELECT \"issuer\", \"source\", \"external_value\", \"role\" FROM %s"},
	    {"function_gate", "SELECT \"role\", \"name\", \"kind\", \"allowed\" FROM %s"},
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
	    {"role_mappings", "role_mappings"},
	    {"function_gate", "function_gate"},
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
	for (auto &name : result->GetNames()) {
		out.names.push_back(name.GetIdentifierName());
	}
	out.types = result->GetTypes();
	for (idx_t row = 0; row < result->RowCount(); row++) {
		vector<Value> values;
		for (idx_t col = 0; col < result->ColumnCount(); col++) {
			values.push_back(result->GetValue(col, row));
		}
		out.rows.push_back(std::move(values));
	}
	return out;
}

bool PolicyStore::MetadataListing(const Principal &principal, const string &surface, string &sql) {
	if (!catalog) {
		return false; // the memory store has no catalog to list; the surface stays denied
	}
	sql = catalog->MetadataListingSql(principal, surface);
	return true;
}

} // namespace acl
} // namespace duckdb
