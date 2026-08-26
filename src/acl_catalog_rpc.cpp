#include "acl_catalog_rpc.hpp"

#include "duckdb/common/string_util.hpp"

namespace duckdb {
namespace acl {

namespace {

//! `$1`, `$2`, ... - the door's own placeholders, numbered as they are appended.
string Bind(CatalogQuery &query, Value value) {
	query.parameters.push_back(std::move(value));
	return "$" + std::to_string(query.parameters.size());
}

//! The virtual path of an object as the listings spell it: bare in `main`, `schema.name` elsewhere.
//! Composed in SQL rather than in C++ so it is built from the listing's own columns.
//!
//! This is the store's own spelling, not a convention of the door's: a relation's key *is* this path
//! (`relations.vname`, and `from_vname`/`to_vname` on a reference), and `acl_policy_catalog.cpp`
//! spells the same CASE in its `path()` helpers. Which is also why the obvious collision - a table
//! named "foo.bar" in main against a table `bar` in schema `foo` - cannot arise: both would be the
//! key `foo.bar`, and the store holds one row for it (checked, not assumed). If the store's spelling
//! ever changes, this must change with it, or every key answer becomes silently empty.
string PathExpr(const string &schema_column, const string &name_column) {
	return "CASE WHEN " + schema_column + " = 'main' THEN " + name_column + " ELSE " + schema_column + " || '.' || " +
	       name_column + " END";
}

void AppendCatalogFilter(CatalogQuery &query, vector<string> &conditions, const CatalogFilter &filter,
                         const string &catalog_column) {
	if (filter.has_catalog) {
		conditions.push_back(catalog_column + " = " + Bind(query, Value(filter.catalog)));
	}
}

//! The tables listing reduced to (catalog, schema, name, path), which is what a reference's ends are
//! matched against. Splitting `schema.name` back apart with `split_part` would be wrong for a name
//! that contains a dot; joining against the listing recovers both halves exactly, and drops an end
//! that is not a table this role sees.
string TablePathsCte() {
	return "acl_table_paths AS (SELECT table_catalog, table_schema, table_name, " +
	       PathExpr("table_schema", "table_name") + " AS path FROM information_schema.tables)";
}

void AppendTableRef(CatalogQuery &query, vector<string> &conditions, const CatalogTableRef &table,
                    const string &alias) {
	if (table.has_catalog) {
		// the catalog of a reference is the row's own `vcat` - `alias` is a VARCHAR path column, and
		// `<path>.vcat` binds as a struct extraction and fails. Found by review: JDBC/ADBC clients
		// pass the catalog routinely, and neither test did.
		conditions.push_back("r.vcat = " + Bind(query, Value(table.catalog)));
	}
	auto schema = table.schema.empty() ? string("main") : table.schema;
	auto path = schema == "main" ? table.table : schema + "." + table.table;
	conditions.push_back(alias + " = " + Bind(query, Value(path)));
}

string Where(const vector<string> &conditions) {
	if (conditions.empty()) {
		return "";
	}
	return " WHERE " + StringUtil::Join(conditions, " AND ");
}

} // namespace

CatalogQuery BuildCatalogListing(CatalogListing listing, const CatalogFilter &filter) {
	CatalogQuery query;
	vector<string> conditions;

	switch (listing) {
	case CatalogListing::CATALOGS:
		// One column, and the protocol wants it non-null - which it is, since a schema always has a
		// catalog. No filters: `GetCatalogs` carries none.
		query.sql = "SELECT DISTINCT catalog_name FROM information_schema.schemata ORDER BY 1";
		return query;

	case CatalogListing::TABLE_TYPES:
		// Derived from the listing rather than answered with the constants: the protocol says the
		// values a client may pass to `GetTables(table_types=...)` are the ones this returned, so the
		// two have to come from the same rows or a client can filter itself into an empty answer.
		query.sql = "SELECT DISTINCT table_type FROM information_schema.tables ORDER BY 1";
		return query;

	case CatalogListing::DB_SCHEMAS:
		AppendCatalogFilter(query, conditions, filter, "catalog_name");
		if (filter.has_db_schema_pattern) {
			conditions.push_back("schema_name LIKE " + Bind(query, Value(filter.db_schema_pattern)));
		}
		query.sql = "SELECT catalog_name, schema_name AS db_schema_name FROM information_schema.schemata" +
		            Where(conditions) + " ORDER BY 1, 2";
		return query;

	case CatalogListing::TABLES:
		AppendCatalogFilter(query, conditions, filter, "table_catalog");
		if (filter.has_db_schema_pattern) {
			conditions.push_back("table_schema LIKE " + Bind(query, Value(filter.db_schema_pattern)));
		}
		if (filter.has_table_pattern) {
			conditions.push_back("table_name LIKE " + Bind(query, Value(filter.table_pattern)));
		}
		if (!filter.table_types.empty()) {
			vector<string> placeholders;
			for (auto &type : filter.table_types) {
				placeholders.push_back(Bind(query, Value(type)));
			}
			conditions.push_back("table_type IN (" + StringUtil::Join(placeholders, ", ") + ")");
		}
		query.sql = "SELECT table_catalog AS catalog_name, table_schema AS db_schema_name, table_name, table_type"
		            " FROM information_schema.tables" +
		            Where(conditions) + " ORDER BY 1, 2, 3";
		return query;

	case CatalogListing::COLUMNS:
		// What `include_schema` is built from: every column of every table the same filters select, in
		// one statement. The `table_types` filter is deliberately *not* applied - this listing has no
		// `table_type`, and a superset is harmless because the rows are matched back to the tables
		// listing by (catalog, schema, name).
		AppendCatalogFilter(query, conditions, filter, "table_catalog");
		if (filter.has_db_schema_pattern) {
			conditions.push_back("table_schema LIKE " + Bind(query, Value(filter.db_schema_pattern)));
		}
		if (filter.has_table_pattern) {
			conditions.push_back("table_name LIKE " + Bind(query, Value(filter.table_pattern)));
		}
		query.sql = "SELECT table_catalog, table_schema, table_name, column_name, data_type"
		            " FROM information_schema.columns" +
		            Where(conditions) + " ORDER BY 1, 2, 3, ordinal_position";
		return query;
	}
	throw InternalException("acl: unknown catalog listing");
}

CatalogQuery BuildKeyListing(KeyListing listing, const CatalogTableRef &table, const CatalogTableRef &second) {
	CatalogQuery query;
	vector<string> conditions;

	// Spec 022 already decides visibility: a reference is listed only when both ends and every column
	// it names are visible. What is filtered here is only what cannot be a *key*: a lateral call to a
	// table function is not a foreign key, and a reference declared with ON EXPRESSION has no column
	// pairs to number.
	conditions.push_back("r.to_kind <> 'function'");
	// A reference declared with ON EXPRESSION still *names* columns - spec 022 records them so their
	// visibility can be checked - so an empty column list is not what tells the two apart. The
	// expression is: where there is one, the relationship is not column equality and its columns
	// cannot be numbered into key pairs. Found by running the statement rather than reading it.
	conditions.push_back("r.expression IS NULL");
	conditions.push_back("r.from_column_list IS NOT NULL AND r.to_column_list IS NOT NULL");
	conditions.push_back("len(r.from_column_list) = len(r.to_column_list)");
	conditions.push_back("len(r.from_column_list) > 0");

	switch (listing) {
	case KeyListing::IMPORTED:
		AppendTableRef(query, conditions, table, "r.from_object");
		break;
	case KeyListing::EXPORTED:
		AppendTableRef(query, conditions, table, "r.to_object");
		break;
	case KeyListing::CROSS:
		AppendTableRef(query, conditions, table, "r.to_object");
		AppendTableRef(query, conditions, second, "r.from_object");
		break;
	}

	// One row per column pair, aligned by position: duckdb expands several `unnest`es in one select
	// list side by side, and `generate_subscripts` numbers them. `key_sequence` is 1-based, as the
	// protocol has it.
	query.sql = "WITH " + TablePathsCte() +
	            ", pairs AS (SELECT r.vcat, r.name, r.from_object, r.to_object,"
	            " unnest(r.from_column_list) AS fk_column, unnest(r.to_column_list) AS pk_column,"
	            " generate_subscripts(r.from_column_list, 1) AS key_sequence"
	            " FROM acl_references() r" +
	            Where(conditions) +
	            ")"
	            " SELECT pk.table_catalog AS pk_catalog_name, pk.table_schema AS pk_db_schema_name,"
	            " pk.table_name AS pk_table_name, pairs.pk_column AS pk_column_name,"
	            " fk.table_catalog AS fk_catalog_name, fk.table_schema AS fk_db_schema_name,"
	            " fk.table_name AS fk_table_name, pairs.fk_column AS fk_column_name,"
	            " pairs.key_sequence::INTEGER AS key_sequence,"
	            " pairs.name AS fk_key_name, pairs.name AS pk_key_name,"
	            // A reference is a declaration and enforces nothing, so "no action" (3) is the only
	            // honest answer for rules the protocol insists are non-null.
	            " 3::UTINYINT AS update_rule, 3::UTINYINT AS delete_rule"
	            " FROM pairs"
	            " JOIN acl_table_paths pk ON pk.table_catalog = pairs.vcat AND pk.path = pairs.to_object"
	            " JOIN acl_table_paths fk ON fk.table_catalog = pairs.vcat AND fk.path = pairs.from_object" +
	            // The proto fixes the ordering per listing, and they differ: exported keys group by the
	            // *referencing* table (a driver folds consecutive rows into per-table key sets), the
	            // other two by the referenced one. One ORDER BY for all three passed a one-reference
	            // test and was wrong for exported keys the moment a parent had two children.
	            (listing == KeyListing::EXPORTED
	                 ? string(" ORDER BY fk_catalog_name, fk_db_schema_name, fk_table_name, fk_key_name, key_sequence")
	                 : string(" ORDER BY pk_catalog_name, pk_db_schema_name, pk_table_name, pk_key_name,"
	                          " key_sequence"));
	return query;
}

} // namespace acl
} // namespace duckdb
