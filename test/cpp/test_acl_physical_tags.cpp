// A principal's listings carry the physical catalog's tags (spec 143).
//
// duckdb keeps tags on every catalog entry and lists them, but no SQL statement of the release sets them - a source's
// extension does (DuckLake: a table's, never a column's). So the tagged table is created here through the catalog API,
// and what is checked is where its tags reach a principal: an alias relation's table and columns, a declared list's
// columns by the source column each reads, a live schema alias's schema and tables, a masked column (kept), a hidden
// one (absent), a virtual view (none) - and that information_schema keeps its shape.

#include "acl_test_util.hpp"
#include "duckdb/catalog/catalog.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/parser/parsed_data/create_schema_info.hpp"
#include "duckdb/parser/parsed_data/create_table_info.hpp"
#include "duckdb/transaction/meta_transaction.hpp"

using namespace duckdb;
using acl_test::Check;
using acl_test::Exec;
using acl_test::Scenario;

namespace {

//! The rows of a query as `|`-joined lines, joined by ` ; `
string Rows(Connection &con, const string &sql) {
	auto result = con.Query(sql);
	if (result->HasError()) {
		throw std::runtime_error("query failed: " + result->GetError() + "\n  sql: " + sql);
	}
	string out;
	while (true) {
		auto chunk = result->Fetch();
		if (!chunk || chunk->size() == 0) {
			break;
		}
		for (idx_t row = 0; row < chunk->size(); row++) {
			if (!out.empty()) {
				out += " ; ";
			}
			for (idx_t col = 0; col < chunk->ColumnCount(); col++) {
				out += (col > 0 ? "|" : "") + chunk->GetValue(col, row).ToString();
			}
		}
	}
	return out;
}

//! phys.sales.orders(id, amount, note) with a tag on the schema, on the table and on each column
void CreateTaggedTable(Connection &con) {
	con.context->RunFunctionInTransaction([&]() {
		auto &catalog = Catalog::GetCatalog(*con.context, "phys");
		MetaTransaction::Get(*con.context)
		    .ModifyDatabase(catalog.GetAttached(), DatabaseModificationType::CREATE_CATALOG_ENTRY);
		CreateSchemaInfo schema;
		schema.SetQualifiedName(QualifiedName(Identifier("phys"), Identifier("sales"), Identifier()));
		schema.tags["domain"] = "finance";
		catalog.CreateSchema(*con.context, schema);
		auto info = make_uniq<CreateTableInfo>(QualifiedName("phys", "sales", "orders"));
		info->tags["owner"] = "sales";
		auto add = [&](const char *name, const LogicalType &type, const char *key, const char *value) {
			ColumnDefinition column(name, type);
			InsertionOrderPreservingMap<string> tags;
			tags[key] = value;
			column.SetTags(std::move(tags));
			info->columns.AddColumn(std::move(column));
		};
		add("id", LogicalType::INTEGER, "key", "pk");
		add("amount", LogicalType::INTEGER, "pii", "no");
		add("note", LogicalType::VARCHAR, "pii", "yes");
		catalog.CreateTable(*con.context, std::move(info));
	});
}

string ColumnTags(Connection &con, const string &role, const string &table) {
	return Rows(con, "ACL ROLE \"" + role +
	                     "\" SELECT column_name, tags FROM duckdb_columns()"
	                     " WHERE schema_name = 'main' AND table_name = '" +
	                     table + "' ORDER BY column_index");
}

} // namespace

int main() {
	return acl_test::RunMain("test_acl_physical_tags", []() {
		DuckDB db(nullptr);
		Connection con(db);
		Exec(con, "SET allow_parser_override_extension='STRICT'");
		Exec(con, "LOAD acl");
		Exec(con, "ATTACH ':memory:' AS phys");
		Exec(con, "ATTACH ':memory:' AS store");
		CreateTaggedTable(con);
		Exec(con, "SELECT acl_use_db('store','acl',true)");
		Exec(con, "SET GLOBAL acl_allow_anonymous_admin=true");
		Exec(con, "ACL ADMIN CREATE VIRTUAL CATALOG c");
		Exec(con, "ACL ADMIN CREATE VIRTUAL TABLE c.orders AS phys.sales.orders");
		Exec(con, "ACL ADMIN CREATE VIRTUAL TABLE c.narrow AS phys.sales.orders"
		          " COLUMNS (id, paid = amount, doubled = amount * 2, \"note\")");
		Exec(con, "ACL ADMIN CREATE VIRTUAL VIEW c.recent AS SELECT id, amount FROM phys.sales.orders");
		Exec(con, "ACL ADMIN CREATE VIRTUAL SCHEMA c.raw AS phys.sales");
		Exec(con, "ACL ADMIN CREATE ROLE analyst");
		Exec(con, "ACL ADMIN GRANT CATALOG c TO ROLE analyst WITH (select) MAIN");
		Exec(con, "ACL ADMIN CREATE ROLE masked");
		Exec(con, "ACL ADMIN GRANT CATALOG c TO ROLE masked WITH (select) MAIN COLUMNS (id, amount = 0)");

		Scenario("the source's tags", [&]() {
			Check(Rows(con, "SELECT tags FROM duckdb_tables() WHERE database_name = 'phys'") == "{owner=sales}",
			      "the table carries its tag (the catalog API set it)");
			Check(
			    Rows(con, "SELECT tags FROM duckdb_schemas() WHERE database_name = 'phys' AND schema_name = 'sales'") ==
			        "{domain=finance}",
			    "and the schema its own");
		});
		Scenario("an alias relation", [&]() {
			auto table = Rows(con, "ACL ROLE \"analyst\" SELECT tags FROM duckdb_tables()"
			                       " WHERE schema_name = 'main' AND table_name = 'orders'");
			Check(table == "{owner=sales}", "its table's tags: " + table);
			auto columns = ColumnTags(con, "analyst", "orders");
			Check(columns == "id|{key=pk} ; amount|{pii=no} ; note|{pii=yes}", "its columns' tags: " + columns);
		});
		Scenario("a declared list", [&]() {
			auto table = Rows(con, "ACL ROLE \"analyst\" SELECT tags FROM duckdb_tables() WHERE table_name = 'narrow'");
			Check(table == "{owner=sales}", "the object's tags are its table's: " + table);
			auto columns = ColumnTags(con, "analyst", "narrow");
			Check(columns == "id|{key=pk} ; paid|{pii=no} ; doubled|{} ; note|{pii=yes}",
			      "each column the source column it reads by name, a computed one none: " + columns);
		});
		Scenario("a live schema alias", [&]() {
			auto schemas = Rows(con, "ACL ROLE \"analyst\" SELECT schema_name, tags FROM duckdb_schemas()"
			                         " ORDER BY schema_name");
			Check(schemas == "main|{} ; raw|{domain=finance}",
			      "the alias schema carries its schema's tags: " + schemas);
			auto table = Rows(con, "ACL ROLE \"analyst\" SELECT tags FROM duckdb_tables() WHERE schema_name = 'raw'");
			Check(table == "{owner=sales}", "its tables' tags: " + table);
			auto columns = Rows(con, "ACL ROLE \"analyst\" SELECT column_name, tags FROM duckdb_columns()"
			                         " WHERE schema_name = 'raw' ORDER BY column_index");
			Check(columns == "id|{key=pk} ; amount|{pii=no} ; note|{pii=yes}", "and their columns': " + columns);
		});
		Scenario("a grant's projection", [&]() {
			auto columns = ColumnTags(con, "masked", "orders");
			Check(columns == "id|{key=pk} ; amount|{pii=no}",
			      "a masked column keeps its tags, a hidden one is not listed: " + columns);
		});
		Scenario("a virtual view", [&]() {
			auto view = Rows(con, "ACL ROLE \"analyst\" SELECT tags FROM duckdb_views() WHERE view_name = 'recent'");
			Check(view == "{}", "carries none: " + view);
			auto columns = ColumnTags(con, "analyst", "recent");
			Check(columns == "id|{} ; amount|{}", "nor do its columns - nothing is derived from its query: " + columns);
		});
		Scenario("information_schema keeps its shape", [&]() {
			for (auto surface : {"columns", "tables"}) {
				auto own = con.Query(string("SELECT * FROM information_schema.") + surface + " LIMIT 0");
				auto principal =
				    con.Query(string("ACL ROLE \"analyst\" SELECT * FROM information_schema.") + surface + " LIMIT 0");
				if (!acl_test::CheckOk(*principal, string("information_schema.") + surface)) {
					continue;
				}
				Check(own->GetNames() == principal->GetNames(),
				      string("information_schema.") + surface + " has duckdb's columns, no tags column");
			}
		});
	});
}
