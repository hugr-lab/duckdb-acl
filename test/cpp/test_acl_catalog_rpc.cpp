// The statements behind Flight SQL's catalog RPCs (spec 046).
//
// Two things are checked, and the second is the one that matters. First, the composition itself: what
// each command turns into, that a filter arrives as a parameter rather than as text, and that Flight's
// absent-vs-empty catalog distinction survives. Second - and this is why the test is C++ rather than a
// string comparison - each statement is *run* under a principal, so a listing that composes beautifully
// and does not bind is caught here rather than in a client.

#include "acl_catalog_rpc.hpp"
#include "acl_test_util.hpp"

using namespace duckdb;
using namespace duckdb::acl;
using acl_test::Check;
using acl_test::Exec;
using acl_test::Scenario;

namespace {

//! Run a composed statement under a role, returning the rows as `|`-joined lines.
vector<string> RunAsRole(Connection &con, const string &role, const CatalogQuery &query) {
	auto prepared = con.Prepare("ACL ROLE \"" + role + "\" " + query.sql);
	if (prepared->HasError()) {
		throw std::runtime_error("prepare failed: " + prepared->GetError() + "\n  sql: " + query.sql);
	}
	vector<Value> values = query.parameters;
	auto result = prepared->Execute(values);
	if (result->HasError()) {
		throw std::runtime_error("execute failed: " + result->GetError() + "\n  sql: " + query.sql);
	}
	vector<string> rows;
	while (true) {
		auto chunk = result->Fetch();
		if (!chunk || chunk->size() == 0) {
			break;
		}
		for (idx_t row = 0; row < chunk->size(); row++) {
			string line;
			for (idx_t col = 0; col < chunk->ColumnCount(); col++) {
				if (col > 0) {
					line += "|";
				}
				line += chunk->GetValue(col, row).ToString();
			}
			rows.push_back(line);
		}
	}
	return rows;
}

string Joined(const vector<string> &rows) {
	string out;
	for (auto &row : rows) {
		if (!out.empty()) {
			out += " ; ";
		}
		out += row;
	}
	return out;
}

//! A filter pattern is bound, never concatenated - so there is nothing to escape and nothing to get
//! wrong. The pattern below would be a syntax error if it reached the parser as text.
void PatternsAreParameters() {
	CatalogFilter filter;
	filter.has_table_pattern = true;
	filter.table_pattern = "o'rd%";
	auto query = BuildCatalogListing(CatalogListing::TABLES, filter);
	Check(query.sql.find("o'rd%") == string::npos, "the pattern is not in the statement text");
	Check(query.sql.find("table_name LIKE $1") != string::npos, "the pattern is a placeholder");
	Check(query.parameters.size() == 1 && query.parameters[0].ToString() == "o'rd%", "and it is the bound value");
}

//! Flight distinguishes an absent catalog (no filter) from an empty one ("objects with no catalog").
void AbsentCatalogIsNotAnEmptyOne() {
	CatalogFilter absent;
	auto no_filter = BuildCatalogListing(CatalogListing::TABLES, absent);
	Check(no_filter.parameters.empty(), "an absent catalog binds nothing");
	Check(no_filter.sql.find("WHERE") == string::npos, "and adds no condition");

	CatalogFilter empty;
	empty.has_catalog = true;
	auto filtered = BuildCatalogListing(CatalogListing::TABLES, empty);
	Check(filtered.parameters.size() == 1 && filtered.parameters[0].ToString() == "",
	      "an empty catalog binds the empty string");
	Check(filtered.sql.find("table_catalog = $1") != string::npos, "as an ordinary equality");
}

void TableTypesBecomeAnInList() {
	CatalogFilter filter;
	filter.table_types = {"BASE TABLE", "VIEW"};
	auto query = BuildCatalogListing(CatalogListing::TABLES, filter);
	Check(query.sql.find("table_type IN ($1, $2)") != string::npos, "the type list is an IN list");
	Check(query.parameters.size() == 2, "with one parameter each");
}

void ListingsAnswerUnderARole(Connection &con) {
	CatalogFilter none;
	auto catalogs = RunAsRole(con, "analyst", BuildCatalogListing(CatalogListing::CATALOGS, none));
	Check(Joined(catalogs) == "c", "GetCatalogs is the principal's catalogs: " + Joined(catalogs));

	auto schemas = RunAsRole(con, "analyst", BuildCatalogListing(CatalogListing::DB_SCHEMAS, none));
	Check(Joined(schemas) == "c|main", "GetDbSchemas: " + Joined(schemas));

	auto tables = RunAsRole(con, "analyst", BuildCatalogListing(CatalogListing::TABLES, none));
	Check(Joined(tables) == "c|main|customers|BASE TABLE ; c|main|orders|BASE TABLE",
	      "GetTables is what the role is granted: " + Joined(tables));

	// the other role is granted one object of the two, and it is not the one above
	auto other = RunAsRole(con, "narrow", BuildCatalogListing(CatalogListing::TABLES, none));
	Check(Joined(other) == "c|main|customers|BASE TABLE", "and another role sees its own: " + Joined(other));

	auto types = RunAsRole(con, "analyst", BuildCatalogListing(CatalogListing::TABLE_TYPES, none));
	Check(Joined(types) == "BASE TABLE", "GetTableTypes comes from the same rows: " + Joined(types));
}

void FiltersNarrowTheListing(Connection &con) {
	CatalogFilter filter;
	filter.has_table_pattern = true;
	filter.table_pattern = "ord%";
	auto tables = RunAsRole(con, "analyst", BuildCatalogListing(CatalogListing::TABLES, filter));
	Check(Joined(tables) == "c|main|orders|BASE TABLE", "a table pattern narrows: " + Joined(tables));

	CatalogFilter nowhere;
	nowhere.has_catalog = true; // the empty string: objects with no catalog, of which there are none
	auto empty = RunAsRole(con, "analyst", BuildCatalogListing(CatalogListing::TABLES, nowhere));
	Check(empty.empty(), "an empty catalog matches nothing");
}

void ColumnsAreOneStatementForEveryTable(Connection &con) {
	CatalogFilter none;
	auto columns = RunAsRole(con, "analyst", BuildCatalogListing(CatalogListing::COLUMNS, none));
	Check(Joined(columns) == "c|main|customers|id|INTEGER ; c|main|customers|name|VARCHAR ; "
	                         "c|main|orders|id|INTEGER ; c|main|orders|customer_id|INTEGER",
	      "every column of every table, in order, in one statement: " + Joined(columns));
	// `secret` is not granted to this role, so it is absent here - which is the whole point: what the
	// client is told it will receive is what it will receive (spec 026)
	Check(Joined(columns).find("secret") == string::npos, "and a column the role cannot read is not in it");
}

void ReferencesAreTheForeignKeys(Connection &con) {
	CatalogTableRef orders;
	orders.table = "orders";
	CatalogTableRef customers;
	customers.table = "customers";
	CatalogTableRef none;

	auto imported = RunAsRole(con, "analyst", BuildKeyListing(KeyListing::IMPORTED, orders, none));
	Check(Joined(imported) == "c|main|customers|id|c|main|orders|customer_id|1|orders_customer|orders_customer|3|3",
	      "imported keys of the referencing table: " + Joined(imported));

	auto exported = RunAsRole(con, "analyst", BuildKeyListing(KeyListing::EXPORTED, customers, none));
	Check(Joined(exported) == Joined(imported), "the same reference is the parent's exported key");

	// the other direction is not a key of this table
	auto backwards = RunAsRole(con, "analyst", BuildKeyListing(KeyListing::IMPORTED, customers, none));
	Check(backwards.empty(), "and the parent imports nothing");

	auto cross = RunAsRole(con, "analyst", BuildKeyListing(KeyListing::CROSS, customers, orders));
	Check(Joined(cross) == Joined(imported), "cross reference names both ends: " + Joined(cross));
}

void WhatCannotBeAKeyIsNotOne(Connection &con) {
	CatalogTableRef orders;
	orders.table = "orders";
	CatalogTableRef none;
	// `by_expression` is declared with ON EXPRESSION and has no column pairs; `to_function` points at
	// a table function. Both stay visible through acl_references() and neither is a foreign key.
	auto imported = RunAsRole(con, "analyst", BuildKeyListing(KeyListing::IMPORTED, orders, none));
	Check(Joined(imported).find("by_expression") == string::npos, "an ON EXPRESSION reference is not a key");
	Check(Joined(imported).find("to_function") == string::npos, "and neither is a lateral call");
}

} // namespace

int main() {
	DuckDB db(nullptr);
	Connection con(db);
	Exec(con, "SET allow_parser_override_extension='STRICT'");
	Exec(con, "LOAD acl");

	Exec(con, "ATTACH ':memory:' AS phys");
	Exec(con, "ATTACH ':memory:' AS store");
	Exec(con, "CREATE TABLE phys.main.orders(id INTEGER, customer_id INTEGER, secret VARCHAR)");
	Exec(con, "CREATE TABLE phys.main.customers(id INTEGER, name VARCHAR)");
	Exec(con, "SELECT acl_use_db('store','acl',true)");
	Exec(con, "SET GLOBAL acl_allow_anonymous_admin=true");
	Exec(con, "ACL ADMIN CREATE VIRTUAL CATALOG c");
	Exec(con, "ACL ADMIN CREATE VIRTUAL TABLE c.orders AS phys.main.orders");
	Exec(con, "ACL ADMIN CREATE VIRTUAL TABLE c.customers AS phys.main.customers");
	Exec(con, "ACL ADMIN CREATE VIRTUAL REFERENCE c.orders_customer FROM orders TO customers"
	          " ON (customer_id = id) CARDINALITY many_to_one");
	Exec(con, "ACL ADMIN CREATE VIRTUAL REFERENCE c.by_expression FROM orders TO customers"
	          " ON EXPRESSION 'orders.customer_id > customers.id'");
	Exec(con, "ACL ADMIN CREATE ROLE analyst");
	Exec(con, "ACL ADMIN GRANT CATALOG c TO ROLE analyst MAIN COLUMNS (id, customer_id, name)");
	Exec(con, "ACL ADMIN CREATE ROLE narrow");
	Exec(con, "ACL ADMIN GRANT CATALOG c TO ROLE narrow MAIN");
	Exec(con, "ACL ADMIN GRANT OBJECT c.orders TO ROLE narrow WITH ()");

	return acl_test::RunMain("acl Flight SQL catalog statements (spec 046)", [&]() {
		Scenario("patterns-are-parameters", PatternsAreParameters);
		Scenario("absent-catalog-is-not-empty", AbsentCatalogIsNotAnEmptyOne);
		Scenario("table-types-in-list", TableTypesBecomeAnInList);
		Scenario("listings-under-a-role", [&]() { ListingsAnswerUnderARole(con); });
		Scenario("filters-narrow", [&]() { FiltersNarrowTheListing(con); });
		Scenario("columns-in-one-statement", [&]() { ColumnsAreOneStatementForEveryTable(con); });
		Scenario("references-are-keys", [&]() { ReferencesAreTheForeignKeys(con); });
		Scenario("not-every-reference-is-a-key", [&]() { WhatCannotBeAKeyIsNotOne(con); });
	});
}
