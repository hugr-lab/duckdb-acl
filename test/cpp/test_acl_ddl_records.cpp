// spec 151: the record a principal's DDL writes answers nothing. A CREATE / DROP / RENAME of a principal in a schema
// that records its objects is followed by the catalog record (`acl_register_created`, `acl_register_view`, ...), a
// `PRAGMA acl_…(…)` now: the client is answered `Success` with no row - never the record's arguments (the physical
// name, a view's rewritten body), which a `SELECT acl_…(…)` answered as its column's name.
// Names are what sqllogictest cannot see, so they are checked here. Build + run via `GEN=ninja make test-cpp`.

#include "acl_test_util.hpp"

using namespace duckdb;
using namespace acl_test;

namespace {

void Setup(Connection &con, const std::string &extension) {
	Exec(con, "LOAD '" + extension + "'");
	Exec(con, "ATTACH ':memory:' AS phys");
	Exec(con, "CREATE SCHEMA phys.lake");
	Exec(con, "CREATE TABLE phys.lake.orders(id INT, tenant VARCHAR, amount INT)");
	Exec(con, "INSERT INTO phys.lake.orders VALUES (1, 'acme', 100), (2, 'globex', 200)");
	Exec(con, "ATTACH ':memory:' AS aclcat");
	Exec(con, "SELECT acl_use_db('aclcat', 'acl', true)");
	Exec(con, "SET GLOBAL acl_allow_anonymous_admin=true");
	Exec(con, "ACL ADMIN CREATE VIRTUAL CATALOG sales");
	// an expansion: it shows only its own records, so every object a principal makes there gets one
	Exec(con, "ACL ADMIN CREATE VIRTUAL SCHEMA sales.vs FROM phys.lake");
	Exec(con, "ACL ADMIN CREATE ROLE wide CLAIMS (tenant = 'acme')");
	Exec(con, "ACL ADMIN GRANT CATALOG sales TO ROLE wide CAPS '{}' MAIN");
	Exec(con, "ACL ADMIN GRANT SCHEMA sales.vs TO ROLE wide WITH (select, create, drop)");
	Exec(con, "ACL ADMIN GRANT TABLE sales.vs.orders TO ROLE wide WITH (select) COLUMNS (id, amount) "
	          "RLS (tenant = acl_claim('tenant'))");
}

//! What a client is answered: `Success`, no rows, nothing of the record's arguments
bool AnswersNothing(QueryResult &result, const std::string &what) {
	if (!CheckOk(result, what)) {
		return false;
	}
	auto names = result.GetNames();
	bool ok = Check(names.size() == 1 && names[0].GetIdentifierName() == "Success",
	                what + ": the one column is Success, not the record's call (" +
	                    (names.empty() ? std::string("none") : names[0].GetIdentifierName()) + ")");
	return Check(result.RowCount() == 0, what + ": no row") && ok;
}

std::string One(Connection &con, const std::string &sql) {
	auto result = con.Query(sql);
	if (result->HasError()) {
		return "ERROR: " + result->GetError();
	}
	if (result->RowCount() == 0) {
		return "(none)";
	}
	return result->Collection().GetValue(0, 0).ToString();
}

} // namespace

int main(int argc, char *argv[]) {
	std::string extension = argc > 1 ? argv[1] : "build/release/extension/acl/acl.duckdb_extension";
	return RunMain("acl DDL records (spec 151)", [&]() {
		DBConfig config;
		config.SetOptionByName("allow_unsigned_extensions", Value::BOOLEAN(true));
		DuckDB db(nullptr, &config);
		Connection con(db);
		Setup(con, extension);
		const std::string wide = "ACL ROLE \"wide\" ";

		Scenario("every DDL a record follows answers Success and no row", [&]() {
			AnswersNothing(*con.Query(wide + "CREATE TABLE vs.t1(i INTEGER)"), "CREATE TABLE");
			AnswersNothing(*con.Query(wide + "CREATE TABLE vs.t2 AS SELECT 1 AS x"), "CREATE TABLE AS");
			AnswersNothing(*con.Query(wide + "CREATE VIEW vs.v1 AS SELECT id, amount FROM vs.orders"), "CREATE VIEW");
			AnswersNothing(*con.Query(wide + "ALTER TABLE vs.t2 RENAME TO t3"), "ALTER TABLE RENAME");
			AnswersNothing(*con.Query(wide + "ALTER VIEW vs.v1 RENAME TO v2"), "ALTER VIEW RENAME");
			AnswersNothing(*con.Query(wide + "DROP VIEW vs.v2"), "DROP VIEW");
			AnswersNothing(*con.Query(wide + "DROP TABLE vs.t3"), "DROP TABLE");
			AnswersNothing(*con.Query(wide + "DROP TABLE vs.t1"), "DROP TABLE");
			// ...and each record was written
			Check(One(con, wide + "SELECT string_agg(table_name, ',' ORDER BY table_name) FROM "
			                      "information_schema.tables") == "orders",
			      "made, renamed and dropped: only orders is left");
		});

		Scenario("a batch answers the DDL, then the query", [&]() {
			auto result = con.Query(wide + "CREATE TABLE vs.b1(i INTEGER); SELECT 42 AS answer");
			if (AnswersNothing(*result, "the CREATE of the batch") && Check(result->next != nullptr, "two results")) {
				Check(result->next->Collection().GetValue(0, 0).ToString() == "42", "...the second is the query's");
			}
			AnswersNothing(*con.Query(wide + "DROP TABLE vs.b1"), "cleanup");
		});

		Scenario("a prepared CREATE VIEW announces Success", [&]() {
			// the view is its record alone - one statement, which Flight prepares at GetFlightInfo
			auto view = con.Prepare(wide + "CREATE VIEW vs.pv AS SELECT id FROM vs.orders");
			if (CheckOk(*view, "a CREATE VIEW prepares")) {
				auto names = view->GetNames();
				Check(names.size() == 1 && names[0].GetIdentifierName() == "Success",
				      "its announced column is Success, not the view's rewritten body");
				AnswersNothing(*view->Execute(), "...and executes");
			}
			Check(One(con, wide + "SELECT count(*) FROM vs.pv") == "1", "the view reads the author's slice");
			AnswersNothing(*con.Query(wide + "DROP VIEW vs.pv"), "cleanup");
		});

		Scenario("a principal cannot run a record itself", [&]() {
			auto refused = One(con, wide + "PRAGMA acl_register_created('sales', 'vs.orders', 'phys.lake.orders')");
			Check(refused.find("PRAGMA \"acl_register_created\" is not permitted under ACL") != std::string::npos,
			      "a principal's PRAGMA is one of the two answered names: " + refused);
		});
	});
}
