// spec 151: the record a principal's DDL writes answers nothing. A CREATE / DROP / RENAME of a principal in a schema
// that records its objects is followed by the catalog record (`acl_register_created`, `acl_register_view`, ...); it
// was a `SELECT acl_…(…)`, answered to the client with its call as its column's name - the physical name, and for a
// view the whole rewritten body (the physical relation, the author's RLS and column list). Now it is a
// `PRAGMA acl_…(…)` run in one query with the DDL: the answer is `Success` with no rows, a prepared one works (it
// was "Cannot prepare multiple statements"), and a record that fails takes its CREATE back.
// Names are what sqllogictest cannot see, so they are checked here. Build + run via `GEN=ninja make test-cpp`.

#include "acl_test_util.hpp"

#include <cstdlib>
#include <unistd.h>

using namespace duckdb;
using namespace acl_test;

namespace {

void Setup(Connection &con, const std::string &extension, const std::string &store) {
	Exec(con, "LOAD '" + extension + "'");
	Exec(con, "ATTACH ':memory:' AS phys");
	Exec(con, "CREATE SCHEMA phys.lake");
	Exec(con, "CREATE TABLE phys.lake.orders(id INT, tenant VARCHAR, amount INT)");
	Exec(con, "INSERT INTO phys.lake.orders VALUES (1, 'acme', 100), (2, 'globex', 200)");
	Exec(con, "ATTACH '" + store + "' AS aclcat");
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
		Setup(con, extension, ":memory:");
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

		Scenario("a prepared DDL works and answers the same", [&]() {
			// the record made a CREATE TABLE two statements: "Cannot prepare multiple statements at once!"
			auto made = con.Prepare(wide + "CREATE TABLE vs.p1 AS SELECT 7 AS x");
			if (CheckOk(*made, "a CREATE TABLE AS prepares")) {
				AnswersNothing(*made->Execute(), "...and executes");
			}
			Check(One(con, wide + "SELECT x FROM vs.p1") == "7", "the prepared CREATE made the table");
			auto view = con.Prepare(wide + "CREATE VIEW vs.pv AS SELECT id FROM vs.orders");
			if (CheckOk(*view, "a CREATE VIEW prepares")) {
				auto names = view->GetNames();
				Check(names.size() == 1 && names[0].GetIdentifierName() == "Success",
				      "its announced column is Success - the view's rewritten body was its name");
				AnswersNothing(*view->Execute(), "...and executes");
			}
			Check(One(con, wide + "SELECT count(*) FROM vs.pv") == "1", "the view reads the author's slice");
			AnswersNothing(*con.Query(wide + "DROP VIEW vs.pv"), "cleanup");
			AnswersNothing(*con.Query(wide + "DROP TABLE vs.p1"), "cleanup");
		});

		Scenario("a principal cannot run a record itself", [&]() {
			auto refused = One(con, wide + "PRAGMA acl_register_created('sales', 'vs.orders', 'phys.lake.orders')");
			Check(refused.find("PRAGMA \"acl_register_created\" is not permitted under ACL") != std::string::npos,
			      "a principal's PRAGMA is one of the two answered names: " + refused);
		});

		Scenario("a record that fails takes its CREATE back", [&]() {
			// a policy store attached read-only: the CREATE runs, its record cannot be written. Before spec 151
			// the CREATE had committed on its own - a table no listing showed
			char directory[] = "/tmp/acl-ddl-records-XXXXXX";
			if (!Check(mkdtemp(directory) != nullptr, "a directory of the test's own")) {
				return;
			}
			auto store = std::string(directory) + "/store.db";
			{
				DuckDB file_db(nullptr, &config);
				Connection writer(file_db);
				Setup(writer, extension, store);
			}
			DuckDB again(nullptr, &config);
			Connection reader(again);
			Exec(reader, "LOAD '" + extension + "'");
			Exec(reader, "ATTACH ':memory:' AS phys");
			Exec(reader, "CREATE SCHEMA phys.lake");
			Exec(reader, "CREATE TABLE phys.lake.orders(id INT, tenant VARCHAR, amount INT)");
			Exec(reader, "ATTACH '" + store + "' AS aclcat (READ_ONLY)");
			Exec(reader, "SELECT acl_use_db('aclcat', 'acl')");
			auto failed = reader.Query(wide + "CREATE TABLE vs.lost AS SELECT 1 AS x");
			Check(failed->HasError() && failed->GetError().find("read-only") != std::string::npos,
			      "the record is refused: " + (failed->HasError() ? failed->GetError() : std::string("no error")));
			Check(One(reader, "SELECT count(*) FROM duckdb_tables() WHERE database_name = 'phys' AND "
			                  "table_name = 'lost'") == "0",
			      "...and the CREATE with it: phys.lake.lost was never left behind");
			unlink(store.c_str());
			unlink((store + ".wal").c_str());
			rmdir(directory);
		});
	});
}
