// spec 120.3: view-as - an administrator's session rewritten as another role, metadata only.
// `SET SESSION VIEW AS ROLE '<r>'` / `RESET SESSION VIEW AS` act on the session the statement runs under, so the
// path needs a minted session handle in the prefix - which no sqllogictest file can splice in.
// Build + run via `GEN=ninja make test-cpp`.

#include "acl_test_util.hpp"

using namespace duckdb;
using namespace acl_test;

namespace {

std::string OpenSession(Connection &con, const std::string &token) {
	auto result = con.Query("SELECT acl_session_open('" + token + "')");
	if (result->HasError() || result->RowCount() == 0 || result->Collection().GetValue(0, 0).IsNull()) {
		return std::string();
	}
	return result->Collection().GetValue(0, 0).ToString();
}

//! The rows a query answers, one value per row joined with ',', or "ERROR: …"
std::string Rows(Connection &con, const std::string &sql) {
	auto result = con.Query(sql);
	if (result->HasError()) {
		return "ERROR: " + result->GetError();
	}
	std::string out;
	for (idx_t row = 0; row < result->RowCount(); row++) {
		out += (row ? "," : "") + result->Collection().GetValue(0, row).ToString();
	}
	return out;
}

bool Contains(const std::string &text, const std::string &part) {
	return text.find(part) != std::string::npos;
}

bool MetadataOnly(const std::string &text) {
	return Contains(text, "ERROR") && Contains(text, "a view-as session reads metadata only");
}

} // namespace

int main(int argc, char *argv[]) {
	std::string extension = argc > 1 ? argv[1] : "build/release/extension/acl/acl.duckdb_extension";
	DBConfig config;
	config.SetOptionByName("allow_unsigned_extensions", Value::BOOLEAN(true));
	DuckDB db(nullptr, &config);
	Connection con(db);
	Exec(con, "LOAD '" + extension + "'");
	Exec(con, "ATTACH ':memory:' AS store");
	Exec(con, "ATTACH ':memory:' AS phys");
	Exec(con, "CREATE TABLE phys.main.orders AS SELECT 1 AS id, 'acme' AS tenant, 10 AS amount");
	Exec(con, "CREATE TABLE phys.main.hidden AS SELECT 2 AS id");
	Exec(con, "SELECT acl_use_db('store','acl',true)");
	Exec(con, "SET GLOBAL acl_allow_anonymous_admin=true");
	Exec(con, "ACL ADMIN CREATE VIRTUAL CATALOG c");
	Exec(con, "ACL ADMIN CREATE VIRTUAL TABLE c.orders AS phys.main.orders");
	Exec(con, "ACL ADMIN CREATE VIRTUAL TABLE c.hidden AS phys.main.hidden");
	Exec(con, "ACL ADMIN ADD SCALAR c.shout MACRO 'upper(acl_arg(1))'");
	Exec(con, "ACL ADMIN CREATE ROLE r");
	Exec(con, "ACL ADMIN GRANT CATALOG c TO ROLE r MAIN CAPS '{\"select\": true, \"insert\": true}'");
	Exec(con, "ACL ADMIN GRANT TABLE c.orders TO ROLE r COLUMNS (id, amount)");
	Exec(con, "ACL ADMIN GRANT TABLE c.hidden TO ROLE r CAPS '{}'");
	Exec(con, "ACL ADMIN CREATE ROLE pol");
	Exec(con, "ACL ADMIN GRANT ADMIN policy TO ROLE pol");
	Exec(con, "ACL ADMIN CREATE ROLE cadm");
	Exec(con, "ACL ADMIN GRANT CATALOG c TO ROLE cadm CAPS '{\"select\": true, \"manage\": true}' MAIN");
	Exec(con, "ACL ADMIN CREATE ROLE pt");
	Exec(con, "ACL ADMIN GRANT ADMIN passthrough TO ROLE pt");
	Exec(con, "ACL ADMIN CREATE ROLE pol2");
	Exec(con, "ACL ADMIN GRANT ADMIN policy TO ROLE pol2");
	// a virtual table function named like a metadata surface (only duckdb_* names are reserved)
	Exec(con, "ACL ADMIN CREATE VIRTUAL TABLE FUNCTION c.acl_references AS 'SELECT id FROM phys.main.orders'");
	// a physical scalar macro granted to r: its body reads a table r cannot even see
	Exec(con, "CREATE MACRO phys.main.peek() AS (SELECT max(id) FROM phys.main.hidden)");
	Exec(con, "SELECT acl_grant_function('r', 'phys.main.peek')");
	Exec(con, "SELECT acl_define_token('pttok', 'pt', '')");
	Exec(con, "SELECT acl_define_token('pol2tok', 'pol2', '')");
	Exec(con, "SELECT acl_define_token('poltok', 'pol', '')");
	Exec(con, "SELECT acl_define_token('rtok', 'r', '')");
	Exec(con, "SELECT acl_define_token('cadmtok', 'cadm', '')");

	auto handle = OpenSession(con, "poltok");
	auto other = OpenSession(con, "poltok");
	auto plain = OpenSession(con, "rtok");
	auto catalog_admin = OpenSession(con, "cadmtok");
	if (!Check(!handle.empty() && !other.empty() && !plain.empty() && !catalog_admin.empty(), "the sessions open")) {
		return 1;
	}
	auto session = "ACL SESSION '" + handle + "' ";

	Scenario("before: the administrator's own view", [&]() {
		Check(Rows(con, session + "SELECT count(*) FROM platform.roles") != "0", "platform.roles reads");
		Check(Contains(Rows(con, session + "SELECT id FROM c.orders"), "ERROR"), "pol holds no data grant");
	});

	Scenario("SET SESSION VIEW AS ROLE: the listings answer what r sees", [&]() {
		CheckOk(*con.Query(session + "SET SESSION VIEW AS ROLE 'r'"), "SET SESSION VIEW AS ROLE 'r'");
		Check(Rows(con, session + "SELECT table_name FROM information_schema.tables ORDER BY 1") == "orders",
		      "information_schema.tables is r's: the hidden object is not there");
		Check(Rows(con, session + "SELECT column_name FROM information_schema.columns WHERE table_name = 'orders' "
		                          "ORDER BY ordinal_position") == "id,amount",
		      "...and its columns are r's: tenant is not granted");
		Check(Rows(con, session + "SELECT column_name FROM (DESCRIBE c.orders)") == "id,amount",
		      "DESCRIBE describes what r reads");
		Check(Rows(con, session + "SELECT name FROM (SHOW TABLES)") == "orders", "SHOW TABLES is r's");
		Check(Rows(con, session + "SELECT current_database()") == "c", "current_database() is r's MAIN");
		Check(Rows(con, session + "SELECT 1 + 1") == "2", "a statement reading no object runs");
	});

	Scenario("in view-as every read of rows, write and DDL is refused", [&]() {
		Check(MetadataOnly(Rows(con, session + "SELECT id FROM c.orders")), "a read of c.orders");
		Check(MetadataOnly(Rows(con, session + "SELECT id FROM orders")), "...by its bare name");
		Check(MetadataOnly(Rows(con, session + "SELECT table_name FROM information_schema.tables WHERE "
		                                       "table_name IN (SELECT 'orders' FROM c.orders)")),
		      "a read inside a listing's WHERE");
		Check(MetadataOnly(Rows(con, session + "INSERT INTO c.orders (id, amount) VALUES (3, 3)")), "an INSERT");
		Check(MetadataOnly(Rows(con, session + "CREATE TABLE c.t (x INTEGER)")), "a CREATE");
		Check(MetadataOnly(Rows(con, session + "SUMMARIZE c.orders")), "SUMMARIZE reads every row");
		Check(MetadataOnly(Rows(con, session + "SELECT * FROM range(3)")), "a table function returns rows");
		Check(MetadataOnly(Rows(con, session + "SELECT c.shout('x')")), "a virtual scalar's template may read");
		Check(MetadataOnly(Rows(con, session + "SELECT * FROM c.acl_references()")),
		      "a virtual table function named like a metadata surface");
		Check(MetadataOnly(Rows(con, session + "SELECT * FROM acl_references()")), "...by its bare name");
		Check(MetadataOnly(Rows(con, session + "SELECT phys.main.peek()")),
		      "a physical macro the role may call - its body reads rows");
		Check(MetadataOnly(Rows(con, session + "USE c")), "USE - the session's record is the viewer's");
		Check(MetadataOnly(Rows(con, session + "EXPLAIN SELECT 1")), "EXPLAIN");
		Check(MetadataOnly(Rows(con, session + "CREATE ROLE made_in_view_as")), "management");
		Check(MetadataOnly(Rows(con, session + "ACL NATIVE SELECT 1")), "native SQL");
		Check(MetadataOnly(Rows(con, session + "SELECT platform.create_role('made_in_view_as')")), "a platform call");
		Check(Contains(Rows(con, session + "SELECT count(*) FROM platform.roles"), "ERROR"),
		      "platform.roles is r's to read - r holds nothing on platform");
		auto made = con.Query("SELECT count(*) FROM store.acl.roles WHERE role = 'made_in_view_as'");
		Check(made->Collection().GetValue(0, 0).GetValue<int64_t>() == 0, "...and nothing was written");
	});

	Scenario("the mode is the session's: another session of the same principal is untouched", [&]() {
		Check(Rows(con, "ACL SESSION '" + other + "' SELECT count(*) FROM platform.roles") != "0",
		      "the other session still reads platform.roles");
		Check(Rows(con, "ACL SESSION '" + plain + "' SELECT id FROM c.orders") == "1", "r itself still reads rows");
		Check(Rows(con, "ACL SESSION '" + plain + "' SELECT c.shout('x')") == "X", "...and calls its scalar");
		Check(Rows(con, "ACL SESSION '" + plain + "' SELECT phys.main.peek()") == "2", "...and its granted macro");
	});

	Scenario("RESET SESSION VIEW AS leaves it; platform.view_as is the same", [&]() {
		CheckOk(*con.Query(session + "RESET SESSION VIEW AS"), "RESET SESSION VIEW AS");
		Check(Rows(con, session + "SELECT count(*) FROM platform.roles") != "0", "platform.roles reads again");
		CheckOk(*con.Query(session + "SELECT platform.view_as('r')"), "platform.view_as('r')");
		Check(MetadataOnly(Rows(con, session + "SELECT id FROM c.orders")), "...is view-as");
		CheckOk(*con.Query(session + "SELECT platform.view_as('')"), "platform.view_as('') leaves it");
		Check(Rows(con, session + "SELECT count(*) FROM platform.roles") != "0", "...back");
	});

	Scenario("who may: policy (or passthrough), on a session of its own, for a role that exists", [&]() {
		Check(Contains(Rows(con, session + "SET SESSION VIEW AS ROLE 'nosuch'"), "role \"nosuch\" does not exist"),
		      "an unknown role is refused");
		Check(Contains(Rows(con, "ACL SESSION '" + plain + "' SET SESSION VIEW AS ROLE 'pol'"), "ERROR"),
		      "a role without administration may not");
		Check(Contains(Rows(con, "ACL SESSION '" + catalog_admin + "' SET SESSION VIEW AS ROLE 'r'"),
		               "unrestricted manage"),
		      "a catalog admin may not (r's tree spans catalogs it does not administer)");
		Check(Contains(Rows(con, "ACL ROLE \"pol\" SET SESSION VIEW AS ROLE 'r'"), "ERROR"),
		      "a per-statement prefix has no session of its own");
		Check(Contains(Rows(con, "ACL SESSION '" + plain + "' SELECT id FROM c.orders"), "1"),
		      "...and r's session stayed r's");
	});

	Scenario("a view never shows more than the viewer may read", [&]() {
		Check(Contains(Rows(con, session + "SET SESSION VIEW AS ROLE 'pt'"), "holds administration"),
		      "the policy bundle may not view a role holding administration");
		Check(Contains(Rows(con, session + "SELECT platform.view_as('pt')"), "holds administration"),
		      "...nor through the call");
		auto pt = OpenSession(con, "pttok");
		CheckOk(*con.Query("ACL SESSION '" + pt + "' SET SESSION VIEW AS ROLE 'pol'"), "passthrough may");
		Check(Rows(con, "ACL SESSION '" + pt + "' SELECT count(*) FROM platform.roles") != "0",
		      "...and reads platform as pol does");
		Check(Contains(Rows(con, "ACL SESSION '" + pt + "' SELECT count(*) FROM platform.sessions"), "ERROR"),
		      "...but not what pol does not read");
		Exec(con, "SELECT acl_session_close('" + pt + "')");
		Exec(con, "ACL ADMIN GRANT FUNCTION platform.view_as TO ROLE cadm");
		Check(Contains(Rows(con, "ACL SESSION '" + catalog_admin + "' SET SESSION VIEW AS ROLE 'r'"),
		               "a point grant does not reach it"),
		      "a point grant on platform.view_as does not reach the mode");
		Exec(con, "ACL ADMIN REVOKE FUNCTION platform.view_as FROM ROLE cadm");
	});

	Scenario("a viewer that loses the policy bundle leaves the mode at once", [&]() {
		auto pol2 = OpenSession(con, "pol2tok");
		auto in = "ACL SESSION '" + pol2 + "' ";
		CheckOk(*con.Query(in + "SET SESSION VIEW AS ROLE 'r'"), "pol2 views as r");
		Check(Rows(con, in + "SELECT table_name FROM information_schema.tables") == "orders", "...r's tree");
		Exec(con, "ACL ADMIN REVOKE ADMIN FROM ROLE pol2");
		auto after = Rows(con, in + "SELECT table_name FROM information_schema.tables");
		Check(after != "orders" && !MetadataOnly(after), "the next statement is pol2's own again: " + after);
		Exec(con, "SELECT acl_session_close('" + pol2 + "')");
	});

	for (auto &h : {handle, other, plain, catalog_admin}) {
		Exec(con, "SELECT acl_session_close('" + h + "')");
	}
	std::cout << (failures == 0 ? "PASS" : "FAIL") << "\n";
	return failures == 0 ? 0 : 1;
}
