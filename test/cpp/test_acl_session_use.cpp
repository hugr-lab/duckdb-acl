// spec 114: a session's default catalog and schema - `USE <vcat>[.<schema>]` and `USE SCHEMA <schema>`.
// A session handle is minted at runtime and no sqllogictest file can splice it into the prefix, so the
// positive path lives here (the refusals on a per-statement prefix are in test/sql/acl_session_use.test).
// Build + run via `GEN=ninja make test-cpp`.

#include "acl_test_util.hpp"

using namespace duckdb;
using namespace acl_test;

namespace {

//! roles ["analyst"], tid=acme, exp in 2100 (the fixture issuer test/idp/s) - test_acl_session.cpp's
const char *const TOKEN =
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2V5In0.eyJpc3MiOiJ0ZXN0L2lkcC9zIiwiYXVkIjoiYXBp"
    "Oi8vYWNsLXRlc3QiLCJleHAiOjQxMDI0NDQ4MDAsInN1YiI6InUiLCJyb2xlcyI6WyJhbmFseXN0Il0sInRpZCI6ImFjbWUifQ.C"
    "2rTehH2D3jptrk0TWAepMNA5XjhgHBCEYVr1NzJm7xa7ygxGtgCV9NpejZV3FFT2ex7QaC5xaoFHy59n5VbOw8I9t5_5qUvGkbDu"
    "SvyEYCLBlzdSczLOn7Su7k9rSIsMVvmbamtp_IhgyF1_ct0e1hm03Q2Vrm509omfcDvs9W8AyV9aPHUWui8bC-7hzw__gyiiZsRH"
    "8PEqZr3JqSPL5FdHp54d7YdGkgMZAR-TkB68NhjvcEmIaNG4Dr2ncL78Brj21nwtTIo3HbeNmhKzUbEp0uwH_-XkV2kxkKQXc2Ty"
    "sjble9-G50jiFYfciBfmh6rGkct3o-XcVwdC3YV1A";

std::string OpenSession(Connection &con) {
	auto result = con.Query(std::string("SELECT acl_session_open('") + TOKEN + "')");
	if (result->HasError() || result->RowCount() == 0 || result->Collection().GetValue(0, 0).IsNull()) {
		return std::string();
	}
	return result->Collection().GetValue(0, 0).ToString();
}

//! The one value a query answers, or "ERROR: …"
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

bool Contains(const std::string &text, const std::string &part) {
	return text.find(part) != std::string::npos;
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
	Exec(con, "CREATE SCHEMA phys.home");
	Exec(con, "CREATE SCHEMA phys.other");
	Exec(con, "CREATE TABLE phys.main.orders AS SELECT 1 AS id");
	Exec(con, "CREATE TABLE phys.main.facts AS SELECT 2 AS id");
	Exec(con, "CREATE TABLE phys.other.t AS SELECT 3 AS id");
	Exec(con, "SELECT acl_use_db('store','acl',true)");
	Exec(con, "SET GLOBAL acl_allow_anonymous_admin=true");
	Exec(con, "SET GLOBAL acl_jwks_locations = 'test/idp/'");
	Exec(con, "SELECT acl_define_issuer('test/idp/s', '{\"url\": \"test/idp/s\", \"client\": {\"audiences\": "
	          "[\"api://acl-test\"], \"roles_from\": [\"roles\"], \"attributes\": {\"tid\": \"tenant\"}}}')");
	Exec(con, "ACL ADMIN CREATE VIRTUAL CATALOG sales");
	Exec(con, "ACL ADMIN CREATE VIRTUAL CATALOG mart");
	Exec(con, "ACL ADMIN CREATE VIRTUAL CATALOG secret");
	Exec(con, "ACL ADMIN CREATE VIRTUAL TABLE sales.orders AS phys.main.orders");
	Exec(con, "ACL ADMIN CREATE VIRTUAL TABLE mart.facts AS phys.main.facts");
	Exec(con, "ACL ADMIN CREATE VIRTUAL SCHEMA mart.out AS phys.other");
	Exec(con, "ACL ADMIN CREATE VIRTUAL SCHEMA mart.home AS phys.home");
	Exec(con, "ACL ADMIN CREATE ROLE analyst");
	Exec(con, "ACL ADMIN GRANT CATALOG sales TO ROLE analyst WITH (select) MAIN");
	Exec(con, "ACL ADMIN GRANT CATALOG mart TO ROLE analyst WITH (select)");
	Exec(con, "ACL ADMIN GRANT SCHEMA mart.out TO ROLE analyst WITH (select)");
	Exec(con, "ACL ADMIN GRANT SCHEMA mart.home TO ROLE analyst WITH (select, insert, create, drop)");

	auto handle = OpenSession(con);
	if (!Check(!handle.empty(), "a session opens")) {
		return 1;
	}
	auto session = "ACL SESSION '" + handle + "' ";

	Scenario("short names resolve in the role's MAIN catalog until USE", [&]() {
		Check(One(con, session + "SELECT id FROM orders") == "1", "orders is sales.orders");
		Check(Contains(One(con, session + "SELECT id FROM facts"), "ERROR"), "facts is not in sales");
		Check(One(con, session + "SELECT current_database()") == "sales", "current_database() is sales");
	});

	Scenario("USE <vcat> makes it the session's catalog", [&]() {
		CheckOk(*con.Query(session + "USE mart"), "USE mart");
		Check(One(con, session + "SELECT id FROM facts") == "2", "facts is mart.facts now");
		Check(One(con, session + "SELECT id FROM out.t") == "3", "a two-part name is read in mart");
		Check(One(con, session + "SELECT id FROM sales.orders") == "1", "a catalog written in front still wins");
		Check(One(con, session + "SELECT current_database()") == "mart", "current_database() is mart");
		Check(One(con, session + "SELECT current_schema()") == "main", "current_schema() is the root");
	});

	Scenario("USE SCHEMA and USE <vcat>.<schema> set the default schema", [&]() {
		CheckOk(*con.Query(session + "USE SCHEMA out"), "USE SCHEMA out");
		Check(One(con, session + "SELECT id FROM t") == "3", "a bare name is read in mart.out");
		Check(One(con, session + "SELECT current_schema()") == "out", "current_schema() is out");
		Check(One(con, session + "SELECT id FROM main.facts") == "2", "the root is main.<object>");
		CheckOk(*con.Query(session + "USE mart.home"), "USE mart.home");
		CheckOk(*con.Query(session + "CREATE TABLE made AS SELECT 7 AS id"), "a bare CREATE lands in the schema");
		Check(One(con, "SELECT count(*) FROM duckdb_tables() WHERE schema_name = 'home' AND table_name = 'made'") ==
		          "1",
		      "made is phys.home.made");
		CheckOk(*con.Query(session + "USE SCHEMA main"), "USE SCHEMA main");
		Check(One(con, session + "SELECT current_schema()") == "main", "back to the root");
	});

	Scenario("refusals", [&]() {
		Check(Contains(One(con, session + "USE secret"), "no catalog of the principal"), "a catalog not held");
		Check(Contains(One(con, session + "USE mart.nope"), "no schema the principal holds"), "a schema not held");
		Check(Contains(One(con, session + "USE a.b.c"), "ERROR"), "three parts are no USE");
		Check(One(con, session + "SELECT current_database()") == "mart", "a refused USE changed nothing");
	});

	Scenario("USE of the MAIN catalog goes back", [&]() {
		CheckOk(*con.Query(session + "USE sales"), "USE sales");
		Check(One(con, session + "SELECT id FROM orders") == "1", "orders is sales.orders again");
		Check(Contains(One(con, session + "SELECT id FROM facts"), "ERROR"), "facts is not in sales");
	});

	Scenario("another session keeps its own", [&]() {
		CheckOk(*con.Query(session + "USE mart"), "USE mart on the first session");
		auto other = OpenSession(con);
		if (!Check(!other.empty(), "a second session opens")) {
			return;
		}
		Check(One(con, "ACL SESSION '" + other + "' SELECT current_database()") == "sales",
		      "the second session is still in sales");
		Check(One(con, session + "SELECT id FROM facts") == "2", "the first is in mart (no shared cache)");
		Exec(con, "SELECT acl_session_close('" + other + "')");
	});

	Exec(con, "SELECT acl_session_close('" + handle + "')");
	std::cout << (failures == 0 ? "PASS" : "FAIL") << "\n";
	return failures == 0 ? 0 : 1;
}
