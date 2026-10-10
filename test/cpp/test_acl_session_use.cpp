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

//! A refusal naming what was asked for: with the temp capability a bare name the catalog lacks is tried as
//! the session's temp, so the binder's "does not exist" answers instead of the rewriter's "no access"
bool Refused(const std::string &text, const std::string &name) {
	return Contains(text, "ERROR") && Contains(text, name) &&
	       (Contains(text, "no access to object") || Contains(text, "does not exist"));
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
	Exec(con, "CREATE SCHEMA phys.exp");
	Exec(con, "CREATE TABLE phys.exp.loose AS SELECT 1 AS id");
	Exec(con, "CREATE SCHEMA phys.shadow");
	Exec(con, "CREATE TABLE phys.shadow.orders AS SELECT 99 AS id");
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
	Exec(con, "ACL ADMIN CREATE VIRTUAL SCHEMA mart.sales AS phys.shadow");
	Exec(con, "ACL ADMIN CREATE VIRTUAL SCHEMA mart.exp FROM phys.exp");
	Exec(con, "ACL ADMIN ADD SCALAR mart.shout MACRO 'upper(acl_arg(1))'");
	Exec(con, "SELECT acl_add_table_function('mart', 'out.rows', 'SELECT 9 AS nine', '', 'nine INTEGER', '')");
	Exec(con, "ACL ADMIN CREATE ROLE analyst");
	Exec(con, "ACL ADMIN GRANT CATALOG sales TO ROLE analyst WITH (select, temp) MAIN");
	Exec(con, "ACL ADMIN GRANT CATALOG mart TO ROLE analyst WITH (select)");
	Exec(con, "ACL ADMIN GRANT SCHEMA mart.out TO ROLE analyst WITH (select)");
	Exec(con, "ACL ADMIN GRANT SCHEMA mart.home TO ROLE analyst WITH (select, insert, create, drop)");
	Exec(con, "ACL ADMIN GRANT SCHEMA mart.sales TO ROLE analyst WITH (select)");
	Exec(con, "ACL ADMIN GRANT SCHEMA mart.exp TO ROLE analyst WITH (select, insert, create, drop)");

	// spec 116: a catalog and a schema named the way SQL allows
	Exec(con, "CREATE SCHEMA phys.\"Raw Data\"");
	Exec(con, "CREATE TABLE phys.\"Raw Data\".\"Order Items\" AS SELECT 5 AS id");
	Exec(con, "ACL ADMIN CREATE VIRTUAL CATALOG \"Sales Mart\"");
	Exec(con, "ACL ADMIN CREATE VIRTUAL SCHEMA \"Sales Mart\".\"Raw Data\" AS phys.\"Raw Data\"");
	Exec(con, "ACL ADMIN GRANT CATALOG \"Sales Mart\" TO ROLE analyst WITH (select)");
	Exec(con, "ACL ADMIN GRANT SCHEMA \"Sales Mart\".\"Raw Data\" TO ROLE analyst WITH (select)");

	auto handle = OpenSession(con);
	if (!Check(!handle.empty(), "a session opens")) {
		return 1;
	}
	auto session = "ACL SESSION '" + handle + "' ";

	Scenario("short names resolve in the role's MAIN catalog until USE", [&]() {
		Check(One(con, session + "SELECT id FROM orders") == "1", "orders is sales.orders");
		Check(Refused(One(con, session + "SELECT id FROM facts"), "facts"), "facts is not in sales");
		Check(One(con, session + "SELECT current_database()") == "sales", "current_database() is sales");
	});

	Scenario("USE <vcat> makes it the session's catalog", [&]() {
		CheckOk(*con.Query(session + "USE mart"), "USE mart");
		Check(One(con, session + "SELECT id FROM facts") == "2", "facts is mart.facts now");
		Check(One(con, session + "SELECT id FROM out.t") == "3", "a two-part name is read in mart");
		Check(One(con, session + "SELECT id FROM sales.main.orders") == "1", "a catalog written in front still wins");
		Check(One(con, session + "SELECT current_database()") == "mart", "current_database() is mart");
		Check(One(con, session + "SELECT current_schema()") == "main", "current_schema() is the root");
		Check(One(con, session + "SELECT string_agg(name, ',' ORDER BY name) FROM (SHOW TABLES)") == "facts",
		      "SHOW TABLES is mart's root");
	});

	Scenario("a held catalog in front that is also a schema of the session's catalog is refused", [&]() {
		Check(Contains(One(con, session + "SELECT id FROM sales.orders"), "is ambiguous"), "sales.orders is ambiguous");
		Check(One(con, session + "SELECT id FROM mart.sales.orders") == "99", "mart.sales.orders is the schema");
	});

	Scenario("USE SCHEMA and USE <vcat>.<schema> set the default schema", [&]() {
		CheckOk(*con.Query(session + "USE SCHEMA out"), "USE SCHEMA out");
		Check(One(con, session + "SELECT id FROM t") == "3", "a bare name is read in mart.out");
		Check(One(con, session + "SELECT current_schema()") == "out", "current_schema() is out");
		Check(One(con, session + "SELECT id FROM main.facts") == "2", "the root is main.<object>");
		Check(One(con, session + "SELECT string_agg(name, ',' ORDER BY name) FROM (SHOW TABLES)") == "t",
		      "SHOW TABLES is mart.out");
		CheckOk(*con.Query(session + "USE mart.home"), "USE mart.home");
		CheckOk(*con.Query(session + "CREATE TABLE made AS SELECT 7 AS id"), "a bare CREATE lands in the schema");
		Check(One(con, "SELECT count(*) FROM duckdb_tables() WHERE schema_name = 'home' AND table_name = 'made'") ==
		          "1",
		      "made is phys.home.made");
		CheckOk(*con.Query(session + "INSERT INTO made VALUES (8)"), "a bare INSERT");
		Check(One(con, session + "SELECT sum(id) FROM made") == "15", "a bare read of what was made");
		CheckOk(*con.Query(session + "CREATE VIEW made_v AS SELECT id FROM made"), "a bare CREATE VIEW");
		Check(One(con, session + "SELECT count(*) FROM made_v") == "2", "the view reads in the schema");
		CheckOk(*con.Query(session + "DROP VIEW made_v"), "a bare DROP VIEW");
		CheckOk(*con.Query(session + "ALTER TABLE made RENAME TO made2"), "a bare RENAME");
		Check(One(con, session + "SELECT count(*) FROM made2") == "2", "renamed in the schema");
		CheckOk(*con.Query(session + "DROP TABLE made2"), "a bare DROP");
		Check(One(con, "SELECT count(*) FROM duckdb_tables() WHERE schema_name = 'home'") == "0",
		      "phys.home is empty again");
		CheckOk(*con.Query(session + "USE SCHEMA main"), "USE SCHEMA main");
		Check(One(con, session + "SELECT current_schema()") == "main", "back to the root");
	});

	Scenario("refusals", [&]() {
		Check(Contains(One(con, session + "USE secret"), "no catalog of the principal"), "a catalog not held");
		Check(Contains(One(con, session + "USE mart.nope"), "no schema the principal holds"), "a schema not held");
		Check(Contains(One(con, session + "USE a.b.c"), "Expected \"USE database\" or \"USE database.schema\""),
		      "three parts are no USE");
		Check(One(con, session + "SELECT current_database()") == "mart", "a refused USE changed nothing");
	});

	Scenario("USE of the MAIN catalog goes back", [&]() {
		CheckOk(*con.Query(session + "USE sales"), "USE sales");
		Check(One(con, session + "SELECT id FROM orders") == "1", "orders is sales.orders again");
		Check(Refused(One(con, session + "SELECT id FROM facts"), "facts"), "facts is not in sales");
	});

	Scenario("only a session-scoped SET is a USE", [&]() {
		Check(Contains(One(con, session + "SET GLOBAL schema = 'mart'"), "ERROR"), "SET GLOBAL schema is refused");
		Check(Contains(One(con, session + "SET VARIABLE schema = 'mart'"), "ERROR"), "a variable is no USE");
		Check(One(con, session + "SELECT current_database()") == "sales", "neither moved the session");
		CheckOk(*con.Query(session + "USE mart"), "USE mart");
		CheckOk(*con.Query(session + "USE /* the mart */ SCHEMA -- a comment\n out;"), "USE SCHEMA among comments");
		Check(One(con, session + "SELECT current_schema()") == "out", "read past the comments");
		CheckOk(*con.Query(session + "USE sales"), "back");
	});

	Scenario("session temps under a USE", [&]() {
		CheckOk(*con.Query(session + "USE mart"), "USE mart");
		Check(Contains(One(con, session + "CREATE TEMP TABLE facts AS SELECT 0 AS id"), "is a granted object"),
		      "a temp named like an object of the session's catalog is refused");
		CheckOk(*con.Query(session + "CREATE TEMP TABLE scratch AS SELECT 5 AS id"), "a temp of its own name");
		CheckOk(*con.Query(session + "USE mart.home"), "USE mart.home");
		// a schema alias claims every name in it, so the temp is reached by its own catalog's name
		Check(Contains(One(con, session + "SELECT id FROM scratch"), "ERROR"), "a bare name is mart.home's");
		Check(One(con, session + "SELECT id FROM temp.main.scratch") == "5", "temp.main.scratch is the temp");
		CheckOk(*con.Query(session + "DROP TABLE temp.main.scratch"), "DROP of the temp by its name");
		Check(One(con, "SELECT count(*) FROM duckdb_tables() WHERE table_name = 'scratch'") == "0", "the temp is gone");
		CheckOk(*con.Query(session + "CREATE TEMP TABLE staged AS SELECT 6 AS id"),
		        "a temp under a schema alias (which claims every name) shadows no object");
		Check(One(con, session + "SELECT id FROM temp.main.staged") == "6", "reached by its own catalog's name");
		CheckOk(*con.Query(session + "DROP TABLE temp.main.staged"), "and dropped so");
		CheckOk(*con.Query(session + "USE sales"), "back");
	});

	Scenario("a bare DROP under a USE is the home's, not a guessed temp", [&]() {
		auto phys_count = [&](const std::string &name) {
			return One(con, "SELECT count(*) FROM duckdb_tables() WHERE database_name = 'phys' AND schema_name = "
			                "'exp' AND table_name = '" +
			                    name + "'");
		};
		CheckOk(*con.Query(session + "USE mart.exp"), "USE mart.exp");
		CheckOk(*con.Query(session + "CREATE TABLE y AS SELECT 1 AS id; DROP TABLE y"), "CREATE + DROP in one batch");
		Check(phys_count("y") == "0", "y is dropped in phys.exp");
		CheckOk(*con.Query(session + "DROP TABLE IF EXISTS loose"), "DROP IF EXISTS of a table with no record");
		Check(phys_count("loose") == "0", "loose is dropped in phys.exp");
		CheckOk(*con.Query(session + "USE sales"), "back");
	});

	Scenario("quoted and differently cased names", [&]() {
		CheckOk(*con.Query(session + "USE \"mart\".\"out\""), "USE \"mart\".\"out\"");
		Check(One(con, session + "SELECT id FROM t") == "3", "a bare name is read in mart.out");
		CheckOk(*con.Query(session + "USE MART"), "USE MART");
		Check(One(con, session + "SELECT current_database()") == "mart", "as the policy spells it");
		CheckOk(*con.Query(session + "USE SCHEMA \"out\""), "USE SCHEMA \"out\"");
		Check(One(con, session + "SELECT current_schema()") == "out", "the quoted schema");
		Check(Contains(One(con, session + "USE SCHEMA \"out.t\""), "no schema the principal holds"),
		      "a quoted dotted name is no schema");
		CheckOk(*con.Query(session + "USE sales"), "back");
	});

	Scenario("a USE inside a batch applies to what follows it", [&]() {
		// without it the SELECT reads sales, which has no facts, and the batch fails
		CheckOk(*con.Query(session + "USE mart; SELECT id FROM facts"), "the batch reads in mart");
		Check(One(con, session + "SELECT current_database()") == "mart", "and the session keeps it");
		CheckOk(*con.Query(session + "USE sales"), "back");
	});

	Scenario("another session keeps its own", [&]() {
		CheckOk(*con.Query(session + "USE mart"), "USE mart on the first session");
		auto other = OpenSession(con);
		if (!Check(!other.empty(), "a second session opens")) {
			return;
		}
		Check(One(con, "ACL SESSION '" + other + "' SELECT current_database()") == "sales",
		      "the second session is still in sales");
		Check(Refused(One(con, "ACL SESSION '" + other + "' SELECT id FROM facts"), "facts"),
		      "a short name on the second session is read in sales");
		Check(One(con, session + "SELECT id FROM facts") == "2", "the first is in mart (no shared cache)");
		Exec(con, "SELECT acl_session_close('" + other + "')");
	});

	Scenario("lineage names what the session read and wrote", [&]() {
		Exec(con, "SET GLOBAL acl_lineage_namespace = 'acl://test'");
		Exec(con, "SET GLOBAL acl_lineage_level = 'on'");
		auto last_run = [&](const std::string &side) {
			Exec(con, "SELECT acl_lineage_flush()");
			return One(con, "SELECT payload->'datasets'->(payload->'" + side +
			                    "'->>0)::INT->>'name' FROM acl_lineage_events() WHERE event_type = 'RUN_COMPLETE' "
			                    "ORDER BY seq DESC LIMIT 1");
		};
		CheckOk(*con.Query(session + "USE mart.home"), "USE mart.home");
		CheckOk(*con.Query(session + "CREATE TABLE lin AS SELECT id FROM out.t"), "a bare CTAS");
		Check(last_run("outputs") == "mart.home.lin", "the output is mart.home.lin");
		Check(last_run("inputs") == "mart.out.t", "the input is mart.out.t");
		CheckOk(*con.Query(session + "USE sales"), "USE sales");
		// a USE earlier in the batch: the INSERT was read under it, whatever the session says by the time
		// the worker runs
		CheckOk(*con.Query(session + "USE mart.home; INSERT INTO lin SELECT id FROM main.facts; USE sales"),
		        "USE, INSERT, USE back in one batch");
		Check(last_run("outputs") == "mart.home.lin", "the batch's output is mart.home.lin");
		Check(last_run("inputs") == "mart.main.facts", "the batch's input is mart.main.facts");
		CheckOk(*con.Query(session + "DROP TABLE mart.home.lin"), "drop it");
		Exec(con, "SET GLOBAL acl_lineage_level = 'off'");
	});

	Scenario("a function's short name is read in the session's catalog too (spec 115)", [&]() {
		Check(Contains(One(con, session + "SELECT shout('a')"), "shout"), "shout is not in sales");
		Check(One(con, session + "SELECT mart.shout('a')") == "A", "qualified, it is called from anywhere");
		CheckOk(*con.Query(session + "USE mart"), "USE mart");
		Check(One(con, session + "SELECT shout('a')") == "A", "under USE mart the bare name reaches mart.shout");
		Check(One(con, session + "SELECT upper('a')") == "A", "an engine function is still itself");
		Check(One(con, session + "SELECT * FROM out.rows()") == "9", "a two-part name is read in mart");
		CheckOk(*con.Query(session + "USE SCHEMA out"), "USE SCHEMA out");
		Check(One(con, session + "SELECT * FROM rows()") == "9", "a bare name is read in mart.out");
		CheckOk(*con.Query(session + "USE sales"), "back");
	});

	Scenario("USE takes a quoted catalog and schema, in any case (spec 116)", [&]() {
		CheckOk(*con.Query(session + "USE \"sales mart\""), "USE \"sales mart\"");
		Check(One(con, session + "SELECT current_database()") == "Sales Mart",
		      "current_database() is the catalog as the policy spells it");
		Check(One(con, session + "SELECT id FROM \"Raw Data\".\"order items\"") == "5",
		      "a two-part name is read in \"Sales Mart\"");
		CheckOk(*con.Query(session + "USE SCHEMA \"raw data\""), "USE SCHEMA \"raw data\"");
		Check(One(con, session + "SELECT current_schema()") == "Raw Data", "current_schema() is the schema's name");
		Check(One(con, session + "SELECT id FROM \"ORDER ITEMS\"") == "5", "a bare name is read in the schema");
		Check(One(con, session + "SELECT string_agg(name, ',') FROM (SHOW TABLES)") == "Order Items",
		      "SHOW TABLES is the schema's");
		CheckOk(*con.Query(session + "USE \"SALES MART\".\"RAW DATA\""), "USE catalog.schema, upper case");
		Check(One(con, session + "SELECT id FROM \"Order Items\"") == "5", "and reads there");
		Check(Refused(One(con, session + "USE \"Sales Mart.Raw Data\""), "Sales Mart.Raw Data") ||
		          Contains(One(con, session + "USE \"Sales Mart.Raw Data\""), "no catalog of the principal"),
		      "one identifier with a dot is no catalog.schema");
		CheckOk(*con.Query(session + "USE sales"), "back");
	});

	Scenario("a revoked catalog is no longer the session's", [&]() {
		Exec(con, "ACL ADMIN REVOKE CATALOG mart FROM ROLE analyst");
		Check(Contains(One(con, session + "SELECT id FROM facts"), "ERROR"), "mart.facts is refused");
		Check(One(con, session + "SELECT current_database()") == "sales", "current_database() is not claimed");
		Check(Contains(One(con, session + "USE mart"), "no catalog of the principal"), "USE mart is refused");
		CheckOk(*con.Query(session + "USE sales"), "USE sales recovers");
		Check(One(con, session + "SELECT id FROM orders") == "1", "orders is sales.orders");
	});

	Exec(con, "SELECT acl_session_close('" + handle + "')");
	std::cout << (failures == 0 ? "PASS" : "FAIL") << "\n";
	return failures == 0 ? 0 : 1;
}
