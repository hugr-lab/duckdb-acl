// The ACL INGEST prefix (spec 049) is composed by the Flight door's own C++ with a session handle
// minted at runtime, so - exactly as with ACL SESSION (spec 040) - its properties cannot be written
// in sqllogictest: no test file can splice a handle into a prefix. Hence a standalone binary.
// Build + run via `GEN=ninja make test-cpp`.

#include "acl_test_util.hpp"

using namespace duckdb;
using namespace acl_test;

namespace {

std::string OpenSession(Connection &con) {
	auto result = con.Query("SELECT acl_session_open('tok')");
	if (result->HasError() || result->RowCount() == 0) {
		return std::string();
	}
	auto value = result->GetValue(0, 0);
	return value.IsNull() ? std::string() : value.ToString();
}

bool ErrorContains(QueryResult &result, const std::string &needle, const std::string &what) {
	if (!result.HasError()) {
		return Check(false, what + ": unexpectedly succeeded");
	}
	auto error = result.GetError();
	return Check(error.find(needle) != std::string::npos, what + ": " + error);
}

} // namespace

int main(int argc, char *argv[]) {
	std::string extension = argc > 1 ? argv[1] : "build/release/extension/acl/acl.duckdb_extension";
	DBConfig config;
	config.SetOptionByName("allow_unsigned_extensions", Value::BOOLEAN(true));
	DuckDB db(nullptr, &config);
	Connection con(db);

	return RunMain("acl: the INGEST prefix and the arrow_scan exemption (spec 049)", [&]() {
		Exec(con, "LOAD '" + extension + "'");
		Exec(con, "CREATE TABLE phys_orders(id INT, tenant VARCHAR, amount INT)");
		Exec(con, "ATTACH ':memory:' AS store");
		Exec(con, "SELECT acl_use_db('store', 'acl', true)");
		Exec(con, "SET GLOBAL acl_allow_anonymous_admin=true");
		Exec(con, "ACL ADMIN CREATE VIRTUAL CATALOG c");
		Exec(con, "ACL ADMIN CREATE VIRTUAL TABLE c.orders AS memory.main.phys_orders");
		Exec(con, "ACL ADMIN CREATE ROLE r");
		Exec(con, "ACL ADMIN GRANT CATALOG c TO ROLE r WITH (select, insert) MAIN");
		Exec(con, "SELECT acl_define_token('tok', 'r', 'tenant=acme')");
		auto handle = OpenSession(con);
		if (!Check(!handle.empty(), "a defined token opens a session")) {
			return;
		}

		Scenario("the prefix carries exactly one INSERT", [&]() {
			auto select = con.Query("ACL INGEST '" + handle + "' SELECT 1");
			ErrorContains(*select, "exactly one INSERT", "a SELECT under INGEST is refused");
			auto batch = con.Query("ACL INGEST '" + handle + "' INSERT INTO orders (id) VALUES (1); SELECT 1");
			ErrorContains(*batch, "exactly one INSERT", "a batch under INGEST is refused");
		});

		Scenario("an unknown handle earns nothing", [&]() {
			auto result = con.Query("ACL INGEST 'nope' INSERT INTO orders (id) VALUES (1)");
			ErrorContains(*result, "session", "an unknown handle is a session refusal");
		});

		Scenario("the gate stays closed outside the prefix", [&]() {
			auto by_session = con.Query("ACL SESSION '" + handle + "' SELECT * FROM arrow_scan(NULL, NULL, NULL)");
			ErrorContains(*by_session, "not allowed", "arrow_scan under ACL SESSION is denied");
			auto by_role = con.Query("ACL ROLE \"r\" SELECT * FROM arrow_scan(NULL, NULL, NULL)");
			ErrorContains(*by_role, "not allowed", "arrow_scan under ACL ROLE is denied");
		});

		Scenario("the exemption opens exactly the composed shape", [&]() {
			// under the INGEST prefix the gate passes arrow_scan, so the refusal that comes back is
			// duckdb's own binder error about the pointers - which is what proves the gate opened
			auto composed = con.Query("ACL INGEST '" + handle +
			                          "' INSERT INTO orders (id, tenant, amount)"
			                          " SELECT id, tenant, amount FROM arrow_scan(NULL, NULL, NULL)");
			ErrorContains(*composed, "pointers cannot be null", "the gate passed arrow_scan to duckdb's own check");
			// and only arrow_scan: its dumb sibling stays denied even here
			auto dumb = con.Query("ACL INGEST '" + handle +
			                      "' INSERT INTO orders (id) SELECT id FROM arrow_scan_dumb(NULL, NULL, NULL)");
			ErrorContains(*dumb, "not allowed", "arrow_scan_dumb stays denied under INGEST");
		});

		Scenario("no marker rides after the handle", [&]() {
			auto native = con.Query("ACL INGEST '" + handle + "' ACL NATIVE SELECT 1");
			Check(native->HasError(), "an embedded ACL marker after INGEST does not parse");
		});
	});
}
