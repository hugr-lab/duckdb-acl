// A session is a handle a door exchanges a token for once (spec 040), and the handle is minted at
// runtime - so the one property that matters most, "ACL SESSION '<handle>' answers exactly as
// ACL TOKEN '<jwt>' does", cannot be written in sqllogictest: the prefix is text scanned before the
// parser runs, and no test file can splice a value into it. Hence a standalone binary.
// Build + run via `GEN=ninja make test-cpp`.

#include "acl_test_util.hpp"

using namespace duckdb;
using namespace acl_test;

namespace {

//! An HS256 token for the issuer the fixture defines: roles ["analyst"], tid=acme, exp in 2100.
const char *const TOKEN =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci50ZXN0L3MiLCJhdWQiOiJhcGk6Ly9hY2w"
    "tdGVzdCIsImV4cCI6NDEwMjQ0NDgwMCwic3ViIjoidSIsInJvbGVzIjpbImFuYWx5c3QiXSwidGlkIjoiYWNtZSJ9.c_RJ0X6_Gj"
    "5O5Z273KOaB9e11XFXVgQkEbtTCayEzJc";

//! The handle a door would hold, or "" when the token did not verify
std::string OpenSession(Connection &con, const std::string &token) {
	auto result = con.Query("SELECT acl_session_open('" + token + "')");
	if (result->HasError() || result->RowCount() == 0) {
		return std::string();
	}
	auto value = result->GetValue(0, 0);
	return value.IsNull() ? std::string() : value.ToString();
}

//! The heart of it: the same statement, once behind the token and once behind the handle, has to
//! answer identically - claims-driven RLS included, since the claims travel in the session.
void SessionAnswersAsTheTokenDoes(Connection &con) {
	auto handle = OpenSession(con, TOKEN);
	if (!Check(!handle.empty(), "a verified token opens a session")) {
		return;
	}
	auto by_token = con.Query(std::string("ACL TOKEN '") + TOKEN + "' SELECT id FROM orders ORDER BY id");
	if (CheckOk(*by_token, "the token form runs")) {
		CheckColumn(*by_token, {1, 2}, "token: tenant=acme sees ids 1,2");
	}
	auto by_session = con.Query("ACL SESSION '" + handle + "' SELECT id FROM orders ORDER BY id");
	if (CheckOk(*by_session, "the session form runs")) {
		CheckColumn(*by_session, {1, 2}, "session: the same rows, so the claim travelled with it");
	}
}

//! What a door actually calls: acl_session_sql composes the statement, and running its output is the
//! query. If these two ever disagree, every door built on the contract is wrong at once.
void ComposedSqlIsTheQuery(Connection &con) {
	auto handle = OpenSession(con, TOKEN);
	if (!Check(!handle.empty(), "session opens for the composition check")) {
		return;
	}
	auto composed = con.Query("SELECT acl_session_sql('" + handle + "', 'SELECT id FROM orders ORDER BY id')");
	if (!CheckOk(*composed, "acl_session_sql composes")) {
		return;
	}
	auto sql = composed->GetValue(0, 0);
	if (!Check(!sql.IsNull(), "a live session composes rather than refusing")) {
		return;
	}
	auto result = con.Query(sql.ToString());
	if (CheckOk(*result, "the composed statement runs")) {
		CheckColumn(*result, {1, 2}, "composed: the door's own path gives the principal's rows");
	}
}

//! A closed session stops working immediately, and the composition refuses rather than producing a
//! statement that would fail later.
void ClosingEndsIt(Connection &con) {
	auto handle = OpenSession(con, TOKEN);
	if (!Check(!handle.empty(), "session opens for the close check")) {
		return;
	}
	Exec(con, "SELECT acl_session_close('" + handle + "')");
	auto composed = con.Query("SELECT acl_session_sql('" + handle + "', 'SELECT 1')");
	if (CheckOk(*composed, "acl_session_sql answers for a closed handle")) {
		Check(composed->GetValue(0, 0).IsNull(), "a closed session composes nothing");
	}
	auto result = con.Query("ACL SESSION '" + handle + "' SELECT id FROM orders");
	Check(result->HasError(), "a closed handle is refused by the prefix too");
}

//! Sessions are per-instance state, like the store itself: two databases in one process never see
//! each other's handles.
void InstancesDoNotShareSessions(Connection &first, const std::string &extension) {
	auto handle = OpenSession(first, TOKEN);
	if (!Check(!handle.empty(), "session opens in the first instance")) {
		return;
	}
	DuckDB other(nullptr);
	Connection con(other);
	Exec(con, "LOAD '" + extension + "'");
	auto composed = con.Query("SELECT acl_session_sql('" + handle + "', 'SELECT 1')");
	if (CheckOk(*composed, "the other instance answers")) {
		Check(composed->GetValue(0, 0).IsNull(), "another instance does not know this handle");
	}
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
	Exec(con, "CREATE TABLE phys.main.orders(id INTEGER, tenant VARCHAR)");
	Exec(con, "INSERT INTO phys.main.orders VALUES (1,'acme'),(2,'acme'),(3,'globex')");
	Exec(con, "SELECT acl_use_db('store','acl',true)");
	Exec(con, "SET GLOBAL acl_allow_anonymous_admin=true");
	Exec(con, "SELECT acl_define_issuer('https://issuer.test/s',"
	          "'{\"keys\":[{\"kty\":\"oct\",\"k\":\"YWNsLXRlc3QtaHMyNTYtc2VjcmV0\"}]}',"
	          "'api://acl-test','HS256','roles','{\"tid\": \"tenant\"}')");
	Exec(con, "ACL ADMIN CREATE VIRTUAL CATALOG c");
	Exec(con, "ACL ADMIN CREATE VIRTUAL TABLE c.orders AS phys.main.orders "
	          "RLS 'tenant = acl_claim(''tenant'')'");
	Exec(con, "ACL ADMIN CREATE ROLE analyst");
	Exec(con, "ACL ADMIN GRANT CATALOG c TO ROLE analyst MAIN");

	Scenario("session-answers-as-the-token", [&]() { SessionAnswersAsTheTokenDoes(con); });
	Scenario("composed-sql-is-the-query", [&]() { ComposedSqlIsTheQuery(con); });
	Scenario("closing-ends-it", [&]() { ClosingEndsIt(con); });
	Scenario("instances-do-not-share-sessions", [&]() { InstancesDoNotShareSessions(con, extension); });

	std::cout << (failures == 0 ? "PASS" : "FAIL") << "\n";
	return failures == 0 ? 0 : 1;
}
