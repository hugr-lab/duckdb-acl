// The idle rule of spec 044 needs time to pass, and a .test file has no way to wait - so the one
// property that cannot be written there lives here: a session nobody uses dies, a session somebody
// uses does not, and the sweep is what removes the first without touching the second.
//
// The tokens are valid until 2100 on purpose. That is exactly the case the idle rule exists for: `exp`
// bounds a credential and says nothing about whether anyone is still there, so if the sweep only ever
// consulted `exp`, everything below would survive forever.
// Build + run via `GEN=ninja make test-cpp`.

#include "acl_test_util.hpp"

#include <thread>

using namespace duckdb;
using namespace acl_test;

namespace {

//! An HS256 token for the issuer the fixture defines: roles ["analyst"], tid=acme, exp in 2100.
const char *const TOKEN =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci50ZXN0L3MiLCJhdWQiOiJhcGk6Ly9hY2w"
    "tdGVzdCIsImV4cCI6NDEwMjQ0NDgwMCwic3ViIjoidSIsInJvbGVzIjpbImFuYWx5c3QiXSwidGlkIjoiYWNtZSJ9.c_RJ0X6_Gj"
    "5O5Z273KOaB9e11XFXVgQkEbtTCayEzJc";

std::string OpenSession(Connection &con) {
	auto result = con.Query(std::string("SELECT acl_session_open('") + TOKEN + "')");
	if (result->HasError() || result->RowCount() == 0) {
		return std::string();
	}
	auto value = result->GetValue(0, 0);
	return value.IsNull() ? std::string() : value.ToString();
}

int64_t Scalar(Connection &con, const std::string &sql) {
	auto result = con.Query(sql);
	if (result->HasError() || result->RowCount() == 0) {
		return -1;
	}
	auto value = result->GetValue(0, 0);
	return value.IsNull() ? -1 : value.GetValue<int64_t>();
}

//! Two sessions, one of them used while the clock runs. Only the untouched one should go.
void IdleGoesAndUsedStays(Connection &con) {
	// Two seconds and 1.5s sleeps, not one second and 1.4s: the clock is whole seconds, so a margin
	// under a second decides the outcome by where the boundary happens to fall.
	Exec(con, "SET GLOBAL acl_session_idle_timeout=2");
	auto idle = OpenSession(con);
	auto kept = OpenSession(con);
	if (!Check(!idle.empty() && !kept.empty(), "two sessions open")) {
		return;
	}
	Check(Scalar(con, "SELECT acl_session_count()") == 2, "both are live");

	// Past the timeout, but the second is used on the way there - resolving a session is what marks it
	// as still in use, so this is the difference between "nobody is there" and "nobody asked lately".
	std::this_thread::sleep_for(std::chrono::milliseconds(1500));
	Check(!con.Query("SELECT acl_session_sql('" + kept + "', 'SELECT 1')")->HasError(), "the kept one is used");
	std::this_thread::sleep_for(std::chrono::milliseconds(1500));

	Check(Scalar(con, "SELECT acl_session_sweep()") == 1, "the sweep takes exactly the idle one");
	Check(Scalar(con, "SELECT acl_session_count()") == 1, "one session left");
	// and the survivor is the one that was used, not merely the one that was luckier
	auto composed = con.Query("SELECT acl_session_sql('" + kept + "', 'SELECT 1')");
	Check(!composed->HasError() && !composed->GetValue(0, 0).IsNull(), "the used session still composes");
	auto gone = con.Query("SELECT acl_session_sql('" + idle + "', 'SELECT 1')");
	Check(!gone->HasError() && gone->GetValue(0, 0).IsNull(), "the idle one no longer composes");

	Exec(con, "SELECT acl_session_close('" + kept + "')");
	Exec(con, "SET GLOBAL acl_session_idle_timeout=900");
}

//! An idle session is refused on use even before anything sweeps: the rule is judged where the session
//! is resolved, so a sweep that never ran cannot leave a dead session usable.
void IdleIsRefusedBeforeAnySweep(Connection &con) {
	Exec(con, "SET GLOBAL acl_session_idle_timeout=1");
	auto handle = OpenSession(con);
	if (!Check(!handle.empty(), "a session opens")) {
		return;
	}
	std::this_thread::sleep_for(std::chrono::milliseconds(2500));
	auto composed = con.Query("SELECT acl_session_sql('" + handle + "', 'SELECT 1')");
	Check(!composed->HasError() && composed->GetValue(0, 0).IsNull(), "an idle session composes nothing");
	Check(Scalar(con, "SELECT acl_session_count()") == 0, "and resolving it dropped the record");
	Exec(con, "SET GLOBAL acl_session_idle_timeout=900");
}

//! Re-authenticating a connection used to leave its previous session behind - unreachable, since the
//! handle is never handed out twice and the binding is gone, but permanent all the same.
void RebindingEndsWhatItReplaces(Connection &con) {
	Exec(con, "SELECT acl_session_sweep()");
	auto before = Scalar(con, "SELECT acl_session_count()");
	Check(!con.Query(std::string("SELECT acl_quack_authenticate('conn-x', '") + TOKEN + "', 'srv')")->HasError(),
	      "a connection authenticates");
	Check(!con.Query(std::string("SELECT acl_quack_authenticate('conn-x', '") + TOKEN + "', 'srv')")->HasError(),
	      "and authenticates again on the same connection");
	Check(Scalar(con, "SELECT acl_session_count()") == before + 1, "one session for the connection, not two");
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
	Exec(con, "SELECT acl_use_db('store','acl',true)");
	Exec(con, "SET GLOBAL acl_allow_anonymous_admin=true");
	Exec(con, "SELECT acl_define_issuer('https://issuer.test/s',"
	          "'{\"keys\":[{\"kty\":\"oct\",\"k\":\"YWNsLXRlc3QtaHMyNTYtc2VjcmV0\"}]}',"
	          "'api://acl-test','HS256','roles','{\"tid\": \"tenant\"}')");
	Exec(con, "ACL ADMIN CREATE ROLE analyst");
	Exec(con, "SET GLOBAL acl_allow_anonymous_admin=false");

	Scenario("idle-goes-and-used-stays", [&]() { IdleGoesAndUsedStays(con); });
	Scenario("idle-is-refused-before-any-sweep", [&]() { IdleIsRefusedBeforeAnySweep(con); });
	Scenario("rebinding-ends-what-it-replaces", [&]() { RebindingEndsWhatItReplaces(con); });

	std::cout << (failures == 0 ? "PASS" : "FAIL") << "\n";
	return failures == 0 ? 0 : 1;
}
