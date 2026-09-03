// A session is a handle a door exchanges a token for once (spec 040), and the handle is minted at
// runtime - so the one property that matters most, "ACL SESSION '<handle>' answers exactly as
// ACL TOKEN '<jwt>' does", cannot be written in sqllogictest: the prefix is text scanned before the
// parser runs, and no test file can splice a value into it. Hence a standalone binary.
// Build + run via `GEN=ninja make test-cpp`.

#include "acl_test_util.hpp"

#include <chrono>
#include <thread>

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

//! Why a NULL (spec 054): a client that gets nothing from acl_session_sql learns whether to reopen
//! with the same token or fetch a fresh one. The reason is read-only, so it survives the NULL that
//! prompts it, and a live session reports "live".
std::string ReasonOf(Connection &con, const std::string &handle) {
	auto result = con.Query("SELECT acl_session_reason('" + handle + "')");
	if (result->HasError() || result->RowCount() == 0 || result->GetValue(0, 0).IsNull()) {
		return std::string();
	}
	return result->GetValue(0, 0).ToString();
}

void SessionEndReason(Connection &con) {
	// unknown: a handle no session ever had
	Check(ReasonOf(con, "nosuchhandle") == "unknown", "an unknown handle reads as unknown");

	auto handle = OpenSession(con, TOKEN);
	if (!Check(!handle.empty(), "session opens for the reason check")) {
		return;
	}
	Check(ReasonOf(con, handle) == "live", "a fresh session reads as live");

	// idle: swept for inactivity - the reason must survive the NULL that acl_session_sql returns, so
	// the two calls in sequence (compose -> reason) both see the dead session, not one erasing it
	Exec(con, "SET GLOBAL acl_session_idle_timeout=1");
	std::this_thread::sleep_for(std::chrono::milliseconds(2200));
	auto composed = con.Query("SELECT acl_session_sql('" + handle + "', 'SELECT 1')");
	if (CheckOk(*composed, "acl_session_sql answers for an idle handle")) {
		Check(composed->GetValue(0, 0).IsNull(), "an idle session composes nothing");
	}
	Check(ReasonOf(con, handle) == "idle", "and the reason after the NULL is idle, not unknown");
	Exec(con, "SET GLOBAL acl_session_idle_timeout=900");

	// closed: indistinguishable from never-existed by design (no tombstone), so it reads as unknown
	auto fresh = OpenSession(con, TOKEN);
	Exec(con, "SELECT acl_session_close('" + fresh + "')");
	Check(ReasonOf(con, fresh) == "unknown", "a closed session reads as unknown (reopen with the same token)");
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

//! The ops surface (spec 050): acl_sessions() lists the live sessions by a NON-secret id, and
//! acl_session_kill(id) ends one. Both are the door's - a principal is refused.
void OpsSurfaceListsAndKills(Connection &con) {
	auto open = con.Query("SELECT acl_session_open('opstok')");
	if (!Check(!open->HasError() && !open->GetValue(0, 0).IsNull(), "a session opens for the ops test")) {
		return;
	}
	auto listed = con.Query("SELECT acl_sessions()");
	if (!CheckOk(*listed, "acl_sessions() answers")) {
		return;
	}
	auto json = listed->GetValue(0, 0).ToString();
	Check(json.find("\"analyst\"") != std::string::npos, "the listing carries the principal's role");
	Check(json.find("opstok") == std::string::npos, "the listing never carries the handle");
	// pull the non-secret ops id out of the JSON and kill by it
	auto key = json.find("\"id\":\"");
	if (!Check(key != std::string::npos, "the listing carries an ops id")) {
		return;
	}
	auto start = key + 6;
	auto end = json.find('"', start);
	auto id = json.substr(start, end - start);
	auto killed = con.Query("SELECT acl_session_kill('" + id + "')");
	if (CheckOk(*killed, "acl_session_kill runs")) {
		Check(killed->GetValue(0, 0).GetValue<bool>(), "it reports the session was found");
	}
	auto again = con.Query("SELECT acl_session_kill('" + id + "')");
	Check(!again->HasError() && !again->GetValue(0, 0).GetValue<bool>(),
	      "killing a gone session is false, not an error");
	// a principal may not see or end sessions - the acl_ gate denies the whole surface
	auto denied = con.Query("ACL ROLE \"analyst\" SELECT acl_sessions()");
	Check(denied->HasError(), "a principal is refused the ops listing");
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
	Scenario("role-default-claims-reach-the-session", [&]() {
		// A role that carries the tenant as a DEFAULT claim, and a token that names the role but
		// carries no tenant claim at all: the prefix path merges the default (VerifyPrincipal), and
		// the session must answer identically - it replays what SessionOpen stored, so a merge the
		// session path skipped made the same token return NOTHING through a door (RLS on an absent
		// claim bakes NULL, fail-closed) while the gateway returned the slice. The 2026-09-03 review.
		Exec(con, "ACL ADMIN CREATE ROLE defaulted CLAIMS (tenant = 'acme')");
		Exec(con, "ACL ADMIN GRANT CATALOG c TO ROLE defaulted MAIN");
		const std::string no_tid =
		    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci50ZXN0L3MiLCJhdWQiOiJhcGk6Ly9hY2wt"
		    "dGVzdCIsImV4cCI6NDEwMjQ0NDgwMCwic3ViIjoiZCIsInJvbGVzIjpbImRlZmF1bHRlZCJdfQ."
		    "hBRUGp4u7kgSswo0DSb-3yDV_ZxBpluov1IpAdZ-5nk";
		auto by_token = con.Query("ACL TOKEN '" + no_tid + "' SELECT count(*)::BIGINT FROM orders");
		auto handle = OpenSession(con, no_tid);
		Check(!handle.empty(), "the claim-less token opens a session");
		auto by_session = con.Query("ACL SESSION '" + handle + "' SELECT count(*)::BIGINT FROM orders");
		if (CheckOk(*by_token, "the prefix path answers") && CheckOk(*by_session, "the session path answers")) {
			auto prefix_rows = by_token->GetValue(0, 0).GetValue<int64_t>();
			auto session_rows = by_session->GetValue(0, 0).GetValue<int64_t>();
			Check(prefix_rows == 2,
			      "the prefix path sees the role's default slice (acme): " + std::to_string(prefix_rows));
			Check(session_rows == prefix_rows,
			      "...and the session sees the SAME slice: " + std::to_string(session_rows));
		}
		Exec(con, "SELECT acl_session_close('" + handle + "')");
	});

	Scenario("a session may set its own rendering settings (spec 068)", [&]() {
		// icu carries TimeZone/Calendar; the test binary links it (extension_config.cmake)
		auto icu = con.Query("LOAD icu");
		if (icu->HasError()) {
			std::cout << "  skip: no icu in this build (" << icu->GetError() << ")\n";
			return;
		}
		auto handle = OpenSession(con, TOKEN);
		if (!Check(!handle.empty(), "a session opens for the settings check")) {
			return;
		}
		auto prefix = "ACL SESSION '" + handle + "' ";
		auto render = [&]() {
			auto shown = con.Query(prefix + "SELECT '2026-01-01 00:00:00+00'::TIMESTAMPTZ::VARCHAR");
			return shown->HasError() ? "ERROR: " + shown->GetError() : shown->GetValue(0, 0).ToString();
		};
		auto set = con.Query(prefix + "SET TimeZone = 'Asia/Tokyo'");
		if (CheckOk(*set, "the session sets its time zone")) {
			auto tokyo = render();
			Check(tokyo.find("09:00:00+09") != std::string::npos, "...and renders a TIMESTAMPTZ in it: " + tokyo);
		}
		auto reset = con.Query(prefix + "RESET TimeZone");
		if (CheckOk(*reset, "the session resets it")) {
			auto after = render();
			Check(after.find("+09") == std::string::npos, "...and the zone is the server's again: " + after);
		}
		// the same session may not reach outside the list, nor the node
		auto other = con.Query(prefix + "SET threads = 1");
		Check(other->HasError() && other->GetError().find("not permitted under ACL") != std::string::npos,
		      "a setting outside the list is refused on a session too");
		auto global = con.Query(prefix + "SET GLOBAL TimeZone = 'Asia/Tokyo'");
		Check(global->HasError() && global->GetError().find("SET GLOBAL") != std::string::npos,
		      "GLOBAL is refused on a session too");
		auto computed = con.Query(prefix + "SET TimeZone = (SELECT 'Asia/Tokyo')");
		Check(computed->HasError(), "a non-constant value is refused");
		Exec(con, "SELECT acl_session_close('" + handle + "')");
	});
	Scenario("management and native SQL over a session are the session's scope, exactly (plan 2.2)", [&]() {
		// What a door's client writes after the principal is what a gateway's client writes after
		// the prefix: `ACL <management>` and `ACL NATIVE <sql>` (spec 009). The door composes
		// `ACL SESSION '<h>' ` in front and nothing else, so the same gates decide - the session's
		// principal, its scope resolved per statement (a grant made after the session opened counts),
		// and never the door's own rights. Pinned here because no test ever drove the admin path
		// through a session, and it is the most privileged path a door carries.
		auto handle = OpenSession(con, TOKEN);
		if (!Check(!handle.empty(), "a session opens for the admin-path check")) {
			return;
		}
		auto prefix = "ACL SESSION '" + handle + "' ";
		auto refused_with = [&](const string &sql, const string &needle, const string &what) {
			auto result = con.Query(prefix + sql);
			Check(result->HasError() && result->GetError().find(needle) != std::string::npos,
			      what + ": " + (result->HasError() ? result->GetError() : "it passed"));
		};
		// no scope: neither management nor native, and the refusal names the scope
		refused_with("ACL CREATE ROLE made_over_session", "no ACL administration scope",
		             "a session without a scope may not administer");
		refused_with("ACL NATIVE SELECT acl_drain_status()", "no ACL administration scope", "...nor run native SQL");
		// manage: management yes, native no, admin grants no (never self-escalating)
		Exec(con, "SELECT acl_grant_admin('analyst', 'manage')");
		auto made = con.Query(prefix + "ACL CREATE ROLE made_over_session");
		if (CheckOk(*made, "a manage scope administers over a session")) {
			auto rows = con.Query("SELECT count(*)::BIGINT FROM store.acl.roles WHERE \"role\" = 'made_over_session'");
			Check(!rows->HasError() && rows->GetValue(0, 0).GetValue<int64_t>() == 1,
			      "...and the policy write landed in the catalog");
		}
		refused_with("ACL NATIVE SELECT acl_drain_status()", "requires a passthrough scope",
		             "a manage scope is refused native SQL");
		refused_with("ACL GRANT ADMIN passthrough TO ROLE analyst", "requires a passthrough scope",
		             "a manage scope cannot grant itself passthrough");
		auto still_manage = con.Query(prefix + "ACL NATIVE SELECT 1");
		Check(still_manage->HasError(), "...and it is still not passthrough afterwards");
		// passthrough: native SQL runs - including the node's own control functions. That is the
		// operator path over a door (spec 066 made acl_drain reachable this way on purpose): a
		// passthrough scope is god mode by definition, and a door adds no authority it lacked.
		Exec(con, "SELECT acl_revoke_admin('analyst')");
		Exec(con, "SELECT acl_grant_admin('analyst', 'passthrough')");
		auto native = con.Query(prefix + "ACL NATIVE SELECT acl_drain_status()");
		if (CheckOk(*native, "a passthrough scope runs native SQL over a session")) {
			Check(native->GetValue(0, 0).ToString() == "serving", "...including the node's control surface");
		}
		// the virtual context is unchanged by the scope: the same session still reads its slice
		auto slice = con.Query(prefix + "SELECT count(*)::BIGINT FROM orders");
		Check(!slice->HasError() && slice->GetValue(0, 0).GetValue<int64_t>() == 2,
		      "the virtual context still confines the passthrough principal's ordinary statements");
		Exec(con, "SELECT acl_revoke_admin('analyst')");
		Exec(con, "ACL ADMIN DROP ROLE made_over_session");
		Exec(con, "SELECT acl_session_close('" + handle + "')");
	});
	Exec(con, "SELECT acl_define_token('opstok','analyst','tenant=acme')");
	Scenario("ops-surface-lists-and-kills", [&]() { OpsSurfaceListsAndKills(con); });
	Scenario("session-end-reason", [&]() { SessionEndReason(con); });

	std::cout << (failures == 0 ? "PASS" : "FAIL") << "\n";
	return failures == 0 ? 0 : 1;
}
