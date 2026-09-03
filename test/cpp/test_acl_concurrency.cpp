// Spec 043's in-process half: several principals at once, on one instance, while the policy moves
// under them. What the e2e door harness proves through sockets and real sources, this proves for the
// store and the rewriter themselves - cheaply, deterministically, and under ASan/UBSan in CI
// (SANITIZE=1). It fails fast when the rewriter or the store grows per-instance state that one
// principal's statement could leave for the next.
//
// The isolation assertions are by `id`, never by `tenant` (spec 043's own correction): the grant
// injects `tenant` from the claim, so every row reads back carrying the reader's tenant whatever is
// stored underneath, and a check on that column cannot fail. Each writer owns an id range; reading
// its own range must answer exactly its writes, reading another tenant's range must answer nothing -
// throughout the run, while that tenant writes into it.
//
// Build + run via `GEN=ninja make test-cpp`.

#include "acl_test_util.hpp"

#include <atomic>
#include <chrono>
#include <mutex>
#include <thread>

using namespace duckdb;
using namespace acl_test;

namespace {

//! HS256 tokens for the fixture's issuer (roles/tid; exp in 2100): two tenants of one role, and an
//! auditor role that sees every tenant but not `amount`.
const char *const TOKEN_ACME =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci50ZXN0L3MiLCJhdWQiOiJhcGk6Ly9hY2wtdGVzdCIsImV4"
    "cCI6NDEwMjQ0NDgwMCwic3ViIjoidWEiLCJyb2xlcyI6WyJhbmFseXN0Il0sInRpZCI6ImFjbWUifQ.pj_vV6OmT_k_3y1MWLBTC_SjngWPkzsFS5"
    "K0iULL6OM";
const char *const TOKEN_GLOBEX =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci50ZXN0L3MiLCJhdWQiOiJhcGk6Ly9hY2wtdGVzdCIsImV4"
    "cCI6NDEwMjQ0NDgwMCwic3ViIjoidWciLCJyb2xlcyI6WyJhbmFseXN0Il0sInRpZCI6Imdsb2JleCJ9.DV-dX_z7H-uxTOIX3yDXS0Q2eDP5gimr"
    "26DeTKQaKBo";
const char *const TOKEN_AUDITOR =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci50ZXN0L3MiLCJhdWQiOiJhcGk6Ly9hY2wtdGVzdCIsImV4"
    "cCI6NDEwMjQ0NDgwMCwic3ViIjoiYXVkIiwicm9sZXMiOlsiYXVkaXRvciJdfQ.GLaMBhs876oMzP_stlzO4Vo8uYYbR7rX9r-TvAxkPvY";

//! The writers' id ranges: two per tenant, RANGE ids apart; the seed rows sit below all of them.
constexpr int64_t RANGE = 1000;
constexpr int64_t ACME_BASES[] = {1000, 2000};
constexpr int64_t GLOBEX_BASES[] = {3000, 4000};
constexpr int ROUNDS = 120;

//! Checks made on worker threads are collected, not printed: the test util's counters are the main
//! thread's. The first failure of each kind is kept in words.
struct Report {
	std::atomic<int> failures {0};
	std::atomic<int> checks {0};
	std::mutex lock;
	std::string first;

	void Fail(const std::string &what) {
		failures++;
		std::lock_guard<std::mutex> guard(lock);
		if (first.empty()) {
			first = what;
		}
	}
	void Ok() {
		checks++;
	}
};

std::vector<int64_t> Column(QueryResult &result) {
	std::vector<int64_t> values;
	while (true) {
		auto chunk = result.Fetch();
		if (!chunk || chunk->size() == 0) {
			break;
		}
		for (idx_t row = 0; row < chunk->size(); row++) {
			values.push_back(chunk->GetValue(0, row).GetValue<int64_t>());
		}
	}
	return values;
}

std::string OpenSession(Connection &con, const std::string &token) {
	auto result = con.Query("SELECT acl_session_open('" + token + "')");
	if (result->HasError() || result->RowCount() == 0) {
		return std::string();
	}
	auto value = result->GetValue(0, 0);
	return value.IsNull() ? std::string() : value.ToString();
}

std::string Range(int64_t base) {
	return "id BETWEEN " + std::to_string(base) + " AND " + std::to_string(base + RANGE - 1);
}

//! A writer: its own connection, its own session, its own id range. Each round inserts one row (the
//! grant injects the tenant), reads its range back (exactly its writes, in order) and reads one range
//! of the other tenant (nothing, however many rows that tenant has put there by now).
void Writer(DuckDB &db, const char *token, int64_t base, int64_t foreign_base, Report &report) {
	Connection con(db);
	auto handle = OpenSession(con, token);
	if (handle.empty()) {
		report.Fail("writer " + std::to_string(base) + ": the session did not open");
		return;
	}
	auto prefix = "ACL SESSION '" + handle + "' ";
	std::vector<int64_t> mine;
	for (int round = 0; round < ROUNDS; round++) {
		auto id = base + round;
		auto insert = con.Query(prefix + "INSERT INTO orders (id, amount) VALUES (" + std::to_string(id) + ", " +
		                        std::to_string(round) + ")");
		if (insert->HasError()) {
			report.Fail("writer " + std::to_string(base) + " insert: " + insert->GetError());
			return;
		}
		mine.push_back(id);
		auto own = con.Query(prefix + "SELECT id FROM orders WHERE " + Range(base) + " ORDER BY id");
		if (own->HasError()) {
			report.Fail("writer " + std::to_string(base) + " read: " + own->GetError());
			return;
		}
		if (Column(*own) != mine) {
			report.Fail("writer " + std::to_string(base) + " round " + std::to_string(round) +
			            ": its own range is not exactly its own writes");
			return;
		}
		report.Ok();
		auto foreign = con.Query(prefix + "SELECT id FROM orders WHERE " + Range(foreign_base));
		if (foreign->HasError()) {
			report.Fail("writer " + std::to_string(base) + " foreign read: " + foreign->GetError());
			return;
		}
		if (!Column(*foreign).empty()) {
			report.Fail("writer " + std::to_string(base) + " round " + std::to_string(round) +
			            ": saw a row in the other tenant's range - the slice leaked");
			return;
		}
		report.Ok();
	}
	// a delete under the grant's predicate takes its own rows and nothing else: the first half goes,
	// the second half is exactly what is read back
	auto del = con.Query(prefix + "DELETE FROM orders WHERE id BETWEEN " + std::to_string(base) + " AND " +
	                     std::to_string(base + ROUNDS / 2 - 1));
	if (del->HasError()) {
		report.Fail("writer " + std::to_string(base) + " delete: " + del->GetError());
		return;
	}
	auto after = con.Query(prefix + "SELECT id FROM orders WHERE " + Range(base) + " ORDER BY id");
	std::vector<int64_t> kept(mine.begin() + ROUNDS / 2, mine.end());
	if (after->HasError() || Column(*after) != kept) {
		report.Fail("writer " + std::to_string(base) + ": the delete did not leave exactly the second half");
		return;
	}
	report.Ok();
	con.Query("SELECT acl_session_close('" + handle + "')");
}

//! The auditor: another role on the same object, with a projection that hides `amount`. It reads
//! throughout - every tenant's rows, never the hidden column - while the caches are cleared under it.
void Auditor(DuckDB &db, std::atomic<bool> &stop, Report &report) {
	Connection con(db);
	auto handle = OpenSession(con, TOKEN_AUDITOR);
	if (handle.empty()) {
		report.Fail("auditor: the session did not open");
		return;
	}
	auto prefix = "ACL SESSION '" + handle + "' ";
	int rounds = 0;
	while (!stop.load()) {
		auto count = con.Query(prefix + "SELECT count(*) FROM orders WHERE id < " + std::to_string(ACME_BASES[0]));
		if (count->HasError() || Column(*count) != std::vector<int64_t> {20}) {
			report.Fail("auditor: the seed rows of both tenants are not all there");
			return;
		}
		auto hidden = con.Query(prefix + "SELECT amount FROM orders LIMIT 1");
		if (!hidden->HasError()) {
			report.Fail("auditor round " + std::to_string(rounds) + ": read the column the grant hides");
			return;
		}
		report.Ok();
		rounds++;
	}
	con.Query("SELECT acl_session_close('" + handle + "')");
}

//! The policy moves while everybody works: every write bumps policy_version and clears every cache,
//! so resolution is re-queried under load; the sweep walks the session map while sessions are used.
void Churn(DuckDB &db, std::atomic<bool> &stop, Report &report) {
	Connection con(db);
	int tick = 0;
	while (!stop.load()) {
		auto bump = con.Query("ACL ADMIN COMMENT ON VIRTUAL TABLE c.orders IS 'tick " + std::to_string(tick++) + "'");
		if (bump->HasError()) {
			report.Fail("churn: the policy bump failed: " + bump->GetError());
			return;
		}
		auto sweep = con.Query("SELECT acl_session_sweep()");
		if (sweep->HasError()) {
			report.Fail("churn: the sweep failed: " + sweep->GetError());
			return;
		}
		// sessions come and go beside the ones in use
		auto handle = OpenSession(con, TOKEN_AUDITOR);
		if (handle.empty()) {
			report.Fail("churn: a session did not open");
			return;
		}
		con.Query("SELECT acl_session_close('" + handle + "')");
		report.Ok();
		std::this_thread::sleep_for(std::chrono::milliseconds(3));
	}
}

//! The gateway's shape: ONE connection shared by every principal, each statement carrying its own
//! prefix, interleaved from several threads. Nothing a statement does may reach the next one.
void SharedConnection(Connection &con, const char *token, int64_t own_base, int64_t foreign_base,
                      const std::vector<int64_t> &expected_own, Report &report) {
	auto prefix = std::string("ACL TOKEN '") + token + "' ";
	for (int round = 0; round < 60; round++) {
		auto own = con.Query(prefix + "SELECT id FROM orders WHERE " + Range(own_base) + " ORDER BY id");
		if (own->HasError() || Column(*own) != expected_own) {
			report.Fail("shared connection: a principal's own range came back wrong (round " + std::to_string(round) +
			            ")");
			return;
		}
		auto foreign = con.Query(prefix + "SELECT id FROM orders WHERE " + Range(foreign_base));
		if (foreign->HasError() || !Column(*foreign).empty()) {
			report.Fail("shared connection: a principal saw the other tenant's range (round " + std::to_string(round) +
			            ")");
			return;
		}
		report.Ok();
	}
}

void Summarise(const std::string &name, Report &report) {
	Check(report.failures.load() == 0, name + ": " + std::to_string(report.checks.load()) + " checks, " +
	                                       std::to_string(report.failures.load()) + " failures" +
	                                       (report.first.empty() ? "" : " - first: " + report.first));
}

} // namespace

int main(int argc, char *argv[]) {
	std::string extension = argc > 1 ? argv[1] : "build/release/extension/acl/acl.duckdb_extension";
	return RunMain("test_acl_concurrency: several principals at once, on one instance (spec 043)", [&]() {
		DBConfig config;
		config.SetOptionByName("allow_unsigned_extensions", Value::BOOLEAN(true));
		DuckDB db(nullptr, &config);
		Connection con(db);
		Exec(con, "LOAD '" + extension + "'");
		Exec(con, "ATTACH ':memory:' AS store");
		Exec(con, "ATTACH ':memory:' AS phys");
		Exec(con, "CREATE TABLE phys.main.orders(id INTEGER, tenant VARCHAR, amount INTEGER)");
		Exec(con, "INSERT INTO phys.main.orders SELECT i, CASE WHEN i <= 10 THEN 'acme' ELSE 'globex' END, i "
		          "FROM range(1, 21) t(i)");
		Exec(con, "SELECT acl_use_db('store','acl',true)");
		Exec(con, "SET GLOBAL acl_allow_anonymous_admin=true");
		Exec(con, "SELECT acl_define_issuer('https://issuer.test/s',"
		          "'{\"keys\":[{\"kty\":\"oct\",\"k\":\"YWNsLXRlc3QtaHMyNTYtc2VjcmV0\"}]}',"
		          "'api://acl-test','HS256','roles','{\"tid\": \"tenant\"}')");
		Exec(con, "ACL ADMIN CREATE VIRTUAL CATALOG c");
		Exec(con, "ACL ADMIN CREATE VIRTUAL TABLE c.orders AS phys.main.orders");
		Exec(con, "ACL ADMIN CREATE ROLE analyst");
		Exec(con, "ACL ADMIN CREATE ROLE auditor");
		Exec(con, "ACL ADMIN GRANT CATALOG c TO ROLE analyst WITH (select, insert, delete) MAIN");
		// the writable slice: the predicate confines reads and writes, the assigned column makes every
		// insert land inside it (specs 011/024)
		Exec(con, "ACL ADMIN GRANT TABLE c.orders TO ROLE analyst WITH (select, insert, delete) "
		          "RLS (tenant = acl_claim('tenant')) COLUMNS (id, amount, tenant = acl_claim('tenant'))");
		Exec(con, "ACL ADMIN GRANT CATALOG c TO ROLE auditor WITH (select) MAIN");
		Exec(con, "ACL ADMIN GRANT TABLE c.orders TO ROLE auditor WITH (select) COLUMNS (id, tenant)");

		// --- phase 1: four writers, an auditor and the churn, all at once --------------------------
		Report writers, auditor_report, churn_report;
		std::atomic<bool> stop {false};
		std::vector<std::thread> threads;
		threads.emplace_back(Writer, std::ref(db), TOKEN_ACME, ACME_BASES[0], GLOBEX_BASES[0], std::ref(writers));
		threads.emplace_back(Writer, std::ref(db), TOKEN_ACME, ACME_BASES[1], GLOBEX_BASES[1], std::ref(writers));
		threads.emplace_back(Writer, std::ref(db), TOKEN_GLOBEX, GLOBEX_BASES[0], ACME_BASES[1], std::ref(writers));
		threads.emplace_back(Writer, std::ref(db), TOKEN_GLOBEX, GLOBEX_BASES[1], ACME_BASES[0], std::ref(writers));
		std::thread auditor(Auditor, std::ref(db), std::ref(stop), std::ref(auditor_report));
		std::thread churn(Churn, std::ref(db), std::ref(stop), std::ref(churn_report));
		for (auto &thread : threads) {
			thread.join();
		}
		stop.store(true);
		auditor.join();
		churn.join();
		Summarise("writers (own range exact, foreign range empty, delete confined)", writers);
		Summarise("auditor (every tenant, never the hidden column)", auditor_report);
		Summarise("churn (policy bumps, sweeps, sessions opened and closed)", churn_report);

		// --- what is stored, read natively: no row outside the slice that wrote it -----------------
		auto stray = con.Query("ACL ADMIN SELECT count(*) FROM phys.main.orders WHERE id >= 1000 AND NOT ("
		                       "(tenant = 'acme' AND (id BETWEEN 1000 AND 1999 OR id BETWEEN 2000 AND 2999)) OR "
		                       "(tenant = 'globex' AND (id BETWEEN 3000 AND 3999 OR id BETWEEN 4000 AND 4999)))");
		if (CheckOk(*stray, "the physical table can be read natively")) {
			CheckColumn(*stray, {0}, "no stored row carries a tenant other than its writer's (spec 024)");
		}
		auto totals = con.Query("ACL ADMIN SELECT count(*) FROM phys.main.orders WHERE id >= 1000 GROUP BY tenant "
		                        "ORDER BY tenant");
		if (CheckOk(*totals, "the per-tenant totals can be read")) {
			auto kept = int64_t(ROUNDS - ROUNDS / 2) * 2;
			CheckColumn(*totals, {kept, kept}, "each tenant holds exactly what its two writers kept");
		}
		auto nulls = con.Query("ACL ADMIN SELECT count(*) FROM phys.main.orders WHERE tenant IS NULL");
		if (CheckOk(*nulls, "the NULL-tenant count can be read")) {
			CheckColumn(*nulls, {0}, "every written row got its tenant from the claim");
		}
		auto live = con.Query("SELECT acl_session_count()");
		if (CheckOk(*live, "acl_session_count answers after the run")) {
			CheckColumn(*live, {0}, "every session the run opened is closed again");
		}

		// --- phase 2: one shared connection, both tenants' prefixes interleaved ----------------------
		std::vector<int64_t> acme_kept, globex_kept;
		for (int64_t id = ACME_BASES[0] + ROUNDS / 2; id < ACME_BASES[0] + ROUNDS; id++) {
			acme_kept.push_back(id);
		}
		for (int64_t id = GLOBEX_BASES[0] + ROUNDS / 2; id < GLOBEX_BASES[0] + ROUNDS; id++) {
			globex_kept.push_back(id);
		}
		Report shared;
		Connection gateway(db);
		std::vector<std::thread> mixed;
		for (int i = 0; i < 3; i++) {
			mixed.emplace_back(SharedConnection, std::ref(gateway), TOKEN_ACME, ACME_BASES[0], GLOBEX_BASES[0],
			                   std::cref(acme_kept), std::ref(shared));
			mixed.emplace_back(SharedConnection, std::ref(gateway), TOKEN_GLOBEX, GLOBEX_BASES[0], ACME_BASES[0],
			                   std::cref(globex_kept), std::ref(shared));
		}
		for (auto &thread : mixed) {
			thread.join();
		}
		Summarise("shared connection (six threads, two tenants, one connection)", shared);
	});
}
