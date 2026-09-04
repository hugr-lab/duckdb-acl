// The audit contract an extended extension builds on (spec 069), proven from the outside: this TU
// includes acl_audit.hpp - the header-only contract - and nothing else of the extension's, reaches
// the hook registry the way another extension would (through the object cache, BEFORE acl is even
// loaded) and registers a sink and a session policy. It never calls a symbol of acl's: a loadable
// extension is dlopen'd RTLD_LOCAL, so neither could an extension. What it then checks is the base's
// promises: events arrive on a thread that is not the caller's, in order, at the level the policy
// chose; a sink that blocks never slows a decision; a sink that throws is counted and the next event
// still arrives; the counters are a state of the node whatever the level; the Prometheus rendering
// is the same numbers.
// Build + run via `GEN=ninja make test-cpp`.

#include "acl_audit.hpp"
#include "acl_test_util.hpp"

#include <chrono>
#include <thread>

using namespace duckdb;
using namespace acl_test;

namespace {

//! HS256 token for the fixture's issuer: roles ["analyst"], tid=acme, exp in 2100.
const char *const TOKEN =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci50ZXN0L3MiLCJhdWQiOiJhcGk6Ly9hY2wtdGVzdCIsImV4"
    "cCI6NDEwMjQ0NDgwMCwic3ViIjoidWEiLCJyb2xlcyI6WyJhbmFseXN0Il0sInRpZCI6ImFjbWUifQ.pj_vV6OmT_k_3y1MWLBTC_SjngWPkzsFS5"
    "K0iULL6OM";

//! What an OTel exporter is, minus the network: it keeps what it was handed and notes the thread.
struct RecordingSink : acl::AuditSink {
	std::mutex lock;
	vector<acl::AuditEvent> events;
	std::thread::id caller;
	std::atomic<int> off_thread {0};

	void OnEvent(const acl::AuditEvent &event) override {
		std::lock_guard<std::mutex> guard(lock);
		events.push_back(event);
		if (std::this_thread::get_id() != caller) {
			off_thread++;
		}
	}
	vector<acl::AuditEvent> Snapshot() {
		std::lock_guard<std::mutex> guard(lock);
		return events;
	}
};

//! A sink that misbehaves: sleeps on every event. The decision path must not notice.
struct SlowSink : acl::AuditSink {
	std::atomic<int> seen {0};
	void OnEvent(const acl::AuditEvent &) override {
		std::this_thread::sleep_for(std::chrono::milliseconds(150));
		seen++;
	}
};

struct ThrowingSink : acl::AuditSink {
	std::atomic<int> seen {0};
	void OnEvent(const acl::AuditEvent &) override {
		seen++;
		throw std::runtime_error("an exporter that fails");
	}
};

//! The extended extension's rule: analysts are audited at `all`, whatever the instance says.
struct AnalystsAtAll : acl::SessionPolicy {
	bool LevelFor(const acl::Principal &principal, const string &, acl::AuditLevel &out) override {
		for (auto &role : principal.roles) {
			if (role == "analyst") {
				out = acl::AuditLevel::ALL;
				return true;
			}
		}
		return false;
	}
};

std::string OpenSession(Connection &con, const std::string &token) {
	auto result = con.Query("SELECT acl_session_open('" + token + "')");
	if (result->HasError() || result->RowCount() == 0) {
		return std::string();
	}
	auto value = result->GetValue(0, 0);
	return value.IsNull() ? std::string() : value.ToString();
}

//! What a consumer has: the SQL surface. The pipeline itself is acl's and out of reach.
void FlushAudit(Connection &con) {
	Exec(con, "SELECT acl_audit_flush()");
}

} // namespace

int main(int argc, char *argv[]) {
	std::string extension = argc > 1 ? argv[1] : "build/release/extension/acl/acl.duckdb_extension";
	return RunMain("test_acl_audit_hooks: the contract an extended extension builds on (spec 069)", [&]() {
		DBConfig config;
		config.SetOptionByName("allow_unsigned_extensions", Value::BOOLEAN(true));
		DuckDB db(nullptr, &config);

		// --- reached BEFORE acl loads, the way an extension loaded first would ------------------
		auto hooks = db.instance->GetObjectCache().GetOrCreate<acl::AuditHooks>(acl::AuditHooks::ObjectType());
		auto sink = make_shared_ptr<RecordingSink>();
		sink->caller = std::this_thread::get_id();
		hooks->AddSink(sink);
		hooks->SetSessionPolicy(make_shared_ptr<AnalystsAtAll>());

		Connection con(db);
		Exec(con, "LOAD '" + extension + "'");
		auto again = db.instance->GetObjectCache().GetOrCreate<acl::AuditHooks>(acl::AuditHooks::ObjectType());
		Check(again.get() == hooks.get(),
		      "acl adopted the registry created before it loaded (load order is irrelevant)");

		Exec(con, "ATTACH ':memory:' AS store");
		Exec(con, "ATTACH ':memory:' AS phys");
		Exec(con, "CREATE TABLE phys.main.orders(id INTEGER, tenant VARCHAR)");
		Exec(con, "SELECT acl_use_db('store','acl',true)");
		Exec(con, "SET GLOBAL acl_allow_anonymous_admin=true");
		Exec(con, "SELECT acl_define_issuer('https://issuer.test/s',"
		          "'{\"keys\":[{\"kty\":\"oct\",\"k\":\"YWNsLXRlc3QtaHMyNTYtc2VjcmV0\"}]}',"
		          "'api://acl-test','HS256','roles','{\"tid\": \"tenant\"}')");
		Exec(con, "ACL ADMIN CREATE VIRTUAL CATALOG c");
		Exec(con, "ACL ADMIN CREATE VIRTUAL TABLE c.orders AS phys.main.orders");
		Exec(con, "ACL ADMIN CREATE ROLE analyst");
		Exec(con, "ACL ADMIN GRANT CATALOG c TO ROLE analyst MAIN");
		// the instance records refusals only; the policy raises an analyst's session to `all`
		Exec(con, "SET GLOBAL acl_audit_level='denied'");

		Scenario("the policy's level lands on the session, the sink sees it off-thread", [&]() {
			auto handle = OpenSession(con, TOKEN);
			if (!Check(!handle.empty(), "an analyst's session opens")) {
				return;
			}
			Exec(con, "SELECT acl_session_close('" + handle + "')");
			FlushAudit(con);
			auto events = sink->Snapshot();
			Check(events.size() == 2, "the open and the close reached the sink: " + std::to_string(events.size()));
			if (events.size() == 2) {
				Check(events[0].kind == "session" && events[0].detail == "opened", "first the open");
				Check(events[1].detail == "client" && events[1].duration_us >= 0, "then the close, with how long");
				Check(events[0].level == acl::AuditLevel::ALL, "at the policy's level, not the instance's");
				Check(events[0].seq < events[1].seq, "in seq order");
				Check(events[0].principal.subject == "ua" && !events[0].principal.claims.empty(),
				      "the sink receives the whole principal, claims included - filtering is its business");
				Check(events[0].recorded, "a sink only ever sees recorded events");
				Check(!events[0].node.empty(), "the node is named on every event");
			}
			Check(sink->off_thread.load() == 2, "delivered on the audit thread, never the caller's");
		});

		Scenario("a refusal is a denial, recorded at `denied`, counted either way", [&]() {
			auto before = sink->Snapshot().size();
			auto refused = OpenSession(con, "not-a-jwt");
			Check(refused.empty(), "a bad token opens nothing");
			FlushAudit(con);
			auto events = sink->Snapshot();
			Check(events.size() == before + 1, "the refusal reached the sink");
			if (events.size() == before + 1) {
				Check(!events.back().allowed && events.back().reason_code == "principal",
				      "as a denial with reason_code principal");
				Check(events.back().level == acl::AuditLevel::DENIED, "at level denied");
			}
			Check(hooks->Counters().Get("acl.sessions.refused", {{"door", "session"}, {"reason_code", "principal"}}) >=
			          1,
			      "and counted");
		});

		Scenario("a blocking sink costs the audit thread, never the decision", [&]() {
			auto slow = make_shared_ptr<SlowSink>();
			hooks->AddSink(slow);
			auto started = std::chrono::steady_clock::now();
			int opened = 0;
			for (int i = 0; i < 10; i++) {
				auto handle = OpenSession(con, TOKEN);
				if (!handle.empty()) {
					opened++;
					Exec(con, "SELECT acl_session_close('" + handle + "')");
				}
			}
			auto elapsed =
			    std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started);
			Check(opened == 10, "ten sessions opened and closed");
			// twenty events x 150 ms of sink time = 3 s if the caller waited; it does not
			Check(elapsed.count() < 1000, "the twenty decisions took " + std::to_string(elapsed.count()) +
			                                  " ms while the sink would have taken 3000");
			hooks->RemoveSink(slow);
			FlushAudit(con);
			Check(slow->seen.load() > 0, "the slow sink was fed in the meantime: " + std::to_string(slow->seen.load()));
		});

		Scenario("a throwing sink is counted and skipped; the next sink still gets the event", [&]() {
			auto throwing = make_shared_ptr<ThrowingSink>();
			hooks->AddSink(throwing);
			auto before = sink->Snapshot().size();
			auto handle = OpenSession(con, TOKEN);
			Exec(con, "SELECT acl_session_close('" + handle + "')");
			FlushAudit(con);
			hooks->RemoveSink(throwing);
			Check(throwing->seen.load() == 2, "the throwing sink was called for both events");
			Check(sink->Snapshot().size() == before + 2, "the recording sink still received both");
			Check(hooks->Counters().Get("acl.audit.sink_errors", {{"sink", "extension"}}) >= 2,
			      "the errors are counted");
		});

		Scenario("the counters are the node's state and the Prometheus text says the same", [&]() {
			auto opened = hooks->Counters().Get("acl.sessions.opened", {{"door", "session"}});
			Check(opened >= 12, "sessions opened so far: " + std::to_string(opened));
			auto text = acl::RenderPrometheus(*hooks);
			Check(text.find("# TYPE acl_sessions_opened counter") != string::npos, "a TYPE line per counter");
			Check(text.find("acl_sessions_opened{door=\"session\"} " + std::to_string(opened)) != string::npos,
			      "the same number the counter holds");
			Check(text.find("acl_sessions_live") != string::npos, "the gauges render too");
			Check(text.find("acl_node_draining 0") != string::npos, "a gauge without attributes renders bare");
			bool live_seen = false;
			for (auto &metric : hooks->Gauges().Snapshot()) {
				if (metric.name == "acl.sessions.live") {
					live_seen = true;
					Check(metric.value == 0, "no session is live after every close");
				}
			}
			Check(live_seen, "acl.sessions.live is a gauge the store registered");
		});

		Scenario("no event is lost silently: emitted = seen + dropped", [&]() {
			FlushAudit(con);
			auto emitted = hooks->Counters().Get("acl.audit.events", {});
			auto seen = int64_t(sink->Snapshot().size());
			Check(emitted >= seen, "every recorded event the sink saw was counted: " + std::to_string(emitted) +
			                           " >= " + std::to_string(seen));
			auto dropped = con.Query("SELECT acl_audit_dropped()");
			CheckColumn(*dropped, {0}, "nothing was dropped in this run");
		});
	});
}
