// The acl_connection contract, acl's side (spec 078): what another extension - tresor - sees of acl's
// sessions. This binary plays that extension, reaching every object the way it would: by name, from
// duckdb-ext-common's contracts/acl_connection.hpp, checked by its stamp. (acl is linked statically
// into the libduckdb it uses and loads with the instance; the observer registers after that, which
// works because acl reads the observers at every call.)
//
//   - a registered observer hears every session open (the verified token by reference, during the
//     call) and exactly one close per open, after it, whatever ended the session: the client,
//     an operator's kill, idleness, the instance going away;
//   - while a statement runs under ACL SESSION, AclConnection on its connection names the session;
//     before, after and between statements, and after a statement that failed, it names nothing;
//   - an observer that throws never fails an open; a registry stamped with another contract version
//     is never called; the token appears in no listing and no audit event.
// Build + run via `GEN=ninja make test-cpp`.

#include "acl_test_util.hpp"

#include "acl_connection.hpp"

#include "duckdb/catalog/catalog.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/parser/parsed_data/create_scalar_function_info.hpp"

#include <chrono>
#include <fstream>
#include <map>
#include <thread>

using namespace duckdb;
using namespace duckdb::acl;
using namespace acl_test;

namespace {

//! An HS256 token for the fixture issuer: sub u, roles ["analyst"], tid=acme, exp 4102444800 (2100).
const char *const TOKEN =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci50ZXN0L3MiLCJhdWQiOiJhcGk6Ly9hY2w"
    "tdGVzdCIsImV4cCI6NDEwMjQ0NDgwMCwic3ViIjoidSIsInJvbGVzIjpbImFuYWx5c3QiXSwidGlkIjoiYWNtZSJ9.c_RJ0X6_Gj"
    "5O5Z273KOaB9e11XFXVgQkEbtTCayEzJc";
const char *const ISSUER = "https://issuer.test/s";

//! What an observer saw, in order.
struct Seen {
	std::string kind; // open / close
	std::string session_id;
	std::string reason;
	SessionOpenInfo info;
	bool token_matched = false;
};

class FakeObserver : public SessionObserver {
public:
	void OnSessionOpen(const SessionOpenInfo &info, const string &access_token) override {
		std::lock_guard<std::mutex> guard(lock);
		Seen seen;
		seen.kind = "open";
		seen.session_id = info.session_id;
		seen.info = info;
		seen.token_matched = access_token == TOKEN; // compared during the call, never kept
		events.push_back(seen);
		if (throw_on_open) {
			throw std::runtime_error("an observer that fails");
		}
	}
	void OnSessionClose(const string &session_id, const string &reason) override {
		std::lock_guard<std::mutex> guard(lock);
		Seen seen;
		seen.kind = "close";
		seen.session_id = session_id;
		seen.reason = reason;
		events.push_back(seen);
	}
	std::vector<Seen> Events() {
		std::lock_guard<std::mutex> guard(lock);
		return events;
	}
	//! Every session this observer heard open: opened once, closed at most once, never closed first.
	bool Ordered(std::string &why) {
		std::map<std::string, int> state; // 1 open, 2 closed
		for (auto &seen : Events()) {
			auto &now = state[seen.session_id];
			if (seen.kind == "open") {
				if (now != 0) {
					why = "opened twice: " + seen.session_id;
					return false;
				}
				now = 1;
			} else {
				if (now == 0) {
					continue; // a session this observer never saw open (it registered later) may close
				}
				if (now == 2) {
					why = "closed twice: " + seen.session_id;
					return false;
				}
				now = 2;
			}
		}
		return true;
	}
	bool throw_on_open = false;

private:
	std::mutex lock;
	std::vector<Seen> events;
};

//! session_probe(): the session AclConnection shows on the calling connection right now
//! ("<id>|<door>|<subject>|<issuer>|<has opened_at>|<has expires_at>"), or "none".
void SessionProbe(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &context = state.GetContext();
	string why;
	auto connection = AclConnection::Reach(context, why);
	AclSessionView view;
	string out = "none";
	if (connection && connection->Current(view)) {
		out = view.session_id + "|" + view.door + "|" + view.principal.subject + "|" + view.principal.issuer + "|" +
		      (view.opened_at > 0 ? "1" : "0") + "|" + (view.expires_at == 4102444800 ? "1" : "0");
	}
	result.Reference(Value(out), count_t(MaxValue<idx_t>(args.size(), 1)));
}

void RegisterProbe(DuckDB &db, Connection &con) {
	ScalarFunction probe("session_probe", {}, LogicalType::VARCHAR, SessionProbe);
	probe.SetStability(FunctionStability::VOLATILE);
	CreateScalarFunctionInfo info(probe);
	con.BeginTransaction();
	Catalog::GetSystemCatalog(*con.context).CreateFunction(*con.context, info);
	con.Commit();
}

bool FileExists(const std::string &path) {
	std::ifstream file(path);
	return file.good();
}

std::string Scalar(Connection &con, const std::string &sql) {
	auto result = con.Query(sql);
	if (result->HasError()) {
		return "ERROR: " + result->GetError();
	}
	if (result->RowCount() == 0) {
		return "(no rows)";
	}
	auto value = result->GetValue(0, 0);
	return value.IsNull() ? "NULL" : value.ToString();
}

std::string OpenSession(Connection &con) {
	auto handle = Scalar(con, std::string("SELECT acl_session_open('") + TOKEN + "')");
	return handle.rfind("ERROR", 0) == 0 || handle == "NULL" ? std::string() : handle;
}

//! The ops id acl_sessions() lists for the last session of this instance (the listing's `id`).
std::string LastSessionId(Connection &con) {
	auto json = Scalar(con, "SELECT acl_sessions()::VARCHAR");
	auto key = json.rfind("\"id\":\"");
	if (key == std::string::npos) {
		return std::string();
	}
	auto start = key + 6;
	return json.substr(start, json.find('"', start) - start);
}

int64_t Gauge(Connection &con, const std::string &name) {
	auto value = Scalar(con, "SELECT value FROM acl_metrics() WHERE name = '" + name + "'");
	try {
		return std::stoll(value);
	} catch (...) {
		return INT64_MIN;
	}
}

void Fixture(Connection &con, const std::string &extension) {
	Exec(con, "LOAD '" + extension + "'");
	Exec(con, "ATTACH ':memory:' AS store");
	Exec(con, "ATTACH ':memory:' AS phys");
	Exec(con, "CREATE TABLE phys.main.orders(id INTEGER, tenant VARCHAR)");
	Exec(con, "INSERT INTO phys.main.orders VALUES (1,'acme'),(2,'globex')");
	Exec(con, "SELECT acl_use_db('store','acl',true)");
	Exec(con, "SET GLOBAL acl_allow_anonymous_admin=true");
	Exec(con, std::string("SELECT acl_define_issuer('") + ISSUER +
	              "','{\"keys\":[{\"kty\":\"oct\",\"k\":\"YWNsLXRlc3QtaHMyNTYtc2VjcmV0\"}]}',"
	              "'api://acl-test','HS256','roles','{\"tid\": \"tenant\"}')");
	Exec(con, "ACL ADMIN CREATE VIRTUAL CATALOG c");
	Exec(con, "ACL ADMIN CREATE VIRTUAL TABLE c.orders AS phys.main.orders RLS 'tenant = acl_claim(''tenant'')'");
	Exec(con, "ACL ADMIN CREATE ROLE analyst");
	Exec(con, "ACL ADMIN GRANT CATALOG c TO ROLE analyst MAIN");
	// the probe is a function a principal may call: granted by name to every role
	Exec(con, "SELECT acl_grant_function('', 'system.main.session_probe')");
}

} // namespace

int main(int argc, char *argv[]) {
	std::string extension = argc > 1 ? argv[1] : "build/release/extension/acl/acl.duckdb_extension";
	return RunMain("the acl_connection contract, acl's side (spec 078)", [&] {
		DBConfig config;
		config.SetOptionByName("allow_unsigned_extensions", Value::BOOLEAN(true));
		DuckDB db(nullptr, &config);
		Connection con(db);
		// the consumer registers whenever it loads: acl reads the registry's observers at every call
		auto observer = make_shared_ptr<FakeObserver>();
		string why;
		auto hooks = AclSessionHooks::Reach(db.instance->GetObjectCache(), why);
		if (!Check(hooks != nullptr, "the registry is reachable: " + why)) {
			return;
		}
		hooks->AddObserver(observer);
		RegisterProbe(db, con);
		Fixture(con, extension);

		std::string handle, id;
		Scenario("an open reaches the observer with who, where and the token - before the handle is anyone's", [&] {
			handle = OpenSession(con);
			if (!Check(!handle.empty(), "a verified token opens a session")) {
				return;
			}
			auto events = observer->Events();
			if (!Check(events.size() == 1 && events[0].kind == "open", "exactly one open was delivered")) {
				return;
			}
			auto &info = events[0].info;
			id = LastSessionId(con);
			Check(!id.empty() && info.session_id == id, "the open names the ops id acl_sessions() lists");
			Check(info.session_id != handle, "never the handle");
			Check(info.principal.subject == "u" && info.principal.issuer == ISSUER, "the principal: subject, issuer");
			Check(info.token_issuer == ISSUER, "the token's issuer, to exchange it at");
			Check(info.door == "session" && info.opened_at > 0 && info.expires_at == 4102444800,
			      "the door, the open time, the token's exp");
			Check(events[0].token_matched, "the verified token, by reference during the call");
		});

		Scenario("a statement under the session shows it on its connection, and only while it runs", [&] {
			Check(Scalar(con, "SELECT session_probe()") == "none", "before: the connection runs under no session");
			auto during = Scalar(con, "ACL SESSION '" + handle + "' SELECT session_probe()");
			Check(during == id + "|session|u|" + ISSUER + "|1|1", "during: the session, whole (" + during + ")");
			Check(Scalar(con, "SELECT session_probe()") == "none", "after: withdrawn");
			// a batch: every statement of it runs under the session, and the last result says so
			auto batch = Scalar(con, "ACL SESSION '" + handle + "' SELECT session_probe(); SELECT session_probe()");
			Check(batch == during, "each statement of a batch (" + batch + ")");
			Check(Scalar(con, "SELECT session_probe()") == "none", "after the batch: withdrawn");
			// a statement that fails at execution still takes its session off the connection
			auto failed = con.Query("ACL SESSION '" + handle +
			                        "' SELECT session_probe(), CAST('x' || id AS INTEGER) "
			                        "FROM orders");
			Check(failed->HasError(), "the failing statement fails");
			Check(Scalar(con, "SELECT session_probe()") == "none", "after a failure: withdrawn");
			// a token prefix is a principal without a session: nothing to show
			auto token_form = Scalar(con, std::string("ACL TOKEN '") + TOKEN + "' SELECT session_probe()");
			Check(token_form == "none", "ACL TOKEN runs under no session (" + token_form + ")");
		});

		Scenario("the token is kept nowhere acl shows", [&] {
			std::string signature = std::string(TOKEN).substr(std::string(TOKEN).rfind('.') + 1);
			Check(Scalar(con, "SELECT acl_sessions()::VARCHAR").find(signature) == std::string::npos,
			      "not in the session listing");
			Exec(con, "SELECT acl_audit_flush()");
			auto audit = Scalar(con, "SELECT string_agg(e::VARCHAR, ' ') FROM acl_audit_events() e");
			Check(audit.find(signature) == std::string::npos, "not in any audit event");
		});

		Scenario("every end is one close, after its open: client, kill, idle", [&] {
			Exec(con, "SELECT acl_session_close('" + handle + "')");
			auto killed = OpenSession(con);
			auto killed_id = LastSessionId(con);
			Exec(con, "SELECT acl_session_kill('" + killed_id + "')");
			Exec(con, "SET GLOBAL acl_session_idle_timeout = 1");
			auto idle = OpenSession(con);
			auto idle_id = LastSessionId(con);
			std::this_thread::sleep_for(std::chrono::milliseconds(2200));
			Exec(con, "SELECT acl_session_sweep()");
			Exec(con, "SET GLOBAL acl_session_idle_timeout = 900");
			std::map<std::string, std::string> closed;
			for (auto &seen : observer->Events()) {
				if (seen.kind == "close") {
					closed[seen.session_id] = seen.reason;
				}
			}
			Check(closed[id] == "client", "acl_session_close: client (" + closed[id] + ")");
			Check(closed[killed_id] == "killed", "acl_session_kill: killed (" + closed[killed_id] + ")");
			Check(closed[idle_id] == "idle", "idle past the timeout: idle (" + closed[idle_id] + ")");
			std::string order;
			Check(observer->Ordered(order), "one open, then one close, per session: " + order);
		});

		Scenario("an observer that throws never fails an open", [&] {
			observer->throw_on_open = true;
			auto before = Gauge(con, "acl.sessions.observer_failures");
			auto opened = OpenSession(con);
			observer->throw_on_open = false;
			Check(!opened.empty(), "the session opens regardless");
			Check(Gauge(con, "acl.sessions.observer_failures") == before + 1, "the failure is counted");
			Check(Gauge(con, "acl.sessions.observers") == 1, "one observer registered");
			Exec(con, "SELECT acl_session_close('" + opened + "')");
		});

		Scenario("through a real door: a quack client's statement runs under its session", [&] {
			auto quack_ext = std::string("build/release/extension/quack/quack.duckdb_extension");
			auto httpfs_ext = std::string("build/release/extension/httpfs/httpfs.duckdb_extension");
			if (!FileExists(quack_ext) || !FileExists(httpfs_ext)) {
				std::cout << "  note: no quack build, the door leg is skipped\n";
				return;
			}
			Exec(con, "LOAD '" + httpfs_ext + "'");
			Exec(con, "LOAD '" + quack_ext + "'");
			Exec(con, "SET GLOBAL acl_allow_anonymous_admin=false");
			Exec(con, "SELECT acl_quack_serve('quack:localhost:31596', 'hooks-server-token')");
			auto seen = observer->Events().size();
			auto through = Scalar(con, std::string("SELECT * FROM quack_query('quack:localhost:31596', ") +
			                               "'SELECT session_probe()', token := '" + TOKEN + "')");
			auto events = observer->Events();
			std::string door_id;
			for (auto i = seen; i < events.size(); i++) {
				if (events[i].kind == "open" && events[i].info.door == "quack") {
					door_id = events[i].session_id;
				}
			}
			Check(!door_id.empty(), "the door's session open reached the observer, door quack");
			Check(through == door_id + "|quack|u|" + ISSUER + "|1|1",
			      "the statement the door ran shows that session (" + through + ")");
			Exec(con, "SELECT acl_quack_stop('quack:localhost:31596')");
			bool closed = false;
			for (auto &event : observer->Events()) {
				closed = closed || (event.kind == "close" && event.session_id == door_id);
			}
			Check(closed, "stopping the door closes its session, and the observer hears it");
			Exec(con, "SET GLOBAL acl_allow_anonymous_admin=true");
		});

		Scenario("the instance going away closes what is still open: shutdown", [&] {
			auto other = make_shared_ptr<FakeObserver>();
			std::string other_id;
			{
				DuckDB second(nullptr, &config);
				Connection con2(second);
				string reach_why;
				auto second_hooks = AclSessionHooks::Reach(second.instance->GetObjectCache(), reach_why);
				second_hooks->AddObserver(other);
				RegisterProbe(second, con2);
				Fixture(con2, extension);
				Check(!OpenSession(con2).empty(), "a session in the second instance");
				other_id = LastSessionId(con2);
			}
			auto events = other->Events();
			bool shut = !events.empty() && events.back().kind == "close" && events.back().session_id == other_id &&
			            events.back().reason == "shutdown";
			Check(shut, "its close says shutdown");
			Check(observer->Events().size() > 0 && observer->Events().back().session_id != other_id,
			      "the first instance's observer heard nothing of the second's");
		});

		Scenario("a registry stamped with another contract is refused by Reach", [&] {
			// acl is linked statically into the libduckdb this binary uses, so it reaches the registry when
			// the instance is created - before a test could stamp one otherwise. What is checkable here is
			// the contract's own refusal, which is all either side ever goes through.
			DuckDB third(nullptr, &config);
			auto foreign = third.instance->GetObjectCache().GetOrCreate<AclSessionHooks>(AclSessionHooks::ObjectType());
			auto kept = foreign->contract_version;
			foreign->contract_version = AclConnectionContract::VERSION + 98; // built from another revision
			string reach_why;
			Check(AclSessionHooks::Reach(third.instance->GetObjectCache(), reach_why) == nullptr &&
			          reach_why.find("another acl_connection contract") != string::npos,
			      "Reach refuses it and says why (" + reach_why + ")");
			foreign->contract_version = kept;
			Connection con3(third);
			string state_why;
			auto state = AclConnection::Reach(*con3.context, state_why);
			if (Check(state != nullptr, "a connection's state is reachable")) {
				state->contract_magic = 0; // no stamp at all
				Check(AclConnection::Reach(*con3.context, state_why) == nullptr, "an unstamped state is refused");
				state->contract_magic = AclConnectionContract::MAGIC;
			}
		});
	});
}
