// spec 066's addendum: the node's counts leave out the calling call's own session - a session of one call (a
// cookie-less Flight call). The load report read them at several looks - the live total, then that session's door and
// group from the list - so a call's session that ended between two of them was counted by the first and found by
// none after: the drain e2e's `sessions_live 2` (a DoGet's session ends while the statement it submitted already
// runs). One look now, `PolicyStore::SessionTallyBesides`. Here: what the tally leaves out (the door's and the
// resource group's counts too), and many calls' sessions ending while the report is read.
// Build + run via `GEN=ninja make test-cpp`.

#include "acl_test_util.hpp"

#include "acl_node_load.hpp"
#include "acl_policy.hpp"

#include <atomic>
#include <thread>

using namespace duckdb;
using namespace acl_test;

namespace {

//! An RS256 token for the issuer the fixture defines: roles ["analyst"], tid=acme, exp in 2100.
const char *const TOKEN =
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2V5In0.eyJpc3MiOiJ0ZXN0L2lkcC9zIiwiYXVkIjoiYXBp"
    "Oi8vYWNsLXRlc3QiLCJleHAiOjQxMDI0NDQ4MDAsInN1YiI6InUiLCJyb2xlcyI6WyJhbmFseXN0Il0sInRpZCI6ImFjbWUifQ.C"
    "2rTehH2D3jptrk0TWAepMNA5XjhgHBCEYVr1NzJm7xa7ygxGtgCV9NpejZV3FFT2ex7QaC5xaoFHy59n5VbOw8I9t5_5qUvGkbDu"
    "SvyEYCLBlzdSczLOn7Su7k9rSIsMVvmbamtp_IhgyF1_ct0e1hm03Q2Vrm509omfcDvs9W8AyV9aPHUWui8bC-7hzw__gyiiZsRH"
    "8PEqZr3JqSPL5FdHp54d7YdGkgMZAR-TkB68NhjvcEmIaNG4Dr2ncL78Brj21nwtTIo3HbeNmhKzUbEp0uwH_-XkV2kxkKQXc2Ty"
    "sjble9-G50jiFYfciBfmh6rGkct3o-XcVwdC3YV1A";

//! The number after `key` in the report (`"sessions":{"live":N`, `"flight":N`), -1 when absent
int64_t NumberAfter(const std::string &json, const std::string &key) {
	auto at = json.find(key);
	if (at == std::string::npos) {
		return -1;
	}
	at += key.size();
	int64_t value = 0;
	bool any = false;
	while (at < json.size() && json[at] >= '0' && json[at] <= '9') {
		value = value * 10 + (json[at] - '0');
		at++;
		any = true;
	}
	return any ? value : -1;
}

//! A session as the Flight door opens one for a cookie-less call: opened, then marked a session of that call
std::string OpenCallSession(acl::PolicyStore &store) {
	auto handle = store.SessionOpen(TOKEN, "flight");
	if (!handle.empty()) {
		store.SessionMarkPerCall(handle);
	}
	return handle;
}

std::string OpsId(acl::PolicyStore &store, const std::string &handle) {
	acl::PolicyStore::SessionRef ref;
	return store.SessionRefOf(handle, ref) ? ref.id : std::string();
}

} // namespace

int main(int argc, char *argv[]) {
	DBConfig config;
	DuckDB db(nullptr, &config);
	Connection con(db);
	// statically linked: the generated extension loader publishes 'acl' on the config
	Exec(con, "LOAD acl");
	Exec(con, "ATTACH ':memory:' AS store");
	Exec(con, "SELECT acl_use_db('store','acl',true)");
	Exec(con, "SET GLOBAL acl_allow_anonymous_admin=true");
	Exec(con, "SET GLOBAL acl_jwks_locations = 'test/idp/'");
	Exec(con, "SELECT acl_define_issuer('test/idp/s', '{\"url\": \"test/idp/s\", \"client\": {\"audiences\": "
	          "[\"api://acl-test\"], \"roles_from\": [\"roles\"], \"attributes\": {\"tid\": \"tenant\"}}}')");
	Exec(con, "ACL ADMIN CREATE ROLE analyst");
	Exec(con, "ACL ADMIN CREATE RESOURCE GROUP g (max_sessions 5)");
	Exec(con, "ACL ADMIN GRANT RESOURCE GROUP g TO ROLE analyst");
	Exec(con, "SET GLOBAL acl_allow_anonymous_admin=false");
	auto store = acl::PolicyStore::Of(*db.instance);
	if (!Check(store != nullptr, "the instance has a policy store")) {
		return 1;
	}

	Scenario("the calling call's own session is left out of every count, a connection-long one is not", [&] {
		auto durable = store->SessionOpen(TOKEN, "flight");
		auto call = OpenCallSession(*store);
		if (!Check(!durable.empty() && !call.empty(), "two sessions open")) {
			return;
		}
		auto besides_call = store->SessionTallyBesides(OpsId(*store, call));
		Check(besides_call.live == 1, "the call's own session is not live to it: " + std::to_string(besides_call.live));
		for (auto &door : besides_call.by_door) {
			if (door.first == "flight") {
				Check(door.second == 1, "...nor at its door: " + std::to_string(door.second));
			}
		}
		Check(besides_call.by_group.size() == 1 && besides_call.by_group[0].first == "g" &&
		          besides_call.by_group[0].second.first == 1 && besides_call.by_group[0].second.second == 5,
		      "...nor in its resource group's");
		auto besides_durable = store->SessionTallyBesides(OpsId(*store, durable));
		Check(besides_durable.live == 2,
		      "a connection-long session is somebody connected, whoever asks: " + std::to_string(besides_durable.live));
		auto report = acl::NodeLoadJson(*db.instance, *store, OpsId(*store, call));
		Check(NumberAfter(report, "\"sessions\":{\"live\":") == 1 && NumberAfter(report, "\"flight\":") == 1,
		      "the load report agrees: " + report);
		store->SessionClose(durable);
		auto alone = store->SessionTallyBesides(OpsId(*store, call));
		Check(alone.live == 0 && alone.by_group.empty(), "a group whose only session is the call's own is not listed");
		Check(store->SessionTallyBesides(std::string()).by_group.size() == 1, "...and is, when nothing is left out");
		store->SessionClose(call);
	});

	Scenario("a call's session that ends while the report is read is in no count", [&] {
		// the race of the drain e2e: the report is asked for by the call whose session closes meanwhile. One closer
		// thread, released per round, waits a different while each round, so the close sweeps across the report's
		// looks (a thread per round lands where its start takes it; read at several looks, the old report was off in
		// a few hundred of these rounds)
		const idx_t rounds = 2000;
		std::atomic<idx_t> go {0}, done {0};
		std::atomic<int> delay {0};
		std::atomic<bool> stop {false};
		std::string target;
		std::thread closer([&]() {
			for (idx_t seen = 0;;) {
				idx_t round;
				while ((round = go.load(std::memory_order_acquire)) == seen) {
					if (stop.load(std::memory_order_acquire)) {
						return;
					}
				}
				seen = round;
				for (volatile int spin = 0; spin < delay.load(std::memory_order_relaxed); spin = spin + 1) {
				}
				store->SessionClose(target);
				done.store(seen, std::memory_order_release);
			}
		});
		struct Joined { // the closer is joined whatever the rounds throw
			std::atomic<bool> &stop;
			std::thread &closer;
			~Joined() {
				stop.store(true, std::memory_order_release);
				closer.join();
			}
		} joined {stop, closer};
		idx_t wrong = 0;
		std::string example;
		for (idx_t i = 0; i < rounds; i++) {
			auto call = OpenCallSession(*store);
			auto id = OpsId(*store, call);
			if (call.empty() || id.empty()) {
				wrong++;
				example = "no session opened";
				continue;
			}
			target = call;
			delay.store(static_cast<int>(i * 37 % 4000), std::memory_order_relaxed);
			go.store(i + 1, std::memory_order_release);
			auto report = acl::NodeLoadJson(*db.instance, *store, id);
			while (done.load(std::memory_order_acquire) != i + 1) {
			}
			if (NumberAfter(report, "\"sessions\":{\"live\":") != 0 || NumberAfter(report, "\"flight\":") != 0) {
				wrong++;
				example = report;
			}
		}
		Check(wrong == 0, std::to_string(wrong) + " of " + std::to_string(rounds) +
		                      " reports counted the calling call's session: " + example);
	});

	std::cout << (failures == 0 ? "PASS" : "FAIL") << "\n";
	return failures == 0 ? 0 : 1;
}
