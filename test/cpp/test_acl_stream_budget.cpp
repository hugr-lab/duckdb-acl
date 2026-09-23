// The node's stream budget (spec 080): a producing quack statement reserves its worst case, a
// statement that finds the budget full waits in arrival order and is refused - with the reason - when
// the wait runs out. The budget itself (header-only) under threads, then the door: one heavy
// statement holds the only room, a second client is told why it cannot run, and runs once it can.
// Build + run via `GEN=ninja make test-cpp`.

#include "acl_test_util.hpp"

#include "acl_stream_budget.hpp"

#include <atomic>
#include <fstream>
#include <thread>
#include <vector>

using namespace duckdb;
using namespace duckdb::acl;
using namespace acl_test;

namespace {

using ms = std::chrono::milliseconds;

const char *const TOKEN =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci50ZXN0L3MiLCJhdWQiOiJhcGk6Ly9hY2w"
    "tdGVzdCIsImV4cCI6NDEwMjQ0NDgwMCwic3ViIjoidSIsInJvbGVzIjpbImFuYWx5c3QiXSwidGlkIjoiYWNtZSJ9.c_RJ0X6_Gj"
    "5O5Z273KOaB9e11XFXVgQkEbtTCayEzJc";

bool Take(StreamBudget &budget, idx_t bytes, idx_t total, ms wait) {
	bool interrupted = false;
	return budget.Acquire(bytes, total, wait, nullptr, interrupted);
}

bool FileExists(const std::string &path) {
	std::ifstream file(path);
	return file.good();
}

} // namespace

int main(int argc, char *argv[]) {
	std::string extension = argc > 1 ? argv[1] : "build/release/extension/acl/acl.duckdb_extension";
	return RunMain("the node's stream budget (spec 080)", [&] {
		Scenario("a lone stream bigger than the budget runs; 0 means no budget", [] {
			StreamBudget budget;
			Check(Take(budget, 100, 10, ms(0)), "admitted with nothing else reserved - it must run eventually");
			Check(!Take(budget, 1, 10, ms(0)), "and while it holds the room, the next one is not");
			budget.Release(100);
			StreamBudget none;
			Check(Take(none, 100, 0, ms(0)) && Take(none, 100, 0, ms(0)), "budget 0: everything is admitted");
		});

		Scenario("a statement waits for room and runs when it frees", [] {
			StreamBudget budget;
			Take(budget, 8, 10, ms(0));
			auto started = std::chrono::steady_clock::now();
			std::atomic<bool> got {false};
			std::thread waiter([&] { got = Take(budget, 5, 10, ms(3000)); });
			std::this_thread::sleep_for(ms(200));
			Check(budget.Now().queued == 1, "it waits in the queue");
			budget.Release(8);
			waiter.join();
			auto waited = std::chrono::duration_cast<ms>(std::chrono::steady_clock::now() - started).count();
			Check(got && waited >= 180 && waited < 2000,
			      "admitted once the room freed (" + std::to_string(waited) + " ms)");
			Check(budget.Now().reserved == 5 && budget.Now().producing == 1, "and it holds its reservation");
		});

		Scenario("a wait that runs out is refused and counted; an interrupted one is not counted", [] {
			StreamBudget budget;
			Take(budget, 8, 10, ms(0));
			Check(!Take(budget, 5, 10, ms(150)), "refused after its wait");
			Check(budget.Now().refused == 1 && budget.Now().queued == 0, "counted, and out of the queue");
			bool interrupted = false;
			Check(!budget.Acquire(
			          5, 10, ms(3000), [] { return true; }, interrupted) &&
			          interrupted,
			      "a client that went away stops waiting at once");
			Check(budget.Now().refused == 1, "not a refusal of the node's: the client left");
		});

		Scenario("arrival order: a small statement behind a big one does not jump the queue", [] {
			StreamBudget budget;
			Take(budget, 8, 10, ms(0));
			std::vector<std::string> order;
			std::mutex order_lock;
			std::thread big([&] {
				if (Take(budget, 5, 10, ms(3000))) {
					std::lock_guard<std::mutex> guard(order_lock);
					order.emplace_back("big");
				}
			});
			std::this_thread::sleep_for(ms(100));
			std::thread small([&] {
				// 8 + 1 fits now, but the big one arrived first
				if (Take(budget, 1, 10, ms(3000))) {
					std::lock_guard<std::mutex> guard(order_lock);
					order.emplace_back("small");
				}
			});
			std::this_thread::sleep_for(ms(200));
			Check(order.empty(), "neither ran while the first holds the room");
			budget.Release(8);
			big.join();
			small.join();
			Check(order.size() == 2 && order[0] == "big", "the big one ran first");
		});

		Scenario("a statement that gives up in the middle of the queue does not block the ones behind it", [] {
			StreamBudget budget;
			Take(budget, 8, 10, ms(0));
			std::thread quitter([&] { Take(budget, 5, 10, ms(100)); });
			std::this_thread::sleep_for(ms(20));
			std::atomic<bool> got {false};
			std::thread patient([&] { got = Take(budget, 5, 10, ms(3000)); });
			quitter.join(); // gave up at 100 ms, still behind the holder
			std::this_thread::sleep_for(ms(100));
			budget.Release(8);
			patient.join();
			Check(got, "the one behind the quitter got the room");
		});

		// --- the door ------------------------------------------------------------------------------
		auto quack_ext = std::string("build/release/extension/quack/quack.duckdb_extension");
		auto httpfs_ext = std::string("build/release/extension/httpfs/httpfs.duckdb_extension");
		if (!FileExists(quack_ext) || !FileExists(httpfs_ext)) {
			std::cout << "  note: no quack build, the door leg is skipped\n";
			return;
		}
		DBConfig config;
		config.SetOptionByName("allow_unsigned_extensions", Value::BOOLEAN(true));
		DuckDB db(nullptr, &config);
		Connection con(db);
		Exec(con, "LOAD '" + extension + "'");
		Exec(con, "LOAD '" + httpfs_ext + "'");
		Exec(con, "LOAD '" + quack_ext + "'");
		Exec(con, "ATTACH ':memory:' AS store");
		Exec(con, "SELECT acl_use_db('store','acl',true)");
		Exec(con, "SET GLOBAL acl_allow_anonymous_admin=true");
		Exec(con, "SELECT acl_define_issuer('https://issuer.test/s',"
		          "'{\"keys\":[{\"kty\":\"oct\",\"k\":\"YWNsLXRlc3QtaHMyNTYtc2VjcmV0\"}]}',"
		          "'api://acl-test','HS256','roles','{\"tid\": \"tenant\"}')");
		Exec(con, "ACL ADMIN CREATE VIRTUAL CATALOG c");
		// the view's SQL is the administrator's: its work runs on the server, holding the reservation
		Exec(con, "ACL ADMIN CREATE VIRTUAL VIEW c.heavy AS SELECT sum(length(md5(md5(md5(i::VARCHAR))))) AS h "
		          "FROM range(15000000) t(i)");
		Exec(con, "ACL ADMIN CREATE VIRTUAL VIEW c.light AS SELECT 42 AS answer");
		Exec(con, "ACL ADMIN CREATE ROLE analyst");
		Exec(con, "ACL ADMIN GRANT CATALOG c TO ROLE analyst WITH (select) MAIN");
		Exec(con, "SET GLOBAL acl_allow_anonymous_admin=false");
		// room for exactly one producing statement, and a short wait
		Exec(con, "SET GLOBAL acl_node_stream_budget = 1");
		Exec(con, "SET GLOBAL acl_stream_queue_timeout = 1");
		Exec(con, "SELECT acl_quack_serve('quack:localhost:31598', 'budget-server-token')");
		auto through = [&](const std::string &view) {
			return std::string("SELECT * FROM quack_query('quack:localhost:31598', 'SELECT * FROM ") + view +
			       "', token := '" + TOKEN + "')";
		};

		Scenario("the door: a statement that finds the budget full is told why, and runs once it frees", [&] {
			std::atomic<bool> heavy_ok {false};
			std::thread heavy([&] {
				Connection holder(db);
				auto result = holder.Query(through("heavy"));
				heavy_ok = !result->HasError();
			});
			std::this_thread::sleep_for(ms(400));
			Connection second(db);
			auto refused = second.Query(through("light"));
			Check(refused->HasError() && refused->GetError().find("stream memory budget") != std::string::npos,
			      "refused with the reason: " + (refused->HasError() ? refused->GetError() : "it ran"));
			heavy.join();
			Check(heavy_ok, "the holder finished");
			auto after = second.Query(through("light"));
			Check(!after->HasError() && after->RowCount() == 1 && after->GetValue(0, 0).GetValue<int32_t>() == 42,
			      "the same statement runs once the room is free");
			auto load = con.Query("SELECT acl_node_load()::VARCHAR");
			if (CheckOk(*load, "acl_node_load answers")) {
				auto json = load->GetValue(0, 0).ToString();
				Check(json.find("\"refused\":1") != std::string::npos &&
				          json.find("\"producing\":0") != std::string::npos,
				      "the report counts the refusal and nothing producing now: " + json);
			}
		});
		Exec(con, "SELECT acl_quack_stop('quack:localhost:31598')");
	});
}
