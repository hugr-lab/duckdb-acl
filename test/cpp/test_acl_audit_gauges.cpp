// The audit gauges read under their lock (duckdb-ext-common spec 009): a Remove() waits for a
// snapshot that is calling the reader it removes, so an owner that frees its state after Remove()
// returns never has a reader of it run on freed memory. A reader is held inside Snapshot() here, and
// Remove() on another thread must not return before that reader has finished.
// Build + run via `GEN=ninja make test-cpp`.

#include "acl_test_util.hpp"

#include "acl_audit.hpp"

#include <atomic>
#include <chrono>
#include <thread>

using namespace duckdb;
using namespace acl_test;

int main() {
	return RunMain("the audit gauges read under their lock (ext-common spec 009)", [] {
		Scenario("Remove() waits for the snapshot that is calling the reader it removes", [] {
			acl::AuditGauges gauges;
			std::atomic<bool> reading {false};
			std::atomic<bool> finished {false};
			gauges.Register("owned", {}, "1", "a reader of state its owner frees after Remove()", [&]() {
				reading = true;
				std::this_thread::sleep_for(std::chrono::milliseconds(300));
				finished = true;
				return int64_t(1);
			});
			std::thread snapshot([&] { gauges.Snapshot(); });
			while (!reading) {
				std::this_thread::sleep_for(std::chrono::milliseconds(1));
			}
			gauges.Remove("owned");
			bool reader_done = finished;
			snapshot.join();
			Check(reader_done, "Remove() returned only after the running reader finished");
			Check(gauges.Snapshot().empty(), "and the gauge is gone");
		});

		Scenario("a snapshot still reads every gauge, fixed and dynamic", [] {
			acl::AuditGauges gauges;
			gauges.Register("a", {{"k", "v"}}, "1", "fixed", []() { return int64_t(7); });
			gauges.RegisterDynamic("b", "1", "dynamic", []() {
				vector<std::pair<vector<std::pair<string, string>>, int64_t>> rows;
				rows.push_back({{{"issuer", "x"}}, 3});
				rows.push_back({{{"issuer", "y"}}, 4});
				return rows;
			});
			auto metrics = gauges.Snapshot();
			Check(metrics.size() == 3 && metrics[0].value == 7 && metrics[1].value + metrics[2].value == 7,
			      "one fixed and two dynamic rows");
		});
	});
}
