// Shared scaffolding for the standalone C++ invariant tests (specs/002): a global failure count,
// small check helpers that read GetError() only after HasError(), fail-fast setup, and a per-scenario
// wrapper so one aborted scenario cannot mask the others.

#pragma once

#include "duckdb.hpp"

#include <functional>
#include <iostream>
#include <string>
#include <vector>

namespace acl_test {

inline int failures = 0;

//! Record one check; returns ok so a scenario can short-circuit without ending the program
inline bool Check(bool ok, const std::string &what) {
	std::cout << (ok ? "  ok:   " : "  FAIL: ") << what << "\n";
	if (!ok) {
		failures++;
	}
	return ok;
}

//! Check a result / prepared statement for success; reads GetError() only on failure
template <class T>
bool CheckOk(T &object, const std::string &what) {
	if (!object.HasError()) {
		return Check(true, what);
	}
	return Check(false, what + ": " + object.GetError());
}

//! Run a setup statement that must succeed; throws to abort the whole test on failure
inline void Exec(duckdb::Connection &con, const std::string &sql) {
	auto result = con.Query(sql);
	if (result->HasError()) {
		throw std::runtime_error("setup failed: " + sql + ": " + result->GetError());
	}
}

//! Fetch the whole first column as int64 and compare. Checks the error state both before fetching
//! (an errored materialized result throws on Fetch) and after the loop (a stream sets it mid-fetch).
inline bool CheckColumn(duckdb::QueryResult &result, const std::vector<int64_t> &expected, const std::string &what) {
	if (result.HasError()) {
		return Check(false, what + ": " + result.GetError());
	}
	std::vector<int64_t> values;
	while (true) {
		auto chunk = result.Fetch();
		if (!chunk || chunk->size() == 0) {
			break;
		}
		for (duckdb::idx_t row = 0; row < chunk->size(); row++) {
			values.push_back(chunk->GetValue(0, row).GetValue<int64_t>());
		}
	}
	if (result.HasError()) {
		return Check(false, what + ": " + result.GetError());
	}
	return Check(values == expected, what);
}

//! Run one scenario, converting an escaped exception into a single failed check - the remaining
//! scenarios still run, so one regression cannot hide another
inline void Scenario(const std::string &name, const std::function<void()> &body) {
	try {
		body();
	} catch (std::exception &ex) {
		Check(false, name + " aborted: " + std::string(ex.what()));
	}
}

//! Shared main body: runs the test, converts a setup exception into a failure, reports PASS/FAIL
inline int RunMain(const std::string &banner, const std::function<void()> &test) {
	std::cout << banner << "\n";
	try {
		test();
	} catch (std::exception &ex) {
		std::cout << "  FAIL: " << ex.what() << "\n";
		failures++;
	}
	std::cout << (failures == 0 ? "PASS" : "FAIL") << "\n";
	return failures == 0 ? 0 : 1;
}

} // namespace acl_test
