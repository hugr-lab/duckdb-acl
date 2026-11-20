// spec 177 (hugr-node spec 035 stage 2): a source the node keeps lazy is attached on demand - by the rewrite of a
// principal's statement that reads it (a relation's physical name, or a database a policy text in the rewritten
// statement names), again before an execution of a statement decided earlier (QueryBegin), and before a policy
// write's probes and the catalog's check. A listing never wakes one. The traits are the platform part's
// (PolicyStore::NodeTraits::lazy_sources / attach_on_demand); here they are set by hand.
// Build + run via `GEN=ninja make test-cpp`.

#include "acl_test_util.hpp"

#include "acl_policy.hpp"

#include <cstdio>

using namespace duckdb;
using namespace acl_test;

namespace {

//! the error of a statement, or "" when it ran
std::string ErrorOf(Connection &con, const std::string &sql) {
	auto result = con.Query(sql);
	return result->HasError() ? result->GetError() : std::string();
}

bool Attached(Connection &con, const std::string &name) {
	auto result = con.Query("SELECT count(*) FROM duckdb_databases() WHERE database_name = '" + name + "'");
	return !result->HasError() && result->Collection().GetValue(0, 0).GetValue<int64_t>() == 1;
}

} // namespace

int main(int argc, char *argv[]) {
	return RunMain("spec 177: a source attached on demand", [] {
		const std::string path = "build/test_acl_lazy_sources.duckdb";
		std::remove(path.c_str());
		std::remove((path + ".wal").c_str());
		DBConfig config;
		DuckDB db(nullptr, &config);
		Connection con(db);
		Exec(con, "LOAD acl");
		Exec(con, "ATTACH ':memory:' AS store");
		Exec(con, "SELECT acl_use_db('store','acl',true)");
		Exec(con, "SET GLOBAL acl_allow_anonymous_admin=true");
		Exec(con, "ATTACH '" + path + "' AS lazy");
		Exec(con, "CREATE TABLE lazy.main.t AS SELECT 1 AS a");
		Exec(con, "CREATE TABLE lazy.main.u AS SELECT 2 AS b");
		Exec(con, "CREATE TABLE lazy.main.w AS SELECT 3 AS c");
		Exec(con, "ATTACH ':memory:' AS steady");
		Exec(con, "CREATE TABLE steady.main.s AS SELECT 4 AS d");
		Exec(con, "ACL ADMIN CREATE ROLE analyst");
		Exec(con, "ACL ADMIN CREATE VIRTUAL CATALOG c");
		Exec(con, "ACL ADMIN CREATE VIRTUAL TABLE c.t AS lazy.main.t");
		// an operator's view: its SQL names the source - only the rewritten statement shows it
		Exec(con, "ACL ADMIN CREATE VIRTUAL VIEW c.v AS 'SELECT b FROM lazy.main.u'");
		Exec(con, "ACL ADMIN CREATE VIRTUAL TABLE c.s AS steady.main.s");
		// a live schema alias: its objects resolve to the source's tables at the read
		Exec(con, "ACL ADMIN CREATE VIRTUAL SCHEMA c.arch AS lazy.main");
		Exec(con, "ACL ADMIN GRANT CATALOG c TO ROLE analyst WITH (select, insert, delete) MAIN");
		auto store = acl::PolicyStore::Of(*db.instance);
		if (!Check(store != nullptr, "the instance has a policy store")) {
			return;
		}
		const std::string principal = "ACL ROLE 'analyst' ";

		std::vector<std::string> calls;
		std::string failure;
		store->node_traits.lazy_sources = [] {
			return vector<string> {"lazy"};
		};
		store->node_traits.attach_on_demand = [&](const string &alias) {
			calls.push_back(alias);
			if (!failure.empty()) {
				throw InvalidInputException(failure);
			}
			Connection own(db);
			auto attached = own.Query("SELECT count(*) FROM duckdb_databases() WHERE database_name = '" + alias + "'");
			if (attached->Collection().GetValue(0, 0).GetValue<int64_t>() == 0) {
				auto result = own.Query("ATTACH '" + path + "' AS " + alias);
				if (result->HasError()) {
					throw InvalidInputException("acl: source %s could not be attached", alias);
				}
			}
		};
		auto detach = [&] {
			Exec(con, "DETACH DATABASE IF EXISTS lazy");
			calls.clear();
		};

		Scenario("a relation's physical name in a lazy source attaches it", [&] {
			detach();
			auto result = con.Query(principal + "SELECT a FROM t");
			CheckColumn(*result, {1}, "the read of the lazy source");
			Check(!calls.empty() && calls.front() == "lazy", "the trait was asked for the source");
			Check(Attached(con, "lazy"), "the source is attached");
		});

		Scenario("a database a policy text names (an operator's view) attaches it", [&] {
			detach();
			auto result = con.Query(principal + "SELECT b FROM v");
			CheckColumn(*result, {2}, "the view over the lazy source");
			Check(Attached(con, "lazy"), "the view's source is attached");
		});

		Scenario("a live schema alias over a lazy source attaches it", [&] {
			detach();
			auto result = con.Query(principal + "SELECT a FROM arch.t");
			CheckColumn(*result, {1}, "the read through the alias");
			Check(Attached(con, "lazy"), "the alias's source is attached");
		});

		Scenario("a write into a lazy source attaches it (an INSERT's target is the node's name)", [&] {
			detach();
			auto error = ErrorOf(con, principal + "INSERT INTO t VALUES (5)");
			Check(error.empty(), "the INSERT: " + error);
			Check(Attached(con, "lazy"), "the target's source is attached");
			detach();
			error = ErrorOf(con, principal + "DELETE FROM t WHERE a = 5");
			Check(error.empty(), "the DELETE: " + error);
		});

		Scenario("negative: a principal's own physical name wakes nothing - it is refused first", [&] {
			detach();
			auto error = ErrorOf(con, principal + "SELECT * FROM lazy.main.t");
			Check(!error.empty(), "the physical name is refused: " + error);
			Check(calls.empty(), "the trait was not asked");
		});

		Scenario("negative: a management call the principal may not make wakes nothing", [&] {
			detach();
			auto error = ErrorOf(con, principal + "CREATE ROLE refused_by_rights");
			Check(!error.empty(), "the write is refused: " + error);
			Check(calls.empty(), "the trait was not asked");
		});

		Scenario("a statement reading no lazy source wakes none", [&] {
			detach();
			auto result = con.Query(principal + "SELECT d FROM s");
			CheckColumn(*result, {4}, "the read of another source");
			Check(calls.empty(), "the trait was not asked");
			Check(!Attached(con, "lazy"), "the lazy source stays detached");
		});

		Scenario("a listing never wakes a source", [&] {
			detach();
			auto tables = ErrorOf(con, principal + "SELECT * FROM information_schema.tables");
			Check(tables.empty(), "the tables listing: " + tables);
			auto show = ErrorOf(con, principal + "SHOW TABLES");
			Check(show.empty(), "SHOW TABLES: " + show);
			Check(calls.empty(), "the trait was not asked");
			Check(!Attached(con, "lazy"), "the lazy source stays detached");
		});

		Scenario("a statement decided earlier attaches it again before it runs (a source idle since)", [&] {
			Exec(con, "ATTACH '" + path + "' AS lazy");
			auto prepared = con.Prepare(principal + "SELECT a FROM t");
			if (!CheckOk(*prepared, "prepared")) {
				return;
			}
			detach();
			auto result = prepared->Execute();
			CheckColumn(*result, {1}, "the execution after the source went idle");
			Check(!calls.empty(), "the trait was asked at the execution");
		});

		Scenario("a source that does not attach refuses the statement with what the trait says", [&] {
			detach();
			failure = "acl: source lazy could not be attached (IOException)";
			auto error = ErrorOf(con, principal + "SELECT a FROM t");
			Check(error.find("could not be attached (IOException)") != std::string::npos, "the refusal: " + error);
			failure.clear();
		});

		Scenario("a policy write's probes and the catalog's check have every lazy source attached first", [&] {
			detach();
			auto write = ErrorOf(con, "ACL ADMIN CREATE VIRTUAL TABLE c.w AS lazy.main.w");
			Check(write.empty(), "a relation over the lazy source is written: " + write);
			Check(!calls.empty(), "the trait was asked before the probe");
			detach();
			auto findings = con.Query("ACL ADMIN CHECK VIRTUAL CATALOG c");
			Check(!findings->HasError(), "the check runs: " + (findings->HasError() ? findings->GetError() : ""));
			Check(Attached(con, "lazy"), "the check had the source attached");
			detach();
			auto own = con.Query("SELECT count(*) FROM acl_check_catalog('c') WHERE kind = 'source_missing'");
			CheckColumn(*own, {0}, "the operator's own call of the check finds no source missing");
			Check(Attached(con, "lazy"), "the operator's own check had the source attached");
		});

		store->node_traits.lazy_sources = nullptr;
		store->node_traits.attach_on_demand = nullptr;
		Scenario("no traits: nothing is attached on demand", [&] {
			Exec(con, "DETACH DATABASE IF EXISTS lazy");
			auto error = ErrorOf(con, principal + "SELECT a FROM t");
			Check(!error.empty(), "the read of a detached source fails at bind");
		});
		std::remove(path.c_str());
		std::remove((path + ".wal").c_str());
	});
}
