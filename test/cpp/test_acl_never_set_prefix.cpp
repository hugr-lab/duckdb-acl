// spec 178: a module linked into the extension (the platform part - hugr-node's `hugr_node_` functions) puts its
// operator-only functions in the never set by their prefix: no grant by name opens one to a principal, and a grant
// written before is not enough to call it. Build + run via `GEN=ninja make test-cpp`.

#include "acl_test_util.hpp"

#include "acl_function_categories.hpp"

using namespace duckdb;
using namespace acl_test;

namespace {

std::string ErrorOf(Connection &con, const std::string &sql) {
	auto result = con.Query(sql);
	return result->HasError() ? result->GetError() : std::string();
}

} // namespace

int main(int argc, char *argv[]) {
	return RunMain("spec 178: a platform part's never-set prefix", [] {
		DBConfig config;
		DuckDB db(nullptr, &config);
		Connection con(db);
		Exec(con, "LOAD acl");
		Exec(con, "ATTACH ':memory:' AS store");
		Exec(con, "SELECT acl_use_db('store','acl',true)");
		Exec(con, "SET GLOBAL acl_allow_anonymous_admin=true");
		Exec(con, "CREATE MACRO probe_node_plan() AS 42");
		Exec(con, "ACL ADMIN CREATE ROLE analyst");
		Exec(con, "ACL ADMIN CREATE VIRTUAL CATALOG c");
		Exec(con, "ACL ADMIN GRANT CATALOG c TO ROLE analyst WITH (select) MAIN");

		Scenario("before the prefix is registered: the name is not in the never set",
		         [&] { Check(!acl::FunctionNeverCallable("probe_node_plan"), "not yet never"); });

		acl::RegisterNeverCallablePrefix("probe_node_");
		acl::RegisterNeverCallablePrefix("probe_node_"); // idempotent

		Scenario("registered: a grant by name is refused as the never set's", [&] {
			auto grant = ErrorOf(con, "ACL ADMIN GRANT FUNCTION probe_node_plan SCALAR TO ROLE analyst");
			Check(grant.find("never") != std::string::npos, "a new grant is refused: " + grant);
			Check(acl::FunctionNeverCallable("probe_node_other"), "any name of the prefix is in the never set");
			Check(!acl::FunctionNeverCallable("probe_nodes"), "a name merely starting alike is not");
		});

		Scenario("the operator's own SQL is untouched", [&] {
			auto own = con.Query("SELECT probe_node_plan()");
			CheckColumn(*own, {42}, "the operator's call");
		});
	});
}
