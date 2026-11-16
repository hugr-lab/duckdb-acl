// Golden rule (specs/001, specs/002): the rewriter adds no query parameters - a user's $1 / ? is the
// only parameter and binds normally, even as a virtual-function argument. This needs real parameter
// binding through the C++ API, which sqllogictest cannot express - hence a standalone test binary.
// Build + run via `GEN=ninja make test-cpp`.

#include "acl_test_util.hpp"

#include <cstdlib>
#include <unistd.h>

using namespace duckdb;
using namespace acl_test;

namespace {

//! The pure form of the golden rule: a parameterless query stays parameterless after the rewrite,
//! even though the rewrite splices in an RLS claim value (as a constant, never a parameter)
void NoUserParameters(Connection &con) {
	auto prepared = con.Prepare("ACL TOKEN 'tok' SELECT id FROM orders ORDER BY id");
	if (!CheckOk(*prepared, "parameterless query prepares")) {
		return;
	}
	Check(prepared->GetParameterCount() == 0, "parameterless query: the rewrite added no parameter");
	auto result = prepared->Execute();
	if (CheckOk(*result, "parameterless query executes")) {
		CheckColumn(*result, {1, 2}, "tenant=acme sees ids 1,2");
	}
}

void DollarParamInOuterWhere(Connection &con) {
	auto prepared = con.Prepare("ACL TOKEN 'tok' SELECT id FROM orders WHERE amount >= $1 ORDER BY id");
	if (!CheckOk(*prepared, "outer-WHERE $1 prepares")) {
		return;
	}
	Check(prepared->GetParameterCount() == 1, "outer-WHERE $1: exactly one (user) parameter");
	auto result = prepared->Execute(150);
	if (CheckOk(*result, "outer-WHERE $1 executes")) {
		// acme rows are (1:100, 2:200); amount >= 150 -> id 2
		CheckColumn(*result, {2}, "amount >= 150 under tenant=acme -> id 2");
	}
	// re-execute with a different bound value; the RLS constant (tenant=acme) stays baked in
	result = prepared->Execute(50);
	if (CheckOk(*result, "outer-WHERE $1 re-executes")) {
		CheckColumn(*result, {1, 2}, "amount >= 50 under tenant=acme -> ids 1,2");
	}
}

//! ? placeholders are numbered by traversal order at bind, so this also catches a rewrite that
//! duplicates or reorders the node holding one - which a fixed $1 cannot detect
void QuestionMarkParam(Connection &con) {
	auto prepared = con.Prepare("ACL TOKEN 'tok' SELECT id FROM orders WHERE amount >= ? ORDER BY id");
	if (!CheckOk(*prepared, "? placeholder prepares")) {
		return;
	}
	Check(prepared->GetParameterCount() == 1, "? placeholder: exactly one (user) parameter");
	auto result = prepared->Execute(150);
	if (CheckOk(*result, "? placeholder executes")) {
		CheckColumn(*result, {2}, "amount >= 150 under tenant=acme -> id 2");
	}
}

void DollarParamAsVfuncArgument(Connection &con) {
	auto prepared = con.Prepare("ACL TOKEN 'tok' SELECT id FROM report($1) ORDER BY id");
	if (!CheckOk(*prepared, "vfunc-argument $1 prepares")) {
		return;
	}
	Check(prepared->GetParameterCount() == 1, "vfunc-argument $1: exactly one (user) parameter");
	auto result = prepared->Execute(200);
	if (CheckOk(*result, "vfunc-argument $1 executes")) {
		// acme rows with amount >= 200 -> id 2
		CheckColumn(*result, {2}, "report(200) under tenant=acme -> id 2");
	}
	// re-execute with a different bound value: the argument spliced into the expanded template is a
	// live user parameter, while the claim baked next to it stays a constant
	result = prepared->Execute(50);
	if (CheckOk(*result, "vfunc-argument $1 re-executes")) {
		CheckColumn(*result, {1, 2}, "report(50) under tenant=acme -> ids 1,2");
	}
}

//! spec 011: an INSERT into a relation a grant narrowed is re-projected through a subquery, so the
//! grant's value columns are assigned. The user's parameters must survive that restructuring - same
//! count, same order, same bound values - and the rewrite must still add none of its own.
void ParamsThroughInjectedInsert() {
	DuckDB db(nullptr);
	Connection con(db);
	Exec(con, "LOAD acl");
	Exec(con, "ATTACH ':memory:' AS phys");
	Exec(con, "CREATE TABLE phys.main.t(id INT, tenant VARCHAR, amount INT)");
	Exec(con, "ATTACH ':memory:' AS aclcat");
	Exec(con, "SELECT acl_use_db('aclcat', 'acl', true)");
	Exec(con, "SET GLOBAL acl_allow_anonymous_admin=true");
	Exec(con, "SET allow_parser_override_extension='fallback'");
	Exec(con, "ACL ADMIN CREATE VIRTUAL CATALOG sales");
	Exec(con, "ACL ADMIN CREATE ROLE writer CLAIMS 'tenant=acme'");
	Exec(con, "ACL ADMIN ADD TABLE phys.main.t AS sales.t");
	Exec(con, "ACL ADMIN GRANT CATALOG sales TO ROLE writer CAPS '{\"select\": true, \"insert\": true}' MAIN");
	Exec(con, "ACL ADMIN GRANT TABLE sales.t TO ROLE writer CAPS '{\"select\": true, \"insert\": true}' "
	          "COLUMNS 'id,amount,tenant=acl_claim(''tenant'')'");

	auto prepared = con.Prepare("ACL ROLE \"writer\" INSERT INTO t(id, amount) VALUES ($1, $2)");
	if (!CheckOk(*prepared, "injected INSERT prepares")) {
		return;
	}
	Check(prepared->GetParameterCount() == 2, "injected INSERT: exactly two (user) parameters");
	auto result = prepared->Execute(7, 700);
	if (!CheckOk(*result, "injected INSERT executes")) {
		return;
	}
	// the parameters landed in their own columns, and the grant assigned the third
	auto rows = con.Query("SELECT id FROM phys.main.t WHERE tenant = 'acme' AND amount = 700");
	CheckColumn(*rows, {7}, "injected INSERT: $1/$2 bound in order, tenant assigned from the claim");
	// re-execute: the injected value stays a constant while the parameters rebind
	result = prepared->Execute(8, 800);
	if (CheckOk(*result, "injected INSERT re-executes")) {
		auto again = con.Query("SELECT id FROM phys.main.t WHERE tenant = 'acme' ORDER BY id");
		CheckColumn(*again, {7, 8}, "injected INSERT: the second row is assigned the same claim value");
	}
}

//! spec 117: a platform call's arguments are constants where they carry authorization - judged before the
//! call runs, which a parameter cannot be - and may be the user's parameters elsewhere; the compiled acl_*
//! call carries exactly the user's parameters, still none of the rewrite's own
void PlatformCallParameters() {
	DuckDB db(nullptr);
	Connection con(db);
	Exec(con, "LOAD acl");
	Exec(con, "ATTACH ':memory:' AS store");
	Exec(con, "SELECT acl_use_db('store', 'acl', true)");
	Exec(con, "SET GLOBAL acl_allow_anonymous_admin=true");
	Exec(con, "ACL ADMIN CREATE VIRTUAL CATALOG sales");
	Exec(con, "ACL ADMIN CREATE ROLE pol");
	Exec(con, "ACL ADMIN GRANT ADMIN policy TO ROLE pol");

	auto authz = con.Prepare("ACL ROLE \"pol\" SELECT platform.create_role(?)");
	Check(authz->HasError() &&
	          authz->GetError().find("carries authorization and must be a constant") != std::string::npos,
	      "a parameter for the role is refused: " + (authz->HasError() ? authz->GetError() : "it prepared"));
	auto catalog = con.Prepare("ACL ROLE \"pol\" SELECT platform.alter_catalog($1, 'x')");
	Check(catalog->HasError() &&
	          catalog->GetError().find("carries authorization and must be a constant") != std::string::npos,
	      "...and for the catalog: " + (catalog->HasError() ? catalog->GetError() : "it prepared"));

	auto payload = con.Prepare("ACL ROLE \"pol\" SELECT platform.alter_catalog('sales', comment := ?)");
	if (!CheckOk(*payload, "a parameter for the comment prepares")) {
		return;
	}
	Check(payload->GetParameterCount() == 1, "the compiled call carries exactly the user's parameter");
	auto first = payload->Execute("the first");
	CheckOk(*first, "...and executes");
	auto stored = con.Query("SELECT comment FROM store.acl.catalogs WHERE vcat = 'sales'");
	Check(!stored->HasError() && stored->Collection().GetValue(0, 0).ToString() == "the first",
	      "the bound value is what the call wrote");
	auto second = payload->Execute("the second");
	CheckOk(*second, "...and re-executes with another value");
	stored = con.Query("SELECT comment FROM store.acl.catalogs WHERE vcat = 'sales'");
	Check(!stored->HasError() && stored->Collection().GetValue(0, 0).ToString() == "the second",
	      "each execution is its own change");

	// the call keeps the column alias it was written with; the grammar answers under the call's name
	auto aliased = con.Query("ACL ROLE \"pol\" SELECT platform.create_role('aliased_role') AS made");
	Check(!aliased->HasError() && aliased->ColumnName(0).GetIdentifierName() == "made",
	      "a call keeps its alias: " +
	          (aliased->HasError() ? aliased->GetError() : aliased->ColumnName(0).GetIdentifierName()));
	auto named = con.Query("ACL ROLE \"pol\" CREATE ROLE named_role");
	Check(!named->HasError() && named->ColumnName(0).GetIdentifierName() == "create_role",
	      "the grammar answers as the call is named: " +
	          (named->HasError() ? named->GetError() : named->ColumnName(0).GetIdentifierName()));
	// the grammar's compiled call prepares the same way (and carries no parameter of its own)
	auto grammar = con.Prepare("ACL ROLE \"pol\" CREATE ROLE prepared_role");
	if (CheckOk(*grammar, "a management statement prepares")) {
		Check(grammar->GetParameterCount() == 0, "...with no parameter");
		CheckOk(*grammar->Execute(), "...and executes");
	}
}

//! spec 167: an AT's parameter stays the client's (the rewrite adds none), carried to the source below a grant's row
//! filter, and a grant's window checks it where duckdb evaluates it - at each execution
void VersionsAtParameter() {
	char directory[] = "/tmp/acl-versions-XXXXXX";
	if (!Check(mkdtemp(directory) != nullptr, "a lake directory of the test's own")) {
		return;
	}
	std::string lake = directory;
	// the lake's own extension, as the build made it (the test binaries link duckdb without it); a build without it
	// has no time travel to test
	const std::string ducklake = "build/release/extension/ducklake/ducklake.duckdb_extension";
	if (access(ducklake.c_str(), R_OK) != 0) {
		std::cout << "  skip: no " << ducklake << std::endl;
		return;
	}
	DBConfig config;
	config.SetOptionByName("allow_unsigned_extensions", Value::BOOLEAN(true));
	DuckDB db(nullptr, &config);
	Connection con(db);
	Exec(con, "LOAD acl");
	Exec(con, "LOAD parquet");
	Exec(con, "LOAD '" + ducklake + "'");
	Exec(con, "ATTACH 'ducklake:" + lake + "/meta.ducklake' AS lk (DATA_PATH '" + lake + "/data')");
	Exec(con, "CREATE TABLE lk.t (id INTEGER, region VARCHAR)");
	Exec(con, "INSERT INTO lk.t VALUES (1, 'eu')"); // snapshot 2
	Exec(con, "INSERT INTO lk.t VALUES (2, 'us')"); // snapshot 3
	Exec(con, "DELETE FROM lk.t WHERE id = 1");     // snapshot 4
	Exec(con, "ATTACH ':memory:' AS store");
	Exec(con, "SELECT acl_use_db('store', 'acl', true)");
	Exec(con, "SET GLOBAL acl_allow_anonymous_admin=true");
	Exec(con, "ACL ADMIN CREATE VIRTUAL CATALOG c; CREATE VIRTUAL TABLE c.t AS lk.main.t; CREATE ROLE rls; "
	          "CREATE ROLE win; CREATE ROLE every");
	Exec(con, "ACL ADMIN GRANT CATALOG c TO ROLE every MAIN VERSIONS ANY");
	Exec(con,
	     "ACL ADMIN GRANT CATALOG c TO ROLE rls MAIN VERSIONS ANY; GRANT TABLE c.t TO ROLE rls RLS (region = 'eu')");
	Exec(con, "ACL ADMIN GRANT CATALOG c TO ROLE win MAIN VERSIONS BETWEEN TIMESTAMP '2000-01-01' AND TIMESTAMP "
	          "'2100-01-01'");

	// the in-place read (no policy text): the client's parameter, rebound at each execution as duckdb does
	auto every = con.Prepare("ACL ROLE \"every\" SELECT id FROM t AT (VERSION => $1) ORDER BY id");
	if (CheckOk(*every, "an AT with a parameter prepares")) {
		Check(every->GetParameterCount() == 1, "...with the client's one parameter");
		auto old = every->Execute(3);
		CheckColumn(*old, {1, 2}, "AT (VERSION => 3): that snapshot");
		auto now = every->Execute(4);
		CheckColumn(*now, {2}, "AT (VERSION => 4): the current one");
	}
	// a read through the grant's policy is bound alone too (spec 159), where a parameter has no value: refused
	auto rls = con.Prepare("ACL ROLE \"rls\" SELECT id FROM t AT (VERSION => $1)");
	Check(rls->HasError() && rls->GetError().find("not a parameter") != std::string::npos,
	      "an AT parameter under a row filter is refused: " + (rls->HasError() ? rls->GetError() : "it prepared"));
	auto window = con.Prepare("ACL ROLE \"win\" SELECT id FROM t AT (TIMESTAMP => $1)");
	Check(window->HasError() && window->GetError().find("is a constant") != std::string::npos,
	      "an AT parameter under a window is refused: " + (window->HasError() ? window->GetError() : "it prepared"));
	auto constant = con.Prepare("ACL ROLE \"rls\" SELECT id FROM t AT (VERSION => 3) WHERE id > $1");
	if (CheckOk(*constant, "a constant AT beside a parameter prepares")) {
		auto rows = constant->Execute(0);
		CheckColumn(*rows, {1}, "AT (VERSION => 3) under the row filter: the eu row of that snapshot");
	}
}

void Run() {
	DuckDB db(nullptr);
	Connection con(db);
	// statically linked: the generated extension loader publishes 'acl' on the config
	Exec(con, "LOAD acl");

	// physical data, a virtual relation (SUBQUERY with RLS) and a virtual table function
	Exec(con, "ATTACH ':memory:' AS phys");
	Exec(con, "CREATE TABLE phys.main.orders_physical(id INT, tenant VARCHAR, amount INT)");
	Exec(con, "INSERT INTO phys.main.orders_physical VALUES (1,'acme',100),(2,'acme',200),(3,'globex',300)");
	Exec(con, "SELECT acl_grant_table('analyst','orders','phys.main.orders_physical','id,amount',"
	          "'tenant = acl_claim(''tenant'')','select')");
	Exec(con, "SELECT acl_grant_table_function('analyst','report','SELECT id, amount FROM "
	          "phys.main.orders_physical WHERE amount >= acl_arg(1) AND tenant = acl_claim(''tenant'')')");
	Exec(con, "SELECT acl_define_token('tok','analyst','tenant=acme')");
	Exec(con, "SET allow_parser_override_extension='fallback'");

	Scenario("no-user-parameters", [&]() { NoUserParameters(con); });
	Scenario("dollar-in-outer-where", [&]() { DollarParamInOuterWhere(con); });
	Scenario("question-mark", [&]() { QuestionMarkParam(con); });
	Scenario("dollar-as-vfunc-argument", [&]() { DollarParamAsVfuncArgument(con); });
	// its own instance: the grant policy needs a policy catalog, and switching the store mid-test
	// would change what the scenarios above resolve against
	Scenario("params-through-injected-insert", []() { ParamsThroughInjectedInsert(); });
	Scenario("platform-call-parameters", []() { PlatformCallParameters(); });
	Scenario("versions-at-parameter", []() { VersionsAtParameter(); });
}

} // namespace

int main() {
	return RunMain("acl params passthrough (spec 002)", Run);
}
