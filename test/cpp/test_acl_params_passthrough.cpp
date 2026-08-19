// Golden rule (specs/001, specs/002): the rewriter adds no query parameters - a user's $1 / ? is the
// only parameter and binds normally, even as a virtual-function argument. This needs real parameter
// binding through the C++ API, which sqllogictest cannot express - hence a standalone test binary.
// Build + run via `GEN=ninja make test-cpp`.

#include "duckdb.hpp"

#include <iostream>
#include <string>
#include <vector>

using namespace duckdb;

namespace {

int failures = 0;

void Check(bool ok, const std::string &what) {
	std::cout << (ok ? "  ok:   " : "  FAIL: ") << what << "\n";
	if (!ok) {
		failures++;
	}
}

void Exec(Connection &con, const std::string &sql) {
	auto result = con.Query(sql);
	if (result->HasError()) {
		throw std::runtime_error("setup failed: " + sql + ": " + result->GetError());
	}
}

void LoadAcl(Connection &con) {
	auto local = con.Query("LOAD 'build/release/extension/acl/acl.duckdb_extension'");
	if (local->HasError()) {
		auto linked = con.Query("LOAD acl");
		if (linked->HasError()) {
			throw std::runtime_error("cannot load the acl extension: " + linked->GetError());
		}
	}
}

//! Collect the first column of a result as int64 values
std::vector<int64_t> ColumnValues(QueryResult &result) {
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

void Run() {
	DBConfig config;
	config.SetOptionByName("allow_unsigned_extensions", true);
	DuckDB db(nullptr, &config);
	Connection con(db);
	LoadAcl(con);

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

	// a user parameter in the outer query survives the rewrite: exactly one parameter, and it is the user's
	{
		auto prepared = con.Prepare("ACL TOKEN 'tok' SELECT id FROM orders WHERE amount >= $1 ORDER BY id");
		Check(!prepared->HasError(), "outer-WHERE $1 prepares: " + prepared->GetError());
		Check(prepared->GetParameterCount() == 1, "outer-WHERE $1: exactly one (user) parameter");

		auto result = prepared->Execute(150);
		Check(!result->HasError(), "outer-WHERE $1 executes: " + result->GetError());
		// acme rows are (1:100, 2:200); amount >= 150 -> id 2
		Check(ColumnValues(*result) == std::vector<int64_t> {2}, "amount >= 150 under tenant=acme -> id 2");

		// re-execute with a different bound value; the RLS constant (tenant=acme) stays baked in
		result = prepared->Execute(50);
		Check(!result->HasError(), "outer-WHERE $1 re-executes: " + result->GetError());
		Check(ColumnValues(*result) == std::vector<int64_t> {1, 2}, "amount >= 50 under tenant=acme -> ids 1,2");
	}

	// a user parameter passed as a table-function argument also flows through unchanged
	{
		auto prepared = con.Prepare("ACL TOKEN 'tok' SELECT id FROM report($1) ORDER BY id");
		Check(!prepared->HasError(), "vfunc-argument $1 prepares: " + prepared->GetError());
		Check(prepared->GetParameterCount() == 1, "vfunc-argument $1: exactly one (user) parameter");

		auto result = prepared->Execute(200);
		Check(!result->HasError(), "vfunc-argument $1 executes: " + result->GetError());
		// acme rows with amount >= 200 -> id 2
		Check(ColumnValues(*result) == std::vector<int64_t> {2}, "report(200) under tenant=acme -> id 2");
	}
}

} // namespace

int main() {
	std::cout << "acl params passthrough (spec 002)\n";
	try {
		Run();
	} catch (std::exception &ex) {
		std::cout << "  FAIL: " << ex.what() << "\n";
		failures++;
	}
	std::cout << (failures == 0 ? "PASS" : "FAIL") << "\n";
	return failures == 0 ? 0 : 1;
}
