// spec 155: a principal's error names nothing it was not shown. duckdb answers a missing catalog entry with the
// closest names it finds in every attached database ("Did you mean "aclcat.acl.relations"?" - the policy store's
// own table; a table an expansion does not show) and names the physical object it looked for. The error of a
// principal's statement is rewritten where the client reads it (QueryEnd, on the result's own error), on every
// path: a query, a Prepare (which runs as a PREPARE and throws its result's error), an execution. NATIVE and the
// operator keep duckdb's text. The Prepare path is what sqllogictest cannot take. Build + run via `make test-cpp`.

#include "acl_test_util.hpp"

using namespace duckdb;
using namespace acl_test;

namespace {

void Setup(Connection &con, const std::string &extension) {
	Exec(con, "LOAD '" + extension + "'");
	Exec(con, "ATTACH ':memory:' AS phys");
	Exec(con, "CREATE SCHEMA phys.lake");
	Exec(con, "CREATE TABLE phys.lake.payroll(who VARCHAR, pay INT)");
	Exec(con, "CREATE TABLE phys.lake.hidden_thing(x INT)");
	Exec(con, "ATTACH ':memory:' AS aclcat");
	Exec(con, "SELECT acl_use_db('aclcat', 'acl', true)");
	Exec(con, "SET GLOBAL acl_allow_anonymous_admin=true");
	Exec(con, "ACL ADMIN CREATE VIRTUAL CATALOG sales");
	Exec(con, "ACL ADMIN CREATE VIRTUAL SCHEMA sales.vs FROM phys.lake");
	Exec(con, "ACL ADMIN DROP VIRTUAL TABLE sales.vs.hidden_thing");
	Exec(con, "ACL ADMIN CREATE ROLE wide");
	Exec(con, "ACL ADMIN GRANT CATALOG sales TO ROLE wide CAPS '{}' MAIN");
	Exec(con, "ACL ADMIN GRANT SCHEMA sales.vs TO ROLE wide WITH (select, create, drop)");
	// a record of nothing: the operator dropped the physical table behind it
	Exec(con, "ACL ROLE \"wide\" CREATE TABLE vs.gone(x INT)");
	Exec(con, "DROP TABLE phys.lake.gone");
	// ...and one whose source is named otherwise than the record
	Exec(con, "CREATE TABLE phys.lake.salaries_2024(who VARCHAR)");
	Exec(con, "ACL ADMIN CREATE VIRTUAL TABLE sales.pay AS phys.lake.salaries_2024");
	Exec(con, "ACL ADMIN GRANT TABLE sales.pay TO ROLE wide WITH (select)");
	Exec(con, "DROP TABLE phys.lake.salaries_2024");
}

//! An error that names none of what the principal was not shown
void NamesNothing(const std::string &error, const std::string &what) {
	Check(!error.empty(), what + ": refused");
	Check(error.find("Did you mean") == std::string::npos, what + ": no suggestion (" + error + ")");
	Check(error.find("aclcat") == std::string::npos, what + ": not the policy store (" + error + ")");
	Check(error.find("hidden_thing") == std::string::npos,
	      what + ": not a table the expansion does not show (" + error + ")");
	Check(error.find("does not exist") != std::string::npos, what + ": says what is wrong (" + error + ")");
}

} // namespace

int main(int argc, char *argv[]) {
	std::string extension = argc > 1 ? argv[1] : "build/release/extension/acl/acl.duckdb_extension";
	return RunMain("acl principal errors (spec 155)", [&]() {
		DBConfig config;
		config.SetOptionByName("allow_unsigned_extensions", Value::BOOLEAN(true));
		DuckDB db(nullptr, &config);
		Connection con(db);
		Setup(con, extension);
		const std::string wide = "ACL ROLE \"wide\" ";

		Scenario("a query: a DROP of a name nothing holds, a record of nothing read", [&]() {
			NamesNothing(con.Query(wide + "DROP TABLE vs.hidden_thin")->GetError(), "DROP near a hidden table");
			NamesNothing(con.Query(wide + "DROP TABLE vs.relation")->GetError(), "DROP near the store's table");
			NamesNothing(con.Query(wide + "SELECT * FROM vs.gone")->GetError(), "a read of a record of nothing");
		});

		Scenario("a Prepare: the error it answers is rewritten too", [&]() {
			auto prepared = con.Prepare(wide + "SELECT * FROM vs.gone");
			Check(prepared->HasError(), "the Prepare is refused");
			NamesNothing(prepared->GetError(), "Prepare of a read of a record of nothing");
			// a source named otherwise: its physical name is not said
			auto renamed = con.Prepare(wide + "SELECT * FROM pay");
			Check(renamed->HasError(), "the Prepare is refused");
			NamesNothing(renamed->GetError(), "Prepare of a read of a record whose source is named otherwise");
			Check(renamed->GetError().find("salaries_2024") == std::string::npos,
			      "the source's physical name is not said (" + renamed->GetError() + ")");
		});

		Scenario("the operator and NATIVE keep duckdb's text", [&]() {
			auto plain = con.Query("DROP TABLE phys.lake.hidden_thin")->GetError();
			Check(plain.find("Did you mean") != std::string::npos,
			      "the operator's own SQL: duckdb's suggestion (" + plain + ")");
		});
	});
}
