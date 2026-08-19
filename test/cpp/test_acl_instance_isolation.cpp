// The policy store lives on the parser extension (AclParserInfo) per database instance, not in a
// process global - so grants AND principals registered in one instance must be invisible to another,
// and must survive the other instance's lifecycle. Needs two DuckDB instances in one process, which
// sqllogictest cannot express. Build + run via `GEN=ninja make test-cpp`.

#include "acl_test_util.hpp"

using namespace duckdb;
using namespace acl_test;

namespace {

void Run() {
	DuckDB db1(nullptr);
	Connection con1(db1);
	Exec(con1, "LOAD acl");
	Exec(con1, "ATTACH ':memory:' AS phys");
	Exec(con1, "CREATE TABLE phys.main.t(id INT)");
	Exec(con1, "INSERT INTO phys.main.t VALUES (1)");
	Exec(con1, "SELECT acl_grant_table('r','v','phys.main.t','','','select')");
	Exec(con1, "SELECT acl_define_token('tok','r','tenant=acme')");
	Exec(con1, "SET allow_parser_override_extension='fallback'");

	// the first instance resolves the virtual name it registered
	auto by_role = con1.Query("ACL ROLE \"r\" SELECT id FROM v");
	if (CheckOk(*by_role, "instance 1 resolves its grant under ROLE")) {
		CheckColumn(*by_role, {1}, "instance 1 reads the physical row through the grant");
	}

	// a second, independent instance: nothing instance 1 registered may be visible here
	DuckDB db2(nullptr);
	Connection con2(db2);
	Exec(con2, "LOAD acl");
	Exec(con2, "SET allow_parser_override_extension='fallback'");

	auto other_table = con2.Query("ACL ROLE \"r\" SELECT id FROM v");
	Check(other_table->HasError(), "instance 2 is denied the name granted in instance 1");
	Check(other_table->HasError() && other_table->GetError().find("no access to object") != std::string::npos,
	      "instance 2 denial names the object");

	// the token minted in instance 1 must not authenticate in instance 2: a process-global token map
	// would be a cross-tenant leak even with a per-instance tables map
	auto other_token = con2.Query("ACL TOKEN 'tok' SELECT 1");
	Check(other_token->HasError(), "instance 2 rejects instance 1's token");
	Check(other_token->HasError() && other_token->GetError().find("verification failed") != std::string::npos,
	      "instance 2 token denial is a verification failure");

	// instance 1 is unaffected by instance 2's existence: its grant and token still resolve
	auto by_token = con1.Query("ACL TOKEN 'tok' SELECT id FROM v");
	if (CheckOk(*by_token, "instance 1 still resolves its grant under its TOKEN")) {
		CheckColumn(*by_token, {1}, "instance 1 still reads the physical row");
	}
}

} // namespace

int main() {
	return RunMain("acl per-instance policy isolation (spec 002)", Run);
}
