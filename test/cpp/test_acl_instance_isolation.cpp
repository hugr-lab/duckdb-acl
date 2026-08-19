// The policy store lives on the parser extension (AclParserInfo) per database instance, not in a
// process global - so a policy registered in one instance must be invisible to another (specs/002).
// Needs two DuckDB instances in one process, which sqllogictest cannot express.
// Build + run via `GEN=ninja make test-cpp`.

#include "duckdb.hpp"

#include <iostream>
#include <string>

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

void Run() {
	DBConfig config1;
	config1.SetOptionByName("allow_unsigned_extensions", true);
	DuckDB db1(nullptr, &config1);
	Connection con1(db1);
	LoadAcl(con1);
	Exec(con1, "ATTACH ':memory:' AS phys");
	Exec(con1, "CREATE TABLE phys.main.t(id INT)");
	Exec(con1, "INSERT INTO phys.main.t VALUES (1)");
	Exec(con1, "SELECT acl_grant_table('r','v','phys.main.t','','','select')");
	Exec(con1, "SET allow_parser_override_extension='fallback'");

	// the first instance resolves the virtual name it registered
	auto in_db1 = con1.Query("ACL ROLE \"r\" SELECT id FROM v");
	Check(!in_db1->HasError(), "instance 1 resolves its own grant: " + in_db1->GetError());
	Check(in_db1->RowCount() == 1 && in_db1->GetValue(0, 0).GetValue<int64_t>() == 1,
	      "instance 1 reads the physical row through the grant");

	// a second, independent instance never registered 'v' -> it is denied (no shared global state)
	DBConfig config2;
	config2.SetOptionByName("allow_unsigned_extensions", true);
	DuckDB db2(nullptr, &config2);
	Connection con2(db2);
	LoadAcl(con2);
	Exec(con2, "SET allow_parser_override_extension='fallback'");

	auto in_db2 = con2.Query("ACL ROLE \"r\" SELECT id FROM v");
	Check(in_db2->HasError(), "instance 2 is denied the name granted in instance 1");
	Check(in_db2->GetError().find("no access to object") != std::string::npos,
	      "instance 2 denial names the object: " + in_db2->GetError());
}

} // namespace

int main() {
	std::cout << "acl per-instance policy isolation (spec 002)\n";
	try {
		Run();
	} catch (std::exception &ex) {
		std::cout << "  FAIL: " << ex.what() << "\n";
		failures++;
	}
	std::cout << (failures == 0 ? "PASS" : "FAIL") << "\n";
	return failures == 0 ? 0 : 1;
}
