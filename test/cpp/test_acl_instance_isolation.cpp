// The policy store lives on the parser extension (AclParserInfo) per database instance, not in a
// process global - so grants AND principals registered in one instance must be invisible to another,
// and must survive the other instance's lifecycle. Needs two DuckDB instances in one process, which
// sqllogictest cannot express. Build + run via `GEN=ninja make test-cpp`.

#include "acl_test_util.hpp"

#include <fstream>
#include <iostream>

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

	// The doors' registries are per process, keyed by listen uri - so a door must know which
	// instance opened it, or instance 2 could stop instance 1's door and close instance 2's own
	// sessions for the privilege (the 2026-09-03 review). Both doors need a policy source and a
	// STRICT override to open at all; the memory-mode instances above cannot serve, so serving
	// instances are made here.
	Scenario("doors-belong-to-the-instance-that-opened-them", [&]() {
		auto has_function = [](Connection &con, const string &name) {
			auto probe = con.Query("SELECT count(*) FROM duckdb_functions() WHERE function_name = '" + name + "'");
			return !probe->HasError() && probe->GetValue(0, 0).GetValue<int64_t>() > 0;
		};
		auto serving_setup = [](Connection &con) {
			Exec(con, "ATTACH ':memory:' AS store");
			Exec(con, "SELECT acl_use_db('store','acl',true)");
			Exec(con, "SET GLOBAL acl_allow_anonymous_admin=false");
		};
		DuckDB a(nullptr);
		Connection ca(a);
		Exec(ca, "LOAD acl");
		serving_setup(ca);
		DuckDB b(nullptr);
		Connection cb(b);
		Exec(cb, "LOAD acl");
		serving_setup(cb);

		if (has_function(ca, "acl_quack_serve")) {
			// the embedded quack server's RNG needs a crypto module: httpfs provides one where the
			// build is not OpenSSL-backed (the flight build registers its own) - load it if present.
			// A build with neither (the plain macOS job: ACL_NO_FLIGHT, no ACL_QUACK, so no httpfs)
			// gets duckdb's non-crypto PRNG through force_mbedtls_unsafe - unfit for a deployment's
			// tokens, exactly right for a test whose subject is door ownership, not RNG quality.
			auto httpfs = std::string("build/release/extension/httpfs/httpfs.duckdb_extension");
			std::ifstream probe(httpfs);
			if (probe.good()) {
				Exec(ca, "LOAD '" + httpfs + "'");
				Exec(cb, "LOAD '" + httpfs + "'");
			} else {
				Exec(ca, "SET force_mbedtls_unsafe = 'true'");
				Exec(cb, "SET force_mbedtls_unsafe = 'true'");
			}
			auto served = ca.Query("SELECT acl_quack_serve('quack:localhost:31990', 'server-token')");
			if (CheckOk(*served, "instance A opens a quack door")) {
				auto foreign_stop = cb.Query("SELECT acl_quack_stop('quack:localhost:31990')");
				Check(foreign_stop->HasError() &&
				          foreign_stop->GetError().find("another database instance") != std::string::npos,
				      "instance B may not stop A's quack door: " +
				          (foreign_stop->HasError() ? foreign_stop->GetError() : "it did"));
				auto foreign_serve = cb.Query("SELECT acl_quack_serve('quack:localhost:31990', 'server-token')");
				Check(foreign_serve->HasError() &&
				          foreign_serve->GetError().find("already listening") != std::string::npos,
				      "...nor open one on the same address while A's is live");
				auto own_stop = ca.Query("SELECT acl_quack_stop('quack:localhost:31990')");
				if (CheckOk(*own_stop, "instance A stops its own quack door")) {
					Check(own_stop->GetValue(0, 0).ToString().find("session(s) closed") != std::string::npos,
					      "...and it was A's last door, so A's sessions closed: " +
					          own_stop->GetValue(0, 0).ToString());
				}
			}
		} else {
			std::cout << "  skip: no embedded quack door in this build\n";
		}

		if (has_function(ca, "acl_flight_serve")) {
			auto served = ca.Query("SELECT acl_flight_serve('grpc://localhost:31991')");
			if (CheckOk(*served, "instance A opens a Flight door")) {
				auto foreign_stop = cb.Query("SELECT acl_flight_stop('grpc://localhost:31991')");
				Check(foreign_stop->HasError() &&
				          foreign_stop->GetError().find("another database instance") != std::string::npos,
				      "instance B may not stop A's Flight door: " +
				          (foreign_stop->HasError() ? foreign_stop->GetError() : "it did"));
				auto own_stop = ca.Query("SELECT acl_flight_stop('grpc://localhost:31991')");
				CheckOk(*own_stop, "instance A stops its own Flight door");
			}
		} else {
			std::cout << "  skip: no Flight door in this build\n";
		}
	});
}

} // namespace

int main() {
	return RunMain("acl per-instance policy isolation (spec 002)", Run);
}
