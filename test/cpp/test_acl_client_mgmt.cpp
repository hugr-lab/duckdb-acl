// The batch's classification on duckdb's tokens (spec 150 stage 3g-1): a door's command detection
// (`ClientTextIsMgmt`, the Flight door's ClientStatementIsCommand - spec 111 runs a management statement at
// GetFlightInfo) reads a client's text as the override does - duckdb's normalized text, the client's `ACL` marker a
// token, comments gone. A statement the override compiles as management that the door missed ran only at DoGet,
// and a client that never fetched lost the write.
// Build + run via `GEN=ninja make test-cpp`.

#include "acl_test_util.hpp"

#include "acl_admin_sql.hpp"

using namespace acl_test;

int main(int argc, char *argv[]) {
	return RunMain("a client's management text, as the override reads it (spec 150 3g-1)", [&] {
		const std::string nbsp = "\xc2\xa0"; // U+00A0, a space duckdb's parser normalizes
		Scenario("management, however it is spaced or commented", [&] {
			std::vector<std::string> management = {
			    "ACL REVOKE CATALOG c FROM ROLE r",
			    "REVOKE" + nbsp + "CATALOG c FROM ROLE r",
			    "ACL/* x */REVOKE CATALOG c FROM ROLE r",
			    "ACL-- x\nREVOKE CATALOG c FROM ROLE r",
			    nbsp + ";REVOKE CATALOG c FROM ROLE r",
			    "CREATE" + nbsp + "ROLE m",
			    "  /* lead */ acl DROP /* c */ ROLE m",
			    "GRANT SECRET s TO ROLE r",
			    // the markers a client writes itself, its ACL marker (management unless NATIVE), an empty statement
			    "TRACE 'x' GRANT CATALOG c TO ROLE r",
			    "LINEAGE JOB 'j' ACL CREATE ROLE m",
			    "ACL ; REVOKE CATALOG c FROM ROLE r",
			    "acl ; ; CREATE ROLE m",
			    "TRACE 'x' ; CREATE ROLE m",
			    "ACL SELECT 1",
			};
			for (auto &text : management) {
				Check(duckdb::acl::ClientTextIsMgmt(text), "management: " + text);
			}
		});
		Scenario("a query stays a query", [&] {
			std::vector<std::string> queries = {
			    "SELECT 1",
			    "SELECT 'GRANT CATALOG c TO ROLE r'",
			    "/* GRANT CATALOG c TO ROLE r */ SELECT 1",
			    "ANALYZE virtual",
			    "CREATE FUNCTION category(x) AS x",
			    "DROP FUNCTION category CASCADE",
			    "DROP FUNCTION category RESTRICT",
			    "ANALYZE virtual.t",
			    "ACL NATIVE SELECT 1",
			    "TRACE 'x' SELECT 1",
			    "",
			};
			for (auto &text : queries) {
				Check(!duckdb::acl::ClientTextIsMgmt(text), "a query: " + text);
			}
		});
	});
}
