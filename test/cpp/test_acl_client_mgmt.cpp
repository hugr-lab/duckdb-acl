// The batch's classification on duckdb's tokens (spec 150 stage 3g-1): a door's command detection
// (`ClientTextIsMgmt`, the Flight door's ClientStatementIsCommand - spec 111 runs a management statement at
// GetFlightInfo) reads a client's text as the override does behind the door's prefix - duckdb's normalized text, the
// markers a client writes itself (TRACE / PARENT / LINEAGE parts, a value '…' or "…"), its `ACL` marker, comments
// gone - and hands the door's other checks the text past them. A statement the override compiles as management that the
// door missed ran only at DoGet, and a client that never fetched lost the write. Build + run via `GEN=ninja make
// test-cpp`.

#include "acl_test_util.hpp"

#include "acl_admin_sql.hpp"
#include "acl_parser_override.hpp"

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
			    // the markers as the prefix rule reads them: LINEAGE's parts repeat, a value '…' or "…"
			    "LINEAGE PARENT 'n/j/u' ROOT 'n/j/u' CREATE ROLE m",
			    "LINEAGE JOB 'j' ROOT 'n/j/u' ACL CREATE ROLE m",
			    "TRACE \"x\" CREATE ROLE m",
			    "TRACE 'x' PARENT 'y' LINEAGE PARENT 'n/j/u' JOB 'j' ACL CREATE ROLE m",
			};
			for (auto &text : management) {
				std::string rest;
				Check(duckdb::acl::ClientTextIsMgmt(text, rest), "management: " + text);
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
				std::string rest;
				Check(!duckdb::acl::ClientTextIsMgmt(text, rest), "a query: " + text);
			}
		});
		Scenario(
		    "USE [SCHEMA] on duckdb's tokens (spec 150 3g-2b): the SET it compiles to, or the text unchanged", [&] {
			    std::vector<std::pair<std::string, std::string>> cases = {
			        {"USE SCHEMA out", "SET acl_use_schema = 'out'"},
			        {"USE /* c */ SCHEMA -- x\n out;", "SET acl_use_schema = 'out'"},
			        {"USE SCHEMA \"out\".\"deep\"", "SET acl_use_schema = '\"out\".\"deep\"'"},
			        {"USE SCHEMA out . deep", "SET acl_use_schema = 'out.deep'"},
			        {"USE SCHEMA \"a'b\"", "SET acl_use_schema = '\"a''b\"'"},
			        {"USE SCHEMA 2024", "SET acl_use_schema = '2024'"},
			        {"USE SCHEMA 1abc", "SET acl_use_schema = '1abc'"},
			        {"USE a.b.c", "SET schema = 'a.b.c'"},
			        {"USE a.b", "USE a.b"},
			        {"USE schema.x", "USE schema.x"},
			        {"USE SCHEMA \"open", "USE SCHEMA \"open"},
			        {"USE SCHEMA out; SELECT 1", "USE SCHEMA out; SELECT 1"},
			        {"USE SCHEMA out.", "USE SCHEMA out."},
			        {"USE SCHEMA 'out'", "USE SCHEMA 'out'"},
			        {"SELECT 1", "SELECT 1"},
			        // digit-led parts after a dot (the tokenizer reads `.2024` into a number), an open comment, junk
			        {"USE SCHEMA raw.2024", "SET acl_use_schema = 'raw.2024'"},
			        {"USE mart.out.2024", "SET schema = 'mart.out.2024'"},
			        {"USE SCHEMA a.1b", "SET acl_use_schema = 'a.1b'"},
			        {"USE SCHEMA \"q\".2024", "SET acl_use_schema = '\"q\".2024'"},
			        {"USE SCHEMA 2024.\"q1\"", "SET acl_use_schema = '2024.\"q1\"'"},
			        {"USE 2024.q1.x", "SET schema = '2024.q1.x'"},
			        {"USE SCHEMA a$b", "SET acl_use_schema = 'a$b'"},
			        {"USE SCHEMA out;;", "SET acl_use_schema = 'out'"},
			        {"USE SCHEMA 1.", "USE SCHEMA 1."},
			        {"USE SCHEMA 1..2", "USE SCHEMA 1..2"},
			        {"USE SCHEMA 1e-5", "USE SCHEMA 1e-5"},
			        {"USE SCHEMA out /* open", "USE SCHEMA out /* open"},
			        {"USE SCHEMA `out`", "USE SCHEMA `out`"},
			        {"", ""},
			        {";", ";"},
			        {"/* only */", "/* only */"},
			    };
			    for (auto &entry : cases) {
				    auto got = duckdb::acl::UseSchemaAsSet(entry.first);
				    Check(got == entry.second, entry.first + " -> " + got);
			    }
		    });
		Scenario("the rest past the markers is what the door's other checks read", [&] {
			std::string rest;
			Check(!duckdb::acl::ClientTextIsMgmt("TRACE 'x' SELECT platform.create_role('z')", rest) &&
			          rest == "SELECT platform.create_role('z')",
			      "a platform call behind a marker: " + rest);
			Check(!duckdb::acl::ClientTextIsMgmt("LINEAGE JOB 'j' ACL NATIVE CREATE TABLE t (a INT)", rest) &&
			          rest == "CREATE TABLE t (a INT)",
			      "a native statement behind the markers: " + rest);
			Check(!duckdb::acl::ClientTextIsMgmt("USE SCHEMA s", rest) && rest == "USE SCHEMA s",
			      "no marker: the text itself: " + rest);
		});
	});
}
