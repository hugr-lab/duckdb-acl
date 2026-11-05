// The batch's classification on duckdb's tokens (spec 150 stage 3g-1): a door's command detection
// (`ClientTextIsMgmt`, the Flight door's ClientStatementIsCommand - spec 111 runs a management statement at
// GetFlightInfo) reads a client's text as the override does behind the door's prefix - duckdb's normalized text, the
// markers a client writes itself (TRACE / PARENT / LINEAGE parts, a value '…' or "…"), its `ACL` marker, comments
// gone - and hands the door's other checks the text past them. A statement the override compiles as management that the
// door missed ran only at DoGet, and a client that never fetched lost the write. Also the batch of an
// `ATTACH … LINEAGE` (3g-2c) where a sqllogictest cannot write it - a `--` comment ended by a carriage return. Build +
// run via `GEN=ninja make test-cpp`.

#include "acl_test_util.hpp"

#include "acl_admin_sql.hpp"
#include "acl_attach_lineage.hpp"
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
			        {"USE SCHEMA mart.2024_01", "SET acl_use_schema = 'mart.2024_01'"},
			        {"USE mart.2024_01.x", "SET schema = 'mart.2024_01.x'"},
			        {"USE SCHEMA out.1e5", "SET acl_use_schema = 'out.1e5'"},
			        {"USE SCHEMA 2024.e5", "SET acl_use_schema = '2024.e5'"},
			        {"USE SCHEMA 1.5e3", "SET acl_use_schema = '1.5e3'"},
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
		Scenario("a client's DDL runs as text over Flight, the rest stays prepared (spec 153)", [&] {
			std::vector<std::string> ddl = {
			    "CREATE TABLE t AS SELECT 1",
			    "DROP TABLE t",
			    "ALTER TABLE t RENAME TO u",
			    "CREATE VIEW v AS SELECT 1",
			    "TRACE 'x' CREATE TABLE t (a INT)",
			    "ACL NATIVE DROP TABLE t",
			    "DROP SECRET s",
			    "CREATE" + nbsp + "TABLE t (a INT)",
			    "/* lead */ CREATE TABLE t (a INT);",
			};
			for (auto &text : ddl) {
				Check(duckdb::acl::ClientTextIsDdl(text), "DDL: " + text);
			}
			std::vector<std::string> prepared = {
			    "CREATE SECRET s (TYPE http)",      // answers a row
			    "CREATE TABLE t AS SELECT $1",      // a parameter
			    "CREATE TABLE t AS SELECT ?",       //
			    "CREATE TABLE t (a INT); SELECT 1", // two statements
			    "CREATE ROLE r",                    // management
			    "ACL CREATE VIRTUAL CATALOG c",     //
			    "SELECT 1",                         // a query
			    "INSERT INTO t VALUES (1)",         // DML
			    "SET TimeZone = 'UTC'",             // a setting
			    "CREATE TABLE (",                   // what the plain parser cannot read
			};
			for (auto &text : prepared) {
				Check(!duckdb::acl::ClientTextIsDdl(text), "not DDL: " + text);
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
		Scenario("ATTACH … LINEAGE: a `--` comment ends at a carriage return, as duckdb's tokenizer ends it", [&] {
			bool found = false;
			// the splitter ran the comment on to a line feed: the ATTACH behind it was none, the SELECT after it
			// dropped
			auto behind =
			    duckdb::acl::SplitAttachLineage("SELECT 1; -- c\rATTACH ':memory:' AS m LINEAGE 'pg://m:1'", found);
			Check(found && behind.size() == 2 && behind[1].marked && behind[1].identity == "pg://m:1" &&
			          behind[1].text == "ATTACH ':memory:' AS m ",
			      "an ATTACH after a comment ended by \\r is marked");
			auto after =
			    duckdb::acl::SplitAttachLineage("ATTACH ':memory:' AS m LINEAGE 'pg://m:1' -- c\r; SELECT 42", found);
			Check(found && after.size() == 2 && after[0].marked && after[1].text == "SELECT 42",
			      "the statement after a comment ended by \\r is kept");
			auto padded = duckdb::acl::SplitAttachLineage("ATTACH ':memory:' AS m LINEAGE ' pg://m:1 '", found);
			Check(found && padded.size() == 1 && padded[0].identity == "pg://m:1",
			      "the identity is read trimmed: '" + (padded.empty() ? std::string() : padded[0].identity) + "'");
			Check(duckdb::acl::AttachLineageIdentity("ATTACH ':memory:' AS m LINEAGE ' pg://m:1 '") == "pg://m:1",
			      "...and read back the same by the hook");
		});
	});
}
