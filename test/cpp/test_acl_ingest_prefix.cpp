// The ACL INGEST prefix (spec 049) is composed by the Flight door's own C++ with a session handle
// minted at runtime, so - exactly as with ACL SESSION (spec 040) - its properties cannot be written
// in sqllogictest: no test file can splice a handle into a prefix. Hence a standalone binary.
// Build + run via `GEN=ninja make test-cpp`.

#include "acl_test_util.hpp"

using namespace duckdb;
using namespace acl_test;

namespace {

std::string OpenSession(Connection &con) {
	auto result = con.Query("SELECT acl_session_open('tok')");
	if (result->HasError() || result->RowCount() == 0) {
		return std::string();
	}
	auto value = result->Collection().GetValue(0, 0);
	return value.IsNull() ? std::string() : value.ToString();
}

bool ErrorContains(QueryResult &result, const std::string &needle, const std::string &what) {
	if (!result.HasError()) {
		return Check(false, what + ": unexpectedly succeeded");
	}
	auto error = result.GetError();
	return Check(error.find(needle) != std::string::npos, what + ": " + error);
}

} // namespace

int main(int argc, char *argv[]) {
	std::string extension = argc > 1 ? argv[1] : "build/release/extension/acl/acl.duckdb_extension";
	DBConfig config;
	config.SetOptionByName("allow_unsigned_extensions", Value::BOOLEAN(true));
	DuckDB db(nullptr, &config);
	Connection con(db);

	return RunMain("acl: the INGEST prefix and the arrow_scan exemption (spec 049)", [&]() {
		Exec(con, "LOAD '" + extension + "'");
		Exec(con, "CREATE TABLE phys_orders(id INT, tenant VARCHAR, amount INT)");
		Exec(con, "ATTACH ':memory:' AS store");
		Exec(con, "SELECT acl_use_db('store', 'acl', true)");
		Exec(con, "SET GLOBAL acl_allow_anonymous_admin=true");
		Exec(con, "ACL ADMIN CREATE VIRTUAL CATALOG c");
		Exec(con, "ACL ADMIN CREATE VIRTUAL TABLE c.orders AS memory.main.phys_orders");
		Exec(con, "ACL ADMIN CREATE ROLE r");
		Exec(con, "ACL ADMIN GRANT CATALOG c TO ROLE r WITH (select, insert, update, delete, merge, ingest) MAIN");
		// spec 173: a load by key - an object with a declared key, one without, one whose grant withholds ingest
		Exec(con, "CREATE TABLE phys_keyed(id INT, tenant VARCHAR, amount INT)");
		Exec(con, "ACL ADMIN CREATE VIRTUAL TABLE c.keyed AS memory.main.phys_keyed PRIMARY KEY (id)");
		Exec(con, "CREATE TABLE phys_masked(id VARCHAR, amount INT)");
		Exec(con, "ACL ADMIN CREATE VIRTUAL TABLE c.masked AS memory.main.phys_masked PRIMARY KEY (id)");
		Exec(con, "ACL ADMIN GRANT TABLE c.masked TO ROLE r WITH (select, insert, update, delete, merge, ingest) "
		          "MASK (id AS 'xx')");
		Exec(con, "CREATE TABLE phys_bulk(id INT)");
		Exec(con, "ACL ADMIN CREATE VIRTUAL TABLE c.bulk AS memory.main.phys_bulk PRIMARY KEY (id)");
		Exec(con, "ACL ADMIN GRANT TABLE c.bulk TO ROLE r CAPS '{\"select\": true, \"insert\": true, "
		          "\"merge\": true, \"delete\": true}'");
		// spec 151: a schema that records what is made in it (an expansion) and one that does not (a live alias)
		Exec(con, "CREATE SCHEMA lake");
		Exec(con, "CREATE SCHEMA live");
		Exec(con, "ACL ADMIN CREATE VIRTUAL SCHEMA c.vs FROM memory.lake");
		Exec(con, "ACL ADMIN CREATE VIRTUAL SCHEMA c.lv AS memory.live");
		Exec(con, "ACL ADMIN GRANT SCHEMA c.vs TO ROLE r WITH (select, insert, create, ingest)");
		Exec(con, "ACL ADMIN GRANT SCHEMA c.lv TO ROLE r WITH (select, insert, create, ingest)");
		Exec(con, "CREATE SCHEMA reg");
		Exec(con, "CREATE TABLE reg.existing(id INT)");
		Exec(con, "ACL ADMIN CREATE VIRTUAL SCHEMA c.reg FROM memory.reg");
		Exec(con, "ACL ADMIN DROP VIRTUAL TABLE c.reg.existing");
		Exec(con, "ACL ADMIN GRANT SCHEMA c.reg TO ROLE r WITH (select, insert, create, ingest) VIRTUAL ONLY");
		Exec(con, "SELECT acl_define_token('tok', 'r', 'tenant=acme')");
		auto handle = OpenSession(con);
		if (!Check(!handle.empty(), "a defined token opens a session")) {
			return;
		}

		Scenario("the prefix carries exactly one INSERT", [&]() {
			auto select = con.Query("ACL INGEST '" + handle + "' SELECT 1");
			ErrorContains(*select, "exactly one INSERT", "a SELECT under INGEST is refused");
			auto batch = con.Query("ACL INGEST '" + handle + "' INSERT INTO orders (id) VALUES (1); SELECT 1");
			ErrorContains(*batch, "exactly one INSERT", "a batch under INGEST is refused");
			auto update = con.Query("ACL INGEST '" + handle + "' UPDATE orders SET amount = 1");
			ErrorContains(*update, "exactly one INSERT", "an UPDATE under INGEST is refused");
		});

		// spec 173: the door's MERGE / DELETE of a load by key, as it composes them
		auto merge_into = [&](const std::string &target) {
			return "ACL INGEST '" + handle + "' MERGE INTO " + target +
			       " AS __acl_target USING (SELECT id, amount FROM arrow_scan() QUALIFY row_number() OVER "
			       "(PARTITION BY acl_ingest_key() ORDER BY \"__acl_ingest_row\" DESC) = 1) AS __acl_ingest ON "
			       "acl_ingest_key() WHEN MATCHED THEN UPDATE SET id = __acl_ingest.id, amount = __acl_ingest.amount "
			       "WHEN NOT MATCHED THEN INSERT (id, amount) VALUES (__acl_ingest.id, __acl_ingest.amount)";
		};
		auto delete_from = [&](const std::string &target) {
			return "ACL INGEST '" + handle + "' DELETE FROM " + target +
			       " AS __acl_target USING (SELECT id FROM arrow_scan()) AS __acl_ingest WHERE acl_ingest_key()";
		};

		Scenario("a load by key merges or deletes by the declared key (spec 173)", [&]() {
			// the gate passed both shapes and expanded the key: what comes back is duckdb's own check of the stream
			ErrorContains(*con.Query(merge_into("keyed")), "ArrowScanFactory bind input",
			              "the MERGE of a load by key reaches duckdb's own check");
			ErrorContains(*con.Query(delete_from("keyed")), "ArrowScanFactory bind input",
			              "the DELETE of a load by key reaches duckdb's own check");
			ErrorContains(*con.Query(merge_into("orders")), "needs its declared key",
			              "a target with no declared key refuses a load by key");
			ErrorContains(*con.Query(delete_from("orders")), "needs its declared key", "...the DELETE too");
		});

		Scenario("a load by key compares the key as stored (spec 173 review)", [&]() {
			// a mask in the ON would match by the mask's value - a constant one, every row
			ErrorContains(*con.Query(merge_into("masked")), "compares its key as stored",
			              "a merge over a masked key is refused");
			ErrorContains(*con.Query(delete_from("masked")), "compares its key as stored",
			              "a remove over a masked key is refused");
		});

		Scenario("a bulk load is the ingest capability on top of the verb's (spec 173)", [&]() {
			ErrorContains(*con.Query(merge_into("bulk")), "a bulk load needs the ingest capability",
			              "a merge without ingest is refused");
			ErrorContains(*con.Query(delete_from("bulk")), "a bulk load needs the ingest capability",
			              "a remove without ingest is refused");
			auto append = con.Query("ACL INGEST '" + handle + "' INSERT INTO bulk (id) SELECT id FROM arrow_scan()");
			ErrorContains(*append, "a bulk load needs the ingest capability", "an append without ingest is refused");
			// the same statements outside the door's prefix: the client's own, no stream, no bulk load
			Exec(con, "ACL SESSION '" + handle + "' INSERT INTO bulk (id) VALUES (1)");
		});

		Scenario("the key marker is the door's alone (spec 173)", [&]() {
			auto by_session = con.Query("ACL SESSION '" + handle +
			                            "' DELETE FROM keyed AS __acl_target USING (SELECT 1 AS id) AS __acl_ingest "
			                            "WHERE acl_ingest_key()");
			ErrorContains(*by_session, "not allowed", "acl_ingest_key under ACL SESSION is denied");
			auto in_select = con.Query("ACL INGEST '" + handle +
			                           "' INSERT INTO keyed (id) SELECT id FROM arrow_scan() WHERE acl_ingest_key()");
			Check(in_select->HasError(), "a marker where the door composes none is no condition");
		});

		Scenario("an unknown handle earns nothing", [&]() {
			auto result = con.Query("ACL INGEST 'nope' INSERT INTO orders (id) VALUES (1)");
			ErrorContains(*result, "session", "an unknown handle is a session refusal");
		});

		Scenario("the gate stays closed outside the prefix", [&]() {
			auto by_session = con.Query("ACL SESSION '" + handle + "' SELECT * FROM arrow_scan()");
			ErrorContains(*by_session, "not allowed", "arrow_scan under ACL SESSION is denied");
			auto by_role = con.Query("ACL ROLE \"r\" SELECT * FROM arrow_scan()");
			ErrorContains(*by_role, "not allowed", "arrow_scan under ACL ROLE is denied");
		});

		Scenario("the exemption opens exactly the composed shape", [&]() {
			// under the INGEST prefix the gate passes arrow_scan, so the refusal that comes back is
			// duckdb's own binder error about the missing stream - bind input only the door attaches
			// (duckdb #25726) - which is what proves the gate opened
			auto composed = con.Query("ACL INGEST '" + handle +
			                          "' INSERT INTO orders (id, tenant, amount)"
			                          " SELECT id, tenant, amount FROM arrow_scan()");
			ErrorContains(*composed, "ArrowScanFactory bind input", "the gate passed arrow_scan to duckdb's own check");
			// and only arrow_scan: its dumb sibling stays denied even here
			auto dumb = con.Query("ACL INGEST '" + handle +
			                      "' INSERT INTO orders (id) SELECT id FROM arrow_scan_dumb(NULL, NULL, NULL)");
			ErrorContains(*dumb, "not allowed", "arrow_scan_dumb stays denied under INGEST");
		});

		Scenario("an ingest creates a table only where no catalog record is kept for it (spec 151)", [&]() {
			// the door checks a load by the count its statement answers: a CREATE with its record answers the
			// record's Success, so the load would be reported failed after the record was written
			auto recorded =
			    con.Query("ACL INGEST '" + handle + "' CREATE TABLE vs.loaded AS SELECT * FROM arrow_scan()");
			ErrorContains(*recorded, "an ingest creates a table only where no catalog record is kept",
			              "a create into an expansion is refused before anything runs");
			Check(con.Query("SELECT * FROM memory.lake.loaded")->HasError(), "...and made nothing");
			// VIRTUAL ONLY makes no table - the load was reported failed after the record of what exists was written
			auto registered =
			    con.Query("ACL INGEST '" + handle + "' CREATE TABLE reg.existing AS SELECT * FROM arrow_scan()");
			ErrorContains(*registered, "an ingest creates a table only where no catalog record is kept",
			              "a create into a VIRTUAL ONLY schema is refused");
			Check(con.Query("SELECT 1 FROM store.acl.relations WHERE vname = 'reg.existing'")->RowCount() == 0,
			      "...and records nothing");
			// a live alias keeps no record: the gate passes, and duckdb's own bind wants the door's stream
			auto live = con.Query("ACL INGEST '" + handle + "' CREATE TABLE lv.loaded AS SELECT * FROM arrow_scan()");
			ErrorContains(*live, "ArrowScanFactory bind input", "a create into a live alias passes to duckdb's check");
			// spec 173: the home's ingest beside its create
			Exec(con, "ACL ADMIN GRANT SCHEMA c.lv TO ROLE r WITH (select, insert, create)");
			auto no_ingest =
			    con.Query("ACL INGEST '" + handle + "' CREATE TABLE lv.loaded AS SELECT * FROM arrow_scan()");
			ErrorContains(*no_ingest, "ingest on schema", "a create without the home's ingest is refused");
		});

		Scenario("no marker rides after the handle", [&]() {
			auto native = con.Query("ACL INGEST '" + handle + "' ACL NATIVE SELECT 1");
			Check(native->HasError(), "an embedded ACL marker after INGEST does not parse");
		});
	});
}
