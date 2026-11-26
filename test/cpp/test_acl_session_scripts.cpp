// spec 181: a session's scripts run as the node on the session's own connection when it opens, before its first
// statement. Driven through a door's real session path - a quack client's ATTACH makes the session and its connection
// on the embedded server, whose CONNECT runs the scripts (a sync.py patch) - and read back by the principal's own
// statements through that session:
//   - the layers in order (the group's, the role's, the grant's), a later one overriding an earlier one's variable
//   - the variables acl_session_roles / _groups / _group / _subject set before them
//   - ON ERROR CONTINUE serves the session (a `script_failed` event); FAIL SESSION refuses it (`refused`,
//     reason session_script) - neither event carries the script's text nor the error's message
//   - the resolved list read again after a policy write, while an open session keeps what it ran
//   - the writers refused in memory mode
// Needs an ACL_QUACK=1 build for the client (the quack loadable does the ATTACH); skips that part otherwise.
// Build + run via `GEN=ninja make test-cpp`.

#include "acl_test_util.hpp"

#include <fstream>

using namespace duckdb;
using namespace acl_test;

namespace {

//! roles ["analyst"], sub "u", tid=acme, exp in 2100 (the fixture issuer test/idp/s) - test_acl_session.cpp's
const char *const TOKEN =
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2V5In0.eyJpc3MiOiJ0ZXN0L2lkcC9zIiwiYXVkIjoiYXBp"
    "Oi8vYWNsLXRlc3QiLCJleHAiOjQxMDI0NDQ4MDAsInN1YiI6InUiLCJyb2xlcyI6WyJhbmFseXN0Il0sInRpZCI6ImFjbWUifQ.C"
    "2rTehH2D3jptrk0TWAepMNA5XjhgHBCEYVr1NzJm7xa7ygxGtgCV9NpejZV3FFT2ex7QaC5xaoFHy59n5VbOw8I9t5_5qUvGkbDu"
    "SvyEYCLBlzdSczLOn7Su7k9rSIsMVvmbamtp_IhgyF1_ct0e1hm03Q2Vrm509omfcDvs9W8AyV9aPHUWui8bC-7hzw__gyiiZsRH"
    "8PEqZr3JqSPL5FdHp54d7YdGkgMZAR-TkB68NhjvcEmIaNG4Dr2ncL78Brj21nwtTIo3HbeNmhKzUbEp0uwH_-XkV2kxkKQXc2Ty"
    "sjble9-G50jiFYfciBfmh6rGkct3o-XcVwdC3YV1A";

const char *const DOOR = "quack:localhost:31981";

//! The one value a query answers, or "ERROR: …"
std::string One(Connection &con, const std::string &sql) {
	auto result = con.Query(sql);
	if (result->HasError()) {
		return "ERROR: " + result->GetError();
	}
	if (result->RowCount() == 0) {
		return "(none)";
	}
	auto value = result->Collection().GetValue(0, 0);
	return value.IsNull() ? "NULL" : value.ToString();
}

bool FileExists(const std::string &path) {
	return std::ifstream(path).good();
}

bool Contains(const std::string &text, const std::string &part) {
	return text.find(part) != std::string::npos;
}

std::string Attach(Connection &con, const std::string &alias) {
	auto result = con.Query("ATTACH '" + std::string(DOOR) + "' AS " + alias + " (TYPE quack, TOKEN '" + TOKEN + "')");
	return result->HasError() ? result->GetError() : std::string();
}

//! What the principal's own statement reads through the session `alias`
std::string Read(Connection &con, const std::string &alias, const std::string &expression) {
	return One(con, "FROM " + alias + ".query('SELECT " + expression + " AS v')");
}

} // namespace

int main(int argc, char *argv[]) {
	std::string extension = argc > 1 ? argv[1] : "build/release/extension/acl/acl.duckdb_extension";
	return RunMain("a session's scripts, run as the node when it opens (spec 181)", [&] {
		Scenario("the writers need a policy catalog: memory mode keeps no session scripts", [&] {
			DBConfig config;
			config.SetOptionByName("allow_unsigned_extensions", Value::BOOLEAN(true));
			DuckDB memory(nullptr, &config);
			Connection con(memory);
			Exec(con, "LOAD '" + extension + "'");
			Check(Contains(One(con, "SELECT acl_set_session_script('', 'r', 'SELECT 1')"), "policy catalog"),
			      "acl_set_session_script is refused without a catalog");
			Check(Contains(One(con, "SELECT acl_drop_session_script('g', '')"), "policy catalog"),
			      "acl_drop_session_script too");
		});

		auto quack_ext = std::string("build/release/extension/quack/quack.duckdb_extension");
		auto httpfs_ext = std::string("build/release/extension/httpfs/httpfs.duckdb_extension");
		if (!FileExists(quack_ext) || !FileExists(httpfs_ext)) {
			std::cout << "  skip: running the scripts through a door needs an ACL_QUACK=1 build\n";
			return;
		}
		DBConfig config;
		config.SetOptionByName("allow_unsigned_extensions", Value::BOOLEAN(true));
		DuckDB db(nullptr, &config);
		Connection con(db);
		Exec(con, "LOAD '" + extension + "'");
		Exec(con, "LOAD '" + quack_ext + "'"); // the client half
		Exec(con, "LOAD '" + httpfs_ext + "'");
		Exec(con, "ATTACH ':memory:' AS store");
		Exec(con, "CREATE TABLE orders(id INTEGER, tenant VARCHAR)");
		Exec(con, "INSERT INTO orders VALUES (1, 'acme')");
		Exec(con, "SELECT acl_use_db('store', 'acl', true)");
		Exec(con, "SET GLOBAL acl_allow_anonymous_admin=true");
		Exec(con, "SET GLOBAL acl_jwks_locations = 'test/idp/'");
		Exec(con, "SET GLOBAL acl_audit_level = 'all'");
		Exec(con, "SELECT acl_define_issuer('test/idp/s', '{\"url\": \"test/idp/s\", \"client\": {\"audiences\": "
		          "[\"api://acl-test\"], \"roles_from\": [\"roles\"], \"attributes\": {\"tid\": \"tenant\"}}}')");
		Exec(con, "ACL ADMIN CREATE VIRTUAL CATALOG c");
		Exec(con, "ACL ADMIN CREATE VIRTUAL TABLE c.orders AS memory.main.orders");
		Exec(con, "ACL ADMIN CREATE ROLE analyst");
		Exec(con, "ACL ADMIN GRANT CATALOG c TO ROLE analyst WITH (select) MAIN");
		// getvariable by name - what lets the principal's statement read what a script set (its category, environment,
		// would hand out getenv and the settings too)
		Exec(con, "ACL ADMIN GRANT FUNCTION getvariable TO ROLE analyst");
		Exec(con, "ACL ADMIN CREATE RESOURCE GROUP north");
		Exec(con, "ACL ADMIN GRANT RESOURCE GROUP north TO ROLE analyst");
		// the layers: each sees what the one before it set, and the last word is the most specific's
		Exec(con, "ACL ADMIN ALTER RESOURCE GROUP north SET SESSION SCRIPT "
		          "'SET VARIABLE region = ''north''; SET VARIABLE layer = ''group'''");
		Exec(con, "ACL ADMIN ALTER ROLE analyst SET SESSION SCRIPT "
		          "'SET VARIABLE role_saw = getvariable(''layer''); SET VARIABLE layer = ''role'''");
		Exec(con,
		     "ACL ADMIN ALTER RESOURCE GROUP north FOR ROLE analyst SET SESSION SCRIPT "
		     "'SET VARIABLE grant_saw = getvariable(''layer''); SET VARIABLE layer = ''grant''; "
		     "SET VARIABLE seen = getvariable(''acl_session_group'') || ''|'' || getvariable(''acl_session_subject'') "
		     "|| ''|'' || array_to_string(getvariable(''acl_session_roles''), '','') || ''|'' || "
		     "array_to_string(getvariable(''acl_session_groups''), '','')'");
		Exec(con, "SET GLOBAL acl_allow_anonymous_admin=false");
		Exec(con, std::string("SELECT acl_quack_serve('") + DOOR + "', 'server-token')");

		Scenario("the layers run in order on the session's connection, before its first statement", [&] {
			auto error = Attach(con, "first");
			if (!Check(error.empty(), "the session opens: " + error)) {
				return;
			}
			Check(Read(con, "first", "getvariable(''layer'')") == "grant",
			      "the grant's script ran last: " + Read(con, "first", "getvariable(''layer'')"));
			Check(Read(con, "first", "getvariable(''region'')") == "north", "the group's variable is there");
			Check(Read(con, "first", "getvariable(''role_saw'')") == "group",
			      "the role's script ran after the group's");
			Check(Read(con, "first", "getvariable(''grant_saw'')") == "role",
			      "the grant's script ran after the role's");
			auto seen = Read(con, "first", "getvariable(''seen'')");
			Check(seen == "north|u|analyst|north", "the variables were set before the scripts: " + seen);
			// SQL that ran unprefixed leaves no statement event: each script that ran is a `script_ran` of its own
			Exec(con, "SELECT acl_audit_flush()");
			auto ran = One(con, "SELECT string_agg(reason, ' / ' ORDER BY seq) FROM acl_audit_events() WHERE kind = "
			                    "'session' AND detail = 'script_ran'");
			Check(Contains(ran, "resource group \"north\" ran") && Contains(ran, "role \"analyst\" ran") &&
			          Contains(ran, "role \"analyst\" in resource group \"north\" ran"),
			      "a script_ran event per script, naming its level and owner: " + ran);
			Check(!Contains(ran, "SET VARIABLE"), "...never its text");
			// the principal's own statements stay judged: the scripts' rights are the node's, not the session's
			Check(Contains(Read(con, "first", "acl_session_count()"), "ERROR"),
			      "the principal still may not call the node's functions");
		});

		Scenario("a policy write is read by the next session; an open one keeps what it ran", [&] {
			Exec(con, "SET GLOBAL acl_allow_anonymous_admin=true");
			Exec(con, "ACL ADMIN ALTER RESOURCE GROUP north FOR ROLE analyst SET SESSION SCRIPT "
			          "'SET VARIABLE layer = ''grant, rewritten'''");
			Exec(con, "SET GLOBAL acl_allow_anonymous_admin=false");
			auto error = Attach(con, "second");
			if (!Check(error.empty(), "the session opens: " + error)) {
				return;
			}
			Check(Read(con, "second", "getvariable(''layer'')") == "grant, rewritten",
			      "the new session ran the script as written now");
			Check(Read(con, "first", "getvariable(''layer'')") == "grant", "the open session kept what it ran");
			Exec(con, "DETACH second");
		});

		Scenario("ON ERROR CONTINUE serves the session, and says so", [&] {
			Exec(con, "SET GLOBAL acl_allow_anonymous_admin=true");
			Exec(con, "ACL ADMIN ALTER ROLE analyst SET SESSION SCRIPT 'SELECT nosuch_function_181()' "
			          "ON ERROR CONTINUE");
			Exec(con, "SET GLOBAL acl_allow_anonymous_admin=false");
			auto error = Attach(con, "served");
			if (!Check(error.empty(), "the session opens: " + error)) {
				return;
			}
			Check(Read(con, "served", "getvariable(''layer'')") == "grant, rewritten",
			      "the scripts after the failed one ran");
			Exec(con, "DETACH served");
			Exec(con, "SELECT acl_audit_flush()");
			auto event = One(con, "SELECT reason_code || ' ' || reason FROM acl_audit_events() WHERE kind = 'session' "
			                      "AND detail = 'script_failed' ORDER BY seq DESC LIMIT 1");
			Check(Contains(event, "session_script") && Contains(event, "role \"analyst\""),
			      "a script_failed event names the level and the owner: " + event);
			Check(!Contains(event, "nosuch_function_181"), "...never the script's text nor the error's message");
			Check(One(con, "SELECT value FROM acl_metrics() WHERE name = 'acl.sessions.script_failed'") != "(none)",
			      "...and is counted");
		});

		Scenario("ON ERROR FAIL SESSION refuses the session", [&] {
			Exec(con, "SET GLOBAL acl_allow_anonymous_admin=true");
			Exec(con, "ACL ADMIN ALTER ROLE analyst SET SESSION SCRIPT 'SELECT nosuch_function_181()'");
			Exec(con, "SET GLOBAL acl_allow_anonymous_admin=false");
			auto error = Attach(con, "refused");
			Check(!error.empty(), "the ATTACH is refused");
			Check(Contains(error, "the session could not be prepared") && !Contains(error, "nosuch_function_181"),
			      "...saying only that the session could not be prepared: " + error);
			Exec(con, "SELECT acl_audit_flush()");
			auto event =
			    One(con, "SELECT reason_code || ' ' || reason FROM acl_audit_events() WHERE kind = 'session' "
			             "AND detail = 'refused' AND reason_code = 'session_script' ORDER BY seq DESC LIMIT 1");
			Check(Contains(event, "role \"analyst\"") && !Contains(event, "nosuch_function_181"),
			      "a refused event, reason session_script, names the owner and not the text: " + event);
			Check(One(con, "SELECT acl_session_count()") == "1", "the refused session is gone; the first stays");
			auto closed = One(con, "SELECT reason FROM acl_audit_events() WHERE kind = 'session' AND detail = 'client' "
			                       "ORDER BY seq DESC LIMIT 1");
			Check(Contains(closed, "refused by a session script"),
			      "its close keeps the observers' reason (client) and says why: " + closed);
		});

		Exec(con, "DETACH first");
		Exec(con, std::string("SELECT acl_quack_stop('") + DOOR + "')");
	});
}
