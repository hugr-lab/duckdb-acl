// The embedded quack door (spec 063): quack's server compiled INTO acl, replacing the spec-062
// loopback front. One listener owns the public address - it answers the unauthenticated
// /.well-known/quack-auth itself, speaks the quack protocol directly (a real client ATTACHes and
// reads its own RLS slice), and terminates TLS where asked. Exercised end to end: discovery names the
// fixture issuers; a real quack client rides the embedded server; an ISSUER-less provider secret
// discovers the issuer from the door; the TLS variant serves the same discovery over https; and a
// leaked server of a dead instance is reclaimed by a later serve of the same address.
//
// Needs an ACL_QUACK=1 build for the client leg (the quack loadable does the ATTACH); skips it
// gracefully otherwise. httpfs is loaded so the server has a writable crypto module for its RNG.

#include "acl_test_util.hpp"

#include "oidc_core.hpp"

#include "httplib.hpp"

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <thread>

using namespace duckdb;
using namespace acl_test;

namespace {

const char *const TOKEN =
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2V5In0.eyJpc3MiOiJ0ZXN0L2lkcC9zIiwiYXVkIjoiYXBp"
    "Oi8vYWNsLXRlc3QiLCJleHAiOjQxMDI0NDQ4MDAsInN1YiI6InUiLCJyb2xlcyI6WyJhbmFseXN0Il0sInRpZCI6ImFjbWUifQ.C"
    "2rTehH2D3jptrk0TWAepMNA5XjhgHBCEYVr1NzJm7xa7ygxGtgCV9NpejZV3FFT2ex7QaC5xaoFHy59n5VbOw8I9t5_5qUvGkbDu"
    "SvyEYCLBlzdSczLOn7Su7k9rSIsMVvmbamtp_IhgyF1_ct0e1hm03Q2Vrm509omfcDvs9W8AyV9aPHUWui8bC-7hzw__gyiiZsRH"
    "8PEqZr3JqSPL5FdHp54d7YdGkgMZAR-TkB68NhjvcEmIaNG4Dr2ncL78Brj21nwtTIo3HbeNmhKzUbEp0uwH_-XkV2kxkKQXc2Ty"
    "sjble9-G50jiFYfciBfmh6rGkct3o-XcVwdC3YV1A";

// spec 097: service principals of the same issuer - roles `observer` (GRANT ADMIN observe), `mgr`
// (an unrestricted manage), `catmgr` (manage of one catalog only) and `pt` (passthrough)
const char *const PASSTHROUGH_TOKEN =
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2V5In0.eyJpc3MiOiJ0ZXN0L2lkcC9zIiwiYXVkIjoiYXBp"
    "Oi8vYWNsLXRlc3QiLCJleHAiOjQxMDI0NDQ4MDAsInN1YiI6InN2Yy1wdCIsInJvbGVzIjpbInB0Il19.ea3v4v03I4CVy724GyV"
    "uOP4yfco_jaZfpBoaFGlIj7YAaNmejrf8OPfOlanQFTtwQWkHWo0tmpvNSxcpkR7EHDHq2PLTEtNOrPfxntauCAtWNIvW4gO4o7s"
    "NcSKChiunvxuUQXPgo5sRcMtIT2mIKIeHZFwtHHYGbskLRdmbBq7YCTggf1SfRoXIp-2DVbOaqiBsTyM1k65ak5VHpxORDYALQU7"
    "fkiHavbUsEe7TFlfu2aNLQfw0MV42ODdRnrt_gPfS7I_hoy1CA4uN7gOE8E2trm5Zv6nGyVIdqTMCr6s1cQWy0WW4TRubkSZvSik"
    "QG01rRsPLOi5C3jNkBdalVQ";
const char *const OBSERVER_TOKEN =
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2V5In0.eyJpc3MiOiJ0ZXN0L2lkcC9zIiwiYXVkIjoiYXBp"
    "Oi8vYWNsLXRlc3QiLCJleHAiOjQxMDI0NDQ4MDAsInN1YiI6InN2Yy1vYnNlcnZlciIsInJvbGVzIjpbIm9ic2VydmVyIl19.DB5"
    "7ToRZb-AS6ei1s17oZMJMWuafJACzI5SfYFEiDRypcaYrWAfNpELBfmOVC9dZ9U8ZpGUM5D9FfIr6FOZu09kyBwjCCwBysGVwM9c"
    "fTgEMh_5lTVvc7XUjChnnKr1Bv3Au56agB78j5JF5ZhYgOIfjkSaZS86ACPiAsyp3z2szyCyCTfZwd9_pEewZCHtvt0DcI5mNG-I"
    "9IuEVCzkQ_hLQOjs8c3axJj7uu345g6b0blWo8AfxcoKNErwZ8JQDBte0AG9Psvio2gvOJVF8tYkfQKgXVvfu0x2_LrQTXdlG1aJ"
    "L7Bf5RRoCbhmfF1Wd2xuTy7R2V2TuxbQaymBGwA";
const char *const MANAGER_TOKEN =
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2V5In0.eyJpc3MiOiJ0ZXN0L2lkcC9zIiwiYXVkIjoiYXBp"
    "Oi8vYWNsLXRlc3QiLCJleHAiOjQxMDI0NDQ4MDAsInN1YiI6InN2Yy1tZ3IiLCJyb2xlcyI6WyJtZ3IiXX0.LYv-MIDAqch_cTM5"
    "qG7hI5t-9X2rC9-klo5wNxN6X_0HzoLB6WUT4ue-Lj-_081sV0g9LVOBWzqrr_9UbtVi5yeDF1u8civJ2SO1pg-tRmJHBDvzuV8Z"
    "Q5Te0VDC0AzXg4g7RxejGpkKZhDoCBS4EfJs1IEKWYfULaN4TM1awHU0A1uBb7MsxCSkYBnuceFdggI_xDnXyRsaR0GkKaHh1Wrj"
    "f5tNON_pO8hUSbpJcyGfilalN-WGrmE-vEB9oW-DVB4VnDRVQ4wTHCdcVq9R3upkB1uU4UtPbUyx8t9Sddma6kCY-QABatkrk-VM"
    "wBUMCV4CcMmBLgUDZyGjzfaWUQ";
const char *const CATALOG_MANAGER_TOKEN =
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2V5In0.eyJpc3MiOiJ0ZXN0L2lkcC9zIiwiYXVkIjoiYXBp"
    "Oi8vYWNsLXRlc3QiLCJleHAiOjQxMDI0NDQ4MDAsInN1YiI6InN2Yy1jYXRtZ3IiLCJyb2xlcyI6WyJjYXRtZ3IiXX0.b0iVRlBx"
    "6-5vWHE2F1XCYFGIjbl5fDJUH7AD4Yiid8KMboO6Xuj6MwXOTp3Hkf9bTto6cd99luOzuaz2NIqIbkMoYlNwFH2I2jfMUvgaO_8H"
    "1ZnNApIJQjjs8S3sMynw1PZlHJCECoIvdVKwC1Kw8ZEIaI165fw6V-4XL2EP65QMtlF9JP33LrWWMEoXGgCQSlzP0oA6Ty2JSh-P"
    "shyeNwBG1ixz6QWYXRGPxQwS-gwuLK61Ng_ZmTUqne3ckZ99cWbIyieaRR37XMwVQXLyhWMoBc8J7bgiY8MSdui201iv4o5yByth"
    "oycYrjbhFiju4oMVnPqXfN9DwiGo2IzS9Q";

struct ObservedResult {
	int status = 0;
	std::string body;
	std::string error;
	std::string www_authenticate;
};

//! spec 097: GET with an `Authorization: Bearer` header ("" = none) against the door
ObservedResult GetObserved(const std::string &path, const std::string &token) {
	duckdb_httplib::Client client("localhost", 31975);
	duckdb_httplib::Headers headers;
	if (!token.empty()) {
		headers.emplace("Authorization", "Bearer " + token);
	}
	ObservedResult result;
	auto response = client.Get(path, headers);
	if (!response) {
		result.error = "no response";
		return result;
	}
	result.status = response->status;
	result.body = response->body;
	result.www_authenticate = response->get_header_value("WWW-Authenticate");
	return result;
}

//! The same fake IdP the provider test uses, trimmed to the password grant.
struct FakeIdp {
	duckdb_httplib::Server server;
	std::thread thread;
	int port = 0;

	std::string Issuer() const {
		return "http://127.0.0.1:" + std::to_string(port);
	}

	void Start() {
		server.Get("/.well-known/openid-configuration", [this](const duckdb_httplib::Request &,
		                                                       duckdb_httplib::Response &res) {
			res.set_content("{\"issuer\":\"" + Issuer() + "\",\"token_endpoint\":\"" + Issuer() + "/token\"}",
			                "application/json");
		});
		server.Post("/token", [this](const duckdb_httplib::Request &req, duckdb_httplib::Response &res) {
			if (req.get_param_value("grant_type") == "password" && req.get_param_value("password") == "pw") {
				res.set_content("{\"access_token\":\"" + std::string(TOKEN) + "\",\"expires_in\":60}",
				                "application/json");
			} else {
				res.status = 400;
				res.set_content("{\"error\":\"invalid_grant\"}", "application/json");
			}
		});
		port = server.bind_to_any_port("127.0.0.1");
		thread = std::thread([this] { server.listen_after_bind(); });
		server.wait_until_ready();
	}
	void Stop() {
		server.stop();
		if (thread.joinable()) {
			thread.join();
		}
	}
	//! RAII: if any Exec throws mid-test, the unwind must not destroy a joinable thread (that is a
	//! std::terminate). Stop() is safe to call twice.
	~FakeIdp() {
		Stop();
	}
};

bool FileExists(const std::string &path) {
	std::ifstream probe(path);
	return probe.good();
}

std::string Shell(const std::string &command) {
	auto *pipe = popen(command.c_str(), "r");
	if (!pipe) {
		return "";
	}
	std::string out;
	char buffer[512];
	while (fgets(buffer, sizeof(buffer), pipe)) {
		out += buffer;
	}
	pclose(pipe);
	return out;
}

void SetupFixture(Connection &con, const std::string &httpfs_ext, const std::string &extra_issuer) {
	// The embedded server's RNG needs a crypto module. httpfs provides one (its OpenSSL util), but acl
	// registers its own OpenSSL-backed one at serve time too, so an empty httpfs_ext exercises that
	// self-contained path — no httpfs, no force_mbedtls_unsafe.
	if (!httpfs_ext.empty()) {
		Exec(con, "LOAD '" + httpfs_ext + "'");
	}
	Exec(con, "ATTACH ':memory:' AS store");
	Exec(con, "CREATE TABLE orders(id INTEGER, tenant VARCHAR)");
	Exec(con, "INSERT INTO orders VALUES (1,'acme'),(2,'acme'),(3,'globex')");
	Exec(con, "SELECT acl_use_db('store','acl',true)");
	Exec(con, "SET GLOBAL acl_allow_anonymous_admin=true");
	Exec(con, "SET GLOBAL acl_jwks_locations = 'test/idp/'");
	Exec(con, "SELECT acl_define_issuer('test/idp/s', '{\"url\": \"test/idp/s\", \"client\": {\"audiences\": "
	          "[\"api://acl-test\"], \"roles_from\": [\"roles\"], \"attributes\": {\"tid\": \"tenant\"}}}')");
	if (!extra_issuer.empty()) {
		// registered ONLY so door discovery would list two issuers; removed again below. Carries a
		// client_id, so discovery must advertise it in the spec-064 shape. The stub IdP is http on
		// loopback: the node fetches its discovery only from a location the operator listed (spec 071)
		Exec(con, "SET GLOBAL acl_jwks_locations = 'https://, test/idp/, " + extra_issuer + "/'");
		Exec(con, "SELECT acl_define_issuer('" + extra_issuer + "', '{\"url\": \"" + extra_issuer +
		              "\", \"client\": {\"audiences\": [\"api://acl-test\"], \"roles_from\": [\"roles\"], "
		              "\"client_id\": \"door-app\"}}')");
	}
	Exec(con, "ACL ADMIN CREATE VIRTUAL CATALOG c");
	Exec(con, "ACL ADMIN CREATE VIRTUAL TABLE c.orders AS memory.main.orders");
	Exec(con, "ACL ADMIN CREATE ROLE analyst");
	Exec(con, "ACL ADMIN GRANT CATALOG c TO ROLE analyst WITH (select, insert) MAIN");
	Exec(con, "ACL ADMIN GRANT TABLE c.orders TO ROLE analyst CAPS '{\"select\": true}' "
	          "RLS 'tenant = acl_claim(''tenant'')' COLUMNS 'id,tenant'");
	// spec 097: who may read the load report and the metrics
	Exec(con, "ACL ADMIN CREATE ROLE observer");
	Exec(con, "ACL ADMIN GRANT ADMIN observe TO ROLE observer");
	Exec(con, "ACL ADMIN CREATE ROLE mgr");
	Exec(con, "ACL ADMIN GRANT ADMIN manage TO ROLE mgr");
	Exec(con, "ACL ADMIN CREATE ROLE catmgr");
	Exec(con, "ACL ADMIN GRANT CATALOG c TO ROLE catmgr CAPS '{\"manage\": true}'");
	Exec(con, "ACL ADMIN CREATE ROLE pt");
	Exec(con, "ACL ADMIN GRANT ADMIN passthrough TO ROLE pt");
	// a privileged role - observe included - is reached only through the client's own mapping (spec 095)
	for (auto role : {"observer", "mgr", "catmgr", "pt"}) {
		Exec(con, std::string("ACL ADMIN MAP CLAIM '") + role + "' FROM CLIENT 'test/idp/s' TO ROLE " + role);
	}
	Exec(con, "SET GLOBAL acl_allow_anonymous_admin=false");
}

} // namespace

int main(int argc, char *argv[]) {
	std::string extension = argc > 1 ? argv[1] : "build/release/extension/acl/acl.duckdb_extension";
	return RunMain("the embedded quack door: discovery + real client + TLS (spec 063)", [&] {
		auto quack_ext = std::string("build/release/extension/quack/quack.duckdb_extension");
		auto httpfs_ext = std::string("build/release/extension/httpfs/httpfs.duckdb_extension");
		if (!FileExists(quack_ext) || !FileExists(httpfs_ext)) {
			std::cout << "  skip: the embedded-door test needs an ACL_QUACK=1 build\n";
			return;
		}
		FakeIdp idp;
		idp.Start();

		DBConfig config;
		config.SetOptionByName("allow_unsigned_extensions", Value::BOOLEAN(true));
		DuckDB db(nullptr, &config);
		Connection con(db);
		Exec(con, "LOAD '" + extension + "'");
		Exec(con, "LOAD '" + quack_ext + "'"); // the CLIENT half, for the ATTACH leg; no clash (acl_quack_* names)
		SetupFixture(con, httpfs_ext, idp.Issuer());
		Exec(con, "SELECT acl_quack_serve('quack:localhost:31975', 'server-token')");

		Scenario("the door advertises its issuers, unauthenticated", [&] {
			auto answer = duckdb::acl::oidc::HttpGet("http://localhost:31975/.well-known/quack-auth");
			Check(answer.Ok(), "the well-known answers: " + answer.error);
			Check(answer.body.find("test/idp/s") != std::string::npos &&
			          answer.body.find(idp.Issuer()) != std::string::npos,
			      "...naming both configured issuers: " + answer.body);
			// spec 064: the document is the doors' shared shape - the reachable IdP's entry carries
			// its client_id and the token endpoint the IdP's own discovery names; the unreachable
			// fixture issuer stays named, endpoint-less
			Check(answer.body.find("\"client_id\":\"door-app\"") != std::string::npos,
			      "...with the issuer's client_id: " + answer.body);
			Check(answer.body.find("\"token_endpoint\":\"" + idp.Issuer() + "/token\"") != std::string::npos,
			      "...and the IdP's live token endpoint: " + answer.body);
		});

		Scenario("a real quack client reads its own slice through the embedded server", [&] {
			Exec(con, "ATTACH 'quack:localhost:31975' AS remote (TYPE quack, TOKEN '" + std::string(TOKEN) + "')");
			auto rows = con.Query("SELECT count(*)::BIGINT FROM remote.main.orders");
			if (CheckOk(*rows, "the ATTACH answers")) {
				Check(rows->Collection().GetValue(0, 0).GetValue<int64_t>() == 2,
				      "...with the acme slice (RLS applied)");
			}
			Exec(con, "DETACH remote");
		});

		Scenario("GET /metrics is opt-in and renders what acl_metrics() answers (spec 069)", [&] {
			auto off = GetObserved("/metrics", OBSERVER_TOKEN);
			Check(off.status == 404,
			      "off by default: 404, like a route that is not there (" + std::to_string(off.status) + ")");
			Exec(con, "SET GLOBAL acl_metrics_endpoint = true");
			auto on = GetObserved("/metrics", OBSERVER_TOKEN);
			Check(on.status == 200, "on: the Prometheus text answers an observer: " + on.error);
			Check(on.body.find("# TYPE acl_sessions_live gauge\n") != std::string::npos,
			      "...with a TYPE line per metric");
			// the client's ATTACH above opened a session at this door: the counter names the door, and
			// the text carries the same value acl_metrics() answers
			auto opened = con.Query("SELECT value FROM acl_metrics() WHERE name = 'acl.sessions.opened' AND "
			                        "attributes = '{\"door\":\"quack\"}'");
			if (CheckOk(*opened, "acl_metrics() has the sessions the door opened") && opened->RowCount() == 1) {
				auto line =
				    "acl_sessions_opened{door=\"quack\"} " + opened->Collection().GetValue(0, 0).ToString() + "\n";
				Check(on.body.find(line) != std::string::npos, "...and the endpoint renders the same row: " + line);
			}
			Check(on.body.find("acl_decisions{") != std::string::npos, "...and the decisions the client's reads were");
			// never a session handle, a subject or an object name: the attribute sets are bounded
			Check(on.body.find("subject=") == std::string::npos && on.body.find("object=") == std::string::npos &&
			          on.body.find("role=") == std::string::npos,
			      "no principal, object or role label anywhere in the text");
			Exec(con, "SET GLOBAL acl_metrics_endpoint = false");
			auto again = GetObserved("/metrics", OBSERVER_TOKEN);
			Check(again.status == 404, "off again: 404 - the setting is read per request");
		});

		Scenario("the load report and /metrics answer only the observe scope (spec 097)", [&] {
			Exec(con, "SET GLOBAL acl_metrics_endpoint = true");
			for (auto path : {"/metrics", "/.well-known/acl-node"}) {
				auto p = std::string(path);
				auto none = GetObserved(p, "");
				Check(none.status == 401 && none.www_authenticate == "Bearer" && none.body == "unauthorized\n",
				      p + ": no token is 401 with WWW-Authenticate: Bearer, and says no more (" +
				          std::to_string(none.status) + " " + none.body + ")");
				auto bad = GetObserved(p, "not-a-jwt");
				Check(bad.status == 401,
				      p + ": a token that does not verify is 401 (" + std::to_string(bad.status) + ")");
				auto analyst = GetObserved(p, TOKEN);
				Check(analyst.status == 403 && analyst.body == "forbidden\n",
				      p + ": a principal without observe is 403 (" + std::to_string(analyst.status) + ")");
				auto catalog_manager = GetObserved(p, CATALOG_MANAGER_TOKEN);
				Check(catalog_manager.status == 403, p + ": a catalog-scoped manage does not read the node's report (" +
				                                         std::to_string(catalog_manager.status) + ")");
				Check(GetObserved(p, OBSERVER_TOKEN).status == 200, p + ": observe reads it");
				Check(GetObserved(p, MANAGER_TOKEN).status == 200, p + ": an unrestricted manage implies observe");
				Check(GetObserved(p, PASSTHROUGH_TOKEN).status == 200, p + ": passthrough implies observe");
			}
			// the operator's opt-out: anyone who reaches the port, and the report says which mode is in force
			Check(GetObserved("/.well-known/acl-node", OBSERVER_TOKEN).body.find("\"observe\":\"token\"") !=
			          std::string::npos,
			      "the report says the token mode is in force");
			Exec(con, "SET GLOBAL acl_observe_unauthenticated = true");
			auto open = GetObserved("/.well-known/acl-node", "");
			Check(open.status == 200 && open.body.find("\"observe\":\"open\"") != std::string::npos,
			      "acl_observe_unauthenticated opens both routes without a token: " + std::to_string(open.status));
			Check(GetObserved("/metrics", "").status == 200, ".../metrics too");
			Exec(con, "SET GLOBAL acl_observe_unauthenticated = false");
			Check(GetObserved("/metrics", "").status == 401, "closed again: 401 - read per request");
			// reads are counted, refusals are recorded and counted - by surface and result, never a principal;
			// the counters are the audit worker's, so drain it first
			Exec(con, "SELECT acl_audit_flush()");
			auto counted = con.Query("SELECT count(*) FROM acl_metrics() WHERE name = 'acl.door.observe' AND "
			                         "attributes LIKE '%\"result\":\"allowed\"%'");
			if (CheckOk(*counted, "acl.door.observe is a counter")) {
				Check(counted->Collection().GetValue(0, 0).GetValue<int64_t>() >= 2,
				      "...with allowed reads of both surfaces");
			}
			auto refused = con.Query("SELECT count(*) FROM acl_metrics() WHERE name = 'acl.door.observe' AND "
			                         "attributes LIKE '%\"result\":\"capability\"%'");
			if (CheckOk(*refused, "...and the refusals")) {
				Check(refused->Collection().GetValue(0, 0).GetValue<int64_t>() >= 1,
				      "...a refusal without the scope counted as capability");
			}
			Exec(con, "SET GLOBAL acl_metrics_endpoint = false");
		});

		Scenario("GET /.well-known/acl-node is the load report, behind the /metrics switch (spec 079)", [&] {
			auto off = GetObserved("/.well-known/acl-node", OBSERVER_TOKEN);
			Check(off.status == 404, "off with acl_metrics_endpoint: 404 (" + std::to_string(off.status) + ")");
			Exec(con, "SET GLOBAL acl_metrics_endpoint = true");
			auto on = GetObserved("/.well-known/acl-node", OBSERVER_TOKEN);
			Check(on.status == 200, "on: the report answers: " + on.error);
			Check(on.body.find("\"uri\":\"quack:localhost:31975\"") != std::string::npos &&
			          on.body.find("\"seats\":16") != std::string::npos,
			      "it names this door and its seats (1024 / 64): " + on.body);
			// the same document acl_node_load() answers, never an identity
			auto sql = con.Query("SELECT acl_node_load()");
			if (CheckOk(*sql, "acl_node_load() answers")) {
				Check(sql->Collection().GetValue(0, 0).ToString() == on.body,
				      "the route and the function are one document");
			}
			Check(on.body.find("analyst") == std::string::npos && on.body.find("\"sub") == std::string::npos,
			      "no role or subject in it");
			Exec(con, "SET GLOBAL acl_metrics_endpoint = false");
		});

		Scenario("a draining node refuses new clients while the established one finishes (spec 066)", [&] {
			Exec(con, "ATTACH 'quack:localhost:31975' AS before (TYPE quack, TOKEN '" + std::string(TOKEN) + "')");
			auto rows = con.Query("SELECT count(*)::BIGINT FROM before.main.orders");
			CheckOk(*rows, "a client is seated before the drain");
			Exec(con, "SELECT acl_drain()");
			rows = con.Query("SELECT count(*)::BIGINT FROM before.main.orders");
			if (CheckOk(*rows, "...and its connection still answers during the drain")) {
				Check(rows->Collection().GetValue(0, 0).GetValue<int64_t>() == 2, "...the same acme slice");
			}
			// the discovery route is the LB's take-me-out signal
			auto wk = duckdb::acl::oidc::HttpGet("http://localhost:31975/.well-known/quack-auth");
			Check(wk.status == 503 && wk.body == "draining",
			      "the well-known answers 503 `draining`: " + std::to_string(wk.status) + " " + wk.body);
			// a fresh connection - the same valid tokens that seated `before` - is refused now
			auto during =
			    con.Query("ATTACH 'quack:localhost:31975' AS during (TYPE quack, TOKEN '" + std::string(TOKEN) + "')");
			auto refused = during->HasError();
			if (!refused) {
				auto probe = con.Query("SELECT count(*) FROM during.main.orders");
				refused = probe->HasError();
				Exec(con, "DETACH during");
			}
			Check(refused, "a new client is refused during the drain");
			Exec(con, "SELECT acl_resume()");
			Exec(con, "ATTACH 'quack:localhost:31975' AS after (TYPE quack, TOKEN '" + std::string(TOKEN) + "')");
			rows = con.Query("SELECT count(*)::BIGINT FROM after.main.orders");
			CheckOk(*rows, "after acl_resume a new client is seated again");
			Exec(con, "DETACH after");
			Exec(con, "DETACH before");
		});

		Scenario("two advertised issuers make an ISSUER-less secret ask for one", [&] {
			auto ambiguous = con.Query("CREATE SECRET amb (TYPE quack, PROVIDER oidc, SCOPE "
			                           "'quack:localhost:31975', CLIENT_ID 'cli', FLOW 'password', "
			                           "USERNAME 'analyst', PASSWORD 'pw')");
			Check(ambiguous->HasError() && ambiguous->GetError().find("2 issuers") != std::string::npos,
			      "the ambiguity is refused with a count: " + ambiguous->GetError());
		});

		Scenario("with one issuer left, discovery fills ISSUER by itself", [&] {
			Exec(con, "SET GLOBAL acl_allow_anonymous_admin=true");
			Exec(con, "ACL ADMIN DROP ISSUER 'test/idp/s'");
			Exec(con, "SET GLOBAL acl_allow_anonymous_admin=false");
			auto minted = con.Query("CREATE SECRET disc (TYPE quack, PROVIDER oidc, SCOPE "
			                        "'quack:localhost:31975', CLIENT_ID 'cli', FLOW 'password', "
			                        "USERNAME 'analyst', PASSWORD 'pw')");
			Check(!minted->HasError(),
			      "the ISSUER-less secret mints via the door: " + (minted->HasError() ? minted->GetError() : ""));
		});

		// LAST on this door: it breaks the policy source under it on purpose
		Scenario("a source that stops answering is 'Authentication failed', never its own text", [&] {
			// Since quack f4328c5 the server hands a failed callback's error back to the client, and a
			// policy source fails with a message that can name a DSN or a catalog. SessionOpen catches
			// its own (spec 040 addendum): the client learns the refusal, the operator learns the
			// reason. This is the client's half of it - what actually crosses the wire.
			Exec(con, "SET GLOBAL acl_audit_level='all'");
			Exec(con, "SET GLOBAL acl_version_check_interval=0");
			Exec(con, "SET GLOBAL acl_allow_anonymous_admin=true");
			// renamed away rather than dropped: the scenarios after this one share the store
			Exec(con, "ALTER TABLE store.acl.meta RENAME TO meta_gone");
			Exec(con, "SET GLOBAL acl_allow_anonymous_admin=false");
			auto refused =
			    con.Query("ATTACH 'quack:localhost:31975' AS broken (TYPE quack, TOKEN '" + std::string(TOKEN) + "')");
			Check(refused->HasError(), "the client's ATTACH is refused");
			auto text = refused->HasError() ? refused->GetError() : std::string();
			Check(text.find("Authentication failed") != std::string::npos, "...with the flat refusal: " + text);
			Check(text.find("meta") == std::string::npos && text.find("acl catalog") == std::string::npos &&
			          text.find("Catalog Error") == std::string::npos,
			      "...and nothing of what the source said: " + text);
			Exec(con, "SELECT acl_audit_flush()");
			auto event = con.Query("SELECT count(*)::BIGINT FROM acl_audit_events() WHERE kind = 'session' AND "
			                       "detail = 'refused' AND door = 'quack' AND reason_code = 'source_error'");
			if (CheckOk(*event, "the audit is asked for the reason")) {
				Check(event->Collection().GetValue(0, 0).GetValue<int64_t>() >= 1,
				      "...and carries it where every refusal at this seam goes: session refused, source_error");
			}
			Exec(con, "SET GLOBAL acl_allow_anonymous_admin=true");
			Exec(con, "ALTER TABLE store.acl.meta_gone RENAME TO meta");
			Exec(con, "SET GLOBAL acl_allow_anonymous_admin=false");
			Exec(con, "SET GLOBAL acl_version_check_interval=1000");
			// the door itself is proven healthy again by the scenarios below, which serve from this
			// same store (the token's issuer was dropped above, so re-attaching here would refuse for
			// a different reason and prove nothing)
		});

		Exec(con, "SELECT acl_quack_stop('quack:localhost:31975')");

		Scenario("the TLS server serves the same discovery over https", [&] {
			auto tmpdir = std::string(getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp");
			auto cert = tmpdir + "/aclembed-cert.pem";
			auto key = tmpdir + "/aclembed-key.pem";
			Shell("openssl req -x509 -newkey rsa:2048 -keyout '" + key + "' -out '" + cert +
			      "' -days 2 -nodes -subj /CN=localhost -addext subjectAltName=DNS:localhost 2>/dev/null");
			if (!FileExists(cert) || !FileExists(key)) {
				std::cout << "  skip: no openssl to mint a throwaway cert\n";
				return;
			}
			if (Shell("command -v curl 2>/dev/null").empty()) {
				std::cout << "  skip: no curl to probe the https server\n";
				std::remove(cert.c_str());
				std::remove(key.c_str());
				return;
			}
			auto served = con.Query("SELECT acl_quack_serve('quack:localhost:31976', 'server-token', '" + cert +
			                        "', '" + key + "')");
			if (served->HasError()) {
				// a build without OpenSSL serves cleartext only, and says so
				Check(served->GetError().find("OpenSSL") != std::string::npos,
				      "TLS on a non-TLS build is a named refusal: " + served->GetError());
				std::remove(cert.c_str());
				std::remove(key.c_str());
				return;
			}
			auto body = Shell("curl -sk https://localhost:31976/.well-known/quack-auth");
			Check(body.find("\"issuers\"") != std::string::npos, "https discovery answers: " + body);
			auto clear = Shell("curl -s -m 3 http://localhost:31976/.well-known/quack-auth");
			Check(clear.find("\"issuers\"") == std::string::npos, "...and cleartext on the same port does not");
			Exec(con, "SELECT acl_quack_stop('quack:localhost:31976')");
			std::remove(cert.c_str());
			std::remove(key.c_str());
		});

		Scenario("mode := 'plain' is a bare server: no discovery route, still acl-gated", [&] {
			// an earlier scenario dropped the token's issuer; re-add it so the client can authenticate
			Exec(con, "SET GLOBAL acl_allow_anonymous_admin=true");
			Exec(con, "SET GLOBAL acl_jwks_locations = 'test/idp/'");
			Exec(con, "SELECT acl_define_issuer('test/idp/s', '{\"url\": \"test/idp/s\", \"client\": {\"audiences\": "
			          "[\"api://acl-test\"], \"roles_from\": [\"roles\"], \"attributes\": {\"tid\": \"tenant\"}}}')");
			Exec(con, "SET GLOBAL acl_allow_anonymous_admin=false");
			Exec(con, "SELECT acl_quack_serve('quack:localhost:31978', 'server-token', 'plain')");
			auto disc = duckdb::acl::oidc::HttpGet("http://localhost:31978/.well-known/quack-auth");
			// the route is not registered in plain mode, so discovery does not carry the issuers list
			Check(!disc.Ok() || disc.body.find("\"issuers\"") == std::string::npos,
			      "plain mode does not advertise discovery: " + disc.body);
			Exec(con, "ATTACH 'quack:localhost:31978' AS bare (TYPE quack, TOKEN '" + std::string(TOKEN) + "')");
			auto rows = con.Query("SELECT count(*)::BIGINT FROM bare.main.orders");
			if (CheckOk(*rows, "a client still ATTACHes to the bare server")) {
				Check(rows->Collection().GetValue(0, 0).GetValue<int64_t>() == 2,
				      "...and the acl gate still applies (acme slice)");
			}
			Exec(con, "DETACH bare");
			Exec(con, "SELECT acl_quack_stop('quack:localhost:31978')");
		});

		Scenario("the server is self-contained: serves with no httpfs and no force_mbedtls_unsafe", [&] {
			// acl registers its own OpenSSL-backed crypto module at serve time, so the RNG works without
			// httpfs and without the unsafe mbedtls flag (whose RNG is a non-crypto PRNG anyway).
			DBConfig cfg;
			cfg.SetOptionByName("allow_unsigned_extensions", Value::BOOLEAN(true));
			DuckDB bare(nullptr, &cfg);
			Connection bc(bare);
			Exec(bc, "LOAD '" + extension + "'");
			SetupFixture(bc, /* no httpfs */ "", "");
			auto served = bc.Query("SELECT acl_quack_serve('quack:localhost:31979', 'server-token')");
			bool ok = !served->HasError();
			// A build with OpenSSL (the flight build) registers acl's own RNG util, so serve succeeds. A
			// build without it (ACL_NO_FLIGHT - the PR CI's linux job) has no such util, so serve is
			// legitimately refused for want of a crypto module. Both are correct; only the flag matters.
			bool refused_no_crypto =
			    served->HasError() && served->GetError().find("crypto module") != std::string::npos;
			Check(ok || refused_no_crypto, "serve without httpfs succeeds (OpenSSL build), or is refused for want of a "
			                               "crypto module (non-OpenSSL build): " +
			                                   (served->HasError() ? served->GetError() : "ok"));
			if (ok) {
				Exec(bc, "SELECT acl_quack_stop('quack:localhost:31979')");
			}
		});

		Scenario("a new instance reclaims a leaked server of a dead one (spec 062 review, kept in 063)", [&] {
			{
				DBConfig cfg;
				cfg.SetOptionByName("allow_unsigned_extensions", Value::BOOLEAN(true));
				DuckDB dying(nullptr, &cfg);
				Connection dc(dying);
				Exec(dc, "LOAD '" + extension + "'");
				Exec(dc, "LOAD '" + quack_ext + "'");
				SetupFixture(dc, httpfs_ext, "");
				Exec(dc, "SELECT acl_quack_serve('quack:localhost:31977', 'server-token')");
				// no acl_quack_stop: the instance is destroyed here, leaking its embedded server
			}
			DBConfig cfg;
			cfg.SetOptionByName("allow_unsigned_extensions", Value::BOOLEAN(true));
			DuckDB fresh(nullptr, &cfg);
			Connection fc(fresh);
			Exec(fc, "LOAD '" + extension + "'");
			Exec(fc, "LOAD '" + quack_ext + "'");
			SetupFixture(fc, httpfs_ext, "");
			auto reserved = fc.Query("SELECT acl_quack_serve('quack:localhost:31977', 'server-token')");
			Check(!reserved->HasError(), "the same address serves again - the dead instance's server was reclaimed: " +
			                                 (reserved->HasError() ? reserved->GetError() : ""));
			Exec(fc, "SELECT acl_quack_stop('quack:localhost:31977')");
		});

		idp.Stop();
	});
}
