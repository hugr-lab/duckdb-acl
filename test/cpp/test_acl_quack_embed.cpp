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

#include "acl_oidc.hpp"

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
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci50ZXN0L3MiLCJhdWQiOiJhcGk6Ly9hY2w"
    "tdGVzdCIsImV4cCI6NDEwMjQ0NDgwMCwic3ViIjoidSIsInJvbGVzIjpbImFuYWx5c3QiXSwidGlkIjoiYWNtZSJ9.c_RJ0X6_Gj"
    "5O5Z273KOaB9e11XFXVgQkEbtTCayEzJc";

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
	Exec(con, "SELECT acl_define_issuer('https://issuer.test/s',"
	          "'{\"keys\":[{\"kty\":\"oct\",\"k\":\"YWNsLXRlc3QtaHMyNTYtc2VjcmV0\"}]}',"
	          "'api://acl-test','HS256','roles','{\"tid\": \"tenant\"}')");
	if (!extra_issuer.empty()) {
		// registered ONLY so door discovery would list two issuers; removed again below
		Exec(con, "SELECT acl_define_issuer('" + extra_issuer +
		              "','{\"keys\":[{\"kty\":\"oct\",\"k\":\"YWNsLXRlc3QtaHMyNTYtc2VjcmV0\"}]}',"
		              "'api://acl-test','HS256','roles','{}')");
	}
	Exec(con, "ACL ADMIN CREATE VIRTUAL CATALOG c");
	Exec(con, "ACL ADMIN CREATE VIRTUAL TABLE c.orders AS memory.main.orders");
	Exec(con, "ACL ADMIN CREATE ROLE analyst");
	Exec(con, "ACL ADMIN GRANT CATALOG c TO ROLE analyst WITH (select, insert) MAIN");
	Exec(con, "ACL ADMIN GRANT TABLE c.orders TO ROLE analyst CAPS '{\"select\": true}' "
	          "RLS 'tenant = acl_claim(''tenant'')' COLUMNS 'id,tenant'");
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
			Check(answer.body.find("https://issuer.test/s") != std::string::npos &&
			          answer.body.find(idp.Issuer()) != std::string::npos,
			      "...naming both configured issuers: " + answer.body);
		});

		Scenario("a real quack client reads its own slice through the embedded server", [&] {
			Exec(con, "ATTACH 'quack:localhost:31975' AS remote (TYPE quack, TOKEN '" + std::string(TOKEN) + "')");
			auto rows = con.Query("SELECT count(*)::BIGINT FROM remote.main.orders");
			if (CheckOk(*rows, "the ATTACH answers")) {
				Check(rows->GetValue(0, 0).GetValue<int64_t>() == 2, "...with the acme slice (RLS applied)");
			}
			Exec(con, "DETACH remote");
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
			Exec(con, "ACL ADMIN DROP ISSUER 'https://issuer.test/s'");
			Exec(con, "SET GLOBAL acl_allow_anonymous_admin=false");
			auto minted = con.Query("CREATE SECRET disc (TYPE quack, PROVIDER oidc, SCOPE "
			                        "'quack:localhost:31975', CLIENT_ID 'cli', FLOW 'password', "
			                        "USERNAME 'analyst', PASSWORD 'pw')");
			Check(!minted->HasError(),
			      "the ISSUER-less secret mints via the door: " + (minted->HasError() ? minted->GetError() : ""));
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
			Exec(con, "SELECT acl_define_issuer('https://issuer.test/s',"
			          "'{\"keys\":[{\"kty\":\"oct\",\"k\":\"YWNsLXRlc3QtaHMyNTYtc2VjcmV0\"}]}',"
			          "'api://acl-test','HS256','roles','{\"tid\": \"tenant\"}')");
			Exec(con, "SET GLOBAL acl_allow_anonymous_admin=false");
			Exec(con, "SELECT acl_quack_serve('quack:localhost:31978', 'server-token', 'plain')");
			auto disc = duckdb::acl::oidc::HttpGet("http://localhost:31978/.well-known/quack-auth");
			// the route is not registered in plain mode, so discovery does not carry the issuers list
			Check(!disc.Ok() || disc.body.find("\"issuers\"") == std::string::npos,
			      "plain mode does not advertise discovery: " + disc.body);
			Exec(con, "ATTACH 'quack:localhost:31978' AS bare (TYPE quack, TOKEN '" + std::string(TOKEN) + "')");
			auto rows = con.Query("SELECT count(*)::BIGINT FROM bare.main.orders");
			if (CheckOk(*rows, "a client still ATTACHes to the bare server")) {
				Check(rows->GetValue(0, 0).GetValue<int64_t>() == 2, "...and the acl gate still applies (acme slice)");
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
			Check(!served->HasError(),
			      "serve without httpfs succeeds: " + (served->HasError() ? served->GetError() : ""));
			Exec(bc, "SELECT acl_quack_stop('quack:localhost:31979')");
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
