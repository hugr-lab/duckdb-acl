// The quack door's front listener (spec 062): the public bind belongs to the front, which answers
// /.well-known/quack-auth itself and streams everything else to the loopback quack. Exercised end to
// end: the discovery document names the fixture issuer; a real quack ATTACH rides through the proxy;
// an ISSUER-less provider secret discovers the issuer from the door; and the TLS variant serves the
// same discovery over https (checked with curl -k against a throwaway openssl cert). Needs an
// ACL_QUACK build for the proxy legs; skips them gracefully otherwise.

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

void SetupFixture(Connection &con, const std::string &extra_issuer) {
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
	return RunMain("the quack front: discovery + proxy + TLS (spec 062)", [&] {
		auto quack_ext = std::string("build/release/extension/quack/quack.duckdb_extension");
		auto httpfs_ext = std::string("build/release/extension/httpfs/httpfs.duckdb_extension");
		if (!FileExists(quack_ext) || !FileExists(httpfs_ext)) {
			std::cout << "  skip: the front test needs an ACL_QUACK=1 build\n";
			return;
		}
		FakeIdp idp;
		idp.Start();

		DBConfig config;
		config.SetOptionByName("allow_unsigned_extensions", Value::BOOLEAN(true));
		DuckDB db(nullptr, &config);
		Connection con(db);
		Exec(con, "LOAD '" + extension + "'");
		Exec(con, "LOAD '" + httpfs_ext + "'");
		Exec(con, "LOAD '" + quack_ext + "'");
		SetupFixture(con, idp.Issuer());
		Exec(con, "SELECT acl_quack_serve('quack:localhost:31975', 'front-token')");

		Scenario("the door advertises its issuers, unauthenticated", [&] {
			auto answer = duckdb::acl::oidc::HttpGet("http://localhost:31975/.well-known/quack-auth");
			Check(answer.Ok(), "the well-known answers: " + answer.error);
			Check(answer.body.find("https://issuer.test/s") != std::string::npos &&
			          answer.body.find(idp.Issuer()) != std::string::npos,
			      "...naming both configured issuers: " + answer.body);
		});

		Scenario("a real quack client rides through the front's proxy", [&] {
			Exec(con, "ATTACH 'quack:localhost:31975' AS remote (TYPE quack, TOKEN '" + std::string(TOKEN) + "')");
			auto rows = con.Query("SELECT count(*)::BIGINT FROM remote.main.orders");
			if (CheckOk(*rows, "the proxied ATTACH answers")) {
				Check(rows->GetValue(0, 0).GetValue<int64_t>() == 2, "...with the acme slice");
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

		Scenario("the TLS front serves the same discovery over https", [&] {
			auto tmpdir = std::string(getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp");
			auto cert = tmpdir + "/aclfront-cert.pem";
			auto key = tmpdir + "/aclfront-key.pem";
			Shell("openssl req -x509 -newkey rsa:2048 -keyout '" + key + "' -out '" + cert +
			      "' -days 2 -nodes -subj /CN=localhost -addext subjectAltName=DNS:localhost 2>/dev/null");
			if (!FileExists(cert) || !FileExists(key)) {
				Check(true, "skip: no openssl to mint a throwaway cert");
				return;
			}
			auto served = con.Query("SELECT acl_quack_serve('quack:localhost:31976', 'front-token', '" + cert + "', '" +
			                        key + "')");
			if (served->HasError()) {
				// a build without OpenSSL fronts cleartext only, and says so
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

		idp.Stop();
	});
}
