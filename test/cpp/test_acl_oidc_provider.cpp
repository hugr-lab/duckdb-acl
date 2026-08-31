// The quack OIDC secret provider (spec 061) against a fake IdP: CREATE SECRET runs the configured
// flow at create time and stores the minted token in the shape quack reads. Exercises every flow's
// happy path and protocol refusal, the fresh-mint-on-replace rule (the cache serves refresh tokens
// only), and — where a quack build is present — the full round trip: a TOKEN-less ATTACH rides the
// provider-minted secret through a served quack door. Build + run via `GEN=ninja make test-cpp`.

#include "acl_test_util.hpp"

#include "duckdb/main/secret/secret.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include "httplib.hpp"

#include <atomic>
#include <fstream>
#include <thread>

using namespace duckdb;
using namespace acl_test;

namespace {

//! The fixture issuer's HS256 token: roles ["analyst"], tid=acme, exp in 2100 - the same one every
//! session test uses, so the round trip's RLS answers are predictable.
const char *const TOKEN =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci50ZXN0L3MiLCJhdWQiOiJhcGk6Ly9hY2w"
    "tdGVzdCIsImV4cCI6NDEwMjQ0NDgwMCwic3ViIjoidSIsInJvbGVzIjpbImFuYWx5c3QiXSwidGlkIjoiYWNtZSJ9.c_RJ0X6_Gj"
    "5O5Z273KOaB9e11XFXVgQkEbtTCayEzJc";

//! A fake IdP with counters, so the test can see WHICH grant answered.
struct FakeIdp {
	duckdb_httplib::Server server;
	std::thread thread;
	int port = 0;
	std::atomic<int> password_grants {0};
	std::atomic<int> refresh_grants {0};

	std::string Issuer() const {
		return "http://127.0.0.1:" + std::to_string(port);
	}

	void Start() {
		server.Get("/.well-known/openid-configuration",
		           [this](const duckdb_httplib::Request &, duckdb_httplib::Response &res) {
			           res.set_content("{\"issuer\":\"" + Issuer() + "\",\"token_endpoint\":\"" + Issuer() +
			                               "/token\",\"device_authorization_endpoint\":\"" + Issuer() + "/device\"}",
			                           "application/json");
		           });
		server.Post("/device", [this](const duckdb_httplib::Request &, duckdb_httplib::Response &res) {
			res.set_content("{\"device_code\":\"dc-1\",\"user_code\":\"WDJB\",\"verification_uri\":\"" + Issuer() +
			                    "/activate\",\"interval\":0,\"expires_in\":60}",
			                "application/json");
		});
		server.Post("/token", [this](const duckdb_httplib::Request &req, duckdb_httplib::Response &res) {
			auto grant = req.get_param_value("grant_type");
			auto deny = [&](const std::string &code) {
				res.status = 400;
				res.set_content("{\"error\":\"" + code + "\",\"error_description\":\"refused\"}", "application/json");
			};
			if (grant == "client_credentials") {
				if (req.get_param_value("client_secret") == "s3cr3t") {
					res.set_content("{\"access_token\":\"cc-token\",\"expires_in\":120}", "application/json");
				} else {
					deny("invalid_client");
				}
				return;
			}
			if (grant == "password") {
				password_grants++;
				if (req.get_param_value("password") == "pw") {
					// the fixture's own HS256 token, so the quack round trip verifies at the door
					res.set_content("{\"access_token\":\"" + std::string(TOKEN) +
					                    "\",\"refresh_token\":\"rt-1\",\"expires_in\":60}",
					                "application/json");
				} else {
					deny("invalid_grant");
				}
				return;
			}
			if (grant == "refresh_token") {
				refresh_grants++;
				if (req.get_param_value("refresh_token") == "rt-1") {
					res.set_content("{\"access_token\":\"" + std::string(TOKEN) + "\",\"expires_in\":60}",
					                "application/json");
				} else {
					deny("invalid_grant");
				}
				return;
			}
			if (grant == "urn:ietf:params:oauth:grant-type:device_code") {
				res.set_content("{\"access_token\":\"device-token\",\"expires_in\":90}", "application/json");
				return;
			}
			deny("unsupported_grant_type");
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

//! The canonical policy fixture of the session tests: a physical orders table, the HS256 issuer,
//! a virtual catalog with claim-driven RLS, and the analyst role the TOKEN carries.
void SetupFixture(Connection &con) {
	// the RLS travels on the GRANT, not inline on the virtual table: the inline form breaks quack's
	// attach-time view composition today (a pre-existing bug recorded in spec 061's notes), and the
	// grant-borne shape is what the quack integration tests serve
	Exec(con, "ATTACH ':memory:' AS store");
	Exec(con, "CREATE TABLE orders(id INTEGER, tenant VARCHAR)");
	Exec(con, "INSERT INTO orders VALUES (1,'acme'),(2,'acme'),(3,'globex')");
	Exec(con, "SELECT acl_use_db('store','acl',true)");
	Exec(con, "SET GLOBAL acl_allow_anonymous_admin=true");
	Exec(con, "SELECT acl_define_issuer('https://issuer.test/s',"
	          "'{\"keys\":[{\"kty\":\"oct\",\"k\":\"YWNsLXRlc3QtaHMyNTYtc2VjcmV0\"}]}',"
	          "'api://acl-test','HS256','roles','{\"tid\": \"tenant\"}')");
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
	return RunMain("the quack OIDC secret provider against a fake IdP (spec 061)", [&] {
		FakeIdp idp;
		idp.Start();

		DBConfig config;
		config.SetOptionByName("allow_unsigned_extensions", Value::BOOLEAN(true));
		DuckDB db(nullptr, &config);
		Connection con(db);
		Exec(con, "LOAD '" + extension + "'");

		Scenario("before quack's type exists, CREATE SECRET is the type lookup's refusal", [&] {
			auto refused = con.Query("CREATE SECRET early (TYPE quack, PROVIDER oidc, FLOW 'token', TOKEN 't')");
			Check(refused->HasError(), "refused: " + (refused->HasError() ? refused->GetError() : "it passed"));
		});

		// the round trip needs the quack extension; without a quack build the flows still run by
		// registering the TYPE the way quack would (a KeyValueSecret type named quack)
		auto quack_ext = std::string("build/release/extension/quack/quack.duckdb_extension");
		auto httpfs_ext = std::string("build/release/extension/httpfs/httpfs.duckdb_extension");
		bool quack_loaded = false;
		if (FileExists(quack_ext) && FileExists(httpfs_ext)) {
			auto loaded_httpfs = con.Query("LOAD '" + httpfs_ext + "'");
			auto loaded = con.Query("LOAD '" + quack_ext + "'");
			quack_loaded = !loaded->HasError() && !loaded_httpfs->HasError();
			if (!quack_loaded) {
				std::cout << "  note: quack/httpfs did not load, provider-only run: " << loaded->GetError() << "\n";
			}
		} else {
			std::cout << "  note: no quack build, provider-only run\n";
		}
		if (!quack_loaded) {
			SecretType secret_type;
			secret_type.name = Identifier("quack");
			secret_type.deserializer = KeyValueSecret::Deserialize<KeyValueSecret>;
			secret_type.default_provider = "oidc";
			SecretManager::Get(*db.instance).RegisterSecretType(secret_type);
		}

		Scenario("every flow mints through the IdP, and refusals are the protocol's own", [&] {
			auto ok = con.Query("CREATE SECRET cc (TYPE quack, PROVIDER oidc, SCOPE 'quack:a', FLOW "
			                    "'client_credentials', ISSUER '" +
			                    idp.Issuer() + "', CLIENT_ID 'svc', CLIENT_SECRET 's3cr3t')");
			Check(!ok->HasError(), "client_credentials mints: " + (ok->HasError() ? ok->GetError() : ""));
			auto bad = con.Query("CREATE SECRET cc2 (TYPE quack, PROVIDER oidc, SCOPE 'quack:b', FLOW "
			                     "'client_credentials', ISSUER '" +
			                     idp.Issuer() + "', CLIENT_ID 'svc', CLIENT_SECRET 'wrong')");
			Check(bad->HasError() && bad->GetError().find("invalid_client") != std::string::npos,
			      "a wrong client secret surfaces the IdP's refusal: " + bad->GetError());
			auto pw = con.Query("CREATE SECRET pw (TYPE quack, PROVIDER oidc, SCOPE 'quack:c', FLOW 'password', "
			                    "ISSUER '" +
			                    idp.Issuer() + "', CLIENT_ID 'cli', USERNAME 'analyst', PASSWORD 'pw')");
			Check(!pw->HasError(), "password mints: " + (pw->HasError() ? pw->GetError() : ""));
			auto dev = con.Query("CREATE SECRET dev (TYPE quack, PROVIDER oidc, SCOPE 'quack:d', FLOW 'device', "
			                     "ISSUER '" +
			                     idp.Issuer() + "', CLIENT_ID 'cli')");
			Check(!dev->HasError(),
			      "device mints (instant grant, no pending): " + (dev->HasError() ? dev->GetError() : ""));
			auto missing = con.Query("CREATE SECRET nf (TYPE quack, PROVIDER oidc, SCOPE 'quack:e', ISSUER '" +
			                         idp.Issuer() + "', CLIENT_ID 'cli')");
			Check(missing->HasError() && missing->GetError().find("FLOW") != std::string::npos,
			      "no flow and no token is refused with guidance");
			auto listed = con.Query("SELECT count(*)::BIGINT FROM duckdb_secrets() WHERE type='quack'");
			if (CheckOk(*listed, "duckdb_secrets answers")) {
				Check(listed->GetValue(0, 0).GetValue<int64_t>() >= 3, "the provider secrets stand");
			}
		});

		Scenario("a replace re-mints FRESH - through the refresh token, never a cached access token", [&] {
			auto before_refresh = idp.refresh_grants.load();
			auto before_password = idp.password_grants.load();
			auto replaced = con.Query("CREATE OR REPLACE SECRET pw (TYPE quack, PROVIDER oidc, SCOPE 'quack:c', "
			                          "FLOW 'password', ISSUER '" +
			                          idp.Issuer() + "', CLIENT_ID 'cli', USERNAME 'analyst', PASSWORD 'pw')");
			Check(!replaced->HasError(), "the replace mints again");
			Check(idp.refresh_grants.load() == before_refresh + 1, "...via grant_type=refresh_token (silent)");
			Check(idp.password_grants.load() == before_password, "...and the password never travelled again");
		});

		if (quack_loaded) {
			Scenario("the round trip: a TOKEN-less ATTACH rides the provider's secret through the door", [&] {
				SetupFixture(con);
				Exec(con, "SELECT acl_quack_serve('quack:localhost:31961', 'test-server-token')");
				Exec(con, "CREATE OR REPLACE SECRET rt (TYPE quack, PROVIDER oidc, SCOPE "
				          "'quack:localhost:31961', FLOW 'password', ISSUER '" +
				              idp.Issuer() + "', CLIENT_ID 'cli', USERNAME 'analyst', PASSWORD 'pw')");
				Exec(con, "ATTACH 'quack:localhost:31961' AS remote (TYPE quack)");
				auto rows = con.Query("SELECT count(*)::BIGINT FROM remote.main.orders");
				if (CheckOk(*rows, "the TOKEN-less ATTACH answers")) {
					Check(rows->GetValue(0, 0).GetValue<int64_t>() == 2,
					      "...with the acme slice the minted token names: " + rows->GetValue(0, 0).ToString());
				}
				Exec(con, "DETACH remote");
				Exec(con, "SELECT acl_quack_stop('quack:localhost:31961')");
			});
		} else {
			std::cout << "  skip: the quack round trip needs an ACL_QUACK=1 build\n";
		}

		idp.Stop();
	});
}
