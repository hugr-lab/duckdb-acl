// Issuers and clients whose connection lives in the node's secrets service (spec 095), against a
// catalog of type `tresor` - the shape tresor attaches: an in-memory catalog and a persistent secret
// storage of the catalog's name (the fake of test_acl_secrets.cpp, without the service functions).
// Here: pasted keys and HS256 from an oidc_issuer secret, KEYS_FROM, one home per parameter, a named
// secret that is missing or of the wrong type, a rotation in the service with no policy write, the
// connection_changed event, an oidc_client carrying CLIENT_SECRET, the node's own memory secrets
// never read, two services and IN, and a service that goes away (fail closed for its issuer only).
// Build + run via `GEN=ninja make test-cpp`.

#include "acl_test_util.hpp"

#include "duckdb/catalog/catalog_transaction.hpp"
#include "duckdb/catalog/duck_catalog.hpp"
#include "duckdb/main/attached_database.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include "duckdb/main/secret/secret_storage.hpp"
#include "duckdb/parser/parsed_data/attach_info.hpp"
#include "duckdb/storage/storage_extension.hpp"
#include "duckdb/transaction/duck_transaction_manager.hpp"

#include <atomic>
#include <unistd.h>

using namespace duckdb;
using namespace acl_test;

namespace {

//! HS256 tokens of https://issuer.test/hs (roles analyst, tid acme): one signed with the fixture's
//! shared key, one with the key it is rotated to
const char *const HS_OK =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci50ZXN0L2hzIiwiYXVkIjoiYXBpOi8vYWNsLXRlc3Qi"
    "LCJleHAiOjQxMDI0NDQ4MDAsInN1YiI6InU4Iiwicm9sZXMiOlsiYW5hbHlzdCJdLCJ0aWQiOiJhY21lIn0.GAd8icsdg891l7-NVJ8bBuz01d"
    "2M2nyNU6uGT6FradM";
const char *const HS_ROTATED =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci50ZXN0L2hzIiwiYXVkIjoiYXBpOi8vYWNsLXRlc3Qi"
    "LCJleHAiOjQxMDI0NDQ4MDAsInN1YiI6InU4Iiwicm9sZXMiOlsiYW5hbHlzdCJdLCJ0aWQiOiJhY21lIn0.HFWoKUb2DiOtoPdM2z2X1GDVkb"
    "XqhvqVVAuv7Dvvgdg";
const char *const OCT_OK = "YWNsLXRlc3QtaHMyNTYtc2VjcmV0";
const char *const OCT_ROTATED = "cm90YXRlZC1zZWNyZXQtMDEyMzQ1Njc4OQ";
//! RS256 tokens of https://issuer.test/kf, signed with the fixture key (test/idp/*/jwks.json):
//! audience api://acl-test (tid acme) and api://door (tid globex)
const char *const KF_RS =
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2V5In0.eyJpc3MiOiJodHRwczovL2lzc3Vlci50ZXN0L2tmIiwiYXVkIjoi"
    "YXBpOi8vYWNsLXRlc3QiLCJleHAiOjQxMDI0NDQ4MDAsInN1YiI6ImsxIiwicm9sZXMiOlsiYW5hbHlzdCJdLCJ0aWQiOiJhY21lIn0.PX_C5AE"
    "m3BqT78CvZ4OR1h8-EDoFOkn0nSmjq8UcvzyNahkaoIxMOERY9vzRe5gyBzlTuVJqqQaqkeDENoiBZaE6BJoFPJL42RSRtwOBLzRZ8ZO3e_vTU7"
    "PlXYmrT5vMsGa0OdUn8tRT4r1EMI6eeP8WhQmFkWdiFS3m-R6jNI4gL4aEeg_M6eCduKuwcFAqTxhMeIvWIH6H1IZxAkFF1MzQR_19npFO2ae1a"
    "Ro4tJ7_f2mXwCE3VRK6OlJ3OiWiKYat4QpLju8ZI-s5SK5oc8dW3VboQwi7bmezaOnbVwvc_KZkERrjKKBgah-jzl4MTytGQANR6YZieQrcauN1"
    "tQ";
const char *const DOOR_RS =
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2V5In0.eyJpc3MiOiJodHRwczovL2lzc3Vlci50ZXN0L2tmIiwiYXVkIjoi"
    "YXBpOi8vZG9vciIsImV4cCI6NDEwMjQ0NDgwMCwic3ViIjoiazIiLCJyb2xlcyI6WyJhbmFseXN0Il0sInRpZCI6Imdsb2JleCJ9.GfmcUPYYjY"
    "Og8JdW0E9K7KZGKFimkS9q22QnpDw-Z6WZ1oPmCh8pYFGiM8G1o5iZvototlr0jRyZD9L8IXgwbR69BlNcAtmdya_VPYtNTpgnpUmC490CvpuXV"
    "S_u2uXsIZCRqchbeRdkMGJLqnTuaI3WQTRQTthmW5s0kKcBGw2Y08V7k6DHFg82kBO6K47K_7RxRCYt3pgdxFlRZ7DV8Hu5P1NAvDXPbw0YJ4r4"
    "x9AaelONOPOjacTY65_or1CKHIJLY0yZ8U9_yJGhUe5KAGMAVeApnGxyGr95XYZa2CmWrCSKvj2KRpPnnZI70cPwsOdP8j4rj2825WBQp5h3dw";

class FakeServiceStorage : public CatalogSetSecretStorage {
public:
	FakeServiceStorage(DatabaseInstance &db, const string &name, int64_t offset)
	    : CatalogSetSecretStorage(db, name, offset) {
		secrets = make_uniq<CatalogSet>(Catalog::GetSystemCatalog(db));
		persistent = true;
	}
};

class FakeServiceCatalog : public DuckCatalog {
public:
	explicit FakeServiceCatalog(AttachedDatabase &db) : DuckCatalog(db) {
	}
	string GetCatalogType() override {
		return "tresor";
	}
	void Initialize(bool load_builtin) override {
		DuckCatalog::Initialize(false);
		GetAttached().SetReadOnlyDatabase();
	}
};

unique_ptr<Catalog> FakeAttach(optional_ptr<StorageExtensionInfo>, ClientContext &context, AttachedDatabase &db,
                               const string &name, AttachInfo &info, AttachOptions &) {
	static std::atomic<int64_t> next_offset {30}; // duckdb refuses two storages with one tie-break score
	SecretManager::Get(context).LoadSecretStorage(
	    make_uniq<FakeServiceStorage>(db.GetDatabase(), name, next_offset.fetch_add(1)));
	info.path = IN_MEMORY_PATH;
	return make_uniq<FakeServiceCatalog>(db);
}

unique_ptr<TransactionManager> FakeTransactions(optional_ptr<StorageExtensionInfo>, AttachedDatabase &db, Catalog &) {
	return make_uniq<DuckTransactionManager>(db);
}

std::string One(Connection &con, const std::string &sql) {
	auto result = con.Query(sql);
	if (result->HasError()) {
		return "ERROR: " + result->GetError();
	}
	return result->RowCount() ? result->Collection().GetValue(0, 0).ToString() : "";
}

bool Refused(Connection &con, const std::string &sql, const std::string &why) {
	auto result = con.Query(sql);
	return Check(result->HasError() && result->GetError().find(why) != std::string::npos,
	             "refused (" + why + "): " + (result->HasError() ? result->GetError() : "it ran"));
}

std::string Token(const char *token, const std::string &sql) {
	return std::string("ACL TOKEN '") + token + "' " + sql;
}

std::string IssuerSecret(const std::string &name, const std::string &service, const std::string &fields,
                         bool replace = false) {
	return std::string("CREATE ") + (replace ? "OR REPLACE " : "") + "PERSISTENT SECRET " + name + " IN " + service +
	       " (TYPE oidc_issuer, " + fields + ")";
}

std::string OctKeys(const char *k) {
	return std::string("KEYS '{\"keys\":[{\"kty\":\"oct\",\"k\":\"") + k + "\"}]}'";
}

} // namespace

int main(int argc, char *argv[]) {
	return RunMain("issuers and clients from the secrets service (spec 095)", [&] {
		DBConfig config;
		char directory[] = "/tmp/acl-identity-secrets-XXXXXX";
		if (!Check(mkdtemp(directory) != nullptr, "a secret directory of the test's own")) {
			return;
		}
		config.SetOptionByName("secret_directory", Value(std::string(directory)));
		DuckDB db(nullptr, &config);
		auto storage = make_shared_ptr<StorageExtension>();
		storage->attach = FakeAttach;
		storage->create_transaction_manager = FakeTransactions;
		StorageExtension::Register(DBConfig::GetConfig(*db.instance), "tresor", std::move(storage));
		Connection con(db);
		Exec(con, "ATTACH ':memory:' AS phys");
		Exec(con, "CREATE TABLE phys.main.orders(id INT, tenant VARCHAR)");
		Exec(con, "INSERT INTO phys.main.orders VALUES (1, 'acme'), (2, 'acme'), (3, 'globex')");
		Exec(con, "ATTACH ':memory:' AS store");
		Exec(con, "SELECT acl_use_db('store','acl',true)");
		Exec(con, "SET GLOBAL acl_allow_anonymous_admin=true");
		Exec(con, "SET GLOBAL acl_jwks_locations = 'test/idp/'");
		Exec(con, "SET GLOBAL acl_audit_level='all'");
		Exec(con, "ACL ADMIN CREATE VIRTUAL CATALOG c");
		Exec(con, "ACL ADMIN CREATE VIRTUAL TABLE c.orders AS phys.main.orders RLS 'tenant = acl_claim(''tenant'')'");
		Exec(con, "ACL ADMIN CREATE ROLE analyst");
		Exec(con, "ACL ADMIN GRANT CATALOG c TO ROLE analyst MAIN");
		Exec(con, "ATTACH '' AS corp (TYPE tresor)");

		Scenario("an HS256 key is pasted into a secret, and only there", [&] {
			Exec(con, IssuerSecret("hs_conn", "corp",
			                       "URL 'https://issuer.test/hs', " + OctKeys(OCT_OK) + ", ALGS 'HS256'"));
			Exec(con, "ACL ADMIN CREATE ISSUER hs FROM SECRET hs_conn");
			Exec(con, "ACL ADMIN CREATE CLIENT hs_app ISSUER hs AUDIENCES ('api://acl-test') ROLES FROM ('roles') "
			          "UNMAPPED AS ROLE ATTRIBUTES (tenant = 'tid')");
			Check(One(con, Token(HS_OK, "SELECT count(*) FROM orders")) == "2",
			      "the token verifies with the pasted key");
			// what the policy holds: the secret's name and its service, never its fields
			Check(One(con, "SELECT url IS NULL AND secret = 'hs_conn' AND secret_service = 'corp' FROM acl_issuers() "
			               "WHERE name = 'hs'") == "true",
			      "the issuer names its secret: " + One(con, "SELECT * FROM acl_issuers()"));
			Check(One(con, "SELECT count(*) FROM store.acl.issuers WHERE columns(*)::VARCHAR LIKE '%" +
			                   std::string(OCT_OK) + "%'") == "0",
			      "no key material in the policy catalog");
			// the service redacts the pasted keys like any secret field it must
			Check(
			    One(con, "SELECT secret_string LIKE '%keys=redacted%' FROM duckdb_secrets() WHERE name = 'hs_conn'") ==
			        "true",
			    "KEYS is redacted: " + One(con, "SELECT secret_string FROM duckdb_secrets() WHERE name = 'hs_conn'"));
		});

		Scenario("without ALGS naming it, a pasted key verifies RS256 / ES256 only", [&] {
			Exec(con, IssuerSecret("hs_conn", "corp", "URL 'https://issuer.test/hs', " + OctKeys(OCT_OK), true));
			Refused(con, Token(HS_OK, "SELECT 1"), "algorithm \"HS256\" is not allowed for this issuer");
			Exec(con, IssuerSecret("hs_conn", "corp",
			                       "URL 'https://issuer.test/hs', " + OctKeys(OCT_OK) + ", ALGS 'HS256'", true));
			// the algorithms are part of the connection: the node notices the change where it resolves it
			Check(One(con, Token(HS_OK, "SELECT count(*) FROM orders")) == "2", "HS256 again, once ALGS names it");
		});

		Scenario("a key swapped in the service takes effect with no policy write, and is audited", [&] {
			auto version = One(con, "SELECT policy_version FROM acl_status()");
			Exec(con, "SELECT acl_audit_flush()");
			auto changes = One(con, "SELECT count(*) FROM acl_audit_events() WHERE kind = 'policy' AND detail = "
			                        "'connection_changed'");
			Exec(con, IssuerSecret("hs_conn", "corp",
			                       "URL 'https://issuer.test/hs', " + OctKeys(OCT_ROTATED) + ", ALGS 'HS256'", true));
			Refused(con, Token(HS_OK, "SELECT 1"), "signature verification failed");
			Check(One(con, Token(HS_ROTATED, "SELECT count(*) FROM orders")) == "2", "the rotated key verifies");
			Check(One(con, "SELECT policy_version FROM acl_status()") == version, "the policy did not change");
			// a pasted key swapped in the service changes whom the node trusts (whoever holds the new key mints
			// its tokens): one connection_changed, with a fingerprint and never the key
			Exec(con, "SELECT acl_audit_flush()");
			Check(One(con, "SELECT count(*) FROM acl_audit_events() WHERE kind = 'policy' AND detail = "
			               "'connection_changed'") == std::to_string(std::stoll(changes) + 1),
			      "a swapped key is a connection change");
			Check(One(con, "SELECT count(*) FROM acl_audit_events() WHERE reason LIKE '%" + std::string(OCT_ROTATED) +
			                   "%'") == "0",
			      "the key is not in the event");
		});

		Scenario("one home per parameter, and a named secret must exist with the right type", [&] {
			Refused(con, "ACL ADMIN ALTER ISSUER hs SET URL 'https://issuer.test/hs'",
			        "has its URL both on the issuer and in its secret");
			Refused(con, "ACL ADMIN CREATE ISSUER ghost FROM SECRET nosuch", "has no secret of type oidc_issuer");
			Exec(con, "CREATE PERSISTENT SECRET a_client IN corp (TYPE oidc_client, CLIENT_ID 'x')");
			Refused(con, "ACL ADMIN CREATE ISSUER wrong FROM SECRET a_client", "has no secret of type oidc_issuer");
			Exec(con, IssuerSecret("both_keys", "corp",
			                       "URL 'https://issuer.test/both', " + OctKeys(OCT_OK) +
			                           ", KEYS_FROM 'test/idp/rs/jwks.json'"));
			Refused(con, "ACL ADMIN CREATE ISSUER both_keys FROM SECRET both_keys", "carries both KEYS and KEYS_FROM");
		});

		Scenario("the node's own memory secrets are never read", [&] {
			Exec(con, "CREATE SECRET local_conn (TYPE oidc_issuer, URL 'https://issuer.test/local', " +
			              OctKeys(OCT_OK) + ", ALGS 'HS256')");
			Refused(con, "ACL ADMIN CREATE ISSUER local FROM SECRET local_conn",
			        "corp has no secret of type oidc_issuer by that name");
		});

		Scenario("KEYS_FROM: a location of the secret's, judged by the node's list", [&] {
			Exec(con,
			     IssuerSecret("kf_conn", "corp", "URL 'https://issuer.test/kf', KEYS_FROM 'test/idp/rs/jwks.json'"));
			Exec(con, "ACL ADMIN CREATE ISSUER kf FROM SECRET kf_conn");
			Exec(con, "ACL ADMIN CREATE CLIENT kf_app ISSUER kf AUDIENCES ('api://acl-test') ROLES FROM ('roles') "
			          "UNMAPPED AS ROLE ATTRIBUTES (tenant = 'tid')");
			Check(One(con, Token(KF_RS, "SELECT count(*) FROM orders")) == "2", "keys read from the secret's location");
			Exec(con, "SET GLOBAL acl_jwks_locations = 'https://'");
			Refused(con, Token(KF_RS, "SELECT 1"), "is outside acl_jwks_locations");
			Exec(con, "SET GLOBAL acl_jwks_locations = 'test/idp/'");
			// a change of the key SOURCE through the secret is a connection change, audited
			Exec(con, IssuerSecret("kf_conn", "corp", "URL 'https://issuer.test/kf', KEYS_FROM 'test/idp/s/jwks.json'",
			                       true));
			Check(One(con, Token(KF_RS, "SELECT count(*) FROM orders")) == "2", "the same keys from the new location");
			Exec(con, "SELECT acl_audit_flush()");
			Check(One(con, "SELECT count(*) FROM acl_audit_events() WHERE kind = 'policy' AND detail = "
			               "'connection_changed' AND reason LIKE 'issuer kf now resolves to connection %'") == "1",
			      "connection_changed: " +
			          One(con, "SELECT string_agg(detail || ' ' || reason, '; ') FROM acl_audit_events() WHERE kind = "
			                   "'policy'"));
		});

		Scenario("an oidc_client secret: audiences, client id and the client secret", [&] {
			Exec(con, "CREATE PERSISTENT SECRET door_conn IN corp (TYPE oidc_client, AUDIENCES 'api://door', "
			          "CLIENT_ID 'door-app', CLIENT_SECRET 'super-secret-value')");
			Exec(con, "ACL ADMIN CREATE CLIENT door ISSUER kf FROM SECRET door_conn ROLES FROM ('roles') UNMAPPED AS "
			          "ROLE ATTRIBUTES (tenant = 'tid') FLOWS (password)");
			Check(One(con, Token(DOOR_RS, "SELECT count(*) FROM orders")) == "1", "the secret's audience routes it");
			Check(One(con, "SELECT audiences IS NULL AND client_id IS NULL AND secret = 'door_conn' FROM acl_clients() "
			               "WHERE name = 'door'") == "true",
			      "the client names its secret: " + One(con, "SELECT * FROM acl_clients() WHERE name = 'door'"));
			Check(One(con, "SELECT count(*) FROM (SELECT * FROM acl_clients()) WHERE columns(*)::VARCHAR LIKE "
			               "'%super-secret-value%'") == "0",
			      "no listing carries the client secret");
			Check(One(con, "SELECT secret_string LIKE '%client_secret=redacted%' FROM duckdb_secrets() WHERE name = "
			               "'door_conn'") == "true",
			      "CLIENT_SECRET is redacted");
			// a parameter in both places is refused where it is written
			Refused(con, "ACL ADMIN ALTER CLIENT door SET CLIENT ID 'other-app'",
			        "both on the client and in its secret");
			// the short form's client may name one too: a confidential client runs the password flow
			Exec(con, IssuerSecret("short_conn", "corp", "URL 'https://issuer.test/short', " + OctKeys(OCT_OK)));
			Exec(con, "CREATE PERSISTENT SECRET short_client IN corp (TYPE oidc_client, CLIENT_ID 'short-app', "
			          "CLIENT_SECRET 'another-secret')");
			Exec(con, "ACL ADMIN CREATE ISSUER short FROM SECRET short_conn AUDIENCES ('api://short') ROLE CLAIM "
			          "'roles' CLIENT FROM SECRET short_client");
			Check(One(con, "SELECT flows FROM acl_clients() WHERE name = 'short'") == "[\"password\"]",
			      "a confidential implicit client runs the password flow: " +
			          One(con, "SELECT flows FROM acl_clients() WHERE name = 'short'"));
		});

		Scenario("two services: an unnamed one is ambiguous, IN names it", [&] {
			Exec(con, "ATTACH '' AS vault (TYPE tresor)");
			Exec(con,
			     IssuerSecret("v_conn", "vault", "URL 'https://issuer.test/v', KEYS_FROM 'test/idp/rs/jwks.json'"));
			Refused(con, "ACL ADMIN CREATE ISSUER v FROM SECRET v_conn", "several secrets services are attached");
			Exec(con, "ACL ADMIN CREATE ISSUER v FROM SECRET v_conn IN vault");
			Check(One(con, "SELECT secret_service FROM acl_issuers() WHERE name = 'v'") == "vault",
			      "kept with its service");
		});

		Scenario("a service that goes away fails its issuers closed, and only them", [&] {
			Exec(con, "DETACH vault");
			Check(One(con, Token(KF_RS, "SELECT count(*) FROM orders")) == "2",
			      "an issuer of another service still works");
			Exec(con, "DETACH corp");
			Refused(con, Token(KF_RS, "SELECT 1"), "unknown issuer \"https://issuer.test/kf\" (the URL of");
		});
	});
}
