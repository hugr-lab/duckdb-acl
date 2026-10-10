// Spec 093: ACL CLUSTER INSTALL EXTENSION installs from a trusted repository (duckdb 2.0's CREATE
// EXTENSION REPOSITORY) and writes the item only when the live install worked. Spec 103: the item is
// a version and a repository - the repository's signature, which DuckDB verifies at every INSTALL and
// LOAD, is the integrity check, and a SHA256 clause is refused. The repository is a local directory in duckdb's
// versioned layout
// (<repo>/<name>/<version>/<revision>/<platform>/<name>.duckdb_extension.gz), holding this build's
// own postgres_scanner - a loadable built against this exact duckdb. Skipped when the build has none
// (a plain build: postgres_scanner comes with ACL_INTEGRATION=1).
// Build + run via `GEN=ninja make test-cpp`.

#include "acl_test_util.hpp"

#include "duckdb.hpp"
#include "duckdb/main/extension_helper.hpp"

#include <cstdlib>
#include <sys/stat.h>
#include <unistd.h>

using namespace duckdb;
using namespace acl_test;

namespace {

const char *const LOADABLE = "build/release/extension/postgres_scanner/postgres_scanner.duckdb_extension";

//! A valid RSA public key (duckdb's own repository test key): the repository needs one pinned; the
//! loadable is unsigned, which allow_unsigned_extensions admits in this test only
const char *const PUBLIC_KEY =
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt9+KeDkWJa7SiBb7AMdXAPV2qpRunztoC2c7DtRmN9+Lq2YQm4rMQmmAQcwyxTxcK8vwPK"
    "OiE4mLMwmQMvTty9tL+buREfvg5KJ+FY3Bv05cZYsf7VuYgUDcw41zSEE5W1thh5PiafcrMn7CPF0jN0oFfVvAHB/fAM0yaZGPKs3WYqnHAHa6v/cV"
    "MeiWZ/lQORCBqqL2hii1fEiuIqw6AOEoZVsN0/lqm7GfnD899zrzLOPRuP4YFg46drL1UyNdg+4TquJ2OV9kR4CAfdGRexqHFWLmoxkTfnUxJ4yL+g"
    "kV57K1H+smEdKrDhDX68pEFM/34E2eVKZoRU/0paxDZQIDAQAB";

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

} // namespace

int main() {
	return RunMain("the cluster profile installs from a trusted repository (specs 093, 103)", [] {
		struct stat info;
		if (stat(LOADABLE, &info) != 0) {
			std::cout << "  SKIP: no postgres_scanner loadable in this build (ACL_INTEGRATION=1 builds one)\n";
			return;
		}
		char root[] = "/tmp/acl-cluster-XXXXXX";
		if (!Check(mkdtemp(root) != nullptr, "a directory of the test's own")) {
			return;
		}
		std::string base(root);
		auto dir = base + "/repo/postgres_scanner/v9.9.9/" + ExtensionHelper::GetVersionDirectoryName() + "/" +
		           DuckDB::Platform();
		Check(std::system(("mkdir -p '" + dir + "' '" + base + "/repos' '" + base + "/ext'").c_str()) == 0,
		      "the repository's layout");
		Check(
		    std::system(("gzip -c '" + std::string(LOADABLE) + "' > '" + dir + "/postgres_scanner.duckdb_extension.gz'")
		                    .c_str()) == 0,
		    "the extension in it");

		DBConfig config;
		config.SetOptionByName("allow_extension_repositories", Value("allowed"));
		config.SetOptionByName("allow_unsigned_extensions", Value::BOOLEAN(true));
		config.SetOptionByName("extension_repository_directory", Value(base + "/repos"));
		config.SetOptionByName("extension_directory", Value(base + "/ext"));
		config.SetOptionByName("autoload_known_extensions", Value::BOOLEAN(false));
		DuckDB db(nullptr, &config);
		Connection con(db);
		Exec(con, "CREATE EXTENSION REPOSITORY trusted WITH PREFIX '" + base + "/repo' USING PUBLIC KEY '" +
		              PUBLIC_KEY + "'");
		Exec(con, "ATTACH ':memory:' AS store");
		Exec(con, "SELECT acl_use_db('store','acl',true)");
		Exec(con, "SET GLOBAL acl_deployment = 'cluster'"); // spec 118: the profile is a cluster node's
		Exec(con, "SET GLOBAL acl_allow_anonymous_admin=true");

		Scenario("a SHA256 clause is refused, never ignored, and writes nothing (spec 103)", [&] {
			Refused(con,
			        "ACL ADMIN CLUSTER INSTALL EXTENSION postgres_scanner VERSION 'v9.9.9' FROM trusted SHA256 "
			        "'0000000000000000000000000000000000000000000000000000000000000000'",
			        "SHA256 is no longer part of the cluster profile (spec 103)");
			Check(One(con, "SELECT count(*) FROM acl_cluster_items()") == "0", "the profile is unchanged");
			Check(One(con, "SELECT acl_cluster_version()") == "0", "and so is its version");
		});

		Scenario("the install loads the extension and writes a version and a repository", [&] {
			auto answer =
			    One(con, "ACL ADMIN CLUSTER INSTALL EXTENSION postgres_scanner VERSION 'v9.9.9' FROM trusted");
			Check(answer.find("'applied_here': true") != std::string::npos, "applied on this node: " + answer);
			Check(One(con, "SELECT count(*) FROM duckdb_functions() WHERE function_name = 'postgres_query'") != "0",
			      "loaded: its functions are registered");
			auto spec = One(con, "SELECT spec FROM acl_cluster_items() WHERE name = 'postgres_scanner'");
			Check(spec.find("\"repository\": \"trusted\"") != std::string::npos &&
			          spec.find("\"version\": \"v9.9.9\"") != std::string::npos,
			      "the item names its version and repository: " + spec);
			Check(spec.find("sha256") == std::string::npos, "and no hash: " + spec);
			Refused(con, "ACL ADMIN CLUSTER INSTALL EXTENSION postgres_scanner VERSION 'v9.9.9' FROM trusted",
			        "already in the profile");
			Refused(con, "ACL ADMIN CLUSTER UPDATE EXTENSION postgres_scanner VERSION 'v9.9.10' SHA256 'ab'",
			        "spec 103");
		});

		Scenario("an update or a removal is restart class: described, not applied live", [&] {
			auto answer = One(con, "ACL ADMIN CLUSTER UPDATE EXTENSION postgres_scanner VERSION 'v9.9.10'");
			Check(answer.find("'class': restart") != std::string::npos &&
			          answer.find("'applied_here': false") != std::string::npos,
			      "update: " + answer);
			answer = One(con, "ACL ADMIN CLUSTER REMOVE EXTENSION postgres_scanner");
			Check(answer.find("'class': restart") != std::string::npos, "remove: " + answer);
			Check(One(con, "SELECT count(*) FROM acl_cluster_items()") == "0", "the item left the profile");
		});
	});
}
