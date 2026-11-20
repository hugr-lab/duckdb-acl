// spec 176 (hugr-node spec 035): a node whose resource group declares the sources it attaches - only part of the
// cluster's - writes no policy and runs no check of the stored facts against the sources: either would be judged
// against sources it lacks. Its operation and console_info run. The trait is the platform part's
// (PolicyStore::NodeTraits::partial_sources); here it is set by hand.
// Build + run via `GEN=ninja make test-cpp`.

#include "acl_test_util.hpp"

#include "acl_policy.hpp"

using namespace duckdb;
using namespace acl_test;

namespace {

//! An RS256 token for the issuer the fixture defines: roles ["analyst"], tid=acme, exp in 2100.
const char *const TOKEN =
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2V5In0.eyJpc3MiOiJ0ZXN0L2lkcC9zIiwiYXVkIjoiYXBp"
    "Oi8vYWNsLXRlc3QiLCJleHAiOjQxMDI0NDQ4MDAsInN1YiI6InUiLCJyb2xlcyI6WyJhbmFseXN0Il0sInRpZCI6ImFjbWUifQ.C"
    "2rTehH2D3jptrk0TWAepMNA5XjhgHBCEYVr1NzJm7xa7ygxGtgCV9NpejZV3FFT2ex7QaC5xaoFHy59n5VbOw8I9t5_5qUvGkbDu"
    "SvyEYCLBlzdSczLOn7Su7k9rSIsMVvmbamtp_IhgyF1_ct0e1hm03Q2Vrm509omfcDvs9W8AyV9aPHUWui8bC-7hzw__gyiiZsRH"
    "8PEqZr3JqSPL5FdHp54d7YdGkgMZAR-TkB68NhjvcEmIaNG4Dr2ncL78Brj21nwtTIo3HbeNmhKzUbEp0uwH_-XkV2kxkKQXc2Ty"
    "sjble9-G50jiFYfciBfmh6rGkct3o-XcVwdC3YV1A";

const std::string REFUSAL = "attaches the sources of group \"etl\" only";

//! the error of a statement, or "" when it ran
std::string ErrorOf(Connection &con, const std::string &sql) {
	auto result = con.Query(sql);
	return result->HasError() ? result->GetError() : std::string();
}

} // namespace

int main(int argc, char *argv[]) {
	return RunMain("spec 176: a node with part of the sources writes no policy", [] {
		DBConfig config;
		DuckDB db(nullptr, &config);
		Connection con(db);
		Exec(con, "LOAD acl");
		Exec(con, "ATTACH ':memory:' AS store");
		Exec(con, "SELECT acl_use_db('store','acl',true)");
		Exec(con, "SET GLOBAL acl_allow_anonymous_admin=true");
		Exec(con, "SET GLOBAL acl_jwks_locations = 'test/idp/'");
		Exec(con, "SELECT acl_define_issuer('test/idp/s', '{\"url\": \"test/idp/s\", \"client\": {\"audiences\": "
		          "[\"api://acl-test\"], \"roles_from\": [\"roles\"], \"attributes\": {\"tid\": \"tenant\"}}}')");
		Exec(con, "ACL ADMIN CREATE ROLE analyst");
		Exec(con, "ACL ADMIN CREATE ROLE ops");
		Exec(con, "ACL ADMIN MAP CLAIM 'analyst' FROM CLIENT 'test/idp/s' TO ROLE ops");
		Exec(con, "SELECT acl_grant_admin('ops', 'policy')");
		Exec(con, "SELECT acl_grant_admin('ops', 'operate')");
		Exec(con, "ACL ADMIN CREATE VIRTUAL CATALOG c");
		auto store = acl::PolicyStore::Of(*db.instance);
		if (!Check(store != nullptr, "the instance has a policy store")) {
			return;
		}
		const std::string principal = std::string("ACL TOKEN '") + TOKEN + "' ";

		Scenario("a node with every source: the writes run", [&] {
			Check(ErrorOf(con, "ACL ADMIN CREATE ROLE before_partial").empty(), "a write by the gateway");
			Check(ErrorOf(con, principal + "CREATE ROLE by_principal").empty(), "a write by a principal");
		});

		store->node_traits.partial_sources = [] {
			return std::string("etl");
		};

		Scenario("a node with part of the sources: every write refused, naming where to run it", [&] {
			auto gateway = ErrorOf(con, "ACL ADMIN CREATE ROLE refused_gateway");
			Check(gateway.find(REFUSAL) != std::string::npos, "the gateway's write: " + gateway);
			auto own = ErrorOf(con, principal + "CREATE ROLE refused_principal");
			Check(own.find(REFUSAL) != std::string::npos, "a principal's write: " + own);
			auto grant = ErrorOf(con, principal + "GRANT CATALOG c TO ROLE analyst WITH (select) MAIN");
			Check(grant.find(REFUSAL) != std::string::npos, "a grant: " + grant);
			auto check = ErrorOf(con, principal + "SELECT * FROM platform.check_catalog()");
			Check(check.find(REFUSAL) != std::string::npos, "the catalog's check against the sources: " + check);
			auto written = con.Query("SELECT count(*) FROM store.acl.roles WHERE \"role\" LIKE 'refused%'");
			Check(!written->HasError() && written->Collection().GetValue(0, 0).GetValue<int64_t>() == 0,
			      "nothing written");
		});

		Scenario("...its operation and the reads run", [&] {
			Check(ErrorOf(con, principal + "RESUME NODE").empty(),
			      "the node's operation (OPERATE): " + ErrorOf(con, principal + "RESUME NODE"));
			auto info = ErrorOf(con, principal + "SELECT * FROM platform.console_info()");
			Check(info.empty(), "console_info (OPEN): " + info);
			auto roles = ErrorOf(con, principal + "SELECT * FROM platform.roles");
			Check(roles.empty(), "a read of the policy: " + roles);
		});

		store->node_traits.partial_sources = nullptr;
		Scenario("every source again: writes run", [&] {
			Check(ErrorOf(con, "ACL ADMIN CREATE ROLE after_partial").empty(), "a write once the set is gone");
		});
	});
}
