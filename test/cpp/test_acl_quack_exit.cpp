// A door nobody stopped does not crash the process at exit (spec 084). The process serves, attaches a
// quack client to its own door and leaves without acl_quack_stop - the shape that aborted with
// "mutex lock failed: Invalid argument" when the static registry of doors tore the instance down among
// the static destructors. The scenario runs in a child process (this binary, `--child`), because what
// is judged is how that process ends.
// Build + run via `GEN=ninja make test-cpp`.

#include "acl_test_util.hpp"

#include <cstdlib>
#include <fstream>
#include <sys/wait.h>

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

const char *const QUACK_EXT = "build/release/extension/quack/quack.duckdb_extension";
const char *const HTTPFS_EXT = "build/release/extension/httpfs/httpfs.duckdb_extension";

bool FileExists(const std::string &path) {
	std::ifstream file(path);
	return file.good();
}

//! Serve, attach a client to the door, answer through it, and leave - no acl_quack_stop
int Child(const std::string &extension) {
	DBConfig config;
	config.SetOptionByName("allow_unsigned_extensions", Value::BOOLEAN(true));
	DuckDB db(nullptr, &config);
	Connection con(db);
	for (auto &sql : std::vector<std::string> {
	         "LOAD '" + extension + "'", std::string("LOAD '") + HTTPFS_EXT + "'",
	         std::string("LOAD '") + QUACK_EXT + "'", "ATTACH ':memory:' AS store",
	         "SELECT acl_use_db('store','acl',true)", "SET GLOBAL acl_allow_anonymous_admin=true",
	         "SET GLOBAL acl_jwks_locations = 'test/idp/'",
	         "SELECT acl_define_issuer('test/idp/s', '{\"url\": \"test/idp/s\", \"client\": {\"audiences\": "
	         "[\"api://acl-test\"], \"roles_from\": [\"roles\"], \"attributes\": {\"tid\": \"tenant\"}}}')",
	         "ACL ADMIN CREATE VIRTUAL CATALOG c", "ACL ADMIN CREATE VIRTUAL VIEW c.light AS SELECT 42 AS answer",
	         "ACL ADMIN CREATE ROLE analyst", "ACL ADMIN GRANT CATALOG c TO ROLE analyst WITH (select) MAIN",
	         "SET GLOBAL acl_allow_anonymous_admin=false",
	         "SELECT acl_quack_serve('quack:localhost:31612', 'exit-server-token')",
	         std::string("ATTACH 'quack:localhost:31612' AS remote (TYPE quack, TOKEN '") + TOKEN + "')"}) {
		auto result = con.Query(sql);
		if (result->HasError()) {
			std::cerr << "child: " << sql << ": " << result->GetError() << "\n";
			return 2;
		}
	}
	auto answer = con.Query("SELECT * FROM remote.light");
	if (answer->HasError() || answer->RowCount() != 1 ||
	    answer->Collection().GetValue(0, 0).GetValue<int32_t>() != 42) {
		std::cerr << "child: the door did not answer: " << (answer->HasError() ? answer->GetError() : "") << "\n";
		return 3;
	}
	return 0; // the DuckDB goes out of scope here; the door keeps its instance until the process ends
}

} // namespace

int main(int argc, char *argv[]) {
	if (argc > 1 && std::string(argv[1]) == "--child") {
		return Child(argc > 2 ? argv[2] : "build/release/extension/acl/acl.duckdb_extension");
	}
	std::string extension = argc > 1 ? argv[1] : "build/release/extension/acl/acl.duckdb_extension";
	return RunMain("a door nobody stopped, at exit (spec 084)", [&] {
		if (!FileExists(QUACK_EXT) || !FileExists(HTTPFS_EXT)) {
			std::cout << "  note: no quack build, skipped\n";
			return;
		}
		Scenario("serve, attach a client to the door, exit without acl_quack_stop: a clean exit", [&] {
			for (int run = 0; run < 3; run++) {
				auto status = std::system((std::string(argv[0]) + " --child '" + extension + "'").c_str());
				bool clean = status != -1 && WIFEXITED(status) && WEXITSTATUS(status) == 0;
				Check(clean, "run " + std::to_string(run + 1) + ": the process exited cleanly (status " +
				                 std::to_string(status) + ")");
			}
		});
	});
}
