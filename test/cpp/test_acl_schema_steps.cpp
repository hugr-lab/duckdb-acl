// spec 117 review: a migration step re-creating a table re-creates its key - and a key column must take
// the type the catalog's kind can index (spec 033: SQL Server's NVARCHAR(MAX) carries no index, error
// 1750). The steps are embedded by scripts/gen_schema.py; this checks every CREATE TABLE with a primary key,
// in the steps and in the schema, declares its key columns ACL_KEY_TEXT - what the runner and the init
// replace with KeyColumnType(). Without the generator's rewrite, step 21's `admins` keyed VARCHAR fails here.
// Build + run via `GEN=ninja make test-cpp`.

#include "acl_test_util.hpp"
#include "../../src/acl_schema_sql.hpp"

#include <regex>

using namespace acl_test;

namespace {

//! The text key columns of a CREATE TABLE declared plain VARCHAR (not ACL_KEY_TEXT); empty when none
std::vector<std::string> UnboundedKeys(const std::string &sql) {
	std::vector<std::string> out;
	std::smatch match;
	static const std::regex create(R"x(^CREATE TABLE .*PRIMARY KEY \(([^)]*)\)\)$)x");
	if (!std::regex_match(sql, match, create)) {
		return out;
	}
	std::string keys = match[1];
	std::regex key(R"x("([a-z_]+)")x");
	for (auto it = std::sregex_iterator(keys.begin(), keys.end(), key); it != std::sregex_iterator(); ++it) {
		auto column = (*it)[1].str();
		// a text key must be ACL_KEY_TEXT; an INTEGER key (a position) is indexable as it is
		if (sql.find("\"" + column + "\" VARCHAR") != std::string::npos) {
			out.push_back(column);
		}
	}
	return out;
}

void Run() {
	int checked = 0;
	for (auto sql : duckdb::acl::ACL_SCHEMA_SQL) {
		auto bad = UnboundedKeys(sql);
		checked += sql[0] == 'C';
		Check(bad.empty(), std::string("schema: key columns are ACL_KEY_TEXT: ") + std::string(sql).substr(0, 60));
	}
	for (auto &step : duckdb::acl::ACL_SCHEMA_STEPS) {
		for (int i = 0; i < step.count; i++) {
			auto bad = UnboundedKeys(step.statements[i]);
			if (!bad.empty()) {
				Check(false, "step v" + std::to_string(step.version) + ": key column " + bad[0] +
				                 " is not ACL_KEY_TEXT: " + std::string(step.statements[i]).substr(0, 80));
			}
		}
	}
	Check(checked > 0, "the schema's statements were read");
	bool admins = false;
	for (auto &step : duckdb::acl::ACL_SCHEMA_STEPS) {
		for (int i = 0; i < step.count; i++) {
			std::string sql = step.statements[i];
			admins = admins || (step.version == 21 && sql.rfind("CREATE TABLE <admins>(", 0) == 0 &&
			                    sql.find("\"role\" ACL_KEY_TEXT") != std::string::npos);
		}
	}
	Check(admins, "step v21 re-keys admins with key columns of the catalog's key type");
}

} // namespace

int main() {
	return RunMain("acl schema steps (spec 117 review: key columns indexable on every catalog kind)", Run);
}
