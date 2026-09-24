// Secrets through the ACL (spec 082) against a secrets service: a catalog of type `tresor`, the shape
// tresor attaches (an in-memory DuckCatalog with the service's table functions, and a persistent
// secret storage of the catalog's name). The fake records what it is asked; the service's own
// refusal of a non-administrator is tresor's and tested there. Here: the catalog choice, what
// GRANT / REVOKE SECRET compile to, CREATE / DROP SECRET landing in the service and never in the
// node's own secret manager, the function gate over a direct call, and no secret value on any event.
// The secrets are of duckdb's own `http` type: no extension to load, so the distribution build (no
// httpfs linked) runs this as it is.
// Build + run via `GEN=ninja make test-cpp`.

#include "acl_test_util.hpp"

#include "acl_connection.hpp"

#include "duckdb/catalog/catalog_transaction.hpp"
#include "duckdb/catalog/duck_catalog.hpp"
#include "duckdb/main/attached_database.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include "duckdb/main/secret/secret_storage.hpp"
#include "duckdb/parser/parsed_data/attach_info.hpp"
#include "duckdb/parser/parsed_data/create_table_function_info.hpp"
#include "duckdb/storage/storage_extension.hpp"
#include "duckdb/transaction/duck_transaction_manager.hpp"

#include <atomic>
#include <cstdlib>
#include <unistd.h>
#include <mutex>
#include <vector>

using namespace duckdb;
using namespace acl_test;

namespace {

std::mutex calls_lock;
std::vector<std::string> calls; // what the fake service was asked, in order

void Record(const std::string &call) {
	std::lock_guard<std::mutex> guard(calls_lock);
	calls.push_back(call);
}

std::vector<std::string> TakeCalls() {
	std::lock_guard<std::mutex> guard(calls_lock);
	auto out = calls;
	calls.clear();
	return out;
}

//! The service's secrets: persistent, named after the catalog (tresor's TresorSecretStorage)
class FakeServiceStorage : public CatalogSetSecretStorage {
public:
	FakeServiceStorage(DatabaseInstance &db, const string &name, int64_t offset)
	    : CatalogSetSecretStorage(db, name, offset) {
		secrets = make_uniq<CatalogSet>(Catalog::GetSystemCatalog(db));
		persistent = true;
	}
};

struct CallData : public TableFunctionData {
	vector<string> inputs;
};

unique_ptr<FunctionData> ServiceBind(ClientContext &context, TableFunctionBindInput &input,
                                     vector<LogicalType> &return_types, vector<Identifier> &names) {
	std::string call = input.table_function.name.GetIdentifierName() + "(";
	for (idx_t i = 0; i < input.inputs.size(); i++) {
		call += (i ? ", " : "") + input.inputs[i].ToString();
	}
	call += ")";
	// whom the call goes as: the session published on the connection (tresor's actor reads the same)
	string why;
	auto connection = acl::AclConnection::Reach(context, why);
	acl::AclSessionView view;
	if (connection && connection->Current(view)) {
		call += " as session " + view.session_id;
	}
	Record(call);
	if (!input.inputs.empty() && input.inputs[0].ToString() == "missing") {
		throw InvalidInputException("service: no secret missing");
	}
	return_types.push_back(LogicalType::BOOLEAN);
	names.emplace_back("ok");
	auto data = make_uniq<CallData>();
	for (auto &value : input.inputs) {
		data->inputs.push_back(value.ToString());
	}
	return std::move(data);
}

struct CallState : public GlobalTableFunctionState {
	bool done = false;
};

unique_ptr<GlobalTableFunctionState> ServiceInit(ClientContext &context, TableFunctionInitInput &input) {
	return make_uniq<CallState>();
}

void ServiceScan(ClientContext &context, TableFunctionInput &input, DataChunk &output) {
	auto &state = input.global_state->Cast<CallState>();
	if (state.done) {
		return;
	}
	state.done = true;
	// the service's refusal may come while the call runs, not only when it binds (tresor's does)
	auto &inputs = input.bind_data->Cast<CallData>().inputs;
	if (!inputs.empty() && inputs[0] == "refused_late") {
		throw InvalidInputException("service: no secret refused_late");
	}
	output.data[0].Append(Value::BOOLEAN(true));
}

class FakeServiceCatalog : public DuckCatalog {
public:
	explicit FakeServiceCatalog(AttachedDatabase &db) : DuckCatalog(db) {
	}
	string GetCatalogType() override {
		return "tresor";
	}
	void Initialize(bool load_builtin) override {
		DuckCatalog::Initialize(false);
		auto transaction = CatalogTransaction::GetSystemTransaction(GetDatabase());
		auto text = LogicalType::VARCHAR;
		vector<std::pair<const char *, vector<LogicalType>>> signatures {
		    {"grant_secret", {text, text, LogicalType::LIST(text)}}, {"revoke_secret", {text, text}}, {"whoami", {}}};
		vector<TableFunction> functions;
		for (auto &signature : signatures) {
			functions.emplace_back(Identifier(signature.first), signature.second, ServiceScan, ServiceBind,
			                       ServiceInit);
		}
		for (auto &function : functions) {
			CreateTableFunctionInfo info(std::move(function));
			info.internal = false;
			CreateTableFunction(transaction, info);
		}
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
	return result->RowCount() ? result->GetValue(0, 0).ToString() : "";
}

bool Refused(Connection &con, const std::string &sql, const std::string &why) {
	auto result = con.Query(sql);
	return Check(result->HasError() && result->GetError().find(why) != std::string::npos,
	             "refused (" + why + "): " + (result->HasError() ? result->GetError() : "it ran"));
}

} // namespace

int main(int argc, char *argv[]) {
	return RunMain("secrets through the ACL (spec 082)", [&] {
		DBConfig config;
		// the node's own persistent secrets (local_file) in a directory of this test's: never the
		// person's ~/.duckdb/stored_secrets, which the checks below would otherwise count
		char directory[] = "/tmp/acl-secrets-XXXXXX";
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
		Exec(con, "CREATE TABLE phys.main.orders(id INT)");
		Exec(con, "ATTACH ':memory:' AS store");
		Exec(con, "SELECT acl_use_db('store','acl',true)");
		Exec(con, "SET GLOBAL acl_allow_anonymous_admin=true");
		Exec(con, "ACL ADMIN CREATE VIRTUAL CATALOG c");
		Exec(con, "ACL ADMIN CREATE VIRTUAL TABLE c.orders AS phys.main.orders");
		Exec(con, "ACL ADMIN CREATE ROLE keeper");
		Exec(con, "ACL ADMIN CREATE ROLE plain");
		Exec(con, "ACL ADMIN CREATE ROLE analyst");
		Exec(con, "SELECT acl_define_issuer('https://issuer.test/s',"
		          "'{\"keys\":[{\"kty\":\"oct\",\"k\":\"YWNsLXRlc3QtaHMyNTYtc2VjcmV0\"}]}',"
		          "'api://acl-test','HS256','roles','{\"tid\": \"tenant\"}')");
		Exec(con, "ACL ADMIN GRANT CATALOG c TO ROLE analyst WITH (select, secrets) MAIN");
		Exec(con, "ACL ADMIN GRANT CATALOG c TO ROLE keeper WITH (select, secrets) MAIN");
		Exec(con, "ACL ADMIN GRANT CATALOG c TO ROLE plain WITH (select) MAIN");
		Exec(con, "SET GLOBAL acl_audit_level='all'");
		Exec(con, "SET GLOBAL acl_profile_level='all'");

		Exec(con, "ATTACH '' AS corp (TYPE tresor)");
		TakeCalls();

		Scenario("GRANT / REVOKE SECRET compile to the service's own calls, in the one service attached", [&] {
			auto granted = One(con, "ACL ROLE \"keeper\" ACL GRANT SECRET lake TO ROLE analysts");
			auto revoked = One(con, "ACL ROLE \"keeper\" ACL REVOKE SECRET 'lake' FROM GROUP \"Data Team\"");
			auto seen = TakeCalls();
			Check(granted == "true" && revoked == "true", "both ran: " + granted + " / " + revoked);
			Check(seen.size() == 2 && seen[0] == "grant_secret(lake, role:analysts, [use])" &&
			          seen[1] == "revoke_secret(lake, group:Data Team)",
			      "the service heard: " + (seen.empty() ? std::string("nothing") : seen[0]) +
			          (seen.size() > 1 ? " | " + seen[1] : ""));
			Check(One(con, "ACL ROLE \"keeper\" ACL GRANT SECRET lake TO ROLE a; GRANT SECRET lake TO ROLE b") ==
			              "true" &&
			          TakeCalls().size() == 2,
			      "a batch of them runs each");
			Refused(con, "ACL ROLE \"plain\" ACL GRANT SECRET lake TO ROLE analysts", "needs the secrets capability");
			Check(TakeCalls().empty(), "a refused grant reaches nothing");
		});

		Scenario("CREATE / DROP SECRET land in the service, never in the node's own secret manager", [&] {
			Exec(con, "ACL ROLE \"keeper\" CREATE SECRET lake_key (TYPE http, "
			          "HTTP_PROXY_USERNAME 'AKIA-ID-082', BEARER_TOKEN 'value-that-must-not-leak-082', "
			          "SCOPE ['s3://lake/a', 's3://lake/b'], VERIFY_SSL true)");
			Check(One(con, "SELECT storage FROM duckdb_secrets() WHERE name = 'lake_key'") == "corp",
			      "kept by the service's storage");
			Check(One(con, "SELECT count(*) FROM duckdb_secrets() WHERE storage <> 'corp'") == "0",
			      "and nothing in the node's own: " +
			          One(con, "SELECT string_agg(name || '@' || storage, ',') FROM duckdb_secrets()"));
			Exec(con,
			     "ACL ROLE \"keeper\" CREATE PERSISTENT SECRET IN corp (TYPE http, PROVIDER config, BEARER_TOKEN 'x')");
			Check(One(con, "SELECT storage FROM duckdb_secrets() WHERE name = '__default_http'") == "corp",
			      "PERSISTENT ... IN the service, named: the same place");
			Exec(con, "ACL ROLE \"keeper\" DROP SECRET lake_key");
			Exec(con, "ACL ROLE \"keeper\" DROP PERSISTENT SECRET __default_http FROM corp");
			Check(One(con, "SELECT count(*) FROM duckdb_secrets()") == "0", "both dropped from the service");
			Refused(con, "ACL ROLE \"plain\" CREATE SECRET s (TYPE http, BEARER_TOKEN 'k')",
			        "needs the secrets capability");
			Refused(con, "ACL ROLE \"keeper\" CREATE TEMPORARY SECRET s (TYPE http, BEARER_TOKEN 'k')",
			        "a temporary secret is kept by this node");
			Refused(con, "ACL ROLE \"keeper\" CREATE SECRET s IN memory (TYPE http, BEARER_TOKEN 'k')",
			        "\"memory\" is not a secrets service");
		});

		Scenario("no secret value reaches an event: statement, profile, or any other", [&] {
			Exec(con, "SELECT acl_audit_flush()");
			auto events = One(con, "SELECT string_agg(e::VARCHAR, ' ') FROM acl_audit_events() e");
			Check(events.find("secrets") != std::string::npos, "the decisions are there (capability secrets)");
			Check(One(con, "SELECT count(*) FROM acl_audit_events() WHERE kind = 'profile'") != "0",
			      "and the executions were profiled");
			Check(events.find("value-that-must-not-leak-082") == std::string::npos &&
			          events.find("AKIA-ID-082") == std::string::npos && events.find("s3://lake") == std::string::npos,
			      "no value, key id or scope on any event");
		});

		Scenario("two services attached: a statement names one, or is told to", [&] {
			Exec(con, "ATTACH '' AS vault (TYPE tresor)");
			Refused(con, "ACL ROLE \"keeper\" ACL GRANT SECRET lake TO ROLE analysts",
			        "several secrets services are attached to this node (corp, vault)");
			Refused(con, "ACL ROLE \"keeper\" CREATE SECRET s (TYPE http, BEARER_TOKEN 'k')",
			        "several secrets services");
			Check(One(con, "ACL ROLE \"keeper\" ACL GRANT SECRET lake TO ROLE analysts FROM vault") == "true",
			      "FROM names it");
			auto seen = TakeCalls();
			Check(!seen.empty() && seen.back() == "grant_secret(lake, role:analysts, [use])", "in vault");
			Exec(con, "ACL ROLE \"keeper\" CREATE SECRET s IN vault (TYPE http, BEARER_TOKEN 'k')");
			Check(One(con, "SELECT storage FROM duckdb_secrets() WHERE name = 's'") == "vault", "IN names it");
			Exec(con, "ACL ROLE \"keeper\" DROP SECRET s FROM vault");
			Exec(con, "DETACH vault");
		});

		Scenario("under a session, the service's call goes as the session - and its refusal reaches the client", [&] {
			const std::string token =
			    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci50ZXN0L3MiLCJhdWQiOiJhcGk6Ly9hY2w"
			    "tdGVzdCIsImV4cCI6NDEwMjQ0NDgwMCwic3ViIjoidSIsInJvbGVzIjpbImFuYWx5c3QiXSwidGlkIjoiYWNtZSJ9.c_RJ0X6_Gj"
			    "5O5Z273KOaB9e11XFXVgQkEbtTCayEzJc";
			auto handle = One(con, "SELECT acl_session_open('" + token + "')");
			auto under = [&](const std::string &sql) {
				return One(con,
				           "SELECT acl_session_sql('" + handle + "', '" + StringUtil::Replace(sql, "'", "''") + "')");
			};
			Check(One(con, under("ACL GRANT SECRET lake TO ROLE analysts")) == "true", "the grant ran");
			Check(One(con, under("ACL REVOKE SECRET lake FROM GROUP g")) == "true", "the revoke ran");
			auto seen = TakeCalls();
			const std::string grant = "grant_secret(lake, role:analysts, [use]) as session ";
			const std::string revoke = "revoke_secret(lake, group:g) as session ";
			bool as_session = seen.size() == 2 && seen[0].rfind(grant, 0) == 0 && seen[0].size() > grant.size() &&
			                  seen[1].rfind(revoke, 0) == 0 &&
			                  seen[0].substr(grant.size()) == seen[1].substr(revoke.size());
			Check(as_session,
			      "both reached the service as the one session: " + (seen.empty() ? std::string("nothing") : seen[0]) +
			          (seen.size() > 1 ? " | " + seen[1] : ""));
			Check(One(con, "ACL ROLE \"keeper\" ACL GRANT SECRET lake TO ROLE analysts") == "true" &&
			          TakeCalls() == std::vector<std::string> {"grant_secret(lake, role:analysts, [use])"},
			      "and a gateway's per-statement prefix names no session");
			// a passthrough administrator's native batch: every statement of it runs as the session
			Exec(con, "ACL ADMIN GRANT ADMIN passthrough TO ROLE analyst");
			Exec(con, under("ACL NATIVE SELECT * FROM corp.main.grant_secret('a', 'role:r', ['use']); "
			                "SELECT * FROM corp.main.grant_secret('b', 'role:r', ['use'])"));
			seen = TakeCalls();
			Check(seen.size() == 2 && seen[0].find(" as session ") != std::string::npos &&
			          seen[1].find(" as session ") != std::string::npos,
			      "both statements of a native batch went as the session: " +
			          (seen.size() > 1 ? seen[0] + " | " + seen[1] : std::string("fewer calls")));
			Exec(con, "ACL ADMIN REVOKE ADMIN FROM ROLE analyst");
			auto refused = One(con, under("ACL GRANT SECRET missing TO ROLE analysts"));
			Check(refused.find("service: no secret missing") != std::string::npos,
			      "the service's refusal reaches the client as it is: " + refused);
			auto late = One(con, under("ACL GRANT SECRET refused_late TO ROLE analysts"));
			Check(late.find("service: no secret refused_late") != std::string::npos,
			      "and so does one raised while the call runs: " + late);
			TakeCalls();
			Exec(con, "SELECT acl_session_close('" + handle + "')");
		});

		Scenario("a direct call into the service catalog is the function gate's: a category, or nothing", [&] {
			Refused(con, "ACL ROLE \"keeper\" SELECT * FROM corp.whoami()", "is not allowed");
			Refused(con, "ACL ROLE \"keeper\" SELECT * FROM corp.main.grant_secret('x', 'role:r', ['use'])",
			        "is not allowed");
			Check(TakeCalls().empty(), "the service heard nothing");
			Exec(con, "ACL ADMIN CREATE FUNCTION CATEGORY secrets_service COMMENT 'the node''s secrets service'");
			Exec(con, "ACL ADMIN ALTER FUNCTION CATEGORY secrets_service ADD (corp.main.whoami TABLE)");
			Exec(con, "ACL ADMIN GRANT FUNCTION CATEGORY secrets_service TO ROLE keeper");
			auto who = One(con, "ACL ROLE \"keeper\" SELECT * FROM corp.whoami()");
			Check(who == "true", "admitted through it: " + who);
			Refused(con, "ACL ROLE \"plain\" SELECT * FROM corp.whoami()", "is not allowed");
			Refused(con, "ACL ROLE \"keeper\" SELECT * FROM corp.main.grant_secret('x', 'role:r', ['use'])",
			        "is not allowed");
			// quack's whoami() stays in the never set: the system catalog's is not the service's
			Refused(con, "ACL ROLE \"keeper\" SELECT * FROM system.main.whoami()", "is not allowed");
			Refused(con, "ACL ADMIN ALTER FUNCTION CATEGORY secrets_service ADD (system.main.whoami TABLE)",
			        "never callable");
			auto seen = TakeCalls();
			Check(seen.size() == 1 && seen[0] == "whoami()", "only the granted call reached the service");
			// a bare whoami() is resolved like any bare name (spec 072): to the one member categorized,
			// and emitted qualified to it - the service's, never the system catalog's
			Check(One(con, "ACL ROLE \"keeper\" SELECT * FROM whoami()") == "true" && TakeCalls().size() == 1,
			      "a bare whoami() is the service's");
			Check(One(con, "ACL ROLE \"keeper\" SELECT * FROM corp.main.whoami()") == "true" && TakeCalls().size() == 1,
			      "and so is the fully qualified one");
		});
	});
}
