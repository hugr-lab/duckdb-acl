// spec 179: every management statement and every top-level platform call answers `(ok BOOLEAN, message VARCHAR)` -
// the call run once, its false / count / text in the pair, a STRUCT answer's other fields after it, and the platform
// part's note (PolicyStore::NodeTraits::management_note, set by hand here) added after a call that succeeded.
// Build + run via `GEN=ninja make test-cpp`.

#include "acl_test_util.hpp"

#include "acl_mgmt_answer.hpp"
#include "acl_policy.hpp"

using namespace duckdb;
using namespace acl_test;

namespace {

std::string Columns(QueryResult &result) {
	std::string names;
	for (idx_t c = 0; c < result.ColumnCount(); c++) {
		names += (c ? "," : "") + result.ColumnName(c).GetIdentifierName();
	}
	return names;
}

std::string Cell(QueryResult &result, idx_t column) {
	auto value = result.Collection().GetValue(column, 0);
	return value.IsNull() ? "NULL" : value.ToString();
}

std::string Answer(Connection &con, const std::string &sql) {
	auto result = con.Query(sql);
	if (result->HasError()) {
		return "error: " + result->GetError();
	}
	if (Columns(*result) != "ok,message" || result->RowCount() != 1) {
		return "columns " + Columns(*result);
	}
	return Cell(*result, 0) + "|" + Cell(*result, 1);
}

} // namespace

int main(int argc, char *argv[]) {
	return RunMain("spec 179: what a management statement answers", [] {
		DBConfig config;
		DuckDB db(nullptr, &config);
		Connection con(db);
		Exec(con, "LOAD acl");
		Exec(con, "ATTACH ':memory:' AS store");
		Exec(con, "SELECT acl_use_db('store','acl',true)");
		Exec(con, "SET GLOBAL acl_allow_anonymous_admin=true");
		auto store = acl::PolicyStore::Of(*db.instance);
		if (!Check(store != nullptr, "the instance has a policy store")) {
			return;
		}

		Scenario("the grammar answers (ok, message), the call run once", [&] {
			// run twice, the second CREATE would be refused as the role's that exists
			auto made = Answer(con, "ACL ADMIN CREATE ROLE analyst");
			Check(made == "true|NULL", "a plain write: " + made);
			auto batch = con.Query("ACL ADMIN CREATE ROLE a2; CREATE ROLE a3");
			Check(!batch->HasError() && Columns(*batch) == "ok,message", "each of a batch answers the pair");
			Exec(con, "ACL ADMIN CREATE VIRTUAL CATALOG c");
		});

		Scenario("a false, a count, in the pair's own words", [&] {
			auto drained = Answer(con, "ACL ADMIN DRAIN NODE");
			Check(drained == "true|0 sessions still open", "DRAIN answers what remains: " + drained);
			auto resumed = Answer(con, "ACL ADMIN RESUME NODE");
			Check(resumed == "true|NULL", "RESUME of a draining node: " + resumed);
			auto again = Answer(con, "ACL ADMIN RESUME NODE");
			Check(again == "false|the node was not draining", "RESUME of a serving node: " + again);
			auto killed = Answer(con, "ACL ADMIN KILL SESSION 'nope'");
			Check(killed == "false|no session has that id", "KILL of no session: " + killed);
		});

		Scenario("a direct acl_* call and a table call answer as before", [&] {
			auto direct = con.Query("SELECT acl_define_role('direct', '')");
			Check(!direct->HasError() && direct->ColumnCount() == 1 && Cell(*direct, 0) == "true",
			      "the direct call: " + (direct->HasError() ? direct->GetError() : Columns(*direct)));
			auto check = con.Query("ACL ADMIN CHECK VIRTUAL CATALOG c");
			Check(!check->HasError() && Columns(*check) != "ok,message",
			      "CHECK answers its findings: " + (check->HasError() ? check->GetError() : Columns(*check)));
		});

		Scenario("the platform part's note, after a call that succeeded", [&] {
			std::vector<std::string> seen;
			store->node_traits.management_note = [&](ClientContext &, const std::string &function,
			                                         const vector<Value> &args) -> std::string {
				std::string call = function;
				for (auto &arg : args) {
					call += "|" + (arg.IsNull() ? std::string("NULL") : arg.ToString());
				}
				seen.push_back(call);
				return function == "acl_grant_catalog" ? "group etl does not list a source of c" : std::string();
			};
			auto granted = Answer(con, "ACL ADMIN GRANT CATALOG c TO ROLE analyst WITH (select) MAIN");
			Check(granted == "true|group etl does not list a source of c", "the grant's note: " + granted);
			Check(!seen.empty() && seen.back().rfind("acl_grant_catalog|analyst|c|", 0) == 0,
			      "the note reads the call's arguments: " + (seen.empty() ? std::string() : seen.back()));
			// named arguments reach the note in the function's order
			Exec(con, "ACL ADMIN CREATE ROLE pol_n");
			Exec(con, "SELECT acl_grant_admin('pol_n', 'policy')");
			auto named = Answer(con, "ACL ROLE \"pol_n\" SELECT platform.grant_catalog(catalog := 'c', "
			                         "role := 'analyst', caps := ['select'], main := true)");
			Check(named == "true|group etl does not list a source of c" &&
			          seen.back().rfind("acl_grant_catalog|analyst|c|", 0) == 0,
			      "named arguments in the call's order: " + named + " / " + seen.back());
			auto count = seen.size();
			auto again = Answer(con, "ACL ADMIN RESUME NODE");
			Check(again == "false|the node was not draining" && seen.size() == count,
			      "no note after a call that did not happen: " + again);
			auto drained = Answer(con, "ACL ADMIN DRAIN NODE");
			Check(drained == "true|0 sessions still open", "an empty note adds nothing: " + drained);
			Exec(con, "ACL ADMIN RESUME NODE");
			// a note that throws is dropped: the grant has committed and answers ok
			store->node_traits.management_note = [](ClientContext &, const std::string &,
			                                        const vector<Value> &) -> std::string {
				throw IOException("the platform part's catalog is down");
			};
			auto thrown = Answer(con, "ACL ADMIN GRANT CATALOG c TO ROLE thrower WITH (select)");
			Check(thrown == "true|NULL", "a throwing note: " + thrown);
			auto stored = con.Query("SELECT count(*) FROM store.acl.role_catalogs WHERE role = 'thrower'");
			Check(!stored->HasError() && Cell(*stored, 0) == "1", "the grant stands");
			store->node_traits.management_note = nullptr;
		});

		Scenario("a prepared call answers the pair at each execution, once", [&] {
			Exec(con, "ACL ADMIN CREATE ROLE pol");
			Exec(con, "SELECT acl_grant_admin('pol', 'policy')");
			auto prepared = con.Prepare("ACL ROLE \"pol\" SELECT platform.alter_catalog(catalog := 'c', comment := ?)");
			if (!Check(!prepared->HasError(), "prepared: " + (prepared->HasError() ? prepared->GetError() : ""))) {
				return;
			}
			auto version = [&]() {
				auto v = con.Query("SELECT CAST(value AS BIGINT) FROM store.acl.meta WHERE key = 'policy_version'");
				return v->HasError() ? int64_t(-1) : v->Collection().GetValue(0, 0).GetValue<int64_t>();
			};
			for (auto comment : {"first", "second"}) {
				auto before = version();
				auto result = prepared->Execute(comment);
				Check(version() == before + 1, std::string("execution ") + comment + " writes once");
				Check(!result->HasError() && Columns(*result) == "ok,message" && Cell(*result, 0) == "true",
				      std::string("execution ") + comment + ": " +
				          (result->HasError() ? result->GetError() : Columns(*result)));
				auto stored = con.Query("SELECT comment FROM store.acl.catalogs WHERE vcat = 'c'");
				Check(!stored->HasError() && Cell(*stored, 0) == comment, std::string("wrote ") + comment);
			}
		});

		Scenario("a STRUCT answer keeps its fields after the pair", [&] {
			child_list_t<LogicalType> types {
			    {"version", LogicalType::BIGINT}, {"class", LogicalType::VARCHAR}, {"message", LogicalType::VARCHAR}};
			auto type = LogicalType::STRUCT(types);
			auto value = Value::STRUCT(type, {Value::BIGINT(7), Value("hot"), Value("applied here")});
			auto answer = acl::ManagementAnswer("acl_cluster_setting", value, type, "a note");
			auto &fields = StructValue::GetChildren(answer);
			auto &names = StructType::GetChildTypes(answer.type());
			Check(names.size() == 4 && names[0].first.GetIdentifierName() == "ok" &&
			          names[1].first.GetIdentifierName() == "message" &&
			          names[2].first.GetIdentifierName() == "version" && names[3].first.GetIdentifierName() == "class",
			      "ok, message, then its own fields: " + answer.ToString());
			Check(fields[0] == Value::BOOLEAN(true) && fields[1].ToString() == "applied here; a note" &&
			          fields[2] == Value::BIGINT(7),
			      "its message first, then the note: " + answer.ToString());
			auto through = [&](const std::string &value) {
				auto r = con.Query("SELECT a.* FROM (SELECT acl_answer('acl_x', " + value + ") AS a)");
				if (r->HasError()) {
					return "error: " + r->GetError();
				}
				std::string out = Columns(*r);
				for (idx_t c = 0; c < r->ColumnCount(); c++) {
					out += "|" + Cell(*r, c);
				}
				return out;
			};
			auto null_ok = through("{'ok': NULL::BOOLEAN, 'v': 1}");
			Check(null_ok == "ok,message,v|false|NULL|1", "a STRUCT's NULL ok is not ok: " + null_ok);
			auto bad_ok = through("{'ok': 'maybe', 'v': 1}");
			Check(bad_ok == "ok,message,v|false|NULL|1", "an ok that is no BOOLEAN is not ok, no throw: " + bad_ok);
			auto huge = through("18446744073709551615::UBIGINT");
			Check(huge == "ok,message|true|18446744073709551615", "a count past BIGINT is its text: " + huge);
			auto none = acl::ManagementAnswer("acl_x", Value(type), type, "");
			Check(StructValue::GetChildren(none)[0] == Value::BOOLEAN(false), "no answer is not ok");
			auto text = acl::ManagementAnswer("acl_migrate_catalog", Value("migrated to 28"), LogicalType::VARCHAR, "");
			Check(StructValue::GetChildren(text)[1].ToString() == "migrated to 28", "a text is the message");
		});
	});
}
