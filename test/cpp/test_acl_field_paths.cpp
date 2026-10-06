// Fields of structured types (spec 102): acl_field_paths.hpp's parse, tree, levels (intersect), roles
// (unite) and compile - the compiled projection run on a real instance, so what a role reads is
// checked, not the SQL text.
// Build + run via `GEN=ninja make test-cpp`.

#include "acl_test_util.hpp"

#include "acl_field_paths.hpp"
#include "acl_result_rows.hpp"

using namespace acl_test;
using duckdb::acl::acl_detail::ColumnTrees;
using duckdb::acl::acl_detail::CompileNode;
using duckdb::acl::acl_detail::FieldPath;
using duckdb::acl::acl_detail::IntersectColumnItems;
using duckdb::acl::acl_detail::ParseFieldPath;
using duckdb::acl::acl_detail::UniteColumnItems;

using Items = duckdb::vector<std::pair<std::string, std::string>>;

static std::string Joined(const Items &items) {
	std::string out;
	for (auto &item : items) {
		out += (out.empty() ? "" : ", ") + item.first + (item.second.empty() ? "" : " = " + item.second);
	}
	return out;
}

//! What a role reads of column `column` when its grant lists `items`
static std::string Read(duckdb::Connection &con, const Items &items, const std::string &column) {
	auto trees = ColumnTrees::From(items);
	auto root = trees.Find(column);
	if (!root) {
		return "<hidden>";
	}
	auto result = con.Query("SELECT " + CompileNode(*root, "\"" + column + "\"") + "::VARCHAR FROM t ORDER BY id");
	if (result->HasError()) {
		return "ERROR " + result->GetError();
	}
	std::string out;
	duckdb::acl::ResultRows rows(*result);
	for (duckdb::idx_t row = 0; row < rows.Count(); row++) {
		out += (out.empty() ? "" : " | ") + rows.GetValue(0, row).ToString();
	}
	return out;
}

int main(int argc, char *argv[]) {
	return RunMain("fields of structured types per role (spec 102)", [&] {
		duckdb::DuckDB db(nullptr);
		duckdb::Connection con(db);
		con.Query("CREATE TABLE t AS SELECT * FROM (VALUES "
		          "(1, {'city': 'A', 'ssn': 'S1', 'geo': {'lat': 1, 'lon': 2}}, [{'price': 1, 'cost': 9}]), "
		          "(2, NULL, NULL)) v(id, address, items)");

		Scenario("a path parses into a column and its steps, and nothing else does", [&] {
			FieldPath path;
			std::string error;
			Check(ParseFieldPath("address.geo.lat", path, error) && path.head == "address" && path.steps.size() == 2,
			      "address.geo.lat");
			Check(ParseFieldPath("items[].price", path, error) && path.steps.size() == 2 && path.steps[0].empty(),
			      "items[].price: an element step, then a field");
			Check(ParseFieldPath("\"Order\".\"Zip Code\"", path, error) && path.head == "Order" &&
			          path.steps[0] == "Zip Code",
			      "quoted names");
			Check(ParseFieldPath("id", path, error) && path.IsColumn(), "a column is a path without steps");
			for (auto bad : {"address.", "a.b || c", "a[0].b", "a..b", "(a).b", "a.b c"}) {
				Check(!ParseFieldPath(bad, path, error), std::string("refused: ") + bad);
			}
		});

		Scenario("what a role reads, compiled and run", [&] {
			Check(Read(con, {{"address.city", ""}}, "address") == "{'city': A} | NULL",
			      "one field, a NULL struct stays NULL: " + Read(con, {{"address.city", ""}}, "address"));
			Check(Read(con, {{"address.geo.lat", ""}, {"address.city", ""}}, "address") ==
			          "{'geo': {'lat': 1}, 'city': A} | NULL",
			      "nested: " + Read(con, {{"address.geo.lat", ""}, {"address.city", ""}}, "address"));
			Check(Read(con, {{"address", ""}, {"address.ssn", "NULL"}}, "address") ==
			          "{'city': A, 'ssn': NULL, 'geo': {'lat': 1, 'lon': 2}} | NULL",
			      "the whole, one field masked: " + Read(con, {{"address", ""}, {"address.ssn", "NULL"}}, "address"));
			Check(Read(con, {{"items[].price", ""}}, "items") == "[{'price': 1}] | NULL",
			      "a list of structs: " + Read(con, {{"items[].price", ""}}, "items"));
			Check(Read(con, {{"address", ""}, {"address.city", ""}}, "address").find("ssn") != std::string::npos,
			      "the whole beats its part within one grant");
		});

		Scenario("levels intersect: a narrower grant never re-exposes", [&] {
			Check(Joined(IntersectColumnItems({{"address", ""}}, {{"address.city", ""}})) == "address.city",
			      "catalog whole, object narrows");
			Check(Joined(IntersectColumnItems({{"address.city", ""}}, {{"address", ""}})) == "address.city",
			      "catalog narrow, object whole: still narrow");
			Check(Joined(IntersectColumnItems({{"address.city", ""}, {"address.zip", ""}}, {{"address.zip", ""}})) ==
			          "address.zip",
			      "a subset of a subset");
			Check(Joined(IntersectColumnItems({{"address.city", ""}}, {{"address.zip", ""}})).empty(),
			      "disjoint fields: the column is gone");
			Check(Joined(IntersectColumnItems({{"address", ""}}, {{"address", ""}, {"address.ssn", "NULL"}})) ==
			          "address, address.ssn = NULL",
			      "the narrower masks a field of the whole");
			Check(Joined(IntersectColumnItems({{"id", ""}, {"ssn", "NULL"}}, {{"ssn", ""}, {"id", ""}})) ==
			          "id, ssn = NULL",
			      "columns as before: the wider's mask stands, the wider's order");
		});

		Scenario("roles unite: a visible field beats a masked one", [&] {
			Check(Joined(UniteColumnItems({{"address.city", ""}}, {{"address.zip", ""}})) ==
			          "address.city, address.zip",
			      "{city} + {zip}");
			Check(Joined(UniteColumnItems({{"address.city", ""}}, {{"address", ""}})) == "address",
			      "the whole beats a part");
			Check(Joined(UniteColumnItems({{"address", ""}, {"address.ssn", "NULL"}}, {{"address", ""}})) == "address",
			      "an unmasked whole lifts the mask");
			Check(Joined(UniteColumnItems({{"address.ssn", "NULL"}}, {{"address.ssn", ""}})) == "address.ssn",
			      "plain beats masked, per field");
			bool refused = false;
			try {
				UniteColumnItems({{"address.ssn", "NULL"}}, {{"address.ssn", "'x'"}});
			} catch (std::exception &) {
				refused = true;
			}
			Check(refused, "two different masks of one field are refused, never picked");
			Check(Joined(UniteColumnItems({{"id", ""}}, {{"name", ""}})) == "id, name", "columns as before");
		});
	});
}
