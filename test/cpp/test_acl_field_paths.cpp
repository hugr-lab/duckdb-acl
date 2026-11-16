// The names in a stored column list (acl_field_paths.hpp, what spec 158 left of spec 102): the column an item names.
// Build + run via `GEN=ninja make test-cpp`.

#include "acl_test_util.hpp"

#include "acl_field_paths.hpp"

using namespace acl_test;
using duckdb::acl::acl_detail::FieldPath;
using duckdb::acl::acl_detail::ItemHead;
using duckdb::acl::acl_detail::ParseFieldPath;

int main(int argc, char *argv[]) {
	return RunMain("the names in a stored column list", [&] {
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

		Scenario("an item's column", [&] {
			bool is_path = false;
			Check(ItemHead("id", is_path) == "id" && !is_path, "a name");
			Check(ItemHead("\"Zip Code\"", is_path) == "Zip Code" && !is_path, "a quoted name, unquoted");
			Check(ItemHead("a.b", is_path) == "a" && is_path, "a dotted name reads its first part");
			Check(ItemHead("odd name", is_path) == "odd name" && !is_path, "a name that reads as no path");
		});
	});
}
