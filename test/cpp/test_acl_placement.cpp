// Placement (spec 096): every row of the decision a node of a resource group makes about a session,
// against acl_placement.hpp's Place() - header-only, no instance. The principal's groups arrive
// already resolved (bound, or the default group for a principal bound to none); what the store reads
// is test/sql/acl_node_group.test's.
// Build + run via `GEN=ninja make test-cpp`.

#include "acl_test_util.hpp"

#include "acl_placement.hpp"

using duckdb::acl::Place;
using namespace acl_test;

int main(int argc, char *argv[]) {
	return RunMain("placement of sessions on a node of a resource group (spec 096)", [&] {
		Scenario("a node without a group serves everyone", [&] {
			for (auto &groups : std::vector<std::vector<std::string>> {{}, {"a"}, {"a", "b"}}) {
				auto decision = Place("", true, groups);
				Check(decision.admitted && decision.group.empty(), "admitted, the 085 merge applies");
			}
			Check(Place("", false, {}).admitted, "an empty node group is never 'unknown'");
		});
		Scenario("a node of g serves the holders of g, as members of g", [&] {
			auto decision = Place("g", true, {"a", "g", "z"});
			Check(decision.admitted && decision.group == "g", "admitted with g's limits only");
			Check(Place("g", true, {"g"}).group == "g", "the default group arrives as the principal's own");
		});
		Scenario("a node of g refuses everyone else, and says where to go", [&] {
			auto other = Place("g", true, {"h", "k"});
			Check(!other.admitted, "another group's principal refused");
			Check(other.refusal == "acl: this node serves resource group \"g\" - your roles are served by \"h\", \"k\"",
			      "the refusal names the groups: " + other.refusal);
			auto none = Place("g", true, {});
			Check(!none.admitted && none.refusal.find("no resource group serves your roles") != std::string::npos,
			      "a principal no group serves (and no default): " + none.refusal);
			Check(!Place("g", true, {"G"}).admitted, "group names compare as written, as the catalog does");
		});
		Scenario("a node whose group the policy does not have serves nobody new", [&] {
			auto unknown = Place("g", false, {"g"});
			Check(!unknown.admitted &&
			          unknown.refusal.find("is not a resource group of the policy") != std::string::npos,
			      "fail closed even for a holder of the name: " + unknown.refusal);
		});
	});
}
