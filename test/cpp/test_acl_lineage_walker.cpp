// Lineage edges of a bound plan (spec 107): acl_lineage_walker.hpp over plans bound from SQL on an
// in-memory database, before the optimizer - what the pre-optimize hook and the lineage worker see.
// Build + run via `GEN=ninja make test-cpp`.

#include "acl_test_util.hpp"

#include "acl_lineage_walker.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/parser/parser.hpp"
#include "duckdb/planner/operator/logical_get.hpp"
#include "duckdb/planner/planner.hpp"
#include "duckdb/catalog/catalog_entry/table_catalog_entry.hpp"

using namespace acl_test;
using duckdb::acl::LineageWalk;
using duckdb::acl::LineageWalkOptions;
using duckdb::acl::WalkLineage;

namespace {

//! Bind `sql` (one statement) and walk its plan; tables are physical datasets named `<schema>.<table>`.
LineageWalk Walk(duckdb::Connection &con, const std::string &sql, duckdb::idx_t max_edges = 4096) {
	duckdb::Parser parser(duckdb::ParserOptions::Builtin());
	parser.ParseQuery(sql);
	LineageWalk walk;
	LineageWalkOptions options;
	options.max_edges = max_edges;
	options.classify = [](duckdb::LogicalGet &get, duckdb::acl::LineageDatasetKey &out) {
		auto table = get.GetTable();
		if (!table) {
			return false;
		}
		out.kind = "physical";
		out.catalog = table->ParentCatalog().GetName().GetIdentifierName();
		out.schema = table->ParentSchema().name.GetIdentifierName();
		out.name = table->name.GetIdentifierName();
		return true;
	};
	con.context->RunFunctionInTransaction([&]() {
		duckdb::Planner planner(*con.context);
		planner.CreatePlan(std::move(parser.statements[0]));
		options.output_names.clear();
		for (auto &name : planner.names) {
			options.output_names.push_back(name.GetIdentifierName());
		}
		walk = WalkLineage(*planner.plan, options);
	});
	return walk;
}

//! "dataset.field:TYPE/SUBTYPE" for every source of `output`, sorted - or "<none>" when the output is absent.
std::string Sources(const LineageWalk &walk, const std::string &output) {
	for (auto &out : walk.outputs) {
		if (out.name != output) {
			continue;
		}
		std::vector<std::string> items;
		for (auto &source : out.sources) {
			items.push_back(walk.datasets[source.dataset].name + "." + source.field + ":" + source.type + "/" +
			                source.subtype);
		}
		std::sort(items.begin(), items.end());
		std::string joined;
		for (auto &item : items) {
			joined += (joined.empty() ? "" : ", ") + item;
		}
		return joined;
	}
	return "<none>";
}

std::string Whole(const LineageWalk &walk) {
	std::vector<std::string> items;
	for (auto &source : walk.whole_target) {
		items.push_back(walk.datasets[source.dataset].name + "." + source.field + ":" + source.subtype);
	}
	std::sort(items.begin(), items.end());
	std::string joined;
	for (auto &item : items) {
		joined += (joined.empty() ? "" : ", ") + item;
	}
	return joined;
}

bool Expect(const std::string &got, const std::string &want, const std::string &what) {
	return Check(got == want, what + ": got [" + got + "], want [" + want + "]");
}

} // namespace

int main() {
	return RunMain("lineage edges of a bound plan (spec 107)", [] {
		duckdb::DuckDB db(nullptr);
		duckdb::Connection con(db);
		Exec(con, "CREATE TABLE t1 (id INT, x INT, y VARCHAR, g VARCHAR, v DOUBLE, flag BOOLEAN)");
		Exec(con, "CREATE TABLE t2 (a INT, b VARCHAR)");
		Exec(con, "CREATE TABLE t3 (id INT, y VARCHAR)");
		Exec(con, "CREATE TABLE t4 (id INT, s STRUCT(city VARCHAR, zip VARCHAR), items STRUCT(price INT, qty INT)[])");

		Scenario("INSERT ... SELECT: identity and transformation, into the target's columns", [&] {
			auto walk = Walk(con, "INSERT INTO t2 (a, b) SELECT x, upper(y) FROM t1");
			Check(walk.has_target && walk.target.name == "t2" && walk.target_operation == "INSERT", "the target");
			Expect(Sources(walk, "a"), "t1.x:DIRECT/IDENTITY", "a");
			Expect(Sources(walk, "b"), "t1.y:DIRECT/TRANSFORMATION", "b");
			Check(!walk.approximate, "exact");
		});

		Scenario("CTAS with GROUP BY: aggregation, and the group key as an INDIRECT edge", [&] {
			auto walk = Walk(con, "CREATE TABLE agg AS SELECT g, sum(v) AS s FROM t1 GROUP BY g");
			Check(walk.has_target && walk.target.name == "agg" && walk.target_operation == "CREATE_TABLE_AS",
			      "the target");
			Expect(Sources(walk, "g"), "t1.g:DIRECT/IDENTITY", "g");
			Expect(Sources(walk, "s"), "t1.v:DIRECT/AGGREGATION", "s");
			Expect(Whole(walk), "t1.g:GROUP_BY", "whole target");
		});

		Scenario("a join and a filter decide the rows: JOIN and FILTER edges on the whole target", [&] {
			auto walk = Walk(con, "INSERT INTO t2 SELECT a.x, b.y FROM t1 a JOIN t3 b ON a.id = b.id WHERE a.flag");
			Expect(Sources(walk, "a"), "t1.x:DIRECT/IDENTITY", "a");
			Expect(Sources(walk, "b"), "t3.y:DIRECT/IDENTITY", "b");
			Expect(Whole(walk), "t1.flag:FILTER, t1.id:JOIN, t3.id:JOIN", "whole target");
		});

		Scenario("struct fields and list elements extend the field path (spec 102's spelling)", [&] {
			auto walk = Walk(con, "SELECT s.city, list_transform(items, lambda x: x.price) AS prices, s FROM t4");
			Expect(Sources(walk, "city"), "t4.s.city:DIRECT/IDENTITY", "s.city");
			Expect(Sources(walk, "prices"), "t4.items[].price:DIRECT/IDENTITY", "items[].price");
			Expect(Sources(walk, "s"), "t4.s:DIRECT/IDENTITY", "the whole struct");
		});

		Scenario("UPDATE: a SET column from its expression, the WHERE as a filter", [&] {
			auto walk = Walk(con, "UPDATE t2 SET b = upper(b || 'x') WHERE a > 3");
			Check(walk.has_target && walk.target_operation == "UPDATE", "an update of t2");
			Expect(Sources(walk, "b"), "t2.b:DIRECT/TRANSFORMATION", "b");
			Expect(Whole(walk), "t2.a:FILTER", "whole target");
		});

		Scenario("CASE: the condition is CONDITIONAL on the field, the branches its values", [&] {
			auto walk = Walk(con, "SELECT CASE WHEN flag THEN x ELSE 0 END AS c FROM t1");
			Expect(Sources(walk, "c"), "t1.flag:INDIRECT/CONDITIONAL, t1.x:DIRECT/TRANSFORMATION", "c");
		});

		Scenario("a window: its argument aggregated, its partition and order as WINDOW", [&] {
			auto walk = Walk(con, "SELECT sum(v) OVER (PARTITION BY g ORDER BY id) AS w FROM t1");
			Expect(Sources(walk, "w"), "t1.g:INDIRECT/WINDOW, t1.id:INDIRECT/WINDOW, t1.v:DIRECT/AGGREGATION", "w");
		});

		Scenario("a materialized CTE and a UNION: both sides reach the output", [&] {
			auto walk =
			    Walk(con, "WITH c AS MATERIALIZED (SELECT y FROM t1) SELECT y FROM c UNION ALL SELECT y FROM t3");
			Expect(Sources(walk, "y"), "t1.y:DIRECT/IDENTITY, t3.y:DIRECT/IDENTITY", "y");
			Check(!walk.approximate, "exact");
		});

		Scenario("no value is ever an edge: a constant has no source", [&] {
			auto walk = Walk(con, "INSERT INTO t2 VALUES (1, 'secret')");
			Check(walk.has_target, "the target");
			Expect(Sources(walk, "b"), "", "b from a literal");
		});

		Scenario("the edge cap: truncated, never more than the cap", [&] {
			auto walk = Walk(con, "SELECT x, y, g, v FROM t1", 2);
			Check(walk.truncated, "truncated");
			Check(walk.EdgeCount() <= 2, "at most 2 edges, got " + std::to_string(walk.EdgeCount()));
		});
	});
}
