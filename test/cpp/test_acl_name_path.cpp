// Quoted names (spec 116): acl_name_path.hpp's canonical key. FromKey / ToKey round trip against
// duckdb's own QualifiedName::ParseComponents over a matrix of names, the refusals ParseComponents
// does not make (an empty part), and the SQL fragments the listings and the resolver build from it -
// evaluated in duckdb, so what is checked is what a query answers, not the SQL text.
// Build + run via `GEN=ninja make test-cpp`.

#include "acl_test_util.hpp"

#include "acl_name_path.hpp"
#include "acl_result_rows.hpp"

using namespace acl_test;
using duckdb::acl::NamePath;

using Parts = duckdb::vector<std::string>;

static std::string Lit(const std::string &text) {
	return "'" + duckdb::StringUtil::Replace(text, "'", "''") + "'";
}

static std::string One(duckdb::Connection &con, const std::string &sql) {
	auto result = con.Query(sql);
	if (result->HasError()) {
		return "ERROR " + result->GetError();
	}
	duckdb::acl::ResultRows rows(*result);
	if (rows.Count() != 1) {
		return "ROWS " + std::to_string(rows.Count());
	}
	auto value = rows.GetValue(0, 0);
	return value.IsNull() ? "NULL" : value.ToString();
}

int main(int argc, char *argv[]) {
	return RunMain("quoted names: the canonical key (spec 116)", [&] {
		duckdb::DuckDB db(nullptr);
		duckdb::Connection con(db);

		// raw parts, and the key each must have: a part quoted only when it holds `.` or `"`
		std::vector<std::pair<Parts, std::string>> matrix = {
		    {{"orders"}, "orders"},
		    {{"Sales Mart", "Order Items"}, "Sales Mart.Order Items"},
		    {{"a.b"}, "\"a.b\""},
		    {{"a", "b"}, "a.b"},
		    {{"q\"uote"}, "\"q\"\"uote\""},
		    {{"c", "Raw Data", "sub", "T"}, "c.Raw Data.sub.T"},
		    {{"x-y", "a.b", "c"}, "x-y.\"a.b\".c"},
		    {{"\"", "."}, "\"\"\"\".\".\""},
		    {{"a.", "\"b"}, "\"a.\".\"\"\"b\""},
		    {{"select", "Upper"}, "select.Upper"},
		};

		Scenario("a key is the exact inverse of duckdb's ParseComponents", [&] {
			for (auto &entry : matrix) {
				auto key = NamePath(entry.first).ToKey();
				Check(key == entry.second, "key of [" + duckdb::StringUtil::Join(entry.first, "|") + "] is " + key);
				Parts parsed;
				for (auto &part : duckdb::QualifiedName::ParseComponents(key)) {
					parsed.push_back(part.GetIdentifierName());
				}
				Check(parsed == entry.first, "ParseComponents reads " + key + " back as its parts");
				auto ours = NamePath::FromKey(key);
				Check(ours.Parts() == entry.first, "FromKey reads " + key + " back as its parts");
				Check(NamePath::FromKey(ours.ToKey()).ToKey() == key, "and the round trip is stable: " + key);
			}
		});

		Scenario("what is not a key is refused - including what ParseComponents lets through", [&] {
			for (auto bad : {"", "a..b", "a.", ".a", "\"\"", "\"abc", "a\"b", "\"a\"b", "\"a\".\"\""}) {
				NamePath path;
				std::string error;
				Check(!NamePath::TryFromKey(bad, path, error), std::string("refused: ") + bad + " (" + error + ")");
			}
		});

		Scenario("head, rest, parent, leaf keep a part whole", [&] {
			std::string head, rest, parent, leaf;
			Check(NamePath::SplitHeadKey("\"a.b\".c.\"d.e\"", head, rest) && head == "\"a.b\"" && rest == "c.\"d.e\"",
			      "SplitHeadKey: \"a.b\" | c.\"d.e\"");
			Check(!NamePath::SplitHeadKey("\"a.b\"", head, rest), "a one-part key has no rest");
			NamePath::SplitLeaf("sales.\"Order.Items\"", parent, leaf);
			Check(parent == "sales" && leaf == "Order.Items", "SplitLeaf: the raw leaf");
			Check(NamePath::ChildKey("phys.Raw Data", "x.y") == "phys.Raw Data.\"x.y\"", "ChildKey quotes a raw part");
			Check(NamePath::KeyUnder("Sales.\"a.b\"", "sales") && !NamePath::KeyUnder("salesx.t", "sales"),
			      "KeyUnder is case-insensitive and stops at a part boundary");
			Check(NamePath::FromKey("c.Raw Data.select.\"a.b\"").ToSql() == "c.\"Raw Data\".\"select\".\"a.b\"",
			      "ToSql quotes as duckdb does (a keyword too)");
			Check(NamePath::FromKey("c.Raw Data.t_1").ToGrammar() == "c.\"Raw Data\".t_1",
			      "ToGrammar quotes only what the grammar cannot read bare");
			Check(NamePath::Display("Raw Data") == "Raw Data" && NamePath::Display("\"q\"\"uote\"") == "q\"uote" &&
			          NamePath::Display("\"a.b\"") == "\"a.b\"" && NamePath::Display("a.\"b.c\"") == "a.\"b.c\"",
			      "Display: one part unquoted unless it holds a dot, a path as its key");
			for (auto key : {"Raw Data", "\"q\"\"uote\"", "\"a.b\"", "a.\"b.c\"", "a.b"}) {
				Check(NamePath::FromDisplay(NamePath::Display(key)) == key,
				      std::string("FromDisplay inverts Display: ") + key);
			}
		});

		Scenario("the SQL fragments answer what the C++ answers, for every key of the matrix", [&] {
			for (auto &entry : matrix) {
				auto key = entry.second;
				auto lit = Lit(key);
				std::string parent, leaf;
				NamePath::SplitLeaf(key, parent, leaf);
				Check(One(con, "SELECT " + duckdb::acl::KeyUnquoteSql(duckdb::acl::KeyLeafSql(lit))) == leaf,
				      "KeyLeafSql of " + key + " is " + leaf);
				Check(One(con, "SELECT " + duckdb::acl::KeyParentSql(lit)) == parent,
				      "KeyParentSql of " + key + " is '" + parent + "'");
				Check(One(con, "SELECT " + duckdb::acl::KeyNestedSql(lit)) ==
				          (entry.first.size() > 1 ? "true" : "false"),
				      "KeyNestedSql of " + key);
				Check(One(con, "SELECT array_to_string(" + duckdb::acl::KeyPartsSql(lit) + ", '|')") ==
				          duckdb::StringUtil::Join(entry.first, "|"),
				      "KeyPartsSql of " + key);
				Check(One(con, "SELECT " + duckdb::acl::KeyDisplaySql(lit)) == NamePath::Display(key),
				      "KeyDisplaySql of " + key);
				auto shown = NamePath::Display(key);
				Check(One(con, "SELECT " + duckdb::acl::KeyFromDisplaySql(Lit(shown))) == NamePath::FromDisplay(shown),
				      "KeyFromDisplaySql of " + shown);
				if (entry.first.size() == 1) {
					Check(One(con, "SELECT " + duckdb::acl::KeyQuotePartSql(Lit(entry.first[0]))) == key,
					      "KeyQuotePartSql of " + entry.first[0]);
				}
			}
			Check(One(con, "SELECT " + duckdb::acl::KeyEqSql("'Sales Mart.Order Items'", "'sales mart.ORDER ITEMS'")) ==
			          "true",
			      "KeyEqSql is case-insensitive");
			Check(One(con, "SELECT " + duckdb::acl::KeyPrefixSql("'\"a.b\".c'", "'\"A.B\"'")) == "true" &&
			          One(con, "SELECT " + duckdb::acl::KeyPrefixSql("'\"a.b\".c'", "'a'")) == "false",
			      "KeyPrefixSql: a quoted part is a prefix whole, never the text before its dot");
		});

		Scenario("one fold: the SQL comparison answers what C++ (and duckdb's catalog) answers", [&] {
			std::vector<std::pair<std::string, std::string>> pairs = {
			    {"Order Items", "order ITEMS"},
			    {"\xc3\x84", "\xc3\xa4"},                     // Ä / ä
			    {"STRA\xe1\xba\x9e\x45", "stra\xc3\x9f\x65"}, // STRAẞE / straße
			    {"i\xe2\x84\xaa", "ik"},                      // i + Kelvin sign / ik
			    {"\xc4\xb0K", "ik"},                          // İK / ik
			    {"a.b", "A.B"}};
			for (auto &pair : pairs) {
				auto sql = One(con, "SELECT " + duckdb::acl::KeyEqSql(Lit(pair.first), Lit(pair.second)));
				auto cpp = duckdb::StringUtil::CIEquals(pair.first, pair.second) ? "true" : "false";
				Check(sql == cpp, "KeyEqSql agrees with CIEquals: " + pair.first + " / " + pair.second + " = " + cpp);
				Check(One(con, "SELECT strlen(" + duckdb::acl::KeyFoldSql(Lit(pair.first)) + ")") ==
				          std::to_string(pair.first.size()),
				      "the fold keeps the length in bytes: " + pair.first);
			}
		});
	});
}
