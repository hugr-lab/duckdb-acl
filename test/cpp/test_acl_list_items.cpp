// Spec 150 4e: a stored list's items (`SplitListItems`) are what duckdb's parser reads the same text as - a
// differential over expression lists holding every literal and bracket the old comma counter misread (`[ ]`, `{ }`,
// `$$…$$`, `E'…'`, comments, lambdas), and the `name = <mask>` form a grant stores: each name the text before the
// first top-level `=`, each mask one expression duckdb reads as written. src/acl_list_items.cpp is compiled into this
// test. Build + run via `GEN=ninja make test-cpp`.

#include "acl_test_util.hpp"

#include "acl_list_items.hpp"
#include "duckdb/parser/parsed_expression.hpp"
#include "duckdb/parser/parser.hpp"

using namespace acl_test;
using duckdb::Parser;
using duckdb::ParserOptions;
using duckdb::acl::SplitListItems;

namespace {

std::vector<std::string> Parsed(const std::string &list) {
	std::vector<std::string> out;
	Parser parser(ParserOptions::Builtin());
	for (auto &expression : parser.ParseExpressionList(list)) {
		out.push_back(expression->ToString());
	}
	return out;
}

//! the items as duckdb's parser reads each one alone
std::vector<std::string> SplitThenParsed(const std::string &list) {
	std::vector<std::string> out;
	for (auto &item : SplitListItems(list)) {
		auto one = Parsed(item.text);
		if (one.size() != 1) {
			out.push_back("<" + std::to_string(one.size()) + " expressions in " + item.text + ">");
			continue;
		}
		out.push_back(one[0]);
	}
	return out;
}

void Differential() {
	const std::vector<std::string> lists = {
	    "a, b",
	    "coalesce(a, b), c",
	    "['a', 'b'], {'k': 1, 'j': 2}",
	    "[1, [2, 3]][1], d",
	    "MAP {'a': 1, 'b': 2}, x",
	    "list_transform(l, lambda x: x + 1), y",
	    "list_transform(l, x -> x + 1), y",
	    "'a,b', \"c,d\"",
	    "$$x, y$$, z",
	    "$t$x, ) y$t$, z",
	    "E'a\\', b', c",
	    "/* , */ a, -- ,\n b",
	    "a /* , /* nested , */ , */, b",
	    "x::DECIMAL(10, 2), y",
	    "struct_pack(a := 1, b := 2), c",
	    "CASE WHEN a = 1 THEN 'x,y' ELSE 'z' END, e",
	    "a = 1, b >= 2, c",
	    "(a, b), c",
	    "{'k': [1, 2], 'j': {'n': (3, 4)}}, d",
	    "'it''s, here', f",
	};
	for (auto &list : lists) {
		auto expected = Parsed(list);
		auto split = SplitThenParsed(list);
		Check(split == expected, "split as duckdb parses: " + list);
	}
}

void NamedItems() {
	// what a grant stores: `name` or `name = <mask>`, the name the text before the first top-level `=`
	auto items = SplitListItems("id, tags = ['a', 'b'], s = {'x': 9, 'y': 8}, odd name, note = a = b, "
	                            "m = MAP {'k': 1}, \"a=b\", items[].price, f = list_filter(l, x -> x = 1)");
	std::vector<std::pair<std::string, std::string>> got;
	for (auto &item : items) {
		got.emplace_back(item.has_value ? item.name : item.text, item.has_value ? item.value : "");
	}
	std::vector<std::pair<std::string, std::string>> want = {
	    {"id", ""},       {"tags", "['a', 'b']"}, {"s", "{'x': 9, 'y': 8}"},
	    {"odd name", ""}, {"note", "a = b"},      {"m", "MAP {'k': 1}"},
	    {"\"a=b\"", ""},  {"items[].price", ""},  {"f", "list_filter(l, x -> x = 1)"},
	};
	Check(got == want, "names before the first top-level '=', masks as written");
	for (auto &item : items) {
		if (item.has_value) {
			Check(Parsed(item.value).size() == 1, "one expression: " + item.value);
		}
	}
}

void Edges() {
	Check(SplitListItems("").empty(), "an empty text has no item");
	Check(SplitListItems(" , ,, ").empty(), "separators only have no item");
	Check(SplitListItems("a,,b").size() == 2, "an empty item is left out");
	bool open = false;
	SplitListItems("a, b /* open", &open);
	Check(open, "a text ending inside a comment is open");
	open = false;
	SplitListItems("a, 'b", &open);
	Check(open, "a text ending inside a literal is open");
	open = false;
	SplitListItems("a, \"b", &open);
	Check(open, "a text ending inside a quoted name is open");
	open = true;
	SplitListItems("a, b -- closed by the end", &open);
	Check(!open, "a line comment to the end is not open");
	auto items = SplitListItems("a = 1 -- note\n, b");
	Check(items.size() == 2 && items[0].value == "1", "a comment after an item is not the item's");
	Check(SplitListItems("a, b; c").size() == 2, "a ';' belongs to the item it stands in");
}

} // namespace

int main() {
	Differential();
	NamedItems();
	Edges();
	if (failures) {
		std::cout << failures << " FAILED\n";
		return 1;
	}
	std::cout << "PASS\n";
	return 0;
}
