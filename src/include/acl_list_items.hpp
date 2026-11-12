//===----------------------------------------------------------------------===//
//                         DuckDB ACL
//
// acl_list_items.hpp
//
// Spec 150 4e: a stored list (a grant's columns, a parameter list) split as duckdb's tokenizer reads the text - the
// one reader of a list's items, so the rule that wrote a list and every reader of the stored text split it alike.
// Its own translation unit: the differential test compiles it beside duckdb's parser.
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb/common/common.hpp"

namespace duckdb {
namespace acl {

//! One item of a stored list as duckdb's tokenizer reads it (spec 150 4e): `text` from its first token to its last
//! as written, and - when a top-level `=` stands in it - the text before it (`name`) and after it (`value`), trimmed
struct ListItemText {
	string text;
	//! where `text` ends in the list
	idx_t end = 0;
	bool has_value = false;
	string name;
	string value;
};

//! A stored list (a grant's columns, a parameter list) split on duckdb's tokens (spec 150 4e): an item ends at a
//! comma outside every `( )`, `[ ]` and `{ }` and every literal, quoted name and comment - the reading duckdb gives the
//! same text, so a mask `tags = ['a', 'b']` or `{'k': 1, 'j': 2}` is one item; an item without a token is left out
//! `open`: set when the text ends inside a comment, a literal or a quoted name (what a writer refuses)
vector<ListItemText> SplitListItems(const string &text, bool *open = nullptr);

} // namespace acl
} // namespace duckdb
