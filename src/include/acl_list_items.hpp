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

//! Split a comma-style list on top-level delimiters only: a delimiter inside quotes or inside
//! parentheses belongs to an expression, not to the list. Without this a column list breaks on the
//! first `coalesce(a, b)` - and breaks it silently, into two nonsense entries.
vector<string> SplitTopLevel(const string &text, char delimiter);

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
//! A text holding a comment (outside literals and quoted names) is read as the builds before 4e read every list - the
//! items at `SplitTopLevel`'s commas, the name before an item's first `=`: only such a build stored one (a name holding
//! `--` or `/*` was stored as it is - `a--b`, which duckdb's tokens read as `a` and a comment), and no writer since
//! stores a comment. `open`: set when the text ends inside a comment, a literal or a quoted name; `comment`: set when
//! it holds a comment (both what a writer refuses)
vector<ListItemText> SplitListItems(const string &text, bool *open = nullptr, bool *comment = nullptr);

//! Whether a column's name may be stored bare in a list (spec 150 4e): it reads back as one item that is itself - no
//! `,` / `=` / bracket or quote that the split reads otherwise, no comment, no space at an end - and not as a path (no
//! `.` / `[`, no leading `"`). Otherwise a writer quotes it, and the path reader takes the quotes off
bool StoresBare(const string &name);

} // namespace acl
} // namespace duckdb
