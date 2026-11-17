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
#include "acl_grant_columns.hpp"

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

//! One item of a column list read as a SELECT list (spec 158): `name` (expr ''), `<expression> AS name` or
//! `name: <expression>` (expr the expression as duckdb prints it), `a.b` a column of its own named as SELECT names it
//! (`b`, expr `a.b`), or - where admitted - a star (`*`, `* EXCLUDE (…)`, `COLUMNS(…)`: `star`, expr its text). The
//! name is the identifier itself, never quoted
struct SelectListItem {
	string name;
	string expr;
	bool star = false;
};

//! A column list (a grant's, an object's own) read by duckdb's parser as the list of `SELECT <text> FROM t` (spec
//! 158): refused when the text holds anything more than the list, an expression without a name, a positional
//! reference (`#2`) or - unless `allow_star` - a star. `what` names the list in the refusal
vector<SelectListItem> ReadSelectList(const string &text, const char *what, bool allow_star);

//! An object grant's `COLUMNS` (spec 158) read by duckdb's parser: names (`a, b`), `*`, or `* EXCLUDE (a, b)` - and
//! nothing else (an expression, a qualified or a replacing star, `COLUMNS(…)`, a star beside names refuse). '' is ALL
acl_detail::ColumnTest ReadColumnTest(const string &text);

//! The test as its rows store it - as duckdb prints a SELECT list ('' for every column)
string ColumnTestText(const acl_detail::ColumnTest &test);

//! An object grant's `MASK` items (spec 158): `<column> AS <expression>`, each split on duckdb's tokens, the
//! expression one expression read by duckdb's parser and kept as it prints it; a column named twice refuses
//! `written`, when given, receives each mask's expression as it stands in `text` (where spec 160 qualifies its tables)
acl_detail::GrantMasks ReadMasks(const string &text, vector<string> *written = nullptr);

//! The masks as their rows store them (`"ssn" AS <expr>, …`), read back by `ReadMasks`
string MasksText(const acl_detail::GrantMasks &masks);

//! One item of an object's declared column list: the column's name and its expression ('' = the source's column as it
//! is). `nullable` / `quoted` are kept for the callers and always unset since spec 158 (no NULL marks)
struct DeclaredColumnText {
	string name;
	string expr;
	int8_t nullable = -1;
	bool quoted = false;
};

//! An object's declared column list (CREATE VIRTUAL TABLE ... COLUMNS, SET COLUMNS, REMAP, the function forms) read as
//! a SELECT list (`ReadSelectList`); a name holding `.` or `[` is refused (a stored declared name is read as a path).
//! `allow_star` (an object's own list, spec 158 stage 2): one star item, with no name and the star as duckdb prints
//! it. `what` names the list in the refusal
vector<DeclaredColumnText> SplitDeclaredColumns(const string &text, const char *what, bool allow_star = false);

//! spec 158 stage 2: what a stored star makes of the source's columns by name - each REPLACE (column, expression) and
//! each RENAME (new name, the source's name); empty when the text is no star
struct StarParts {
	vector<std::pair<string, string>> replaced;
	vector<std::pair<string, string>> renamed;
};
StarParts ReadStarParts(const string &star_text);

//! spec 172: an object's ON INSERT / ON UPDATE items read by duckdb's parser as a SET list - (column, expression as
//! duckdb prints it); `new.<column>` is the value the write gives a column, a bare column (ON UPDATE only) the row's
//! current value; no subquery, star, position, parameter, DEFAULT or other qualified name; a column set twice refuses
vector<std::pair<string, string>> ReadWriteValues(const string &text, const char *what, bool on_update);
//! The bare names duckdb reads as a value where no column has the name (`current_timestamp`, `user`, …)
bool IsSqlValueKeyword(const string &name);
//! The items as their rows show them (`"col" = <expr>, …`)
string WriteValuesText(const vector<std::pair<string, string>> &items);

//! Whether a column's name may be stored bare in a list (spec 150 4e): it reads back as one item that is itself - no
//! `,` / `=` / bracket or quote that the split reads otherwise, no comment, no space at an end - and not as a path (no
//! `.` / `[`, no leading `"`). Otherwise a writer quotes it, and the path reader takes the quotes off
bool StoresBare(const string &name);

} // namespace acl
} // namespace duckdb
