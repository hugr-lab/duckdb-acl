//! The names in a stored column list (spec 150 4e, 158): the column an item names - a quoted part unquoted, a dotted
//! name read as its first part - and the list as the grant rows store it. What remains of spec 102's field paths,
//! which spec 158 superseded (a grant's COLUMNS is a test on the object's column names). Header-only.
#pragma once

#include "duckdb/parser/keyword_helper.hpp"

#include "duckdb/common/common.hpp"
#include "duckdb/common/string_util.hpp"

namespace duckdb {
namespace acl {
namespace acl_detail {

//! A parsed item name: the column, then the steps into it - a field name, or "" for `[]` (an element)
struct FieldPath {
	string head;
	vector<string> steps;
	bool IsColumn() const {
		return steps.empty();
	}
};

//! `address.city`, `"Order"."Zip Code"`, `items[].price`. A name is an identifier (letters, digits,
//! `_`, `$`) or a double-quoted string; `[]` follows a name or another `[]`. Anything else is refused,
//! so a path is never an expression in disguise.
inline bool ParseFieldPath(const string &text_p, FieldPath &out, string &error) {
	auto text = text_p;
	StringUtil::Trim(text);
	vector<string> parts;
	idx_t i = 0;
	bool expect_name = true;
	while (i < text.size()) {
		auto ch = text[i];
		if (expect_name) {
			string name;
			if (ch == '"') {
				i++;
				bool closed = false;
				while (i < text.size()) {
					if (text[i] == '"') {
						if (i + 1 < text.size() && text[i + 1] == '"') {
							name += '"';
							i += 2;
							continue;
						}
						closed = true;
						i++;
						break;
					}
					name += text[i++];
				}
				if (!closed || name.empty()) {
					error = "an unterminated or empty quoted name";
					return false;
				}
			} else {
				while (i < text.size() && (isalnum(static_cast<unsigned char>(text[i])) || text[i] == '_' ||
				                           text[i] == '$' || static_cast<unsigned char>(text[i]) >= 0x80)) {
					name += text[i++];
				}
				if (name.empty()) {
					error = "a path is names separated by '.', each optionally followed by []";
					return false;
				}
			}
			parts.push_back(name);
			expect_name = false;
			continue;
		}
		if (ch == '[') {
			if (i + 1 >= text.size() || text[i + 1] != ']') {
				error = "'[' must be '[]' (every element of a list)";
				return false;
			}
			parts.push_back(string());
			i += 2;
			continue;
		}
		if (ch == '.') {
			expect_name = true;
			i++;
			continue;
		}
		error = "a path is names separated by '.', each optionally followed by []";
		return false;
	}
	if (expect_name || parts.empty()) {
		error = "a path cannot end with '.'";
		return false;
	}
	out.head = parts[0];
	out.steps.assign(parts.begin() + 1, parts.end());
	return true;
}

//! A name always double-quoted (a quote doubled)
inline string QuotedName(const string &name) {
	return "\"" + StringUtil::Replace(name, "\"", "\"\"") + "\"";
}

//! The column an item's name reads (spec 150 4e: one reading for the read path and the listings) - a path's head, or
//! the name itself when it holds no `.` / `[`, opens no quoted name, or does not read as a path (a column whatever it
//! holds: `odd name`, `od'd`); `is_path` when it steps into the column
inline string ItemHead(const string &name_p, bool &is_path) {
	auto name = name_p;
	StringUtil::Trim(name);
	FieldPath path;
	string error;
	is_path = false;
	if ((name.find('.') == string::npos && name.find('[') == string::npos && (name.empty() || name[0] != '"')) ||
	    !ParseFieldPath(name, path, error)) {
		return name;
	}
	is_path = !path.IsColumn();
	return path.head;
}

//! COLUMNS items as the text the grant rows store (spec 158): a SELECT list - `name`, `<expr> AS name`, each name
//! quoted as duckdb quotes an identifier
inline string ItemsCsv(const vector<std::pair<string, string>> &items) {
	vector<string> parts;
	for (auto &item : items) {
		bool is_path = false;
		auto name = ItemHead(item.first, is_path);
		auto written = is_path ? item.first : KeywordHelper::WriteOptionallyQuoted(name, '"', true);
		parts.push_back(item.second.empty() ? written : item.second + " AS " + written);
	}
	return StringUtil::Join(parts, ", ");
}

} // namespace acl_detail
} // namespace acl
} // namespace duckdb
