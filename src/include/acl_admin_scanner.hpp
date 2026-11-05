//===----------------------------------------------------------------------===//
// acl_admin_scanner.hpp
//
// The scanner the readers of a management statement's lists still use (spec 008): a list a rule read is handed to
// them as its text (REQUIRE / ATTRIBUTES, a column list, a claim map, limits). Every statement is a rule since spec
// 150 3g-3c; the lists become rules with stage 4.
//===----------------------------------------------------------------------===//

#pragma once

#include "acl_scan_util.hpp"

#include "duckdb/common/exception/binder_exception.hpp"
#include "duckdb/common/string_util.hpp"

namespace duckdb {
namespace acl {

struct AdminScanner {
	const string &text;
	idx_t pos = 0;

	explicit AdminScanner(const string &text_p) : text(text_p) {
	}
	void Skip() {
		SkipWhitespace(text, pos);
	}
	bool Done() {
		Skip();
		return pos >= text.size();
	}
	string Word(const char *what) {
		Skip();
		auto word = ReadWord(text, pos);
		if (word.empty()) {
			throw BinderException("acl admin: expected %s at position %llu", what, pos);
		}
		return word;
	}
	void Expect(const char *keyword) {
		auto word = Word(keyword);
		if (!StringUtil::CIEquals(word, keyword)) {
			throw BinderException("acl admin: expected %s, got \"%s\"", keyword, word);
		}
	}
	bool Accept(const char *keyword) {
		Skip();
		auto saved = pos;
		auto word = ReadWord(text, pos);
		if (StringUtil::CIEquals(word, keyword)) {
			return true;
		}
		pos = saved;
		return false;
	}
	bool AtParen() {
		Skip();
		return pos < text.size() && text[pos] == '(';
	}
	string Quoted(const char *what) {
		Skip();
		if (pos >= text.size() || (text[pos] != '\'' && text[pos] != '"')) {
			throw BinderException("acl admin: expected a quoted %s at position %llu", what, pos);
		}
		return ReadQuoted(text, pos);
	}
	//! The text inside a parenthesised list, e.g. `(id INT, amount INT)` -> "id INT, amount INT".
	//! Returns empty when the next token is not '('.
	string Parens() {
		Skip();
		if (pos >= text.size() || text[pos] != '(') {
			return string();
		}
		auto start = ++pos;
		idx_t depth = 1;
		while (pos < text.size() && depth > 0) {
			auto c = text[pos];
			if (c == '\'' || c == '"') {
				ReadQuoted(text, pos);
				continue;
			}
			if (c == '(') {
				depth++;
			} else if (c == ')') {
				depth--;
				if (depth == 0) {
					break;
				}
			}
			pos++;
		}
		if (depth != 0) {
			throw BinderException("acl admin: unbalanced parentheses at position %llu", start);
		}
		auto body = text.substr(start, pos - start);
		pos++; // the closing paren
		StringUtil::Trim(body);
		return body;
	}

	//! words joined by `.`, as written - a claim path, a value; never a SQL name (that is Path)
	string DottedWords(const char *what) {
		auto path = Word(what);
		while (pos < text.size() && text[pos] == '.') {
			pos++;
			path += "." + Word(what);
		}
		return path;
	}
};

//! Strip one layer of quotes from a list element written as a literal
string Unquoted(string value);

} // namespace acl
} // namespace duckdb
