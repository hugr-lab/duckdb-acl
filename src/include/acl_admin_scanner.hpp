//===----------------------------------------------------------------------===//
// acl_admin_scanner.hpp
//
// The management grammar's scanner (spec 008) and the seam a linked module's grammar plugs into (spec 126):
// a keyword the override recognizes as management (`CLUSTER …`) and the parser that compiles its text into
// acl_* calls. The authorizer and the audit stay the override's - a module only compiles text.
//===----------------------------------------------------------------------===//

#pragma once

#include "acl_name_path.hpp"
#include "acl_scan_util.hpp"

#include "duckdb/common/exception/binder_exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/types/value.hpp"
#include "duckdb/parser/sql_statement.hpp"

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
	bool AtSemicolon() {
		Skip();
		return pos < text.size() && text[pos] == ';';
	}
	string PeekWord() {
		Skip();
		auto saved = pos;
		auto word = ReadWord(text, pos);
		pos = saved;
		return word;
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

	//! Everything up to the end of this statement, taken verbatim - quote- and paren-aware, so a
	//! body may contain ';' inside a literal or a parenthesised list. This is what makes an inline
	//! body possible: `AS SELECT … WHERE tenant = acl_claim('tenant')` instead of the same text in a
	//! quoted string with every quote doubled.
	string Rest(const char *what) {
		Skip();
		auto start = pos;
		idx_t depth = 0;
		while (pos < text.size()) {
			auto c = text[pos];
			if (c == '\'' || c == '"') {
				ReadQuoted(text, pos);
				continue;
			}
			if (c == '(') {
				depth++;
			} else if (c == ')' && depth > 0) {
				depth--;
			} else if (c == ';' && depth == 0) {
				break;
			}
			pos++;
		}
		auto body = text.substr(start, pos - start);
		StringUtil::Trim(body);
		if (body.empty()) {
			throw BinderException("acl admin: expected %s at position %llu", what, start);
		}
		return body;
	}

	//! A body written either way: a quoted string (what a gateway generates) or inline to the end of
	//! the statement (what a human writes). Both forms are accepted everywhere a body is taken.
	string Body(const char *what) {
		Skip();
		if (pos < text.size() && (text[pos] == '\'' || text[pos] == '"')) {
			return Quoted(what);
		}
		return Rest(what);
	}

	//! A name that is a VALUE, not an SQL identifier (an issuer, a client, a resource group, a secret, an
	//! extension, a source's alias - spec 116 §3): bare (`range`, `a.b`) or quoted either way, as written
	string NameValue(const char *what) {
		Skip();
		if (pos < text.size() && (text[pos] == '\'' || text[pos] == '"')) {
			return Quoted(what);
		}
		return DottedWords(what);
	}

	//! A virtual or physical name, as its canonical key (spec 116): written as SQL writes one
	//! (`pg."Raw Data".orders`, each part a word or a double-quoted identifier), or as the legacy
	//! single-quoted string holding a whole path (`'pg.public.orders'`), read with the key rules
	string PathName(const char *what) {
		Skip();
		if (pos < text.size() && text[pos] == '\'') {
			auto written = Quoted(what);
			return NamePath::FromKey(written, what).ToKey();
		}
		return Dotted(what);
	}

	//! A list written either way: `(a, b = c)` or the legacy quoted csv/JSON string
	string List(const char *what) {
		Skip();
		if (pos < text.size() && text[pos] == '(') {
			return Parens();
		}
		return Quoted(what);
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

	//! One SQL identifier (spec 116): a word, or a double-quoted identifier with `""` for a quote - any
	//! case, spaces, a dot inside. The raw name, unquoted.
	string Ident(const char *what) {
		Skip();
		if (pos < text.size() && text[pos] == '"') {
			auto start = pos;
			pos++;
			string name;
			bool closed = false;
			while (pos < text.size()) {
				if (text[pos] == '"') {
					if (pos + 1 < text.size() && text[pos + 1] == '"') {
						name += '"';
						pos += 2;
						continue;
					}
					pos++;
					closed = true;
					break;
				}
				name += text[pos++];
			}
			if (!closed) {
				throw BinderException("acl admin: an unterminated quoted identifier at position %llu", start);
			}
			if (name.empty()) {
				throw BinderException("acl admin: an empty quoted identifier at position %llu - %s cannot be empty",
				                      start, what);
			}
			return name;
		}
		return Word(what);
	}

	//! Identifiers joined by `.` (spec 116): `c."Raw Data".sub."T"` - each part one identifier
	NamePath Path(const char *what) {
		vector<string> parts;
		parts.push_back(Ident(what));
		while (pos < text.size() && text[pos] == '.') {
			pos++;
			parts.push_back(Ident(what));
		}
		return NamePath(std::move(parts));
	}

	//! A path as its canonical key
	string Dotted(const char *what) {
		return Path(what).ToKey();
	}

	//! One identifier as the key of a one-part name (a catalog: `"Sales Mart"`, `"a.b"`)
	string IdentKey(const char *what) {
		return NamePath::QuotePart(Ident(what));
	}
};

//! Strip one layer of quotes from a list element written as a literal
string Unquoted(string value);

//! `SELECT <function>(<args>)` - what every management form compiles to (the authorizer judges the call)
unique_ptr<SQLStatement> MakeAdminCall(const string &function, const vector<Value> &args);

//! spec 126: a management form a linked module adds - `keyword …` after the prefix (or `ACL ADMIN`) is
//! management, and `parse` compiles it (the scanner stands after the keyword). Registered at load, before the
//! first statement; idempotent by keyword.
using MgmtGrammar = unique_ptr<SQLStatement> (*)(AdminScanner &scanner);
void RegisterMgmtGrammar(const char *keyword, MgmtGrammar parse);

} // namespace acl
} // namespace duckdb
