//===----------------------------------------------------------------------===//
// acl_scan_util.hpp — the text-scanning helpers the management grammar and the batch checks still
// use until spec 150's stage 3 makes them rules (a word, whitespace, a quoted literal with the
// doubled-quote escape); the override's one-word ACL gate too. Nothing here parses SQL.
//===----------------------------------------------------------------------===//
#pragma once

#include "duckdb/common/exception/parser_exception.hpp"
#include "duckdb/common/string_util.hpp"

namespace duckdb {
namespace acl {

inline bool IsWordChar(char c) {
	return StringUtil::CharacterIsAlpha(c) || StringUtil::CharacterIsDigit(c) || c == '_';
}

inline string ReadWord(const string &query, idx_t &pos) {
	auto start = pos;
	while (pos < query.size() && IsWordChar(query[pos])) {
		pos++;
	}
	return query.substr(start, pos - start);
}

inline void SkipWhitespace(const string &query, idx_t &pos) {
	while (pos < query.size() && StringUtil::CharacterIsSpace(query[pos])) {
		pos++;
	}
}

//! Read a single-quoted or double-quoted literal, honoring the doubled-quote escape
inline string ReadQuoted(const string &query, idx_t &pos) {
	char quote = query[pos++];
	string value;
	while (pos < query.size()) {
		if (query[pos] == quote) {
			if (pos + 1 < query.size() && query[pos + 1] == quote) {
				value += quote;
				pos += 2;
				continue;
			}
			pos++;
			return value;
		}
		value += query[pos++];
	}
	throw ParserException("acl_rewrite: unterminated quoted value");
}

} // namespace acl
} // namespace duckdb
