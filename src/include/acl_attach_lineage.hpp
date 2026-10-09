//===----------------------------------------------------------------------===//
//                         duckdb-acl
//
// acl_attach_lineage.hpp
//
// Spec 112 §9: `ATTACH … LINEAGE '<identity>'` - the operator names a source where it attaches it.
// The parser override takes the trailing `LINEAGE '<x>'` off each such statement and compiles it to
// the native ATTACH followed by `acl_lineage_source('<alias>', '<x>')`. This is the text side only:
// a quote-, identifier- and comment-aware split of a batch into its statements, and the marker found
// at the end of an ATTACH. Header-only, no parse - what the text means is the native parser's.
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb/common/string_util.hpp"

namespace duckdb {
namespace acl {

//! One statement of a batch: its text (the marker taken off) and the identity it declared ('' = none)
struct AttachLineageSegment {
	string text;
	string original; // as written, the marker included: the ATTACH's own text (its hook reads it back)
	string identity;
	bool marked = false;
};

namespace attach_lineage_detail {

struct Token {
	idx_t start;
	idx_t end;
	char kind; // 'w' word, 's' single-quoted string, 'p' anything else
};

inline bool WordStart(char c) {
	return StringUtil::CharacterIsAlpha(c) || c == '_';
}

inline bool WordPart(char c) {
	return WordStart(c) || StringUtil::CharacterIsDigit(c) || c == '$';
}

//! Skip a quoted run starting at `pos` (the opening quote); a doubled quote is an escaped one.
//! Answers the position after the closing quote, or the text's end for an unterminated one.
inline idx_t SkipQuoted(const string &text, idx_t pos, char quote, bool backslash) {
	idx_t i = pos + 1;
	while (i < text.size()) {
		if (backslash && text[i] == '\\' && i + 1 < text.size()) {
			i += 2;
			continue;
		}
		if (text[i] == quote) {
			if (i + 1 < text.size() && text[i + 1] == quote) {
				i += 2;
				continue;
			}
			return i + 1;
		}
		i++;
	}
	return text.size();
}

} // namespace attach_lineage_detail

//! Does the text possibly carry the marker? Cheap and allocation-free: every unprefixed statement
//! passes through the override, and nearly none is an ATTACH.
inline bool MayCarryAttachLineage(const string &text) {
	auto ci_find = [&](const char *needle) {
		auto size = strlen(needle);
		return std::search(text.begin(), text.end(), needle, needle + size,
		                   [](char a, char b) { return StringUtil::CharacterToLower(a) == b; }) != text.end();
	};
	return ci_find("attach") && ci_find("lineage");
}

//! The batch's statements, each with the identity its trailing `LINEAGE '<x>'` declared. `found` is
//! whether any statement carried the marker - false leaves the text to the native parser untouched.
inline vector<AttachLineageSegment> SplitAttachLineage(const string &text, bool &found) {
	using attach_lineage_detail::SkipQuoted;
	using attach_lineage_detail::Token;
	using attach_lineage_detail::WordPart;
	using attach_lineage_detail::WordStart;
	found = false;
	vector<AttachLineageSegment> segments;
	vector<Token> tokens;
	idx_t segment_start = 0;
	auto close_segment = [&](idx_t end) {
		AttachLineageSegment segment;
		if (tokens.empty()) {
			segment_start = end + 1;
			return;
		}
		auto &first = tokens.front();
		auto n = tokens.size();
		bool attach =
		    first.kind == 'w' && StringUtil::CIEquals(text.substr(first.start, first.end - first.start), "attach");
		auto &last = tokens[n - 1];
		bool closed = last.kind == 's' && last.end - last.start >= 2 && text[last.end - 1] == '\'';
		if (attach && n >= 4 && closed && tokens[n - 2].kind == 'w' &&
		    StringUtil::CIEquals(text.substr(tokens[n - 2].start, tokens[n - 2].end - tokens[n - 2].start),
		                         "lineage")) {
			auto &literal = tokens[n - 1];
			auto raw = text.substr(literal.start + 1, literal.end - literal.start - 2);
			segment.identity = StringUtil::Replace(raw, "''", "'");
			segment.marked = true;
			segment.text = text.substr(segment_start, tokens[n - 2].start - segment_start);
			segment.original = text.substr(segment_start, end - segment_start);
			found = true;
		} else {
			segment.text = text.substr(segment_start, end - segment_start);
		}
		segments.push_back(std::move(segment));
		tokens.clear();
		segment_start = end + 1;
	};
	idx_t i = 0;
	while (i < text.size()) {
		auto c = text[i];
		if (StringUtil::CharacterIsSpace(c)) {
			i++;
		} else if (c == '-' && i + 1 < text.size() && text[i + 1] == '-') {
			auto eol = text.find('\n', i);
			i = eol == string::npos ? text.size() : eol + 1;
		} else if (c == '/' && i + 1 < text.size() && text[i + 1] == '*') {
			auto close = text.find("*/", i + 2);
			i = close == string::npos ? text.size() : close + 2;
		} else if (c == '\'') {
			auto end = SkipQuoted(text, i, '\'', false);
			tokens.push_back(Token {i, end, 's'});
			i = end;
		} else if (c == '"') {
			auto end = SkipQuoted(text, i, '"', false);
			tokens.push_back(Token {i, end, 'w'});
			i = end;
		} else if ((c == 'e' || c == 'E') && i + 1 < text.size() && text[i + 1] == '\'') {
			auto end = SkipQuoted(text, i + 1, '\'', true); // E'…': backslash escapes, never the marker's
			tokens.push_back(Token {i, end, 'p'});
			i = end;
		} else if (WordStart(c)) {
			auto start = i;
			while (i < text.size() && WordPart(text[i])) {
				i++;
			}
			tokens.push_back(Token {start, i, 'w'});
		} else if (c == ';') {
			close_segment(i);
			i++;
		} else {
			tokens.push_back(Token {i, i + 1, 'p'});
			i++;
		}
	}
	close_segment(text.size());
	return segments;
}

//! The identity one ATTACH statement's text declares ('' = none): what the lineage hook reads back
inline string AttachLineageIdentity(const string &statement_text) {
	if (!MayCarryAttachLineage(statement_text)) {
		return string();
	}
	bool found = false;
	auto segments = SplitAttachLineage(statement_text, found);
	return found && segments.size() == 1 ? segments[0].identity : string();
}

} // namespace acl
} // namespace duckdb
