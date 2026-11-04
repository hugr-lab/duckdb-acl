//===----------------------------------------------------------------------===//
//                         duckdb-acl
//
// acl_attach_lineage.hpp
//
// Spec 112 §9: `ATTACH … LINEAGE '<identity>'` - the operator names a source where it attaches it.
// The parser override takes the trailing `LINEAGE '<x>'` off each such statement and compiles it to
// the native ATTACH followed by `acl_lineage_source('<alias>', '<x>')`. This is the text side only:
// the batch's statements and the marker at the end of an ATTACH, read on duckdb's own tokens (spec 150
// 3g-2c: strings, quoted names and comments as duckdb reads them). What the text means is the native parser's.
//===----------------------------------------------------------------------===//

#pragma once

#include "acl_grammar.hpp"
#include "duckdb/common/limits.hpp"
#include "duckdb/common/string_util.hpp"

#include <algorithm>

namespace duckdb {
namespace acl {

//! One statement of a batch: its text (the marker taken off) and the identity it declared ('' = none)
struct AttachLineageSegment {
	string text;
	string original; // as written, the marker included: the ATTACH's own text (its hook reads it back)
	string identity;
	bool marked = false;
};

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
//! whether any statement carried the marker - false leaves the text to the native parser untouched (also a
//! text ending inside a comment, a string or a name: the native parser refuses it)
inline vector<AttachLineageSegment> SplitAttachLineage(const string &text, bool &found) {
	found = false;
	vector<AttachLineageSegment> segments;
	bool open = false;
	auto heads = ReadStatementHeads(text, NumericLimits<idx_t>::Maximum(), &open);
	if (open) {
		return segments;
	}
	for (auto &tokens : heads) {
		AttachLineageSegment segment;
		auto start = tokens.front().offset;
		auto &last = tokens.back();
		auto end = last.offset + last.text.size();
		auto n = tokens.size();
		// `ATTACH … LINEAGE '<x>'`: an ATTACH whose last two tokens are the word and one plain literal
		if (tokens[0].IsWord("attach") && n >= 4 && tokens[n - 2].IsWord("lineage") &&
		    last.kind == HeadToken::Kind::STRING && last.text.size() >= 2) {
			segment.identity = StringUtil::Replace(last.text.substr(1, last.text.size() - 2), "''", "'");
			segment.marked = true;
			segment.text = text.substr(start, tokens[n - 2].offset - start);
			segment.original = text.substr(start, end - start);
			found = true;
		} else {
			segment.text = text.substr(start, end - start);
		}
		segments.push_back(std::move(segment));
	}
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
