#pragma once

// spec 150 stage 4a: what a bare word of the management grammar is - one predicate for every reader of one (the
// rules' matcher, a name offered back to paste, a refusal's words). Header-only: utf8proc is duckdb's own.

#include "duckdb/common/string_util.hpp"
#include "utf8proc.hpp"
#include "utf8proc_wrapper.hpp"

#include <cstdlib>

namespace duckdb {
namespace acl {

//! Why `text` is no bare word - empty when it is one. A bare word is ASCII letters, digits and `_`, and past ASCII
//! the Unicode letters (with their combining marks) and decimal digits (the owner, 2026-11-06: `größe`, `отдел`):
//! - never a character Unicode calls default-ignorable (it shows nothing: U+034F, U+FE0F, the Hangul fillers) nor a
//!   format or control one (U+202E reverses the text around it, U+200D joins invisibly);
//! - a combining mark never starts a word, nor a part of a dotted one (`dot`: a `.` joins parts);
//! - written in Unicode's composed form (NFC): `ö` as one code point, never `o` + U+0308 - two spellings that look
//!   alike would be two names.
//! A quoted name still takes anything. A code point is said as U+XXXX, never as the character.
inline string WhyNoWord(const string &text, bool dot = false) {
	if (text.empty()) {
		return "it is empty";
	}
	auto bytes = reinterpret_cast<const utf8proc_uint8_t *>(text.data());
	bool part_start = true;
	bool ascii = true;
	idx_t at = 0;
	while (at < text.size()) {
		auto c = text[at];
		if (static_cast<unsigned char>(c) < 0x80) {
			if (dot && c == '.') {
				part_start = true;
				at++;
				continue;
			}
			if (!StringUtil::CharacterIsAlpha(c) && !StringUtil::CharacterIsDigit(c) && c != '_') {
				return StringUtil::Format("'%c' is no letter or digit", c);
			}
			part_start = false;
			at++;
			continue;
		}
		ascii = false;
		utf8proc_int32_t codepoint = 0;
		auto length = utf8proc_iterate(bytes + at, utf8proc_ssize_t(text.size() - at), &codepoint);
		if (length <= 0) {
			return "it is no UTF-8";
		}
		auto said = StringUtil::Format("U+%04X", static_cast<uint32_t>(codepoint));
		auto property = utf8proc_get_property(codepoint);
		if (property->ignorable) {
			return said + " is an invisible character";
		}
		switch (utf8proc_category(codepoint)) {
		case UTF8PROC_CATEGORY_LU:
		case UTF8PROC_CATEGORY_LL:
		case UTF8PROC_CATEGORY_LT:
		case UTF8PROC_CATEGORY_LM:
		case UTF8PROC_CATEGORY_LO:
		case UTF8PROC_CATEGORY_ND:
			break;
		case UTF8PROC_CATEGORY_MN:
		case UTF8PROC_CATEGORY_MC:
			if (part_start) {
				return said + " is a combining mark, which cannot start a name";
			}
			break;
		default:
			return said + " is no letter or digit";
		}
		part_start = false;
		at += idx_t(length);
	}
	if (!ascii) {
		auto composed = Utf8Proc::Normalize(text.c_str(), text.size());
		bool nfc = composed && text == composed;
		free(composed);
		if (!nfc) {
			return "it is not written in Unicode's composed form (NFC)";
		}
	}
	return string();
}

inline bool IsWordText(const string &text, bool dot = false) {
	return WhyNoWord(text, dot).empty();
}

} // namespace acl
} // namespace duckdb
