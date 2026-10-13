#include "acl_sql_text.hpp"

#include "duckdb/common/string_util.hpp"

namespace duckdb {
namespace acl {

namespace {

bool QualifierChar(char c) {
	return StringUtil::CharacterIsAlphaNumeric(c) || c == '_' || c == '$';
}

} // namespace

//! spec 118: a view's SQL names `source` as a qualifier - `source.` or `"source".`, any case, word-bounded.
//! Read as text, never bound (binding would load the source's catalog): over-reading blocks the DETACH,
//! and FORCE is the operator's answer.
bool SqlNamesSource(const string &sql, const string &source) {
	auto folded = StringUtil::Lower(sql);
	auto name = StringUtil::Lower(source);
	if (name.empty()) {
		return false;
	}
	if (name.find('"') != string::npos) {
		// a name holding a quote is written quoted, its quote doubled: `"a""b".`
		auto quoted = "\"" + StringUtil::Replace(name, "\"", "\"\"") + "\"";
		for (idx_t at = folded.find(quoted); at != string::npos; at = folded.find(quoted, at + 1)) {
			auto after = at + quoted.size();
			while (after < folded.size() && StringUtil::CharacterIsSpace(folded[after])) {
				after++;
			}
			if ((at == 0 || folded[at - 1] != '.') && after < folded.size() && folded[after] == '.') {
				return true;
			}
		}
		return false;
	}
	for (idx_t at = folded.find(name); at != string::npos; at = folded.find(name, at + 1)) {
		idx_t before = at;
		idx_t after = at + name.size();
		if (before > 0 && folded[before - 1] == '"') {
			if (after >= folded.size() || folded[after] != '"') {
				continue;
			}
			before--;
			after++;
		}
		if (before > 0 && (QualifierChar(folded[before - 1]) || folded[before - 1] == '.')) {
			continue; // part of a longer name, or not the first part
		}
		while (after < folded.size() && StringUtil::CharacterIsSpace(folded[after])) {
			after++;
		}
		if (after < folded.size() && folded[after] == '.') {
			return true;
		}
	}
	return false;
}

} // namespace acl
} // namespace duckdb
