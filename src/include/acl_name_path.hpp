// A name as a list of identifier parts (spec 116). A virtual catalog, schema, table, view or function -
// and the physical name it points at - may be named the way SQL allows: any case, spaces, a dot or a
// quote inside a part. Every stored name is the CANONICAL KEY of its parts: joined by `.`, a part
// quoted (`"…"`, `""` inside) only when it holds a `.` or a `"` - the exact inverse of duckdb's
// QualifiedName::ParseComponents, so a key built from parts reads back as the same parts. Keys compare
// case-insensitively, as duckdb's catalog does. SQL text (a name the binder reads) is ToSql(), which
// also quotes keywords - never used for keys, since the keyword list changes between versions.
//
// Header-only: the rewriter, the resolver, the writers, the listings and the lineage all read names
// through it, and so does the invariant test.

#pragma once

#include "duckdb/common/exception/binder_exception.hpp"
#include "duckdb/common/sql_identifier.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/parser/qualified_name.hpp"

namespace duckdb {
namespace acl {

class NamePath {
public:
	NamePath() = default;
	explicit NamePath(vector<string> parts_p) : parts(std::move(parts_p)) {
	}

	//! One part as it is written in a key: quoted only when it holds a `.` or a `"`
	static string QuotePart(const string &part) {
		if (part.find('.') == string::npos && part.find('"') == string::npos) {
			return part;
		}
		return "\"" + StringUtil::Replace(part, "\"", "\"\"") + "\"";
	}

	//! A stored key or a name given as text: an unquoted part is anything but `.` and `"`, a quoted one
	//! `"…"` with `""` for a quote; an empty part (`a..b`, a trailing `.`, `""`) is refused
	static bool TryFromKey(const string &key, NamePath &out, string &error) {
		out.parts.clear();
		if (key.empty()) {
			error = "an empty name";
			return false;
		}
		idx_t pos = 0;
		while (true) {
			string part;
			if (pos < key.size() && key[pos] == '"') {
				idx_t i = pos + 1;
				bool closed = false;
				for (; i < key.size(); i++) {
					if (key[i] != '"') {
						part += key[i];
					} else if (i + 1 < key.size() && key[i + 1] == '"') {
						part += '"';
						i++;
					} else {
						closed = true;
						break;
					}
				}
				if (!closed) {
					error = "an unterminated quote in \"" + key + "\"";
					return false;
				}
				pos = i + 1;
				if (pos < key.size() && key[pos] != '.') {
					error = "a character after a quoted part in \"" + key + "\"";
					return false;
				}
			} else {
				for (; pos < key.size() && key[pos] != '.'; pos++) {
					if (key[pos] == '"') {
						error = "a quote inside an unquoted part of \"" + key + "\"";
						return false;
					}
					part += key[pos];
				}
			}
			if (part.empty()) {
				error = "an empty part in \"" + key + "\"";
				return false;
			}
			out.parts.push_back(std::move(part));
			if (pos >= key.size()) {
				return true;
			}
			pos++; // the '.'
			if (pos >= key.size()) {
				error = "an empty part in \"" + key + "\"";
				return false;
			}
		}
	}

	static NamePath FromKey(const string &key, const char *what = "a name") {
		NamePath out;
		string error;
		if (!TryFromKey(key, out, error)) {
			throw BinderException("acl: %s is not a valid name: %s", what, error);
		}
		return out;
	}

	//! The parts of a parsed SQL name (an empty placeholder part is skipped)
	static NamePath FromQualified(const QualifiedName &name) {
		NamePath out;
		for (auto &part : name.Path()) {
			if (!part.empty()) {
				out.parts.push_back(part.GetIdentifierName());
			}
		}
		return out;
	}

	//! The canonical stored key
	string ToKey() const {
		string out;
		for (idx_t i = 0; i < parts.size(); i++) {
			out += (i ? "." : "") + QuotePart(parts[i]);
		}
		return out;
	}
	//! SQL text for the binder: every part as duckdb writes an identifier (quoted when it must be)
	string ToSql() const {
		return ToQualified().ToString();
	}
	QualifiedName ToQualified() const {
		vector<Identifier> path;
		for (auto &part : parts) {
			path.emplace_back(part);
		}
		return QualifiedName::FromPath(std::move(path));
	}
	//! The name as the management grammar reads it (spec 116): a part that is a plain word as it is, any
	//! other part double-quoted - what a repair statement or a message offers to paste
	string ToGrammar() const {
		string out;
		for (idx_t i = 0; i < parts.size(); i++) {
			auto &part = parts[i];
			bool word = !part.empty();
			for (auto c : part) {
				word = word && (StringUtil::CharacterIsAlpha(c) || StringUtil::CharacterIsDigit(c) || c == '_');
			}
			out += (i ? "." : "") + (word ? part : "\"" + StringUtil::Replace(part, "\"", "\"\"") + "\"");
		}
		return out;
	}
	static string KeyToGrammar(const string &key) {
		NamePath path;
		string error;
		return TryFromKey(key, path, error) ? path.ToGrammar() : key;
	}
	//! The key folded for a cache or a map: one entry per name whatever case it was written in
	string Fold() const {
		return StringUtil::Lower(ToKey());
	}

	idx_t Size() const {
		return parts.size();
	}
	bool Empty() const {
		return parts.empty();
	}
	const vector<string> &Parts() const & {
		return parts;
	}
	//! a temporary's parts by value: `for (auto &p : NamePath::FromKey(k).Parts())` must not dangle
	vector<string> Parts() && {
		return std::move(parts);
	}
	const string &Head() const {
		return parts.front();
	}
	const string &Leaf() const {
		return parts.back();
	}
	//! Everything after the first part
	NamePath Rest() const {
		return parts.empty() ? NamePath() : NamePath(vector<string>(parts.begin() + 1, parts.end()));
	}
	//! Everything before the last part
	NamePath Parent() const {
		return parts.empty() ? NamePath() : NamePath(vector<string>(parts.begin(), parts.end() - 1));
	}
	NamePath Child(const string &part) const {
		auto out = *this;
		out.parts.push_back(part);
		return out;
	}
	NamePath Join(const NamePath &tail) const {
		auto out = *this;
		out.parts.insert(out.parts.end(), tail.parts.begin(), tail.parts.end());
		return out;
	}

	//===--------------------------------------------------------------------===//
	// Keys as text: what the resolver and the writers pass around
	//===--------------------------------------------------------------------===//

	//! `a` + `b` as one key: both sides are canonical keys, and canonical parts delimit themselves, so a
	//! join of keys is the key of the joined parts
	static string JoinKeys(const string &prefix, const string &tail) {
		if (prefix.empty()) {
			return tail;
		}
		return tail.empty() ? prefix : prefix + "." + tail;
	}
	//! A key + one raw part
	static string ChildKey(const string &prefix, const string &part) {
		return JoinKeys(prefix, QuotePart(part));
	}
	//! The first part of a key and the rest, both as keys; false (both empty) when the key has one part
	static bool SplitHeadKey(const string &key, string &head, string &rest) {
		NamePath path;
		string error;
		if (!TryFromKey(key, path, error) || path.Size() < 2) {
			head.clear();
			rest.clear();
			return false;
		}
		head = QuotePart(path.Head());
		rest = path.Rest().ToKey();
		return true;
	}
	//! The key of everything before the last part ('' for one part) and the RAW last part
	static bool SplitLeaf(const string &key, string &parent, string &leaf) {
		NamePath path;
		string error;
		if (!TryFromKey(key, path, error)) {
			parent.clear();
			leaf = key;
			return false;
		}
		parent = path.Parent().ToKey();
		leaf = path.Leaf();
		return true;
	}
	static idx_t KeySize(const string &key) {
		NamePath path;
		string error;
		return TryFromKey(key, path, error) ? path.Size() : 0;
	}
	//! Two keys name the same thing
	static bool KeyEquals(const string &a, const string &b) {
		return StringUtil::CIEquals(a, b);
	}
	//! `key` lies strictly under `path` (keys: a part boundary is a `.` outside quotes, so a textual
	//! prefix followed by `.` is a part prefix)
	static bool KeyUnder(const string &key, const string &path) {
		return key.size() > path.size() + 1 && key[path.size()] == '.' &&
		       StringUtil::CIEquals(key.substr(0, path.size()), path);
	}
	//! A stored key (a physical name) as SQL text the binder reads. Text that is no key is refused, never
	//! passed through as SQL (schema v20's migration refuses such a key in the first place)
	static string KeyToSql(const string &key) {
		return FromKey(key, "a stored physical name").ToSql();
	}
	//! A stored key as a parsed name (the binder's form of a physical name)
	static QualifiedName KeyToQualified(const string &key) {
		return FromKey(key, "a stored physical name").ToQualified();
	}
	//! A schema key as a listing shows it (spec 116): one part unquoted (`Raw Data`, `q"uote`) unless it
	//! holds a `.` - then, as a path, its key (`"a.b"`, `a."b.c"`), so a part never reads as two levels
	static string Display(const string &key) {
		NamePath path;
		string error;
		if (!TryFromKey(key, path, error)) {
			return key;
		}
		return path.Size() == 1 && path.Head().find('.') == string::npos ? path.Head() : key;
	}
	//! A one-part key (a catalog, a leaf) as its raw name: `"a.b"` -> `a.b`
	static string Unquote(const string &key) {
		NamePath path;
		string error;
		return TryFromKey(key, path, error) && path.Size() == 1 ? path.Head() : key;
	}
	//! The inverse of Display: a schema as a listing showed it, back to its key
	static string FromDisplay(const string &shown) {
		if (shown.find('"') != string::npos && shown.find('.') == string::npos) {
			return QuotePart(shown); // one part with a quote in it, shown unquoted
		}
		return shown; // a plain part, or a key
	}

private:
	vector<string> parts;
};

//===--------------------------------------------------------------------===//
// SQL fragments over stored keys - so no ad-hoc split or regexp is written anywhere else
//===--------------------------------------------------------------------===//

//! A name folded for comparison: ASCII letters only, as duckdb's catalog (and StringUtil::Lower /
//! CIEquals) folds - SQL's lower() folds Unicode, and two folds would make two answers to "is this the
//! same name" (`Ä` / `ä` are two names, as in duckdb). Byte-for-byte length-preserving.
inline string KeyFoldSql(const string &expr) {
	return "translate(" + expr + ", 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')";
}
//! Two key expressions name the same thing (case-insensitively, as duckdb's catalog compares)
inline string KeyEqSql(const string &a, const string &b) {
	return KeyFoldSql(a) + " = " + KeyFoldSql(b);
}
//! `key` lies strictly under `path` (both expressions; a part boundary is a `.` outside quotes)
inline string KeyPrefixSql(const string &key, const string &path) {
	return KeyFoldSql("substr(" + key + ", 1, length(" + path + ") + 1)") + " = " + KeyFoldSql(path + " || '.'");
}
//! The last part of a key, as written in the key (quoted when it holds `.` or `"`). A quoted part has
//! an even number of quotes and the tail of one cut at an inner `.` an odd one, so the only `.` this
//! anchors at is a part boundary.
inline string KeyLeafSql(const string &key) {
	return "regexp_extract(" + key + ", '(?:^|[.])(\"(?:[^\"]|\"\")*\"|[^.\"]*)$', 1)";
}
//! Everything before the last part ('' for a one-part key)
inline string KeyParentSql(const string &key) {
	auto leaf = KeyLeafSql(key);
	return "(CASE WHEN length(" + leaf + ") >= length(" + key + ") THEN '' ELSE substr(" + key + ", 1, length(" + key +
	       ") - length(" + leaf + ") - 1) END)";
}
//! Whether a key has more than one part
inline string KeyNestedSql(const string &key) {
	return "(length(" + KeyLeafSql(key) + ") < length(" + key + "))";
}
//! One part of a key as its raw name: `"a.b"` -> `a.b`, `""""` -> `"`
inline string KeyUnquoteSql(const string &part) {
	return "(CASE WHEN starts_with(" + part + ", '\"') THEN replace(substr(" + part + ", 2, length(" + part +
	       ") - 2), '\"\"', '\"') ELSE " + part + " END)";
}
//! A schema key as a listing shows it (NamePath::Display): one part unquoted unless it holds a `.`
inline string KeyDisplaySql(const string &key) {
	return "(CASE WHEN " + KeyNestedSql(key) + " OR contains(" + KeyUnquoteSql(key) + ", '.') THEN " + key + " ELSE " +
	       KeyUnquoteSql(key) + " END)";
}
//! The inverse (NamePath::FromDisplay): a shown schema back to its key
inline string KeyFromDisplaySql(const string &shown) {
	return "(CASE WHEN contains(" + shown + ", '\"') AND NOT contains(" + shown + ", '.') THEN '\"' || replace(" +
	       shown + ", '\"', '\"\"') || '\"' ELSE " + shown + " END)";
}
//! The parts of a key as written in it (quoted where a part holds `.` or `"`), in order: a list
inline string KeyTokensSql(const string &key) {
	return "regexp_extract_all(" + key + ", '\"(?:[^\"]|\"\")*\"|[^.\"]+')";
}
//! The raw parts of a key, in order: a list (`phys."Raw Data".t` -> [phys, Raw Data, t])
inline string KeyPartsSql(const string &key) {
	return "list_transform(" + KeyTokensSql(key) + ", lambda __acl_part: " + KeyUnquoteSql("__acl_part") + ")";
}
//! The canonical key of one raw part (NamePath::QuotePart)
inline string KeyQuotePartSql(const string &part) {
	return "(CASE WHEN contains(" + part + ", '.') OR contains(" + part + ", '\"') THEN '\"' || replace(" + part +
	       ", '\"', '\"\"') || '\"' ELSE " + part + " END)";
}

} // namespace acl
} // namespace duckdb
