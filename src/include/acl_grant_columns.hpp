//===----------------------------------------------------------------------===//
//                         duckdb-acl
//
// acl_grant_columns.hpp
//
// spec 158: what an object grant says of the object's columns - which the role sees (`COLUMNS`: names, every column,
// or every column but some) and what it reads in place of some (`MASK (<column> AS <expr>, …)`) - and how the roles
// of one principal unite: a column is visible when some role's test admits it, unmasked when some role shows it
// without a mask, else masked when every role that shows it masks it alike; two different masks refuse.
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb/common/common.hpp"
#include "duckdb/common/exception/binder_exception.hpp"
#include "duckdb/common/string_util.hpp"

namespace duckdb {
namespace acl {
namespace acl_detail {

//! A column name as the policy compares it: ASCII case folded, as duckdb compares identifiers (spec 116)
inline string FoldColumn(const string &name) {
	string folded = name;
	for (auto &c : folded) {
		if (c >= 'A' && c <= 'Z') {
			c = static_cast<char>(c - 'A' + 'a');
		}
	}
	return folded;
}

//! A grant's `COLUMNS`: a test on a column's name (spec 158)
struct ColumnTest {
	enum class Kind : uint8_t { ALL, ONLY, EXCEPT };
	Kind kind = Kind::ALL;
	//! ONLY: the columns shown; EXCEPT: the columns left out - names as they are, never quoted
	vector<string> names;

	bool All() const {
		return kind == Kind::ALL;
	}
	bool Names(const string &name) const {
		auto folded = FoldColumn(name);
		for (auto &listed : names) {
			if (FoldColumn(listed) == folded) {
				return true;
			}
		}
		return false;
	}
	bool Admits(const string &name) const {
		switch (kind) {
		case Kind::ALL:
			return true;
		case Kind::ONLY:
			return Names(name);
		case Kind::EXCEPT:
			return !Names(name);
		}
		return false;
	}
	bool operator==(const ColumnTest &other) const {
		if (kind != other.kind || names.size() != other.names.size()) {
			return false;
		}
		for (auto &name : names) {
			if (!other.Names(name)) {
				return false;
			}
		}
		return true;
	}

	//! The union of two roles' tests: what either admits
	static ColumnTest Union(const ColumnTest &a, const ColumnTest &b) {
		if (a.All() || b.All()) {
			return ColumnTest();
		}
		ColumnTest out;
		if (a.kind == Kind::ONLY && b.kind == Kind::ONLY) {
			out.kind = Kind::ONLY;
			out.names = a.names;
			for (auto &name : b.names) {
				if (!out.Names(name)) {
					out.names.push_back(name);
				}
			}
			return out;
		}
		// at least one leaves out: what both leave out, less what the other shows
		out.kind = Kind::EXCEPT;
		auto &left = a.kind == Kind::EXCEPT ? a : b;
		auto &right = a.kind == Kind::EXCEPT ? b : a;
		for (auto &name : left.names) {
			if (!right.Admits(name)) {
				out.names.push_back(name);
			}
		}
		if (out.names.empty()) {
			return ColumnTest();
		}
		return out;
	}
};

//! A grant's masks: (column, expression) - the column as it is named, the expression as stored
using GrantMasks = vector<std::pair<string, string>>;

//! The mask `masks` gives `column`, nullptr when none
inline optional_ptr<const string> MaskOf(const GrantMasks &masks, const string &column) {
	auto folded = FoldColumn(column);
	for (auto &mask : masks) {
		if (FoldColumn(mask.first) == folded) {
			return &mask.second;
		}
	}
	return nullptr;
}

//! One role's column policy on one object
struct RoleColumns {
	ColumnTest test;
	GrantMasks masks;
};

//! The roles' union (spec 158): the visible test, and the masks that stand - a column some role shows unmasked reads
//! unmasked; one every role that shows it masks alike reads that mask; two different masks refuse
inline RoleColumns UniteRoleColumns(const vector<RoleColumns> &roles, const string &object) {
	RoleColumns out;
	if (roles.empty()) {
		return out;
	}
	out.test = roles[0].test;
	for (idx_t i = 1; i < roles.size(); i++) {
		out.test = ColumnTest::Union(out.test, roles[i].test);
	}
	vector<string> masked;
	for (auto &role : roles) {
		for (auto &mask : role.masks) {
			bool seen = false;
			for (auto &name : masked) {
				seen = seen || FoldColumn(name) == FoldColumn(mask.first);
			}
			if (!seen) {
				masked.push_back(mask.first);
			}
		}
	}
	for (auto &column : masked) {
		bool plain = false;
		optional_ptr<const string> chosen;
		for (auto &role : roles) {
			if (!role.test.Admits(column)) {
				continue;
			}
			auto mask = MaskOf(role.masks, column);
			if (!mask) {
				plain = true;
				break;
			}
			if (chosen && *chosen != *mask) {
				throw BinderException("acl: the principal's roles mask column \"%s\" of \"%s\" differently (\"%s\" vs "
				                      "\"%s\") - grant the same mask, or drop one of the grants",
				                      column, object, *chosen, *mask);
			}
			chosen = mask;
		}
		if (!plain && chosen) {
			out.masks.emplace_back(column, *chosen);
		}
	}
	return out;
}

} // namespace acl_detail
} // namespace acl
} // namespace duckdb
