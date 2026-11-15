//===----------------------------------------------------------------------===//
//                         duckdb-acl
//
// acl_versions.hpp
//
// spec 167: the versions of a time-travel table (DuckLake, Iceberg) a grant admits - its VERSIONS clause.
//
// A grant states one of `CURRENT` (no AT), `ANY` (every version), `AT (VERSION => n)` / `AT (TIMESTAMP => t)` (that
// snapshot only: a read without AT gets it, any other AT is refused) or `BETWEEN t1 AND t2` (an `AT (TIMESTAMP => t)`
// inside the window; a read without AT reads the window's latest). It is stored as the clause, normalized - every
// value a constant - and read back by duckdb's parser, never ours.
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb/parser/parsed_expression.hpp"
#include "duckdb/parser/tableref/at_clause.hpp"

#include <functional>

namespace duckdb {
namespace acl {

struct VersionLimit {
	enum class Kind : uint8_t { ANY, CURRENT, AT, BETWEEN };
	Kind kind = Kind::ANY;
	//! AT: the snapshot the grant pins
	unique_ptr<AtClause> at;
	//! BETWEEN: the window's bounds, TIMESTAMPTZ constants
	unique_ptr<ParsedExpression> lo;
	unique_ptr<ParsedExpression> hi;

	//! A write reads the current rows: only a grant that admits them writes
	bool AdmitsWrites() const {
		return kind == Kind::ANY || kind == Kind::CURRENT;
	}
};

//! A stored clause ('' = every version) read with duckdb's parser
VersionLimit ReadVersions(const string &stored);

//! The clause an operator wrote (`CURRENT`, `ANY`, `AT (…)`, `BETWEEN … AND …`; '' = not stated) as stored: every value
//! a constant, evaluated by `evaluate` (one SQL expression -> its value as text) to its canonical form. Refused with
//! what to write otherwise.
string NormalizeVersions(const string &written, const std::function<string(const string &)> &evaluate);

//! What a role reads where several roles' grants unite (spec 146's per object union): every version when one of them
//! admits every version, else their one clause; clauses that differ refuse (`differ`), as two masks of one column do
string UniteVersions(const vector<string> &stored, bool &differ);

//! Whether an expression is made of constants and casts only
bool ConstantOnly(const ParsedExpression &expr);

//! Whether an expression holds a `$n` / `?` parameter anywhere
bool HasParameter(const ParsedExpression &expr);

} // namespace acl
} // namespace duckdb
