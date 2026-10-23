//===----------------------------------------------------------------------===//
// acl_grammar.hpp
//
// Spec 150: our grammar as rules of duckdb's PEG parser. Stage 1, the prototype: the prefix
// `ACL ROLE <value> [TRACE '<id>'] [PARENT '<tp>'] <statement>` as a rule, parsed with a grammar
// compiled inside the override (the connection's grammar extensions plus ours) - never registered,
// so no connection can switch it on and a bare statement parses as before.
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb.hpp"
#include "duckdb/parser/parser_options.hpp"
#include "duckdb/parser/sql_statement.hpp"

namespace duckdb {
namespace acl {

//! What the prefix rule read off one batch
struct PegPrefix {
	string role;
	string correlation_id;
	string traceparent;
	//! the batch's statements, the first one the prefixed statement itself
	vector<unique_ptr<SQLStatement>> statements;
};

//! The grammars the override compiles, one per set of the caller's grammar extensions
class AclGrammarCache {
public:
	AclGrammarCache();
	~AclGrammarCache();

	//! Parses `query` as one prefixed batch. False when the connection parses with a grammar of its
	//! own choosing (CONNECT-ed, a dialect) - the prototype leaves those to the scanner. Throws a
	//! ParserException for a text the rule does not read.
	bool ParsePrefixed(const string &query, const ParserOptions &options, PegPrefix &out);

private:
	struct Impl;
	unique_ptr<Impl> impl;
};

//! The prototype's switch, `acl_peg_prefix` (GLOBAL, default off)
bool PegPrefixEnabled(const ParserOptions &options);

} // namespace acl
} // namespace duckdb
