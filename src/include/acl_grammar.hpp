//===----------------------------------------------------------------------===//
// acl_grammar.hpp
//
// Spec 150: our grammar as rules of duckdb's PEG parser. Stage 1, the prototype: the prefix
// `ACL ROLE <value> [TRACE '<id>'] [PARENT '<tp>'] <statement>` as a rule, parsed with a grammar
// the override compiles itself (the connection's grammar extensions, ours behind them). The rules
// are also registered as the grammar extension `acl` - for completion only: the override never
// depends on a connection switching them on, and a connection that does not parses as before.
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb.hpp"
#include "duckdb/parser/parser_options.hpp"
#include "duckdb/parser/sql_statement.hpp"

namespace duckdb {
class GrammarExtension;

namespace acl {

//! What the prefix rule read off one batch
struct PegPrefix {
	string role;
	string correlation_id;
	string traceparent;
	//! where the prefixed statement starts in the text, past the principal and the markers - or, for a prefix
	//! with no statement of its own, where the prefix's part of the text ends
	bool has_statement = false;
	idx_t statement_start = 0;
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

	//! The rules as a grammar extension, registered so a connection may switch them on for completion
	//! (`SET active_grammar_extensions = ['acl']`); the override never depends on it being on
	shared_ptr<GrammarExtension> Extension() const;

private:
	struct Impl;
	unique_ptr<Impl> impl;
};

//! The prototype's switch, `acl_peg_prefix` (GLOBAL, default off)
bool PegPrefixEnabled(const ParserOptions &options);

} // namespace acl
} // namespace duckdb
