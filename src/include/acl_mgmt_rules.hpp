//===----------------------------------------------------------------------===//
//                         duckdb-acl
//
// acl_mgmt_rules.hpp
//
// Spec 150, stage 3g-3: the management statements a linked module adds (hugr-node's CLUSTER forms), as rules on
// duckdb's grammar. The module registers its rules at load; the management grammar compiles them in beside acl's own,
// so a module's statement is read on duckdb's tokens like any other - its values by acl's shared rules
// (AclQuotedValue, AclNameValue, AclWordToken, ...) and checked against their tokens where the batch is read - and
// its transform answers the acl_* call it compiles to. Who may run that call is the one authorizer's (spec 117).
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb/common/types/value.hpp"
#include "duckdb/parser/grammar_change.hpp"
#include "duckdb/parser/peg/transformer/parse_result.hpp"
#include "duckdb/parser/peg/transformer/peg_transformer.hpp"

namespace duckdb {
namespace acl {

//! The statements headed by `keyword` (a word duckdb has no statement for: `CLUSTER`) are management. `statement` is
//! the rule such a statement is - its alternative in the management grammar's choice, ahead of the statements no rule
//! reads - and `changes` its rules (the shared ones it names are acl's; a rule's name starts with `Acl`, so a helper
//! rule of one part is read through, `MgmtCall::Part`). A statement headed by the keyword that the
//! rules do not read is refused with `usage` ("ACL CLUSTER expects …"). Registered at load, before the first statement
//! is read (the grammar is compiled then); idempotent by keyword.
void RegisterMgmtRules(const string &keyword, const string &statement, vector<GrammarChange> changes,
                       const string &usage);

//! A rule's transform, as acl's own are written: `MgmtStart<Finalize>` where `Finalize` answers `MgmtCall::Result()`
template <arena_ptr<TransformResultValue> (*FINALIZE)(PEGTransformer &, ParseResult &)>
arena_ptr<TransformProcess> MgmtStart(PEGTransformer &transformer, ParseResult &parse_result) {
	return transformer.MakeProcess<FinalizeTransformProcess>(transformer, parse_result, FINALIZE);
}

//! What a module's transform builds: the acl_* call its statement compiles to (`SELECT <function>(<args>)`), its
//! values read as acl's rules read theirs
class MgmtCall {
public:
	MgmtCall(PEGTransformer &transformer, string function);
	~MgmtCall();
	//! `AclQuotedValue` or a StringLiteral: one plain quoted literal ('' passes - the function judges it)
	string Quoted(ParseResult &result, const char *what);
	//! `AclNameValue`: a name that is a value - quoted either way, or words joined by `.` (judged whole)
	string NameValue(ParseResult &result, const char *what);
	//! `AclWordToken`: a word as written - the run of tokens the tokenizer split at a leading digit (`4GB`)
	static string Word(ParseResult &result);
	//! The word a keyword alternative matched, lower-cased ('' when it matched no keyword)
	static string Keyword(ParseResult &result);
	//! The part a rule holds through its helper rules (an alternative taken, a one-part list)
	static ParseResult &Part(ParseResult &result);
	void Arg(Value value);
	//! The statement; the call is spent
	arena_ptr<TransformResultValue> Result();

private:
	struct Impl;
	unique_ptr<Impl> impl;
};

} // namespace acl
} // namespace duckdb
