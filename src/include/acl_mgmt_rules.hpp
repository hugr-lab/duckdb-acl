//===----------------------------------------------------------------------===//
//                         duckdb-acl
//
// acl_mgmt_rules.hpp
//
// Spec 150, stage 3g-3: the management statements a linked module adds (hugr-node's CLUSTER forms), as rules on
// duckdb's grammar. The module registers its rules at load; the management grammar compiles them in beside acl's own,
// so a module's statement is read on duckdb's tokens like any other - its values by acl's shared rules and checked
// against their tokens where the batch is read - and its transform answers the acl_* call it compiles to. Who may run
// that call is the one authorizer's (spec 117): a call the platform's function table does not know is refused.
//
// The shared rules a module may name - stable, acl keeps them: AclQuotedValue (a '…' or a "…"), AclNameValue (a name
// that is a value: quoted either way, or words joined by `.`), AclName (one SQL identifier), AclWordToken (a word as
// written - the run of tokens the tokenizer split at a leading digit, `4GB`), AclDottedToken, AclValue (AclNameValue
// or AclSignedNumber, `-1`, `0.5`), AclComment (`COMMENT '…'`). A module's own rules are named `Acl<Keyword>…`
// (`AclCluster…` for CLUSTER), a form's rule begins with the keyword's literal, and a helper rule of one part is read
// through; a name acl also defines is refused at registration (its rules are compiled then, against acl's).
//
// Built against duckdb's includes and its third_party/utf8proc/include (parse_result.hpp needs it).
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb/common/optional_ptr.hpp"
#include "duckdb/common/types/value.hpp"
#include "duckdb/parser/grammar_change.hpp"
#include "duckdb/parser/peg/transformer/peg_transformer.hpp"

namespace duckdb {
namespace acl {

//! One statement form of a module: the rule such a statement is (one the registration adds, carrying its transform),
//! the words after the keyword it covers (`{"install", "update", "remove"}`), and how to write it - what a statement
//! headed by them that no rule reads is told ("write CLUSTER SET <setting> = <value> [IN GROUP <group>]")
struct MgmtStatementForm {
	string statement;
	vector<string> verbs;
	string usage;
};

//! The statements headed by `keyword` (one word of letters acl and duckdb have no statement for: `cluster`) are
//! management, read by `forms` - each an alternative in the management grammar's choice, ahead of the statements no
//! rule reads - and the rules `changes` adds (new rules only, named `Acl<Keyword>…`, and terminal overrides of them). A
//! statement headed by the keyword whose verb no form names is told `usage`. Registered at load, before the first
//! statement is read: the rules are compiled then, and a registration that does not compile - or comes later - is
//! refused here. Idempotent by keyword; the keyword with other forms, or registered through the older seam too, is
//! refused.
void RegisterMgmtRules(const string &keyword, vector<MgmtStatementForm> forms, vector<GrammarChange> changes,
                       const string &usage);

//! A rule's transform, as acl's own are written: `MgmtStart<Finalize>` where `Finalize` answers `MgmtCall::Result()`
template <arena_ptr<TransformResultValue> (*FINALIZE)(PEGTransformer &, ParseResult &)>
arena_ptr<TransformProcess> MgmtStart(PEGTransformer &transformer, ParseResult &parse_result) {
	return transformer.MakeProcess<FinalizeTransformProcess>(transformer, parse_result, FINALIZE);
}

//! What a module's transform builds: the acl_* call its statement compiles to (`SELECT <function>(<args>)`). Its
//! readers check what they read as acl's rules do - a quoted value is one plain literal, written so - and refuse a part
//! that is not what they read. A value read any other way (the transformer, a parse result's text) is not checked;
//! neither is what `Arg` is handed. A refusal is thrown as a BinderException, in the module's words.
class MgmtCall {
public:
	MgmtCall(PEGTransformer &transformer, string function);
	~MgmtCall();
	//! `AclQuotedValue` or a StringLiteral: one plain quoted literal ('' passes - the function judges it)
	string Quoted(ParseResult &result, const char *what);
	//! `AclNameValue`: a name that is a value - quoted either way, or words joined by `.` (judged whole)
	string NameValue(ParseResult &result, const char *what);
	//! `AclName`: one SQL identifier - a word, or a double-quoted name with `""` for a quote; never empty
	string Name(ParseResult &result, const char *what);
	//! `AclValue`: a name that is a value, or a signed number (`-0.5`)
	string Text(ParseResult &result, const char *what);
	//! `AclWordToken`: a word as written - the run of tokens the tokenizer split at a leading digit (`4GB`)
	static string Word(ParseResult &result);
	//! The word a keyword alternative matched, lower-cased ('' when it matched no keyword)
	static string Keyword(ParseResult &result);
	//! The part a rule holds through its helper rules (an alternative taken, a one-part list, an optional's result)
	static ParseResult &Part(ParseResult &result);
	//! `X?`: its result through its helper rules, or nullptr when absent
	static optional_ptr<ParseResult> Optional(ParseResult &result);
	//! `X*` / `X+` / `X?`: the results in order - none when absent
	static vector<reference<ParseResult>> Each(ParseResult &result);
	void Arg(Value value);
	//! The statement; the call is spent
	arena_ptr<TransformResultValue> Result();

private:
	struct Impl;
	unique_ptr<Impl> impl;
};

} // namespace acl
} // namespace duckdb
