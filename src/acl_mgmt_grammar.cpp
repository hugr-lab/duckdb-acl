// Spec 150, stage 3: the management statements as rules of duckdb's PEG parser. A management batch (the rest after
// `ACL <prefix> ACL`, or after `ACL ADMIN`) is parsed with a grammar whose Statement is ours: each family that moved
// to rules compiles to the acl_* call it always compiled to, and a statement no rule reads yet goes, as its own text,
// to the management compiler (acl_admin_sql.cpp) - one family moves per PR. Never registered: a connection cannot
// switch it on.

#include "acl_grammar.hpp"
#include "acl_grammar_util.hpp"

#include "duckdb/common/types/value.hpp"
#include "duckdb/parser/grammar_change.hpp"
#include "duckdb/parser/grammar_extension.hpp"
#include "duckdb/parser/parser.hpp"
#include "duckdb/parser/parser_extension.hpp"
#include "duckdb/parser/peg/compiled_grammar.hpp"
#include "duckdb/parser/peg/matcher.hpp"
#include "duckdb/parser/peg/passthrough_dialect.hpp"
#include "duckdb/parser/peg/tokenizer/parser_tokenizer.hpp"
#include "duckdb/parser/statement/extension_statement.hpp"

namespace duckdb {
namespace acl {
namespace {

using grammar::KeywordOf;
using grammar::Start;
using grammar::Strip;
using grammar::TokenIndexAt;
using grammar::ValueOf;
using grammar::WrittenPlainly;

//! A value a rule read that must have been written as one plain quoted literal (checked against the tokens)
struct QuotedValue {
	optional_idx offset;
	string value;
	string what;
};

//! What a management rule yields: the call it compiles to, or - a statement no rule reads yet - its span
struct MgmtParseData : ParserExtensionParseData {
	bool legacy = false;
	idx_t start = 0;
	idx_t end = 0;
	string function;
	vector<Value> args;
	bool current_session = false;
	vector<QuotedValue> quoted;
	//! words that must be written bare (a level is a word, never a quoted name)
	vector<QuotedValue> bare;
	//! arguments written as a parenthesised list: the argument's index and the list's span, inside the parentheses
	struct Span {
		idx_t arg;
		idx_t start;
		idx_t end;
	};
	vector<Span> claims_lists;

	unique_ptr<ParserExtensionParseData> Copy() const override {
		return make_uniq<MgmtParseData>(*this);
	}
	string ToString() const override {
		return legacy ? "acl management statement" : function;
	}
};

ParserExtensionPlanResult RefuseMgmtPlan(ParserExtensionInfo *, ClientContext &, unique_ptr<ParserExtensionParseData>) {
	throw BinderException("acl: a management statement is compiled only through the acl override (spec 150)");
}

arena_ptr<TransformResultValue> MgmtResult(PEGTransformer &transformer, unique_ptr<MgmtParseData> data) {
	ParserExtension extension;
	extension.plan_function = RefuseMgmtPlan;
	unique_ptr<SQLStatement> result = make_uniq<ExtensionStatement>(std::move(extension), std::move(data));
	return transformer.MakeResult<unique_ptr<SQLStatement>>(std::move(result));
}

unique_ptr<MgmtParseData> Call(string function) {
	auto data = make_uniq<MgmtParseData>();
	data->function = std::move(function);
	return data;
}

//! A quoted value of the rule's part `index`, kept for the check against its token
string Quoted(PEGTransformer &transformer, ListParseResult &list, idx_t index, const char *what, MgmtParseData &data) {
	QuotedValue entry;
	entry.value = ValueOf(transformer, list.GetChild(index), entry.offset);
	entry.what = what;
	data.quoted.push_back(entry);
	return entry.value;
}

//! `AclLevelWord <- 'ON' / 'ALL' / 'OFF' / 'DEFAULT' / Identifier`, lower-cased - written bare
string LevelWord(PEGTransformer &transformer, ParseResult &result, const char *what, MgmtParseData &data) {
	auto &base = Strip(result);
	auto keyword = KeywordOf(base);
	if (!keyword.empty()) {
		return keyword;
	}
	QuotedValue entry;
	entry.offset = base.offset;
	entry.what = what;
	data.bare.push_back(entry);
	return StringUtil::Lower(transformer.Transform<string>(base));
}

// --- the values a management statement holds ---------------------------------------------------------------------

//! One token of a kind the management compiler's scanner read: a word (letters, digits, `_` - a keyword too), a
//! double-quoted name, either - or, inside a parenthesised list, any token but a parenthesis
class AclTokenMatcher final : public AtomicMatcher {
public:
	enum class Kind : uint8_t { WORD, QUOTED_NAME, NAME, LIST_ITEM };

	explicit AclTokenMatcher(Kind kind_p) : AtomicMatcher(MatcherType::CUSTOM), kind(kind_p) {
	}

	MatcherResult MatchAtomic(MatchState &state) const override {
		auto current = state.token_iterator.Current();
		if (!current || !Accepts(*current)) {
			return MatcherResult::Failure();
		}
		auto text = current->text;
		auto offset = current->offset;
		auto length = current->length;
		state.token_iterator.Advance();
		state.UpdateMaxTokenIndex();
		return state.AllocateParseResult<TokenParseResult>(std::move(text), offset, length);
	}

	SuggestionType AddSuggestionInternal(MatchState &state) const override {
		return SuggestionType::MANDATORY; // a name: nothing to offer
	}

	string ToString() const override {
		return "AclToken";
	}

private:
	static bool IsWord(const string &text) {
		if (text.empty()) {
			return false;
		}
		for (auto c : text) {
			if (!StringUtil::CharacterIsAlpha(c) && !StringUtil::CharacterIsDigit(c) && c != '_') {
				return false;
			}
		}
		return true;
	}

	bool Accepts(const MatcherToken &token) const {
		if (token.type == TokenType::TERMINATOR || token.type == TokenType::END_OF_INPUT ||
		    token.type == TokenType::END_OF_INPUT_AUTOCOMPLETE) {
			return false;
		}
		bool quoted_name = !token.text.empty() && token.text[0] == '"';
		switch (kind) {
		case Kind::WORD:
			return token.type != TokenType::STRING_LITERAL && IsWord(token.text);
		case Kind::QUOTED_NAME:
			return quoted_name;
		case Kind::NAME:
			return quoted_name || (token.type != TokenType::STRING_LITERAL && IsWord(token.text));
		case Kind::LIST_ITEM:
			return token.text != "(" && token.text != ")";
		}
		return false;
	}

	Kind kind;
};

//! A token's text under a rule part (our token rules have no transform: the token is read here)
const TokenParseResult &TokenOf(ParseResult &result) {
	reference<ParseResult> node = result;
	while (node.get().type != ParseResultType::TOKEN) {
		if (node.get().type == ParseResultType::CHOICE) {
			node = node.get().Cast<ChoiceParseResult>().GetResult();
		} else if (node.get().type == ParseResultType::LIST &&
		           node.get().Cast<ListParseResult>().GetChildren().size() == 1) {
			node = node.get().Cast<ListParseResult>().GetChild(0);
		} else {
			throw InternalException("acl admin: a name's token is not where its rule says");
		}
	}
	return node.get().Cast<TokenParseResult>();
}

//! A double-quoted name's text, `""` a quote - what the compiler's scanner took
string UnquoteName(const string &text) {
	return StringUtil::Replace(text.substr(1, text.size() - 2), "\"\"", "\"");
}

//! `AclName <- AclNameToken`: one SQL identifier as the compiler's `Ident` read it - a word, or a double-quoted
//! name with `""` for a quote; never empty
string NameOf(ParseResult &result, const char *what) {
	auto &token = TokenOf(result);
	if (token.text.empty() || token.text[0] != '"') {
		return token.text;
	}
	auto name = UnquoteName(token.text);
	if (name.empty()) {
		throw BinderException("acl admin: an empty quoted identifier - %s cannot be empty", what);
	}
	return name;
}

//! `AclNameValue <- AclQuotedValue / AclDottedWords`: a name that is a value (spec 116 §3) as `NameValue` read it -
//! quoted either way, as written, or words joined by `.`
string NameValueOf(PEGTransformer &transformer, ParseResult &result, const char *what, MgmtParseData &data) {
	auto &node = Strip(result);
	if (node.Name() == "AclDottedWords") {
		auto &list = node.Cast<ListParseResult>();
		string value = TokenOf(list.GetChild(0)).text;
		vector<reference<ParseResult>> parts;
		grammar::Collect(list.GetChild(1), parts);
		for (auto &part : parts) {
			// AclDottedPart <- '.' AclWordToken
			value += "." + TokenOf(part.get().Cast<ListParseResult>().GetChild(1)).text;
		}
		return value;
	}
	QuotedValue entry;
	entry.value = ValueOf(transformer, node, entry.offset);
	entry.what = what;
	data.quoted.push_back(entry);
	return entry.value;
}

//! `AclClaims <- AclParenList / AclQuotedValue` into argument `arg`: a list keeps its span for the compiler's reader
void ClaimsInto(PEGTransformer &transformer, ParseResult &result, idx_t arg, MgmtParseData &data) {
	auto &node = Strip(result);
	if (node.Name() == "AclParenList") {
		// AclParenList <- '(' AclListItem* ')': the text between the parentheses
		auto &list = node.Cast<ListParseResult>();
		auto &open = list.GetChild(0);
		auto &close = list.GetChild(list.GetChildren().size() - 1);
		if (!open.offset.IsValid() || !close.offset.IsValid()) {
			throw ParserException("acl admin: a list has no position");
		}
		data.claims_lists.push_back(MgmtParseData::Span {arg, open.offset.GetIndex() + 1, close.offset.GetIndex()});
		data.args[arg] = Value(string());
		return;
	}
	QuotedValue entry;
	entry.value = ValueOf(transformer, node, entry.offset);
	entry.what = "claims list";
	data.quoted.push_back(entry);
	data.args[arg] = Value(entry.value);
}

// --- the operations of a node (spec 118) ----------------------------------------------------------------------------

// AclKillSession <- 'KILL' 'SESSION' AclQuotedValue - the id is acl_sessions()' / platform.sessions', never a handle
arena_ptr<TransformResultValue> FinalizeKill(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto data = Call("acl_session_kill");
	data->args.emplace_back(Quoted(transformer, list, 2, "a session id", *data));
	return MgmtResult(transformer, std::move(data));
}

// AclSessionAuditLevel <- 'SET' 'SESSION' AclQuotedValue 'AUDIT' 'LEVEL' AclLevelWord (spec 118 over spec 069)
arena_ptr<TransformResultValue> FinalizeAuditLevel(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto data = Call("acl_session_audit_level");
	data->args.emplace_back(Quoted(transformer, list, 2, "a session id", *data));
	auto level = LevelWord(transformer, list.GetChild(5), "an audit level", *data);
	data->args.emplace_back(level == "default" ? string() : level);
	return MgmtResult(transformer, std::move(data));
}

// AclProfileSession <- 'PROFILE' 'SESSION' AclSessionRef AclLevelWord (spec 074 slice 3): the operator's profile level
// on a session - the caller's own (CURRENT) or another open one by its ops id; OFF clears it
arena_ptr<TransformResultValue> FinalizeProfile(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto data = Call("acl_session_profile");
	auto &session = Strip(list.GetChild(2));
	if (KeywordOf(session) == "current") {
		data->current_session = true;
		data->args.emplace_back(string());
	} else {
		data->args.emplace_back(Quoted(transformer, list, 2, "a session id", *data));
	}
	auto word = LevelWord(transformer, list.GetChild(3), "a profile level", *data);
	string level;
	if (word == "on" || word == "all") {
		level = "all";
	} else if (word == "sampled") {
		level = "sampled";
	} else if (word != "off") {
		throw BinderException("acl admin: PROFILE SESSION expects ON, ALL, SAMPLED or OFF, not \"%s\"", word);
	}
	data->args.emplace_back(level);
	return MgmtResult(transformer, std::move(data));
}

// AclNodeOperation <- AclNodeVerb 'NODE' - DRAIN NODE / RESUME NODE (spec 118 over spec 066): this node
arena_ptr<TransformResultValue> FinalizeNode(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	return MgmtResult(transformer, Call(KeywordOf(list.GetChild(0)) == "drain" ? "acl_drain" : "acl_resume"));
}

// AclMigrateCatalog <- 'MIGRATE' 'POLICY' 'CATALOG' Identifier AclSchemaPart? (spec 118 over spec 094)
arena_ptr<TransformResultValue> FinalizeMigrate(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto data = Call("acl_migrate_catalog");
	data->args.emplace_back(transformer.Transform<string>(Strip(list.GetChild(3))));
	auto &schema = list.Child<OptionalParseResult>(4);
	if (schema.HasResult()) {
		// AclSchemaPart <- '.' Identifier
		data->args.emplace_back(
		    transformer.Transform<string>(Strip(Strip(schema.GetResult()).Cast<ListParseResult>().GetChild(1))));
	}
	return MgmtResult(transformer, std::move(data));
}

// --- roles, administration, mappings, view-as (specs 009, 095, 117, 120) ---------------------------------------------

//! The keyword a rule's optional part holds, '' when absent
string OptionalKeyword(ListParseResult &list, idx_t index) {
	auto &part = list.Child<OptionalParseResult>(index);
	return part.HasResult() ? KeywordOf(part.GetResult()) : string();
}

// AclCreateRole <- 'CREATE' AclOrReplace? 'ROLE' AclIfNotExists? AclName AclRoleClaims?
arena_ptr<TransformResultValue> FinalizeCreateRole(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto data = Call("acl_define_role");
	string mode = OptionalKeyword(list, 1) == "or" ? "replace" : "create";
	if (OptionalKeyword(list, 3) == "if" && mode == "create") {
		mode = "skip";
	}
	data->args.emplace_back(NameOf(list.GetChild(4), "a role name"));
	data->args.emplace_back(string());
	auto &claims = list.Child<OptionalParseResult>(5);
	if (claims.HasResult()) {
		// AclRoleClaims <- 'CLAIMS' AclClaims
		ClaimsInto(transformer, Strip(claims.GetResult()).Cast<ListParseResult>().GetChild(1), 1, *data);
	}
	data->args.emplace_back(mode);
	return MgmtResult(transformer, std::move(data));
}

// AclAlterRoleComment <- 'ALTER' 'ROLE' AclName 'SET' 'COMMENT' AclQuotedValue (spec 120)
arena_ptr<TransformResultValue> FinalizeAlterRoleComment(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto data = Call("acl_comment_role");
	data->args.emplace_back(NameOf(list.GetChild(2), "a role name"));
	data->args.emplace_back(Quoted(transformer, list, 5, "comment", *data));
	return MgmtResult(transformer, std::move(data));
}

// AclAlterRoleClaims <- 'ALTER' 'ROLE' AclName 'SET' 'CLAIMS' AclClaims
arena_ptr<TransformResultValue> FinalizeAlterRoleClaims(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto data = Call("acl_alter_role");
	data->args.emplace_back(NameOf(list.GetChild(2), "a role name"));
	data->args.emplace_back(string());
	ClaimsInto(transformer, list.GetChild(5), 1, *data);
	return MgmtResult(transformer, std::move(data));
}

// AclDropRole <- 'DROP' 'ROLE' AclIfExists? AclName - `IF EXISTS` says nothing-to-drop is not an error (spec 010)
arena_ptr<TransformResultValue> FinalizeDropRole(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto data = Call("acl_drop_role");
	data->args.emplace_back(NameOf(list.GetChild(3), "a role name"));
	data->args.emplace_back(OptionalKeyword(list, 2) == "if" ? "skip" : "");
	return MgmtResult(transformer, std::move(data));
}

// AclGrantAdmin <- 'GRANT' 'ADMIN' AclWordToken 'TO' 'ROLE' AclName - the GLOBAL scope (a catalog's manage is a
// catalog grant's capability)
arena_ptr<TransformResultValue> FinalizeGrantAdmin(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto data = Call("acl_grant_admin");
	data->args.emplace_back(NameOf(list.GetChild(5), "a role name"));
	data->args.emplace_back(TokenOf(list.GetChild(2)).text);
	return MgmtResult(transformer, std::move(data));
}

// AclRevokeAdmin <- 'REVOKE' 'ADMIN' 'FROM' 'ROLE' AclName: every administration of the role
arena_ptr<TransformResultValue> FinalizeRevokeAdmin(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto data = Call("acl_revoke_admin");
	data->args.emplace_back(NameOf(list.GetChild(4), "a role name"));
	return MgmtResult(transformer, std::move(data));
}

// AclRevokeAdminScope <- 'REVOKE' 'ADMIN' AclWordToken 'FROM' 'ROLE' AclName: one bundle (spec 117)
arena_ptr<TransformResultValue> FinalizeRevokeAdminScope(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto data = Call("acl_revoke_admin");
	data->args.emplace_back(NameOf(list.GetChild(5), "a role name"));
	data->args.emplace_back(TokenOf(list.GetChild(2)).text);
	return MgmtResult(transformer, std::move(data));
}

//! AclMapping <- AclMapKind AclQuotedValue 'FROM' AclMapScope AclNameValue 'TO' 'ROLE' AclName (spec 095)
void MappingInto(PEGTransformer &transformer, ParseResult &result, MgmtParseData &data) {
	auto &list = Strip(result).Cast<ListParseResult>();
	auto is_group = KeywordOf(list.GetChild(0)) == "group";
	auto external = Quoted(transformer, list, 1, "external value", data);
	auto kind = KeywordOf(list.GetChild(3));
	auto scope =
	    NameValueOf(transformer, list.GetChild(4), kind == "client" ? "a client name" : "an issuer name", data);
	auto role = NameOf(list.GetChild(7), "a role name");
	data.args = {Value(kind), Value(scope), Value(is_group ? "group" : "claim-value"), Value(external), Value(role)};
}

// AclMapRole <- 'MAP' AclMapping
arena_ptr<TransformResultValue> FinalizeMapRole(PEGTransformer &transformer, ParseResult &parse_result) {
	auto data = Call("acl_map_role");
	MappingInto(transformer, parse_result.Cast<ListParseResult>().GetChild(1), *data);
	return MgmtResult(transformer, std::move(data));
}

// AclDropMap <- 'DROP' 'MAP' AclMapping
arena_ptr<TransformResultValue> FinalizeDropMap(PEGTransformer &transformer, ParseResult &parse_result) {
	auto data = Call("acl_drop_role_mapping");
	MappingInto(transformer, parse_result.Cast<ListParseResult>().GetChild(2), *data);
	return MgmtResult(transformer, std::move(data));
}

// AclViewAs <- 'SET' 'SESSION' 'VIEW' 'AS' 'ROLE' AclNameValue (spec 120.3): this session, as role r, metadata only
arena_ptr<TransformResultValue> FinalizeViewAs(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto data = Call("acl_session_view_as");
	data->args.emplace_back(NameValueOf(transformer, list.GetChild(5), "a role", *data));
	return MgmtResult(transformer, std::move(data));
}

// AclResetViewAs <- 'RESET' 'SESSION' 'VIEW' 'AS': back to the session's own principal
arena_ptr<TransformResultValue> FinalizeResetViewAs(PEGTransformer &transformer, ParseResult &parse_result) {
	auto data = Call("acl_session_view_as");
	data->args.emplace_back(string());
	return MgmtResult(transformer, std::move(data));
}

// --- a statement no rule reads yet ------------------------------------------------------------------------------

// AclMgmtLegacy <- AclTailToken+ : its span, for the management compiler
arena_ptr<TransformResultValue> FinalizeLegacy(PEGTransformer &transformer, ParseResult &parse_result) {
	auto data = make_uniq<MgmtParseData>();
	data->legacy = true;
	vector<reference<ParseResult>> parts;
	auto &list = parse_result.Cast<ListParseResult>();
	grammar::Collect(list.GetChild(0), parts);
	if (parts.empty() || !parts.front().get().offset.IsValid() || !parts.back().get().offset.IsValid() ||
	    !parts.back().get().length.IsValid()) {
		throw ParserException("acl admin: a management statement has no position");
	}
	data->start = parts.front().get().offset.GetIndex();
	data->end = parts.back().get().offset.GetIndex() + parts.back().get().length.GetIndex();
	return MgmtResult(transformer, std::move(data));
}

// Statement <- AclMgmtStatement: the alternative taken, transformed by its own rule
arena_ptr<TransformResultValue> FinalizeStatement(PEGTransformer &transformer, ParseResult &parse_result) {
	// through Statement's one part and AclMgmtStatement's choice - never into the rule taken, which has its transform
	reference<ParseResult> node = parse_result;
	while (true) {
		auto &current = node.get();
		if (current.type == ParseResultType::CHOICE) {
			node = current.Cast<ChoiceParseResult>().GetResult();
			continue;
		}
		if (current.type == ParseResultType::LIST &&
		    (current.Name() == "Statement" || current.Name() == "AclMgmtStatement") &&
		    current.Cast<ListParseResult>().GetChildren().size() == 1) {
			node = current.Cast<ListParseResult>().GetChild(0);
			continue;
		}
		break;
	}
	return transformer.MakeResult<unique_ptr<SQLStatement>>(
	    transformer.Transform<unique_ptr<SQLStatement>>(node.get()));
}

class AclMgmtGrammar final : public GrammarExtension {
public:
	AclMgmtGrammar() : GrammarExtension("acl_management", "acl: the management statements (spec 150)") {
	}

	vector<GrammarChange> GetChanges() const override {
		vector<GrammarChange> changes;
		// a quoted value is '…' or "…" (checked against its token: one literal written plainly)
		changes.push_back(GrammarChange::AddRule("AclQuotedValue <- StringLiteral / Identifier"));
		changes.push_back(GrammarChange::AddRule("AclLevelWord <- 'ON' / 'ALL' / 'OFF' / 'DEFAULT' / Identifier"));
		// the operations of a node
		changes.push_back(
		    GrammarChange::AddRule("AclKillSession <- 'KILL' 'SESSION' AclQuotedValue", Start<FinalizeKill>));
		changes.push_back(GrammarChange::AddRule(
		    "AclSessionAuditLevel <- 'SET' 'SESSION' AclQuotedValue 'AUDIT' 'LEVEL' AclLevelWord",
		    Start<FinalizeAuditLevel>));
		changes.push_back(GrammarChange::AddRule("AclSessionRef <- 'CURRENT' / AclQuotedValue"));
		changes.push_back(GrammarChange::AddRule("AclProfileSession <- 'PROFILE' 'SESSION' AclSessionRef AclLevelWord",
		                                         Start<FinalizeProfile>));
		changes.push_back(GrammarChange::AddRule("AclNodeVerb <- 'DRAIN' / 'RESUME'"));
		changes.push_back(GrammarChange::AddRule("AclNodeOperation <- AclNodeVerb 'NODE'", Start<FinalizeNode>));
		changes.push_back(GrammarChange::AddRule("AclSchemaPart <- '.' Identifier"));
		changes.push_back(GrammarChange::AddRule(
		    "AclMigrateCatalog <- 'MIGRATE' 'POLICY' 'CATALOG' Identifier AclSchemaPart?", Start<FinalizeMigrate>));
		// the values the compiler's scanner read, on duckdb's tokens: a word, a double-quoted name, either; a list's
		// items
		changes.push_back(GrammarChange::AddRule("AclWordToken <- Identifier"));
		changes.push_back(
		    GrammarChange::AddTerminalRuleOverride("AclWordToken", [](const PEGKeywordHelper &) -> unique_ptr<Matcher> {
			    return make_uniq<AclTokenMatcher>(AclTokenMatcher::Kind::WORD);
		    }));
		changes.push_back(GrammarChange::AddRule("AclNameToken <- Identifier"));
		changes.push_back(
		    GrammarChange::AddTerminalRuleOverride("AclNameToken", [](const PEGKeywordHelper &) -> unique_ptr<Matcher> {
			    return make_uniq<AclTokenMatcher>(AclTokenMatcher::Kind::NAME);
		    }));
		changes.push_back(GrammarChange::AddRule("AclListToken <- Identifier"));
		changes.push_back(
		    GrammarChange::AddTerminalRuleOverride("AclListToken", [](const PEGKeywordHelper &) -> unique_ptr<Matcher> {
			    return make_uniq<AclTokenMatcher>(AclTokenMatcher::Kind::LIST_ITEM);
		    }));
		changes.push_back(GrammarChange::AddRule("AclName <- AclNameToken"));
		changes.push_back(GrammarChange::AddRule("AclDottedPart <- '.' AclWordToken"));
		changes.push_back(GrammarChange::AddRule("AclDottedWords <- AclWordToken AclDottedPart*"));
		changes.push_back(GrammarChange::AddRule("AclNameValue <- StringLiteral / AclDottedWords / Identifier"));
		changes.push_back(GrammarChange::AddRule("AclListItem <- AclParenList / AclListToken"));
		changes.push_back(GrammarChange::AddRule("AclParenList <- '(' AclListItem* ')'"));
		changes.push_back(GrammarChange::AddRule("AclClaims <- AclParenList / AclQuotedValue"));
		changes.push_back(GrammarChange::AddRule("AclOrReplace <- 'OR' 'REPLACE'"));
		changes.push_back(GrammarChange::AddRule("AclIfNotExists <- 'IF' 'NOT' 'EXISTS'"));
		changes.push_back(GrammarChange::AddRule("AclIfExists <- 'IF' 'EXISTS'"));
		// roles, administration, mappings, view-as
		changes.push_back(GrammarChange::AddRule("AclRoleClaims <- 'CLAIMS' AclClaims"));
		changes.push_back(GrammarChange::AddRule(
		    "AclCreateRole <- 'CREATE' AclOrReplace? 'ROLE' AclIfNotExists? AclName AclRoleClaims?",
		    Start<FinalizeCreateRole>));
		changes.push_back(
		    GrammarChange::AddRule("AclAlterRoleComment <- 'ALTER' 'ROLE' AclName 'SET' 'COMMENT' AclQuotedValue",
		                           Start<FinalizeAlterRoleComment>));
		changes.push_back(GrammarChange::AddRule(
		    "AclAlterRoleClaims <- 'ALTER' 'ROLE' AclName 'SET' 'CLAIMS' AclClaims", Start<FinalizeAlterRoleClaims>));
		changes.push_back(
		    GrammarChange::AddRule("AclDropRole <- 'DROP' 'ROLE' AclIfExists? AclName", Start<FinalizeDropRole>));
		changes.push_back(GrammarChange::AddRule("AclGrantAdmin <- 'GRANT' 'ADMIN' AclWordToken 'TO' 'ROLE' AclName",
		                                         Start<FinalizeGrantAdmin>));
		changes.push_back(GrammarChange::AddRule("AclRevokeAdmin <- 'REVOKE' 'ADMIN' 'FROM' 'ROLE' AclName",
		                                         Start<FinalizeRevokeAdmin>));
		changes.push_back(
		    GrammarChange::AddRule("AclRevokeAdminScope <- 'REVOKE' 'ADMIN' AclWordToken 'FROM' 'ROLE' AclName",
		                           Start<FinalizeRevokeAdminScope>));
		changes.push_back(GrammarChange::AddRule("AclMapKind <- 'GROUP' / 'CLAIM'"));
		changes.push_back(GrammarChange::AddRule("AclMapScope <- 'CLIENT' / 'ISSUER'"));
		changes.push_back(GrammarChange::AddRule(
		    "AclMapping <- AclMapKind AclQuotedValue 'FROM' AclMapScope AclNameValue 'TO' 'ROLE' AclName"));
		changes.push_back(GrammarChange::AddRule("AclMapRole <- 'MAP' AclMapping", Start<FinalizeMapRole>));
		changes.push_back(GrammarChange::AddRule("AclDropMap <- 'DROP' 'MAP' AclMapping", Start<FinalizeDropMap>));
		changes.push_back(GrammarChange::AddRule("AclViewAs <- 'SET' 'SESSION' 'VIEW' 'AS' 'ROLE' AclNameValue",
		                                         Start<FinalizeViewAs>));
		changes.push_back(
		    GrammarChange::AddRule("AclResetViewAs <- 'RESET' 'SESSION' 'VIEW' 'AS'", Start<FinalizeResetViewAs>));
		// a statement no rule reads yet: its tokens, to the management compiler
		changes.push_back(GrammarChange::AddRule("AclTailToken <- Identifier"));
		changes.push_back(
		    GrammarChange::AddTerminalRuleOverride("AclTailToken", [](const PEGKeywordHelper &) -> unique_ptr<Matcher> {
			    return make_uniq<PassthroughTokenMatcher>();
		    }));
		changes.push_back(GrammarChange::AddRule("AclMgmtLegacy <- AclTailToken+", Start<FinalizeLegacy>));
		changes.push_back(GrammarChange::AddRule(
		    "AclMgmtStatement <- AclKillSession / AclSessionAuditLevel / AclProfileSession / AclNodeOperation / "
		    "AclMigrateCatalog / AclCreateRole / AclAlterRoleComment / AclAlterRoleClaims / AclDropRole / "
		    "AclGrantAdmin / AclRevokeAdmin / AclRevokeAdminScope / AclMapRole / AclDropMap / AclViewAs / "
		    "AclResetViewAs / AclMgmtLegacy"));
		// the batch holds management statements only: duckdb's own are not ours to read here
		changes.push_back(GrammarChange::ReplaceRule("Statement <- AclMgmtStatement", Start<FinalizeStatement>));
		return changes;
	}
};

} // namespace

shared_ptr<GrammarExtension> MakeMgmtGrammar() {
	return make_shared_ptr<AclMgmtGrammar>();
}

vector<MgmtParsed> ReadMgmtStatements(shared_ptr<CompiledGrammar> compiled, const string &text,
                                      const ParserOptions &options) {
	ParserOptions inner = options;
	inner.compiled_grammar = compiled;
	auto owned = make_uniq<vector<MatcherToken>>();
	ParserTokenizerBehavior behavior(text, *owned);
	compiled->GetTokenizer().TokenizeInput(behavior);
	TokenIterator tokens(std::move(owned));
	TokenIterator cursor(tokens);
	Parser parser(inner);
	vector<MgmtParsed> result;
	while (cursor.Current()) {
		auto start = cursor.Position();
		unique_ptr<SQLStatement> statement;
		try {
			statement = parser.ParseTopLevelStatement(cursor);
		} catch (ParserException &) {
			// a form a rule began but more follows it before its `;` (PEG keeps the rule that matched): the statement's
			// tokens up to its `;` go to the compiler as its own text, as a statement no rule reads does
			auto end = start;
			while (end < tokens.Size() && tokens.GetToken(end).type != TokenType::TERMINATOR &&
			       tokens.GetToken(end).type != TokenType::END_OF_INPUT) {
				end++;
			}
			if (end == start) {
				throw;
			}
			auto &last = tokens.GetToken(end - 1);
			MgmtParsed parsed;
			parsed.legacy = true;
			parsed.text =
			    text.substr(tokens.GetToken(start).offset, last.offset + last.length - tokens.GetToken(start).offset);
			result.push_back(std::move(parsed));
			cursor.SetPosition(end);
			while (cursor.Current() && cursor.Current()->type == TokenType::TERMINATOR) {
				cursor.Advance();
			}
			continue;
		}
		if (!statement) {
			continue; // a separator
		}
		auto &data = statement->Cast<ExtensionStatement>().parse_data->Cast<MgmtParseData>();
		for (auto &quoted : data.quoted) {
			auto index = quoted.offset.IsValid() ? TokenIndexAt(tokens, quoted.offset.GetIndex()) : optional_idx();
			if (!index.IsValid() || !WrittenPlainly(text, tokens.GetToken(index.GetIndex()), quoted.value)) {
				throw BinderException("acl admin: expected %s, quoted ('...' or \"...\") as one plain literal",
				                      quoted.what);
			}
		}
		for (auto &bare : data.bare) {
			auto index = bare.offset.IsValid() ? TokenIndexAt(tokens, bare.offset.GetIndex()) : optional_idx();
			auto written = index.IsValid() ? tokens.GetToken(index.GetIndex()).text : string();
			if (written.empty() || written[0] == '"' || written[0] == '`') {
				throw BinderException("acl admin: expected %s written as a word, not a quoted name", bare.what);
			}
		}
		MgmtParsed parsed;
		parsed.legacy = data.legacy;
		if (data.legacy) {
			parsed.text = text.substr(data.start, data.end - data.start);
		} else {
			parsed.function = data.function;
			parsed.args = data.args;
			parsed.current_session = data.current_session;
			for (auto &span : data.claims_lists) {
				auto inside = text.substr(span.start, span.end - span.start);
				StringUtil::Trim(inside);
				parsed.claims_lists.emplace_back(span.arg, std::move(inside));
			}
		}
		result.push_back(std::move(parsed));
	}
	return result;
}

} // namespace acl
} // namespace duckdb
