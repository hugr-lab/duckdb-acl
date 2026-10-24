// Spec 150, stage 3: the management statements as rules of duckdb's PEG parser. A management batch (the rest after
// `ACL <prefix> ACL`, or after `ACL ADMIN`) is parsed with a grammar whose Statement is ours: each family that moved
// to rules compiles to the acl_* call it always compiled to, and a statement no rule reads yet goes, as its own text,
// to the management compiler (acl_admin_sql.cpp) - one family moves per PR. Never registered: a connection cannot
// switch it on.

#include "acl_grammar.hpp"
#include "acl_grammar_util.hpp"
#include "acl_name_path.hpp"

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
	//! arguments written as a list or a body: read as text once the batch's tokens are known (a parenthesised list
	//! inside its parentheses, a body its first token to its last) - or, written as a quoted string, its value
	struct Span {
		idx_t arg;
		MgmtParsed::TextKind kind;
		bool body = false;
		//! SQL read by duckdb's parser (an RLS predicate, a body) - any literal; a list our readers split takes
		//! `'…'` literals only
		bool sql = false;
		idx_t start = 0;
		idx_t end = 0;
		bool resolved = false;
		string text;
		string what;
	};
	vector<Span> spans;

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

//! A double-quoted name's text, `""` a quote - what the compiler's scanner took
string UnquoteName(const string &text) {
	return StringUtil::Replace(text.substr(1, text.size() - 2), "\"\"", "\"");
}

//! One token of a kind the management compiler's scanner read: a word (ASCII letters, digits, `_` - a keyword too),
//! a double-quoted name, either, words joined by `.`, a path (identifiers joined by `.`) - or, inside a parenthesised
//! list, any token but a parenthesis.
//! The scanner read a word whole where duckdb's tokenizer splits it at a leading digit (`9abc` is `9` `abc`, `0x1F` is
//! `0` `x1F`): a word is the run of word tokens with nothing between them. The tokenizer also reads a number through
//! its dots (`v2.0.1` is `v2` `.0.1`, `9.x` is `9.` `x`): a dotted name is the run of tokens of word characters and
//! dots that touch or meet at a dot (`a . b`, `a /* c */ .b` too), then judged whole - every part a word
class AclTokenMatcher final : public AtomicMatcher {
public:
	enum class Kind : uint8_t { WORD, NAME, DOTTED, PATH, LIST_ITEM };

	explicit AclTokenMatcher(Kind kind_p) : AtomicMatcher(MatcherType::CUSTOM), kind(kind_p) {
	}

	MatcherResult MatchAtomic(MatchState &state) const override {
		auto current = state.token_iterator.Current();
		if (!current || !Accepts(*current)) {
			return MatcherResult::Failure();
		}
		if (kind == Kind::DOTTED) {
			return MatchDotted(state);
		}
		if (kind == Kind::PATH) {
			return MatchPath(state);
		}
		auto text = current->text;
		auto offset = current->offset;
		auto length = current->length;
		bool joins = kind != Kind::LIST_ITEM && current->type != TokenType::STRING_LITERAL && text[0] != '"';
		state.token_iterator.Advance();
		state.UpdateMaxTokenIndex();
		while (joins) {
			auto next = state.token_iterator.Current();
			if (!next || next->offset != offset + length || next->type == TokenType::STRING_LITERAL ||
			    !IsWord(next->text)) {
				break;
			}
			text += next->text;
			length += next->length;
			state.token_iterator.Advance();
			state.UpdateMaxTokenIndex();
		}
		return state.AllocateParseResult<TokenParseResult>(std::move(text), offset, length);
	}

	SuggestionType AddSuggestionInternal(MatchState &state) const override {
		return SuggestionType::MANDATORY; // a name: nothing to offer
	}

	string ToString() const override {
		return "AclToken";
	}

private:
	static bool IsDottedText(const MatcherToken &token) {
		if (token.type == TokenType::STRING_LITERAL || token.text.empty()) {
			return false;
		}
		for (auto c : token.text) {
			if (!StringUtil::CharacterIsAlpha(c) && !StringUtil::CharacterIsDigit(c) && c != '_' && c != '.') {
				return false;
			}
		}
		return true;
	}

	MatcherResult MatchDotted(MatchState &state) const {
		auto &tokens = state.token_iterator;
		auto first = tokens.Position();
		auto &head = tokens.GetToken(first);
		string text = head.text;
		auto end = head.offset + head.length;
		idx_t count = 1;
		while (first + count < tokens.Size()) {
			auto &next = tokens.GetToken(first + count);
			bool touches = next.offset == end;
			if (!IsDottedText(next) || (!touches && text.back() != '.' && next.text[0] != '.')) {
				break;
			}
			text += next.text;
			end = next.offset + next.length;
			count++;
		}
		// every part a word: no dot first, last or twice
		idx_t part_start = 0;
		for (idx_t i = 0; i <= text.size(); i++) {
			if (i == text.size() || text[i] == '.') {
				if (!IsWord(text.substr(part_start, i - part_start))) {
					return MatcherResult::Failure();
				}
				part_start = i + 1;
			}
		}
		tokens.Advance(count);
		state.UpdateMaxTokenIndex();
		return state.AllocateParseResult<TokenParseResult>(std::move(text), head.offset, end - head.offset);
	}

	static bool IsQuotedName(const MatcherToken &token) {
		return token.type != TokenType::STRING_LITERAL && token.text.size() >= 2 && token.text[0] == '"';
	}

	//! A path (spec 116) as the compiler's `Path` read it - identifiers joined by `.`, each a word or a double-quoted
	//! name - on the same run of tokens a dotted name takes, a double-quoted name a part of its own; its canonical key
	MatcherResult MatchPath(MatchState &state) const {
		auto &tokens = state.token_iterator;
		auto first = tokens.Position();
		vector<string> parts;
		string current;
		bool in_word = false;      // a word part is being read
		bool after_quoted = false; // a quoted part just ended: a dot or the end comes next
		idx_t count = 0;
		idx_t end = 0;
		char last = 0;
		for (idx_t index = first; index < tokens.Size(); index++) {
			auto &token = tokens.GetToken(index);
			if (!IsDottedText(token) && !IsQuotedName(token)) {
				break;
			}
			if (count > 0 && token.offset != end && last != '.' && token.text[0] != '.') {
				break; // neither touching nor meeting at a dot: the path ended
			}
			if (IsQuotedName(token)) {
				auto name = UnquoteName(token.text);
				if (in_word || after_quoted || name.empty()) {
					return MatcherResult::Failure(); // `a"b"` (a word touching a quoted part)
				}
				parts.push_back(std::move(name));
				after_quoted = true;
			} else {
				for (auto c : token.text) {
					if (c != '.') {
						if (after_quoted) {
							return MatcherResult::Failure(); // `"a"b`
						}
						current += c;
						in_word = true;
						continue;
					}
					if (in_word) {
						parts.push_back(std::move(current));
						current.clear();
						in_word = false;
					} else if (after_quoted) {
						after_quoted = false;
					} else {
						return MatcherResult::Failure(); // a dot first or twice: an empty part
					}
				}
			}
			end = token.offset + token.length;
			last = token.text.back();
			count++;
		}
		if (in_word) {
			parts.push_back(std::move(current));
		} else if (!after_quoted) {
			return MatcherResult::Failure(); // nothing, or a dot last
		}
		auto &head = tokens.GetToken(first);
		tokens.Advance(count);
		state.UpdateMaxTokenIndex();
		return state.AllocateParseResult<TokenParseResult>(NamePath(std::move(parts)).ToKey(), head.offset,
		                                                   end - head.offset);
	}

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
		case Kind::NAME:
			return quoted_name || (token.type != TokenType::STRING_LITERAL && IsWord(token.text));
		case Kind::DOTTED:
			return IsDottedText(token);
		case Kind::PATH:
			return IsDottedText(token) || IsQuotedName(token);
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
			throw ParserException("acl admin: a name's token is not where its rule says");
		}
	}
	return node.get().Cast<TokenParseResult>();
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

//! `AclNameValue <- StringLiteral / AclDottedToken / Identifier`: a name that is a value (spec 116 §3) as `NameValue`
//! read it - quoted either way, as written, or words joined by `.`
string NameValueOf(PEGTransformer &transformer, ParseResult &result, const char *what, MgmtParseData &data) {
	auto &node = Strip(result);
	if (node.Name() == "AclDottedToken") {
		// the matcher joined the name's tokens, its dots kept
		return TokenOf(node).text;
	}
	QuotedValue entry;
	entry.value = ValueOf(transformer, node, entry.offset);
	entry.what = what;
	data.quoted.push_back(entry);
	return entry.value;
}

//! Where a repetition of tokens (`AclTailToken+`) stands: its first token's start, its last token's end
void RepeatSpan(ParseResult &result, idx_t &start, idx_t &end, const char *what) {
	vector<reference<ParseResult>> parts;
	grammar::Collect(Strip(result), parts);
	if (parts.empty() || !parts.front().get().offset.IsValid() || !parts.back().get().offset.IsValid() ||
	    !parts.back().get().length.IsValid()) {
		throw ParserException("acl admin: %s has no position", what);
	}
	start = parts.front().get().offset.GetIndex();
	end = parts.back().get().offset.GetIndex() + parts.back().get().length.GetIndex();
}

//! A new argument of the call, its index
idx_t AddArg(MgmtParseData &data, Value value = Value(string())) {
	data.args.push_back(std::move(value));
	return data.args.size() - 1;
}

//! `AclParenList <- '(' AclListItem* ')'` into argument `arg`: its text between the parentheses, read once the
//! batch's tokens are known (no argument: judged, not stored - what an alias form does not keep)
void ParensInto(ParseResult &result, optional_idx arg, MgmtParsed::TextKind kind, bool sql, MgmtParseData &data) {
	auto &list = Strip(result).Cast<ListParseResult>();
	auto &open = list.GetChild(0);
	auto &close = list.GetChild(list.GetChildren().size() - 1);
	if (!open.offset.IsValid() || !close.offset.IsValid()) {
		throw ParserException("acl admin: a list has no position");
	}
	if (!arg.IsValid()) {
		return; // its tokens are judged with the batch's
	}
	MgmtParseData::Span span;
	span.arg = arg.GetIndex();
	span.kind = kind;
	span.sql = sql;
	span.start = open.offset.GetIndex() + 1;
	span.end = close.offset.GetIndex();
	data.spans.push_back(std::move(span));
}

//! An optional `AclParenList` into argument `arg` (left '' when absent): a parameter or a column list, as written
void OptionalParensInto(ListParseResult &list, idx_t index, idx_t arg, MgmtParseData &data) {
	auto &part = list.Child<OptionalParseResult>(index);
	if (part.HasResult()) {
		ParensInto(part.GetResult(), arg, MgmtParsed::TextKind::TEXT, false, data);
	}
}

//! `AclList <- AclParenList / AclQuotedValue` into argument `arg`: a list as written, or the legacy quoted string -
//! both to the compiler's reader of that kind (a quoted claims list is the stored csv as it stands); `sql` for a
//! list duckdb's parser reads (an RLS predicate), which may hold any literal
void ListInto(PEGTransformer &transformer, ParseResult &result, optional_idx arg, MgmtParsed::TextKind kind, bool sql,
              const char *what, MgmtParseData &data) {
	auto &node = Strip(result);
	if (node.Name() == "AclParenList") {
		ParensInto(node, arg, kind, sql, data);
		return;
	}
	QuotedValue entry;
	entry.value = ValueOf(transformer, node, entry.offset);
	entry.what = what;
	data.quoted.push_back(entry);
	if (!arg.IsValid()) {
		return;
	}
	if (kind == MgmtParsed::TextKind::CLAIMS) {
		data.args[arg.GetIndex()] = Value(entry.value);
		return;
	}
	MgmtParseData::Span span;
	span.arg = arg.GetIndex();
	span.kind = kind;
	span.resolved = true;
	span.text = entry.value;
	data.spans.push_back(std::move(span));
}

//! `AclClaims <- AclParenList / AclQuotedValue` into argument `arg`
void ClaimsInto(PEGTransformer &transformer, ParseResult &result, idx_t arg, MgmtParseData &data) {
	ListInto(transformer, result, arg, MgmtParsed::TextKind::CLAIMS, false, "claims list", data);
}

//! `AclBody <- AclTailToken+` into argument `arg`: a body written either way - inline to the end of the statement
//! (what a human writes) or as one quoted string (what a gateway generates), read once the tokens are known
void BodyInto(ParseResult &result, idx_t arg, const char *what, MgmtParseData &data) {
	MgmtParseData::Span span;
	span.arg = arg;
	span.kind = MgmtParsed::TextKind::TEXT;
	span.body = true;
	span.sql = true;
	RepeatSpan(result, span.start, span.end, "a body");
	span.what = what;
	data.spans.push_back(std::move(span));
}

//! `AclPath <- AclPathToken`: the path's canonical key (the matcher read it)
string PathOf(ParseResult &result) {
	return TokenOf(result).text;
}

//! A virtual name `<catalog>.<name>`: the catalog's key and the object's (spec 116)
void SplitVirtualName(const string &key, string &vcat, string &vname) {
	if (!NamePath::SplitHeadKey(key, vcat, vname)) {
		throw BinderException("acl admin: \"%s\" must be written as <catalog>.<name>", key);
	}
}

//! `AclPathName <- StringLiteral / AclPathToken`: a path as SQL writes one, or the legacy single-quoted whole path
//! read with the key rules - its canonical key
string PathNameOf(PEGTransformer &transformer, ParseResult &result, const char *what, MgmtParseData &data) {
	auto &node = Strip(result);
	if (node.Name() == "AclPathToken") {
		return TokenOf(node).text;
	}
	QuotedValue entry;
	entry.value = ValueOf(transformer, node, entry.offset);
	entry.what = what;
	data.quoted.push_back(entry);
	return NamePath::FromKey(entry.value, what).ToKey();
}

//! An optional `AclComment <- 'COMMENT' AclQuotedValue` at part `index`, '' when absent
string OptionalComment(PEGTransformer &transformer, ListParseResult &list, idx_t index, MgmtParseData &data) {
	auto &part = list.Child<OptionalParseResult>(index);
	if (!part.HasResult()) {
		return string();
	}
	return Quoted(transformer, Strip(part.GetResult()).Cast<ListParseResult>(), 1, "comment", data);
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

//! `'CREATE' AclOrReplace? … AclIfNotExists?`: what the statement promises about an existing object (spec 013) -
//! CREATE refuses to overwrite one, OR REPLACE overwrites, IF NOT EXISTS keeps it
string CreateMode(ListParseResult &list, idx_t or_replace, idx_t if_not_exists) {
	string mode = OptionalKeyword(list, or_replace) == "or" ? "replace" : "create";
	if (OptionalKeyword(list, if_not_exists) == "if" && mode == "create") {
		mode = "skip";
	}
	return mode;
}

// AclCreateRole <- 'CREATE' AclOrReplace? 'ROLE' AclIfNotExists? AclName AclRoleClaims?
arena_ptr<TransformResultValue> FinalizeCreateRole(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto data = Call("acl_define_role");
	auto mode = CreateMode(list, 1, 3);
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

// --- the virtual catalog's objects (specs 008, 010, 013, 022, 048) -------------------------------------------------

//! The clauses of a repetition at part `index`, each the clause's own result (its keyword says which)
vector<reference<ParseResult>> Clauses(ListParseResult &list, idx_t index) {
	vector<reference<ParseResult>> clauses;
	grammar::Collect(list.GetChild(index), clauses);
	return clauses;
}

//! A clause `'<KEYWORD>' … <value>`'s list (its value the last part)
ListParseResult &ClauseList(ParseResult &clause) {
	return Strip(clause).Cast<ListParseResult>();
}

// AclCreateCatalog <- 'CREATE' AclOrReplace? 'VIRTUAL' 'CATALOG' AclIfNotExists? AclName AclComment?
arena_ptr<TransformResultValue> FinalizeCreateCatalog(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto data = Call("acl_create_catalog");
	data->args.emplace_back(NamePath::QuotePart(NameOf(list.GetChild(5), "a catalog name")));
	data->args.emplace_back(OptionalComment(transformer, list, 6, *data));
	data->args.emplace_back(CreateMode(list, 1, 4));
	return MgmtResult(transformer, std::move(data));
}

// AclCreateReference <- 'CREATE' AclOrReplace? 'VIRTUAL' 'REFERENCE' AclIfNotExists? AclPath 'FROM' AclPath 'TO'
//     AclRefTarget AclRefOn? AclRefClause* (spec 022): a declared join path between two objects. An endpoint may be
// written with or without the reference's own catalog in front; TO FUNCTION f(param => col, …) - the parenthesis is
// the argument substitution and ON, when present, the join condition on the function's result
arena_ptr<TransformResultValue> FinalizeCreateReference(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto data = Call("acl_add_reference");
	string vcat, name;
	SplitVirtualName(PathOf(list.GetChild(5)), vcat, name);
	auto endpoint = [&vcat](const string &written) {
		return NamePath::KeyUnder(written, vcat) ? written.substr(vcat.size() + 1) : written;
	};
	data->args = {Value(vcat), Value(name), Value(endpoint(PathOf(list.GetChild(7))))};
	auto &target = Strip(list.GetChild(9));
	bool to_function = target.Name() == "AclRefFunction";
	auto to = AddArg(*data);
	AddArg(*data, Value(to_function ? "function" : "relation"));
	auto call_args = AddArg(*data);
	if (to_function) {
		// AclRefFunction <- 'FUNCTION' AclPath AclParenList?
		auto &function = target.Cast<ListParseResult>();
		data->args[to] = Value(endpoint(PathOf(function.GetChild(1))));
		OptionalParensInto(function, 2, call_args, *data);
	} else {
		data->args[to] = Value(endpoint(PathOf(target)));
	}
	auto pairs = AddArg(*data);
	auto expr = AddArg(*data);
	auto &on = list.Child<OptionalParseResult>(10);
	if (on.HasResult()) {
		// AclRefOn <- 'ON' AclRefCondition; AclRefCondition <- AclRefExpression / AclList - a bare list is a list of
		// column pairs, SQL is spelled out, so neither is mistaken for the other
		auto &condition = Strip(Strip(on.GetResult()).Cast<ListParseResult>().GetChild(1));
		if (condition.Name() == "AclRefExpression") {
			data->args[expr] =
			    Value(Quoted(transformer, condition.Cast<ListParseResult>(), 1, "a join expression", *data));
		} else {
			ListInto(transformer, condition, pairs, MgmtParsed::TextKind::TEXT, false, "column pairs", *data);
		}
	} else if (!to_function) {
		throw BinderException("acl admin: a reference between objects needs an ON condition");
	}
	string cardinality, join_method, comment;
	bool optional = false;
	for (auto &clause : Clauses(list, 11)) {
		auto keyword = KeywordOf(clause);
		if (keyword == "optional") {
			optional = true;
		} else if (keyword == "comment") {
			comment = Quoted(transformer, ClauseList(clause), 1, "comment", *data);
		} else if (keyword == "cardinality") {
			cardinality = TokenOf(ClauseList(clause).GetChild(1)).text;
		} else {
			join_method = TokenOf(ClauseList(clause).GetChild(1)).text;
		}
	}
	data->args.emplace_back(cardinality);
	data->args.emplace_back(optional ? "true" : "false");
	data->args.emplace_back(join_method);
	data->args.emplace_back(comment);
	data->args.emplace_back(CreateMode(list, 1, 4));
	return MgmtResult(transformer, std::move(data));
}

// AclCreateSchema <- 'CREATE' AclOrReplace? 'VIRTUAL' 'SCHEMA' AclIfNotExists? AclPath AclSchemaSource AclPathName
//     AclComment? - AS <phys>: the live alias, resolved through; FROM <phys>: the expansion, one record per object now
arena_ptr<TransformResultValue> FinalizeCreateSchema(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	bool expand = KeywordOf(list.GetChild(6)) == "from";
	auto data = Call(expand ? "acl_expand_schema" : "acl_add_schema_alias");
	string vcat, path;
	SplitVirtualName(PathOf(list.GetChild(5)), vcat, path);
	data->args = {Value(vcat), Value(path),
	              Value(PathNameOf(transformer, list.GetChild(7), "a physical schema path", *data))};
	data->args.emplace_back(OptionalComment(transformer, list, 8, *data));
	data->args.emplace_back(CreateMode(list, 1, 4));
	return MgmtResult(transformer, std::move(data));
}

// AclCreateView <- 'CREATE' AclOrReplace? 'VIRTUAL' 'VIEW' AclIfNotExists? AclPath AclParenList? AclViewClause* 'AS'
//     AclBody - a declared column list is the truth and spares the write-time probe; a body runs to the end of the
// statement, so a clause comes before AS
arena_ptr<TransformResultValue> FinalizeCreateView(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto data = Call("acl_add_view");
	string vcat, vname;
	SplitVirtualName(PathOf(list.GetChild(5)), vcat, vname);
	data->args = {Value(vcat), Value(vname)};
	BodyInto(list.GetChild(9), AddArg(*data), "view SQL", *data);
	OptionalParensInto(list, 6, AddArg(*data), *data);
	auto comment = AddArg(*data);
	data->args.emplace_back(CreateMode(list, 1, 4));
	auto pk = AddArg(*data);
	for (auto &clause : Clauses(list, 7)) {
		if (KeywordOf(clause) == "comment") {
			data->args[comment] = Value(Quoted(transformer, ClauseList(clause), 1, "comment", *data));
		} else {
			// AclPrimaryKey <- 'PRIMARY' 'KEY' AclList
			ListInto(transformer, ClauseList(clause).GetChild(2), pk, MgmtParsed::TextKind::TEXT, false, "key columns",
			         *data);
		}
	}
	return MgmtResult(transformer, std::move(data));
}

//! `AclReturns <- 'RETURNS' AclReturnType` (AclReturnType <- AclReturnsTable / AclWordToken) into argument `arg`: a
//! scalar's one type word, a table function's column list (TABLE before it optional) - judged also where it is not
//! kept (no argument: an alias)
void ReturnsInto(ListParseResult &list, idx_t index, bool scalar, optional_idx arg, MgmtParseData &data) {
	auto &part = list.Child<OptionalParseResult>(index);
	if (!part.HasResult()) {
		return;
	}
	auto &type = Strip(Strip(part.GetResult()).Cast<ListParseResult>().GetChild(1));
	bool table = type.Name() == "AclReturnsTable";
	if (scalar) {
		if (table) {
			throw BinderException("acl admin: a scalar RETURNS one type");
		}
		if (arg.IsValid()) {
			data.args[arg.GetIndex()] = Value(TokenOf(type).text);
		}
		return;
	}
	// AclReturnsTable <- 'TABLE'? AclParenList
	vector<reference<ParseResult>> items;
	if (table) {
		grammar::Collect(Strip(type.Cast<ListParseResult>().GetChild(1)).Cast<ListParseResult>().GetChild(1), items);
	}
	if (items.empty()) {
		throw BinderException("acl admin: RETURNS TABLE needs a column list");
	}
	ParensInto(type.Cast<ListParseResult>().GetChild(1), arg, MgmtParsed::TextKind::TEXT, false, data);
}

// AclCreateFunction <- 'CREATE' AclOrReplace? 'VIRTUAL' AclFunctionKind AclIfNotExists? AclPath AclParenList?
//     AclReturns? AclPrimaryKey? AclComment? AclFunctionDefinition - SCALAR | TABLE FUNCTION, AS <body> or ALIAS OF
// <function> (an alias has no body, so its comment may also come last)
arena_ptr<TransformResultValue> FinalizeCreateFunction(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	bool scalar = KeywordOf(list.GetChild(3)) == "scalar";
	auto data = make_uniq<MgmtParseData>();
	string vcat, vname;
	SplitVirtualName(PathOf(list.GetChild(5)), vcat, vname);
	auto &pk = list.Child<OptionalParseResult>(8);
	if (scalar && pk.HasResult()) {
		throw BinderException("acl admin: a scalar has no PRIMARY KEY - its result is one value");
	}
	auto comment = OptionalComment(transformer, list, 9, *data);
	auto &definition = Strip(list.GetChild(10)).Cast<ListParseResult>();
	auto mode = CreateMode(list, 1, 4);
	if (KeywordOf(definition.GetChild(0)) == "alias") {
		// AclAliasOf <- 'ALIAS' 'OF' AclPathName AclComment? - an alias keeps no parameters, result or key, but they
		// are judged as the body form judges them
		ReturnsInto(list, 7, scalar, optional_idx(), *data);
		if (pk.HasResult()) {
			ListInto(transformer, Strip(pk.GetResult()).Cast<ListParseResult>().GetChild(2), optional_idx(),
			         MgmtParsed::TextKind::TEXT, false, "key columns", *data);
		}
		data->function = scalar ? "acl_add_scalar_alias" : "acl_add_table_function_alias";
		auto target = PathNameOf(transformer, definition.GetChild(2), "a target function", *data);
		if (definition.Child<OptionalParseResult>(3).HasResult()) {
			comment = OptionalComment(transformer, definition, 3, *data);
		}
		data->args = {Value(vcat), Value(vname), Value(target), Value(""), Value(""), Value(comment), Value(mode)};
		return MgmtResult(transformer, std::move(data));
	}
	// AclAsBody <- 'AS' AclBody
	data->function = scalar ? "acl_add_scalar" : "acl_add_table_function";
	data->args = {Value(vcat), Value(vname)};
	BodyInto(definition.GetChild(1), AddArg(*data), scalar ? "expression template" : "SQL template", *data);
	OptionalParensInto(list, 6, AddArg(*data), *data);
	ReturnsInto(list, 7, scalar, AddArg(*data), *data);
	data->args.emplace_back(comment);
	data->args.emplace_back(mode);
	if (!scalar) {
		// a key describes the result (spec 048); a scalar result has no key to declare
		auto key = AddArg(*data);
		if (pk.HasResult()) {
			ListInto(transformer, Strip(pk.GetResult()).Cast<ListParseResult>().GetChild(2), key,
			         MgmtParsed::TextKind::TEXT, false, "key columns", *data);
		}
	}
	return MgmtResult(transformer, std::move(data));
}

// AclCreateTable <- 'CREATE' AclOrReplace? 'VIRTUAL' 'TABLE' AclIfNotExists? AclPath 'AS' AclPathName
//     AclTableClause* - COLUMNS, RLS, PRIMARY KEY (declared, never enforced: spec 048), COMMENT, in any order
arena_ptr<TransformResultValue> FinalizeCreateTable(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto data = Call("acl_add_relation");
	string vcat, vname;
	SplitVirtualName(PathOf(list.GetChild(5)), vcat, vname);
	data->args = {Value(vcat), Value(vname),
	              Value(PathNameOf(transformer, list.GetChild(7), "a physical table path", *data))};
	auto columns = AddArg(*data);
	auto rls = AddArg(*data);
	auto comment = AddArg(*data);
	data->args.emplace_back(CreateMode(list, 1, 4));
	auto pk = AddArg(*data);
	for (auto &clause : Clauses(list, 8)) {
		auto keyword = KeywordOf(clause);
		auto &value = ClauseList(clause);
		if (keyword == "columns") {
			ListInto(transformer, value.GetChild(1), columns, MgmtParsed::TextKind::COLUMNS, false, "columns list",
			         *data);
		} else if (keyword == "rls") {
			ListInto(transformer, value.GetChild(1), rls, MgmtParsed::TextKind::TEXT, true, "RLS predicate", *data);
		} else if (keyword == "primary") {
			ListInto(transformer, value.GetChild(2), pk, MgmtParsed::TextKind::TEXT, false, "key columns", *data);
		} else {
			data->args[comment] = Value(Quoted(transformer, value, 1, "comment", *data));
		}
	}
	return MgmtResult(transformer, std::move(data));
}

// AclAddView <- 'ADD' 'VIEW' AclPath AclParenList? 'AS' AclBody - the spec-008 spelling of CREATE VIRTUAL VIEW, kept
// (a gateway generates the ADD forms, and every existing script uses them)
arena_ptr<TransformResultValue> FinalizeAddView(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto data = Call("acl_add_view");
	string vcat, vname;
	SplitVirtualName(PathOf(list.GetChild(2)), vcat, vname);
	data->args = {Value(vcat), Value(vname)};
	BodyInto(list.GetChild(5), AddArg(*data), "view SQL", *data);
	OptionalParensInto(list, 3, AddArg(*data), *data);
	return MgmtResult(transformer, std::move(data));
}

// AclAddSchema <- 'ADD' 'SCHEMA' AclPath 'AS' AclPath - the physical schema first, the alias after AS
arena_ptr<TransformResultValue> FinalizeAddSchema(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto data = Call("acl_add_schema_alias");
	string vcat, alias;
	SplitVirtualName(PathOf(list.GetChild(4)), vcat, alias);
	data->args = {Value(vcat), Value(alias), Value(PathOf(list.GetChild(2)))};
	return MgmtResult(transformer, std::move(data));
}

// AclAddFunction <- 'ADD' AclFunctionKind AclPath AclParenList? AclReturns? AclAddDefinition - MACRO <body> or
// ALIAS [OF] <function> (the older ALIAS <fn> and ALIAS OF <fn> are the same thing)
arena_ptr<TransformResultValue> FinalizeAddFunction(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	bool scalar = KeywordOf(list.GetChild(1)) == "scalar";
	auto data = make_uniq<MgmtParseData>();
	string vcat, vname;
	SplitVirtualName(PathOf(list.GetChild(2)), vcat, vname);
	data->args = {Value(vcat), Value(vname)};
	auto &definition = Strip(list.GetChild(5)).Cast<ListParseResult>();
	if (KeywordOf(definition.GetChild(0)) == "alias") {
		// AclAddAlias <- 'ALIAS' 'OF'? AclPathName - the result is judged, not kept
		ReturnsInto(list, 4, scalar, optional_idx(), *data);
		data->function = scalar ? "acl_add_scalar_alias" : "acl_add_table_function_alias";
		data->args.emplace_back(PathNameOf(transformer, definition.GetChild(2), "a target function", *data));
		return MgmtResult(transformer, std::move(data));
	}
	// AclAddMacro <- 'MACRO' AclBody
	data->function = scalar ? "acl_add_scalar" : "acl_add_table_function";
	BodyInto(definition.GetChild(1), AddArg(*data), scalar ? "expression template" : "SQL template", *data);
	OptionalParensInto(list, 3, AddArg(*data), *data);
	ReturnsInto(list, 4, scalar, AddArg(*data), *data);
	return MgmtResult(transformer, std::move(data));
}

// AclAddTable <- 'ADD' 'TABLE' AclPath 'AS' AclPath AclColumnsClause? AclRlsClause? - the physical table first
arena_ptr<TransformResultValue> FinalizeAddTable(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto data = Call("acl_add_relation");
	string vcat, vname;
	SplitVirtualName(PathOf(list.GetChild(4)), vcat, vname);
	data->args = {Value(vcat), Value(vname), Value(PathOf(list.GetChild(2)))};
	auto columns = AddArg(*data);
	auto rls = AddArg(*data);
	auto &columns_part = list.Child<OptionalParseResult>(5);
	if (columns_part.HasResult()) {
		ListInto(transformer, ClauseList(columns_part.GetResult()).GetChild(1), columns, MgmtParsed::TextKind::COLUMNS,
		         false, "columns list", *data);
	}
	auto &rls_part = list.Child<OptionalParseResult>(6);
	if (rls_part.HasResult()) {
		ListInto(transformer, ClauseList(rls_part.GetResult()).GetChild(1), rls, MgmtParsed::TextKind::TEXT, true,
		         "RLS predicate", *data);
	}
	return MgmtResult(transformer, std::move(data));
}

// --- a statement no rule reads yet ------------------------------------------------------------------------------

// AclMgmtLegacy <- AclTailToken+ : its span, for the management compiler
arena_ptr<TransformResultValue> FinalizeLegacy(PEGTransformer &transformer, ParseResult &parse_result) {
	auto data = make_uniq<MgmtParseData>();
	data->legacy = true;
	RepeatSpan(parse_result.Cast<ListParseResult>().GetChild(0), data->start, data->end, "a management statement");
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
		changes.push_back(GrammarChange::AddRule("AclDottedToken <- Identifier"));
		changes.push_back(GrammarChange::AddTerminalRuleOverride(
		    "AclDottedToken", [](const PEGKeywordHelper &) -> unique_ptr<Matcher> {
			    return make_uniq<AclTokenMatcher>(AclTokenMatcher::Kind::DOTTED);
		    }));
		changes.push_back(GrammarChange::AddRule("AclPathToken <- Identifier"));
		changes.push_back(
		    GrammarChange::AddTerminalRuleOverride("AclPathToken", [](const PEGKeywordHelper &) -> unique_ptr<Matcher> {
			    return make_uniq<AclTokenMatcher>(AclTokenMatcher::Kind::PATH);
		    }));
		changes.push_back(GrammarChange::AddRule("AclListToken <- Identifier"));
		changes.push_back(
		    GrammarChange::AddTerminalRuleOverride("AclListToken", [](const PEGKeywordHelper &) -> unique_ptr<Matcher> {
			    return make_uniq<AclTokenMatcher>(AclTokenMatcher::Kind::LIST_ITEM);
		    }));
		changes.push_back(GrammarChange::AddRule("AclName <- AclNameToken"));
		changes.push_back(GrammarChange::AddRule("AclNameValue <- StringLiteral / AclDottedToken / Identifier"));
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
		// the virtual catalog's objects: paths, lists and bodies as the compiler's Path / List / Body read them
		changes.push_back(GrammarChange::AddRule("AclPath <- AclPathToken"));
		changes.push_back(GrammarChange::AddRule("AclPathName <- StringLiteral / AclPathToken"));
		changes.push_back(GrammarChange::AddRule("AclList <- AclParenList / AclQuotedValue"));
		changes.push_back(GrammarChange::AddRule("AclBody <- AclTailToken+"));
		changes.push_back(GrammarChange::AddRule("AclComment <- 'COMMENT' AclQuotedValue"));
		changes.push_back(GrammarChange::AddRule("AclPrimaryKey <- 'PRIMARY' 'KEY' AclList"));
		changes.push_back(GrammarChange::AddRule("AclColumnsClause <- 'COLUMNS' AclList"));
		changes.push_back(GrammarChange::AddRule("AclRlsClause <- 'RLS' AclList"));
		changes.push_back(GrammarChange::AddRule(
		    "AclCreateCatalog <- 'CREATE' AclOrReplace? 'VIRTUAL' 'CATALOG' AclIfNotExists? AclName AclComment?",
		    Start<FinalizeCreateCatalog>));
		changes.push_back(GrammarChange::AddRule("AclRefFunction <- 'FUNCTION' AclPath AclParenList?"));
		changes.push_back(GrammarChange::AddRule("AclRefTarget <- AclRefFunction / AclPath"));
		changes.push_back(GrammarChange::AddRule("AclRefExpression <- 'EXPRESSION' AclQuotedValue"));
		changes.push_back(GrammarChange::AddRule("AclRefCondition <- AclRefExpression / AclList"));
		changes.push_back(GrammarChange::AddRule("AclRefOn <- 'ON' AclRefCondition"));
		changes.push_back(GrammarChange::AddRule("AclRefCardinality <- 'CARDINALITY' AclWordToken"));
		changes.push_back(GrammarChange::AddRule("AclRefOptional <- 'OPTIONAL'"));
		changes.push_back(GrammarChange::AddRule("AclRefJoin <- 'JOIN' AclWordToken"));
		changes.push_back(
		    GrammarChange::AddRule("AclRefClause <- AclRefCardinality / AclRefOptional / AclRefJoin / AclComment"));
		changes.push_back(GrammarChange::AddRule(
		    "AclCreateReference <- 'CREATE' AclOrReplace? 'VIRTUAL' 'REFERENCE' AclIfNotExists? AclPath 'FROM' "
		    "AclPath 'TO' AclRefTarget AclRefOn? AclRefClause*",
		    Start<FinalizeCreateReference>));
		changes.push_back(GrammarChange::AddRule("AclSchemaSource <- 'FROM' / 'AS'"));
		changes.push_back(GrammarChange::AddRule("AclCreateSchema <- 'CREATE' AclOrReplace? 'VIRTUAL' 'SCHEMA' "
		                                         "AclIfNotExists? AclPath AclSchemaSource AclPathName AclComment?",
		                                         Start<FinalizeCreateSchema>));
		changes.push_back(GrammarChange::AddRule("AclViewClause <- AclPrimaryKey / AclComment"));
		changes.push_back(GrammarChange::AddRule("AclCreateView <- 'CREATE' AclOrReplace? 'VIRTUAL' 'VIEW' "
		                                         "AclIfNotExists? AclPath AclParenList? AclViewClause* 'AS' AclBody",
		                                         Start<FinalizeCreateView>));
		changes.push_back(GrammarChange::AddRule("AclScalarKind <- 'SCALAR'"));
		changes.push_back(GrammarChange::AddRule("AclTableFunctionKind <- 'TABLE' 'FUNCTION'"));
		changes.push_back(GrammarChange::AddRule("AclFunctionKind <- AclScalarKind / AclTableFunctionKind"));
		changes.push_back(GrammarChange::AddRule("AclReturnsTable <- 'TABLE'? AclParenList"));
		changes.push_back(GrammarChange::AddRule("AclReturnType <- AclReturnsTable / AclWordToken"));
		changes.push_back(GrammarChange::AddRule("AclReturns <- 'RETURNS' AclReturnType"));
		changes.push_back(GrammarChange::AddRule("AclAliasOf <- 'ALIAS' 'OF' AclPathName AclComment?"));
		changes.push_back(GrammarChange::AddRule("AclAsBody <- 'AS' AclBody"));
		changes.push_back(GrammarChange::AddRule("AclFunctionDefinition <- AclAliasOf / AclAsBody"));
		changes.push_back(GrammarChange::AddRule(
		    "AclCreateFunction <- 'CREATE' AclOrReplace? 'VIRTUAL' AclFunctionKind AclIfNotExists? AclPath "
		    "AclParenList? AclReturns? AclPrimaryKey? AclComment? AclFunctionDefinition",
		    Start<FinalizeCreateFunction>));
		changes.push_back(
		    GrammarChange::AddRule("AclTableClause <- AclColumnsClause / AclRlsClause / AclPrimaryKey / AclComment"));
		changes.push_back(GrammarChange::AddRule("AclCreateTable <- 'CREATE' AclOrReplace? 'VIRTUAL' 'TABLE' "
		                                         "AclIfNotExists? AclPath 'AS' AclPathName AclTableClause*",
		                                         Start<FinalizeCreateTable>));
		changes.push_back(GrammarChange::AddRule("AclAddView <- 'ADD' 'VIEW' AclPath AclParenList? 'AS' AclBody",
		                                         Start<FinalizeAddView>));
		changes.push_back(
		    GrammarChange::AddRule("AclAddSchema <- 'ADD' 'SCHEMA' AclPath 'AS' AclPath", Start<FinalizeAddSchema>));
		changes.push_back(GrammarChange::AddRule("AclAddMacro <- 'MACRO' AclBody"));
		changes.push_back(GrammarChange::AddRule("AclAddAlias <- 'ALIAS' 'OF'? AclPathName"));
		changes.push_back(GrammarChange::AddRule("AclAddDefinition <- AclAddMacro / AclAddAlias"));
		changes.push_back(GrammarChange::AddRule(
		    "AclAddFunction <- 'ADD' AclFunctionKind AclPath AclParenList? AclReturns? AclAddDefinition",
		    Start<FinalizeAddFunction>));
		changes.push_back(
		    GrammarChange::AddRule("AclAddTable <- 'ADD' 'TABLE' AclPath 'AS' AclPath AclColumnsClause? AclRlsClause?",
		                           Start<FinalizeAddTable>));
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
		    "AclResetViewAs / AclCreateCatalog / AclCreateReference / AclCreateSchema / AclCreateView / "
		    "AclCreateFunction / AclCreateTable / AclAddView / AclAddSchema / AclAddFunction / AclAddTable / "
		    "AclMgmtLegacy"));
		// the batch holds management statements only: duckdb's own are not ours to read here
		changes.push_back(GrammarChange::ReplaceRule("Statement <- AclMgmtStatement", Start<FinalizeStatement>));
		return changes;
	}
};

const char *const TILING_REFUSAL = "acl admin: a list or a body does not read as written - its tokens do not tile it";

//! The text of the tokens in [start, end) - a list between its parentheses or a body - refused unless the tokens
//! tile it as written (only whitespace and comments between them: after a lone `$` duckdb's tokenizer places the next
//! token at the `$`). A gap that holds a comment is, when `comments_as_space`, a space - a line break for a line
//! comment, which ends a line as the break does (two quoted strings a line apart are one) - else as written
string TokensText(const string &text, const TokenIterator &tokens, idx_t start, idx_t end, bool comments_as_space,
                  const string &refusal, const std::function<void(const MatcherToken &)> &judge) {
	auto refuse = [&refusal]() {
		throw BinderException(refusal);
	};
	string inside;
	optional_idx previous_end;
	for (idx_t index = grammar::FirstTokenFrom(tokens, start); index < tokens.Size(); index++) {
		auto &token = tokens.GetToken(index);
		if (token.offset >= end || token.type == TokenType::END_OF_INPUT) {
			break;
		}
		judge(token);
		if (previous_end.IsValid()) {
			auto gap_start = previous_end.GetIndex();
			if (token.offset < gap_start) {
				refuse();
			}
			auto gap = text.substr(gap_start, token.offset - gap_start);
			auto blank = gap;
			StringUtil::Trim(blank);
			if (blank.empty() || !comments_as_space) {
				if (!blank.empty() && !StringUtil::StartsWith(blank, "--") && !StringUtil::StartsWith(blank, "/*")) {
					refuse();
				}
				inside += gap;
			} else if (StringUtil::StartsWith(blank, "--") || StringUtil::StartsWith(blank, "/*")) {
				inside += StringUtil::Contains(gap, "/*") ? " " : "\n";
			} else {
				refuse();
			}
		}
		if (token.offset + token.length > end) {
			refuse();
		}
		inside += text.substr(token.offset, token.length);
		previous_end = token.offset + token.length;
	}
	return inside;
}

//! Whether [start, end) is a list's inside: a parenthesis right before it and after it (one placed at another token's
//! offset is not)
bool BetweenParentheses(const string &text, idx_t start, idx_t end) {
	return start > 0 && text[start - 1] == '(' && end < text.size() && text[end] == ')';
}

//! A parenthesised list's text between its parentheses, as written with each comment a space (a comment would
//! otherwise be read as part of the list: `(a = 1 -- note⏎)` left an open comment in an RLS predicate). A list our
//! readers split (`SplitTopLevel` knows `'…'` and `"…"` only) takes `'…'` literals only - `E'…'`, `$$…$$` or a
//! backtick name would split into other items than written; one duckdb's parser reads (`sql`) any
string ListText(const string &text, const TokenIterator &tokens, idx_t start, idx_t end, bool sql) {
	if (!BetweenParentheses(text, start, end)) {
		throw BinderException(TILING_REFUSAL);
	}
	return TokensText(text, tokens, start, end, true, TILING_REFUSAL, [sql](const MatcherToken &token) {
		if (sql) {
			return;
		}
		if ((token.type == TokenType::STRING_LITERAL && (token.text.empty() || token.text[0] != '\'')) ||
		    (!token.text.empty() && token.text[0] == '`')) {
			throw BinderException("acl admin: a list is written with '...' literals - E'...', $$...$$ and a backtick "
			                      "name are not read as one item here yet");
		}
	});
}

//! A claims list's text for the compiler's `ClaimsListToCsv`: a list's, in the words of a claims list (that reader
//! keeps a name and an unquoted value as written - `custom:tenant`, `-1`)
string ClaimsListText(const string &text, const TokenIterator &tokens, idx_t start, idx_t end) {
	const string prefix = "acl admin: a claims list is written as name = 'value' items - ";
	auto refuse = [&prefix](const char *why) {
		throw BinderException(prefix + why);
	};
	if (!BetweenParentheses(text, start, end)) {
		refuse("its text does not read as written");
	}
	return TokensText(
	    text, tokens, start, end, true, prefix + "its text does not read as written", [&](const MatcherToken &token) {
		    if (token.type == TokenType::STRING_LITERAL && (token.text.empty() || token.text[0] != '\'')) {
			    refuse("a value is in single quotes (E'...' and $$...$$ are not read as one value here yet)");
		    }
		    if (!token.text.empty() && token.text[0] == '`') {
			    refuse("a backtick name is not read as one name here");
		    }
	    });
}

//! A body's text, its first token to its last as written (the comments inside it are the body's own; one before its
//! first token or after its last is not part of it) - or, written as a quoted string, that string's value: the whole
//! body, as the compiler's `Body` read it (a clause written after it - `AS 'SELECT 1' COMMENT 'x'` - is refused, never
//! stored as the body)
string BodyText(const string &text, const TokenIterator &tokens, idx_t start, idx_t end, const string &what) {
	auto first = TokenIndexAt(tokens, start);
	if (first.IsValid()) {
		auto &token = tokens.GetToken(first.GetIndex());
		bool quoted = !token.text.empty() && (token.text[0] == '\'' || token.text[0] == '"');
		if (quoted && token.offset + token.length != end) {
			throw BinderException("acl admin: %s written quoted is the whole body - nothing may follow it (write it "
			                      "inline, or a clause before AS)",
			                      what);
		}
		if (quoted) {
			auto quote = token.text[0];
			auto value = token.text.size() >= 2 ? token.text.substr(1, token.text.size() - 2) : string();
			value = StringUtil::Replace(value, string(2, quote), string(1, quote));
			if (!WrittenPlainly(text, token, value)) {
				throw BinderException("acl admin: expected %s, quoted ('...' or \"...\") as one plain literal", what);
			}
			return value;
		}
	}
	return TokensText(text, tokens, start, end, false, TILING_REFUSAL, [](const MatcherToken &) {});
}

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
	for (idx_t index = 0; index < tokens.Size(); index++) {
		// the tokenizer keeps a dollar-quoted string nobody closed as one literal to the end of the text: it would
		// take every statement after it into the one it starts (`AS SELECT $x$; REVOKE …` stored the REVOKE as SQL)
		if (tokens.GetToken(index).unterminated) {
			throw BinderException("acl admin: an unterminated quoted string - the batch is refused");
		}
	}
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
			for (auto &span : data.spans) {
				string value;
				if (span.resolved) {
					value = span.text;
				} else if (span.body) {
					value = BodyText(text, tokens, span.start, span.end, span.what);
				} else if (span.kind == MgmtParsed::TextKind::CLAIMS) {
					value = ClaimsListText(text, tokens, span.start, span.end);
				} else {
					value = ListText(text, tokens, span.start, span.end, span.sql);
				}
				parsed.texts.push_back(MgmtParsed::TextArg {span.arg, std::move(value), span.kind});
			}
		}
		result.push_back(std::move(parsed));
	}
	return result;
}

} // namespace acl
} // namespace duckdb
