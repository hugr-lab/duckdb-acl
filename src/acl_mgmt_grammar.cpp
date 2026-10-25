// Spec 150, stage 3: the management statements as rules of duckdb's PEG parser. A management batch (the rest after
// `ACL <prefix> ACL`, or after `ACL ADMIN`) is parsed with a grammar whose Statement is ours: each family that moved
// to rules compiles to the acl_* call it always compiled to, and a statement no rule reads yet goes, as its own text,
// to the management compiler (acl_admin_sql.cpp) - one family moves per PR. Never registered: a connection cannot
// switch it on.

#include "acl_door_common.hpp"
#include "acl_grammar.hpp"
#include "acl_grammar_util.hpp"
#include "acl_name_path.hpp"
#include "acl_platform.hpp"

#include "duckdb/common/error_data.hpp"
#include "duckdb/common/types/value.hpp"
#include "duckdb/parser/grammar_change.hpp"
#include "duckdb/parser/grammar_extension.hpp"
#include "duckdb/parser/parser.hpp"
#include "duckdb/parser/parser_extension.hpp"
#include "duckdb/parser/peg/compiled_grammar.hpp"
#include "duckdb/parser/peg/matcher.hpp"
#include "duckdb/parser/peg/passthrough_dialect.hpp"
#include "duckdb/parser/peg/special_string_utils.hpp"
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
	//! the call is a table function, read in FROM (CHECK VIRTUAL CATALOG)
	bool table_call = false;
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
		//! a body that is an expression (a scalar's template), not a statement
		bool expression = false;
		//! a quoted list a reader of ours splits: judged as the compiler's text is (no comment, no `$$`, ...)
		bool judge = false;
		//! where the list's reading goes inside the argument (a JSON spec), '' = the whole argument
		string splice;
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

//! `AclName` naming a catalog, as its key (one identifier: `"Sales Mart"`, `"a.b"`)
string CatalogKeyOf(ParseResult &result) {
	return NamePath::QuotePart(NameOf(result, "a catalog name"));
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
	MgmtParseData::Span span;
	span.arg = arg.GetIndex();
	// a quoted claims list is the stored csv as it stands; a columns list goes to its reader - both split by readers
	// of ours, judged as the compiler's text is
	span.kind = kind == MgmtParsed::TextKind::CLAIMS ? MgmtParsed::TextKind::TEXT : kind;
	span.judge = kind != MgmtParsed::TextKind::TEXT;
	span.what = kind == MgmtParsed::TextKind::CLAIMS ? "claims list" : "columns list";
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
void BodyInto(ParseResult &result, idx_t arg, const char *what, bool expression, MgmtParseData &data) {
	MgmtParseData::Span span;
	span.arg = arg;
	span.kind = MgmtParsed::TextKind::TEXT;
	span.body = true;
	span.sql = true;
	RepeatSpan(result, span.start, span.end, "a body");
	span.what = what;
	span.expression = expression;
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

//! `AclIfExists?` at part `index`: `IF EXISTS` says nothing-to-drop is not an error (spec 010) - "skip", else ''
string DropMode(ListParseResult &list, idx_t index) {
	return OptionalKeyword(list, index) == "if" ? "skip" : "";
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
	data->args.emplace_back(DropMode(list, 2));
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

//! A clause kind written once: a repeated one (`RLS (tenant = 'x') … RLS ()`) would leave a reader of the statement
//! the first while the last took effect - refused
void ClauseOnce(case_insensitive_set_t &seen, const string &kind, const string &shown = string()) {
	if (!seen.insert(kind).second) {
		auto words = !shown.empty()      ? shown
		             : kind == "primary" ? string("PRIMARY KEY")
		             : kind == "caps"    ? string("CAPS / WITH")
		                                 : StringUtil::Upper(kind);
		throw BinderException("acl admin: %s is written twice - write each clause once", words);
	}
}

//! A clause `'<KEYWORD>' … <value>`'s list (its value the last part)
ListParseResult &ClauseList(ParseResult &clause) {
	return Strip(clause).Cast<ListParseResult>();
}

// AclCreateCatalog <- 'CREATE' AclOrReplace? 'VIRTUAL' 'CATALOG' AclIfNotExists? AclName AclComment?
arena_ptr<TransformResultValue> FinalizeCreateCatalog(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto data = Call("acl_create_catalog");
	data->args.emplace_back(CatalogKeyOf(list.GetChild(5)));
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
	case_insensitive_set_t seen;
	for (auto &clause : Clauses(list, 11)) {
		auto keyword = KeywordOf(clause);
		ClauseOnce(seen, keyword);
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
	BodyInto(list.GetChild(9), AddArg(*data), "view SQL", false, *data);
	OptionalParensInto(list, 6, AddArg(*data), *data);
	auto comment = AddArg(*data);
	data->args.emplace_back(CreateMode(list, 1, 4));
	auto pk = AddArg(*data);
	case_insensitive_set_t seen;
	for (auto &clause : Clauses(list, 7)) {
		ClauseOnce(seen, KeywordOf(clause));
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
		// AclAliasOf <- 'ALIAS' 'OF' AclPathName AclComment? - an alias keeps no parameters, result or key: its
		// result's shape and a quoted key are judged as the body form judges them, a parenthesised list only with the
		// batch's tokens
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
	BodyInto(definition.GetChild(1), AddArg(*data), scalar ? "expression template" : "SQL template", scalar, *data);
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
	case_insensitive_set_t seen;
	for (auto &clause : Clauses(list, 8)) {
		auto keyword = KeywordOf(clause);
		ClauseOnce(seen, keyword);
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
	BodyInto(list.GetChild(5), AddArg(*data), "view SQL", false, *data);
	OptionalParensInto(list, 3, AddArg(*data), *data);
	return MgmtResult(transformer, std::move(data));
}

// AclAddSchema <- 'ADD' 'SCHEMA' AclPath 'AS' AclPath - the physical schema first, the alias after AS
arena_ptr<TransformResultValue> FinalizeAddSchema(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto data = Call("acl_add_schema_alias");
	string vcat, alias;
	SplitVirtualName(PathOf(list.GetChild(4)), vcat, alias);
	data->args = {Value(vcat), Value(alias),
	              Value(PathNameOf(transformer, list.GetChild(2), "a physical schema path", *data))};
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
	BodyInto(definition.GetChild(1), AddArg(*data), scalar ? "expression template" : "SQL template", scalar, *data);
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
	data->args = {Value(vcat), Value(vname),
	              Value(PathNameOf(transformer, list.GetChild(2), "a physical table path", *data))};
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

// --- the objects changed and dropped (specs 010, 039, 048, 099, 120) -----------------------------------------------

//! A virtual name `<catalog>.<name>` at part `index` of a rule, into the call's first two arguments
void VirtualNameArgs(ListParseResult &list, idx_t index, MgmtParseData &data) {
	string vcat, vname;
	SplitVirtualName(PathOf(list.GetChild(index)), vcat, vname);
	data.args = {Value(vcat), Value(vname)};
}

// AclAlterReference <- 'ALTER' 'VIRTUAL' 'REFERENCE' AclPath 'SET' AclReferenceSet (spec 120) - AclReferenceSet <-
//     AclComment / AclRefCardinality / AclRefOptionalSet: one property, the rest kept
arena_ptr<TransformResultValue> FinalizeAlterReference(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto data = Call("acl_alter_reference");
	VirtualNameArgs(list, 3, *data);
	auto &change = ClauseList(list.GetChild(5));
	auto field = KeywordOf(change);
	data->args.emplace_back(field);
	data->args.emplace_back(field == "comment" ? Quoted(transformer, change, 1, "comment", *data)
	                                           : TokenOf(change.GetChild(1)).text);
	return MgmtResult(transformer, std::move(data));
}

// AclAlterCatalog <- 'ALTER' 'VIRTUAL' 'CATALOG' AclName 'SET' AclComment
arena_ptr<TransformResultValue> FinalizeAlterCatalog(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto data = Call("acl_alter_catalog");
	data->args.emplace_back(CatalogKeyOf(list.GetChild(3)));
	data->args.emplace_back(Quoted(transformer, ClauseList(list.GetChild(5)), 1, "comment", *data));
	return MgmtResult(transformer, std::move(data));
}

//! An object's change (`AclDropKey`, `AclSetKey`, `AclSetTypes`, `AclSetColumns`, `AclSetRls`, `AclSetPhys`,
//! `AclSetBody`, `AclSetMacro`, `AclSetAlias`) into the call it compiles to; `key_kind` is what a key is declared on
//! ("relation" or "table" - a table function's result), '' where none may be
void ObjectChangeInto(PEGTransformer &transformer, ParseResult &result, const char *key_kind, const char *function_kind,
                      MgmtParseData &data) {
	auto &change = Strip(result);
	auto name = change.Name();
	auto &parts = change.Cast<ListParseResult>();
	if (name == "AclDropKey" || name == "AclSetKey") {
		// spec 048: declared, never enforced; a scalar's result is one value
		if (!*key_kind) {
			throw BinderException("acl admin: a scalar has no PRIMARY KEY - its result is one value");
		}
		data.function = "acl_set_key";
		data.args.emplace_back(key_kind);
		auto key = AddArg(data);
		if (name == "AclSetKey") {
			// AclSetKey <- 'SET' AclPrimaryKey; AclPrimaryKey <- 'PRIMARY' 'KEY' AclList
			ListInto(transformer, ClauseList(parts.GetChild(1)).GetChild(2), key, MgmtParsed::TextKind::TEXT, false,
			         "key columns", data);
		}
		return;
	}
	if (name == "AclSetMacro" || name == "AclSetAlias") {
		// AclSetMacro <- 'SET' 'MACRO' AclBody; AclSetAlias <- 'SET' 'ALIAS' 'OF'? AclPathName
		data.function = "acl_alter_function";
		data.args.emplace_back(function_kind);
		bool macro = name == "AclSetMacro";
		data.args.emplace_back(macro ? "macro" : "alias");
		if (macro) {
			BodyInto(parts.GetChild(2), AddArg(data), "definition", StringUtil::CIEquals(function_kind, "scalar"),
			         data);
		} else {
			data.args.emplace_back(PathNameOf(transformer, parts.GetChild(3), "a target function", data));
		}
		return;
	}
	data.function = "acl_alter_relation";
	if (name == "AclSetBody") {
		// AclSetBody <- 'SET' 'AS' AclBody
		data.args.emplace_back("view");
		BodyInto(parts.GetChild(2), AddArg(data), "view SQL", false, data);
	} else if (name == "AclSetPhys") {
		// AclSetPhys <- 'SET' 'PHYS' AclPathName
		data.args.emplace_back("phys");
		data.args.emplace_back(PathNameOf(transformer, parts.GetChild(2), "a physical table path", data));
	} else if (name == "AclSetTypes") {
		// AclSetTypes <- 'SET' 'TYPES' AclList (spec 099: aliases = base|keep|default, enums = ...)
		data.args.emplace_back("types");
		ListInto(transformer, parts.GetChild(2), AddArg(data), MgmtParsed::TextKind::TEXT, false, "types list", data);
	} else if (name == "AclSetColumns") {
		// AclSetColumns <- 'SET' AclColumnsClause
		data.args.emplace_back("columns");
		ListInto(transformer, ClauseList(parts.GetChild(1)).GetChild(1), AddArg(data), MgmtParsed::TextKind::COLUMNS,
		         false, "columns list", data);
	} else if (name == "AclSetRls") {
		// AclSetRls <- 'SET' AclRlsClause
		data.args.emplace_back("rls");
		ListInto(transformer, ClauseList(parts.GetChild(1)).GetChild(1), AddArg(data), MgmtParsed::TextKind::TEXT, true,
		         "RLS predicate", data);
	} else {
		throw ParserException("acl admin: an object change no rule names");
	}
}

// AclAlterView <- 'ALTER' 'VIRTUAL' 'VIEW' AclPath AclViewChange - SET AS <sql> | SET|DROP PRIMARY KEY | SET TYPES;
// AclAlterTable <- 'ALTER' 'VIRTUAL' 'TABLE' AclPath AclTableChange - SET PHYS | COLUMNS | RLS | TYPES, SET|DROP
// PRIMARY KEY
arena_ptr<TransformResultValue> FinalizeAlterRelation(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto data = make_uniq<MgmtParseData>();
	VirtualNameArgs(list, 3, *data);
	ObjectChangeInto(transformer, list.GetChild(4), "relation", "", *data);
	return MgmtResult(transformer, std::move(data));
}

// AclAlterFunction <- 'ALTER' 'VIRTUAL' AclFunctionKind AclPath AclFunctionChange - SET MACRO <body> | SET ALIAS
// [OF] <function>, a table function's SET|DROP PRIMARY KEY
arena_ptr<TransformResultValue> FinalizeAlterFunction(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	bool scalar = KeywordOf(list.GetChild(2)) == "scalar";
	auto data = make_uniq<MgmtParseData>();
	VirtualNameArgs(list, 3, *data);
	ObjectChangeInto(transformer, list.GetChild(4), scalar ? "" : "table", scalar ? "scalar" : "table", *data);
	return MgmtResult(transformer, std::move(data));
}

// AclAlterSchema <- 'ALTER' 'VIRTUAL' 'SCHEMA' AclPath AclSchemaChange - REFRESH [PRUNE] (re-expand from the
// source) | SET PHYS <path> (re-point the live alias)
arena_ptr<TransformResultValue> FinalizeAlterSchema(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto data = make_uniq<MgmtParseData>();
	VirtualNameArgs(list, 3, *data);
	auto &change = Strip(list.GetChild(4));
	if (change.Name() == "AclSetSchemaPhys") {
		// AclSetSchemaPhys <- 'SET' 'PHYS' AclPathName
		data->function = "acl_alter_schema_alias";
		data->args.emplace_back(
		    PathNameOf(transformer, change.Cast<ListParseResult>().GetChild(2), "a physical schema path", *data));
	} else {
		// AclRefresh <- 'REFRESH' AclPrune?
		data->function = "acl_refresh_schema_objects";
		data->args.emplace_back(Value::BOOLEAN(OptionalKeyword(change.Cast<ListParseResult>(), 1) == "prune"));
	}
	return MgmtResult(transformer, std::move(data));
}

// AclCommentReference <- 'COMMENT' 'ON' 'VIRTUAL' 'REFERENCE' AclPath 'IS' AclQuotedValue (spec 120)
arena_ptr<TransformResultValue> FinalizeCommentReference(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto data = Call("acl_alter_reference");
	VirtualNameArgs(list, 4, *data);
	data->args.emplace_back("comment");
	data->args.emplace_back(Quoted(transformer, list, 6, "comment", *data));
	return MgmtResult(transformer, std::move(data));
}

// AclCommentObject <- 'COMMENT' 'ON' 'VIRTUAL' AclCommentKind AclPath AclCommentColumn? 'IS' AclQuotedValue -
// an object's comment, or one of its columns' (AclCommentColumn <- 'COLUMN' AclName)
arena_ptr<TransformResultValue> FinalizeCommentObject(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto data = Call("acl_comment");
	VirtualNameArgs(list, 4, *data);
	auto &kind = Strip(list.GetChild(3));
	auto keyword = KeywordOf(kind);
	data->args.emplace_back(kind.Name() == "AclTableFunctionKind"
	                            ? "table"
	                            : (keyword == "schema" || keyword == "scalar" ? keyword : string("relation")));
	auto &column = list.Child<OptionalParseResult>(5);
	data->args.emplace_back(column.HasResult() ? NameOf(ClauseList(column.GetResult()).GetChild(1), "a column name")
	                                           : string());
	data->args.emplace_back(Quoted(transformer, list, 7, "comment", *data));
	return MgmtResult(transformer, std::move(data));
}

// AclCheckCatalog <- 'CHECK' 'VIRTUAL' 'CATALOG' AclName (spec 039): what no longer holds against the source, one row
// each - a table function, read in FROM
arena_ptr<TransformResultValue> FinalizeCheckCatalog(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto data = Call("acl_check_catalog");
	data->table_call = true;
	data->args.emplace_back(CatalogKeyOf(list.GetChild(3)));
	return MgmtResult(transformer, std::move(data));
}

// AclRepairTable <- 'REPAIR' 'VIRTUAL' 'TABLE' AclPath AclRepairAction (spec 039) - REMAP (v = expr, ...) | DROP
// MISSING COLUMNS [AND MASKS]
arena_ptr<TransformResultValue> FinalizeRepairTable(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto data = Call("acl_repair_relation");
	VirtualNameArgs(list, 3, *data);
	auto &action = Strip(list.GetChild(4)).Cast<ListParseResult>();
	if (KeywordOf(action) == "remap") {
		// AclRemap <- 'REMAP' AclList
		data->args.emplace_back("remap");
		ListInto(transformer, action.GetChild(1), AddArg(*data), MgmtParsed::TextKind::COLUMNS, false, "remap list",
		         *data);
	} else {
		// AclDropMissing <- 'DROP' 'MISSING' 'COLUMNS' AclAndMasks?
		data->args.emplace_back(action.Child<OptionalParseResult>(3).HasResult() ? "drop_missing_and_masks"
		                                                                         : "drop_missing");
	}
	return MgmtResult(transformer, std::move(data));
}

// AclAnalyzeCatalog <- 'ANALYZE' 'VIRTUAL' 'CATALOG' AclName - re-derive every stored schema of the catalog
arena_ptr<TransformResultValue> FinalizeAnalyzeCatalog(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto data = Call("acl_refresh_schema");
	data->args = {Value(CatalogKeyOf(list.GetChild(3))), Value("")};
	return MgmtResult(transformer, std::move(data));
}

// AclAnalyzeObject <- 'ANALYZE' 'VIRTUAL' AclAnalyzeTarget - one object's (AclAnalyzeTarget <- AclAnalyzeFunctionTarget
// / AclAnalyzeKindTarget / AclPath: the path last, a kind before it or none)
arena_ptr<TransformResultValue> FinalizeAnalyzeObject(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto data = Call("acl_refresh_schema");
	auto &target = Strip(list.GetChild(2));
	auto &path = target.type == ParseResultType::LIST ? target.Cast<ListParseResult>().GetChild(1) : target;
	string vcat, vname;
	SplitVirtualName(PathOf(path), vcat, vname);
	data->args = {Value(vcat), Value(vname)};
	return MgmtResult(transformer, std::move(data));
}

// AclDropRelation <- 'DROP' 'RELATION' AclIfExists? AclPath (the spec-008 spelling, kept)
arena_ptr<TransformResultValue> FinalizeDropRelation(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto data = Call("acl_drop_relation");
	VirtualNameArgs(list, 3, *data);
	data->args.emplace_back(DropMode(list, 2));
	return MgmtResult(transformer, std::move(data));
}

// AclDropReference <- 'DROP' 'VIRTUAL'? 'REFERENCE' AclIfExists? AclPath
arena_ptr<TransformResultValue> FinalizeDropReference(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto data = Call("acl_drop_reference");
	VirtualNameArgs(list, 4, *data);
	data->args.emplace_back(DropMode(list, 3));
	return MgmtResult(transformer, std::move(data));
}

// AclDropCatalog <- 'DROP' 'VIRTUAL' 'CATALOG' AclIfExists? AclName AclCascade?
arena_ptr<TransformResultValue> FinalizeDropCatalog(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto data = Call("acl_drop_catalog");
	data->args = {Value(CatalogKeyOf(list.GetChild(4))), Value::BOOLEAN(list.Child<OptionalParseResult>(5).HasResult()),
	              Value(DropMode(list, 3))};
	return MgmtResult(transformer, std::move(data));
}

// AclDropSchema <- 'DROP' 'VIRTUAL' 'SCHEMA' AclIfExists? AclPath AclCascade?
arena_ptr<TransformResultValue> FinalizeDropSchema(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto data = Call("acl_drop_schema_alias");
	VirtualNameArgs(list, 4, *data);
	data->args.emplace_back(DropMode(list, 3));
	data->args.emplace_back(Value::BOOLEAN(list.Child<OptionalParseResult>(5).HasResult()));
	return MgmtResult(transformer, std::move(data));
}

// AclDropFunction <- 'DROP' 'VIRTUAL' AclFunctionKind AclIfExists? AclPath
arena_ptr<TransformResultValue> FinalizeDropFunction(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto data = Call("acl_drop_function");
	VirtualNameArgs(list, 4, *data);
	data->args.emplace_back(KeywordOf(list.GetChild(2)) == "scalar" ? "scalar" : "table");
	data->args.emplace_back(DropMode(list, 3));
	return MgmtResult(transformer, std::move(data));
}

// AclDropObject <- 'DROP' 'VIRTUAL' AclDropObjectKind AclIfExists? AclPath - a table or a view
arena_ptr<TransformResultValue> FinalizeDropObject(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto data = Call("acl_drop_relation");
	VirtualNameArgs(list, 4, *data);
	data->args.emplace_back(DropMode(list, 3));
	return MgmtResult(transformer, std::move(data));
}

// --- grants (specs 011, 012, 015, 120) ------------------------------------------------------------------------------

//! A grant's policy clauses, in any order, each once: `WITH (select, insert)` (the list form of
//! CAPS), `CAPS '<json>'`, `RLS <list>`, `COLUMNS <list>`, and - a catalog grant's - `MAIN`
struct GrantClauses {
	optional_idx caps;
	optional_idx rls;
	optional_idx columns;
	bool main = false;
	//! a clause that is present and not empty (a schema grant carries capabilities only)
	bool rls_written = false;
	bool columns_written = false;
};

//! Whether a list clause's value (`AclList`) is empty as written - `()` or `''`
bool ListIsEmpty(PEGTransformer &transformer, ParseResult &result) {
	auto &node = Strip(result);
	if (node.Name() == "AclParenList") {
		// separators only read as no item (the compiler's reader drops empty items)
		vector<reference<ParseResult>> items;
		grammar::Collect(node.Cast<ListParseResult>().GetChild(1), items);
		for (auto &item : items) {
			auto &token = Strip(item.get());
			if (token.type != ParseResultType::TOKEN || token.Cast<TokenParseResult>().text != ",") {
				return false;
			}
		}
		return true;
	}
	optional_idx offset;
	auto value = ValueOf(transformer, node, offset);
	for (auto c : value) {
		if (c != ',' && !StringUtil::CharacterIsSpace(c)) {
			return false;
		}
	}
	return true;
}

//! `AclCapsList <- '(' AclCapsEntry AclCapsMore* ')'` (AclCapsEntry <- AclName?): the capabilities named, as the
//! stored JSON - the list form is what a person writes, JSON the storage format and the admin functions' input. Each
//! a word or a double-quoted name, lower-cased, quoted as JSON (the compiler pasted the text between the commas into
//! the JSON, so `\u006danage` stored manage). An unknown capability is kept as written rather than refused - the
//! vocabulary grows, and a grant authored against a newer version must not fail - but enforces nothing until some
//! spec reads it (design 004)
string CapsListJson(ParseResult &result) {
	vector<reference<ParseResult>> names;
	auto &list = Strip(result).Cast<ListParseResult>();
	auto collect = [&names](ParseResult &entry) {
		auto &part = Strip(entry);
		if (part.type != ParseResultType::OPTIONAL) {
			names.push_back(part);
		}
	};
	collect(list.GetChild(1));
	vector<reference<ParseResult>> more;
	grammar::Collect(list.GetChild(2), more);
	for (auto &next : more) {
		collect(next.get().Cast<ListParseResult>().GetChild(1));
	}
	vector<string> entries;
	case_insensitive_set_t named;
	for (auto &name : names) {
		auto capability = StringUtil::Lower(NameOf(name, "a capability"));
		if (named.insert(capability).second) { // the same capability twice is one
			entries.push_back(JsonQuote(capability) + ": true");
		}
	}
	return "{" + StringUtil::Join(entries, ", ") + "}";
}

//! The clauses of a repetition at part `index` into the call's arguments `clauses` names
void GrantClausesInto(PEGTransformer &transformer, ListParseResult &list, idx_t index, GrantClauses &clauses,
                      MgmtParseData &data) {
	case_insensitive_set_t seen;
	for (auto &clause : Clauses(list, index)) {
		auto keyword = KeywordOf(clause);
		ClauseOnce(seen, keyword == "with" ? "caps" : keyword); // WITH is the list form of CAPS
		if (keyword == "main") {
			clauses.main = true;
			continue;
		}
		auto &parts = ClauseList(clause);
		if (keyword == "with") {
			data.args[clauses.caps.GetIndex()] = Value(CapsListJson(parts.GetChild(1)));
		} else if (keyword == "caps") {
			data.args[clauses.caps.GetIndex()] = Value(Quoted(transformer, parts, 1, "caps JSON", data));
		} else if (keyword == "rls") {
			clauses.rls_written = !ListIsEmpty(transformer, parts.GetChild(1));
			ListInto(transformer, parts.GetChild(1), clauses.rls, MgmtParsed::TextKind::TEXT, true, "an RLS predicate",
			         data);
		} else {
			clauses.columns_written = !ListIsEmpty(transformer, parts.GetChild(1));
			ListInto(transformer, parts.GetChild(1), clauses.columns, MgmtParsed::TextKind::COLUMNS, false,
			         "a column list", data);
		}
	}
}

//! `AclRoleTarget <- AclAllRoles / AclOneRole`: `ROLE r` names the role, `ALL ROLES` is the role '' - every role's
//! (a function grant's alone; the other calls refuse it)
string RoleTargetOf(ParseResult &result) {
	auto &target = Strip(result).Cast<ListParseResult>();
	if (target.Name() == "AclAllRoles") {
		return string();
	}
	return NameOf(target.GetChild(1), "a role name"); // AclOneRole <- 'ROLE' AclName
}

//! A point grant on the platform catalog (spec 117) - `GRANT | DENY | REVOKE VIEW | FUNCTION platform.<x>`: the
//! call, or null when the path is no object of platform's (then a view's grant is an object grant, which refuses the
//! reserved catalog in its own words). `verb` grant / deny / revoke, `role` '' for ALL ROLES (which the call refuses)
unique_ptr<MgmtParseData> PlatformGrantCall(const char *kind, const string &path_key, const string &verb,
                                            const string &role) {
	string leaf;
	if (!PlatformObjectName(NamePath::FromKey(path_key).Parts(), leaf)) {
		return nullptr;
	}
	if (verb == "revoke") {
		auto data = Call("acl_revoke_platform");
		data->args = {Value(role), Value(kind), Value(leaf)};
		return data;
	}
	auto data = Call("acl_grant_platform");
	data->args = {Value(role), Value(kind), Value(leaf), Value(verb == "deny" ? "false" : "true")};
	return data;
}

//! `GRANT | REVOKE VIEW platform.<v> TO | FROM ROLE r` through the object grant's rule: platform's point grant, which
//! takes no clause of an object grant
unique_ptr<MgmtParseData> PlatformViewGrant(ListParseResult &list, const string &verb, optional_idx clauses) {
	if (KeywordOf(list.GetChild(1)) != "view") {
		return nullptr;
	}
	auto data = PlatformGrantCall("view", PathOf(list.GetChild(2)), verb, RoleTargetOf(list.GetChild(4)));
	if (data && clauses.IsValid() && list.Child<OptionalParseResult>(clauses.GetIndex()).HasResult()) {
		throw BinderException("acl admin: a grant on a view of the platform catalog takes no WITH, CAPS, RLS or "
		                      "COLUMNS - it is the view, granted or denied");
	}
	return data;
}

// AclGrantCatalog <- 'GRANT' 'CATALOG' AclName 'TO' 'ROLE' AclName AclGrantClause* - the catalog level (spec 011):
// no capability clause = unspecified, which resolves to every data capability; `WITH ()` / `CAPS '{}'` none
arena_ptr<TransformResultValue> FinalizeGrantCatalog(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto data = Call("acl_grant_catalog");
	data->args = {Value(NameOf(list.GetChild(5), "a role name")), Value(CatalogKeyOf(list.GetChild(2)))};
	GrantClauses clauses;
	clauses.caps = AddArg(*data);
	auto main = AddArg(*data);
	clauses.rls = AddArg(*data);
	clauses.columns = AddArg(*data);
	GrantClausesInto(transformer, list, 6, clauses, *data);
	data->args[main] = Value::BOOLEAN(clauses.main);
	return MgmtResult(transformer, std::move(data));
}

// AclGrantSchema <- 'GRANT' 'SCHEMA' AclPath 'TO' 'ROLE' AclName AclObjectClause* AclSchemaHome? AclComment? - the
// middle level (spec 015): capabilities only; INTO <phys> is where this role creates, VIRTUAL ONLY nowhere
arena_ptr<TransformResultValue> FinalizeGrantSchema(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto data = Call("acl_grant_schema");
	string vcat, path;
	SplitVirtualName(PathOf(list.GetChild(2)), vcat, path);
	data->args = {Value(NameOf(list.GetChild(5), "a role name")), Value(vcat), Value(path)};
	// RLS and COLUMNS are judged, not kept: present and not empty, they are refused
	GrantClauses clauses;
	clauses.caps = AddArg(*data);
	auto comment = AddArg(*data);
	auto into = AddArg(*data);
	auto virtual_only = AddArg(*data, Value::BOOLEAN(false));
	GrantClausesInto(transformer, list, 6, clauses, *data);
	if (clauses.rls_written || clauses.columns_written) {
		throw BinderException("acl admin: a schema grant carries capabilities only - RLS and COLUMNS belong to the "
		                      "catalog or to the object (spec 015)");
	}
	auto &home = list.Child<OptionalParseResult>(7);
	if (home.HasResult()) {
		auto &where = Strip(home.GetResult()).Cast<ListParseResult>();
		if (KeywordOf(where) == "into") {
			// AclInto <- 'INTO' AclPathName
			data->args[into] = Value(PathNameOf(transformer, where.GetChild(1), "a physical schema path", *data));
		} else {
			data->args[virtual_only] = Value::BOOLEAN(true); // AclVirtualOnly <- 'VIRTUAL' 'ONLY'
		}
	}
	data->args[comment] = Value(OptionalComment(transformer, list, 8, *data));
	return MgmtResult(transformer, std::move(data));
}

// AclGrantObject <- 'GRANT' AclObjectKind AclPath 'TO' AclRoleTarget AclObjectClause* - the object's own grant (spec
// 011): it narrows the object for this role, it never widens it
arena_ptr<TransformResultValue> FinalizeGrantObject(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	if (auto platform = PlatformViewGrant(list, "grant", 5)) {
		return MgmtResult(transformer, std::move(platform));
	}
	auto data = Call("acl_grant_object");
	string vcat, vname;
	SplitVirtualName(PathOf(list.GetChild(2)), vcat, vname);
	data->args = {Value(RoleTargetOf(list.GetChild(4))), Value(vcat), Value(vname)};
	GrantClauses clauses;
	clauses.caps = AddArg(*data);
	clauses.rls = AddArg(*data);
	clauses.columns = AddArg(*data);
	GrantClausesInto(transformer, list, 5, clauses, *data);
	return MgmtResult(transformer, std::move(data));
}

// AclRevokeCatalog <- 'REVOKE' 'CATALOG' AclName 'FROM' 'ROLE' AclName
arena_ptr<TransformResultValue> FinalizeRevokeCatalog(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto data = Call("acl_revoke_catalog");
	data->args = {Value(NameOf(list.GetChild(5), "a role name")), Value(CatalogKeyOf(list.GetChild(2)))};
	return MgmtResult(transformer, std::move(data));
}

// AclRevokeSchema <- 'REVOKE' 'SCHEMA' AclPath 'FROM' 'ROLE' AclName
arena_ptr<TransformResultValue> FinalizeRevokeSchema(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto data = Call("acl_revoke_schema");
	string vcat, path;
	SplitVirtualName(PathOf(list.GetChild(2)), vcat, path);
	data->args = {Value(NameOf(list.GetChild(5), "a role name")), Value(vcat), Value(path)};
	return MgmtResult(transformer, std::move(data));
}

// AclRevokeObject <- 'REVOKE' AclObjectKind AclPath 'FROM' AclRoleTarget (spec 120): the object's own grant - the
// catalog's stays
arena_ptr<TransformResultValue> FinalizeRevokeObject(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	if (auto platform = PlatformViewGrant(list, "revoke", optional_idx())) {
		return MgmtResult(transformer, std::move(platform));
	}
	auto data = Call("acl_revoke_object");
	string vcat, vname;
	SplitVirtualName(PathOf(list.GetChild(2)), vcat, vname);
	data->args = {Value(RoleTargetOf(list.GetChild(4))), Value(vcat), Value(vname)};
	return MgmtResult(transformer, std::move(data));
}

// AclAlterGrant <- 'ALTER' 'GRANT' 'CATALOG' AclName 'TO' 'ROLE' AclName 'SET' AclGrantSet - one property of a
// catalog grant, the rest kept; its values are quoted strings (AclGrantSet <- AclCapsClause / AclSetRlsValue /
// AclSetColumnsValue / AclSetMainValue)
arena_ptr<TransformResultValue> FinalizeAlterGrant(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto data = Call("acl_alter_grant");
	data->args = {Value(NameOf(list.GetChild(6), "a role name")), Value(CatalogKeyOf(list.GetChild(3)))};
	auto &change = ClauseList(list.GetChild(8));
	auto field = KeywordOf(change);
	data->args.emplace_back(field);
	if (field == "main") {
		data->args.emplace_back(TokenOf(change.GetChild(1)).text);
	} else if (field == "columns") {
		MgmtParseData::Span span;
		span.arg = AddArg(*data);
		span.kind = MgmtParsed::TextKind::COLUMNS;
		span.resolved = true;
		span.text = Quoted(transformer, change, 1, "a column list", *data);
		data->spans.push_back(std::move(span));
	} else {
		data->args.emplace_back(
		    Quoted(transformer, change, 1, field == "caps" ? "caps JSON" : "an RLS predicate", *data));
	}
	return MgmtResult(transformer, std::move(data));
}

// --- issuers and clients (spec 095) --------------------------------------------------------------------------------

//! A parenthesised list inside a JSON spec: its marker in the spec, which the reading of its text replaces once the
//! batch's tokens are known (a control character never stands raw in JSON, so no value can forge it)
string SpecListMarker(ParseResult &paren_list, MgmtParsed::TextKind kind, idx_t arg, MgmtParseData &data) {
	auto index = data.spans.size();
	auto marker = string("\x01") + std::to_string(index) + "\x01";
	ParensInto(paren_list, arg, kind, false, data);
	if (data.spans.size() != index + 1) {
		throw ParserException("acl admin: a list inside a spec left no span");
	}
	data.spans[index].splice = marker;
	return marker;
}

//! A JSON list of a legacy csv's items (`'a,b'`): split at the commas, each trimmed, the empty ones left out
string CsvItemsJson(const string &csv) {
	vector<string> items;
	for (auto &item : StringUtil::Split(csv, ',')) {
		StringUtil::Trim(item);
		if (!item.empty()) {
			items.push_back(JsonQuote(item));
		}
	}
	return "[" + StringUtil::Join(items, ",") + "]";
}

//! `AclList <- AclParenList / AclQuotedValue` inside a JSON spec: a list of values as written, or the legacy csv
string ItemsJson(PEGTransformer &transformer, ParseResult &result, const char *what, idx_t arg, MgmtParseData &data) {
	auto &node = Strip(result);
	if (node.Name() == "AclParenList") {
		return SpecListMarker(node, MgmtParsed::TextKind::ITEMS, arg, data);
	}
	QuotedValue entry;
	entry.value = ValueOf(transformer, node, entry.offset);
	entry.what = what;
	data.quoted.push_back(entry);
	return CsvItemsJson(entry.value);
}

//! `FROM SECRET <name> [IN <service>]`'s entries: the secret's name at `name`, AclSecretIn? after it
void SecretEntries(PEGTransformer &transformer, ListParseResult &clause, idx_t name, vector<string> &entries,
                   MgmtParseData &data) {
	entries.push_back("\"secret\":" +
	                  JsonQuote(NameValueOf(transformer, clause.GetChild(name), "a secret name", data)));
	auto &in = clause.Child<OptionalParseResult>(name + 1);
	if (in.HasResult()) {
		// AclSecretIn <- 'IN' AclName
		entries.push_back("\"service\":" +
		                  JsonQuote(NameOf(ClauseList(in.GetResult()).GetChild(1), "a secrets service")));
	}
}

//! One clause of a client (spec 095 §2) into its spec entries: each clause once. `issuer` collects what is the
//! issuer's in the short form (URL, its own FROM SECRET); null when the clause belongs to a client alone
void ClientClauseInto(PEGTransformer &transformer, ParseResult &result, idx_t arg, vector<string> &entries,
                      optional_ptr<vector<string>> issuer, case_insensitive_set_t &seen, MgmtParseData &data) {
	auto &clause = Strip(result);
	if (clause.Name() == "AclKeysClause") {
		// AclKeysClause <- AclKeysWord AclList? (AclKeysWord <- 'KEYS' / 'ALGS')
		throw BinderException(
		    "acl admin: an issuer's keys and algorithms are never written into the policy - the "
		    "issuer's OIDC discovery supplies them, or KEYS / KEYS_FROM / ALGS in an oidc_issuer secret "
		    "named with FROM SECRET");
	}
	auto name = clause.Name();
	auto &parts = clause.Cast<ListParseResult>();
	// each clause once, by what it writes (a repeated one wrote its key twice into the spec, the last taking effect):
	// ROLE CLAIM and ROLES FROM both name the role sources, ATTRIBUTES and CLAIM MAP both the attributes
	if (name == "AclRoleClaim" || name == "AclRolesFrom") {
		ClauseOnce(seen, "roles_from", "ROLE CLAIM / ROLES FROM");
	} else if (name == "AclAttributes" || name == "AclClaimMap") {
		ClauseOnce(seen, "attributes", "ATTRIBUTES / CLAIM MAP");
	} else {
		vector<string> words; // shown as its leading words
		for (auto &child : parts.GetChildren()) {
			if (child.get().type != ParseResultType::KEYWORD) {
				break;
			}
			words.push_back(KeywordOf(child.get()));
		}
		ClauseOnce(seen, name, StringUtil::Upper(StringUtil::Join(words, " ")));
	}
	if (name == "AclUrlClause") {
		// AclUrlClause <- 'URL' AclQuotedValue - empty = none (ALTER ISSUER … SET URL '')
		auto url = Quoted(transformer, parts, 1, "URL", data);
		issuer->push_back("\"url\":" + (url.empty() ? string("null") : JsonQuote(url)));
	} else if (name == "AclFromSecret") {
		// AclFromSecret <- 'FROM' 'SECRET' AclNameValue AclSecretIn? - an issuer's clause names the issuer's keys, a
		// client's its own
		SecretEntries(transformer, parts, 2, issuer ? *issuer : entries, data);
	} else if (name == "AclClientSecret") {
		// AclClientSecret <- 'CLIENT' 'FROM' 'SECRET' AclNameValue AclSecretIn? - the short form's client
		SecretEntries(transformer, parts, 3, entries, data);
	} else if (name == "AclAudiences" || name == "AclAzp" || name == "AclFlows" || name == "AclRolesFrom" ||
	           name == "AclRolesConstant") {
		auto key = name == "AclAudiences"   ? "audiences"
		           : name == "AclAzp"       ? "azp"
		           : name == "AclFlows"     ? "flows"
		           : name == "AclRolesFrom" ? "roles_from"
		                                    : "roles_constant";
		auto what = name == "AclRolesFrom" ? "claim paths" : name == "AclRolesConstant" ? "roles" : key;
		entries.push_back(string("\"") + key + "\":" +
		                  ItemsJson(transformer, parts.GetChild(parts.GetChildren().size() - 1), what, arg, data));
	} else if (name == "AclRequire" || name == "AclAttributes") {
		// AclRequire <- 'REQUIRE' AclList / AclAttributes <- 'ATTRIBUTES' AclList - a list in parentheses only
		bool require = name == "AclRequire";
		auto &list = Strip(parts.GetChild(1));
		if (list.Name() != "AclParenList") {
			throw BinderException(require ? "acl admin: REQUIRE takes its conditions in parentheses"
			                              : "acl admin: ATTRIBUTES takes its list in parentheses");
		}
		entries.push_back(string(require ? "\"require\":" : "\"attributes\":") +
		                  SpecListMarker(list,
		                                 require ? MgmtParsed::TextKind::REQUIRE : MgmtParsed::TextKind::ATTRIBUTES,
		                                 arg, data));
	} else if (name == "AclClaimMap") {
		// AclClaimMap <- 'CLAIM' 'MAP' AclList - the map kept as a JSON string, which the spec parses
		auto &map = Strip(parts.GetChild(2));
		entries.push_back("\"claim_map\":" + (map.Name() == "AclParenList"
		                                          ? SpecListMarker(map, MgmtParsed::TextKind::CLAIM_MAP, arg, data)
		                                          : JsonQuote(Quoted(transformer, parts, 2, "claim map", data))));
	} else if (name == "AclRoleClaim") {
		// AclRoleClaim <- 'ROLE' 'CLAIM' AclQuotedValue - the short form's one source
		entries.push_back("\"roles_from\":[" + JsonQuote(Quoted(transformer, parts, 2, "role claim path", data)) + "]");
	} else if (name == "AclUnmapped") {
		// AclUnmapped <- 'UNMAPPED' AclUnmappedAs
		entries.push_back(string("\"unmapped\":") +
		                  (KeywordOf(parts.GetChild(1)) == "ignore" ? "\"ignore\"" : "\"as_role\""));
	} else if (name == "AclSubject") {
		// AclSubject <- 'SUBJECT' AclList - paths in parentheses, or one quoted path
		auto &paths = Strip(parts.GetChild(1));
		entries.push_back("\"subject\":" +
		                  (paths.Name() == "AclParenList"
		                       ? SpecListMarker(paths, MgmtParsed::TextKind::ITEMS, arg, data)
		                       : "[" + JsonQuote(Quoted(transformer, parts, 1, "subject path", data)) + "]"));
	} else if (name == "AclTokenType") {
		// AclTokenType <- 'TOKEN' 'TYPE' AclQuotedValue
		entries.push_back("\"token_type\":" + JsonQuote(Quoted(transformer, parts, 2, "token type", data)));
	} else if (name == "AclClientId") {
		// AclClientId <- 'CLIENT' 'ID' AclQuotedValue
		entries.push_back("\"client_id\":" + JsonQuote(Quoted(transformer, parts, 2, "client id", data)));
	} else if (name == "AclClientSecretValue") {
		throw BinderException("acl admin: a client secret is never written into the policy - keep it as "
		                      "CLIENT_SECRET in an oidc_client secret of the secrets service and name that secret (%s)",
		                      issuer ? "CLIENT FROM SECRET s" : "FROM SECRET s");
	} else {
		throw ParserException("acl admin: a client clause no rule names");
	}
}

string SpecObject(const vector<string> &entries) {
	return "{" + StringUtil::Join(entries, ",") + "}";
}

// AclCreateIssuer <- 'CREATE' AclOrReplace? 'ISSUER' AclIfNotExists? AclIssuerName AclIssuerClause* - any client
// clause makes it the short form, with an implicit client; a quoted name is the short form's URL unless URL says one
arena_ptr<TransformResultValue> FinalizeCreateIssuer(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto data = Call("acl_define_issuer");
	// AclIssuerName <- StringLiteral / AclNameToken: '…' or "…" is a quoted name (the compiler's Quoted), else a word
	auto &name_node = Strip(list.GetChild(4));
	string name;
	bool quoted = name_node.Name() != "AclNameToken" || TokenOf(name_node).text[0] == '"';
	if (name_node.Name() == "AclNameToken") {
		name = NameOf(name_node, "an issuer name");
	} else {
		name = Quoted(transformer, list, 4, "issuer", *data);
	}
	data->args = {Value(name), Value(string()), Value(CreateMode(list, 1, 3))};
	vector<string> issuer_entries, client_entries;
	case_insensitive_set_t seen;
	for (auto &clause : Clauses(list, 5)) {
		ClientClauseInto(transformer, clause, 1, client_entries, &issuer_entries, seen, *data);
	}
	bool has_url = seen.count("AclUrlClause");
	if (!has_url && quoted) {
		issuer_entries.push_back("\"url\":" + JsonQuote(name)); // the short form's name IS its URL
	} else if (!has_url && !seen.count("AclFromSecret")) {
		throw BinderException("acl admin: issuer \"%s\" needs its URL - URL '<url>', or the URL as its quoted name, "
		                      "or an oidc_issuer secret carrying it (FROM SECRET s)",
		                      name);
	}
	if (!client_entries.empty()) {
		issuer_entries.push_back("\"client\":" + SpecObject(client_entries));
	}
	data->args[1] = Value(SpecObject(issuer_entries));
	return MgmtResult(transformer, std::move(data));
}

// AclCreateClient <- 'CREATE' AclOrReplace? 'CLIENT' AclIfNotExists? AclNameValue 'ISSUER' AclNameValue
//     AclClientClause*
arena_ptr<TransformResultValue> FinalizeCreateClient(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto data = Call("acl_define_client");
	data->args = {Value(NameValueOf(transformer, list.GetChild(4), "a client name", *data)),
	              Value(NameValueOf(transformer, list.GetChild(6), "an issuer name", *data)), Value(string()),
	              Value(CreateMode(list, 1, 3))};
	vector<string> entries;
	case_insensitive_set_t seen;
	for (auto &clause : Clauses(list, 7)) {
		ClientClauseInto(transformer, clause, 2, entries, nullptr, seen, *data);
	}
	data->args[2] = Value(SpecObject(entries));
	return MgmtResult(transformer, std::move(data));
}

// AclAlterIssuer <- 'ALTER' 'ISSUER' AclNameValue AclIssuerChange - SET (URL | [CLIENT] FROM SECRET | a client clause)
// … | DROP [CLIENT] FROM SECRET (AclIssuerChange <- AclIssuerDropSecret / AclIssuerSet)
arena_ptr<TransformResultValue> FinalizeAlterIssuer(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto data = Call("acl_alter_issuer");
	auto name = NameValueOf(transformer, list.GetChild(2), "an issuer name", *data);
	data->args = {Value(name), Value(string())};
	vector<string> issuer_entries, client_entries;
	auto &change = Strip(list.GetChild(3)).Cast<ListParseResult>();
	if (change.Name() == "AclIssuerDropSecret") {
		// AclIssuerDropSecret <- 'DROP' 'CLIENT'? 'FROM' 'SECRET'
		(change.Child<OptionalParseResult>(1).HasResult() ? client_entries : issuer_entries)
		    .push_back("\"secret\":null");
	} else {
		// AclIssuerSet <- 'SET' AclIssuerClause+
		case_insensitive_set_t seen;
		vector<reference<ParseResult>> clauses;
		grammar::Collect(change.GetChild(1), clauses);
		for (auto &clause : clauses) {
			ClientClauseInto(transformer, clause, 1, client_entries, &issuer_entries, seen, *data);
		}
	}
	if (!client_entries.empty()) {
		issuer_entries.push_back("\"client\":" + SpecObject(client_entries));
	}
	data->args[1] = Value(SpecObject(issuer_entries));
	return MgmtResult(transformer, std::move(data));
}

// AclAlterClient <- 'ALTER' 'CLIENT' AclNameValue AclClientChange - SET (FROM SECRET | a client clause) … |
// DROP FROM SECRET
arena_ptr<TransformResultValue> FinalizeAlterClient(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto data = Call("acl_alter_client");
	data->args = {Value(NameValueOf(transformer, list.GetChild(2), "a client name", *data)), Value(string())};
	vector<string> entries;
	auto &change = Strip(list.GetChild(3)).Cast<ListParseResult>();
	if (change.Name() == "AclClientDropSecret") {
		entries.push_back("\"secret\":null"); // AclClientDropSecret <- 'DROP' 'FROM' 'SECRET'
	} else {
		// AclClientSet <- 'SET' AclClientClause+
		case_insensitive_set_t seen;
		vector<reference<ParseResult>> clauses;
		grammar::Collect(change.GetChild(1), clauses);
		for (auto &clause : clauses) {
			ClientClauseInto(transformer, clause, 1, entries, nullptr, seen, *data);
		}
	}
	data->args[1] = Value(SpecObject(entries));
	return MgmtResult(transformer, std::move(data));
}

// AclDropIdentity <- 'DROP' AclIdentityKind AclIfExists? AclNameValue (AclIdentityKind <- 'ISSUER' / 'CLIENT')
arena_ptr<TransformResultValue> FinalizeDropIdentity(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	bool issuer = KeywordOf(list.GetChild(1)) == "issuer";
	auto data = Call(issuer ? "acl_drop_issuer" : "acl_drop_client");
	data->args = {Value(NameValueOf(transformer, list.GetChild(3), issuer ? "an issuer name" : "a client name", *data)),
	              Value(DropMode(list, 2))};
	return MgmtResult(transformer, std::move(data));
}

// --- function grants and categories (spec 072), platform's point grants (spec 117), sources (spec 118.3), resource
// groups (spec 085) ---------------------------------------------------------------------------------------------

//! `AclFunctionSpec <- AclPath AclGrantFunctionKind?` as the spec the admin functions parse (ParseFunctionSpec): the
//! path's key, a one-part name no bare word could be (`"+"`, `"IS DISTINCT FROM"`) in double quotes, then the kind
//! written; `key` the path's key
string FunctionSpecOf(ParseResult &result, string &key, bool &kind_written) {
	auto &spec = Strip(result).Cast<ListParseResult>();
	key = PathOf(spec.GetChild(0));
	auto parts = NamePath::FromKey(key).Parts();
	auto text = key;
	if (parts.size() == 1) {
		for (auto c : parts[0]) {
			if (!StringUtil::CharacterIsAlphaNumeric(c) && c != '_') {
				text = "\"" + parts[0] + "\"";
				break;
			}
		}
	}
	auto &kind = spec.Child<OptionalParseResult>(1);
	kind_written = kind.HasResult();
	if (kind_written) {
		text += KeywordOf(kind.GetResult()) == "table" ? " TABLE" : " SCALAR";
	}
	return text;
}

// AclGrantFunctionCategory <- AclFunctionGrantVerb 'FUNCTION' 'CATEGORY' AclName 'TO' AclRoleTarget - a deny wins
// over every grant (spec 072)
arena_ptr<TransformResultValue> FinalizeGrantFunctionCategory(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto data = Call("acl_grant_function_category");
	data->args = {Value(RoleTargetOf(list.GetChild(5))), Value(NameOf(list.GetChild(3), "a category name")),
	              Value(KeywordOf(list.GetChild(0)) == "deny" ? "false" : "true")};
	return MgmtResult(transformer, std::move(data));
}

// AclRevokeFunctionCategory <- 'REVOKE' 'FUNCTION' 'CATEGORY' AclName 'FROM' AclRoleTarget: the row goes, grant or
// deny alike
arena_ptr<TransformResultValue> FinalizeRevokeFunctionCategory(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto data = Call("acl_revoke_function_category");
	data->args = {Value(RoleTargetOf(list.GetChild(5))), Value(NameOf(list.GetChild(3), "a category name"))};
	return MgmtResult(transformer, std::move(data));
}

//! A function grant by name (`acl_grant_function` / `acl_revoke_function`) or, for `platform.<f>`, platform's point
//! grant (spec 117) - which names no kind
arena_ptr<TransformResultValue> FunctionGrant(PEGTransformer &transformer, ParseResult &spec_part, const string &verb,
                                              const string &role) {
	string key;
	bool kind_written = false;
	auto spec = FunctionSpecOf(spec_part, key, kind_written);
	if (auto platform = PlatformGrantCall("function", key, verb, role)) {
		if (kind_written) {
			throw BinderException("acl admin: a function of the platform catalog is named without TABLE or SCALAR");
		}
		return MgmtResult(transformer, std::move(platform));
	}
	auto data = Call(verb == "revoke" ? "acl_revoke_function" : "acl_grant_function");
	data->args = {Value(role), Value(spec)};
	if (verb != "revoke") {
		data->args.emplace_back(verb == "deny" ? "false" : "true");
	}
	return MgmtResult(transformer, std::move(data));
}

// AclGrantFunction <- AclFunctionGrantVerb 'FUNCTION' AclFunctionSpec 'TO' AclRoleTarget - a grant by name admits the
// key whatever its categories
arena_ptr<TransformResultValue> FinalizeGrantFunction(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	return FunctionGrant(transformer, list.GetChild(2), KeywordOf(list.GetChild(0)), RoleTargetOf(list.GetChild(4)));
}

// AclRevokeFunction <- 'REVOKE' 'FUNCTION' AclFunctionSpec 'FROM' AclRoleTarget
arena_ptr<TransformResultValue> FinalizeRevokeFunction(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	return FunctionGrant(transformer, list.GetChild(2), "revoke", RoleTargetOf(list.GetChild(4)));
}

// AclDenyView <- 'DENY' 'VIEW' AclPath 'TO' AclRoleTarget - a view of the platform catalog (spec 117); a virtual
// catalog's view is narrowed by its grant, never denied
arena_ptr<TransformResultValue> FinalizeDenyView(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto data = PlatformGrantCall("view", PathOf(list.GetChild(2)), "deny", RoleTargetOf(list.GetChild(4)));
	if (!data) {
		throw BinderException("acl admin: DENY VIEW names a view of the platform catalog (platform.<view>)");
	}
	return MgmtResult(transformer, std::move(data));
}

// AclCreateFunctionCategory <- 'CREATE' AclOrReplace? 'FUNCTION' 'CATEGORY' AclName AclComment? - the operator's own
// category; a re-create keeps the members and grants and takes the new comment
arena_ptr<TransformResultValue> FinalizeCreateFunctionCategory(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto data = Call("acl_create_function_category");
	data->args = {Value(NameOf(list.GetChild(4), "a category name")), Value(string())};
	data->args[1] = Value(OptionalComment(transformer, list, 5, *data));
	return MgmtResult(transformer, std::move(data));
}

// AclAlterFunctionCategory <- 'ALTER' 'FUNCTION' 'CATEGORY' AclName AclCategoryChange - SET COMMENT '…' (it must
// exist; its members stay) | ADD (…) | DROP (…): the members as written, which the admin function parses
arena_ptr<TransformResultValue> FinalizeAlterFunctionCategory(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto category = NameOf(list.GetChild(3), "a category name");
	auto &change = Strip(list.GetChild(4)).Cast<ListParseResult>();
	if (change.Name() == "AclCategoryComment") {
		// AclCategoryComment <- 'SET' AclComment
		auto data = Call("acl_comment_function_category");
		data->args = {Value(category), Value(Quoted(transformer, ClauseList(change.GetChild(1)), 1, "comment", *data))};
		return MgmtResult(transformer, std::move(data));
	}
	// AclCategoryMembers <- AclCategoryVerb AclParenList (AclCategoryVerb <- 'ADD' / 'DROP')
	bool add = KeywordOf(change.GetChild(0)) == "add";
	auto &members = Strip(change.GetChild(1)).Cast<ListParseResult>();
	if (!members.Child<OptionalParseResult>(1).HasResult()) {
		throw BinderException("acl admin: ALTER FUNCTION CATEGORY %s the members in parentheses",
		                      add ? "ADD takes" : "DROP takes");
	}
	auto data = Call(add ? "acl_function_category_add" : "acl_function_category_remove");
	data->args = {Value(category), Value(string())};
	ParensInto(members, 1, MgmtParsed::TextKind::TEXT, false, *data);
	return MgmtResult(transformer, std::move(data));
}

// AclDropFunctionCategory <- 'DROP' 'FUNCTION' 'CATEGORY' AclIfExists? AclName - the members and every grant on it go
// too
arena_ptr<TransformResultValue> FinalizeDropFunctionCategory(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto data = Call("acl_drop_function_category");
	data->args = {Value(NameOf(list.GetChild(4), "a category name")), Value(DropMode(list, 3))};
	return MgmtResult(transformer, std::move(data));
}

// AclGrantSource <- 'GRANT' 'SOURCE' AclPath 'TO' 'ROLE' AclName / AclRevokeSource <- 'REVOKE' 'SOURCE' AclPath
// 'FROM' 'ROLE' AclName (spec 118.3): `<database>[.<schema>]`, the physical tree a catalog admin sees under
// platform.attached and the only sources it builds over; a revoke leaves what the role declared over it working
arena_ptr<TransformResultValue> FinalizeSourceGrant(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto data = Call(KeywordOf(list.GetChild(0)) == "grant" ? "acl_grant_source" : "acl_revoke_source");
	data->args = {Value(NameOf(list.GetChild(5), "a role name")), Value(PathOf(list.GetChild(2)))};
	return MgmtResult(transformer, std::move(data));
}

//! A resource group's limits `(window_max 64, batch_bytes '32MiB', …)` into argument `arg`, read once the tokens are
//! known (the compiler's ResourceLimitsJson)
void LimitsInto(ParseResult &paren_list, idx_t arg, MgmtParseData &data) {
	ParensInto(paren_list, arg, MgmtParsed::TextKind::LIMITS, false, data);
}

// AclCreateResourceGroup <- 'CREATE' AclOrReplace? 'RESOURCE' 'GROUP' AclName 'WITH'? AclParenList? AclGroupClause*
// (spec 085) - a re-create replaces the limits, the roles bound to it stay; DEFAULT (spec 096: the principals bound to
// no group are its members) and COMMENT in any order, each once
arena_ptr<TransformResultValue> FinalizeCreateResourceGroup(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto data = Call("acl_create_resource_group");
	data->args = {Value(NameOf(list.GetChild(4), "a group name")), Value("{}"), Value(string()), Value(string())};
	auto &limits = list.Child<OptionalParseResult>(6);
	if (limits.HasResult()) {
		LimitsInto(limits.GetResult(), 1, *data);
	}
	case_insensitive_set_t seen;
	for (auto &clause : Clauses(list, 7)) {
		auto &part = Strip(clause.get());
		if (part.Name() == "AclComment") {
			ClauseOnce(seen, "comment");
			data->args[2] = Value(Quoted(transformer, part.Cast<ListParseResult>(), 1, "comment", *data));
		} else {
			ClauseOnce(seen, "default"); // AclGroupDefault <- 'DEFAULT'
			data->args[3] = Value("true");
		}
	}
	return MgmtResult(transformer, std::move(data));
}

// AclAlterResourceGroup <- 'ALTER' 'RESOURCE' 'GROUP' AclName AclGroupChange (spec 096 / 120) - SET (limits): only the
// named limits change | SET COMMENT '…' | SET DEFAULT | DROP DEFAULT
arena_ptr<TransformResultValue> FinalizeAlterResourceGroup(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto data = Call("acl_alter_resource_group");
	data->args = {Value(NameOf(list.GetChild(3), "a group name")), Value(string()), Value(string())};
	auto &change = Strip(list.GetChild(4)).Cast<ListParseResult>();
	auto name = change.Name();
	if (name == "AclGroupSetLimits") {
		data->args[1] = Value("limits"); // AclGroupSetLimits <- 'SET' AclParenList
		LimitsInto(change.GetChild(1), 2, *data);
	} else if (name == "AclGroupSetComment") {
		data->args[1] = Value("comment"); // AclGroupSetComment <- 'SET' AclComment
		data->args[2] = Value(Quoted(transformer, ClauseList(change.GetChild(1)), 1, "comment", *data));
	} else {
		// AclGroupSetDefault <- 'SET' 'DEFAULT' / AclGroupDropDefault <- 'DROP' 'DEFAULT'
		data->args[1] = Value("default");
		data->args[2] = Value(name == "AclGroupSetDefault" ? "true" : "false");
	}
	return MgmtResult(transformer, std::move(data));
}

// AclDropResourceGroup <- 'DROP' 'RESOURCE' 'GROUP' AclIfExists? AclName - its role bindings go too
arena_ptr<TransformResultValue> FinalizeDropResourceGroup(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto data = Call("acl_drop_resource_group");
	data->args = {Value(NameOf(list.GetChild(4), "a group name")), Value(DropMode(list, 3))};
	return MgmtResult(transformer, std::move(data));
}

// AclGrantResourceGroup <- 'GRANT' 'RESOURCE' 'GROUP' AclName 'TO' 'ROLE' AclName / AclRevokeResourceGroup <- 'REVOKE'
// 'RESOURCE' 'GROUP' AclName 'FROM' 'ROLE' AclName
arena_ptr<TransformResultValue> FinalizeResourceGroupGrant(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto grant = KeywordOf(list.GetChild(0)) == "grant";
	auto data = Call(grant ? "acl_grant_resource_group" : "acl_revoke_resource_group");
	data->args = {Value(NameOf(list.GetChild(6), "a role name")), Value(NameOf(list.GetChild(3), "a group name"))};
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
		changes.push_back(GrammarChange::AddRule("AclAddSchema <- 'ADD' 'SCHEMA' AclPathName 'AS' AclPath",
		                                         Start<FinalizeAddSchema>));
		changes.push_back(GrammarChange::AddRule("AclAddMacro <- 'MACRO' AclBody"));
		changes.push_back(GrammarChange::AddRule("AclAddAlias <- 'ALIAS' 'OF'? AclPathName"));
		changes.push_back(GrammarChange::AddRule("AclAddDefinition <- AclAddMacro / AclAddAlias"));
		changes.push_back(GrammarChange::AddRule(
		    "AclAddFunction <- 'ADD' AclFunctionKind AclPath AclParenList? AclReturns? AclAddDefinition",
		    Start<FinalizeAddFunction>));
		changes.push_back(GrammarChange::AddRule(
		    "AclAddTable <- 'ADD' 'TABLE' AclPathName 'AS' AclPath AclColumnsClause? AclRlsClause?",
		    Start<FinalizeAddTable>));
		// the objects changed and dropped
		changes.push_back(GrammarChange::AddRule("AclRefOptionalSet <- 'OPTIONAL' AclWordToken"));
		changes.push_back(
		    GrammarChange::AddRule("AclReferenceSet <- AclComment / AclRefCardinality / AclRefOptionalSet"));
		changes.push_back(
		    GrammarChange::AddRule("AclAlterReference <- 'ALTER' 'VIRTUAL' 'REFERENCE' AclPath 'SET' AclReferenceSet",
		                           Start<FinalizeAlterReference>));
		changes.push_back(GrammarChange::AddRule(
		    "AclAlterCatalog <- 'ALTER' 'VIRTUAL' 'CATALOG' AclName 'SET' AclComment", Start<FinalizeAlterCatalog>));
		changes.push_back(GrammarChange::AddRule("AclDropKey <- 'DROP' 'PRIMARY' 'KEY'"));
		changes.push_back(GrammarChange::AddRule("AclSetKey <- 'SET' AclPrimaryKey"));
		changes.push_back(GrammarChange::AddRule("AclSetTypes <- 'SET' 'TYPES' AclList"));
		changes.push_back(GrammarChange::AddRule("AclSetBody <- 'SET' 'AS' AclBody"));
		changes.push_back(GrammarChange::AddRule("AclSetPhys <- 'SET' 'PHYS' AclPathName"));
		changes.push_back(GrammarChange::AddRule("AclSetColumns <- 'SET' AclColumnsClause"));
		changes.push_back(GrammarChange::AddRule("AclSetRls <- 'SET' AclRlsClause"));
		changes.push_back(GrammarChange::AddRule("AclSetMacro <- 'SET' 'MACRO' AclBody"));
		changes.push_back(GrammarChange::AddRule("AclSetAlias <- 'SET' 'ALIAS' 'OF'? AclPathName"));
		changes.push_back(GrammarChange::AddRule("AclViewChange <- AclDropKey / AclSetKey / AclSetTypes / AclSetBody"));
		changes.push_back(GrammarChange::AddRule("AclAlterView <- 'ALTER' 'VIRTUAL' 'VIEW' AclPath AclViewChange",
		                                         Start<FinalizeAlterRelation>));
		changes.push_back(
		    GrammarChange::AddRule("AclFunctionChange <- AclDropKey / AclSetKey / AclSetMacro / AclSetAlias"));
		changes.push_back(
		    GrammarChange::AddRule("AclAlterFunction <- 'ALTER' 'VIRTUAL' AclFunctionKind AclPath AclFunctionChange",
		                           Start<FinalizeAlterFunction>));
		changes.push_back(GrammarChange::AddRule(
		    "AclTableChange <- AclDropKey / AclSetKey / AclSetPhys / AclSetTypes / AclSetColumns / AclSetRls"));
		changes.push_back(GrammarChange::AddRule("AclAlterTable <- 'ALTER' 'VIRTUAL' 'TABLE' AclPath AclTableChange",
		                                         Start<FinalizeAlterRelation>));
		changes.push_back(GrammarChange::AddRule("AclPrune <- 'PRUNE'"));
		changes.push_back(GrammarChange::AddRule("AclRefresh <- 'REFRESH' AclPrune?"));
		changes.push_back(GrammarChange::AddRule("AclSetSchemaPhys <- 'SET' 'PHYS' AclPathName"));
		changes.push_back(GrammarChange::AddRule("AclSchemaChange <- AclRefresh / AclSetSchemaPhys"));
		changes.push_back(GrammarChange::AddRule("AclAlterSchema <- 'ALTER' 'VIRTUAL' 'SCHEMA' AclPath AclSchemaChange",
		                                         Start<FinalizeAlterSchema>));
		changes.push_back(
		    GrammarChange::AddRule("AclCommentReference <- 'COMMENT' 'ON' 'VIRTUAL' 'REFERENCE' AclPath 'IS' "
		                           "AclQuotedValue",
		                           Start<FinalizeCommentReference>));
		changes.push_back(GrammarChange::AddRule("AclCommentKind <- 'SCHEMA' / 'SCALAR' / 'TABLE' / 'VIEW'"));
		changes.push_back(GrammarChange::AddRule("AclCommentColumn <- 'COLUMN' AclName"));
		// a table function's form is a rule of its own: `TABLE function.t` is a table named in catalog `function`
		changes.push_back(GrammarChange::AddRule("AclCommentFunction <- 'COMMENT' 'ON' 'VIRTUAL' AclTableFunctionKind "
		                                         "AclPath AclCommentColumn? 'IS' AclQuotedValue",
		                                         Start<FinalizeCommentObject>));
		changes.push_back(GrammarChange::AddRule("AclCommentObject <- 'COMMENT' 'ON' 'VIRTUAL' AclCommentKind AclPath "
		                                         "AclCommentColumn? 'IS' AclQuotedValue",
		                                         Start<FinalizeCommentObject>));
		changes.push_back(GrammarChange::AddRule("AclCheckCatalog <- 'CHECK' 'VIRTUAL' 'CATALOG' AclName",
		                                         Start<FinalizeCheckCatalog>));
		changes.push_back(GrammarChange::AddRule("AclRemap <- 'REMAP' AclList"));
		changes.push_back(GrammarChange::AddRule("AclAndMasks <- 'AND' 'MASKS'"));
		changes.push_back(GrammarChange::AddRule("AclDropMissing <- 'DROP' 'MISSING' 'COLUMNS' AclAndMasks?"));
		changes.push_back(GrammarChange::AddRule("AclRepairAction <- AclRemap / AclDropMissing"));
		changes.push_back(GrammarChange::AddRule("AclRepairTable <- 'REPAIR' 'VIRTUAL' 'TABLE' AclPath AclRepairAction",
		                                         Start<FinalizeRepairTable>));
		changes.push_back(GrammarChange::AddRule("AclAnalyzeCatalog <- 'ANALYZE' 'VIRTUAL' 'CATALOG' AclName",
		                                         Start<FinalizeAnalyzeCatalog>));
		// the kind is read only before a path: `ANALYZE VIRTUAL table.t` names catalog `table`
		changes.push_back(GrammarChange::AddRule("AclAnalyzeKind <- 'SCALAR' / 'VIEW' / 'TABLE'"));
		changes.push_back(GrammarChange::AddRule("AclAnalyzeFunctionTarget <- AclTableFunctionKind AclPath"));
		changes.push_back(GrammarChange::AddRule("AclAnalyzeKindTarget <- AclAnalyzeKind AclPath"));
		changes.push_back(
		    GrammarChange::AddRule("AclAnalyzeTarget <- AclAnalyzeFunctionTarget / AclAnalyzeKindTarget / AclPath"));
		changes.push_back(GrammarChange::AddRule("AclAnalyzeObject <- 'ANALYZE' 'VIRTUAL' AclAnalyzeTarget",
		                                         Start<FinalizeAnalyzeObject>));
		changes.push_back(GrammarChange::AddRule("AclCascade <- 'CASCADE'"));
		changes.push_back(GrammarChange::AddRule("AclDropRelation <- 'DROP' 'RELATION' AclIfExists? AclPath",
		                                         Start<FinalizeDropRelation>));
		changes.push_back(GrammarChange::AddRule(
		    "AclDropReference <- 'DROP' 'VIRTUAL'? 'REFERENCE' AclIfExists? AclPath", Start<FinalizeDropReference>));
		changes.push_back(
		    GrammarChange::AddRule("AclDropCatalog <- 'DROP' 'VIRTUAL' 'CATALOG' AclIfExists? AclName AclCascade?",
		                           Start<FinalizeDropCatalog>));
		changes.push_back(GrammarChange::AddRule(
		    "AclDropSchema <- 'DROP' 'VIRTUAL' 'SCHEMA' AclIfExists? AclPath AclCascade?", Start<FinalizeDropSchema>));
		changes.push_back(GrammarChange::AddRule(
		    "AclDropFunction <- 'DROP' 'VIRTUAL' AclFunctionKind AclIfExists? AclPath", Start<FinalizeDropFunction>));
		changes.push_back(GrammarChange::AddRule("AclDropObjectKind <- 'TABLE' / 'VIEW'"));
		changes.push_back(GrammarChange::AddRule(
		    "AclDropObject <- 'DROP' 'VIRTUAL' AclDropObjectKind AclIfExists? AclPath", Start<FinalizeDropObject>));
		// grants
		changes.push_back(GrammarChange::AddRule("AclCapsEntry <- AclName?"));
		changes.push_back(GrammarChange::AddRule("AclCapsMore <- ',' AclCapsEntry"));
		changes.push_back(GrammarChange::AddRule("AclCapsList <- '(' AclCapsEntry AclCapsMore* ')'"));
		changes.push_back(GrammarChange::AddRule("AclWithCaps <- 'WITH' AclCapsList"));
		changes.push_back(GrammarChange::AddRule("AclCapsClause <- 'CAPS' AclQuotedValue"));
		changes.push_back(GrammarChange::AddRule("AclMainClause <- 'MAIN'"));
		changes.push_back(
		    GrammarChange::AddRule("AclObjectClause <- AclWithCaps / AclCapsClause / AclRlsClause / AclColumnsClause"));
		changes.push_back(GrammarChange::AddRule("AclGrantClause <- AclObjectClause / AclMainClause"));
		changes.push_back(
		    GrammarChange::AddRule("AclGrantCatalog <- 'GRANT' 'CATALOG' AclName 'TO' 'ROLE' AclName AclGrantClause*",
		                           Start<FinalizeGrantCatalog>));
		changes.push_back(GrammarChange::AddRule("AclInto <- 'INTO' AclPathName"));
		changes.push_back(GrammarChange::AddRule("AclVirtualOnly <- 'VIRTUAL' 'ONLY'"));
		changes.push_back(GrammarChange::AddRule("AclSchemaHome <- AclInto / AclVirtualOnly"));
		changes.push_back(GrammarChange::AddRule("AclGrantSchema <- 'GRANT' 'SCHEMA' AclPath 'TO' 'ROLE' AclName "
		                                         "AclObjectClause* AclSchemaHome? AclComment?",
		                                         Start<FinalizeGrantSchema>));
		changes.push_back(GrammarChange::AddRule("AclObjectKind <- 'TABLE' / 'VIEW' / 'OBJECT'"));
		changes.push_back(GrammarChange::AddRule(
		    "AclGrantObject <- 'GRANT' AclObjectKind AclPath 'TO' AclRoleTarget AclObjectClause*",
		    Start<FinalizeGrantObject>));
		changes.push_back(GrammarChange::AddRule("AclRevokeCatalog <- 'REVOKE' 'CATALOG' AclName 'FROM' 'ROLE' AclName",
		                                         Start<FinalizeRevokeCatalog>));
		changes.push_back(GrammarChange::AddRule("AclRevokeSchema <- 'REVOKE' 'SCHEMA' AclPath 'FROM' 'ROLE' AclName",
		                                         Start<FinalizeRevokeSchema>));
		changes.push_back(GrammarChange::AddRule(
		    "AclRevokeObject <- 'REVOKE' AclObjectKind AclPath 'FROM' AclRoleTarget", Start<FinalizeRevokeObject>));
		changes.push_back(GrammarChange::AddRule("AclSetRlsValue <- 'RLS' AclQuotedValue"));
		changes.push_back(GrammarChange::AddRule("AclSetColumnsValue <- 'COLUMNS' AclQuotedValue"));
		changes.push_back(GrammarChange::AddRule("AclSetMainValue <- 'MAIN' AclWordToken"));
		changes.push_back(GrammarChange::AddRule(
		    "AclGrantSet <- AclCapsClause / AclSetRlsValue / AclSetColumnsValue / AclSetMainValue"));
		changes.push_back(GrammarChange::AddRule(
		    "AclAlterGrant <- 'ALTER' 'GRANT' 'CATALOG' AclName 'TO' 'ROLE' AclName 'SET' AclGrantSet",
		    Start<FinalizeAlterGrant>));
		// issuers and clients (spec 095)
		changes.push_back(GrammarChange::AddRule("AclSecretIn <- 'IN' AclName"));
		changes.push_back(GrammarChange::AddRule("AclUrlClause <- 'URL' AclQuotedValue"));
		changes.push_back(GrammarChange::AddRule("AclFromSecret <- 'FROM' 'SECRET' AclNameValue AclSecretIn?"));
		changes.push_back(
		    GrammarChange::AddRule("AclClientSecret <- 'CLIENT' 'FROM' 'SECRET' AclNameValue AclSecretIn?"));
		changes.push_back(GrammarChange::AddRule("AclAudiences <- 'AUDIENCES' AclList"));
		changes.push_back(GrammarChange::AddRule("AclAzp <- 'AZP' AclList"));
		changes.push_back(GrammarChange::AddRule("AclRequire <- 'REQUIRE' AclList"));
		changes.push_back(GrammarChange::AddRule("AclRolesFrom <- 'ROLES' 'FROM' AclList"));
		changes.push_back(GrammarChange::AddRule("AclRolesConstant <- 'ROLES' 'CONSTANT' AclList"));
		changes.push_back(GrammarChange::AddRule("AclRoleClaim <- 'ROLE' 'CLAIM' AclQuotedValue"));
		changes.push_back(GrammarChange::AddRule("AclUnmappedAs <- 'IGNORE' / AclAsRole"));
		changes.push_back(GrammarChange::AddRule("AclAsRole <- 'AS' 'ROLE'"));
		changes.push_back(GrammarChange::AddRule("AclUnmapped <- 'UNMAPPED' AclUnmappedAs"));
		changes.push_back(GrammarChange::AddRule("AclAttributes <- 'ATTRIBUTES' AclList"));
		changes.push_back(GrammarChange::AddRule("AclClaimMap <- 'CLAIM' 'MAP' AclList"));
		changes.push_back(GrammarChange::AddRule("AclSubject <- 'SUBJECT' AclList"));
		changes.push_back(GrammarChange::AddRule("AclTokenType <- 'TOKEN' 'TYPE' AclQuotedValue"));
		changes.push_back(GrammarChange::AddRule("AclFlows <- 'FLOWS' AclList"));
		changes.push_back(GrammarChange::AddRule("AclClientId <- 'CLIENT' 'ID' AclQuotedValue"));
		// what is never written into the policy - read with its value, so the refusal says where it goes
		changes.push_back(GrammarChange::AddRule("AclClientSecretValue <- 'CLIENT' 'SECRET' AclList?"));
		changes.push_back(GrammarChange::AddRule("AclKeysWord <- 'KEYS' / 'ALGS'"));
		changes.push_back(GrammarChange::AddRule("AclKeysClause <- AclKeysWord AclList?"));
		changes.push_back(GrammarChange::AddRule(
		    "AclClientCommon <- AclAudiences / AclAzp / AclRequire / AclRolesFrom / AclRolesConstant / AclRoleClaim / "
		    "AclUnmapped / AclAttributes / AclClaimMap / AclSubject / AclTokenType / AclFlows / AclClientId / "
		    "AclClientSecretValue / AclKeysClause"));
		// the short form's clauses: the issuer's URL and secret, the implicit client's CLIENT FROM SECRET
		changes.push_back(GrammarChange::AddRule(
		    "AclIssuerClause <- AclUrlClause / AclFromSecret / AclClientSecret / AclClientCommon"));
		// a client's own: its FROM SECRET
		changes.push_back(GrammarChange::AddRule("AclClientClause <- AclFromSecret / AclClientCommon"));
		changes.push_back(GrammarChange::AddRule("AclIssuerName <- StringLiteral / AclNameToken"));
		changes.push_back(GrammarChange::AddRule(
		    "AclCreateIssuer <- 'CREATE' AclOrReplace? 'ISSUER' AclIfNotExists? AclIssuerName AclIssuerClause*",
		    Start<FinalizeCreateIssuer>));
		changes.push_back(GrammarChange::AddRule("AclCreateClient <- 'CREATE' AclOrReplace? 'CLIENT' AclIfNotExists? "
		                                         "AclNameValue 'ISSUER' AclNameValue AclClientClause*",
		                                         Start<FinalizeCreateClient>));
		changes.push_back(GrammarChange::AddRule("AclIssuerDropSecret <- 'DROP' 'CLIENT'? 'FROM' 'SECRET'"));
		changes.push_back(GrammarChange::AddRule("AclIssuerSet <- 'SET' AclIssuerClause+"));
		changes.push_back(GrammarChange::AddRule("AclIssuerChange <- AclIssuerDropSecret / AclIssuerSet"));
		changes.push_back(GrammarChange::AddRule("AclAlterIssuer <- 'ALTER' 'ISSUER' AclNameValue AclIssuerChange",
		                                         Start<FinalizeAlterIssuer>));
		changes.push_back(GrammarChange::AddRule("AclClientDropSecret <- 'DROP' 'FROM' 'SECRET'"));
		changes.push_back(GrammarChange::AddRule("AclClientSet <- 'SET' AclClientClause+"));
		changes.push_back(GrammarChange::AddRule("AclClientChange <- AclClientDropSecret / AclClientSet"));
		changes.push_back(GrammarChange::AddRule("AclAlterClient <- 'ALTER' 'CLIENT' AclNameValue AclClientChange",
		                                         Start<FinalizeAlterClient>));
		changes.push_back(GrammarChange::AddRule("AclIdentityKind <- 'ISSUER' / 'CLIENT'"));
		changes.push_back(GrammarChange::AddRule("AclDropIdentity <- 'DROP' AclIdentityKind AclIfExists? AclNameValue",
		                                         Start<FinalizeDropIdentity>));
		// function grants and categories (spec 072), platform's point grants (spec 117), sources (spec 118.3),
		// resource groups (spec 085)
		changes.push_back(GrammarChange::AddRule("AclAllRoles <- 'ALL' 'ROLES'"));
		changes.push_back(GrammarChange::AddRule("AclOneRole <- 'ROLE' AclName"));
		changes.push_back(GrammarChange::AddRule("AclRoleTarget <- AclAllRoles / AclOneRole"));
		changes.push_back(GrammarChange::AddRule("AclGrantFunctionKind <- 'TABLE' / 'SCALAR'"));
		changes.push_back(GrammarChange::AddRule("AclFunctionSpec <- AclPath AclGrantFunctionKind?"));
		changes.push_back(GrammarChange::AddRule("AclFunctionGrantVerb <- 'GRANT' / 'DENY'"));
		changes.push_back(GrammarChange::AddRule(
		    "AclGrantFunctionCategory <- AclFunctionGrantVerb 'FUNCTION' 'CATEGORY' AclName 'TO' AclRoleTarget",
		    Start<FinalizeGrantFunctionCategory>));
		changes.push_back(GrammarChange::AddRule(
		    "AclGrantFunction <- AclFunctionGrantVerb 'FUNCTION' AclFunctionSpec 'TO' AclRoleTarget",
		    Start<FinalizeGrantFunction>));
		changes.push_back(GrammarChange::AddRule(
		    "AclRevokeFunctionCategory <- 'REVOKE' 'FUNCTION' 'CATEGORY' AclName 'FROM' AclRoleTarget",
		    Start<FinalizeRevokeFunctionCategory>));
		changes.push_back(
		    GrammarChange::AddRule("AclRevokeFunction <- 'REVOKE' 'FUNCTION' AclFunctionSpec 'FROM' AclRoleTarget",
		                           Start<FinalizeRevokeFunction>));
		changes.push_back(
		    GrammarChange::AddRule("AclDenyView <- 'DENY' 'VIEW' AclPath 'TO' AclRoleTarget", Start<FinalizeDenyView>));
		changes.push_back(GrammarChange::AddRule(
		    "AclCreateFunctionCategory <- 'CREATE' AclOrReplace? 'FUNCTION' 'CATEGORY' AclName AclComment?",
		    Start<FinalizeCreateFunctionCategory>));
		changes.push_back(GrammarChange::AddRule("AclCategoryComment <- 'SET' AclComment"));
		changes.push_back(GrammarChange::AddRule("AclCategoryVerb <- 'ADD' / 'DROP'"));
		changes.push_back(GrammarChange::AddRule("AclCategoryMembers <- AclCategoryVerb AclParenList"));
		changes.push_back(GrammarChange::AddRule("AclCategoryChange <- AclCategoryComment / AclCategoryMembers"));
		changes.push_back(GrammarChange::AddRule(
		    "AclAlterFunctionCategory <- 'ALTER' 'FUNCTION' 'CATEGORY' AclName AclCategoryChange",
		    Start<FinalizeAlterFunctionCategory>));
		changes.push_back(
		    GrammarChange::AddRule("AclDropFunctionCategory <- 'DROP' 'FUNCTION' 'CATEGORY' AclIfExists? AclName",
		                           Start<FinalizeDropFunctionCategory>));
		changes.push_back(GrammarChange::AddRule("AclGrantSource <- 'GRANT' 'SOURCE' AclPath 'TO' 'ROLE' AclName",
		                                         Start<FinalizeSourceGrant>));
		changes.push_back(GrammarChange::AddRule("AclRevokeSource <- 'REVOKE' 'SOURCE' AclPath 'FROM' 'ROLE' AclName",
		                                         Start<FinalizeSourceGrant>));
		changes.push_back(GrammarChange::AddRule("AclGroupDefault <- 'DEFAULT'"));
		changes.push_back(GrammarChange::AddRule("AclGroupClause <- AclGroupDefault / AclComment"));
		changes.push_back(GrammarChange::AddRule("AclCreateResourceGroup <- 'CREATE' AclOrReplace? 'RESOURCE' 'GROUP' "
		                                         "AclName 'WITH'? AclParenList? AclGroupClause*",
		                                         Start<FinalizeCreateResourceGroup>));
		changes.push_back(GrammarChange::AddRule("AclGroupSetLimits <- 'SET' AclParenList"));
		changes.push_back(GrammarChange::AddRule("AclGroupSetComment <- 'SET' AclComment"));
		changes.push_back(GrammarChange::AddRule("AclGroupSetDefault <- 'SET' 'DEFAULT'"));
		changes.push_back(GrammarChange::AddRule("AclGroupDropDefault <- 'DROP' 'DEFAULT'"));
		changes.push_back(GrammarChange::AddRule(
		    "AclGroupChange <- AclGroupSetLimits / AclGroupSetComment / AclGroupSetDefault / AclGroupDropDefault"));
		changes.push_back(
		    GrammarChange::AddRule("AclAlterResourceGroup <- 'ALTER' 'RESOURCE' 'GROUP' AclName AclGroupChange",
		                           Start<FinalizeAlterResourceGroup>));
		changes.push_back(
		    GrammarChange::AddRule("AclDropResourceGroup <- 'DROP' 'RESOURCE' 'GROUP' AclIfExists? AclName",
		                           Start<FinalizeDropResourceGroup>));
		changes.push_back(
		    GrammarChange::AddRule("AclGrantResourceGroup <- 'GRANT' 'RESOURCE' 'GROUP' AclName 'TO' 'ROLE' AclName",
		                           Start<FinalizeResourceGroupGrant>));
		changes.push_back(GrammarChange::AddRule(
		    "AclRevokeResourceGroup <- 'REVOKE' 'RESOURCE' 'GROUP' AclName 'FROM' 'ROLE' AclName",
		    Start<FinalizeResourceGroupGrant>));
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
		    "AclAlterReference / AclAlterCatalog / AclAlterView / AclAlterFunction / AclAlterTable / AclAlterSchema / "
		    "AclCommentReference / AclCommentFunction / AclCommentObject / AclCheckCatalog / AclRepairTable / "
		    "AclAnalyzeCatalog / "
		    "AclAnalyzeObject / AclDropRelation / AclDropReference / AclDropCatalog / AclDropSchema / "
		    "AclDropFunction / AclDropObject / AclGrantCatalog / AclGrantSchema / AclGrantObject / AclRevokeCatalog / "
		    "AclRevokeSchema / AclRevokeObject / AclAlterGrant / AclCreateIssuer / AclCreateClient / AclAlterIssuer / "
		    "AclAlterClient / AclDropIdentity / AclGrantFunctionCategory / AclGrantFunction / "
		    "AclRevokeFunctionCategory / AclRevokeFunction / AclDenyView / AclCreateFunctionCategory / "
		    "AclAlterFunctionCategory / AclDropFunctionCategory / AclGrantSource / AclRevokeSource / "
		    "AclCreateResourceGroup / AclAlterResourceGroup / AclDropResourceGroup / AclGrantResourceGroup / "
		    "AclRevokeResourceGroup / AclMgmtLegacy"));
		// the batch holds management statements only: duckdb's own are not ours to read here
		changes.push_back(GrammarChange::ReplaceRule("Statement <- AclMgmtStatement", Start<FinalizeStatement>));
		return changes;
	}
};

const char *const TILING_REFUSAL = "acl admin: a list or a body does not read as written - its tokens do not tile it";

//! Whether duckdb's parser reads `next` as the continuation of the string `previous` - its StringLiteralMatcher's
//! rule: a quoted string (any prefix) then a plain `'…'` on a new line with no block comment between
bool JoinsStrings(const MatcherToken &previous, const MatcherToken &next) {
	auto quoted = [](const MatcherToken &token, const SpecialStringInfo &info) {
		return token.type == TokenType::STRING_LITERAL && info.prefix_len > 0 &&
		       token.text.size() >= info.prefix_len + 1 && token.text[info.prefix_len - 1] == '\'' &&
		       token.text.back() == '\'';
	};
	if (!next.preceded_by_newline || next.preceded_by_block_comment) {
		return false;
	}
	auto next_info = GetSpecialStringInfo(next.text);
	return next_info.type == SpecialStringCharacter::STANDARD && quoted(next, next_info) &&
	       quoted(previous, GetSpecialStringInfo(previous.text));
}

//! The text of the tokens in [start, end) - a list between its parentheses or a body - refused unless the tokens
//! tile it as written (only whitespace and comments between them: after a lone `$` duckdb's tokenizer places the next
//! token at the `$`). A gap that holds a comment is, when `comments_as_space`, a space - a line break where duckdb
//! would join the strings on its two sides (`'a' -- c⏎'b'` is `'ab'`), when the text's reader joins them as duckdb
//! does (`joins`) - else as written
string TokensText(const string &text, const TokenIterator &tokens, idx_t start, idx_t end, bool comments_as_space,
                  bool joins, const string &refusal, const std::function<void(const MatcherToken &)> &judge) {
	auto refuse = [&refusal]() {
		throw BinderException(refusal);
	};
	string inside;
	optional_idx previous_end;
	optional_ptr<const MatcherToken> previous;
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
				inside += joins && previous && JoinsStrings(*previous, token) ? "\n" : " ";
			} else {
				refuse();
			}
		}
		if (token.offset + token.length > end) {
			refuse();
		}
		inside += text.substr(token.offset, token.length);
		previous_end = token.offset + token.length;
		previous = &token;
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
//! readers split (`SplitTopLevel` knows `'…'` with `''` and `"…"` only) refuses a literal it would split into other
//! items than written - a `$$…$$` string, an `E'…'` one with a backslash, a backtick name - and one whose items its
//! reader takes as literals (`literal_items`: spec 095's lists) a string continued on the next line, which duckdb
//! joins (an item that is SQL - a mask, a REMAP expression - is read by duckdb, joined); one duckdb's parser reads
//! (`sql`) takes any
string ListText(const string &text, const TokenIterator &tokens, idx_t start, idx_t end, bool sql, bool literal_items) {
	if (!BetweenParentheses(text, start, end)) {
		throw BinderException(TILING_REFUSAL);
	}
	optional_ptr<const MatcherToken> previous;
	return TokensText(text, tokens, start, end, true, true, TILING_REFUSAL, [&](const MatcherToken &token) {
		if (sql) {
			return;
		}
		if (literal_items && previous && JoinsStrings(*previous, token)) {
			throw BinderException("acl admin: a list item is one literal - a string continued on the next line (which "
			                      "duckdb joins) is not read as one item here yet");
		}
		previous = &token;
		if (token.text.empty()) {
			return;
		}
		bool dollar = token.type == TokenType::STRING_LITERAL && token.text[0] == '$';
		bool escapes = token.type == TokenType::STRING_LITERAL && (token.text[0] == 'E' || token.text[0] == 'e') &&
		               StringUtil::Contains(token.text, "\\");
		if (dollar || escapes || token.text[0] == '`') {
			throw BinderException("acl admin: a list is written with '...' literals - a $$...$$ string, an E'...' one "
			                      "with a backslash and a backtick name are not read as one item here yet");
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
	optional_ptr<const MatcherToken> previous;
	return TokensText(
	    text, tokens, start, end, true, false, prefix + "its text does not read as written",
	    [&](const MatcherToken &token) {
		    if (previous && JoinsStrings(*previous, token)) {
			    refuse(
			        "a value is one literal (a string continued on the next line is not read as one value here yet)");
		    }
		    previous = &token;
		    if (token.type == TokenType::STRING_LITERAL && (token.text.empty() || token.text[0] != '\'')) {
			    refuse("a value is in single quotes (E'...' and $$...$$ are not read as one value here yet)");
		    }
		    if (!token.text.empty() && token.text[0] == '`') {
			    refuse("a backtick name is not read as one name here");
		    }
	    });
}

//! Why the management compiler cannot read the tokens in [start, end) as written, '' when it can: its scanner knows
//! `'…'` and `"…"` and whitespace only, so a comment, a `$$…$$` string, an `E'…'` string with a backslash or a
//! backtick name would be read as something else than duckdb reads (`WITH (select, /*, manage, */ insert)` granted
//! manage) - refused until its family is a rule
string LegacyUnreadable(const string &text, const TokenIterator &tokens, idx_t start, idx_t end) {
	optional_idx previous_end;
	for (idx_t index = grammar::FirstTokenFrom(tokens, start); index < tokens.Size(); index++) {
		auto &token = tokens.GetToken(index);
		if (token.offset >= end || token.type == TokenType::END_OF_INPUT || token.type == TokenType::TERMINATOR) {
			break;
		}
		if (previous_end.IsValid()) {
			if (token.offset < previous_end.GetIndex()) {
				return "its text does not read as written";
			}
			auto gap = text.substr(previous_end.GetIndex(), token.offset - previous_end.GetIndex());
			StringUtil::Trim(gap);
			if (!gap.empty()) {
				return "a comment";
			}
		}
		if (!token.text.empty() && token.type == TokenType::STRING_LITERAL && token.text[0] == '$') {
			return "a $$...$$ string";
		}
		if (token.type == TokenType::STRING_LITERAL && !token.text.empty() &&
		    (token.text[0] == 'E' || token.text[0] == 'e') && StringUtil::Contains(token.text, "\\")) {
			return "an E'...' string with a backslash";
		}
		if (!token.text.empty() && token.text[0] == '`') {
			return "a backtick name";
		}
		previous_end = token.offset + token.length;
	}
	return string();
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
	return TokensText(text, tokens, start, end, false, true, TILING_REFUSAL, [](const MatcherToken &) {});
}

//! A body read as what it is - one statement (a view's SQL, a table function's template) or one expression list (a
//! scalar's template, spec 148 judges the rest where it is written) - before anything of the batch runs: a `;` ends a
//! statement wherever it stands outside a literal, so a body cut by one (`AS SELECT [1; …`, `CASE … ; … END`) does
//! not parse, and a broken body is never stored
void JudgeBody(const string &body, const string &what, bool expression, const ParserOptions &options) {
	ParserOptions inner = options;
	inner.parser_override_setting = AllowParserOverride::DEFAULT_OVERRIDE;
	Parser parser(inner);
	idx_t statements = 1;
	try {
		if (expression) {
			parser.ParseExpressionList(body);
		} else {
			parser.ParseQuery(body);
			statements = parser.statements.size();
		}
	} catch (ParserException &error) {
		throw BinderException("acl admin: %s does not parse - %s", what, ErrorData(error).RawMessage());
	}
	if (statements != 1) {
		throw BinderException("acl admin: %s is one statement, not %llu", what, statements);
	}
}

} // namespace

namespace {

//! duckdb's tokenizer as the parser runs it, refusing nothing: an empty quoted name is a token, and the text ending
//! inside a comment, a string or a quoted name is noted (the parser's behavior throws for those)
class SplitTokenizerBehavior final : public TokenizerBehavior {
public:
	SplitTokenizerBehavior(const string &sql, vector<MatcherToken> &tokens) : TokenizerBehavior(sql, tokens) {
	}

	void PushToken(idx_t start, idx_t end, TokenType type, bool unterminated) override {
		if (type == TokenType::COMMENT && unterminated) {
			open = "unterminated /* comment";
		}
		TokenizerBehavior::PushToken(start, end, type, unterminated);
	}
	void OnStatementEnd(idx_t pos) override {
		tokens.emplace_back(";", pos, TokenType::TERMINATOR);
	}
	void OnLastToken(const Tokenizer &tokenizer, TokenizeState state, string last_word, idx_t last_pos) override {
		if (state == TokenizeState::STRING_LITERAL) {
			open = "unterminated string literal";
		} else if (state == TokenizeState::QUOTED_IDENTIFIER) {
			open = "unterminated quoted identifier";
		}
		TokenizerBehavior::OnLastToken(tokenizer, state, std::move(last_word), last_pos);
	}

	//! what the text ends inside, in the tokenizer's words ('' when nothing)
	string open;
};

} // namespace

vector<string> SplitMgmtStatements(shared_ptr<CompiledGrammar> compiled, const string &text) {
	vector<MatcherToken> tokens;
	SplitTokenizerBehavior behavior(text, tokens);
	compiled->GetTokenizer().TokenizeInput(behavior);
	auto open = behavior.open;
	for (auto &token : tokens) {
		if (open.empty() && token.unterminated) {
			open = "unterminated quoted string";
		}
	}
	if (!open.empty()) {
		throw ParserException("acl admin: %s - the batch ends inside it, and what that hides is never run without it",
		                      open);
	}
	vector<string> statements;
	optional_idx start;
	idx_t end = 0;
	auto flush = [&]() {
		if (start.IsValid()) {
			statements.push_back(text.substr(start.GetIndex(), end - start.GetIndex()));
		}
		start = optional_idx();
		end = 0;
	};
	for (auto &token : tokens) {
		if (token.type == TokenType::TERMINATOR) {
			flush();
		} else if (token.type != TokenType::END_OF_INPUT && token.type != TokenType::END_OF_INPUT_AUTOCOMPLETE) {
			start = start.IsValid() ? MinValue(start.GetIndex(), token.offset) : token.offset;
			end = MaxValue(end, token.offset + token.length);
		}
	}
	flush();
	return statements;
}

string JudgeLegacyText(shared_ptr<CompiledGrammar> compiled, const string &text) {
	vector<MatcherToken> owned;
	SplitTokenizerBehavior behavior(text, owned);
	compiled->GetTokenizer().TokenizeInput(behavior);
	TokenIterator tokens(owned);
	for (auto &token : owned) {
		if (token.type == TokenType::TERMINATOR) {
			return "a `;`"; // the judgment would stop there, the reader not
		}
	}
	auto why = LegacyUnreadable(text, tokens, 0, text.size());
	if (!why.empty()) {
		return why;
	}
	// the whole text: what stands before its first token or after its last is a comment too
	idx_t first = text.size();
	idx_t last = 0;
	for (auto &token : owned) {
		if (token.type != TokenType::END_OF_INPUT && token.type != TokenType::TERMINATOR) {
			first = MinValue(first, token.offset);
			last = MaxValue(last, token.offset + token.length);
		}
	}
	auto outside = first <= last ? text.substr(0, first) + text.substr(last) : text;
	StringUtil::Trim(outside);
	return outside.empty() ? string() : "a comment";
}

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
			parsed.unreadable =
			    LegacyUnreadable(text, tokens, tokens.GetToken(start).offset, last.offset + last.length);
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
			parsed.unreadable = LegacyUnreadable(text, tokens, data.start, data.end);
		} else {
			parsed.function = data.function;
			parsed.args = data.args;
			parsed.table_call = data.table_call;
			parsed.current_session = data.current_session;
			for (auto &span : data.spans) {
				string value;
				if (span.resolved) {
					value = span.text;
					if (span.judge) {
						// a quoted list is split by a reader of ours, which knows no comment
						auto why = JudgeLegacyText(compiled, value);
						if (!why.empty()) {
							throw BinderException("acl admin: %s in a quoted %s - its reader would read it otherwise "
							                      "than written; write the list in parentheses",
							                      why, span.what);
						}
					}
				} else if (span.body) {
					value = BodyText(text, tokens, span.start, span.end, span.what);
					JudgeBody(value, span.what, span.expression, options);
				} else if (span.kind == MgmtParsed::TextKind::CLAIMS) {
					value = ClaimsListText(text, tokens, span.start, span.end);
				} else {
					auto kind = span.kind;
					value =
					    ListText(text, tokens, span.start, span.end, span.sql,
					             kind == MgmtParsed::TextKind::ITEMS || kind == MgmtParsed::TextKind::REQUIRE ||
					                 kind == MgmtParsed::TextKind::ATTRIBUTES ||
					                 kind == MgmtParsed::TextKind::CLAIM_MAP || kind == MgmtParsed::TextKind::LIMITS);
				}
				parsed.texts.push_back(MgmtParsed::TextArg {span.arg, std::move(value), span.kind, span.splice});
			}
		}
		result.push_back(std::move(parsed));
	}
	return result;
}

} // namespace acl
} // namespace duckdb
