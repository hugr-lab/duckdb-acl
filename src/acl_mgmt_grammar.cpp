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
		// a statement no rule reads yet: its tokens, to the management compiler
		changes.push_back(GrammarChange::AddRule("AclTailToken <- Identifier"));
		changes.push_back(
		    GrammarChange::AddTerminalRuleOverride("AclTailToken", [](const PEGKeywordHelper &) -> unique_ptr<Matcher> {
			    return make_uniq<PassthroughTokenMatcher>();
		    }));
		changes.push_back(GrammarChange::AddRule("AclMgmtLegacy <- AclTailToken+", Start<FinalizeLegacy>));
		changes.push_back(GrammarChange::AddRule(
		    "AclMgmtStatement <- AclKillSession / AclSessionAuditLevel / AclProfileSession / AclNodeOperation / "
		    "AclMigrateCatalog / AclMgmtLegacy"));
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
			if (!index.IsValid() || tokens.GetToken(index.GetIndex()).text.empty() ||
			    tokens.GetToken(index.GetIndex()).text[0] == '"') {
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
		}
		result.push_back(std::move(parsed));
	}
	return result;
}

} // namespace acl
} // namespace duckdb
