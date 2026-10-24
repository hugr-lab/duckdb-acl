#include "acl_grammar.hpp"

#include "duckdb/common/error_data.hpp"
#include "duckdb/common/operator/cast_operators.hpp"
#include "duckdb/common/sql_identifier.hpp"
#include "duckdb/main/client_config.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/extension_callback_manager.hpp"
#include "duckdb/parser/grammar_change.hpp"
#include "duckdb/parser/grammar_extension.hpp"
#include "duckdb/parser/parser.hpp"
#include "duckdb/parser/parser_extension.hpp"
#include "duckdb/parser/peg/compiled_grammar.hpp"
#include "duckdb/parser/peg/passthrough_dialect.hpp"
#include "duckdb/parser/peg/tokenizer/parser_tokenizer.hpp"
#include "duckdb/parser/peg/transformer/peg_transformer.hpp"
#include "duckdb/parser/statement/extension_statement.hpp"
#include "duckdb/parser/token_iterator.hpp"

#include <mutex>

namespace duckdb {
namespace acl {
namespace {

//! What the prefix rule yields: an ExtensionStatement of ours carrying what the head says. It never
//! leaves the override - and one that reached the binder (the registered rules switched on, the
//! override off) is refused by the plan function.
struct PrefixParseData : ParserExtensionParseData {
	string kind;
	string value;
	optional_idx value_offset;
	struct Marker {
		GrammarPrefix::MarkerKind kind;
		string value;
		optional_idx offset;
	};
	vector<Marker> markers;
	idx_t lineage_written = 0;
	bool mode_written = false;
	bool native = false;
	//! where the rest passed through as tokens starts (none when the head is all there is)
	optional_idx tail_offset;

	unique_ptr<ParserExtensionParseData> Copy() const override {
		return make_uniq<PrefixParseData>(*this);
	}
	string ToString() const override {
		return "ACL " + StringUtil::Upper(kind); // never the value: a token or a session handle
	}
};

ParserExtensionPlanResult RefusePrefixPlan(ParserExtensionInfo *, ClientContext &,
                                           unique_ptr<ParserExtensionParseData>) {
	throw BinderException("acl: a prefixed statement is planned only through the acl override (spec 150)");
}

ParserExtension PrefixExtension() {
	ParserExtension extension;
	extension.plan_function = RefusePrefixPlan;
	return extension;
}

bool IsPrefixStatement(const SQLStatement &statement) {
	return statement.type == StatementType::EXTENSION_STATEMENT &&
	       statement.Cast<ExtensionStatement>().extension.plan_function == RefusePrefixPlan;
}

//! The results a rule part holds: an optional one's result if any, a repetition's children, else itself
void Collect(ParseResult &result, vector<reference<ParseResult>> &out) {
	if (result.type == ParseResultType::OPTIONAL) {
		auto &optional = result.Cast<OptionalParseResult>();
		if (optional.HasResult()) {
			Collect(optional.GetResult(), out);
		}
		return;
	}
	if (result.type == ParseResultType::REPEAT) {
		for (auto &child : result.Cast<RepeatParseResult>().GetChildren()) {
			out.push_back(child);
		}
		return;
	}
	out.push_back(result);
}

//! Under one of our helper rules: the choice taken, a list of one part - ours have no transform
ParseResult &Strip(ParseResult &result) {
	if (result.type == ParseResultType::CHOICE) {
		return Strip(result.Cast<ChoiceParseResult>().GetResult());
	}
	if (result.type == ParseResultType::OPTIONAL && result.Cast<OptionalParseResult>().HasResult()) {
		return Strip(result.Cast<OptionalParseResult>().GetResult());
	}
	if (result.type == ParseResultType::LIST && StringUtil::StartsWith(result.Name(), "Acl")) {
		auto &list = result.Cast<ListParseResult>();
		if (list.GetChildren().size() == 1) {
			return Strip(list.GetChild(0));
		}
	}
	return result;
}

//! The keyword a rule part matched, lower-cased ('' when it holds none)
string KeywordOf(ParseResult &result) {
	switch (result.type) {
	case ParseResultType::KEYWORD:
		return StringUtil::Lower(result.Cast<KeywordParseResult>().keyword);
	case ParseResultType::CHOICE:
		return KeywordOf(result.Cast<ChoiceParseResult>().GetResult());
	case ParseResultType::LIST:
		for (auto &child : result.Cast<ListParseResult>().GetChildren()) {
			auto keyword = KeywordOf(child.get());
			if (!keyword.empty()) {
				return keyword;
			}
		}
		return string();
	default:
		return string();
	}
}

//! A quoted value (`AclQuotedValue <- StringLiteral / Identifier`): its text and where its token starts
string ValueOf(PEGTransformer &transformer, ParseResult &result, optional_idx &offset) {
	auto &base = Strip(result);
	offset = base.offset;
	return transformer.Transform<string>(base);
}

// AclPrefixedStatement <- 'ACL' AclPrincipal AclMarker* AclMode? AclTail?
arena_ptr<TransformResultValue> FinalizePrefix(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto data = make_uniq<PrefixParseData>();
	// AclPrincipal <- AclPrincipalWord AclQuotedValue / 'ADMIN'
	auto &principal = Strip(list.GetChild(1));
	data->kind = KeywordOf(principal);
	if (principal.type == ParseResultType::LIST) {
		data->value = ValueOf(transformer, principal.Cast<ListParseResult>().GetChild(1), data->value_offset);
	}
	vector<reference<ParseResult>> markers;
	Collect(list.GetChild(2), markers);
	for (auto &marker_result : markers) {
		auto &marker = Strip(marker_result.get()).Cast<ListParseResult>();
		if (KeywordOf(marker) == "lineage") {
			// AclLineageMarker <- 'LINEAGE' AclLineagePart+, AclLineagePart <- AclLineageWord AclQuotedValue
			data->lineage_written++;
			vector<reference<ParseResult>> parts;
			Collect(marker.GetChild(1), parts);
			for (auto &part_result : parts) {
				auto &part = Strip(part_result.get()).Cast<ListParseResult>();
				PrefixParseData::Marker entry;
				auto word = KeywordOf(part.GetChild(0));
				entry.kind = word == "parent" ? GrammarPrefix::MarkerKind::LINEAGE_PARENT
				             : word == "root" ? GrammarPrefix::MarkerKind::LINEAGE_ROOT
				                              : GrammarPrefix::MarkerKind::LINEAGE_JOB;
				entry.value = ValueOf(transformer, part.GetChild(1), entry.offset);
				data->markers.push_back(std::move(entry));
			}
			continue;
		}
		// AclTraceMarker <- AclTraceWord AclQuotedValue
		PrefixParseData::Marker entry;
		entry.kind = KeywordOf(marker.GetChild(0)) == "trace" ? GrammarPrefix::MarkerKind::TRACE
		                                                      : GrammarPrefix::MarkerKind::PARENT;
		entry.value = ValueOf(transformer, marker.GetChild(1), entry.offset);
		data->markers.push_back(std::move(entry));
	}
	// AclMode <- 'ACL' AclNative?
	auto &mode = list.Child<OptionalParseResult>(3);
	if (mode.HasResult()) {
		data->mode_written = true;
		auto &mode_list = Strip(mode.GetResult()).Cast<ListParseResult>();
		data->native = mode_list.GetChildren().size() > 1 && mode_list.Child<OptionalParseResult>(1).HasResult();
	}
	auto &tail = list.Child<OptionalParseResult>(4);
	if (tail.HasResult()) {
		data->tail_offset = tail.GetResult().offset;
		if (!data->tail_offset.IsValid()) {
			// the rest is cut from here: without its position the head would be read as part of it
			throw ParserException("acl_rewrite: the ACL prefix's rest has no position");
		}
	}
	unique_ptr<SQLStatement> result = make_uniq<ExtensionStatement>(PrefixExtension(), std::move(data));
	return transformer.MakeResult<unique_ptr<SQLStatement>>(std::move(result));
}

arena_ptr<TransformProcess> StartPrefix(PEGTransformer &transformer, ParseResult &parse_result) {
	return transformer.MakeProcess<FinalizeTransformProcess>(transformer, parse_result, FinalizePrefix);
}

//! The rules. The override's variant passes the rest through as tokens - it is parsed as its own text
//! afterwards, by whatever reads that mode - and the registered one (completion only) offers a statement
class AclPrefixGrammar final : public GrammarExtension {
public:
	AclPrefixGrammar(string name, bool passthrough_tail_p)
	    : GrammarExtension(std::move(name), "acl: the ACL prefix (spec 150)"), passthrough_tail(passthrough_tail_p) {
	}

	vector<GrammarChange> GetChanges() const override {
		vector<GrammarChange> changes;
		changes.push_back(GrammarChange::AddRule(
		    "AclPrefixedStatement <- 'ACL' AclPrincipal AclMarker* AclMode? AclTail?", StartPrefix));
		changes.push_back(GrammarChange::AddRule("AclPrincipal <- AclPrincipalWord AclQuotedValue / 'ADMIN'"));
		changes.push_back(GrammarChange::AddRule("AclPrincipalWord <- 'ROLE' / 'TOKEN' / 'SESSION' / 'INGEST'"));
		// a value is quoted text, '…' or "…" (the reader refuses anything but one literal written plainly); the
		// value itself is no keyword to offer
		changes.push_back(GrammarChange::AddRule("AclQuotedValue <- StringLiteral / Identifier", nullptr,
		                                         /*suppress_suggestions=*/true));
		changes.push_back(GrammarChange::AddRule("AclMarker <- AclLineageMarker / AclTraceMarker"));
		changes.push_back(GrammarChange::AddRule("AclTraceMarker <- AclTraceWord AclQuotedValue"));
		changes.push_back(GrammarChange::AddRule("AclTraceWord <- 'TRACE' / 'PARENT'"));
		changes.push_back(GrammarChange::AddRule("AclLineageMarker <- 'LINEAGE' AclLineagePart+"));
		changes.push_back(GrammarChange::AddRule("AclLineagePart <- AclLineageWord AclQuotedValue"));
		changes.push_back(GrammarChange::AddRule("AclLineageWord <- 'PARENT' / 'ROOT' / 'JOB'"));
		changes.push_back(GrammarChange::AddRule("AclMode <- 'ACL' AclNative?"));
		changes.push_back(GrammarChange::AddRule("AclNative <- 'NATIVE'"));
		if (passthrough_tail) {
			// any token up to the statement's end, the way duckdb's own passthrough dialect matches one
			changes.push_back(GrammarChange::AddRule("AclTailToken <- Identifier"));
			changes.push_back(GrammarChange::AddTerminalRuleOverride(
			    "AclTailToken",
			    [](const PEGKeywordHelper &) -> unique_ptr<Matcher> { return make_uniq<PassthroughTokenMatcher>(); }));
			changes.push_back(GrammarChange::AddRule("AclTail <- AclTailToken+"));
		} else {
			changes.push_back(GrammarChange::AddRule("AclTail <- Statement"));
		}
		changes.push_back(GrammarChange::PrependChoice("Statement", "AclPrefixedStatement"));
		return changes;
	}

private:
	bool passthrough_tail;
};

//! The text a value's token must be: the value in its quotes, written plainly - so a string the tokenizer
//! joins across a line break, an escape string or an unquoted name never stands for the value
bool WrittenPlainly(const string &query, const MatcherToken &token, const string &value) {
	if (token.offset + token.length > query.size() || query.compare(token.offset, token.length, token.text) != 0) {
		return false;
	}
	if (token.text.empty() || (token.text[0] != '\'' && token.text[0] != '"')) {
		return false;
	}
	auto quote = token.text[0];
	string written(1, quote);
	written += StringUtil::Replace(value, string(1, quote), string(2, quote));
	written += quote;
	return token.text == written;
}

//! The token starting at `offset` (the tokens come in text order), or none
optional_idx TokenIndexAt(const TokenIterator &tokens, idx_t offset) {
	for (idx_t i = 0; i < tokens.Size(); i++) {
		auto &token = tokens.GetToken(i);
		if (token.offset > offset) {
			break;
		}
		if (token.offset == offset && token.type != TokenType::END_OF_INPUT) {
			return i;
		}
	}
	return optional_idx();
}

//! The kinds, as the rule's `AclPrincipalWord` and `'ADMIN'` spell them
bool TryKindOf(const string &word, GrammarPrefix::Kind &kind) {
	static constexpr struct {
		const char *word;
		GrammarPrefix::Kind kind;
	} KINDS[] = {{"role", GrammarPrefix::Kind::ROLE},
	             {"token", GrammarPrefix::Kind::TOKEN},
	             {"session", GrammarPrefix::Kind::SESSION},
	             {"ingest", GrammarPrefix::Kind::INGEST},
	             {"admin", GrammarPrefix::Kind::ADMIN}};
	for (auto &entry : KINDS) {
		if (StringUtil::CIEquals(word, entry.word)) {
			kind = entry.kind;
			return true;
		}
	}
	return false;
}

//! `ACL <kind>`: the text's first two tokens - anything else is not a prefix of ours
bool StartsWithPrefix(const TokenIterator &tokens) {
	GrammarPrefix::Kind kind;
	return tokens.Size() >= 2 && StringUtil::CIEquals(tokens.GetToken(0).text, "acl") &&
	       TryKindOf(tokens.GetToken(1).text, kind);
}

} // namespace

const char *MarkerWords(GrammarPrefix::MarkerKind kind) {
	switch (kind) {
	case GrammarPrefix::MarkerKind::TRACE:
		return "TRACE";
	case GrammarPrefix::MarkerKind::PARENT:
		return "PARENT";
	case GrammarPrefix::MarkerKind::LINEAGE_PARENT:
		return "LINEAGE PARENT";
	case GrammarPrefix::MarkerKind::LINEAGE_ROOT:
		return "LINEAGE ROOT";
	case GrammarPrefix::MarkerKind::LINEAGE_JOB:
		return "LINEAGE JOB";
	}
	return "";
}

struct AclGrammarCache::Impl {
	//! what the override parses with, never registered; and what a connection may switch on
	shared_ptr<AclPrefixGrammar> grammar = make_shared_ptr<AclPrefixGrammar>("acl_prefix_head", true);
	shared_ptr<AclPrefixGrammar> registered = make_shared_ptr<AclPrefixGrammar>("acl", false);
	std::mutex lock;
	//! the caller's grammar extensions, in order -> the grammar compiled with ours behind them
	vector<pair<vector<string>, shared_ptr<CompiledGrammar>>> compiled;
	static constexpr idx_t MAX_COMPILED = 16;

	shared_ptr<CompiledGrammar> For(optional_ptr<ClientContext> context) {
		vector<string> names;
		vector<reference<GrammarExtension>> extensions;
		if (context) {
			auto &config = ClientConfig::GetConfig(*context);
			auto &callbacks = ExtensionCallbackManager::Get(*context);
			for (auto &name : config.active_grammar_extensions) {
				auto extension = callbacks.FindGrammarExtension(name);
				// the registered rules are ours: the override's own take their place
				if (extension && extension->Name() != registered->Name()) {
					names.push_back(extension->Name());
					extensions.emplace_back(*extension);
				}
			}
		}
		extensions.emplace_back(*grammar);
		std::lock_guard<std::mutex> guard(lock);
		for (auto &entry : compiled) {
			if (entry.first == names) {
				return entry.second;
			}
		}
		auto result = CompiledGrammar::Create(extensions);
		if (compiled.size() >= MAX_COMPILED) {
			compiled.erase(compiled.begin());
		}
		compiled.emplace_back(std::move(names), result);
		return result;
	}
};

AclGrammarCache::AclGrammarCache() : impl(make_uniq<Impl>()) {
}

AclGrammarCache::~AclGrammarCache() {
}

shared_ptr<GrammarExtension> AclGrammarCache::Extension() const {
	return impl->registered;
}

bool AclGrammarCache::ReadPrefix(const string &query, const ParserOptions &options, GrammarPrefix &out) {
	auto context = options.context;
	ParserOptions inner = options;
	inner.parser_override_setting = AllowParserOverride::DEFAULT_OVERRIDE;
	inner.compiled_grammar = impl->For(context);
	auto tokenize = [&](const string &text) {
		auto owned = make_uniq<vector<MatcherToken>>();
		ParserTokenizerBehavior behavior(text, *owned);
		inner.compiled_grammar->GetTokenizer().TokenizeInput(behavior);
		return owned;
	};
	unique_ptr<vector<MatcherToken>> owned;
	try {
		owned = tokenize(query);
	} catch (ParserException &ex) {
		// a text duckdb's tokenizer refuses past the head is the rest's to report, where its mode reads it - after
		// the principal is judged, and under ACL NATIVE by whichever parser it reaches (spec 067): the head is read
		// from the text before the refusal. One inside the head leaves a head that does not read.
		ErrorData error(ex);
		auto entry = error.ExtraInfo().find("position");
		idx_t at = 0;
		if (entry == error.ExtraInfo().end() || !TryCast::Operation(string_t(entry->second), at, false) || at == 0 ||
		    at > query.size()) {
			throw;
		}
		owned = tokenize(query.substr(0, at));
	}
	TokenIterator tokens(std::move(owned));
	if (!StartsWithPrefix(tokens)) {
		return false;
	}
	if (context) {
		auto &config = ClientConfig::GetConfig(*context);
		if (config.connected_grammar || config.current_dialect) {
			// a grammar of the connection owner's choosing: nothing of ours can be added to it, and nothing
			// there runs as a principal
			throw ParserException("acl_rewrite: an ACL prefix is refused on a CONNECT-ed connection or under a "
			                      "dialect - DISCONNECT, or RESET current_dialect");
		}
	}
	// a principal's value must follow its kind as a quoted token - said here, in the words a client knows, rather than
	// as the rule's syntax error at whatever came instead
	TryKindOf(tokens.GetToken(1).text, out.kind);
	auto kind_word = StringUtil::Lower(tokens.GetToken(1).text);
	if (out.kind != GrammarPrefix::Kind::ADMIN) {
		auto value_quoted = tokens.Size() > 2 && !tokens.GetToken(2).text.empty() &&
		                    (tokens.GetToken(2).text[0] == '\'' || tokens.GetToken(2).text[0] == '"');
		if (!value_quoted) {
			if (kind_word == "ingest") {
				throw ParserException("acl_rewrite: ACL INGEST requires a quoted session handle");
			}
			throw ParserException("acl_rewrite: ACL %s requires a quoted value", StringUtil::Upper(kind_word));
		}
	}
	// the head and the rest of its statement, passed through; the statements after it are the rest's
	TokenIterator cursor(tokens);
	Parser parser(inner);
	unique_ptr<SQLStatement> statement;
	try {
		statement = parser.ParseTopLevelStatement(cursor);
	} catch (ParserException &) {
		// never the parser's own message: it draws the text - a token, a session handle - under its caret
		throw ParserException("acl_rewrite: the ACL prefix does not parse");
	}
	if (!statement || !IsPrefixStatement(*statement)) {
		throw ParserException("acl_rewrite: the ACL prefix does not parse");
	}
	auto &data = statement->Cast<ExtensionStatement>().parse_data->Cast<PrefixParseData>();
	auto require_plain = [&](const optional_idx &offset, const string &value, const string &what) {
		auto index = offset.IsValid() ? TokenIndexAt(tokens, offset.GetIndex()) : optional_idx();
		if (!index.IsValid() || !WrittenPlainly(query, tokens.GetToken(index.GetIndex()), value)) {
			throw ParserException("acl_rewrite: ACL %s requires a quoted value, written as one plain literal", what);
		}
	};
	if (out.kind != GrammarPrefix::Kind::ADMIN) {
		require_plain(data.value_offset, data.value, StringUtil::Upper(data.kind));
		if (data.value.empty()) {
			throw ParserException("acl_rewrite: ACL %s requires a value", StringUtil::Upper(data.kind));
		}
		out.value = data.value;
	}
	for (auto &marker : data.markers) {
		require_plain(marker.offset, marker.value, MarkerWords(marker.kind));
		out.markers.push_back(GrammarPrefix::Marker {marker.kind, marker.value});
	}
	// a marker word whose value did not read is where the rule stopped: said in the words a client knows, rather than
	// as the rest's syntax error (the mode marker ends the markers - after it such a word is the rest's)
	if (!data.mode_written && data.tail_offset.IsValid()) {
		auto first = TokenIndexAt(tokens, data.tail_offset.GetIndex());
		auto word = first.IsValid() ? StringUtil::Lower(tokens.GetToken(first.GetIndex()).text) : string();
		bool after_lineage = !data.markers.empty() && data.markers.back().kind != GrammarPrefix::MarkerKind::TRACE &&
		                     data.markers.back().kind != GrammarPrefix::MarkerKind::PARENT;
		if (word == "trace" || (word == "parent" && !after_lineage)) {
			throw ParserException("acl_rewrite: ACL %s requires a quoted value", StringUtil::Upper(word));
		}
		if (word == "lineage") {
			auto next = first.GetIndex() + 1 < tokens.Size()
			                ? StringUtil::Lower(tokens.GetToken(first.GetIndex() + 1).text)
			                : string();
			if (next == "parent" || next == "root" || next == "job") {
				throw ParserException("acl_rewrite: ACL LINEAGE %s requires a quoted value", StringUtil::Upper(next));
			}
			throw ParserException("acl_rewrite: ACL LINEAGE needs PARENT, ROOT or JOB");
		}
		if (after_lineage && (word == "parent" || word == "root" || word == "job")) {
			throw ParserException("acl_rewrite: ACL LINEAGE %s requires a quoted value", StringUtil::Upper(word));
		}
	}
	out.lineage_written = data.lineage_written;
	out.mode_written = data.mode_written;
	out.native = data.native;
	// the rest starts past the head's last token and the whitespace after it
	idx_t head_end = 0;
	auto head_tokens = cursor.Position();
	for (idx_t i = 0; i < head_tokens && i < tokens.Size(); i++) {
		auto &token = tokens.GetToken(i);
		if (data.tail_offset.IsValid() && token.offset >= data.tail_offset.GetIndex()) {
			break;
		}
		if (token.type == TokenType::TERMINATOR || token.type == TokenType::END_OF_INPUT) {
			break;
		}
		head_end = token.offset + token.length;
	}
	while (head_end < query.size() && StringUtil::CharacterIsSpace(query[head_end])) {
		head_end++;
	}
	out.rest_start = head_end;
	return true;
}

} // namespace acl
} // namespace duckdb
