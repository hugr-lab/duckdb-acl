#include "acl_grammar.hpp"

#include "duckdb/common/sql_identifier.hpp"
#include "duckdb/main/client_config.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/extension_callback_manager.hpp"
#include "duckdb/parser/grammar_change.hpp"
#include "duckdb/parser/grammar_extension.hpp"
#include "duckdb/parser/parsed_data/create_info.hpp"
#include "duckdb/parser/parser.hpp"
#include "duckdb/parser/parser_extension.hpp"
#include "duckdb/parser/peg/compiled_grammar.hpp"
#include "duckdb/parser/peg/transformer/peg_transformer.hpp"
#include "duckdb/parser/statement/create_statement.hpp"
#include "duckdb/parser/statement/extension_statement.hpp"

#include <mutex>

namespace duckdb {
namespace acl {
namespace {

//! What the prefix rule yields: an ExtensionStatement of ours carrying the principal, the markers and
//! the statement behind them. It never leaves the override - and if it ever reached the binder, the
//! plan function refuses it.
struct PrefixParseData : ParserExtensionParseData {
	string role;
	string correlation_id;
	string traceparent;
	unique_ptr<SQLStatement> statement;
	//! where the statement starts, counted from the prefix's first token, and in the whole text
	idx_t statement_offset = 0;
	idx_t statement_start = 0;
	//! where the prefix itself starts in the whole text
	optional_idx prefix_start;

	unique_ptr<ParserExtensionParseData> Copy() const override {
		auto copy = make_uniq<PrefixParseData>();
		copy->role = role;
		copy->correlation_id = correlation_id;
		copy->traceparent = traceparent;
		copy->statement = statement ? statement->Copy() : nullptr;
		copy->statement_offset = statement_offset;
		copy->statement_start = statement_start;
		copy->prefix_start = prefix_start;
		return std::move(copy);
	}
	string ToString() const override {
		return "ACL ROLE " + SQLIdentifier::ToString(role) + " " + (statement ? statement->ToString() : "");
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

//! The base rule under one of our helper rules (a choice, or a list of one part): ours have no transform
ParseResult &BaseOf(ParseResult &result) {
	if (result.type == ParseResultType::CHOICE) {
		return BaseOf(result.Cast<ChoiceParseResult>().GetResult());
	}
	if (result.type == ParseResultType::LIST && StringUtil::StartsWith(result.Name(), "Acl")) {
		auto &list = result.Cast<ListParseResult>();
		if (list.GetChildren().size() == 1) {
			return BaseOf(list.GetChild(0));
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

// AclPrefixedStatement <- 'ACL' 'ROLE' AclQuotedValue AclTraceMarker* Statement?
arena_ptr<TransformResultValue> FinalizePrefixed(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto data = make_uniq<PrefixParseData>();
	data->prefix_start = parse_result.offset;
	data->role = transformer.Transform<string>(BaseOf(list.GetChild(2)));
	vector<reference<ParseResult>> markers;
	Collect(list.GetChild(3), markers);
	for (auto &marker_result : markers) {
		// AclTraceMarker <- AclTraceWord AclQuotedValue
		auto &marker = marker_result.get().Cast<ListParseResult>();
		bool trace = KeywordOf(marker.GetChild(0)) == "trace";
		auto &target = trace ? data->correlation_id : data->traceparent;
		if (!target.empty()) {
			throw ParserException("acl_rewrite: ACL %s may be written once in a prefix", trace ? "TRACE" : "PARENT");
		}
		target = transformer.Transform<string>(BaseOf(marker.GetChild(1)));
	}
	auto &optional_statement = list.Child<OptionalParseResult>(4);
	if (!optional_statement.HasResult()) {
		// a prefix with no statement of its own (`ACL ROLE "r";`, a batch whose first part is empty), as the scanner
		// reads it: the statements after it are still the prefix's
		unique_ptr<SQLStatement> result = make_uniq<ExtensionStatement>(PrefixExtension(), std::move(data));
		return transformer.MakeResult<unique_ptr<SQLStatement>>(std::move(result));
	}
	auto &statement_result = optional_statement.GetResult();
	auto statement = transformer.Transform<unique_ptr<SQLStatement>>(statement_result);
	if (IsPrefixStatement(*statement)) {
		throw ParserException("acl_rewrite: a prefix inside a prefix is refused");
	}
	// what duckdb's top level does for a statement (ExtractAndTransformStatement), done here for ours: the
	// parameters on it, its PIVOT enums inside the prefix - never beside it (spec 075) - and the parameters on
	// the wrapper too; taken, so the top level does not wrap the prefix in them again
	if (!transformer.named_parameter_map.empty()) {
		statement->named_param_map = transformer.named_parameter_map;
	}
	if (!transformer.pivot_entries.empty()) {
		statement = transformer.CreatePivotStatement(std::move(statement));
		statement->named_param_map = transformer.named_parameter_map;
		transformer.pivot_entries.clear();
	}
	if (!parse_result.offset.IsValid() || !statement_result.offset.IsValid() ||
	    statement_result.offset.GetIndex() < parse_result.offset.GetIndex()) {
		// the statement's own text is cut from here: without it the prefix would be in it
		throw ParserException("acl_rewrite: the ACL prefix's statement has no position");
	}
	data->statement_offset = statement_result.offset.GetIndex() - parse_result.offset.GetIndex();
	data->statement_start = statement_result.offset.GetIndex();
	data->statement = std::move(statement);
	unique_ptr<SQLStatement> result = make_uniq<ExtensionStatement>(PrefixExtension(), std::move(data));
	return transformer.MakeResult<unique_ptr<SQLStatement>>(std::move(result));
}

arena_ptr<TransformProcess> StartPrefixed(PEGTransformer &transformer, ParseResult &parse_result) {
	return transformer.MakeProcess<FinalizeTransformProcess>(transformer, parse_result, FinalizePrefixed);
}

class AclPrefixGrammar final : public GrammarExtension {
public:
	AclPrefixGrammar() : GrammarExtension("acl", "acl: the ACL prefix (spec 150, stage 1)") {
	}

	vector<GrammarChange> GetChanges() const override {
		vector<GrammarChange> changes;
		changes.push_back(GrammarChange::AddRule(
		    "AclPrefixedStatement <- 'ACL' 'ROLE' AclQuotedValue AclTraceMarker* Statement?", StartPrefixed));
		// a value is any quoted text, as the scanner reads it ('…' or "…"); the value itself is no keyword to offer
		changes.push_back(GrammarChange::AddRule("AclQuotedValue <- StringLiteral / Identifier", nullptr,
		                                         /*suppress_suggestions=*/true));
		changes.push_back(GrammarChange::AddRule("AclTraceMarker <- AclTraceWord AclQuotedValue", nullptr,
		                                         /*suppress_suggestions=*/true));
		changes.push_back(GrammarChange::AddRule("AclTraceWord <- 'TRACE' / 'PARENT'"));
		changes.push_back(GrammarChange::PrependChoice("Statement", "AclPrefixedStatement"));
		return changes;
	}
};

} // namespace

struct AclGrammarCache::Impl {
	shared_ptr<AclPrefixGrammar> grammar = make_shared_ptr<AclPrefixGrammar>();
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
				// the connection switched ours on itself (CLI completion): it goes behind the others, once
				if (extension && extension->Name() != grammar->Name()) {
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
	return impl->grammar;
}

bool AclGrammarCache::ParsePrefixed(const string &query, const ParserOptions &options, PegPrefix &out) {
	auto context = options.context;
	if (context) {
		auto &config = ClientConfig::GetConfig(*context);
		if (config.connected_grammar || config.current_dialect) {
			return false;
		}
	}
	ParserOptions inner = options;
	inner.parser_override_setting = AllowParserOverride::DEFAULT_OVERRIDE;
	inner.compiled_grammar = impl->For(context);
	Parser parser(inner);
	parser.ParseQuery(query);
	if (parser.statements.empty() || !IsPrefixStatement(*parser.statements[0])) {
		throw ParserException("acl_rewrite: the ACL prefix did not parse as a prefix");
	}
	for (idx_t i = 0; i < parser.statements.size(); i++) {
		auto &statement = parser.statements[i];
		if (i > 0) {
			if (IsPrefixStatement(*statement)) {
				throw ParserException("acl_rewrite: a batch carries one prefix");
			}
			out.statements.push_back(std::move(statement));
			continue;
		}
		auto &data = statement->Cast<ExtensionStatement>().parse_data->Cast<PrefixParseData>();
		auto parsed_start = data.prefix_start;
		out.role = data.role;
		out.correlation_id = data.correlation_id;
		out.traceparent = data.traceparent;
		out.has_statement = data.statement != nullptr;
		out.statement_start = data.statement_start;
		if (!data.statement) {
			// where the prefix's own part of the text ends: past its separators, at the next statement
			if (!parsed_start.IsValid()) {
				throw ParserException("acl_rewrite: the ACL prefix has no position");
			}
			out.statement_start = parsed_start.GetIndex() + statement->query.size();
			continue;
		}
		auto inner_statement = std::move(data.statement);
		// the statement's own text, as the scanner's inner parse gave it: the prefix's text past the markers
		inner_statement->query =
		    statement->query.substr(MinValue<idx_t>(data.statement_offset, statement->query.size()));
		inner_statement->stmt_location = QueryLocation(0, inner_statement->query.size());
		if (inner_statement->type == StatementType::CREATE_STATEMENT) {
			inner_statement->Cast<CreateStatement>().info->sql = inner_statement->query;
		}
		out.statements.push_back(std::move(inner_statement));
	}
	return true;
}

bool PegPrefixEnabled(const ParserOptions &options) {
	if (!options.context) {
		return false;
	}
	Value value;
	auto &db = DatabaseInstance::GetDatabase(*options.context);
	return db.TryGetCurrentSetting("acl_peg_prefix", value) && !value.IsNull() && value.GetValue<bool>();
}

} // namespace acl
} // namespace duckdb
