//===----------------------------------------------------------------------===//
// acl_grammar_util.hpp
//
// Spec 150: what the rules of our grammar share - reading a parse result of a helper rule (ours have no
// transform: the base rule under it is transformed), the keyword a part matched, a quoted value and the
// token it was written as - and the seam to the management statements' grammar. Private to acl_grammar.cpp
// and acl_mgmt_grammar.cpp.
//===----------------------------------------------------------------------===//

#pragma once

#include "acl_grammar.hpp"

#include "duckdb/common/string_util.hpp"
#include "duckdb/parser/peg/transformer/parse_result.hpp"
#include "duckdb/parser/peg/transformer/peg_transformer.hpp"
#include "duckdb/parser/token_iterator.hpp"

namespace duckdb {
namespace acl {
namespace grammar {

//! The results a rule part holds: an optional one's result if any, a repetition's children, else itself
inline void Collect(ParseResult &result, vector<reference<ParseResult>> &out) {
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
inline ParseResult &Strip(ParseResult &result) {
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
inline string KeywordOf(ParseResult &result) {
	switch (result.type) {
	case ParseResultType::KEYWORD:
		return StringUtil::Lower(result.Cast<KeywordParseResult>().keyword);
	case ParseResultType::CHOICE:
		return KeywordOf(result.Cast<ChoiceParseResult>().GetResult());
	case ParseResultType::OPTIONAL:
		return result.Cast<OptionalParseResult>().HasResult()
		           ? KeywordOf(result.Cast<OptionalParseResult>().GetResult())
		           : string();
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

//! A quoted value (`StringLiteral / Identifier` under a helper rule): its text and where its token starts
inline string ValueOf(PEGTransformer &transformer, ParseResult &result, optional_idx &offset) {
	auto &base = Strip(result);
	offset = base.offset;
	return transformer.Transform<string>(base);
}

//! The token starting at `offset`, or none - the tokens come in text order, so it is a binary search (a batch of
//! many statements asks once per quoted value)
inline optional_idx TokenIndexAt(const TokenIterator &tokens, idx_t offset) {
	idx_t low = 0;
	idx_t high = tokens.Size();
	while (low < high) {
		auto middle = low + (high - low) / 2;
		if (tokens.GetToken(middle).offset < offset) {
			low = middle + 1;
		} else {
			high = middle;
		}
	}
	if (low < tokens.Size() && tokens.GetToken(low).offset == offset &&
	    tokens.GetToken(low).type != TokenType::END_OF_INPUT) {
		return low;
	}
	return optional_idx();
}

//! A rule's transform process: its parse result finalized by FINALIZE
template <arena_ptr<TransformResultValue> (*FINALIZE)(PEGTransformer &, ParseResult &)>
arena_ptr<TransformProcess> Start(PEGTransformer &transformer, ParseResult &parse_result) {
	return transformer.MakeProcess<FinalizeTransformProcess>(transformer, parse_result, FINALIZE);
}

//! The text a value's token must be: the value in its quotes, written plainly - so a string the tokenizer
//! joins across a line break, an escape string or an unquoted name never stands for the value
inline bool WrittenPlainly(const string &query, const MatcherToken &token, const string &value) {
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

} // namespace grammar

//! spec 150, stage 3 (acl_mgmt_grammar.cpp): the management statements' rules, compiled by AclGrammarCache, and a
//! batch read with them
shared_ptr<GrammarExtension> MakeMgmtGrammar();
vector<MgmtParsed> ReadMgmtStatements(shared_ptr<CompiledGrammar> compiled, const string &text,
                                      const ParserOptions &options);

} // namespace acl
} // namespace duckdb
