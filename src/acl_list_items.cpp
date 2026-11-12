#include "acl_list_items.hpp"

#include "duckdb/common/string_util.hpp"
#include "duckdb/parser/peg/compiled_grammar.hpp"
#include "duckdb/parser/peg/tokenizer/tokenizer.hpp"

namespace duckdb {
namespace acl {

namespace {

//! duckdb's tokenizer as its parser runs it, refusing nothing: a stored list is read, not judged (an open literal
//! runs to the end of the text, as duckdb reads it); a `;` is a token of the item it stands in
class ListTokenizerBehavior final : public TokenizerBehavior {
public:
	ListTokenizerBehavior(const string &sql, vector<MatcherToken> &tokens) : TokenizerBehavior(sql, tokens) {
	}
	void PushToken(idx_t start, idx_t end, TokenType type, bool unterminated) override {
		open = open || unterminated;
		TokenizerBehavior::PushToken(start, end, type, unterminated);
	}
	void OnStatementEnd(idx_t pos) override {
		tokens.emplace_back(";", pos, TokenType::TERMINATOR);
	}
	void OnLastToken(const Tokenizer &tokenizer, TokenizeState state, string last_word, idx_t last_pos) override {
		open = open || Tokenizer::IsUnterminatedState(state);
		TokenizerBehavior::OnLastToken(tokenizer, state, std::move(last_word), last_pos);
	}

	//! the text ends inside a comment, a literal or a quoted name
	bool open = false;
};

} // namespace

vector<ListItemText> SplitListItems(const string &text, bool *open) {
	vector<MatcherToken> tokens;
	ListTokenizerBehavior behavior(text, tokens);
	CompiledGrammar::DefaultGrammar()->GetTokenizer().TokenizeInput(behavior);
	if (open) {
		*open = behavior.open;
		for (auto &token : tokens) {
			*open = *open || token.unterminated;
		}
	}
	vector<ListItemText> items;
	optional_idx first, equals;
	idx_t last_end = 0, equals_end = 0;
	auto flush = [&]() {
		if (!first.IsValid()) {
			return;
		}
		ListItemText item;
		item.text = text.substr(first.GetIndex(), last_end - first.GetIndex());
		item.end = last_end;
		if (equals.IsValid()) {
			item.has_value = true;
			item.name = text.substr(first.GetIndex(), equals.GetIndex() - first.GetIndex());
			item.value = equals_end < last_end ? text.substr(equals_end, last_end - equals_end) : string();
			StringUtil::Trim(item.name);
			StringUtil::Trim(item.value);
		}
		items.push_back(std::move(item));
		first.SetInvalid();
		equals.SetInvalid();
	};
	idx_t depth = 0;
	for (auto &token : tokens) {
		if (token.type == TokenType::END_OF_INPUT || token.type == TokenType::END_OF_INPUT_AUTOCOMPLETE) {
			break;
		}
		// a bracket, a comma and `=` are operator tokens of one character (inside a literal or a quoted name, a comment
		// or `>=` they are none)
		auto c = token.type == TokenType::OPERATOR && token.text.size() == 1 ? token.text[0] : '\0';
		if (c == ',' && depth == 0) {
			flush();
			continue;
		}
		if (c == '(' || c == '[' || c == '{') {
			depth++;
		} else if ((c == ')' || c == ']' || c == '}') && depth > 0) {
			depth--;
		} else if (c == '=' && depth == 0 && first.IsValid() && !equals.IsValid()) {
			equals = token.offset;
			equals_end = token.offset + token.length;
		}
		if (!first.IsValid()) {
			first = token.offset;
		}
		last_end = MaxValue(last_end, token.offset + token.length);
	}
	flush();
	return items;
}

} // namespace acl
} // namespace duckdb
