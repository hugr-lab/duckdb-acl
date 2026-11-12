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
		comment = comment || type == TokenType::COMMENT;
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
	//! the text holds a comment
	bool comment = false;
};

//! The reading of every build before 4e (`SplitTopLevel` and the first `=` of an item, wherever it stands)
vector<ListItemText> SplitListItemsAsStored(const string &text) {
	vector<ListItemText> items;
	idx_t from = 0;
	for (auto &part : SplitTopLevel(text, ',')) {
		if (part.empty()) {
			continue;
		}
		ListItemText item;
		item.text = part;
		auto at = text.find(part, from);
		item.end = at == string::npos ? text.size() : at + part.size();
		from = item.end;
		auto pos = part.find('=');
		if (pos != string::npos) {
			item.has_value = true;
			item.name = part.substr(0, pos);
			item.value = part.substr(pos + 1);
			StringUtil::Trim(item.name);
			StringUtil::Trim(item.value);
		}
		items.push_back(std::move(item));
	}
	return items;
}

} // namespace

vector<string> SplitTopLevel(const string &text, char delimiter) {
	vector<string> parts;
	string current;
	idx_t depth = 0;
	for (idx_t pos = 0; pos < text.size(); pos++) {
		auto c = text[pos];
		if (c == '\'' || c == '"') {
			auto quote = c;
			current += c;
			for (pos++; pos < text.size(); pos++) {
				current += text[pos];
				if (text[pos] == quote) {
					// a doubled quote is an escaped one, not the end of the literal
					if (pos + 1 < text.size() && text[pos + 1] == quote) {
						current += text[++pos];
						continue;
					}
					break;
				}
			}
			continue;
		}
		if (c == '(') {
			depth++;
		} else if (c == ')' && depth > 0) {
			depth--;
		} else if (c == delimiter && depth == 0) {
			parts.push_back(current);
			current.clear();
			continue;
		}
		current += c;
	}
	parts.push_back(current);
	for (auto &part : parts) {
		StringUtil::Trim(part);
	}
	return parts;
}

vector<ListItemText> SplitListItems(const string &text, bool *open, bool *comment) {
	vector<MatcherToken> tokens;
	ListTokenizerBehavior behavior(text, tokens);
	CompiledGrammar::DefaultGrammar()->GetTokenizer().TokenizeInput(behavior);
	if (open) {
		*open = behavior.open;
		for (auto &token : tokens) {
			*open = *open || token.unterminated;
		}
	}
	if (comment) {
		*comment = behavior.comment;
	}
	if (behavior.comment) {
		return SplitListItemsAsStored(text);
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
		// or `>=` they are none) - but an operator token that starts with `=` after the item's name is that `=` and its
		// mask's first operator, as the text reader split it (`ssn=~ssn`, `x=@x`: the tokenizer joins `=~`)
		auto c = token.type == TokenType::OPERATOR && token.text.size() == 1 ? token.text[0] : '\0';
		if (token.type == TokenType::OPERATOR && token.text.size() > 1 && token.text[0] == '=' && depth == 0 &&
		    first.IsValid() && !equals.IsValid()) {
			equals = token.offset;
			equals_end = token.offset + 1;
		}
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

bool StoresBare(const string &name) {
	if (name.empty() || name.find_first_of(".[") != string::npos || name[0] == '"') {
		return false;
	}
	bool open = false, comment = false;
	auto items = SplitListItems(name, &open, &comment);
	return !open && !comment && items.size() == 1 && !items[0].has_value && items[0].text == name;
}

} // namespace acl
} // namespace duckdb
