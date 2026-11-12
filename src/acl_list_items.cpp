#include "acl_list_items.hpp"

#include "duckdb/common/exception.hpp"
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

namespace {

vector<MatcherToken> ListTokens(const string &text, bool *open, bool *comment) {
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
	return tokens;
}

vector<ListItemText> SplitOnTokens(const string &text, const vector<MatcherToken> &tokens);

} // namespace

vector<ListItemText> SplitListItems(const string &text, bool *open, bool *comment) {
	bool has_comment = false;
	auto tokens = ListTokens(text, open, &has_comment);
	if (comment) {
		*comment = has_comment;
	}
	// a literal the text reader did not know - a `$…$` string, an `E'…'` one, a backtick name - is read with it too: a
	// row an older build stored with one (`id, $$'$$, ssn, x'`) was read inside the `'` it opened, duckdb's tokens read
	// `ssn` out of it; since 4e a writer stores such a list only if this reading gives its items back
	bool legacy = has_comment;
	for (auto &token : tokens) {
		auto &written = token.text;
		legacy = legacy || (!written.empty() &&
		                    (written[0] == '`' || (token.type == TokenType::STRING_LITERAL &&
		                                           (written[0] == '$' || written[0] == 'E' || written[0] == 'e'))));
	}
	if (legacy) {
		return SplitListItemsAsStored(text);
	}
	return SplitOnTokens(text, tokens);
}

namespace {

vector<ListItemText> SplitOnTokens(const string &text, const vector<MatcherToken> &tokens) {
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
	// the brackets open, innermost last: a closer ends only the bracket it matches (`x(], ssn` stays inside the `(`, as
	// the text reader read it)
	string open_brackets;
	for (auto &token : tokens) {
		if (token.type == TokenType::END_OF_INPUT || token.type == TokenType::END_OF_INPUT_AUTOCOMPLETE) {
			break;
		}
		// a bracket, a comma and `=` are operator tokens of one character (inside a literal or a quoted name, a comment
		// or `>=` they are none) - but an operator token that starts with `=` after the item's name is that `=` and its
		// mask's first operator, as the text reader split it (`ssn=~ssn`, `x=@x`: the tokenizer joins `=~`)
		auto c = token.type == TokenType::OPERATOR && token.text.size() == 1 ? token.text[0] : '\0';
		bool top = open_brackets.empty();
		if (token.type == TokenType::OPERATOR && token.text.size() > 1 && token.text[0] == '=' && top &&
		    first.IsValid() && !equals.IsValid()) {
			equals = token.offset;
			equals_end = token.offset + 1;
		}
		if (c == ',' && top) {
			flush();
			continue;
		}
		if (c == '(' || c == '[' || c == '{') {
			open_brackets += c;
		} else if (c == ')' || c == ']' || c == '}') {
			auto opener = c == ')' ? '(' : c == ']' ? '[' : '{';
			if (!top && open_brackets.back() == opener) {
				open_brackets.pop_back();
			}
		} else if (c == '=' && top && first.IsValid() && !equals.IsValid()) {
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

string Trimmed(string text) {
	StringUtil::Trim(text);
	return text;
}

//! A token that is the word `word` as written bare (a keyword or an identifier, never a literal or a quoted name)
bool IsWord(const MatcherToken &token, const char *word) {
	return token.type != TokenType::STRING_LITERAL && !token.text.empty() && token.text[0] != '"' &&
	       StringUtil::CIEquals(token.text, word);
}

//! The tokens of `text` outside every bracket (a bracket at the top is one of them)
vector<MatcherToken> TopTokens(const string &text) {
	vector<MatcherToken> top;
	string open_brackets;
	for (auto &token : ListTokens(text, nullptr, nullptr)) {
		if (token.type == TokenType::END_OF_INPUT || token.type == TokenType::END_OF_INPUT_AUTOCOMPLETE) {
			break;
		}
		auto c = token.type == TokenType::OPERATOR && token.text.size() == 1 ? token.text[0] : '\0';
		if (open_brackets.empty()) {
			top.push_back(token);
		}
		if (c == '(' || c == '[' || c == '{') {
			open_brackets += c;
		} else if ((c == ')' || c == ']' || c == '}') && !open_brackets.empty() &&
		           open_brackets.back() == (c == ')'   ? '('
		                                    : c == ']' ? '['
		                                               : '{')) {
			open_brackets.pop_back();
		}
	}
	return top;
}

//! A trailing nullability mark (spec 048) taken off `text`: `NOT NULL` after something (never `IS NOT NULL`), and -
//! for a column's own name, never after an expression, where a bare `NULL` is the mask's value - `NULL`
string TakeMark(const string &text, bool expression, int8_t &mark) {
	auto top = TopTokens(text);
	auto n = top.size();
	if (n >= 3 && IsWord(top[n - 2], "not") && IsWord(top[n - 1], "null") && !IsWord(top[n - 3], "is")) {
		mark = 0;
		return Trimmed(text.substr(0, top[n - 2].offset));
	}
	if (!expression && n >= 2 && IsWord(top[n - 1], "null") && !IsWord(top[n - 2], "not")) {
		mark = 1;
		return Trimmed(text.substr(0, top[n - 1].offset));
	}
	return text;
}

//! A declared column's name as written: one quoted name is the name it quotes; anything else as it stands (a word, a
//! path, the function form's raw text)
string DeclaredName(const string &text, const char *what, bool *quoted = nullptr) {
	vector<MatcherToken> tokens;
	for (auto &token : ListTokens(text, nullptr, nullptr)) {
		if (token.type != TokenType::END_OF_INPUT && token.type != TokenType::END_OF_INPUT_AUTOCOMPLETE) {
			tokens.push_back(token);
		}
	}
	string name = text;
	auto quote = tokens.size() == 1 && !tokens[0].text.empty() ? tokens[0].text[0] : '\0';
	if (tokens.size() == 1 && tokens[0].type != TokenType::STRING_LITERAL && tokens[0].text.size() >= 2 &&
	    (quote == '"' || quote == '`') && tokens[0].offset == 0 && tokens[0].length == text.size()) {
		// a backtick name is a quoted name to duckdb too
		auto doubled = string(2, quote);
		name = StringUtil::Replace(text.substr(1, text.size() - 2), doubled, string(1, quote));
		if (quoted) {
			*quoted = true;
		}
		if (name.empty()) {
			throw BinderException("acl admin: %s holds an item that names no column", what);
		}
		if (name.find_first_of(".[") != string::npos || name[0] == '"') {
			throw BinderException("acl admin: %s declares the column \"%s\" - a declared column's name holds no '.' "
			                      "or '[' and starts with no '\"' (the list reads it as a path into a column)",
			                      what, name);
		}
	}
	// a path written with spaces (`s . x`, `items [ ] . price`) is the path duckdb's tokens read: its tokens joined -
	// only a path's own shape, a name and then `. name` or `[ ]` steps (`my col.x` stays the text it is)
	auto is_word = [](const MatcherToken &token) {
		return (token.type == TokenType::IDENTIFIER || token.type == TokenType::KEYWORD) && !token.text.empty();
	};
	auto is_step = [](const MatcherToken &token, const char *step) {
		// a `.` standing alone is a number token to duckdb's tokenizer
		return (token.type == TokenType::OPERATOR || token.type == TokenType::NUMBER_LITERAL) && token.text == step;
	};
	bool path = tokens.size() > 1 && is_word(tokens[0]);
	for (idx_t i = 1; path && i < tokens.size();) {
		if (is_step(tokens[i], "[]")) {
			i++;
		} else if (is_step(tokens[i], "[") && i + 1 < tokens.size() && is_step(tokens[i + 1], "]")) {
			i += 2;
		} else if (is_step(tokens[i], ".") && i + 1 < tokens.size() && is_word(tokens[i + 1])) {
			i += 2;
		} else {
			path = false;
		}
	}
	if (path) {
		name.clear();
		for (auto &token : tokens) {
			name += token.text;
		}
	}
	if (name.empty() || (!tokens.empty() && tokens[0].type == TokenType::OPERATOR && tokens[0].text[0] == '=')) {
		throw BinderException("acl admin: %s holds an item that names no column", what);
	}
	return name;
}

} // namespace

vector<DeclaredColumnText> SplitDeclaredColumns(const string &text, const char *what) {
	bool open = false, comment = false;
	auto tokens = ListTokens(text, &open, &comment);
	if (open || comment) {
		throw BinderException("acl admin: %s holds a comment or ends inside a literal or a quoted name - it does not "
		                      "stay one expression per item (spec 148); write it without comments",
		                      what);
	}
	vector<DeclaredColumnText> columns;
	for (auto &item : SplitOnTokens(text, tokens)) {
		DeclaredColumnText column;
		// `expr AS name` (SQL's spelling) is `name = expr`: the last `AS` outside every bracket (a CAST's is inside
		// it) - read first, as the rule does, so `CASE WHEN a = 1 THEN x END AS u` is u and `k = id AS y` is y = (k =
		// id)
		auto top = TopTokens(item.text);
		optional_idx as;
		for (idx_t i = 1; i + 1 < top.size(); i++) {
			if (IsWord(top[i], "as")) {
				as = i;
			}
		}
		// ... unless a top-level `=` stands after it: `name as text = upper(a)` is the function form's raw name `name
		// as text`, as the text reader read it (the rule refuses it)
		for (idx_t i = as.IsValid() ? as.GetIndex() + 1 : top.size(); i < top.size(); i++) {
			if (top[i].type == TokenType::OPERATOR && top[i].text[0] == '=') {
				as.SetInvalid();
				break;
			}
		}
		if (as.IsValid()) {
			auto &word = top[as.GetIndex()];
			auto named = Trimmed(item.text.substr(word.offset + word.length));
			// the alias is one word (the rule's `ColLabel`), a mark after it - `x AS NOT NULL` is the name `NOT` and a
			// NULL mark, as the rule reads it; else as written (the function form's raw name)
			auto words = TopTokens(named);
			int8_t after = -1;
			if (words.size() >= 2 &&
			    Trimmed(TakeMark("x " + Trimmed(named.substr(words[1].offset)), false, after)) == "x" && after >= 0) {
				named = Trimmed(named.substr(0, words[1].offset));
				column.nullable = after;
			} else {
				named = TakeMark(named, false, column.nullable);
			}
			column.name = DeclaredName(named, what, &column.quoted);
			int8_t mark = -1;
			column.expr = TakeMark(Trimmed(item.text.substr(0, word.offset)), true, mark);
			if (mark >= 0 && column.nullable >= 0) {
				throw BinderException("acl admin: %s gives \"%s\" two NULL marks - write one", what, column.name);
			}
			if (mark >= 0) {
				column.nullable = mark; // `expr NOT NULL AS name`, as the text reader read it
			}
		} else if (item.has_value) {
			column.name = DeclaredName(item.name, what, &column.quoted);
			column.expr = TakeMark(item.value, true, column.nullable);
		} else {
			column.name = DeclaredName(TakeMark(item.text, false, column.nullable), what, &column.quoted);
		}
		columns.push_back(std::move(column));
	}
	return columns;
}

bool StoresBare(const string &name) {
	// a bracket, a quote, `$` or a backtick in a name: quoted, whatever the split would make of it beside other items
	if (name.empty() || name.find_first_of(".[](){}'\"`$") != string::npos) {
		return false;
	}
	bool open = false, comment = false;
	auto items = SplitListItems(name, &open, &comment);
	return !open && !comment && items.size() == 1 && !items[0].has_value && items[0].text == name;
}

} // namespace acl
} // namespace duckdb
