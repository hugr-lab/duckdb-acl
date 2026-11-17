#include "acl_list_items.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/parser/peg/compiled_grammar.hpp"
#include "duckdb/parser/peg/tokenizer/tokenizer.hpp"
#include "duckdb/common/error_data.hpp"
#include "duckdb/parser/expression/columnref_expression.hpp"
#include "duckdb/parser/expression/constant_expression.hpp"
#include "duckdb/parser/expression/star_expression.hpp"
#include "duckdb/parser/expression/lambda_expression.hpp"
#include "duckdb/parser/expression/function_expression.hpp"
#include "duckdb/parser/keyword_helper.hpp"
#include "duckdb/parser/parsed_expression_iterator.hpp"
#include "duckdb/parser/parser.hpp"
#include "duckdb/parser/query_node/select_node.hpp"
#include "duckdb/parser/statement/select_statement.hpp"
#include "duckdb/parser/statement/update_statement.hpp"
#include "duckdb/parser/query_node/update_query_node.hpp"
#include "duckdb/parser/tableref/basetableref.hpp"

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

} // namespace

namespace {

constexpr const char *LIST_TABLE = "__acl_list";

[[noreturn]] void RefuseList(const char *what, const string &why) {
	throw BinderException("acl admin: %s %s - a column list is a SELECT list: `name`, `<expression> AS name` or "
	                      "`name: <expression>`",
	                      what, why);
}

//! Whether a parsed `SELECT <list> FROM __acl_list` holds nothing but the list over the one table: the node with its
//! list set aside prints as a bare `SELECT 1 FROM __acl_list` (a WHERE, a GROUP BY, a DISTINCT, a second FROM item -
//! anything written after the list - would not). The list itself is not printed back: a star's EXCLUDE set prints
//! its names in no fixed order
bool OnlyTheList(const SelectNode &node) {
	auto copy = node.Copy();
	auto &shape = copy->Cast<SelectNode>();
	shape.select_list.clear();
	shape.select_list.push_back(ConstantExpression::FromValue(Value::INTEGER(1)));
	SelectNode bare;
	bare.select_list.push_back(ConstantExpression::FromValue(Value::INTEGER(1)));
	bare.from_table = node.from_table->Copy();
	return shape.ToString() == bare.ToString();
}

bool HoldsClass(const ParsedExpression &expr, ExpressionClass kind) {
	if (expr.GetExpressionClass() == kind) {
		return true;
	}
	bool found = false;
	ParsedExpressionIterator::EnumerateChildren(
	    expr, [&](const ParsedExpression &child) { found = found || HoldsClass(child, kind); });
	return found;
}

//! A star inside a star's expressions other than duckdb's own `*` of `COLUMNS(lambda …)` (`list_filter(*, …)`): a
//! qualified one or a `COLUMNS(…)` of its own
bool HoldsOtherStar(const ParsedExpression &expr) {
	if (expr.GetExpressionClass() == ExpressionClass::STAR) {
		auto &star = expr.Cast<StarExpression>();
		if (star.IsColumns() || !star.RelationName().empty() || star.Expression() || !star.ReplaceList().empty() ||
		    !star.RenameList().empty() || !star.ExcludeList().empty()) {
			return true;
		}
	}
	bool found = false;
	ParsedExpressionIterator::EnumerateChildren(
	    expr, [&](const ParsedExpression &child) { found = found || HoldsOtherStar(child); });
	return found;
}

//! A column reference of more than one part that is not a lambda parameter's field: a qualified name or a field path
bool HoldsQualifiedColumn(const ParsedExpression &expr, const case_insensitive_set_t &params) {
	if (expr.GetExpressionClass() == ExpressionClass::LAMBDA) {
		auto &lambda = expr.Cast<LambdaExpression>();
		auto inner = params;
		if (lambda.Left().GetExpressionClass() == ExpressionClass::COLUMN_REF) {
			inner.insert(lambda.Left().Cast<ColumnRefExpression>().GetColumnName().GetIdentifierName());
		}
		ParsedExpressionIterator::EnumerateChildren(lambda.Left(), [&](const ParsedExpression &child) {
			if (child.GetExpressionClass() == ExpressionClass::COLUMN_REF) {
				inner.insert(child.Cast<ColumnRefExpression>().GetColumnName().GetIdentifierName());
			}
		});
		return HoldsQualifiedColumn(lambda.Right(), inner);
	}
	if (expr.GetExpressionClass() == ExpressionClass::COLUMN_REF) {
		auto &names = expr.Cast<ColumnRefExpression>().ColumnNames();
		return names.size() > 1 && !params.count(names[0].GetIdentifierName());
	}
	bool found = false;
	ParsedExpressionIterator::EnumerateChildren(
	    expr, [&](const ParsedExpression &child) { found = found || HoldsQualifiedColumn(child, params); });
	return found;
}

//! A call of a marker the rewriter bakes per reader (acl_claim, acl_has_role, acl_arg)
bool HoldsMarker(const ParsedExpression &expr) {
	if (expr.GetExpressionClass() == ExpressionClass::FUNCTION) {
		auto name = StringUtil::Lower(expr.Cast<FunctionExpression>().FunctionName().GetIdentifierName());
		if (name == "acl_claim" || name == "acl_has_role" || name == "acl_arg") {
			return true;
		}
	}
	bool found = false;
	ParsedExpressionIterator::EnumerateChildren(
	    expr, [&](const ParsedExpression &child) { found = found || HoldsMarker(child); });
	return found;
}

bool HoldsPositional(const ParsedExpression &expr) {
	if (expr.GetExpressionClass() == ExpressionClass::POSITIONAL_REFERENCE) {
		return true;
	}
	bool found = false;
	ParsedExpressionIterator::EnumerateChildren(
	    expr, [&](const ParsedExpression &child) { found = found || HoldsPositional(child); });
	return found;
}

} // namespace

vector<SelectListItem> ReadSelectList(const string &text_p, const char *what, bool allow_star) {
	auto text = text_p;
	StringUtil::Trim(text);
	vector<SelectListItem> items;
	if (text.empty()) {
		return items;
	}
	bool open = false, comment = false;
	ListTokens(text, &open, &comment);
	if (comment || open) {
		// spec 148: a list is read as written, item by item - a comment (a stored one: `a--b, c` read `a`) is refused
		RefuseList(what, "holds a comment or ends inside a literal or a quoted name");
	}
	Parser parser(ParserOptions::Builtin());
	try {
		parser.ParseQuery("SELECT " + text + "\nFROM " + LIST_TABLE);
	} catch (std::exception &ex) {
		ErrorData error(ex);
		RefuseList(what, "does not read as a SELECT list (" + error.RawMessage() + ")");
	}
	if (parser.statements.size() != 1 || parser.statements[0]->type != StatementType::SELECT_STATEMENT) {
		RefuseList(what, "holds more than a column list");
	}
	auto &select = parser.statements[0]->Cast<SelectStatement>();
	if (!select.node || select.node->type != QueryNodeType::SELECT_NODE) {
		RefuseList(what, "holds more than a column list");
	}
	auto &node = select.node->Cast<SelectNode>();
	if (!node.from_table || node.from_table->type != TableReferenceType::BASE_TABLE ||
	    node.from_table->ToString() != LIST_TABLE || !OnlyTheList(node)) {
		RefuseList(what, "holds more than a column list");
	}
	bool starred = false;
	for (auto &expr : node.select_list) {
		SelectListItem item;
		auto alias = expr->GetAlias().GetIdentifierName();
		if (expr->GetExpressionClass() == ExpressionClass::STAR) {
			if (!allow_star) {
				RefuseList(what, "holds a star (" + expr->ToString() + ")");
			}
			// spec 158 stage 2: one star over the object's one source - unqualified, unnamed, standing alone, reading
			// no table of its own
			auto &star = expr->Cast<StarExpression>();
			if (!alias.empty()) {
				RefuseList(what, "names a star (" + expr->ToString() + ")");
			}
			if (starred) {
				RefuseList(what,
				           "holds a second star (" + expr->ToString() + ") - one star reads the source's columns");
			}
			bool qualified = !star.RelationName().empty();
			for (auto &excluded : star.ExcludeList()) {
				qualified =
				    qualified || !excluded.catalog.empty() || !excluded.schema.empty() || !excluded.table.empty();
			}
			for (auto &renamed : star.RenameList()) {
				qualified = qualified || !renamed.first.catalog.empty() || !renamed.first.schema.empty() ||
				            !renamed.first.table.empty();
			}
			ParsedExpressionIterator::EnumerateChildren(*expr, [&](const ParsedExpression &child) {
				qualified = qualified || HoldsQualifiedColumn(child, case_insensitive_set_t());
			});
			if (qualified) {
				RefuseList(what, "holds the star " + expr->ToString() +
				                     " - a star of the list reads the object's one source by its columns' names: no "
				                     "qualified name or field path in it (write struct_extract(<column>, '<field>'))");
			}
			if (star.Expression() && HoldsMarker(*star.Expression())) {
				// which columns the object has is the object's, never the reader's: a marker in REPLACE is fine
				RefuseList(what, "holds the star " + expr->ToString() +
				                     " - its COLUMNS selector reads a marker (acl_claim, acl_has_role), so the object "
				                     "would have other columns for each reader");
			}
			bool reads_table = false;
			ParsedExpressionIterator::EnumerateChildren(*expr, [&](const ParsedExpression &child) {
				reads_table = reads_table || HoldsClass(child, ExpressionClass::SUBQUERY) || HoldsOtherStar(child) ||
				              HoldsPositional(child);
			});
			if (reads_table) {
				RefuseList(what, "holds the star " + expr->ToString() +
				                     " - its expressions read the object's source by name: no subquery, star or "
				                     "position inside it");
			}
			starred = true;
			item.star = true;
			item.expr = expr->ToString();
			items.push_back(std::move(item));
			continue;
		}
		if (HoldsClass(*expr, ExpressionClass::STAR)) {
			// duckdb's `* LIKE | ILIKE | GLOB | SIMILAR TO '…'` (TryTransformStarLike): a matching operator over `*`
			bool like = false;
			if (expr->GetExpressionClass() == ExpressionClass::FUNCTION) {
				auto name = expr->Cast<FunctionExpression>().FunctionName().GetIdentifierName();
				static const case_insensitive_set_t matchers {
				    "~~", "!~~", "~~*", "!~~*", "~~~", "!~~~", "regexp_full_match"};
				if (matchers.count(name)) {
					ParsedExpressionIterator::EnumerateChildren(*expr, [&](const ParsedExpression &child) {
						like = like || (child.GetExpressionClass() == ExpressionClass::STAR &&
						                !child.Cast<StarExpression>().IsColumns());
					});
				}
			}
			if (like && allow_star) {
				RefuseList(what, "holds " + expr->ToString() +
				                     " - a star matched by LIKE / GLOB / SIMILAR TO is written COLUMNS('<regex>') or "
				                     "COLUMNS(lambda c: c LIKE '…') here");
			}
			RefuseList(what, "holds a star inside " + expr->ToString() + " - a star stands alone in the list");
		}
		if (HoldsPositional(*expr)) {
			RefuseList(what, "reads a column by its position (" + expr->ToString() + ") - name it");
		}
		auto copy = expr->Copy();
		copy->ClearAlias();
		if (expr->GetExpressionClass() == ExpressionClass::COLUMN_REF) {
			auto &names = expr->Cast<ColumnRefExpression>().ColumnNames();
			auto &last = names.back().GetIdentifierName();
			// `x AS x` is written as an expression, as `x = x` was: what the name reads is stated (a renaming list)
			if (names.size() == 1 && alias.empty()) {
				item.name = last;
				items.push_back(std::move(item));
				continue;
			}
			// `address.city` is a column of its own, as in SELECT: named as duckdb names it
			item.name = alias.empty() ? last : alias;
			item.expr = copy->ToString();
			items.push_back(std::move(item));
			continue;
		}
		if (alias.empty()) {
			RefuseList(what, "holds the expression " + copy->ToString() + " without a name - write `" +
			                     copy->ToString() + " AS <name>`");
		}
		item.name = alias;
		item.expr = copy->ToString();
		items.push_back(std::move(item));
	}
	return items;
}

acl_detail::ColumnTest ReadColumnTest(const string &text_p) {
	const char *what = "the grant's column list";
	acl_detail::ColumnTest test;
	auto text = text_p;
	StringUtil::Trim(text);
	if (text.empty()) {
		return test;
	}
	bool open = false, comment = false;
	ListTokens(text, &open, &comment);
	if (comment || open) {
		RefuseList(what, "holds a comment or ends inside a literal or a quoted name");
	}
	Parser parser(ParserOptions::Builtin());
	try {
		parser.ParseQuery("SELECT " + text + "\nFROM " + LIST_TABLE);
	} catch (std::exception &ex) {
		RefuseList(what, "does not read as a SELECT list (" + ErrorData(ex).RawMessage() + ")");
	}
	auto refuse = [&]() {
		throw BinderException("acl admin: %s is `name, …`, `*` or `* EXCLUDE (name, …)` - which columns of the object "
		                      "the role sees (a mask is MASK (<column> AS <expression>))",
		                      what);
	};
	if (parser.statements.size() != 1 || parser.statements[0]->type != StatementType::SELECT_STATEMENT) {
		refuse();
	}
	auto &select = parser.statements[0]->Cast<SelectStatement>();
	if (!select.node || select.node->type != QueryNodeType::SELECT_NODE) {
		refuse();
	}
	auto &node = select.node->Cast<SelectNode>();
	if (!node.from_table || node.from_table->ToString() != LIST_TABLE || !OnlyTheList(node)) {
		refuse();
	}
	for (auto &expr : node.select_list) {
		if (expr->HasAlias()) {
			refuse();
		}
		if (expr->GetExpressionClass() == ExpressionClass::STAR) {
			auto &star = expr->Cast<StarExpression>();
			if (node.select_list.size() != 1 || star.IsColumns() || !star.RelationName().empty() ||
			    !star.ReplaceList().empty() || !star.RenameList().empty() || star.Expression()) {
				refuse();
			}
			test.kind =
			    star.ExcludeList().empty() ? acl_detail::ColumnTest::Kind::ALL : acl_detail::ColumnTest::Kind::EXCEPT;
			for (auto &excluded : star.ExcludeList()) {
				if (!excluded.catalog.empty() || !excluded.schema.empty() || !excluded.table.empty()) {
					refuse();
				}
				test.names.push_back(excluded.column.GetIdentifierName());
			}
			std::sort(test.names.begin(), test.names.end());
			return test;
		}
		if (expr->GetExpressionClass() != ExpressionClass::COLUMN_REF ||
		    expr->Cast<ColumnRefExpression>().ColumnNames().size() != 1) {
			refuse();
		}
		auto name = expr->Cast<ColumnRefExpression>().ColumnNames()[0].GetIdentifierName();
		if (test.Names(name)) {
			throw BinderException("acl admin: %s names \"%s\" twice", what, name);
		}
		test.kind = acl_detail::ColumnTest::Kind::ONLY;
		test.names.push_back(name);
	}
	return test;
}

string ColumnTestText(const acl_detail::ColumnTest &test) {
	vector<string> names;
	for (auto &name : test.names) {
		names.push_back(KeywordHelper::WriteOptionallyQuoted(name, '"', true));
	}
	switch (test.kind) {
	case acl_detail::ColumnTest::Kind::ALL:
		return string();
	case acl_detail::ColumnTest::Kind::ONLY:
		return StringUtil::Join(names, ", ");
	case acl_detail::ColumnTest::Kind::EXCEPT:
		return "* EXCLUDE (" + StringUtil::Join(names, ", ") + ")";
	}
	return string();
}

acl_detail::GrantMasks ReadMasks(const string &text, vector<string> *written) {
	const char *what = "the grant's MASK";
	acl_detail::GrantMasks masks;
	bool open = false, comment = false;
	auto tokens = ListTokens(text, &open, &comment);
	if (open) {
		throw BinderException("acl admin: %s ends inside a literal, a quoted name or a comment", what);
	}
	if (comment) {
		// spec 148: a mask is one expression - a comment in it is refused as an RLS's is
		throw BinderException("acl admin: %s holds a comment - write each mask as one expression", what);
	}
	for (auto &item : SplitOnTokens(text, tokens)) {
		vector<MatcherToken> words;
		for (auto &token : ListTokens(item.text, nullptr, nullptr)) {
			if (token.type != TokenType::END_OF_INPUT && token.type != TokenType::END_OF_INPUT_AUTOCOMPLETE &&
			    token.type != TokenType::COMMENT) {
				words.push_back(token);
			}
		}
		if (words.size() < 3 || words[1].type == TokenType::STRING_LITERAL || words[1].text.empty() ||
		    words[1].text[0] == '"' || !StringUtil::CIEquals(words[1].text, "as")) {
			throw BinderException("acl admin: %s is items `<column> AS <expression>`", what);
		}
		// the column read as duckdb reads an identifier, the expression as one item of a SELECT list naming it
		auto column_items = ReadSelectList(item.text.substr(0, words[0].offset + words[0].length), what, false);
		if (column_items.size() != 1 || !column_items[0].expr.empty()) {
			throw BinderException("acl admin: %s is items `<column> AS <expression>` - \"%s\" is no column name", what,
			                      words[0].text);
		}
		auto &column = column_items[0].name;
		auto expression = item.text.substr(words[2].offset);
		auto read = ReadSelectList(expression + " AS __acl_mask", what, false);
		if (read.size() != 1 || read[0].name != "__acl_mask" || read[0].expr.empty()) {
			throw BinderException("acl admin: the mask of \"%s\" is one expression", column);
		}
		if (acl_detail::MaskOf(masks, column)) {
			throw BinderException("acl admin: %s masks \"%s\" twice", what, column);
		}
		masks.emplace_back(column, read[0].expr);
		if (written) {
			written->push_back(expression);
		}
	}
	return masks;
}

string MasksText(const acl_detail::GrantMasks &masks) {
	vector<string> items;
	for (auto &mask : masks) {
		items.push_back(KeywordHelper::WriteOptionallyQuoted(mask.first, '"', true) + " AS " + mask.second);
	}
	return StringUtil::Join(items, ", ");
}

vector<DeclaredColumnText> SplitDeclaredColumns(const string &text, const char *what, bool allow_star) {
	vector<DeclaredColumnText> columns;
	case_insensitive_set_t named;
	for (auto &item : ReadSelectList(text, what, allow_star)) {
		if (item.star) {
			DeclaredColumnText column; // spec 158 stage 2: no name, the star as duckdb prints it
			column.expr = std::move(item.expr);
			columns.push_back(std::move(column));
			continue;
		}
		if (!named.insert(item.name).second) {
			throw BinderException("acl admin: %s declares the column \"%s\" twice", what, item.name);
		}
		if (item.name.find_first_of(".[") != string::npos || item.name[0] == '"') {
			throw BinderException("acl admin: %s declares the column \"%s\" - a declared column's name holds no '.' "
			                      "or '[' and starts with no '\"'",
			                      what, item.name);
		}
		DeclaredColumnText column;
		column.name = std::move(item.name);
		column.expr = std::move(item.expr);
		columns.push_back(std::move(column));
	}
	return columns;
}

bool IsSqlValueKeyword(const string &name) {
	static const case_insensitive_set_t KEYWORDS = {
	    "current_date", "current_time", "current_timestamp", "localtime",       "localtimestamp", "current_user",
	    "user",         "session_user", "current_role",      "current_catalog", "current_schema"};
	return KEYWORDS.count(name) > 0;
}

namespace {

//! A column reference that is neither `new.<column>` nor (`bare_ok`) a bare column of the row: a qualified name, a
//! field path, a bare name where none is allowed
bool HoldsOtherColumnRef(const ParsedExpression &expr, bool bare_ok, const case_insensitive_set_t &params,
                         string &found) {
	if (expr.GetExpressionClass() == ExpressionClass::LAMBDA) {
		auto &lambda = expr.Cast<LambdaExpression>();
		auto inner = params;
		if (lambda.Left().GetExpressionClass() == ExpressionClass::COLUMN_REF) {
			inner.insert(lambda.Left().Cast<ColumnRefExpression>().GetColumnName().GetIdentifierName());
		}
		ParsedExpressionIterator::EnumerateChildren(lambda.Left(), [&](const ParsedExpression &child) {
			if (child.GetExpressionClass() == ExpressionClass::COLUMN_REF) {
				inner.insert(child.Cast<ColumnRefExpression>().GetColumnName().GetIdentifierName());
			}
		});
		return HoldsOtherColumnRef(lambda.Right(), bare_ok, inner, found);
	}
	if (expr.GetExpressionClass() == ExpressionClass::COLUMN_REF) {
		auto &names = expr.Cast<ColumnRefExpression>().ColumnNames();
		if (params.count(names[0].GetIdentifierName())) {
			return false;
		}
		if (names.size() == 2 && StringUtil::CIEquals(names[0].GetIdentifierName(), "new")) {
			return false;
		}
		if (names.size() == 1 && (bare_ok || IsSqlValueKeyword(names[0].GetIdentifierName()))) {
			return false; // a value keyword (`current_timestamp`) is the value where no column has its name
		}
		found = expr.ToString();
		return true;
	}
	bool holds = false;
	ParsedExpressionIterator::EnumerateChildren(expr, [&](const ParsedExpression &child) {
		holds = holds || HoldsOtherColumnRef(child, bare_ok, params, found);
	});
	return holds;
}

} // namespace

vector<std::pair<string, string>> ReadWriteValues(const string &text_p, const char *what, bool on_update) {
	vector<std::pair<string, string>> items;
	auto text = text_p;
	StringUtil::Trim(text);
	if (text.empty()) {
		return items;
	}
	auto refuse = [&](const string &why) {
		throw BinderException("acl admin: %s %s - it is items `<column> = <expression>`, `new.<column>` the value this "
		                      "write gives a column%s",
		                      what, why, on_update ? ", a bare column the row's current value" : "");
	};
	bool open = false, comment = false;
	ListTokens(text, &open, &comment);
	if (comment || open) {
		refuse("holds a comment or ends inside a literal or a quoted name");
	}
	Parser parser(ParserOptions::Builtin());
	try {
		parser.ParseQuery("UPDATE __acl_list SET " + text);
	} catch (std::exception &ex) {
		refuse("does not read as a SET list (" + ErrorData(ex).RawMessage() + ")");
	}
	if (parser.statements.size() != 1 || parser.statements[0]->type != StatementType::UPDATE_STATEMENT) {
		refuse("holds more than a SET list");
	}
	auto &update = parser.statements[0]->Cast<UpdateStatement>();
	auto &node = *update.node;
	if (!node.set_info || node.from_table || !node.returning_list.empty() || node.set_info->condition ||
	    !node.cte_map.map.empty()) {
		refuse("holds more than a SET list");
	}
	case_insensitive_set_t named;
	for (idx_t i = 0; i < node.set_info->columns.size(); i++) {
		auto column = node.set_info->columns[i].GetIdentifierName();
		auto &expr = *node.set_info->expressions[i];
		if (!named.insert(column).second) {
			throw BinderException("acl admin: %s sets \"%s\" twice", what, column);
		}
		if (HoldsClass(expr, ExpressionClass::SUBQUERY) || HoldsClass(expr, ExpressionClass::STAR) ||
		    HoldsPositional(expr) || HoldsClass(expr, ExpressionClass::PARAMETER) ||
		    HoldsClass(expr, ExpressionClass::WINDOW) || expr.GetExpressionClass() == ExpressionClass::DEFAULT) {
			refuse("sets \"" + column + "\" to " + expr.ToString() +
			       " - an expression over the row being written: no subquery, star, position, parameter or DEFAULT");
		}
		string other;
		if (HoldsOtherColumnRef(expr, on_update, case_insensitive_set_t(), other)) {
			refuse("sets \"" + column + "\" reading " + other +
			       (on_update ? string() : string(" - on an INSERT there is no current row: write new.<column>")));
		}
		items.emplace_back(column, expr.ToString());
	}
	return items;
}

string WriteValuesText(const vector<std::pair<string, string>> &items) {
	vector<string> parts;
	for (auto &item : items) {
		parts.push_back(KeywordHelper::WriteOptionallyQuoted(item.first, '"', true) + " = " + item.second);
	}
	return StringUtil::Join(parts, ", ");
}

StarParts ReadStarParts(const string &star_text) {
	StarParts parts;
	vector<unique_ptr<ParsedExpression>> parsed;
	try {
		parsed = Parser(ParserOptions::Builtin()).ParseExpressionList(star_text);
	} catch (std::exception &) {
		return parts;
	}
	if (parsed.size() != 1 || parsed[0]->GetExpressionClass() != ExpressionClass::STAR) {
		return parts;
	}
	auto &star = parsed[0]->Cast<StarExpression>();
	for (auto &replaced : star.ReplaceList()) {
		parts.replaced.emplace_back(replaced.first.GetIdentifierName(), replaced.second->ToString());
	}
	for (auto &renamed : star.RenameList()) {
		parts.renamed.emplace_back(renamed.second.GetIdentifierName(), renamed.first.column.GetIdentifierName());
	}
	return parts;
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
