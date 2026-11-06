// The ACL management grammar (spec 008). Since spec 150's stage 3 every management statement is a rule
// (acl_mgmt_grammar.cpp); what is left here reads the lists a rule hands over (ParseMgmtBatch's readers), builds the
// secrets service's call from its rule's reading (spec 082), and refuses a statement no rule reads in its form's own
// words (RefuseUnreadStatement). The authorizer every management statement passes is acl_platform.cpp's (spec 117).
// The parser override is its only caller.

#include "acl_admin_sql.hpp"
#include "duckdb/parser/parser.hpp"
#include "acl_grammar.hpp"
#include "acl_admin_scanner.hpp"
#include "acl_platform.hpp"

#include "acl_door_common.hpp"
#include "acl_scan_util.hpp"
#include "duckdb/common/exception/binder_exception.hpp"
#include "duckdb/common/helper.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/parser/expression/constant_expression.hpp"
#include "duckdb/parser/expression/function_expression.hpp"
#include "duckdb/parser/expression/star_expression.hpp"
#include "duckdb/parser/query_node/select_node.hpp"
#include "duckdb/parser/statement/create_statement.hpp"
#include "duckdb/parser/statement/select_statement.hpp"
#include "duckdb/parser/tableref/emptytableref.hpp"
#include "duckdb/parser/tableref/table_function_ref.hpp"

#include <cstring>
#include <unordered_map>

namespace duckdb {
namespace acl {
//! Strip one layer of quotes from a list element written as a literal
string Unquoted(string value) {
	StringUtil::Trim(value);
	if (value.size() >= 2 && (value.front() == '\'' || value.front() == '"') && value.back() == value.front()) {
		auto quote = value.front();
		value = value.substr(1, value.size() - 2);
		value = StringUtil::Replace(value, string(2, quote), string(1, quote));
	}
	return value;
}

namespace {

//! `(tenant = 'acme', unit = 'eu')` -> the csv `tenant='acme',unit='eu'`: each value stays one quoted literal, so
//! a `,` or a `'` inside it is part of the value (ParseClaims takes the quotes off)
string ClaimsListToCsv(const string &list) {
	vector<string> entries;
	for (auto &item : SplitTopLevel(list, ',')) {
		if (item.empty()) {
			continue;
		}
		auto split = item.find('=');
		if (split == string::npos) {
			throw BinderException("acl admin: a claim is written as name = 'value', got \"%s\"", item);
		}
		auto name = item.substr(0, split);
		StringUtil::Trim(name);
		auto value = Unquoted(item.substr(split + 1));
		entries.push_back(name + "='" + StringUtil::Replace(value, "'", "''") + "'");
	}
	return StringUtil::Join(entries, ",");
}

//! `(tid => tenant, oid => user_id)` -> the stored JSON `{"tid": "tenant", "oid": "user_id"}` - each side quoted as
//! JSON, split at the first `=>` outside quotes (spec 150 stage 3e: the sides were pasted into the JSON, so a quoted
//! side holding `", "` stored a second mapping, and an `=>` inside quotes split the item there)
string ClaimMapToJson(const string &list) {
	vector<string> entries;
	for (auto &item : SplitTopLevel(list, ',')) {
		if (item.empty()) {
			continue;
		}
		idx_t arrow = string::npos;
		char quote = 0;
		for (idx_t i = 0; i + 1 < item.size(); i++) {
			auto c = item[i];
			if (quote) {
				quote = c == quote ? 0 : quote;
			} else if (c == '\'' || c == '"') {
				quote = c;
			} else if (c == '=' && item[i + 1] == '>') {
				arrow = i;
				break;
			}
		}
		if (arrow == string::npos) {
			throw BinderException("acl admin: a claim mapping is written as <jwt path> => <claim>, got \"%s\"", item);
		}
		entries.push_back(JsonQuote(Unquoted(item.substr(0, arrow))) + ": " +
		                  JsonQuote(Unquoted(item.substr(arrow + 2))));
	}
	return "{" + StringUtil::Join(entries, ", ") + "}";
}

//! spec 065: a management COLUMNS list is written like SQL, so a quoted identifier must mean the
//! name it quotes - `COLUMNS ("odd name", id = pk)` stores `odd name` (with its space), not the
//! quotes. Only the item's NAME (left of a top-level `=`) is unquoted: the right side is an
//! expression, where a quoted identifier is already valid SQL. Stored verbatim, the quotes made the
//! item match no column, ever - the function form never had the defect.
string UnquoteColumnsList(const string &raw) {
	vector<string> items;
	for (auto &item : SplitTopLevel(raw, ',')) {
		auto text = item;
		StringUtil::Trim(text);
		if (text.empty()) {
			continue;
		}
		// the first top-level `=` splits name from expression; one inside quotes or parens is the
		// expression's own (the same reading SplitTopLevel gives a comma)
		idx_t split = text.size();
		char quote = 0;
		idx_t depth = 0;
		for (idx_t i = 0; i < text.size(); i++) {
			auto c = text[i];
			if (quote) {
				if (c == quote) {
					quote = 0;
				}
			} else if (c == '\'' || c == '"') {
				quote = c;
			} else if (c == '(') {
				depth++;
			} else if (c == ')' && depth > 0) {
				depth--;
			} else if (c == '=' && depth == 0) {
				split = i;
				break;
			}
		}
		auto name = text.substr(0, split);
		StringUtil::Trim(name);
		if (!name.empty() && name.front() == '"') {
			// the quoted token may carry a suffix (`"odd name" NOT NULL`, spec 048's nullability
			// mark): unquote the token, keep the suffix - the consumer strips it as it always did
			idx_t close = name.size();
			for (idx_t i = 1; i < name.size(); i++) {
				if (name[i] != '"') {
					continue;
				}
				if (i + 1 < name.size() && name[i + 1] == '"') {
					i++; // a doubled quote is a literal one
					continue;
				}
				close = i;
				break;
			}
			if (close < name.size()) {
				auto bare = StringUtil::Replace(name.substr(1, close - 1), "\"\"", "\"");
				// the stored csv form cannot carry these characters in a name: every later reader
				// splits on them, and a silent re-split would grant something the admin never wrote
				if (bare.find(',') != string::npos || bare.find('=') != string::npos) {
					throw BinderException("acl admin: a column name containing ',' or '=' cannot be carried by a "
					                      "COLUMNS list - the stored form splits on them (got \"%s\")",
					                      bare);
				}
				name = bare + name.substr(close + 1);
			}
		}
		if (split < text.size()) {
			auto rest = text.substr(split + 1);
			StringUtil::Trim(rest);
			items.push_back(name + " = " + rest);
		} else {
			items.push_back(name);
		}
	}
	return StringUtil::Join(items, ", ");
}

} // namespace

unique_ptr<SQLStatement> MakeAdminCall(const string &function, const vector<Value> &args) {
	vector<unique_ptr<ParsedExpression>> children;
	for (auto &arg : args) {
		children.push_back(ConstantExpression::FromValue(arg));
	}
	auto node = make_uniq<SelectNode>();
	auto call = make_uniq<FunctionExpression>(Identifier(function), std::move(children));
	// spec 117: the column is named as the platform call names it, so the two forms answer alike
	if (auto operation = PlatformFunctionByTarget(function)) {
		call->SetAlias(Identifier(operation->name));
	}
	node->select_list.push_back(std::move(call));
	node->from_table = make_uniq<EmptyTableRef>();
	auto statement = make_uniq<SelectStatement>();
	statement->node = std::move(node);
	return std::move(statement);
}

namespace {

//! `SELECT * FROM acl_<fn>(...)`: the compiled form of a management statement that answers rows
//! (CHECK VIRTUAL CATALOG, spec 039); authorized by the same name-and-catalog rule as a scalar call
unique_ptr<SQLStatement> MakeAdminTableCall(const string &function, const vector<Value> &args) {
	vector<unique_ptr<ParsedExpression>> children;
	for (auto &arg : args) {
		children.push_back(ConstantExpression::FromValue(arg));
	}
	auto node = make_uniq<SelectNode>();
	node->select_list.push_back(make_uniq<StarExpression>());
	auto ref = make_uniq<TableFunctionRef>();
	ref->function = make_uniq<FunctionExpression>(Identifier(function), std::move(children));
	node->from_table = std::move(ref);
	auto statement = make_uniq<SelectStatement>();
	statement->node = std::move(node);
	return std::move(statement);
}

//! True when the ADMIN remainder starts with a management form (decides the whole batch)

} // namespace

namespace {

//! spec 150, stage 3g-1: whether a statement is the management grammar's, judged by its head on duckdb's tokens (a
//! comment between the words is gone, a string or a quoted name one token): the words duckdb has no statement for,
//! and duckdb's own verbs only with the marker or the noun that is ours alone
bool IsMgmtHead(const vector<HeadToken> &head) {
	auto word = [&](idx_t index) {
		return index < head.size() && head[index].kind == HeadToken::Kind::WORD ? head[index].word : string();
	};
	auto named = [&](idx_t index) {
		return index < head.size() &&
		       (head[index].kind == HeadToken::Kind::WORD || head[index].kind == HeadToken::Kind::QUOTED_NAME ||
		        head[index].kind == HeadToken::Kind::NUMBER);
	};
	auto first = word(0);
	if (first.empty()) {
		return false;
	}
	if (first == "add" || first == "grant" || first == "revoke" || first == "map") {
		return true;
	}
	if (MgmtRulesKeyword(first)) {
		return true; // a linked module's form (hugr-node's CLUSTER - duckdb has no CLUSTER statement)
	}
	auto second = word(1);
	if (first == "deny") {
		return second == "function" || second == "view"; // spec 072 / 117: duckdb has no DENY at all
	}
	if (first == "check" || first == "repair") {
		return second == "virtual"; // spec 039: ours always name a VIRTUAL target
	}
	if (first == "profile" || first == "kill") {
		return second == "session"; // spec 074 / 118: duckdb has neither
	}
	if (first == "drain" || first == "resume") {
		return second == "node"; // spec 118
	}
	if (first == "migrate") {
		return second == "policy"; // spec 118
	}
	if (first == "set") {
		// SET SESSION '<id>' AUDIT LEVEL … (spec 118): a session named by a single-quoted id - duckdb's SET SESSION
		// <setting> names a setting, never a string; SET SESSION VIEW AS ROLE … (spec 120.3): no setting is `view as`
		return second == "session" &&
		       ((head.size() > 2 && head[2].kind == HeadToken::Kind::STRING) || (word(2) == "view" && word(3) == "as"));
	}
	if (first == "reset") {
		return second == "session" && word(2) == "view" && word(3) == "as"; // spec 120.3
	}
	if (first == "analyze") {
		// `ANALYZE virtual` is duckdb's ANALYZE of a table named virtual: ours names a target after it
		return second == "virtual" && named(2);
	}
	if (first == "comment") {
		// duckdb owns COMMENT ON <object>: ours always name a VIRTUAL target
		return word(second == "on" ? 2 : 1) == "virtual";
	}
	if (first != "create" && first != "drop" && first != "alter") {
		return false;
	}
	idx_t at = 1;
	if (first == "create" && second == "or") {
		at = word(2) == "replace" ? 3 : 2; // CREATE OR REPLACE …: the marker after the modifier
	}
	auto noun = word(at);
	// CREATE/ALTER/DROP FUNCTION CATEGORY <name> (spec 072): duckdb's CREATE FUNCTION is a macro - one named
	// `category` (`CREATE FUNCTION category(x) AS …`) has no name after the word, nor does duckdb's DROP of it
	// (`DROP FUNCTION category CASCADE | RESTRICT`)
	bool function_category = noun == "function" && word(at + 1) == "category" && named(at + 2) &&
	                         !(first == "drop" && (word(at + 2) == "cascade" || word(at + 2) == "restrict"));
	if (first == "create") {
		return noun == "virtual" || noun == "role" || noun == "issuer" || noun == "client" || noun == "resource" ||
		       function_category;
	}
	if (first == "alter") {
		// duckdb owns ALTER TABLE/VIEW/…: our object forms carry VIRTUAL, ALTER ROLE/ISSUER/GRANT are not duckdb's
		return noun == "virtual" || noun == "role" || noun == "issuer" || noun == "client" || noun == "grant" ||
		       noun == "resource" || function_category;
	}
	// DROP: our own forms carry VIRTUAL, and duckdb has no DROP ROLE/ISSUER/MAP/RELATION
	return noun == "relation" || noun == "virtual" || noun == "role" || noun == "issuer" || noun == "client" ||
	       noun == "map" || noun == "reference" || noun == "resource" || function_category;
}

//! The heads of a batch's statements: enough tokens for the longest decision (`CREATE OR REPLACE FUNCTION CATEGORY
//! <name>`)
vector<vector<HeadToken>> BatchHeads(const string &text) {
	return ReadStatementHeads(text, 6);
}

//! spec 150, stage 3: a moved family's form written so its rule did not read it - the form's own words. Its own type,
//! so a batch whose tokenizer refused that very statement says the tokenizer's words instead (an unterminated string)
class MovedFormRefusal : public BinderException {
public:
	explicit MovedFormRefusal(const string &usage) : BinderException("acl admin: " + usage) {
	}
};

[[noreturn]] void RefuseMovedForm(const string &usage) {
	throw MovedFormRefusal(usage);
}

//! A statement's head on duckdb's tokens (comments gone): its words lower-cased by place, '' where no word stands
struct HeadWords {
	vector<HeadToken> tokens;
	string Word(idx_t index) const {
		return index < tokens.size() && tokens[index].kind == HeadToken::Kind::WORD ? tokens[index].word : string();
	}
};

//! spec 150, stage 3c: CREATE VIRTUAL … and the ADD forms are rules (acl_mgmt_grammar.cpp) - one that reaches here did
//! not read as its rule, said in the form's own words
[[noreturn]] void RefuseObjectForm(const HeadWords &head, idx_t at, bool add) {
	auto kind = head.Word(at);
	bool function = kind == "scalar" || (kind == "table" && head.Word(at + 1) == "function");
	if (add) {
		if (kind == "view") {
			RefuseMovedForm("write ADD VIEW <catalog>.<name> [(<columns>)] AS <sql>");
		}
		if (kind == "schema") {
			RefuseMovedForm("write ADD SCHEMA <physical schema> AS <catalog>.<alias>");
		}
		if (function) {
			RefuseMovedForm("write ADD SCALAR | TABLE FUNCTION <catalog>.<name>[(<parameters>)] [RETURNS <type> | "
			                "RETURNS TABLE (<columns>)] MACRO <body> | ALIAS [OF] <function>");
		}
		if (kind == "table") {
			RefuseMovedForm("write ADD TABLE <physical table> AS <catalog>.<name> [COLUMNS (...)] [RLS (...)]");
		}
		RefuseMovedForm("write ADD VIEW | SCHEMA | SCALAR | TABLE FUNCTION | TABLE ...");
	}
	if (kind == "catalog") {
		RefuseMovedForm("write CREATE [OR REPLACE] VIRTUAL CATALOG [IF NOT EXISTS] <catalog> [COMMENT '<text>']");
	}
	if (kind == "reference") {
		RefuseMovedForm(
		    "write CREATE [OR REPLACE] VIRTUAL REFERENCE [IF NOT EXISTS] <catalog>.<name> FROM <object> TO "
		    "<object> ON (<pairs>) | ON EXPRESSION '<sql>' - or TO FUNCTION <function>[(<param> => "
		    "<column>, ...)] [ON ...] - [CARDINALITY <kind>] [OPTIONAL] [JOIN <method>] [COMMENT '<text>']");
	}
	if (kind == "schema") {
		RefuseMovedForm("write CREATE [OR REPLACE] VIRTUAL SCHEMA [IF NOT EXISTS] <catalog>.<path> AS | FROM <physical "
		                "schema> [COMMENT '<text>']");
	}
	if (kind == "view") {
		RefuseMovedForm("write CREATE [OR REPLACE] VIRTUAL VIEW [IF NOT EXISTS] <catalog>.<name> [(<columns>)] "
		                "[PRIMARY KEY (<columns>)] [COMMENT '<text>'] AS <sql>");
	}
	if (function) {
		RefuseMovedForm("write CREATE [OR REPLACE] VIRTUAL SCALAR | TABLE FUNCTION [IF NOT EXISTS] "
		                "<catalog>.<name>[(<parameters>)] [RETURNS <type> | RETURNS TABLE (<columns>)] [PRIMARY KEY "
		                "(<columns>)] [COMMENT '<text>'] AS <body> | ALIAS OF <function> [COMMENT '<text>']");
	}
	if (kind == "table") {
		RefuseMovedForm("write CREATE [OR REPLACE] VIRTUAL TABLE [IF NOT EXISTS] <catalog>.<name> AS <physical table> "
		                "[COLUMNS (...)] [RLS (...)] [PRIMARY KEY (...)] [COMMENT '<text>']");
	}
	RefuseMovedForm("write CREATE [OR REPLACE] VIRTUAL CATALOG | REFERENCE | SCHEMA | VIEW | SCALAR | TABLE FUNCTION | "
	                "TABLE ...");
}

//! spec 150, stage 3c part 2: ALTER / COMMENT ON / CHECK / REPAIR / ANALYZE / DROP of the objects are rules - one
//! that reaches here did not read as its rule, said in the form's own words (`at` stands after `VIRTUAL`)
[[noreturn]] void RefuseObjectChange(const HeadWords &head, idx_t at, const string &verb) {
	auto kind = head.Word(at);
	bool function = kind == "scalar" || (kind == "table" && head.Word(at + 1) == "function");
	if (verb == "alter") {
		if (kind == "reference") {
			RefuseMovedForm("write ALTER VIRTUAL REFERENCE <catalog>.<name> SET COMMENT '<text>' | SET CARDINALITY "
			                "<kind> | SET OPTIONAL true | false");
		}
		if (kind == "catalog") {
			RefuseMovedForm("write ALTER VIRTUAL CATALOG <catalog> SET COMMENT '<text>'");
		}
		if (kind == "view") {
			RefuseMovedForm("write ALTER VIRTUAL VIEW <catalog>.<name> SET AS <sql> | SET TYPES (...) | SET PRIMARY "
			                "KEY (...) | DROP PRIMARY KEY");
		}
		if (kind == "schema") {
			RefuseMovedForm("write ALTER VIRTUAL SCHEMA <catalog>.<path> REFRESH [PRUNE] | SET PHYS <physical schema>");
		}
		if (function) {
			RefuseMovedForm("write ALTER VIRTUAL SCALAR | TABLE FUNCTION <catalog>.<name> SET MACRO <body> | SET ALIAS "
			                "[OF] <function> - a table function also SET PRIMARY KEY (...) | DROP PRIMARY KEY");
		}
		if (kind == "table") {
			RefuseMovedForm(
			    "write ALTER VIRTUAL TABLE <catalog>.<name> SET PHYS <physical table> | SET COLUMNS (...) | "
			    "SET RLS (...) | SET TYPES (...) | SET PRIMARY KEY (...) | DROP PRIMARY KEY");
		}
		RefuseMovedForm(
		    "write ALTER VIRTUAL CATALOG | SCHEMA | TABLE | VIEW | SCALAR | TABLE FUNCTION | REFERENCE ...");
	}
	if (verb == "drop") {
		if (kind == "catalog") {
			RefuseMovedForm("write DROP VIRTUAL CATALOG [IF EXISTS] <catalog> [CASCADE]");
		}
		if (kind == "schema") {
			RefuseMovedForm("write DROP VIRTUAL SCHEMA [IF EXISTS] <catalog>.<path> [CASCADE]");
		}
		RefuseMovedForm("write DROP VIRTUAL TABLE | VIEW | SCALAR | TABLE FUNCTION | REFERENCE [IF EXISTS] "
		                "<catalog>.<name>");
	}
	if (verb == "comment") {
		RefuseMovedForm("write COMMENT ON VIRTUAL TABLE | VIEW | SCHEMA | SCALAR | TABLE FUNCTION <catalog>.<name> "
		                "[COLUMN <column>] IS '<text>', or COMMENT ON VIRTUAL REFERENCE <catalog>.<name> IS '<text>'");
	}
	if (verb == "check") {
		RefuseMovedForm("write CHECK VIRTUAL CATALOG <catalog>");
	}
	if (verb == "repair") {
		RefuseMovedForm("write REPAIR VIRTUAL TABLE <catalog>.<name> REMAP (<column> = <expression>, ...) | DROP "
		                "MISSING COLUMNS [AND MASKS]");
	}
	RefuseMovedForm("write ANALYZE VIRTUAL CATALOG <catalog>, or ANALYZE VIRTUAL [TABLE | VIEW | SCALAR | TABLE "
	                "FUNCTION] <catalog>.<name>");
}

//! spec 150, stage 3d: GRANT / REVOKE CATALOG | SCHEMA | TABLE | VIEW | OBJECT are rules - one that reaches here did
//! not read as its rule, said in the form's own words (`at` stands after GRANT / REVOKE)
[[noreturn]] void RefuseGrantForm(const HeadWords &head, idx_t at, const string &verb) {
	auto kind = head.Word(at);
	bool grant = verb == "grant";
	if (kind == "catalog") {
		RefuseMovedForm(grant ? "write GRANT CATALOG <catalog> TO ROLE <role> [WITH (<capability>, ...) | CAPS "
		                        "'<json>'] [RLS (<predicate>)] [COLUMNS (<list>)] [MAIN]"
		                      : "write REVOKE CATALOG <catalog> FROM ROLE <role>");
	}
	if (kind == "schema") {
		RefuseMovedForm(grant ? "write GRANT SCHEMA <catalog>.<path> TO ROLE <role> [WITH (<capability>, ...) | CAPS "
		                        "'<json>'] [INTO <physical schema> | VIRTUAL ONLY] [COMMENT '<text>']"
		                      : "write REVOKE SCHEMA <catalog>.<path> FROM ROLE <role>");
	}
	if (kind == "table" || kind == "view" || kind == "object") {
		RefuseMovedForm(grant
		                    ? "write GRANT TABLE | VIEW | OBJECT <catalog>.<name> TO ROLE <role> [WITH (<capability>, "
		                      "...) | CAPS '<json>'] [RLS (<predicate>)] [COLUMNS (<list>)]"
		                    : "write REVOKE TABLE | VIEW | OBJECT <catalog>.<name> FROM ROLE <role>");
	}
	RefuseMovedForm(grant
	                    ? "write GRANT CATALOG | SCHEMA | TABLE | VIEW | OBJECT | ADMIN | FUNCTION | SOURCE | RESOURCE "
	                      "GROUP ... TO ROLE <role>"
	                    : "write REVOKE CATALOG | SCHEMA | TABLE | VIEW | OBJECT | ADMIN | FUNCTION | SOURCE | "
	                      "RESOURCE GROUP ... FROM ROLE <role>");
}

// --- spec 095: the readers of an issuer's and a client's lists ---------------------------------------

string JsonList(const vector<string> &values) {
	vector<string> quoted;
	for (auto &value : values) {
		quoted.push_back(JsonQuote(value));
	}
	return "[" + StringUtil::Join(quoted, ",") + "]";
}

//! A list written `(a, 'b', …)` - the text between its parentheses - as a JSON list, items unquoted
string ListItemsJson(const string &inside) {
	vector<string> out;
	for (auto &item : SplitTopLevel(inside, ',')) {
		auto value = Unquoted(item);
		StringUtil::Trim(value);
		if (!value.empty()) {
			out.push_back(value);
		}
	}
	return JsonList(out);
}

//! A claim path: a quoted string (a claim with characters a word cannot hold) or word(.word)*
string ClaimPath(AdminScanner &s) {
	s.Skip();
	if (s.pos < s.text.size() && (s.text[s.pos] == '\'' || s.text[s.pos] == '"')) {
		return s.Quoted("claim path");
	}
	return s.DottedWords("a claim path");
}

//! A REQUIRE value: a quoted string, or a bare word or number (a boolean or numeric claim, compared as
//! the text it reads as: `true`, `42`)
string RequireValue(AdminScanner &c) {
	c.Skip();
	if (c.pos < c.text.size() && (c.text[c.pos] == '\'' || c.text[c.pos] == '"')) {
		return c.Quoted("value");
	}
	auto start = c.pos;
	while (c.pos < c.text.size() && (IsWordChar(c.text[c.pos]) || c.text[c.pos] == '.' || c.text[c.pos] == '-')) {
		c.pos++;
	}
	if (c.pos == start) {
		throw BinderException("acl admin: expected a value at position %llu", start);
	}
	return StringUtil::Lower(c.text.substr(start, c.pos - start)) == "true" ||
	               StringUtil::Lower(c.text.substr(start, c.pos - start)) == "false"
	           ? StringUtil::Lower(c.text.substr(start, c.pos - start))
	           : c.text.substr(start, c.pos - start);
}

//! REQUIRE (sub LIKE 'repo:x:%', owner = 'hugr-lab', tid IN ('a', 'b'), 'admin' IN groups)
string RequireJson(const string &list) {
	vector<string> conditions;
	for (auto &item : SplitTopLevel(list, ',')) {
		if (item.empty()) {
			continue;
		}
		AdminScanner c(item);
		string path, op;
		vector<string> values;
		c.Skip();
		if (c.pos < item.size() && item[c.pos] == '\'') {
			// 'v' IN path: the claim (an array) contains the value
			values.push_back(c.Quoted("value"));
			c.Expect("in");
			path = ClaimPath(c);
			op = "contains";
		} else {
			path = ClaimPath(c);
			c.Skip();
			if (c.pos < item.size() && item[c.pos] == '=') {
				c.pos++;
				op = "eq";
				values.push_back(RequireValue(c));
			} else if (c.Accept("in")) {
				op = "in";
				for (auto &value : SplitTopLevel(c.Parens(), ',')) {
					if (!value.empty()) {
						values.push_back(Unquoted(value));
					}
				}
			} else if (c.Accept("like")) {
				op = "like";
				values.push_back(c.Quoted("pattern"));
			} else {
				throw BinderException("acl admin: a REQUIRE condition is path = value, path IN ('a', …), 'v' IN path "
				                      "or path LIKE 'p%%' - got \"%s\"",
				                      item);
			}
		}
		if (!c.Done()) {
			throw BinderException("acl admin: unexpected text in the REQUIRE condition \"%s\"", item);
		}
		conditions.push_back("{\"path\":" + JsonQuote(path) + ",\"op\":" + JsonQuote(op) +
		                     ",\"values\":" + JsonList(values) + "}");
	}
	return "[" + StringUtil::Join(conditions, ",") + "]";
}

//! ATTRIBUTES (tenant = 'tenant', email = ('email', 'upn'), org = CONSTANT 'acme')
string AttributesJson(const string &list) {
	vector<string> attributes;
	for (auto &item : SplitTopLevel(list, ',')) {
		if (item.empty()) {
			continue;
		}
		AdminScanner a(item);
		auto name = a.Word("an attribute name");
		a.Skip();
		if (a.pos >= item.size() || item[a.pos] != '=') {
			throw BinderException("acl admin: an attribute is written name = 'path' | ('path', …) | CONSTANT 'v' - "
			                      "got \"%s\"",
			                      item);
		}
		a.pos++;
		if (a.Accept("constant")) {
			attributes.push_back("{\"name\":" + JsonQuote(name) + ",\"constant\":" + JsonQuote(a.Quoted("value")) +
			                     "}");
		} else {
			vector<string> paths;
			if (a.AtParen()) {
				for (auto &path : SplitTopLevel(a.Parens(), ',')) {
					if (!path.empty()) {
						paths.push_back(Unquoted(path));
					}
				}
			} else {
				paths.push_back(ClaimPath(a));
			}
			attributes.push_back("{\"name\":" + JsonQuote(name) + ",\"paths\":" + JsonList(paths) + "}");
		}
		if (!a.Done()) {
			throw BinderException("acl admin: unexpected text in the attribute \"%s\"", item);
		}
	}
	return "[" + StringUtil::Join(attributes, ",") + "]";
}

//! `(window_max 64, batch_bytes '32MiB', …)` - a resource group's limits as the JSON the admin functions take
//! (spec 085; ALTER RESOURCE GROUP … SET (…), spec 120)
string ResourceLimitsJson(const string &inside) {
	vector<string> entries;
	case_insensitive_set_t named;
	for (auto &item : SplitTopLevel(inside, ',')) {
		auto text = item;
		StringUtil::Trim(text);
		if (text.empty()) {
			continue;
		}
		auto space = text.find_first_of(" \t=");
		if (space == string::npos) {
			throw BinderException("acl admin: a limit is written as name value, got \"%s\"", text);
		}
		auto name = text.substr(0, space);
		auto value = text.substr(space + 1);
		StringUtil::Trim(value);
		if (!value.empty() && value[0] == '=') {
			value = value.substr(1);
		}
		value = Unquoted(value);
		if (!named.insert(name).second) {
			throw BinderException("acl admin: limit \"%s\" is written twice - write each limit once", name);
		}
		entries.push_back(JsonQuote(StringUtil::Lower(name)) + ": " + JsonQuote(value));
	}
	return "{" + StringUtil::Join(entries, ", ") + "}";
}

//! A GRANT / REVOKE SECRET its rule did not read (spec 082 / 150 3g-2a): the form in its own words
[[noreturn]] void RefuseSecretsForm(bool grant) {
	RefuseMovedForm(grant
	                    ? "write GRANT SECRET <name> TO ROLE <role> | GROUP <group> [FROM | IN <service>] (a role or a "
	                      "group, never one user; the service one name - a dotted one quoted: IN \"a.b\")"
	                    : "write REVOKE SECRET <name> FROM ROLE <role> | GROUP <group> [FROM | IN <service>] (the "
	                      "service one name - a dotted one quoted: IN \"a.b\")");
}

//! A CREATE / ALTER / DROP after the `ACL` marker that is no management statement: said so, naming what it is
[[noreturn]] void RefuseNotManagement(const string &verb, const string &noun) {
	if (noun.empty()) {
		throw BinderException("acl admin: unknown management statement \"%s\"", verb);
	}
	throw BinderException("acl admin: %s %s is no management statement", StringUtil::Upper(verb),
	                      StringUtil::Upper(noun));
}

//! spec 150 3g-3c: a management statement no rule reads - refused in its form's own words, chosen by its head on
//! duckdb's tokens (every form is a rule: nothing is compiled from text any more)
[[noreturn]] void RefuseUnreadStatement(const string &text) {
	HeadWords head;
	auto heads = ReadStatementHeads(text, 6);
	if (!heads.empty()) {
		head.tokens = std::move(heads[0]);
	}
	auto keyword = head.Word(0);
	string usage;
	if (MgmtRulesKeyword(keyword, &usage, head.Word(1))) {
		// a linked module's statement its rules did not read - said in the module's words
		RefuseMovedForm(usage);
	}
	// spec 150, stage 3: the operations of a node are rules (acl_mgmt_grammar.cpp); one that reaches here did not
	// read as its rule - said in the form's own words
	if (StringUtil::CIEquals(keyword, "profile")) {
		RefuseMovedForm("write PROFILE SESSION CURRENT | '<id>' ON | ALL | SAMPLED | OFF");
	}
	if (StringUtil::CIEquals(keyword, "kill")) {
		RefuseMovedForm("write KILL SESSION '<id>'");
	}
	if (StringUtil::CIEquals(keyword, "set")) {
		RefuseMovedForm("write SET SESSION '<id>' AUDIT LEVEL OFF | DENIED | DECISIONS | ALL | DEFAULT, or SET SESSION "
		                "VIEW AS ROLE <role>");
	}
	if (StringUtil::CIEquals(keyword, "reset")) {
		RefuseMovedForm("write RESET SESSION VIEW AS");
	}
	if (StringUtil::CIEquals(keyword, "drain") || StringUtil::CIEquals(keyword, "resume")) {
		RefuseMovedForm("write DRAIN NODE / RESUME NODE");
	}
	if (StringUtil::CIEquals(keyword, "migrate")) {
		RefuseMovedForm("write MIGRATE POLICY CATALOG <database>[.<schema>] - a name that is an SQL keyword in double "
		                "quotes");
	}
	// spec 150, stage 3f: function grants and categories, platform's point grants, sources and resource groups are
	// rules - one that reaches here did not read as its rule
	if (StringUtil::CIEquals(keyword, "deny")) {
		RefuseMovedForm("write DENY FUNCTION [CATEGORY] <name> [TABLE | SCALAR] TO ROLE <role> | ALL ROLES, or DENY "
		                "VIEW platform.<view> TO ROLE <role>");
	}
	if (StringUtil::CIEquals(keyword, "create")) {
		idx_t at = 1;
		if (head.Word(at) == "or") {
			at += head.Word(at + 1) == "replace" ? 2 : 1;
		}
		auto noun = head.Word(at);
		if (noun == "virtual") {
			RefuseObjectForm(head, at + 1, false);
		}
		if (noun == "role") {
			RefuseMovedForm("write CREATE [OR REPLACE] ROLE [IF NOT EXISTS] <role> [CLAIMS (name = 'value', ...)]");
		}
		if (noun == "resource") {
			RefuseMovedForm(
			    "write CREATE [OR REPLACE] RESOURCE GROUP <group> [WITH] [(<limit> <value>, ...)] [DEFAULT] "
			    "[COMMENT '<text>']");
		}
		if (noun == "function") {
			if (head.Word(at + 1) != "category") {
				RefuseNotManagement("create", noun); // duckdb's CREATE FUNCTION is a macro
			}
			RefuseMovedForm("write CREATE [OR REPLACE] FUNCTION CATEGORY <category> [COMMENT '<text>']");
		}
		// spec 150, stage 3e: CREATE ISSUER | CLIENT are rules - one that reaches here did not read as its rule
		if (noun == "client") {
			RefuseMovedForm("write CREATE [OR REPLACE] CLIENT [IF NOT EXISTS] <client> ISSUER <issuer> [FROM SECRET "
			                "<secret> [IN <service>]] [<client clause> ...]");
		}
		if (noun != "issuer") {
			RefuseNotManagement("create", noun);
		}
		RefuseMovedForm("write CREATE [OR REPLACE] ISSUER [IF NOT EXISTS] <issuer> | '<url>' [URL '<url>'] [FROM "
		                "SECRET <secret> [IN <service>]] [CLIENT FROM SECRET <secret> [IN <service>]] [<client clause> "
		                "...]");
	}
	if (StringUtil::CIEquals(keyword, "add")) {
		RefuseObjectForm(head, 1, true);
	}
	if (StringUtil::CIEquals(keyword, "grant")) {
		auto noun = head.Word(1);
		if (noun == "secret") {
			RefuseSecretsForm(true);
		}
		if (noun == "source") {
			RefuseMovedForm("write GRANT SOURCE <database>[.<schema>] TO ROLE <role>");
		}
		if (noun == "resource") {
			RefuseMovedForm("write GRANT RESOURCE GROUP <group> TO ROLE <role>");
		}
		if (noun == "admin") {
			RefuseMovedForm("write GRANT ADMIN <scope> TO ROLE <role>");
		}
		if (noun == "function") {
			RefuseMovedForm("write GRANT FUNCTION [CATEGORY] <name> [TABLE | SCALAR] TO ROLE <role> | ALL ROLES");
		}
		// spec 150, stage 3d: GRANT CATALOG | SCHEMA | TABLE | VIEW | OBJECT are rules - one that reaches here did not
		// read as its rule
		RefuseGrantForm(head, 1, "grant");
	}
	if (StringUtil::CIEquals(keyword, "revoke")) {
		auto noun = head.Word(1);
		if (noun == "secret") {
			RefuseSecretsForm(false);
		}
		if (noun == "source") {
			RefuseMovedForm("write REVOKE SOURCE <database>[.<schema>] FROM ROLE <role>");
		}
		if (noun == "admin") {
			RefuseMovedForm("write REVOKE ADMIN [<scope>] FROM ROLE <role>");
		}
		if (noun == "resource") {
			RefuseMovedForm("write REVOKE RESOURCE GROUP <group> FROM ROLE <role>");
		}
		if (noun == "function") {
			RefuseMovedForm("write REVOKE FUNCTION [CATEGORY] <name> [TABLE | SCALAR] FROM ROLE <role> | ALL ROLES");
		}
		RefuseGrantForm(head, 1, "revoke");
	}
	if (StringUtil::CIEquals(keyword, "map")) {
		RefuseMovedForm("write MAP GROUP | CLAIM '<value>' FROM CLIENT | ISSUER <name> TO ROLE <role>");
	}
	if (StringUtil::CIEquals(keyword, "alter")) {
		auto noun = head.Word(1);
		if (noun == "function" && head.Word(2) != "category") {
			RefuseNotManagement("alter", noun);
		}
		if (noun == "function") {
			RefuseMovedForm(
			    "write ALTER FUNCTION CATEGORY <category> ADD | DROP (<function> [TABLE | SCALAR], ...) | SET COMMENT "
			    "'<text>'");
		}
		if (noun == "resource") {
			RefuseMovedForm(
			    "write ALTER RESOURCE GROUP <group> SET (<limit> <value>, ...) | SET COMMENT '<text>' | SET "
			    "DEFAULT | DROP DEFAULT");
		}
		if (noun == "role") {
			RefuseMovedForm("write ALTER ROLE <role> SET COMMENT '<text>' | SET CLAIMS (name = 'value', ...)");
		}
		if (noun == "issuer") {
			RefuseMovedForm(
			    "write ALTER ISSUER <issuer> SET URL '<url>' | [CLIENT] FROM SECRET <secret> [IN <service>] | "
			    "<client clause> ... | DROP [CLIENT] FROM SECRET");
		}
		if (noun == "client") {
			RefuseMovedForm("write ALTER CLIENT <client> SET FROM SECRET <secret> [IN <service>] | <client clause> "
			                "... | DROP FROM SECRET");
		}
		if (noun == "grant") {
			RefuseMovedForm("write ALTER GRANT CATALOG <catalog> TO ROLE <role> SET CAPS '<json>' | SET RLS "
			                "'<predicate>' | SET COLUMNS '<list>' | SET MAIN true | false");
		}
		// the object forms carry the VIRTUAL marker, so they never shadow duckdb's own ALTER
		if (noun != "virtual") {
			RefuseNotManagement("alter", noun);
		}
		RefuseObjectChange(head, 2, "alter");
	}
	if (StringUtil::CIEquals(keyword, "comment") || StringUtil::CIEquals(keyword, "check") ||
	    StringUtil::CIEquals(keyword, "repair") || StringUtil::CIEquals(keyword, "analyze")) {
		idx_t at = 1;
		at += head.Word(at) == "on" ? 1 : 0;
		at += head.Word(at) == "virtual" ? 1 : 0;
		RefuseObjectChange(head, at, StringUtil::Lower(keyword));
	}
	if (StringUtil::CIEquals(keyword, "drop")) {
		auto noun = head.Word(1);
		if (noun == "relation") {
			RefuseMovedForm("write DROP RELATION [IF EXISTS] <catalog>.<name>");
		}
		if (noun == "resource") {
			RefuseMovedForm("write DROP RESOURCE GROUP [IF EXISTS] <group>");
		}
		if (noun == "function") {
			if (head.Word(2) != "category") {
				RefuseNotManagement("drop", noun);
			}
			RefuseMovedForm("write DROP FUNCTION CATEGORY [IF EXISTS] <category>");
		}
		if (noun == "reference") {
			RefuseMovedForm("write DROP [VIRTUAL] REFERENCE [IF EXISTS] <catalog>.<name>");
		}
		if (noun == "role") {
			RefuseMovedForm("write DROP ROLE [IF EXISTS] <role>");
		}
		if (noun == "issuer" || noun == "client") {
			RefuseMovedForm("write DROP ISSUER | CLIENT [IF EXISTS] <name>");
		}
		if (noun == "map") {
			RefuseMovedForm("write DROP MAP GROUP | CLAIM '<value>' FROM CLIENT | ISSUER <name> TO ROLE <role>");
		}
		if (noun != "virtual") {
			RefuseNotManagement("drop", noun);
		}
		RefuseObjectChange(head, 2, "drop");
	}
	throw BinderException("acl admin: unknown management statement \"%s\"", keyword);
}

} // namespace

void RefuseRepeatedPrefix(const string &text) {
	RefuseRepeatedPrefix(BatchHeads(text));
}

void RefuseRepeatedPrefix(const vector<vector<HeadToken>> &heads) {
	// the rest after the prefix (and its marker) never starts with ACL either: `ACL ROLE "r" ; ACL …`
	for (idx_t i = 0; i < heads.size(); i++) {
		if (!heads[i].empty() && heads[i][0].IsWord("acl")) {
			throw BinderException("acl admin: one ACL prefix per batch - the statements after the prefix are written "
			                      "without one of their own (statement %llu starts with ACL)",
			                      i + 1);
		}
	}
}

bool BatchHasMgmtStatement(const string &text) {
	return BatchHasMgmtStatement(BatchHeads(text));
}

bool BatchHasMgmtStatement(const vector<vector<HeadToken>> &heads) {
	for (auto &head : heads) {
		if (IsMgmtHead(head)) {
			return true;
		}
	}
	return false;
}

bool BatchIsAllMgmt(const string &text) {
	auto heads = BatchHeads(text);
	for (auto &head : heads) {
		if (!IsMgmtHead(head)) {
			return false;
		}
	}
	return !heads.empty();
}

vector<unique_ptr<SQLStatement>> ParseMgmtBatch(const string &text, const string &current_session,
                                                AclGrammarCache &grammar, const ParserOptions &options) {
	RefuseRepeatedPrefix(text);
	if (!BatchIsAllMgmt(text) && BatchHasMgmtStatement(text)) {
		// spec 117: a batch is all management or all queries - a mix would run half of it in each world
		throw BinderException("acl admin: a batch mixing management statements and queries is refused - send each "
		                      "kind in a batch of its own");
	}
	// spec 150, stage 3: statement by statement as duckdb's grammar splits the batch - each by its rule; one no rule
	// reads is refused in its form's words
	struct Piece {
		MgmtParsed parsed;
		//! the tokenizer refused this statement: a moved form says the tokenizer's words
		shared_ptr<ErrorData> refused;
	};
	vector<Piece> pieces;
	try {
		for (auto &parsed : grammar.ReadManagement(text, options)) {
			pieces.push_back(Piece {std::move(parsed), nullptr});
		}
	} catch (ParserException &batch_refusal) {
		// a text duckdb's tokenizer refuses (an empty quoted name): statement by statement as that tokenizer ends them
		// - never a split of ours, which read quotes and comments otherwise (`$1$`, backticks, `E'\''`) and so could
		// hide a statement end or an open comment. Each statement the grammar reads is its rules', and the one it
		// refuses is refused in its form's words (or the tokenizer's)
		ErrorData batch_error(batch_refusal);
		pieces.clear();
		for (auto &piece : grammar.SplitManagement(text)) {
			try {
				for (auto &parsed : grammar.ReadManagement(piece, options)) {
					pieces.push_back(Piece {std::move(parsed), nullptr});
				}
			} catch (ParserException &refusal) {
				MgmtParsed parsed;
				parsed.unread = true;
				parsed.text = piece;
				pieces.push_back(Piece {std::move(parsed), make_shared_ptr<ErrorData>(refusal)});
			}
		}
		bool reproduced = false;
		for (auto &piece : pieces) {
			reproduced = reproduced || piece.refused;
		}
		if (!reproduced) {
			// no statement holds what the tokenizer refused: the batch is refused as a whole, never run without it
			auto info = batch_error.ExtraInfo();
			info.erase("position");
			info.erase("location");
			throw ParserException(info, batch_error.RawMessage());
		}
	}
	vector<unique_ptr<SQLStatement>> statements;
	for (auto &piece : pieces) {
		auto &entry = piece.parsed;
		if (entry.secrets || (entry.unread && IsSecretsStart(entry.text))) {
			throw BinderException("acl admin: GRANT / REVOKE SECRET goes in a batch of its own - its right is the "
			                      "secrets capability, not an administration scope");
		}
		if (entry.unread) {
			// a statement no rule reads: refused in its form's own words (or, when the tokenizer refused it, in its)
			try {
				RefuseUnreadStatement(entry.text);
			} catch (MovedFormRefusal &refusal) {
				if (piece.refused) {
					// the tokenizer's words - its position counts in the piece, not in the batch, so it goes
					auto info = piece.refused->ExtraInfo();
					info.erase("position");
					info.erase("location");
					throw ParserException(info, piece.refused->RawMessage());
				}
				if (!entry.hint.empty()) {
					throw BinderException(ErrorData(refusal).RawMessage() + entry.hint);
				}
				throw;
			}
			continue;
		}
		for (auto &list : entry.texts) {
			string read;
			switch (list.kind) {
			case MgmtParsed::TextKind::CLAIMS:
				read = ClaimsListToCsv(list.text);
				break;
			case MgmtParsed::TextKind::COLUMNS:
				read = UnquoteColumnsList(list.text);
				break;
			case MgmtParsed::TextKind::TEXT:
				read = list.text;
				break;
			case MgmtParsed::TextKind::ITEMS:
				read = ListItemsJson(list.text);
				break;
			case MgmtParsed::TextKind::REQUIRE:
				read = RequireJson(list.text);
				break;
			case MgmtParsed::TextKind::ATTRIBUTES:
				read = AttributesJson(list.text);
				break;
			case MgmtParsed::TextKind::CLAIM_MAP:
				read = JsonQuote(ClaimMapToJson(list.text)); // kept as a JSON string, which the spec parses
				break;
			case MgmtParsed::TextKind::LIMITS:
				read = ResourceLimitsJson(list.text);
				break;
			}
			if (list.splice.empty()) {
				entry.args[list.arg] = Value(read);
			} else {
				// a list inside a JSON spec: its reading where the rule left its marker
				entry.args[list.arg] = Value(StringUtil::Replace(entry.args[list.arg].ToString(), list.splice, read));
			}
		}
		for (auto &list : entry.texts) {
			// a reading is JSON, which never holds a raw control character: one left is a marker nothing replaced
			if (!list.splice.empty() && StringUtil::Contains(entry.args[list.arg].ToString(), "\x01")) {
				throw BinderException("acl admin: a list's marker is left in a spec");
			}
		}
		if (entry.current_session) {
			if (current_session.empty()) {
				throw BinderException(
				    "acl admin: PROFILE SESSION CURRENT needs a session - the statement runs under no "
				    "ACL SESSION prefix");
			}
			entry.args[0] = Value(current_session);
		}
		statements.push_back(entry.table_call ? MakeAdminTableCall(entry.function, entry.args)
		                                      : MakeAdminCall(entry.function, entry.args));
	}
	if (statements.empty()) {
		throw BinderException("acl admin: empty management batch");
	}
	return statements;
}

bool StartsWithMgmt(const string &text) {
	return StartsWithMgmt(BatchHeads(text));
}

bool StartsWithMgmt(const vector<vector<HeadToken>> &heads) {
	return !heads.empty() && IsMgmtHead(heads[0]);
}

bool ClientTextIsMgmt(const string &query, string &rest) {
	// as the override reads it behind the door's prefix (`ACL SESSION '<h>' ` + the door's markers + this text):
	// duckdb's normalized text; the markers a client may write itself, as the prefix rule reads them (`AclMarker*`:
	// `TRACE | PARENT <value>`, `LINEAGE` then `PARENT | ROOT | JOB <value>` parts, a value '…' or "…"); its mode
	// marker - `ACL` without NATIVE is management, which compiles or is refused at Prepare; else the first statement's
	// head past an empty one. `rest`: the text past the markers and the mode marker, for the door's other checks
	string normalized;
	vector<vector<HeadToken>> heads;
	try {
		normalized = Parser::NormalizeSQLString(query);
		heads = ReadStatementHeads(normalized, 32);
	} catch (std::exception &) {
		rest = query;
		return false; // text duckdb cannot normalize (invalid UTF-8): Prepare refuses it
	}
	rest = normalized;
	if (heads.empty()) {
		return false;
	}
	auto &first = heads[0];
	idx_t at = 0;
	auto value_at = [&](idx_t index) {
		return index < first.size() &&
		       (first[index].kind == HeadToken::Kind::STRING || first[index].kind == HeadToken::Kind::QUOTED_NAME);
	};
	auto lineage_part_at = [&](idx_t index) {
		return index < first.size() &&
		       (first[index].IsWord("parent") || first[index].IsWord("root") || first[index].IsWord("job")) &&
		       value_at(index + 1);
	};
	while (at < first.size()) {
		if (first[at].IsWord("lineage") && lineage_part_at(at + 1)) {
			at++;
			while (lineage_part_at(at)) {
				at += 2; // the parts repeat, greedily, as AclLineagePart+ takes them
			}
		} else if ((first[at].IsWord("trace") || first[at].IsWord("parent")) && value_at(at + 1)) {
			at += 2;
		} else {
			break;
		}
	}
	auto rest_from = [&](idx_t index) {
		rest = index < first.size() ? normalized.substr(first[index].offset) : string();
	};
	if (at < first.size() && first[at].IsWord("acl")) {
		bool native = at + 1 < first.size() && first[at + 1].IsWord("native");
		rest_from(at + (native ? 2 : 1));
		return !native;
	}
	if (at < first.size()) {
		rest_from(at);
		return IsMgmtHead(vector<HeadToken>(first.begin() + NumericCast<int64_t>(at), first.end()));
	}
	// the markers alone, then `;` (an empty statement)
	rest = heads.size() > 1 && !heads[1].empty() ? normalized.substr(heads[1][0].offset) : string();
	return heads.size() > 1 && IsMgmtHead(heads[1]);
}

bool ClientTextIsDdl(const string &query) {
	string rest;
	if (ClientTextIsMgmt(query, rest)) {
		return false;
	}
	try {
		Parser parser(ParserOptions::Builtin());
		parser.ParseQuery(rest);
		if (parser.statements.size() != 1) {
			return false;
		}
		auto &statement = *parser.statements[0];
		if (!statement.named_param_map.empty() || statement.has_anonymous_parameters) {
			return false;
		}
		switch (statement.type) {
		case StatementType::DROP_STATEMENT:
		case StatementType::ALTER_STATEMENT:
			return true;
		case StatementType::CREATE_STATEMENT: {
			auto &info = statement.Cast<CreateStatement>().info;
			return info && info->type != CatalogType::SECRET_ENTRY;
		}
		default:
			return false;
		}
	} catch (std::exception &) {
		return false; // not ours to judge: the prepared path refuses it in duckdb's words
	}
}

//===--------------------------------------------------------------------===//
// The node's secrets service (spec 082)
//===--------------------------------------------------------------------===//

bool IsSecretsStart(const string &text) {
	return IsSecretsStart(ReadStatementHeads(text, 2));
}

bool IsSecretsStart(const vector<vector<HeadToken>> &heads) {
	if (heads.empty() || heads[0].size() < 2) {
		return false; // never throws: it only decides which grammar the text is
	}
	return (heads[0][0].IsWord("grant") || heads[0][0].IsWord("revoke")) && heads[0][1].IsWord("secret");
}

namespace {

//! `GRANT SECRET <name> TO ROLE|GROUP <principal> [FROM|IN <catalog>]` /
//! `REVOKE SECRET <name> FROM ROLE|GROUP <principal> [FROM|IN <catalog>]` ->
//! `SELECT * FROM <catalog>.main.grant_secret('<name>', 'role:<r>', ['use'])` /
//! `... revoke_secret('<name>', 'role:<r>')` - the service's own calls (tresor spec 009), which it
//! refuses to anyone it does not know as an administrator.
struct SecretsStatement {
	bool grant = false;
	string name;
	string principal;
	string named; // the catalog the statement names ('' = none)
};

unique_ptr<SQLStatement> CompileSecretsStatement(const SecretsStatement &parsed, PolicyStore &store) {
	auto service = store.SecretService(parsed.named);
	bool grant = parsed.grant;
	auto &name = parsed.name;
	auto &principal = parsed.principal;

	vector<unique_ptr<ParsedExpression>> children;
	children.push_back(ConstantExpression::FromValue(Value(name)));
	children.push_back(ConstantExpression::FromValue(Value(principal)));
	if (grant) {
		children.push_back(ConstantExpression::FromValue(Value::LIST(LogicalType::VARCHAR, {Value("use")})));
	}
	auto call = grant ? "grant_secret" : "revoke_secret";
	auto function = make_uniq<FunctionExpression>(Identifier(call), std::move(children));
	function->SetQualifiedName(Identifier(service), Identifier("main"), Identifier(call));
	auto node = make_uniq<SelectNode>();
	node->select_list.push_back(make_uniq<StarExpression>());
	auto ref = make_uniq<TableFunctionRef>();
	ref->function = std::move(function);
	node->from_table = std::move(ref);
	auto statement = make_uniq<SelectStatement>();
	statement->node = std::move(node);
	return std::move(statement);
}

} // namespace

vector<unique_ptr<SQLStatement>> ParseSecretsBatch(const string &text, PolicyStore &store, AclGrammarCache &grammar,
                                                   const ParserOptions &options) {
	// the whole batch is read by its rules before any service is chosen: a malformed batch says so first
	vector<SecretsStatement> parsed;
	for (auto &entry : grammar.ReadManagement(text, options)) {
		if (entry.unread && IsSecretsStart(entry.text)) {
			// a GRANT / REVOKE SECRET its rule did not read, in that form's own words - nothing is compiled from text
			RefuseSecretsForm(ReadStatementHeads(entry.text, 1)[0][0].IsWord("grant"));
		}
		if (!entry.secrets) {
			throw BinderException(
			    "acl admin: a GRANT / REVOKE SECRET batch holds GRANT / REVOKE SECRET statements only");
		}
		SecretsStatement statement;
		statement.grant = entry.function == "grant_secret";
		statement.name = entry.args[0].ToString();
		statement.principal = entry.args[1].ToString();
		statement.named = entry.args[2].ToString();
		parsed.push_back(std::move(statement));
	}
	vector<unique_ptr<SQLStatement>> statements;
	for (auto &statement : parsed) {
		statements.push_back(CompileSecretsStatement(statement, store));
	}
	if (statements.empty()) {
		throw BinderException("acl admin: empty management batch");
	}
	return statements;
}

} // namespace acl
} // namespace duckdb
