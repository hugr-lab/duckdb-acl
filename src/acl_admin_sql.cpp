// The ACL management grammar (spec 008) and its authorization gate (spec 009). Moved out of
// acl_parser_override.cpp on 2026-09-03 (release plan 4.1): AuthorizeMgmt is the gate every
// management statement passes, and it was invisible inside a file named after prefix scanning.
// The grammar compiles text into acl_* admin-function calls; the parser override is its only caller.

#include "acl_admin_sql.hpp"
#include "acl_grammar.hpp"
#include "acl_admin_scanner.hpp"
#include "acl_platform.hpp"

#include "acl_door_common.hpp"
#include "acl_name_path.hpp"
#include "acl_scan_util.hpp"
#include "duckdb/common/exception/binder_exception.hpp"
#include "duckdb/common/helper.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/parser/expression/constant_expression.hpp"
#include "duckdb/parser/expression/function_expression.hpp"
#include "duckdb/parser/expression/star_expression.hpp"
#include "duckdb/parser/query_node/select_node.hpp"
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

struct MgmtGrammarEntry {
	string keyword;
	MgmtGrammar parse;
};

vector<MgmtGrammarEntry> &MgmtGrammars() {
	static vector<MgmtGrammarEntry> grammars;
	return grammars;
}

mutex &MgmtGrammarLock() {
	static mutex lock;
	return lock;
}

MgmtGrammar FindMgmtGrammar(const string &keyword) {
	lock_guard<mutex> guard(MgmtGrammarLock());
	for (auto &entry : MgmtGrammars()) {
		if (StringUtil::CIEquals(entry.keyword, keyword)) {
			return entry.parse;
		}
	}
	return nullptr;
}

} // namespace

void RegisterMgmtGrammar(const char *keyword, MgmtGrammar parse) {
	lock_guard<mutex> guard(MgmtGrammarLock());
	for (auto &entry : MgmtGrammars()) {
		if (StringUtil::CIEquals(entry.keyword, keyword)) {
			return;
		}
	}
	MgmtGrammars().push_back({keyword, parse});
}

bool IsMgmtStart(const string &text) {
	AdminScanner scanner(text);
	auto first = scanner.PeekWord();
	if (StringUtil::CIEquals(first, "add") || StringUtil::CIEquals(first, "grant") ||
	    StringUtil::CIEquals(first, "revoke") || StringUtil::CIEquals(first, "map")) {
		return true;
	}
	if (FindMgmtGrammar(first)) {
		return true; // a linked module's form (spec 126: CLUSTER - duckdb has no CLUSTER statement)
	}
	if (StringUtil::CIEquals(first, "deny")) {
		// DENY FUNCTION [CATEGORY] … (spec 072), DENY VIEW platform.<v> (spec 117): duckdb has no DENY at all
		AdminScanner ahead(text);
		ahead.Word("keyword");
		return StringUtil::CIEquals(ahead.PeekWord(), "function") || StringUtil::CIEquals(ahead.PeekWord(), "view");
	}
	if (StringUtil::CIEquals(first, "check") || StringUtil::CIEquals(first, "repair")) {
		// CHECK VIRTUAL CATALOG / REPAIR VIRTUAL TABLE (spec 039): ours always name a VIRTUAL target
		AdminScanner ahead(text);
		ahead.Word("keyword");
		return StringUtil::CIEquals(ahead.PeekWord(), "virtual");
	}
	if (StringUtil::CIEquals(first, "profile") || StringUtil::CIEquals(first, "kill")) {
		// PROFILE SESSION ... (spec 074 slice 3), KILL SESSION '<id>' (spec 118): duckdb has neither
		AdminScanner ahead(text);
		ahead.Word("keyword");
		return StringUtil::CIEquals(ahead.PeekWord(), "session");
	}
	if (StringUtil::CIEquals(first, "drain") || StringUtil::CIEquals(first, "resume")) {
		// DRAIN NODE / RESUME NODE (spec 118): duckdb has no such statements
		AdminScanner ahead(text);
		ahead.Word("keyword");
		return StringUtil::CIEquals(ahead.PeekWord(), "node");
	}
	if (StringUtil::CIEquals(first, "migrate")) {
		// MIGRATE POLICY CATALOG ... (spec 118)
		AdminScanner ahead(text);
		ahead.Word("keyword");
		return StringUtil::CIEquals(ahead.PeekWord(), "policy");
	}
	if (StringUtil::CIEquals(first, "set")) {
		// SET SESSION '<id>' AUDIT LEVEL ... (spec 118): a session named by a single-quoted id - duckdb's
		// SET SESSION <setting> (spec 068's TimeZone) names a setting, never a string
		AdminScanner ahead(text);
		ahead.Word("keyword");
		if (!ahead.Accept("session")) {
			return false;
		}
		ahead.Skip();
		if (ahead.pos < ahead.text.size() && ahead.text[ahead.pos] == '\'') {
			return true;
		}
		// SET SESSION VIEW AS ROLE ... (spec 120.3): no setting is written `view as`
		return ahead.Accept("view") && ahead.Accept("as");
	}
	if (StringUtil::CIEquals(first, "reset")) {
		// RESET SESSION VIEW AS (spec 120.3) - duckdb's RESET SESSION <setting> names one word
		AdminScanner ahead(text);
		ahead.Word("keyword");
		return ahead.Accept("session") && ahead.Accept("view") && ahead.Accept("as");
	}
	if (StringUtil::CIEquals(first, "comment") || StringUtil::CIEquals(first, "analyze")) {
		// duckdb owns COMMENT ON <object> and ANALYZE: ours always name a VIRTUAL target
		AdminScanner ahead(text);
		ahead.Word("keyword");
		if (StringUtil::CIEquals(first, "analyze")) {
			// `ANALYZE virtual` is duckdb's ANALYZE of a table named virtual: ours names a target after it
			if (!StringUtil::CIEquals(ahead.PeekWord(), "virtual")) {
				return false;
			}
			ahead.Word("virtual");
			return !ahead.PeekWord().empty();
		}
		ahead.Accept("on");
		return StringUtil::CIEquals(ahead.PeekWord(), "virtual");
	}
	if (StringUtil::CIEquals(first, "create") || StringUtil::CIEquals(first, "drop") ||
	    StringUtil::CIEquals(first, "alter")) {
		AdminScanner ahead(text);
		ahead.Word("keyword");
		auto second = ahead.PeekWord();
		// CREATE/ALTER/DROP FUNCTION CATEGORY (spec 072): duckdb's CREATE FUNCTION is a macro, so the
		// third word is what tells ours apart
		auto function_category = [&]() {
			if (!StringUtil::CIEquals(second, "function")) {
				return false;
			}
			ahead.Word("function");
			if (!StringUtil::CIEquals(ahead.PeekWord(), "category")) {
				return false;
			}
			// CREATE FUNCTION category(x) AS … is duckdb's macro named `category`: ours names one after it
			ahead.Word("category");
			return !ahead.PeekWord().empty() || (!ahead.Done() && ahead.text[ahead.pos] == '"');
		};
		if (StringUtil::CIEquals(first, "create")) {
			if (StringUtil::CIEquals(second, "or")) {
				// CREATE OR REPLACE VIRTUAL … - look past the modifier for the marker
				ahead.Word("or");
				ahead.Accept("replace");
				second = ahead.PeekWord();
			}
			return StringUtil::CIEquals(second, "virtual") || StringUtil::CIEquals(second, "role") ||
			       StringUtil::CIEquals(second, "issuer") || StringUtil::CIEquals(second, "client") ||
			       StringUtil::CIEquals(second, "resource") || function_category();
		}
		if (StringUtil::CIEquals(first, "alter")) {
			// duckdb owns ALTER TABLE/VIEW/...: our object forms carry the VIRTUAL marker, and
			// ALTER ROLE/ISSUER/GRANT do not exist in duckdb at all
			return StringUtil::CIEquals(second, "virtual") || StringUtil::CIEquals(second, "role") ||
			       StringUtil::CIEquals(second, "issuer") || StringUtil::CIEquals(second, "client") ||
			       StringUtil::CIEquals(second, "grant") || StringUtil::CIEquals(second, "resource") ||
			       function_category();
		}
		// DROP: our own forms carry VIRTUAL, and duckdb has no DROP ROLE/ISSUER/MAP/RELATION
		return StringUtil::CIEquals(second, "relation") || StringUtil::CIEquals(second, "virtual") ||
		       StringUtil::CIEquals(second, "role") || StringUtil::CIEquals(second, "issuer") ||
		       StringUtil::CIEquals(second, "client") || StringUtil::CIEquals(second, "map") ||
		       StringUtil::CIEquals(second, "reference") || StringUtil::CIEquals(second, "resource") ||
		       function_category();
	}
	return false;
}

namespace {

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

//! spec 150, stage 3c: CREATE VIRTUAL … and the ADD forms are rules (acl_mgmt_grammar.cpp) - one that reaches here did
//! not read as its rule, said in the form's own words
[[noreturn]] void RefuseObjectForm(AdminScanner &s, bool add) {
	auto kind = StringUtil::Lower(s.PeekWord());
	s.Accept(kind.c_str());
	bool function = kind == "scalar" || (kind == "table" && s.Accept("function"));
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
//! that reaches here did not read as its rule, said in the form's own words (`s` stands after `VIRTUAL`)
[[noreturn]] void RefuseObjectChange(AdminScanner &s, const string &verb) {
	auto kind = StringUtil::Lower(s.PeekWord());
	s.Accept(kind.c_str());
	bool function = kind == "scalar" || (kind == "table" && s.Accept("function"));
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
//! not read as its rule, said in the form's own words (`s` stands after GRANT / REVOKE)
[[noreturn]] void RefuseGrantForm(AdminScanner &s, const string &verb) {
	auto kind = StringUtil::Lower(s.PeekWord());
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
		entries.push_back(JsonQuote(StringUtil::Lower(name)) + ": " + JsonQuote(value));
	}
	return "{" + StringUtil::Join(entries, ", ") + "}";
}

unique_ptr<SQLStatement> ParseMgmtStatement(AdminScanner &s) {
	auto keyword = s.Word("a management keyword");
	if (auto parse = FindMgmtGrammar(keyword)) {
		return parse(s); // spec 126: a linked module's form
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
		RefuseMovedForm(
		    "write DENY FUNCTION [CATEGORY] <name> [TABLE] | DENY VIEW platform.<view> TO ROLE <role> | ALL "
		    "ROLES");
	}
	if (StringUtil::CIEquals(keyword, "create")) {
		if (s.Accept("or")) {
			s.Expect("replace");
		}
		if (s.Accept("virtual")) {
			RefuseObjectForm(s, false);
		}
		if (s.Accept("role")) {
			RefuseMovedForm("write CREATE [OR REPLACE] ROLE [IF NOT EXISTS] <role> [CLAIMS (name = 'value', ...)]");
		}
		if (s.Accept("resource")) {
			RefuseMovedForm(
			    "write CREATE [OR REPLACE] RESOURCE GROUP <group> [WITH] [(<limit> <value>, ...)] [DEFAULT] "
			    "[COMMENT '<text>']");
		}
		if (s.Accept("function")) {
			RefuseMovedForm("write CREATE FUNCTION CATEGORY <category> [COMMENT '<text>']");
		}
		// spec 150, stage 3e: CREATE ISSUER | CLIENT are rules - one that reaches here did not read as its rule
		if (s.Accept("client")) {
			RefuseMovedForm("write CREATE [OR REPLACE] CLIENT [IF NOT EXISTS] <client> ISSUER <issuer> [FROM SECRET "
			                "<secret> [IN <service>]] [<client clause> ...]");
		}
		s.Expect("issuer");
		RefuseMovedForm("write CREATE [OR REPLACE] ISSUER [IF NOT EXISTS] <issuer> | '<url>' [URL '<url>'] [FROM "
		                "SECRET <secret> [IN <service>]] [CLIENT FROM SECRET <secret> [IN <service>]] [<client clause> "
		                "...]");
	}
	if (StringUtil::CIEquals(keyword, "add")) {
		RefuseObjectForm(s, true);
	}
	if (StringUtil::CIEquals(keyword, "grant")) {
		if (s.Accept("source")) {
			RefuseMovedForm("write GRANT SOURCE <database>[.<schema>] TO ROLE <role>");
		}
		if (s.Accept("resource")) {
			RefuseMovedForm("write GRANT RESOURCE GROUP <group> TO ROLE <role>");
		}
		if (s.Accept("admin")) {
			RefuseMovedForm("write GRANT ADMIN <scope> TO ROLE <role>");
		}
		if (s.Accept("function")) {
			RefuseMovedForm("write GRANT FUNCTION [CATEGORY] <name> [TABLE] TO ROLE <role> | ALL ROLES");
		}
		// spec 150, stage 3d: GRANT CATALOG | SCHEMA | TABLE | VIEW | OBJECT are rules - one that reaches here did not
		// read as its rule
		RefuseGrantForm(s, "grant");
	}
	if (StringUtil::CIEquals(keyword, "revoke")) {
		if (s.Accept("source")) {
			RefuseMovedForm("write REVOKE SOURCE <database>[.<schema>] FROM ROLE <role>");
		}
		if (s.Accept("admin")) {
			RefuseMovedForm("write REVOKE ADMIN [<scope>] FROM ROLE <role>");
		}
		if (s.Accept("resource")) {
			RefuseMovedForm("write REVOKE RESOURCE GROUP <group> FROM ROLE <role>");
		}
		if (s.Accept("function")) {
			RefuseMovedForm("write REVOKE FUNCTION [CATEGORY] <name> [TABLE] FROM ROLE <role> | ALL ROLES");
		}
		RefuseGrantForm(s, "revoke");
	}
	if (StringUtil::CIEquals(keyword, "map")) {
		RefuseMovedForm("write MAP GROUP | CLAIM '<value>' FROM CLIENT | ISSUER <name> TO ROLE <role>");
	}
	if (StringUtil::CIEquals(keyword, "alter")) {
		if (s.Accept("function")) {
			RefuseMovedForm(
			    "write ALTER FUNCTION CATEGORY <category> ADD | DROP (<function> [TABLE], ...) | SET COMMENT "
			    "'<text>'");
		}
		if (s.Accept("resource")) {
			RefuseMovedForm(
			    "write ALTER RESOURCE GROUP <group> SET (<limit> <value>, ...) | SET COMMENT '<text>' | SET "
			    "DEFAULT | DROP DEFAULT");
		}
		if (s.Accept("role")) {
			RefuseMovedForm("write ALTER ROLE <role> SET COMMENT '<text>' | SET CLAIMS (name = 'value', ...)");
		}
		if (s.Accept("issuer")) {
			RefuseMovedForm(
			    "write ALTER ISSUER <issuer> SET URL '<url>' | [CLIENT] FROM SECRET <secret> [IN <service>] | "
			    "<client clause> ... | DROP [CLIENT] FROM SECRET");
		}
		if (s.Accept("client")) {
			RefuseMovedForm("write ALTER CLIENT <client> SET FROM SECRET <secret> [IN <service>] | <client clause> "
			                "... | DROP FROM SECRET");
		}
		if (s.Accept("grant")) {
			RefuseMovedForm("write ALTER GRANT CATALOG <catalog> TO ROLE <role> SET CAPS '<json>' | SET RLS "
			                "'<predicate>' | SET COLUMNS '<list>' | SET MAIN true | false");
		}
		// the object forms carry the VIRTUAL marker, so they never shadow duckdb's own ALTER
		s.Expect("virtual");
		RefuseObjectChange(s, "alter");
	}
	if (StringUtil::CIEquals(keyword, "comment") || StringUtil::CIEquals(keyword, "check") ||
	    StringUtil::CIEquals(keyword, "repair") || StringUtil::CIEquals(keyword, "analyze")) {
		s.Accept("on");
		s.Accept("virtual");
		RefuseObjectChange(s, StringUtil::Lower(keyword));
	}
	if (StringUtil::CIEquals(keyword, "drop")) {
		if (s.Accept("relation")) {
			RefuseMovedForm("write DROP RELATION [IF EXISTS] <catalog>.<name>");
		}
		if (s.Accept("resource")) {
			RefuseMovedForm("write DROP RESOURCE GROUP [IF EXISTS] <group>");
		}
		if (s.Accept("function")) {
			RefuseMovedForm("write DROP FUNCTION CATEGORY [IF EXISTS] <category>");
		}
		if (s.Accept("reference")) {
			RefuseMovedForm("write DROP [VIRTUAL] REFERENCE [IF EXISTS] <catalog>.<name>");
		}
		if (s.Accept("role")) {
			RefuseMovedForm("write DROP ROLE [IF EXISTS] <role>");
		}
		if (s.Accept("issuer") || s.Accept("client")) {
			RefuseMovedForm("write DROP ISSUER | CLIENT [IF EXISTS] <name>");
		}
		if (s.Accept("map")) {
			RefuseMovedForm("write DROP MAP GROUP | CLAIM '<value>' FROM CLIENT | ISSUER <name> TO ROLE <role>");
		}
		s.Expect("virtual");
		RefuseObjectChange(s, "drop");
	}
	throw BinderException("acl admin: unknown management statement \"%s\"", keyword);
}

//! The whole batch is management statements (the first one decided that); mixing is refused

} // namespace

namespace {

//! Where a comment that opens at `start` ends, as duckdb's tokenizer reads it (spec 150: the batch's split and the
//! grammar's agree) - a line comment at a line break of either kind, a block comment at the `*/` of its own depth
idx_t CommentEnd(const string &text, idx_t start) {
	if (text.compare(start, 2, "--") == 0) {
		auto end = text.find_first_of("\n\r", start);
		return end == string::npos ? text.size() : end;
	}
	idx_t depth = 0;
	for (idx_t i = start; i + 1 < text.size(); i++) {
		if (text[i] == '/' && text[i + 1] == '*') {
			depth++;
			i++;
		} else if (text[i] == '*' && text[i + 1] == '/') {
			if (--depth == 0) {
				return i + 2;
			}
			i++;
		}
	}
	return text.size();
}

} // namespace

vector<string> SplitBatchText(const string &text) {
	vector<string> out;
	string current;
	idx_t depth = 0;
	auto flush = [&]() {
		// the statement without what opens it but says nothing: whitespace and comments
		idx_t i = 0;
		while (i < current.size()) {
			if (StringUtil::CharacterIsSpace(current[i])) {
				i++;
			} else if (current.compare(i, 2, "--") == 0 || current.compare(i, 2, "/*") == 0) {
				i = CommentEnd(current, i);
			} else {
				break;
			}
		}
		auto statement = current.substr(i);
		StringUtil::Trim(statement);
		if (!statement.empty()) {
			out.push_back(statement);
		}
		current.clear();
	};
	for (idx_t i = 0; i < text.size(); i++) {
		auto c = text[i];
		if (c == '\'' || c == '"') {
			// a literal or a quoted identifier, the doubled quote its own escape
			current += c;
			for (i++; i < text.size(); i++) {
				current += text[i];
				if (text[i] == c) {
					if (i + 1 < text.size() && text[i + 1] == c) {
						current += text[++i];
						continue;
					}
					break;
				}
			}
			continue;
		}
		if (c == '$') {
			// a dollar-quoted string: $tag$ ... $tag$
			auto close = text.find('$', i + 1);
			if (close != string::npos) {
				auto tag = text.substr(i, close - i + 1);
				bool word = true;
				for (idx_t k = 1; k + 1 < tag.size(); k++) {
					word = word && IsWordChar(tag[k]);
				}
				auto end = word ? text.find(tag, close + 1) : string::npos;
				if (end != string::npos) {
					current += text.substr(i, end + tag.size() - i);
					i = end + tag.size() - 1;
					continue;
				}
			}
		}
		if ((c == '-' || c == '/') && i + 1 < text.size() && text[i + 1] == (c == '-' ? '-' : '*')) {
			auto end = CommentEnd(text, i);
			current += text.substr(i, end - i);
			i = end - 1;
			continue;
		}
		if (c == '(') {
			depth++;
		} else if (c == ')' && depth > 0) {
			depth--;
		} else if (c == ';' && depth == 0) {
			flush();
			continue;
		}
		current += c;
	}
	flush();
	return out;
}

void RefuseRepeatedPrefix(const string &text) {
	auto statements = SplitBatchText(text);
	for (idx_t i = 1; i < statements.size(); i++) {
		idx_t pos = 0;
		if (StringUtil::CIEquals(ReadWord(statements[i], pos), "acl")) {
			throw BinderException("acl admin: one ACL prefix per batch - the statements after the first are written "
			                      "without a prefix of their own (statement %llu starts with ACL)",
			                      i + 1);
		}
	}
}

bool BatchHasMgmtStatement(const string &text) {
	for (auto &statement : SplitBatchText(text)) {
		if (IsMgmtStart(statement)) {
			return true;
		}
	}
	return false;
}

bool BatchIsAllMgmt(const string &text) {
	auto statements = SplitBatchText(text);
	for (auto &statement : statements) {
		if (!IsMgmtStart(statement)) {
			return false;
		}
	}
	return !statements.empty();
}

//! One management statement written as text, compiled by the management compiler (a family no rule reads yet)
unique_ptr<SQLStatement> CompileMgmtText(const string &text) {
	AdminScanner scanner(text);
	auto statement = ParseMgmtStatement(scanner);
	if (!scanner.Done()) {
		throw BinderException("acl admin: unexpected trailing text at position %llu", scanner.pos);
	}
	return statement;
}

vector<unique_ptr<SQLStatement>> ParseMgmtBatch(const string &text, const string &current_session,
                                                AclGrammarCache &grammar, const ParserOptions &options) {
	RefuseRepeatedPrefix(text);
	if (!BatchIsAllMgmt(text) && BatchHasMgmtStatement(text)) {
		// spec 117: a batch is all management or all queries - a mix would run half of it in each world
		throw BinderException("acl admin: a batch mixing management statements and queries is refused - send each "
		                      "kind in a batch of its own");
	}
	// spec 150, stage 3: statement by statement as duckdb's grammar splits the batch - each by its rule, or as its own
	// text by the management compiler
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
		// refuses goes to the compiler, which says what is wrong in its own words, as it did
		ErrorData batch_error(batch_refusal);
		pieces.clear();
		for (auto &piece : grammar.SplitManagement(text)) {
			try {
				for (auto &parsed : grammar.ReadManagement(piece, options)) {
					pieces.push_back(Piece {std::move(parsed), nullptr});
				}
			} catch (ParserException &refusal) {
				MgmtParsed parsed;
				parsed.legacy = true;
				parsed.text = piece;
				parsed.unreadable = grammar.JudgeLegacy(piece);
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
		if (entry.legacy) {
			try {
				statements.push_back(CompileMgmtText(entry.text));
				if (!entry.unreadable.empty()) {
					// it compiled - from text its scanner reads otherwise than duckdb does
					throw BinderException("acl admin: %s in a statement no rule reads yet - its compiler would read it "
					                      "otherwise than written; write it without (its family becomes a rule in "
					                      "stage 3)",
					                      entry.unreadable);
				}
			} catch (MovedFormRefusal &) {
				if (piece.refused) {
					// the tokenizer's words - its position counts in the piece, not in the batch, so it goes
					auto info = piece.refused->ExtraInfo();
					info.erase("position");
					info.erase("location");
					throw ParserException(info, piece.refused->RawMessage());
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
	auto statements = SplitBatchText(text);
	return !statements.empty() && IsMgmtStart(statements[0]);
}

//===--------------------------------------------------------------------===//
// The node's secrets service (spec 082)
//===--------------------------------------------------------------------===//

bool IsSecretsStart(const string &text) {
	AdminScanner scanner(text);
	if (!scanner.Accept("grant") && !scanner.Accept("revoke")) {
		return false; // never throws: it only decides which grammar the text is
	}
	return StringUtil::CIEquals(scanner.PeekWord(), "secret");
}

namespace {

//! A name as written: quoted (either quote) or a bare word
string SecretsName(AdminScanner &s, const char *what) {
	s.Skip();
	if (s.pos < s.text.size() && (s.text[s.pos] == '\'' || s.text[s.pos] == '"')) {
		return s.Quoted(what);
	}
	return s.Word(what);
}

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

SecretsStatement ParseSecretsStatement(AdminScanner &s) {
	SecretsStatement out;
	auto verb = StringUtil::Lower(s.Word("GRANT or REVOKE"));
	bool grant = verb == "grant";
	out.grant = grant;
	s.Expect("secret");
	auto name = SecretsName(s, "secret name");
	s.Expect(grant ? "to" : "from");
	string kind;
	if (s.Accept("role")) {
		kind = "role";
	} else if (s.Accept("group")) {
		kind = "group";
	} else {
		throw BinderException("acl admin: a secret is granted to a ROLE or a GROUP, never to one user");
	}
	out.name = name;
	out.principal = kind + ":" + SecretsName(s, "role or group");
	if (s.Accept("from") || s.Accept("in")) {
		out.named = SecretsName(s, "catalog");
	}
	return out;
}

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

vector<unique_ptr<SQLStatement>> ParseSecretsBatch(const string &text, PolicyStore &store) {
	// the whole batch is read before any service is chosen: a malformed batch says so first
	vector<SecretsStatement> parsed;
	AdminScanner scanner(text);
	while (!scanner.Done()) {
		if (scanner.AtSemicolon()) {
			scanner.pos++;
			continue;
		}
		auto at = scanner.pos;
		if (!IsSecretsStart(text.substr(at))) {
			throw BinderException("acl admin: a GRANT / REVOKE SECRET batch holds nothing else");
		}
		parsed.push_back(ParseSecretsStatement(scanner));
		scanner.Skip();
		if (scanner.pos < text.size() && text[scanner.pos] != ';') {
			throw BinderException("acl admin: unexpected trailing text at position %llu", scanner.pos);
		}
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
