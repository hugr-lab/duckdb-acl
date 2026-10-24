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
namespace {

//! vcat.vname (a key): the first part is the catalog, the rest the in-catalog path - both as keys
void SplitVirtual(const string &path, string &vcat, string &vname) {
	if (!NamePath::SplitHeadKey(path, vcat, vname)) {
		throw BinderException("acl admin: \"%s\" must be written as <catalog>.<name>", path);
	}
}

} // namespace

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

//! `(tid => tenant, oid => user_id)` -> the stored JSON `{"tid": "tenant", "oid": "user_id"}`
string ClaimMapToJson(const string &list) {
	vector<string> entries;
	for (auto &item : SplitTopLevel(list, ',')) {
		if (item.empty()) {
			continue;
		}
		auto arrow = item.find("=>");
		if (arrow == string::npos) {
			throw BinderException("acl admin: a claim mapping is written as <jwt path> => <claim>, got \"%s\"", item);
		}
		auto from = item.substr(0, arrow);
		StringUtil::Trim(from);
		entries.push_back("\"" + Unquoted(from) + "\": \"" + Unquoted(item.substr(arrow + 2)) + "\"");
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

//! spec 072: a function as a grant or a member names it - `read_parquet`, `lake.main.peek`, a
//! double-quoted operator (`"+"`, `"IS DISTINCT FROM"`) - optionally followed by TABLE (or SCALAR,
//! the default); the text goes to the admin function as one spec, which parses it once more with
//! the same rules the function form takes
string FunctionSpecText(AdminScanner &s) {
	string spec;
	s.Skip();
	if (s.pos < s.text.size() && s.text[s.pos] == '"') {
		spec = "\"" + s.Quoted("a function name") + "\"";
	} else {
		spec = s.Dotted("a function name");
	}
	if (s.Accept("table")) {
		spec += " TABLE";
	} else if (s.Accept("scalar")) {
		spec += " SCALAR";
	}
	return spec;
}

//! `TO|FROM ROLE r` names the role, `TO|FROM ALL ROLES` is the role '' - every role's
string RoleOrAllRoles(AdminScanner &s, const char *preposition) {
	s.Expect(preposition);
	if (s.Accept("all")) {
		s.Expect("roles");
		return string();
	}
	s.Expect("role");
	return s.Ident("a role name");
}

//! spec 117: `platform.<object>` / `platform.main.<object>` next - a view or a function of the system
//! catalog, whose grants are its own (platform_grants), never a catalog's or spec 072's. Consumed only
//! when it is one; `object` is the leaf.
bool PlatformTarget(AdminScanner &s, string &object) {
	auto saved = s.pos;
	s.Skip();
	if (s.pos < s.text.size() && (s.text[s.pos] == '\'' || s.text[s.pos] == '"')) {
		// a quoted function spec (an operator) is never platform's
		if (s.text[s.pos] == '\'') {
			s.pos = saved;
			return false;
		}
	}
	NamePath path;
	try {
		path = s.Path("a name");
	} catch (std::exception &) {
		s.pos = saved;
		return false;
	}
	if (!PlatformObjectName(path.Parts(), object)) {
		s.pos = saved;
		return false;
	}
	return true;
}

//! GRANT | DENY | REVOKE VIEW|FUNCTION platform.<x> TO|FROM ROLE r (spec 117)
unique_ptr<SQLStatement> PlatformGrant(AdminScanner &s, const char *kind, const string &object, const char *verb) {
	auto grant = string(verb) != "revoke";
	auto role = RoleOrAllRoles(s, grant ? "to" : "from");
	if (grant) {
		return MakeAdminCall("acl_grant_platform", {Value(role), Value(kind), Value(object),
		                                            Value(string(verb) == "deny" ? "false" : "true")});
	}
	return MakeAdminCall("acl_revoke_platform", {Value(role), Value(kind), Value(object)});
}

// --- spec 095: issuers, clients, mappings --------------------------------------------------------

string JsonList(const vector<string> &values) {
	vector<string> quoted;
	for (auto &value : values) {
		quoted.push_back(JsonQuote(value));
	}
	return "[" + StringUtil::Join(quoted, ",") + "]";
}

//! A list written `(a, 'b', …)` or as the legacy quoted csv `'a,b'`; items unquoted
vector<string> ListItems(AdminScanner &s, const char *what) {
	vector<string> out;
	if (s.AtParen()) {
		for (auto &item : SplitTopLevel(s.Parens(), ',')) {
			auto value = Unquoted(item);
			StringUtil::Trim(value);
			if (!value.empty()) {
				out.push_back(value);
			}
		}
		return out;
	}
	for (auto &item : StringUtil::Split(s.Quoted(what), ',')) {
		StringUtil::Trim(item);
		if (!item.empty()) {
			out.push_back(item);
		}
	}
	return out;
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

//! `FROM SECRET s [IN c]` after its FROM SECRET: the spec entries naming it
void SecretRef(AdminScanner &s, vector<string> &entries) {
	auto secret = s.NameValue("a secret name");
	entries.push_back("\"secret\":" + JsonQuote(secret));
	if (s.Accept("in")) {
		entries.push_back("\"service\":" + JsonQuote(s.Ident("a secrets service")));
	}
}

//! One clause of a client (spec 095 §2), as a client-spec JSON entry. False when the next words are
//! not a client clause. `secret_clause` is how its secret is written: FROM SECRET (a client) or
//! CLIENT FROM SECRET (the short form, where FROM SECRET is the issuer's).
bool ClientClause(AdminScanner &s, vector<string> &entries, bool short_form) {
	auto saved = s.pos;
	if (s.Accept("audiences")) {
		entries.push_back("\"audiences\":" + JsonList(ListItems(s, "audiences")));
	} else if (s.Accept("azp")) {
		entries.push_back("\"azp\":" + JsonList(ListItems(s, "azp")));
	} else if (s.Accept("require")) {
		if (!s.AtParen()) {
			throw BinderException("acl admin: REQUIRE takes its conditions in parentheses");
		}
		entries.push_back("\"require\":" + RequireJson(s.Parens()));
	} else if (s.Accept("roles")) {
		if (s.Accept("from")) {
			entries.push_back("\"roles_from\":" + JsonList(ListItems(s, "claim paths")));
		} else {
			s.Expect("constant");
			entries.push_back("\"roles_constant\":" + JsonList(ListItems(s, "roles")));
		}
	} else if (s.Accept("role")) {
		s.Expect("claim"); // the short form's ROLE CLAIM 'path' - one source
		entries.push_back("\"roles_from\":" + JsonList({s.Quoted("role claim path")}));
	} else if (s.Accept("unmapped")) {
		if (s.Accept("ignore")) {
			entries.push_back("\"unmapped\":\"ignore\"");
		} else {
			s.Expect("as");
			s.Expect("role");
			entries.push_back("\"unmapped\":\"as_role\"");
		}
	} else if (s.Accept("attributes")) {
		if (!s.AtParen()) {
			throw BinderException("acl admin: ATTRIBUTES takes its list in parentheses");
		}
		entries.push_back("\"attributes\":" + AttributesJson(s.Parens()));
	} else if (s.Accept("claim")) {
		s.Expect("map"); // the short form's CLAIM MAP: {"<jwt path>": "<name>"}
		auto map = s.AtParen() ? ClaimMapToJson(s.Parens()) : s.Quoted("claim map");
		entries.push_back("\"claim_map\":" + JsonQuote(map)); // text: parsed by the spec, never spliced
	} else if (s.Accept("subject")) {
		vector<string> paths;
		if (s.AtParen()) {
			paths = ListItems(s, "subject paths");
		} else {
			paths.push_back(s.Quoted("subject path"));
		}
		entries.push_back("\"subject\":" + JsonList(paths));
	} else if (s.Accept("token")) {
		s.Expect("type");
		entries.push_back("\"token_type\":" + JsonQuote(s.Quoted("token type")));
	} else if (s.Accept("flows")) {
		entries.push_back("\"flows\":" + JsonList(ListItems(s, "flows")));
	} else if (s.Accept("client")) {
		if (s.Accept("id")) {
			entries.push_back("\"client_id\":" + JsonQuote(s.Quoted("client id")));
		} else if (short_form && s.Accept("from")) {
			s.Expect("secret");
			SecretRef(s, entries);
		} else if (s.Accept("secret")) {
			throw BinderException("acl admin: a client secret is never written into the policy - keep it as "
			                      "CLIENT_SECRET in an oidc_client secret of the secrets service and name that "
			                      "secret (%s)",
			                      short_form ? "CLIENT FROM SECRET s" : "FROM SECRET s");
		} else {
			s.pos = saved;
			return false;
		}
	} else if (!short_form && s.Accept("from")) {
		s.Expect("secret");
		SecretRef(s, entries);
	} else if (s.Accept("keys") || s.Accept("algs")) {
		throw BinderException("acl admin: an issuer's keys and algorithms are never written into the policy - "
		                      "the issuer's OIDC discovery supplies them, or KEYS / KEYS_FROM / ALGS in an "
		                      "oidc_issuer secret named with FROM SECRET");
	} else {
		return false;
	}
	return true;
}

string SpecJson(const vector<string> &entries) {
	return "{" + StringUtil::Join(entries, ",") + "}";
}

//! CREATE [OR REPLACE] ISSUER [IF NOT EXISTS] <name | '<url>'> [URL '<url>'] [FROM SECRET s [IN c]]
//! [client clauses] - any client clause makes it the short form, with an implicit client
unique_ptr<SQLStatement> ParseCreateIssuer(AdminScanner &s, string mode) {
	if (s.Accept("if")) {
		s.Expect("not");
		s.Expect("exists");
		if (mode == "create") {
			mode = "skip";
		}
	}
	s.Skip();
	bool quoted = s.pos < s.text.size() && (s.text[s.pos] == '\'' || s.text[s.pos] == '"');
	auto name = quoted ? s.Quoted("issuer") : s.Ident("an issuer name");
	vector<string> issuer_entries, client_entries;
	bool has_url = false, has_secret = false;
	while (!s.Done() && !s.AtSemicolon()) {
		if (s.Accept("url")) {
			issuer_entries.push_back("\"url\":" + JsonQuote(s.Quoted("URL")));
			has_url = true;
			continue;
		}
		auto saved = s.pos;
		if (s.Accept("from")) {
			s.Expect("secret");
			SecretRef(s, issuer_entries);
			has_secret = true;
			continue;
		}
		s.pos = saved;
		if (!ClientClause(s, client_entries, true)) {
			throw BinderException("acl admin: unexpected \"%s\" in CREATE ISSUER", s.PeekWord());
		}
	}
	if (!has_url && quoted) {
		// the short form's name IS its URL
		issuer_entries.push_back("\"url\":" + JsonQuote(name));
	} else if (!has_url && !has_secret) {
		throw BinderException("acl admin: issuer \"%s\" needs its URL - URL '<url>', or the URL as its quoted name, "
		                      "or an oidc_issuer secret carrying it (FROM SECRET s)",
		                      name);
	}
	if (!client_entries.empty()) {
		issuer_entries.push_back("\"client\":" + SpecJson(client_entries));
	}
	return MakeAdminCall("acl_define_issuer", {Value(name), Value(SpecJson(issuer_entries)), Value(mode)});
}

//! CREATE [OR REPLACE] CLIENT [IF NOT EXISTS] c ISSUER i <client clauses>
unique_ptr<SQLStatement> ParseCreateClient(AdminScanner &s, string mode) {
	if (s.Accept("if")) {
		s.Expect("not");
		s.Expect("exists");
		if (mode == "create") {
			mode = "skip";
		}
	}
	auto name = s.NameValue("a client name");
	s.Expect("issuer");
	auto issuer = s.NameValue("an issuer name");
	vector<string> entries;
	while (!s.Done() && !s.AtSemicolon()) {
		if (!ClientClause(s, entries, false)) {
			throw BinderException("acl admin: unexpected \"%s\" in CREATE CLIENT", s.PeekWord());
		}
	}
	return MakeAdminCall("acl_define_client", {Value(name), Value(issuer), Value(SpecJson(entries)), Value(mode)});
}

//! ALTER ISSUER i SET URL '…' | SET FROM SECRET s [IN c] | DROP FROM SECRET | SET <client clause> …
//! | DROP CLIENT FROM SECRET
unique_ptr<SQLStatement> ParseAlterIssuer(AdminScanner &s) {
	auto name = s.NameValue("an issuer name");
	vector<string> issuer_entries, client_entries;
	if (s.Accept("drop")) {
		if (s.Accept("client")) {
			s.Expect("from");
			s.Expect("secret");
			client_entries.push_back("\"secret\":null");
		} else {
			s.Expect("from");
			s.Expect("secret");
			issuer_entries.push_back("\"secret\":null");
		}
	} else {
		s.Expect("set");
		while (!s.Done() && !s.AtSemicolon()) {
			if (s.Accept("url")) {
				auto url = s.Quoted("URL");
				issuer_entries.push_back("\"url\":" + (url.empty() ? string("null") : JsonQuote(url)));
				continue;
			}
			auto saved = s.pos;
			if (s.Accept("from")) {
				s.Expect("secret");
				SecretRef(s, issuer_entries);
				continue;
			}
			s.pos = saved;
			if (!ClientClause(s, client_entries, true)) {
				throw BinderException("acl admin: unexpected \"%s\" in ALTER ISSUER", s.PeekWord());
			}
		}
	}
	if (!client_entries.empty()) {
		issuer_entries.push_back("\"client\":" + SpecJson(client_entries));
	}
	if (issuer_entries.empty()) {
		throw BinderException("acl admin: ALTER ISSUER %s changes nothing", name);
	}
	return MakeAdminCall("acl_alter_issuer", {Value(name), Value(SpecJson(issuer_entries))});
}

//! ALTER CLIENT c SET <client clause> … | DROP FROM SECRET
unique_ptr<SQLStatement> ParseAlterClient(AdminScanner &s) {
	auto name = s.NameValue("a client name");
	vector<string> entries;
	if (s.Accept("drop")) {
		s.Expect("from");
		s.Expect("secret");
		entries.push_back("\"secret\":null");
	} else {
		s.Expect("set");
		while (!s.Done() && !s.AtSemicolon()) {
			if (!ClientClause(s, entries, false)) {
				throw BinderException("acl admin: unexpected \"%s\" in ALTER CLIENT", s.PeekWord());
			}
		}
	}
	if (entries.empty()) {
		throw BinderException("acl admin: ALTER CLIENT %s changes nothing", name);
	}
	return MakeAdminCall("acl_alter_client", {Value(name), Value(SpecJson(entries))});
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
	if (StringUtil::CIEquals(keyword, "deny")) {
		// DENY FUNCTION CATEGORY c TO ROLE r | ALL ROLES; DENY FUNCTION f [TABLE] TO ROLE r | ALL ROLES
		// (spec 072): a grant row with allowed = false, which wins over every grant
		string object;
		if (s.Accept("view")) { // spec 117: DENY VIEW platform.<v> TO ROLE r
			if (!PlatformTarget(s, object)) {
				throw BinderException("acl admin: DENY VIEW names a view of the platform catalog (platform.<view>)");
			}
			return PlatformGrant(s, "view", object, "deny");
		}
		s.Expect("function");
		if (PlatformTarget(s, object)) {
			return PlatformGrant(s, "function", object, "deny");
		}
		if (s.Accept("category")) {
			auto category = s.Ident("a category name");
			auto role = RoleOrAllRoles(s, "to");
			return MakeAdminCall("acl_grant_function_category", {Value(role), Value(category), Value("false")});
		}
		auto spec = FunctionSpecText(s);
		auto role = RoleOrAllRoles(s, "to");
		return MakeAdminCall("acl_grant_function", {Value(role), Value(spec), Value("false")});
	}
	if (StringUtil::CIEquals(keyword, "create")) {
		// what the statement promises about an existing object: CREATE refuses to overwrite one,
		// OR REPLACE overwrites, IF NOT EXISTS keeps it (spec 013). The legacy ADD forms upsert.
		string mode = "create";
		if (s.Accept("or")) {
			s.Expect("replace");
			mode = "replace";
		}
		if (s.Accept("virtual")) {
			RefuseObjectForm(s, false);
		}
		if (s.Accept("role")) {
			RefuseMovedForm("write CREATE [OR REPLACE] ROLE [IF NOT EXISTS] <role> [CLAIMS (name = 'value', ...)]");
		}
		if (s.Accept("resource")) {
			// CREATE [OR REPLACE] RESOURCE GROUP g [WITH] (window_max 64, batch_bytes '32MiB', …)
			// [COMMENT '…'] (spec 085): a re-create replaces the limits; the roles bound to it stay
			s.Expect("group");
			auto group = s.Ident("a group name");
			s.Accept("with");
			string limits = "{}";
			if (s.AtParen()) {
				limits = ResourceLimitsJson(s.Parens());
			}
			// DEFAULT (spec 096): principals bound to no group are its members; before or after COMMENT
			string comment, is_default;
			bool commented = false;
			for (int clause = 0; clause < 2; clause++) {
				if (is_default.empty() && s.Accept("default")) {
					is_default = "true";
				} else if (!commented && s.Accept("comment")) {
					comment = s.Quoted("comment");
					commented = true;
				}
			}
			return MakeAdminCall("acl_create_resource_group",
			                     {Value(group), Value(limits), Value(comment), Value(is_default)});
		}
		if (s.Accept("function")) {
			// CREATE FUNCTION CATEGORY c [COMMENT '…'] (spec 072): the operator's own category; a
			// re-create keeps the members and grants and takes the new comment
			s.Expect("category");
			auto category = s.Ident("a category name");
			string comment;
			if (s.Accept("comment")) {
				comment = s.Quoted("comment");
			}
			return MakeAdminCall("acl_create_function_category", {Value(category), Value(comment)});
		}
		if (s.Accept("client")) {
			return ParseCreateClient(s, mode);
		}
		s.Expect("issuer");
		return ParseCreateIssuer(s, mode);
	}
	if (StringUtil::CIEquals(keyword, "add")) {
		RefuseObjectForm(s, true);
	}
	if (StringUtil::CIEquals(keyword, "grant")) {
		if (s.Accept("source")) {
			// GRANT SOURCE <database>[.<schema>] TO ROLE r (spec 118.3): the physical tree a catalog admin
			// sees under platform.attached, and the only sources it builds over
			auto source = s.Dotted("a source (<database>[.<schema>])");
			s.Expect("to");
			s.Expect("role");
			return MakeAdminCall("acl_grant_source", {Value(s.Ident("a role name")), Value(source)});
		}
		if (s.Accept("resource")) {
			// GRANT RESOURCE GROUP g TO ROLE r (spec 085)
			s.Expect("group");
			auto group = s.Ident("a group name");
			s.Expect("to");
			s.Expect("role");
			return MakeAdminCall("acl_grant_resource_group", {Value(s.Ident("a role name")), Value(group)});
		}
		if (s.Accept("admin")) {
			RefuseMovedForm("write GRANT ADMIN <scope> TO ROLE <role>");
		}
		if (s.Accept("function")) {
			// GRANT FUNCTION CATEGORY c TO ROLE r | ALL ROLES; GRANT FUNCTION f [TABLE] TO ROLE r | ALL
			// ROLES (spec 072) - a grant by name admits the key whatever its categories
			string object;
			if (PlatformTarget(s, object)) { // spec 117: a function of the platform catalog
				return PlatformGrant(s, "function", object, "grant");
			}
			if (s.Accept("category")) {
				auto category = s.Ident("a category name");
				auto role = RoleOrAllRoles(s, "to");
				return MakeAdminCall("acl_grant_function_category", {Value(role), Value(category), Value("true")});
			}
			auto spec = FunctionSpecText(s);
			auto role = RoleOrAllRoles(s, "to");
			return MakeAdminCall("acl_grant_function", {Value(role), Value(spec), Value("true")});
		}
		// spec 117: GRANT VIEW platform.<v> TO ROLE r - a view of the system catalog (the grant rule hands it here)
		{
			auto saved = s.pos;
			string object;
			if (s.Accept("view") && PlatformTarget(s, object)) {
				return PlatformGrant(s, "view", object, "grant");
			}
			s.pos = saved;
		}
		// spec 150, stage 3d: GRANT CATALOG | SCHEMA | TABLE | VIEW | OBJECT are rules - one that reaches here did not
		// read as its rule
		RefuseGrantForm(s, "grant");
	}
	if (StringUtil::CIEquals(keyword, "revoke")) {
		if (s.Accept("source")) {
			// REVOKE SOURCE <database>[.<schema>] FROM ROLE r (spec 118.3): what the role declared over it
			// keeps working - an explicit DROP removes it
			auto source = s.Dotted("a source (<database>[.<schema>])");
			s.Expect("from");
			s.Expect("role");
			return MakeAdminCall("acl_revoke_source", {Value(s.Ident("a role name")), Value(source)});
		}
		if (s.Accept("admin")) {
			RefuseMovedForm("write REVOKE ADMIN [<scope>] FROM ROLE <role>");
		}
		{
			// spec 117: REVOKE VIEW|FUNCTION platform.<x> FROM ROLE r
			auto saved = s.pos;
			string object;
			if (s.Accept("view") && PlatformTarget(s, object)) {
				return PlatformGrant(s, "view", object, "revoke");
			}
			s.pos = saved;
			if (s.Accept("function") && PlatformTarget(s, object)) {
				return PlatformGrant(s, "function", object, "revoke");
			}
			s.pos = saved;
		}
		if (s.Accept("resource")) {
			// REVOKE RESOURCE GROUP g FROM ROLE r (spec 085)
			s.Expect("group");
			auto group = s.Ident("a group name");
			s.Expect("from");
			s.Expect("role");
			return MakeAdminCall("acl_revoke_resource_group", {Value(s.Ident("a role name")), Value(group)});
		}
		if (s.Accept("function")) {
			// REVOKE FUNCTION CATEGORY c FROM ROLE r | ALL ROLES; REVOKE FUNCTION f [TABLE] FROM ROLE r |
			// ALL ROLES (spec 072): the row goes, grant or deny alike
			if (s.Accept("category")) {
				auto category = s.Ident("a category name");
				auto role = RoleOrAllRoles(s, "from");
				return MakeAdminCall("acl_revoke_function_category", {Value(role), Value(category)});
			}
			auto spec = FunctionSpecText(s);
			auto role = RoleOrAllRoles(s, "from");
			return MakeAdminCall("acl_revoke_function", {Value(role), Value(spec)});
		}
		RefuseGrantForm(s, "revoke");
	}
	if (StringUtil::CIEquals(keyword, "map")) {
		RefuseMovedForm("write MAP GROUP | CLAIM '<value>' FROM CLIENT | ISSUER <name> TO ROLE <role>");
	}
	if (StringUtil::CIEquals(keyword, "alter")) {
		if (s.Accept("function")) {
			// ALTER FUNCTION CATEGORY c ADD (f [TABLE], db.schema.f TABLE, "+") | DROP (…) (spec 072):
			// the list goes to the admin function as written, which parses each spec
			s.Expect("category");
			auto category = s.Ident("a category name");
			if (s.Accept("set")) { // spec 120: ALTER FUNCTION CATEGORY c SET COMMENT '…' - the category must exist; its
				                   // members stay
				s.Expect("comment");
				return MakeAdminCall("acl_comment_function_category", {Value(category), Value(s.Quoted("comment"))});
			}
			bool add = s.Accept("add");
			if (!add) {
				s.Expect("drop");
			}
			auto members = s.Parens();
			if (members.empty()) {
				throw BinderException("acl admin: ALTER FUNCTION CATEGORY %s the members in parentheses",
				                      add ? "ADD takes" : "DROP takes");
			}
			return MakeAdminCall(add ? "acl_function_category_add" : "acl_function_category_remove",
			                     {Value(category), Value(members)});
		}
		if (s.Accept(
		        "resource")) { // spec 096 / 120: ALTER RESOURCE GROUP g SET (limits) | SET COMMENT | SET|DROP DEFAULT
			s.Expect("group");
			auto group = s.Ident("a group name");
			bool set = s.Accept("set");
			if (set && s.AtParen()) {
				return MakeAdminCall("acl_alter_resource_group",
				                     {Value(group), Value("limits"), Value(ResourceLimitsJson(s.Parens()))});
			}
			if (set && s.Accept("comment")) {
				return MakeAdminCall("acl_alter_resource_group",
				                     {Value(group), Value("comment"), Value(s.Quoted("comment"))});
			}
			if (!set) {
				s.Expect("drop");
			}
			s.Expect("default");
			return MakeAdminCall("acl_alter_resource_group",
			                     {Value(group), Value("default"), Value(set ? "true" : "false")});
		}
		if (s.Accept("role")) {
			RefuseMovedForm("write ALTER ROLE <role> SET COMMENT '<text>' | SET CLAIMS (name = 'value', ...)");
		}
		if (s.Accept("issuer")) { // spec 095: ALTER ISSUER i SET … | DROP [CLIENT] FROM SECRET
			return ParseAlterIssuer(s);
		}
		if (s.Accept("client")) { // spec 095: ALTER CLIENT c SET … | DROP FROM SECRET
			return ParseAlterClient(s);
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
		// `IF EXISTS` says nothing-to-drop is not an error; without it a missing target is reported,
		// which is what makes a typo visible (spec 010)
		string mode;
		auto if_exists = [&mode](AdminScanner &scanner) {
			if (scanner.Accept("if")) {
				scanner.Expect("exists");
				mode = "skip";
			}
		};
		if (s.Accept("relation")) {
			RefuseMovedForm("write DROP RELATION [IF EXISTS] <catalog>.<name>");
		}
		if (s.Accept("resource")) {
			// DROP RESOURCE GROUP [IF EXISTS] g (spec 085): its role bindings go too
			s.Expect("group");
			if_exists(s);
			return MakeAdminCall("acl_drop_resource_group", {Value(s.Ident("a group name")), Value(mode)});
		}
		if (s.Accept("function")) {
			// DROP FUNCTION CATEGORY [IF EXISTS] c (spec 072): the members and every grant on it go too
			s.Expect("category");
			if_exists(s);
			return MakeAdminCall("acl_drop_function_category", {Value(s.Ident("a category name")), Value(mode)});
		}
		if (s.Accept("reference")) {
			RefuseMovedForm("write DROP [VIRTUAL] REFERENCE [IF EXISTS] <catalog>.<name>");
		}
		if (s.Accept("role")) {
			RefuseMovedForm("write DROP ROLE [IF EXISTS] <role>");
		}
		if (s.Accept("issuer")) {
			if_exists(s);
			return MakeAdminCall("acl_drop_issuer", {Value(s.NameValue("an issuer name")), Value(mode)});
		}
		if (s.Accept("client")) {
			if_exists(s);
			return MakeAdminCall("acl_drop_client", {Value(s.NameValue("a client name")), Value(mode)});
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
			switch (list.kind) {
			case MgmtParsed::TextKind::CLAIMS:
				entry.args[list.arg] = Value(ClaimsListToCsv(list.text));
				break;
			case MgmtParsed::TextKind::COLUMNS:
				entry.args[list.arg] = Value(UnquoteColumnsList(list.text));
				break;
			case MgmtParsed::TextKind::TEXT:
				entry.args[list.arg] = Value(list.text);
				break;
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
