// The ACL management grammar (spec 008) and its authorization gate (spec 009). Moved out of
// acl_parser_override.cpp on 2026-09-03 (release plan 4.1): AuthorizeMgmt is the gate every
// management statement passes, and it was invisible inside a file named after prefix scanning.
// The grammar compiles text into acl_* admin-function calls; the parser override is its only caller.

#include "acl_admin_sql.hpp"

#include "acl_scan_util.hpp"
#include "duckdb/common/exception/binder_exception.hpp"
#include "duckdb/common/exception/parser_exception.hpp"
#include "duckdb/common/helper.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/parser/expression/constant_expression.hpp"
#include "duckdb/parser/expression/function_expression.hpp"
#include "duckdb/parser/parser.hpp"
#include "duckdb/parser/parsed_data/create_info.hpp"
#include "duckdb/parser/query_node/select_node.hpp"
#include "duckdb/parser/statement/create_statement.hpp"
#include "duckdb/parser/statement/select_statement.hpp"
#include "duckdb/parser/tableref/emptytableref.hpp"

#include <algorithm>
#include <cstring>
#include <unordered_map>

namespace duckdb {
namespace acl {
namespace {

struct AdminScanner {
	const string &text;
	idx_t pos = 0;

	explicit AdminScanner(const string &text_p) : text(text_p) {
	}
	void Skip() {
		SkipWhitespace(text, pos);
	}
	bool Done() {
		Skip();
		return pos >= text.size();
	}
	bool AtSemicolon() {
		Skip();
		return pos < text.size() && text[pos] == ';';
	}
	string PeekWord() {
		Skip();
		auto saved = pos;
		auto word = ReadWord(text, pos);
		pos = saved;
		return word;
	}
	string Word(const char *what) {
		Skip();
		auto word = ReadWord(text, pos);
		if (word.empty()) {
			throw BinderException("acl admin: expected %s at position %llu", what, pos);
		}
		return word;
	}
	void Expect(const char *keyword) {
		auto word = Word(keyword);
		if (!StringUtil::CIEquals(word, keyword)) {
			throw BinderException("acl admin: expected %s, got \"%s\"", keyword, word);
		}
	}
	bool Accept(const char *keyword) {
		Skip();
		auto saved = pos;
		auto word = ReadWord(text, pos);
		if (StringUtil::CIEquals(word, keyword)) {
			return true;
		}
		pos = saved;
		return false;
	}
	bool AtParen() {
		Skip();
		return pos < text.size() && text[pos] == '(';
	}
	string Quoted(const char *what) {
		Skip();
		if (pos >= text.size() || (text[pos] != '\'' && text[pos] != '"')) {
			throw BinderException("acl admin: expected a quoted %s at position %llu", what, pos);
		}
		return ReadQuoted(text, pos);
	}
	//! The text inside a parenthesised list, e.g. `(id INT, amount INT)` -> "id INT, amount INT".
	//! Returns empty when the next token is not '('.
	string Parens() {
		Skip();
		if (pos >= text.size() || text[pos] != '(') {
			return string();
		}
		auto start = ++pos;
		idx_t depth = 1;
		while (pos < text.size() && depth > 0) {
			auto c = text[pos];
			if (c == '\'' || c == '"') {
				ReadQuoted(text, pos);
				continue;
			}
			if (c == '(') {
				depth++;
			} else if (c == ')') {
				depth--;
				if (depth == 0) {
					break;
				}
			}
			pos++;
		}
		if (depth != 0) {
			throw BinderException("acl admin: unbalanced parentheses at position %llu", start);
		}
		auto body = text.substr(start, pos - start);
		pos++; // the closing paren
		StringUtil::Trim(body);
		return body;
	}

	//! Everything up to the end of this statement, taken verbatim - quote- and paren-aware, so a
	//! body may contain ';' inside a literal or a parenthesised list. This is what makes an inline
	//! body possible: `AS SELECT … WHERE tenant = acl_claim('tenant')` instead of the same text in a
	//! quoted string with every quote doubled.
	string Rest(const char *what) {
		Skip();
		auto start = pos;
		idx_t depth = 0;
		while (pos < text.size()) {
			auto c = text[pos];
			if (c == '\'' || c == '"') {
				ReadQuoted(text, pos);
				continue;
			}
			if (c == '(') {
				depth++;
			} else if (c == ')' && depth > 0) {
				depth--;
			} else if (c == ';' && depth == 0) {
				break;
			}
			pos++;
		}
		auto body = text.substr(start, pos - start);
		StringUtil::Trim(body);
		if (body.empty()) {
			throw BinderException("acl admin: expected %s at position %llu", what, start);
		}
		return body;
	}

	//! A body written either way: a quoted string (what a gateway generates) or inline to the end of
	//! the statement (what a human writes). Both forms are accepted everywhere a body is taken.
	string Body(const char *what) {
		Skip();
		if (pos < text.size() && (text[pos] == '\'' || text[pos] == '"')) {
			return Quoted(what);
		}
		return Rest(what);
	}

	//! A name written either way: bare (`range`, `pg.public.orders`) or as the legacy quoted string
	string Name(const char *what) {
		Skip();
		if (pos < text.size() && (text[pos] == '\'' || text[pos] == '"')) {
			return Quoted(what);
		}
		return Dotted(what);
	}

	//! A list written either way: `(a, b = c)` or the legacy quoted csv/JSON string
	string List(const char *what) {
		Skip();
		if (pos < text.size() && text[pos] == '(') {
			return Parens();
		}
		return Quoted(what);
	}

	//! a bare identifier path: word(.word)*
	string Dotted(const char *what) {
		auto path = Word(what);
		while (pos < text.size() && text[pos] == '.') {
			pos++;
			path += "." + Word(what);
		}
		return path;
	}
};

//! vcat.vname: the first component is the catalog, the rest the in-catalog path
void SplitVirtual(const string &path, string &vcat, string &vname) {
	auto dot = path.find('.');
	if (dot == string::npos) {
		throw BinderException("acl admin: \"%s\" must be written as <catalog>.<name>", path);
	}
	vcat = path.substr(0, dot);
	vname = path.substr(dot + 1);
}

//! `(select, insert)` -> `{"select": true, "insert": true}`. The list form is what a person writes;
//! JSON stays the storage format and the admin functions' input. An unknown capability is kept as
//! written rather than refused - the vocabulary grows, and a grant authored against a newer version
//! must not fail - but it enforces nothing until some spec starts reading it (design 004).
string CapsListToJson(const string &list) {
	vector<string> entries;
	for (auto &item : SplitTopLevel(list, ',')) {
		if (item.empty()) {
			continue;
		}
		entries.push_back("\"" + StringUtil::Replace(StringUtil::Lower(item), "\"", "") + "\": true");
	}
	return "{" + StringUtil::Join(entries, ", ") + "}";
}

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

//! `(tenant = 'acme', unit = 'eu')` -> the stored csv `tenant=acme,unit=eu`
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
		entries.push_back(name + "=" + Unquoted(item.substr(split + 1)));
	}
	return StringUtil::Join(entries, ",");
}

//! `('api://hugr', 'api://other')` or `(RS256, ES256)` -> the stored csv
string ValueListToCsv(const string &list) {
	vector<string> entries;
	for (auto &item : SplitTopLevel(list, ',')) {
		if (!item.empty()) {
			entries.push_back(Unquoted(item));
		}
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

//! The clauses a grant is written with, in any order: CAPS '<json>' RLS '<predicate>'
//! COLUMNS '<name[=expr], …>' - the grant's own policy (spec 011) - plus MAIN for a catalog grant
void GrantPolicyClauses(AdminScanner &s, string &caps, string &rls, string &columns, bool *main = nullptr) {
	for (bool more = true; more;) {
		more = false;
		if (s.Accept("with")) { // WITH (select, insert) - the list form of CAPS
			caps = CapsListToJson(s.Parens());
			more = true;
		}
		if (s.Accept("caps")) {
			caps = s.Quoted("caps JSON");
			more = true;
		}
		if (s.Accept("rls")) {
			rls = s.List("an RLS predicate");
			more = true;
		}
		if (s.Accept("columns")) {
			columns = UnquoteColumnsList(s.List("a column list"));
			more = true;
		}
		if (main && s.Accept("main")) {
			*main = true;
			more = true;
		}
	}
}

unique_ptr<SQLStatement> MakeAdminCall(const string &function, vector<Value> args) {
	vector<unique_ptr<ParsedExpression>> children;
	for (auto &arg : args) {
		children.push_back(make_uniq<ConstantExpression>(std::move(arg)));
	}
	auto node = make_uniq<SelectNode>();
	node->select_list.push_back(make_uniq<FunctionExpression>(Identifier(function), std::move(children)));
	node->from_table = make_uniq<EmptyTableRef>();
	auto statement = make_uniq<SelectStatement>();
	statement->node = std::move(node);
	return std::move(statement);
}

//! True when the ADMIN remainder starts with a management form (decides the whole batch)

} // namespace

bool IsMgmtStart(const string &text) {
	AdminScanner scanner(text);
	auto first = scanner.PeekWord();
	if (StringUtil::CIEquals(first, "add") || StringUtil::CIEquals(first, "grant") ||
	    StringUtil::CIEquals(first, "revoke") || StringUtil::CIEquals(first, "map")) {
		return true;
	}
	if (StringUtil::CIEquals(first, "comment") || StringUtil::CIEquals(first, "analyze")) {
		// duckdb owns COMMENT ON <object> and ANALYZE: ours always name a VIRTUAL target
		AdminScanner ahead(text);
		ahead.Word("keyword");
		if (StringUtil::CIEquals(first, "analyze")) {
			return StringUtil::CIEquals(ahead.PeekWord(), "virtual");
		}
		ahead.Accept("on");
		return StringUtil::CIEquals(ahead.PeekWord(), "virtual");
	}
	if (StringUtil::CIEquals(first, "create") || StringUtil::CIEquals(first, "drop") ||
	    StringUtil::CIEquals(first, "alter")) {
		AdminScanner ahead(text);
		ahead.Word("keyword");
		auto second = ahead.PeekWord();
		if (StringUtil::CIEquals(first, "create")) {
			if (StringUtil::CIEquals(second, "or")) {
				// CREATE OR REPLACE VIRTUAL … - look past the modifier for the marker
				ahead.Word("or");
				ahead.Accept("replace");
				second = ahead.PeekWord();
			}
			return StringUtil::CIEquals(second, "virtual") || StringUtil::CIEquals(second, "role") ||
			       StringUtil::CIEquals(second, "issuer");
		}
		if (StringUtil::CIEquals(first, "alter")) {
			// duckdb owns ALTER TABLE/VIEW/...: our object forms carry the VIRTUAL marker, and
			// ALTER ROLE/ISSUER/GRANT do not exist in duckdb at all
			return StringUtil::CIEquals(second, "virtual") || StringUtil::CIEquals(second, "role") ||
			       StringUtil::CIEquals(second, "issuer") || StringUtil::CIEquals(second, "grant");
		}
		// DROP: our own forms carry VIRTUAL, and duckdb has no DROP ROLE/ISSUER/MAP/RELATION
		return StringUtil::CIEquals(second, "relation") || StringUtil::CIEquals(second, "virtual") ||
		       StringUtil::CIEquals(second, "role") || StringUtil::CIEquals(second, "issuer") ||
		       StringUtil::CIEquals(second, "map") || StringUtil::CIEquals(second, "reference");
	}
	return false;
}

//! `CREATE VIRTUAL <kind> <name> …` - the SQL-shaped spelling of the ADD forms, with the virtual
//! name first (like `CREATE TABLE`) and `AS` naming the physical target or the body. The ADD forms
//! stay accepted: a gateway generates them, and every existing script uses them.

namespace {

unique_ptr<SQLStatement> ParseCreateVirtual(AdminScanner &s, string mode) {
	//! `IF NOT EXISTS` after the kind keyword: keep what is there instead of refusing
	auto if_not_exists = [&mode](AdminScanner &scanner) {
		if (!scanner.Accept("if")) {
			return;
		}
		scanner.Expect("not");
		scanner.Expect("exists");
		if (mode == "create") {
			mode = "skip";
		}
	};
	//! `COMMENT '…'` may precede the body (a body runs to the end of the statement, so it cannot
	//! follow one); for the forms whose tail is a list it may come last as well
	auto comment_clause = [](AdminScanner &scanner, string &comment) {
		if (scanner.Accept("comment")) {
			comment = scanner.Quoted("comment");
		}
	};
	if (s.Accept("catalog")) {
		if_not_exists(s);
		auto vcat = s.Word("a catalog name");
		string comment;
		comment_clause(s, comment);
		return MakeAdminCall("acl_create_catalog", {Value(vcat), Value(comment), Value(mode)});
	}
	if (s.Accept("reference")) {
		// CREATE VIRTUAL REFERENCE v.name FROM <object> TO <object>
		//     ON (from_col = to_col, …) | ON EXPRESSION '<sql>'
		//     [CARDINALITY <kind>] [OPTIONAL] [JOIN <method>] [COMMENT '…']
		if_not_exists(s);
		string vcat, name;
		SplitVirtual(s.Dotted("a virtual name"), vcat, name);
		//! an endpoint may be written with or without the reference's own catalog in front of it
		auto endpoint = [&s, &vcat]() {
			auto written = s.Dotted("an object name");
			auto prefix = vcat + ".";
			if (written.size() > prefix.size() && StringUtil::CIEquals(written.substr(0, prefix.size()), prefix)) {
				return written.substr(prefix.size());
			}
			return written;
		};
		s.Expect("from");
		auto from_vname = endpoint();
		s.Expect("to");
		// TO FUNCTION f(param => col, …): the parenthesis is the argument substitution - which column
		// of the source row feeds which parameter - and ON, when present, is the join condition on the
		// function's result. Pure substitution needs no condition at all.
		bool to_function = s.Accept("function");
		auto to_vname = endpoint();
		string call_args;
		if (to_function) {
			call_args = s.Parens();
		}
		string pairs, expr;
		if (s.Accept("on")) {
			// a bare list is a list of column pairs; SQL is spelled out, so neither can be mistaken
			// for the other and a qualified name never reads as a column name
			if (s.Accept("expression")) {
				expr = s.Quoted("a join expression");
			} else {
				pairs = s.List("column pairs");
			}
		} else if (!to_function) {
			throw BinderException("acl admin: a reference between objects needs an ON condition");
		}
		string cardinality, join_method, comment;
		bool optional = false;
		for (bool more = true; more;) {
			more = false;
			if (s.Accept("cardinality")) {
				cardinality = s.Word("a cardinality");
				more = true;
			}
			if (s.Accept("optional")) {
				optional = true;
				more = true;
			}
			if (s.Accept("join")) {
				join_method = s.Word("a join method");
				more = true;
			}
			if (s.Accept("comment")) {
				comment = s.Quoted("comment");
				more = true;
			}
		}
		return MakeAdminCall("acl_add_reference",
		                     {Value(vcat), Value(name), Value(from_vname), Value(to_vname),
		                      Value(to_function ? "function" : "relation"), Value(call_args), Value(pairs), Value(expr),
		                      Value(cardinality), Value(optional ? "true" : "false"), Value(join_method),
		                      Value(comment), Value(mode)});
	}
	if (s.Accept("schema")) {
		// CREATE VIRTUAL SCHEMA v.path AS <phys> - the live alias, resolves through
		//                              FROM <phys> - the expansion, one record per object right now
		if_not_exists(s);
		string vcat, path;
		SplitVirtual(s.Dotted("a virtual schema path"), vcat, path);
		bool expand = s.Accept("from");
		if (!expand) {
			s.Expect("as");
		}
		auto phys = s.Name("a physical schema path");
		string comment;
		comment_clause(s, comment);
		return MakeAdminCall(expand ? "acl_expand_schema" : "acl_add_schema_alias",
		                     {Value(vcat), Value(path), Value(phys), Value(comment), Value(mode)});
	}
	if (s.Accept("view")) { // CREATE VIRTUAL VIEW v.n [(col TYPE, …)] [COMMENT '…'] AS <sql>
		if_not_exists(s);
		string vcat, vname;
		SplitVirtual(s.Dotted("a virtual name"), vcat, vname);
		auto returns = s.Parens();
		string comment, pk;
		for (bool more = true; more;) {
			more = false;
			if (s.Accept("primary")) {
				s.Expect("key");
				pk = s.List("key columns");
				more = true;
			}
			if (s.Accept("comment")) {
				comment = s.Quoted("comment");
				more = true;
			}
		}
		s.Expect("as");
		auto sql = s.Body("view SQL");
		return MakeAdminCall("acl_add_view", {Value(vcat), Value(vname), Value(sql), Value(returns), Value(comment),
		                                      Value(mode), Value(pk)});
	}
	bool scalar = s.Accept("scalar");
	bool table_function = false;
	if (!scalar) {
		s.Expect("table");
		table_function = s.Accept("function");
	}
	if_not_exists(s);
	string vcat, vname;
	SplitVirtual(s.Dotted("a virtual name"), vcat, vname);
	if (scalar || table_function) {
		// CREATE VIRTUAL SCALAR|TABLE FUNCTION v.n[(args)] [RETURNS …] [COMMENT '…'] AS <body>
		//                                                                             | ALIAS OF <fn>
		auto params = s.Parens();
		string returns;
		if (s.Accept("returns")) {
			if (scalar) {
				returns = s.Word("a result type");
			} else {
				s.Accept("table");
				returns = s.Parens();
				if (returns.empty()) {
					throw BinderException("acl admin: RETURNS TABLE needs a column list");
				}
			}
		}
		string pk;
		if (!scalar && s.Accept("primary")) { // after RETURNS: a key describes the result (spec 048)
			s.Expect("key");
			pk = s.List("key columns");
		}
		string comment;
		comment_clause(s, comment);
		if (s.Accept("alias")) {
			s.Expect("of");
			auto target = s.Name("a target function");
			comment_clause(s, comment); // an alias has no body, so the comment may also come last
			return MakeAdminCall(
			    scalar ? "acl_add_scalar_alias" : "acl_add_table_function_alias",
			    {Value(vcat), Value(vname), Value(target), Value(""), Value(""), Value(comment), Value(mode)});
		}
		s.Expect("as");
		auto definition = s.Body(scalar ? "expression template" : "SQL template");
		vector<Value> call_args = {Value(vcat),    Value(vname),   Value(definition), Value(params),
		                           Value(returns), Value(comment), Value(mode)};
		if (!scalar) {
			call_args.push_back(Value(pk)); // a scalar result has no key to declare
		}
		return MakeAdminCall(scalar ? "acl_add_scalar" : "acl_add_table_function", std::move(call_args));
	}
	// CREATE VIRTUAL TABLE v.n AS <phys> [COLUMNS (…)] [RLS (…)] [COMMENT '…']
	s.Expect("as");
	auto phys = s.Name("a physical table path");
	string columns, rls, comment, pk;
	for (bool more = true; more;) {
		more = false;
		if (s.Accept("columns")) {
			columns = UnquoteColumnsList(s.List("columns list"));
			more = true;
		}
		if (s.Accept("rls")) {
			rls = s.List("RLS predicate");
			more = true;
		}
		if (s.Accept("primary")) { // PRIMARY KEY (col, ...) - declared, never enforced (spec 048)
			s.Expect("key");
			pk = s.List("key columns");
			more = true;
		}
		if (s.Accept("comment")) {
			comment = s.Quoted("comment");
			more = true;
		}
	}
	return MakeAdminCall("acl_add_relation", {Value(vcat), Value(vname), Value(phys), Value(columns), Value(rls),
	                                          Value(comment), Value(mode), Value(pk)});
}

unique_ptr<SQLStatement> ParseMgmtStatement(AdminScanner &s) {
	auto keyword = s.Word("a management keyword");
	if (StringUtil::CIEquals(keyword, "create")) {
		// what the statement promises about an existing object: CREATE refuses to overwrite one,
		// OR REPLACE overwrites, IF NOT EXISTS keeps it (spec 013). The legacy ADD forms upsert.
		string mode = "create";
		if (s.Accept("or")) {
			s.Expect("replace");
			mode = "replace";
		}
		if (s.Accept("virtual")) {
			return ParseCreateVirtual(s, mode);
		}
		if (s.Accept("role")) {
			if (s.Accept("if")) {
				s.Expect("not");
				s.Expect("exists");
				if (mode == "create") {
					mode = "skip";
				}
			}
			auto role = s.Word("a role name");
			string claims;
			if (s.Accept("claims")) {
				claims = s.AtParen() ? ClaimsListToCsv(s.Parens()) : s.Quoted("claims list");
			}
			return MakeAdminCall("acl_define_role", {Value(role), Value(claims), Value(mode)});
		}
		s.Expect("issuer");
		auto issuer = s.Quoted("issuer");
		s.Expect("keys");
		// KEYS '<jwks>' pastes the document; KEYS FROM '<uri>' names where to read it (spec 023)
		string keys, jwks_uri;
		if (s.Accept("from")) {
			jwks_uri = s.Quoted("a JWKS location");
		} else {
			keys = s.Quoted("keys");
		}
		string audiences, algs = "RS256", role_claim = "roles", claim_map;
		if (s.Accept("audiences")) {
			audiences = s.AtParen() ? ValueListToCsv(s.Parens()) : s.Quoted("audiences");
		}
		if (s.Accept("algs")) {
			algs = s.AtParen() ? ValueListToCsv(s.Parens()) : s.Quoted("algs");
		}
		if (s.Accept("role")) {
			s.Expect("claim");
			role_claim = s.Quoted("role claim path");
		}
		if (s.Accept("claim")) {
			s.Expect("map");
			claim_map = s.AtParen() ? ClaimMapToJson(s.Parens()) : s.Quoted("claim map");
		}
		// CLIENT ID '<id>' [CLIENT SECRET '<secret>'] - the node-side OAuth client (spec 064)
		string client_id, client_secret;
		if (s.Accept("client")) {
			s.Expect("id");
			client_id = s.Quoted("a client id");
			if (s.Accept("client")) {
				s.Expect("secret");
				client_secret = s.Quoted("a client secret");
			}
		}
		return MakeAdminCall("acl_define_issuer",
		                     {Value(issuer), Value(keys), Value(audiences), Value(algs), Value(role_claim),
		                      Value(claim_map), Value(jwks_uri), Value(client_id), Value(client_secret)});
	}
	if (StringUtil::CIEquals(keyword, "add")) {
		if (s.Accept("view")) {
			// ADD VIEW v.n [(col TYPE, …)] AS '<sql>' - the CREATE VIEW shape; a declared column list
			// is the truth and spares the write-time probe
			string vcat, vname;
			SplitVirtual(s.Dotted("a virtual name"), vcat, vname);
			auto returns = s.Parens();
			s.Expect("as");
			auto sql = s.Body("view SQL");
			return MakeAdminCall("acl_add_view", {Value(vcat), Value(vname), Value(sql), Value(returns)});
		}
		if (s.Accept("schema")) {
			auto phys = s.Dotted("a physical schema path");
			s.Expect("as");
			string vcat, alias;
			SplitVirtual(s.Dotted("a virtual alias"), vcat, alias);
			return MakeAdminCall("acl_add_schema_alias", {Value(vcat), Value(alias), Value(phys)});
		}
		if (s.Accept("scalar")) {
			// ADD SCALAR v.n[(arg TYPE, …)] [RETURNS <type>] MACRO '<expr>' | ALIAS '<fn>'
			string vcat, vname;
			SplitVirtual(s.Dotted("a virtual name"), vcat, vname);
			auto params = s.Parens();
			string returns;
			if (s.Accept("returns")) {
				returns = s.Word("a result type");
			}
			bool is_macro = s.Accept("macro");
			if (!is_macro) {
				s.Expect("alias");
				s.Accept("of"); // ALIAS OF <fn> and the older ALIAS <fn> are the same thing
			}
			auto definition = is_macro ? s.Body("expression template") : s.Name("a target function");
			if (!is_macro) {
				return MakeAdminCall("acl_add_scalar_alias", {Value(vcat), Value(vname), Value(definition)});
			}
			return MakeAdminCall("acl_add_scalar",
			                     {Value(vcat), Value(vname), Value(definition), Value(params), Value(returns)});
		}
		s.Expect("table");
		if (s.Accept("function")) {
			// ADD TABLE FUNCTION v.n[(arg TYPE, …)] [RETURNS TABLE (col TYPE, …)] MACRO '<sql>' | ALIAS '<fn>'
			string vcat, vname;
			SplitVirtual(s.Dotted("a virtual name"), vcat, vname);
			auto params = s.Parens();
			string returns;
			if (s.Accept("returns")) {
				s.Accept("table");
				returns = s.Parens();
				if (returns.empty()) {
					throw BinderException("acl admin: RETURNS TABLE needs a column list");
				}
			}
			bool is_macro = s.Accept("macro");
			if (!is_macro) {
				s.Expect("alias");
				s.Accept("of"); // ALIAS OF <fn> and the older ALIAS <fn> are the same thing
			}
			auto definition = is_macro ? s.Body("SQL template") : s.Name("a target function");
			if (!is_macro) {
				return MakeAdminCall("acl_add_table_function_alias", {Value(vcat), Value(vname), Value(definition)});
			}
			return MakeAdminCall("acl_add_table_function",
			                     {Value(vcat), Value(vname), Value(definition), Value(params), Value(returns)});
		}
		auto phys = s.Dotted("a physical table path");
		s.Expect("as");
		string vcat, vname;
		SplitVirtual(s.Dotted("a virtual name"), vcat, vname);
		string columns, rls;
		if (s.Accept("columns")) {
			columns = UnquoteColumnsList(s.List("columns list"));
		}
		if (s.Accept("rls")) {
			rls = s.List("RLS predicate");
		}
		return MakeAdminCall("acl_add_relation", {Value(vcat), Value(vname), Value(phys), Value(columns), Value(rls)});
	}
	if (StringUtil::CIEquals(keyword, "grant")) {
		if (s.Accept("admin")) {
			// GRANT ADMIN <scope> TO ROLE r - the GLOBAL scope; managing one catalog is granted with
			// GRANT CATALOG c TO ROLE r CAPS '{"manage": true}'
			auto scope = s.Word("an admin scope");
			s.Expect("to");
			s.Expect("role");
			auto role = s.Word("a role name");
			return MakeAdminCall("acl_grant_admin", {Value(role), Value(scope)});
		}
		// GRANT SCHEMA v.path TO ROLE r WITH (…) [COMMENT '…'] - the middle level (spec 015)
		if (s.Accept("schema")) {
			string vcat, path;
			SplitVirtual(s.Dotted("a virtual schema path"), vcat, path);
			s.Expect("to");
			s.Expect("role");
			auto role = s.Word("a role name");
			string caps, rls, columns, comment, into;
			bool virtual_only = false;
			GrantPolicyClauses(s, caps, rls, columns);
			if (s.Accept("into")) { // where this role creates - the grant decides, not the schema
				into = s.Name("a physical schema path");
			} else if (s.Accept("virtual")) {
				s.Expect("only");
				virtual_only = true;
			}
			if (!rls.empty() || !columns.empty()) {
				throw BinderException("acl admin: a schema grant carries capabilities only - RLS and COLUMNS belong "
				                      "to the catalog or to the object (spec 015)");
			}
			if (s.Accept("comment")) {
				comment = s.Quoted("comment");
			}
			return MakeAdminCall("acl_grant_schema", {Value(role), Value(vcat), Value(path), Value(caps),
			                                          Value(comment), Value(into), Value::BOOLEAN(virtual_only)});
		}
		// GRANT TABLE|VIEW|OBJECT v.n TO ROLE r [CAPS '…'] [RLS '…'] [COLUMNS '…'] - the grant's own
		// policy (spec 011): it narrows the object for this role, it never widens it
		if (s.Accept("table") || s.Accept("view") || s.Accept("object")) {
			string vcat, vname;
			SplitVirtual(s.Dotted("a virtual name"), vcat, vname);
			s.Expect("to");
			s.Expect("role");
			auto role = s.Word("a role name");
			// no CAPS clause = unspecified, which resolves to the read-only default; an explicit
			// CAPS '{}' still means "no capabilities" (spec 012)
			string caps, rls, columns;
			GrantPolicyClauses(s, caps, rls, columns);
			return MakeAdminCall("acl_grant_object",
			                     {Value(role), Value(vcat), Value(vname), Value(caps), Value(rls), Value(columns)});
		}
		s.Expect("catalog");
		auto vcat = s.Word("a catalog name");
		s.Expect("to"); // GRANT CATALOG c TO ROLE r
		s.Expect("role");
		auto role = s.Word("a role name");
		string caps, rls, columns;
		bool main = false;
		GrantPolicyClauses(s, caps, rls, columns, &main);
		return MakeAdminCall("acl_grant_catalog",
		                     {Value(role), Value(vcat), Value(caps), Value::BOOLEAN(main), Value(rls), Value(columns)});
	}
	if (StringUtil::CIEquals(keyword, "revoke")) {
		if (s.Accept("admin")) { // REVOKE ADMIN FROM ROLE r
			s.Expect("from");
			s.Expect("role");
			auto role = s.Word("a role name");
			return MakeAdminCall("acl_revoke_admin", {Value(role)});
		}
		if (s.Accept("schema")) { // REVOKE SCHEMA v.path FROM ROLE r
			string vcat, path;
			SplitVirtual(s.Dotted("a virtual schema path"), vcat, path);
			s.Expect("from");
			s.Expect("role");
			return MakeAdminCall("acl_revoke_schema", {Value(s.Word("a role name")), Value(vcat), Value(path)});
		}
		s.Expect("catalog");
		auto vcat = s.Word("a catalog name");
		s.Expect("from");
		s.Expect("role");
		auto role = s.Word("a role name");
		return MakeAdminCall("acl_revoke_catalog", {Value(role), Value(vcat)});
	}
	if (StringUtil::CIEquals(keyword, "map")) {
		bool is_group = s.Accept("group");
		if (!is_group) {
			s.Expect("claim");
		}
		auto external = s.Quoted("external value");
		s.Expect("from");
		s.Expect("issuer");
		auto issuer = s.Quoted("issuer");
		s.Expect("to");
		s.Expect("role");
		auto role = s.Word("a role name");
		return MakeAdminCall("acl_map_role",
		                     {Value(issuer), Value(is_group ? "group" : "claim-value"), Value(external), Value(role)});
	}
	if (StringUtil::CIEquals(keyword, "alter")) {
		if (s.Accept("role")) { // ALTER ROLE r SET CLAIMS (...) | '...'
			auto role = s.Word("a role name");
			s.Expect("set");
			s.Expect("claims");
			auto claims = s.AtParen() ? ClaimsListToCsv(s.Parens()) : s.Quoted("claims list");
			return MakeAdminCall("acl_alter_role", {Value(role), Value(claims)});
		}
		if (s.Accept("issuer")) { // ALTER ISSUER '...' SET KEYS|AUDIENCES|ALGS|ROLE CLAIM|CLAIM MAP '...'
			auto issuer = s.Quoted("issuer");
			s.Expect("set");
			string field;
			if (s.Accept("keys")) {
				field = s.Accept("from") ? "jwks_uri" : "keys";
			} else if (s.Accept("audiences")) {
				field = "audiences";
			} else if (s.Accept("algs")) {
				field = "algs";
			} else if (s.Accept("role")) {
				s.Expect("claim");
				field = "role_claim";
			} else if (s.Accept("client")) { // SET CLIENT ID | CLIENT SECRET (spec 064)
				if (s.Accept("id")) {
					field = "client_id";
				} else {
					s.Expect("secret");
					field = "client_secret";
				}
			} else {
				s.Expect("claim");
				s.Expect("map");
				field = "claim_map";
			}
			return MakeAdminCall("acl_alter_issuer", {Value(issuer), Value(field), Value(s.Quoted("value"))});
		}
		// ALTER GRANT CATALOG c TO ROLE r SET CAPS '…' | SET RLS '…' | SET COLUMNS '…' | SET MAIN t|f
		if (s.Accept("grant")) {
			s.Expect("catalog");
			auto vcat = s.Word("a catalog name");
			s.Expect("to");
			s.Expect("role");
			auto role = s.Word("a role name");
			s.Expect("set");
			if (s.Accept("caps")) {
				return MakeAdminCall("acl_alter_grant",
				                     {Value(role), Value(vcat), Value("caps"), Value(s.Quoted("caps JSON"))});
			}
			if (s.Accept("rls")) {
				return MakeAdminCall("acl_alter_grant",
				                     {Value(role), Value(vcat), Value("rls"), Value(s.Quoted("an RLS predicate"))});
			}
			if (s.Accept("columns")) {
				return MakeAdminCall("acl_alter_grant", {Value(role), Value(vcat), Value("columns"),
				                                         Value(UnquoteColumnsList(s.Quoted("a column list")))});
			}
			s.Expect("main");
			auto flag = s.Word("true or false");
			return MakeAdminCall("acl_alter_grant", {Value(role), Value(vcat), Value("main"), Value(flag)});
		}
		// the object forms carry the VIRTUAL marker, so they never shadow duckdb's own ALTER
		s.Expect("virtual");
		if (s.Accept("catalog")) { // ALTER VIRTUAL CATALOG c SET COMMENT '...'
			auto vcat = s.Word("a catalog name");
			s.Expect("set");
			s.Expect("comment");
			return MakeAdminCall("acl_alter_catalog", {Value(vcat), Value(s.Quoted("comment"))});
		}
		if (s.Accept("view")) { // ALTER VIRTUAL VIEW v.n SET AS '...' | SET|DROP PRIMARY KEY (spec 048)
			string vcat, vname;
			SplitVirtual(s.Dotted("a virtual name"), vcat, vname);
			if (s.Accept("drop")) {
				s.Expect("primary");
				s.Expect("key");
				return MakeAdminCall("acl_set_key", {Value(vcat), Value(vname), Value("relation"), Value("")});
			}
			s.Expect("set");
			if (s.Accept("primary")) {
				s.Expect("key");
				return MakeAdminCall("acl_set_key",
				                     {Value(vcat), Value(vname), Value("relation"), Value(s.List("key columns"))});
			}
			s.Expect("as");
			return MakeAdminCall("acl_alter_relation",
			                     {Value(vcat), Value(vname), Value("view"), Value(s.Body("view SQL"))});
		}
		if (s.Accept("schema")) { // ALTER VIRTUAL SCHEMA v.path SET PHYS <path> | REFRESH [PRUNE]
			string vcat, alias;
			SplitVirtual(s.Dotted("a virtual schema path"), vcat, alias);
			if (s.Accept("refresh")) {
				bool prune = s.Accept("prune");
				return MakeAdminCall("acl_refresh_schema_objects", {Value(vcat), Value(alias), Value::BOOLEAN(prune)});
			}
			s.Expect("set");
			s.Expect("phys");
			return MakeAdminCall("acl_alter_schema_alias",
			                     {Value(vcat), Value(alias), Value(s.Dotted("a physical schema path"))});
		}
		bool scalar = s.Accept("scalar");
		if (scalar || s.Accept("table")) {
			bool table_function = !scalar && s.Accept("function");
			string vcat, vname;
			SplitVirtual(s.Dotted("a virtual name"), vcat, vname);
			if (!scalar && s.Accept("drop")) { // ALTER VIRTUAL ... DROP PRIMARY KEY (spec 048: a scalar has none)
				s.Expect("primary");
				s.Expect("key");
				return MakeAdminCall("acl_set_key", {Value(vcat), Value(vname),
				                                     Value(string(table_function ? "table" : "relation")), Value("")});
			}
			s.Expect("set");
			if (!scalar && s.Accept("primary")) { // ALTER VIRTUAL ... SET PRIMARY KEY (col, ...)
				s.Expect("key");
				return MakeAdminCall("acl_set_key",
				                     {Value(vcat), Value(vname), Value(string(table_function ? "table" : "relation")),
				                      Value(s.List("key columns"))});
			}
			if (scalar || table_function) { // ALTER VIRTUAL [TABLE FUNCTION|SCALAR] v.n SET MACRO|ALIAS '...'
				bool is_macro = s.Accept("macro");
				if (!is_macro) {
					s.Expect("alias");
				}
				if (!is_macro) {
					s.Accept("of"); // SET ALIAS OF <fn>, like the CREATE form
				}
				return MakeAdminCall("acl_alter_function",
				                     {Value(vcat), Value(vname), Value(scalar ? "scalar" : "table"),
				                      Value(is_macro ? "macro" : "alias"),
				                      Value(is_macro ? s.Body("definition") : s.Name("a target function"))});
			}
			// ALTER VIRTUAL TABLE v.n SET PHYS <path> | SET COLUMNS '...' | SET RLS '...'
			if (s.Accept("phys")) {
				return MakeAdminCall("acl_alter_relation", {Value(vcat), Value(vname), Value("phys"),
				                                            Value(s.Name("a physical table path"))});
			}
			if (s.Accept("columns")) {
				return MakeAdminCall("acl_alter_relation", {Value(vcat), Value(vname), Value("columns"),
				                                            Value(UnquoteColumnsList(s.List("columns list")))});
			}
			s.Expect("rls");
			return MakeAdminCall("acl_alter_relation",
			                     {Value(vcat), Value(vname), Value("rls"), Value(s.List("RLS predicate"))});
		}
		throw BinderException("acl admin: unknown ALTER VIRTUAL target");
	}
	if (StringUtil::CIEquals(keyword, "comment")) {
		// COMMENT ON VIRTUAL TABLE|VIEW|SCHEMA|TABLE FUNCTION|SCALAR v.n [COLUMN c] IS '...'
		s.Expect("on");
		s.Expect("virtual");
		bool schema = s.Accept("schema");
		bool scalar = !schema && s.Accept("scalar");
		bool table_function = false;
		if (!schema && !scalar && s.Accept("table")) {
			table_function = s.Accept("function");
		} else if (!schema && !scalar) {
			s.Expect("view");
		}
		string vcat, vname;
		SplitVirtual(s.Dotted("a virtual name"), vcat, vname);
		string column;
		if (s.Accept("column")) {
			column = s.Word("a column name");
		}
		s.Expect("is");
		auto comment = s.Quoted("comment");
		auto kind = schema ? "schema" : (scalar ? "scalar" : (table_function ? "table" : "relation"));
		return MakeAdminCall("acl_comment", {Value(vcat), Value(vname), Value(kind), Value(column), Value(comment)});
	}
	if (StringUtil::CIEquals(keyword, "analyze")) {
		// ANALYZE VIRTUAL CATALOG c [TABLE|VIEW|... v.n]: re-derive stored schemas
		s.Expect("virtual");
		if (s.Accept("catalog")) {
			return MakeAdminCall("acl_refresh_schema", {Value(s.Word("a catalog name")), Value("")});
		}
		s.Accept("scalar") || s.Accept("view") || (s.Accept("table") && s.Accept("function"));
		string vcat, vname;
		SplitVirtual(s.Dotted("a virtual name"), vcat, vname);
		return MakeAdminCall("acl_refresh_schema", {Value(vcat), Value(vname)});
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
		if (s.Accept("relation")) { // the spec-008 spelling, kept
			if_exists(s);
			string vcat, vname;
			SplitVirtual(s.Dotted("a virtual name"), vcat, vname);
			return MakeAdminCall("acl_drop_relation", {Value(vcat), Value(vname), Value(mode)});
		}
		if (s.Accept("reference")) {
			if_exists(s);
			string vcat, name;
			SplitVirtual(s.Dotted("a virtual name"), vcat, name);
			return MakeAdminCall("acl_drop_reference", {Value(vcat), Value(name), Value(mode)});
		}
		if (s.Accept("role")) {
			if_exists(s);
			return MakeAdminCall("acl_drop_role", {Value(s.Word("a role name")), Value(mode)});
		}
		if (s.Accept("issuer")) {
			if_exists(s);
			return MakeAdminCall("acl_drop_issuer", {Value(s.Quoted("issuer")), Value(mode)});
		}
		if (s.Accept("map")) { // DROP MAP GROUP|CLAIM '<value>' FROM ISSUER '...' TO ROLE r
			bool is_group = s.Accept("group");
			if (!is_group) {
				s.Expect("claim");
			}
			auto external = s.Quoted("external value");
			s.Expect("from");
			s.Expect("issuer");
			auto issuer = s.Quoted("issuer");
			s.Expect("to");
			s.Expect("role");
			auto role = s.Word("a role name");
			return MakeAdminCall("acl_drop_role_mapping", {Value(issuer), Value(is_group ? "group" : "claim-value"),
			                                               Value(external), Value(role)});
		}
		s.Expect("virtual");
		if (s.Accept("catalog")) { // DROP VIRTUAL CATALOG c [CASCADE]
			if_exists(s);
			auto vcat = s.Word("a catalog name");
			bool cascade = s.Accept("cascade");
			return MakeAdminCall("acl_drop_catalog", {Value(vcat), Value::BOOLEAN(cascade), Value(mode)});
		}
		if (s.Accept("schema")) { // DROP VIRTUAL SCHEMA v.path [CASCADE]
			if_exists(s);
			string vcat, alias;
			SplitVirtual(s.Dotted("a virtual schema path"), vcat, alias);
			bool cascade = s.Accept("cascade");
			return MakeAdminCall("acl_drop_schema_alias",
			                     {Value(vcat), Value(alias), Value(mode), Value::BOOLEAN(cascade)});
		}
		bool scalar = s.Accept("scalar");
		if (scalar || s.Accept("table")) {
			bool table_function = !scalar && s.Accept("function");
			if_exists(s);
			string vcat, vname;
			SplitVirtual(s.Dotted("a virtual name"), vcat, vname);
			if (scalar || table_function) {
				return MakeAdminCall("acl_drop_function",
				                     {Value(vcat), Value(vname), Value(scalar ? "scalar" : "table"), Value(mode)});
			}
			return MakeAdminCall("acl_drop_relation", {Value(vcat), Value(vname), Value(mode)});
		}
		if (s.Accept("view")) {
			if_exists(s);
			string vcat, vname;
			SplitVirtual(s.Dotted("a virtual name"), vcat, vname);
			return MakeAdminCall("acl_drop_relation", {Value(vcat), Value(vname), Value(mode)});
		}
		if (s.Accept("reference")) {
			if_exists(s);
			string vcat, name;
			SplitVirtual(s.Dotted("a virtual name"), vcat, name);
			return MakeAdminCall("acl_drop_reference", {Value(vcat), Value(name), Value(mode)});
		}
		throw BinderException("acl admin: unknown DROP VIRTUAL target");
	}
	throw BinderException("acl admin: unknown management statement \"%s\"", keyword);
}

//! What authorizing a compiled management call needs (spec 009), read off the call itself: which
//! constant argument names the catalog it touches, and whether it escalates privilege.
struct MgmtProvenance {
	string vcat;            // "" = not catalog-specific (roles, issuers, mappings, admin grants)
	bool escalates = false; // admin scopes: only a passthrough scope may hand them out
	//! catalog grants: handing out access is privilege administration, so a catalog-scoped manage
	//! may not grant read on the catalog it manages (to itself or to anyone else)
	bool hands_out = false;
};

MgmtProvenance ProvenanceOf(SQLStatement &statement) {
	// name -> index of the constant argument holding the catalog; -1 = none
	static const std::unordered_map<string, int> CATALOG_ARG = {
	    {"acl_create_catalog", 0},
	    {"acl_add_relation", 0},
	    {"acl_add_view", 0},
	    {"acl_add_schema_alias", 0},
	    {"acl_add_table_function", 0},
	    {"acl_add_table_function_alias", 0},
	    {"acl_add_scalar", 0},
	    {"acl_add_scalar_alias", 0},
	    {"acl_drop_relation", 0},
	    {"acl_grant_catalog", 1},
	    {"acl_revoke_catalog", 1},
	    {"acl_grant_object", 1},
	    {"acl_define_role", -1},
	    {"acl_define_issuer", -1},
	    {"acl_map_role", -1},
	    {"acl_alter_relation", 0},
	    {"acl_alter_schema_alias", 0},
	    {"acl_alter_function", 0},
	    {"acl_alter_catalog", 0},
	    {"acl_alter_grant", 1},
	    {"acl_alter_role", -1},
	    {"acl_alter_issuer", -1},
	    {"acl_drop_schema_alias", 0},
	    {"acl_drop_function", 0},
	    {"acl_drop_role", -1},
	    {"acl_drop_issuer", -1},
	    {"acl_drop_role_mapping", -1},
	    {"acl_comment", 0},
	    {"acl_refresh_schema", 0},
	    {"acl_expand_schema", 0},
	    {"acl_refresh_schema_objects", 0},
	    {"acl_grant_schema", 1},
	    {"acl_revoke_schema", 1},
	    {"acl_rematerialize_schema_caps", 0},
	};
	MgmtProvenance provenance;
	auto &select = statement.Cast<SelectStatement>().node->Cast<SelectNode>();
	auto &call = select.select_list[0]->Cast<FunctionExpression>();
	auto name = StringUtil::Lower(call.FunctionName().GetIdentifierName());
	if (name == "acl_grant_admin" || name == "acl_revoke_admin") {
		provenance.escalates = true;
		return provenance;
	}
	if (name == "acl_grant_catalog" || name == "acl_revoke_catalog" || name == "acl_grant_object" ||
	    name == "acl_grant_schema" || name == "acl_revoke_schema" || name == "acl_alter_grant" ||
	    name == "acl_drop_catalog") {
		// dropping a catalog takes it away from everyone who holds it, so it is privilege
		// administration too - a scope over the catalog's content does not include destroying it
		provenance.hands_out = true;
		return provenance;
	}
	auto entry = CATALOG_ARG.find(name);
	if (entry == CATALOG_ARG.end()) {
		// a management call this table does not know: refuse rather than treat it as unscoped
		throw BinderException("acl admin: cannot authorize the management call \"%s\"", name);
	}
	if (entry->second >= 0) {
		auto &argument = call.GetArguments()[NumericCast<idx_t>(entry->second)].GetExpression();
		provenance.vcat = argument.Cast<ConstantExpression>().GetValue().ToString();
	}
	return provenance;
}

//! The whole batch is management statements (the first one decided that); mixing is refused

} // namespace

vector<unique_ptr<SQLStatement>> ParseMgmtBatch(const string &text) {
	vector<unique_ptr<SQLStatement>> statements;
	AdminScanner scanner(text);
	while (!scanner.Done()) {
		if (scanner.AtSemicolon()) {
			scanner.pos++;
			continue;
		}
		statements.push_back(ParseMgmtStatement(scanner));
		scanner.Skip();
		if (scanner.pos < text.size() && text[scanner.pos] != ';') {
			throw BinderException("acl admin: unexpected trailing text at position %llu", scanner.pos);
		}
	}
	if (statements.empty()) {
		throw BinderException("acl admin: empty management batch");
	}
	return statements;
}

//! Authorize a management batch against the principal's rights (spec 009). A catalog-scoped MANAGE
//! edits the content of its own catalogs; handing out access or admin scopes is privilege
//! administration and needs an unrestricted manage / passthrough. PASSTHROUGH may do anything.

void AuthorizeMgmt(vector<unique_ptr<SQLStatement>> &statements, const PolicyStore::AdminRights &rights) {
	if (rights.scope == AdminScope::PASSTHROUGH) {
		return;
	}
	for (auto &statement : statements) {
		auto provenance = ProvenanceOf(*statement);
		if (provenance.escalates) {
			throw BinderException("acl admin: granting admin scopes requires a passthrough scope");
		}
		if (provenance.hands_out && !rights.unrestricted_manage) {
			throw BinderException("acl admin: granting access to a catalog requires an unrestricted manage "
			                      "scope - managing a catalog does not include handing it out");
		}
		if (rights.unrestricted_manage) {
			continue;
		}
		if (provenance.vcat.empty()) {
			throw BinderException(
			    "acl admin: this statement is not catalog-specific and needs an unrestricted manage scope");
		}
		// exact match: the policy source compares vcat with SQL `=`, so a case-insensitive check here
		// would authorize writes into a genuinely different catalog
		if (!rights.catalogs.count(provenance.vcat)) {
			throw BinderException("acl admin: no manage scope for catalog \"%s\"", provenance.vcat);
		}
	}
}

} // namespace acl
} // namespace duckdb
