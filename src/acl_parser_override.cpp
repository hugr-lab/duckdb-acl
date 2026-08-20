#include "acl_parser_override.hpp"

#include "acl_rewriter.hpp"
#include "duckdb/common/exception/binder_exception.hpp"
#include "duckdb/common/exception/parser_exception.hpp"
#include "duckdb/common/helper.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/parser/expression/constant_expression.hpp"
#include "duckdb/parser/expression/function_expression.hpp"
#include "duckdb/parser/parser.hpp"
#include "duckdb/parser/query_node/select_node.hpp"
#include "duckdb/parser/statement/select_statement.hpp"
#include "duckdb/parser/tableref/emptytableref.hpp"

#include <unordered_map>

namespace duckdb {
namespace acl {
namespace {

struct AclPrefix {
	enum class Kind { NONE, ROLE, TOKEN, ADMIN };
	//! What the remainder is, decided by the marker the CLIENT writes (the gateway only prepends the
	//! principal, so the client itself asks for anything beyond an ordinary query):
	//!   <sql>              -> QUERY:  rewritten inside the principal's virtual catalog
	//!   ACL <mgmt>         -> MANAGE: an ACL management statement (needs a manage/passthrough scope)
	//!   ACL NATIVE <sql>   -> NATIVE: plain SQL outside the virtual catalog (needs passthrough)
	//! `ACL ADMIN ...` is the gateway's own anonymous form of the same thing - NATIVE unless it
	//! carries a marker or a management statement.
	enum class Mode { QUERY, MANAGE, NATIVE };
	Kind kind = Kind::NONE;
	Mode mode = Mode::QUERY;
	bool marked = false; // an explicit `ACL [NATIVE]` marker was written
	string value;
	string rest;
};

bool IsWordChar(char c) {
	return StringUtil::CharacterIsAlpha(c) || StringUtil::CharacterIsDigit(c) || c == '_';
}

string ReadWord(const string &query, idx_t &pos) {
	auto start = pos;
	while (pos < query.size() && IsWordChar(query[pos])) {
		pos++;
	}
	return query.substr(start, pos - start);
}

void SkipWhitespace(const string &query, idx_t &pos) {
	while (pos < query.size() && StringUtil::CharacterIsSpace(query[pos])) {
		pos++;
	}
}

//! Read a single-quoted or double-quoted literal, honoring the doubled-quote escape
string ReadQuoted(const string &query, idx_t &pos) {
	char quote = query[pos++];
	string value;
	while (pos < query.size()) {
		if (query[pos] == quote) {
			if (pos + 1 < query.size() && query[pos + 1] == quote) {
				value += quote;
				pos += 2;
				continue;
			}
			pos++;
			return value;
		}
		value += query[pos++];
	}
	throw ParserException("acl_rewrite: unterminated quoted value after ACL prefix");
}

AclPrefix ParseAclPrefix(const string &query) {
	AclPrefix prefix;
	idx_t pos = 0;
	SkipWhitespace(query, pos);
	auto keyword = ReadWord(query, pos);
	if (!StringUtil::CIEquals(keyword, "acl")) {
		return prefix; // not our syntax
	}
	SkipWhitespace(query, pos);
	auto mode = ReadWord(query, pos);
	//! Read the client's marker off the remainder: `ACL [NATIVE]`
	auto read_marker = [&](idx_t &scan) {
		SkipWhitespace(query, scan);
		auto saved = scan;
		if (!StringUtil::CIEquals(ReadWord(query, scan), "acl")) {
			scan = saved;
			return AclPrefix::Mode::QUERY;
		}
		SkipWhitespace(query, scan);
		auto after_acl = scan;
		if (StringUtil::CIEquals(ReadWord(query, scan), "native")) {
			return AclPrefix::Mode::NATIVE;
		}
		scan = after_acl;
		return AclPrefix::Mode::MANAGE;
	};
	if (StringUtil::CIEquals(mode, "admin")) {
		prefix.kind = AclPrefix::Kind::ADMIN;
		// the gateway's own hatch: native by default, management when marked (or written bare)
		auto marked = read_marker(pos);
		prefix.marked = marked != AclPrefix::Mode::QUERY;
		prefix.mode = prefix.marked ? marked : AclPrefix::Mode::NATIVE;
		prefix.rest = query.substr(pos);
		return prefix;
	}
	bool is_role = StringUtil::CIEquals(mode, "role");
	bool is_token = StringUtil::CIEquals(mode, "token");
	if (!is_role && !is_token) {
		return prefix; // "ACL <unknown>" -> leave for the native parser (NONE)
	}
	SkipWhitespace(query, pos);
	if (pos >= query.size() || (query[pos] != '\'' && query[pos] != '"')) {
		throw ParserException("acl_rewrite: ACL %s requires a quoted value", mode);
	}
	prefix.kind = is_role ? AclPrefix::Kind::ROLE : AclPrefix::Kind::TOKEN;
	prefix.value = ReadQuoted(query, pos);
	prefix.mode = read_marker(pos);
	prefix.marked = prefix.mode != AclPrefix::Mode::QUERY;
	prefix.rest = query.substr(pos);
	return prefix;
}

//===--------------------------------------------------------------------===//
// ACL ADMIN management grammar (spec 008)
//
// Recognized forms compile - with NO side effects at parse time - into synthesized
// `SELECT acl_<fn>(<constants>)` statements that run through the normal pipeline into the existing
// admin functions. Values travel as ConstantExpression nodes, never as SQL text. Anything that does
// not start with a management form stays the native ADMIN passthrough (`ACL ADMIN CREATE TABLE ...`
// is still plain DDL); a management form with a typo is an error, never a fallthrough.
//===--------------------------------------------------------------------===//

//! Token reader over the management text (words, dotted identifiers, quoted values)
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
	string Quoted(const char *what) {
		Skip();
		if (pos >= text.size() || (text[pos] != '\'' && text[pos] != '"')) {
			throw BinderException("acl admin: expected a quoted %s at position %llu", what, pos);
		}
		return ReadQuoted(text, pos);
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
bool IsMgmtStart(const string &text) {
	AdminScanner scanner(text);
	auto first = scanner.PeekWord();
	if (StringUtil::CIEquals(first, "add") || StringUtil::CIEquals(first, "grant") ||
	    StringUtil::CIEquals(first, "revoke") || StringUtil::CIEquals(first, "map")) {
		return true;
	}
	if (StringUtil::CIEquals(first, "create") || StringUtil::CIEquals(first, "drop") ||
	    StringUtil::CIEquals(first, "alter")) {
		AdminScanner ahead(text);
		ahead.Word("keyword");
		auto second = ahead.PeekWord();
		if (StringUtil::CIEquals(first, "create")) {
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
		       StringUtil::CIEquals(second, "map");
	}
	return false;
}

unique_ptr<SQLStatement> ParseMgmtStatement(AdminScanner &s) {
	auto keyword = s.Word("a management keyword");
	if (StringUtil::CIEquals(keyword, "create")) {
		if (s.Accept("virtual")) {
			s.Expect("catalog");
			auto vcat = s.Word("a catalog name");
			string comment;
			if (s.Accept("comment")) {
				comment = s.Quoted("comment");
			}
			return MakeAdminCall("acl_create_catalog", {Value(vcat), Value(comment)});
		}
		if (s.Accept("role")) {
			auto role = s.Word("a role name");
			string claims;
			if (s.Accept("claims")) {
				claims = s.Quoted("claims list");
			}
			return MakeAdminCall("acl_define_role", {Value(role), Value(claims)});
		}
		s.Expect("issuer");
		auto issuer = s.Quoted("issuer");
		s.Expect("keys");
		auto keys = s.Quoted("keys");
		string audiences, algs = "RS256", role_claim = "roles", claim_map;
		if (s.Accept("audiences")) {
			audiences = s.Quoted("audiences");
		}
		if (s.Accept("algs")) {
			algs = s.Quoted("algs");
		}
		if (s.Accept("role")) {
			s.Expect("claim");
			role_claim = s.Quoted("role claim path");
		}
		if (s.Accept("claim")) {
			s.Expect("map");
			claim_map = s.Quoted("claim map");
		}
		return MakeAdminCall("acl_define_issuer", {Value(issuer), Value(keys), Value(audiences), Value(algs),
		                                           Value(role_claim), Value(claim_map)});
	}
	if (StringUtil::CIEquals(keyword, "add")) {
		if (s.Accept("view")) {
			string vcat, vname;
			SplitVirtual(s.Dotted("a virtual name"), vcat, vname);
			s.Expect("as");
			auto sql = s.Quoted("view SQL");
			return MakeAdminCall("acl_add_view", {Value(vcat), Value(vname), Value(sql)});
		}
		if (s.Accept("schema")) {
			auto phys = s.Dotted("a physical schema path");
			s.Expect("as");
			string vcat, alias;
			SplitVirtual(s.Dotted("a virtual alias"), vcat, alias);
			return MakeAdminCall("acl_add_schema_alias", {Value(vcat), Value(alias), Value(phys)});
		}
		if (s.Accept("scalar")) {
			string vcat, vname;
			SplitVirtual(s.Dotted("a virtual name"), vcat, vname);
			bool is_macro = s.Accept("macro");
			if (!is_macro) {
				s.Expect("alias");
			}
			auto definition = s.Quoted(is_macro ? "expression template" : "target function");
			return MakeAdminCall(is_macro ? "acl_add_scalar" : "acl_add_scalar_alias",
			                     {Value(vcat), Value(vname), Value(definition)});
		}
		s.Expect("table");
		if (s.Accept("function")) {
			string vcat, vname;
			SplitVirtual(s.Dotted("a virtual name"), vcat, vname);
			bool is_macro = s.Accept("macro");
			if (!is_macro) {
				s.Expect("alias");
			}
			auto definition = s.Quoted(is_macro ? "SQL template" : "target function");
			return MakeAdminCall(is_macro ? "acl_add_table_function" : "acl_add_table_function_alias",
			                     {Value(vcat), Value(vname), Value(definition)});
		}
		auto phys = s.Dotted("a physical table path");
		s.Expect("as");
		string vcat, vname;
		SplitVirtual(s.Dotted("a virtual name"), vcat, vname);
		string columns, rls;
		if (s.Accept("columns")) {
			columns = s.Quoted("columns list");
		}
		if (s.Accept("rls")) {
			rls = s.Quoted("RLS predicate");
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
		s.Expect("catalog");
		auto vcat = s.Word("a catalog name");
		s.Expect("to");
		s.Expect("role");
		auto role = s.Word("a role name");
		string caps = "{}";
		if (s.Accept("caps")) {
			caps = s.Quoted("caps JSON");
		}
		bool main = s.Accept("main");
		return MakeAdminCall("acl_grant_catalog", {Value(role), Value(vcat), Value(caps), Value::BOOLEAN(main)});
	}
	if (StringUtil::CIEquals(keyword, "revoke")) {
		if (s.Accept("admin")) { // REVOKE ADMIN FROM ROLE r
			s.Expect("from");
			s.Expect("role");
			auto role = s.Word("a role name");
			return MakeAdminCall("acl_revoke_admin", {Value(role)});
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
		if (s.Accept("role")) { // ALTER ROLE r SET CLAIMS '...'
			auto role = s.Word("a role name");
			s.Expect("set");
			s.Expect("claims");
			return MakeAdminCall("acl_alter_role", {Value(role), Value(s.Quoted("claims list"))});
		}
		if (s.Accept("issuer")) { // ALTER ISSUER '...' SET KEYS|AUDIENCES|ALGS|ROLE CLAIM|CLAIM MAP '...'
			auto issuer = s.Quoted("issuer");
			s.Expect("set");
			string field;
			if (s.Accept("keys")) {
				field = "keys";
			} else if (s.Accept("audiences")) {
				field = "audiences";
			} else if (s.Accept("algs")) {
				field = "algs";
			} else if (s.Accept("role")) {
				s.Expect("claim");
				field = "role_claim";
			} else {
				s.Expect("claim");
				s.Expect("map");
				field = "claim_map";
			}
			return MakeAdminCall("acl_alter_issuer", {Value(issuer), Value(field), Value(s.Quoted("value"))});
		}
		if (s.Accept("grant")) { // ALTER GRANT CATALOG c TO ROLE r SET CAPS '...' | SET MAIN true|false
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
		if (s.Accept("view")) { // ALTER VIRTUAL VIEW v.n SET AS '...'
			string vcat, vname;
			SplitVirtual(s.Dotted("a virtual name"), vcat, vname);
			s.Expect("set");
			s.Expect("as");
			return MakeAdminCall("acl_alter_relation",
			                     {Value(vcat), Value(vname), Value("view"), Value(s.Quoted("view SQL"))});
		}
		if (s.Accept("schema")) { // ALTER VIRTUAL SCHEMA v.alias SET PHYS <path>
			string vcat, alias;
			SplitVirtual(s.Dotted("a virtual alias"), vcat, alias);
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
			s.Expect("set");
			if (scalar || table_function) { // ALTER VIRTUAL [TABLE FUNCTION|SCALAR] v.n SET MACRO|ALIAS '...'
				bool is_macro = s.Accept("macro");
				if (!is_macro) {
					s.Expect("alias");
				}
				return MakeAdminCall("acl_alter_function",
				                     {Value(vcat), Value(vname), Value(scalar ? "scalar" : "table"),
				                      Value(is_macro ? "macro" : "alias"), Value(s.Quoted("definition"))});
			}
			// ALTER VIRTUAL TABLE v.n SET PHYS <path> | SET COLUMNS '...' | SET RLS '...'
			if (s.Accept("phys")) {
				return MakeAdminCall("acl_alter_relation", {Value(vcat), Value(vname), Value("phys"),
				                                            Value(s.Dotted("a physical table path"))});
			}
			if (s.Accept("columns")) {
				return MakeAdminCall("acl_alter_relation",
				                     {Value(vcat), Value(vname), Value("columns"), Value(s.Quoted("columns list"))});
			}
			s.Expect("rls");
			return MakeAdminCall("acl_alter_relation",
			                     {Value(vcat), Value(vname), Value("rls"), Value(s.Quoted("RLS predicate"))});
		}
		throw BinderException("acl admin: unknown ALTER VIRTUAL target");
	}
	if (StringUtil::CIEquals(keyword, "drop")) {
		if (s.Accept("relation")) { // the spec-008 spelling, kept
			string vcat, vname;
			SplitVirtual(s.Dotted("a virtual name"), vcat, vname);
			return MakeAdminCall("acl_drop_relation", {Value(vcat), Value(vname)});
		}
		if (s.Accept("role")) {
			return MakeAdminCall("acl_drop_role", {Value(s.Word("a role name"))});
		}
		if (s.Accept("issuer")) {
			return MakeAdminCall("acl_drop_issuer", {Value(s.Quoted("issuer"))});
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
			auto vcat = s.Word("a catalog name");
			bool cascade = s.Accept("cascade");
			return MakeAdminCall("acl_drop_catalog", {Value(vcat), Value::BOOLEAN(cascade)});
		}
		if (s.Accept("schema")) {
			string vcat, alias;
			SplitVirtual(s.Dotted("a virtual alias"), vcat, alias);
			return MakeAdminCall("acl_drop_schema_alias", {Value(vcat), Value(alias)});
		}
		bool scalar = s.Accept("scalar");
		if (scalar || s.Accept("table")) {
			bool table_function = !scalar && s.Accept("function");
			string vcat, vname;
			SplitVirtual(s.Dotted("a virtual name"), vcat, vname);
			if (scalar || table_function) {
				return MakeAdminCall("acl_drop_function",
				                     {Value(vcat), Value(vname), Value(scalar ? "scalar" : "table")});
			}
			return MakeAdminCall("acl_drop_relation", {Value(vcat), Value(vname)});
		}
		if (s.Accept("view")) {
			string vcat, vname;
			SplitVirtual(s.Dotted("a virtual name"), vcat, vname);
			return MakeAdminCall("acl_drop_relation", {Value(vcat), Value(vname)});
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
	    {"acl_create_catalog", 0},     {"acl_add_relation", 0},       {"acl_add_view", 0},
	    {"acl_add_schema_alias", 0},   {"acl_add_table_function", 0}, {"acl_add_table_function_alias", 0},
	    {"acl_add_scalar", 0},         {"acl_add_scalar_alias", 0},   {"acl_drop_relation", 0},
	    {"acl_grant_catalog", 1},      {"acl_revoke_catalog", 1},     {"acl_define_role", -1},
	    {"acl_define_issuer", -1},     {"acl_map_role", -1},          {"acl_alter_relation", 0},
	    {"acl_alter_schema_alias", 0}, {"acl_alter_function", 0},     {"acl_alter_catalog", 0},
	    {"acl_alter_grant", 1},        {"acl_alter_role", -1},        {"acl_alter_issuer", -1},
	    {"acl_drop_schema_alias", 0},  {"acl_drop_function", 0},      {"acl_drop_role", -1},
	    {"acl_drop_issuer", -1},       {"acl_drop_role_mapping", -1},
	};
	MgmtProvenance provenance;
	auto &select = statement.Cast<SelectStatement>().node->Cast<SelectNode>();
	auto &call = select.select_list[0]->Cast<FunctionExpression>();
	auto name = StringUtil::Lower(call.FunctionName().GetIdentifierName());
	if (name == "acl_grant_admin" || name == "acl_revoke_admin") {
		provenance.escalates = true;
		return provenance;
	}
	if (name == "acl_grant_catalog" || name == "acl_revoke_catalog" || name == "acl_alter_grant" ||
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

ParserOverrideResult AclParserOverride(ParserExtensionInfo *info, const string &query, ParserOptions &options) {
	auto prefix = ParseAclPrefix(query);
	if (prefix.kind == AclPrefix::Kind::NONE) {
		return ParserOverrideResult(); // fall through to the native parser
	}
	auto &store = *info->Cast<AclParserInfo>().store;

	auto mode = prefix.mode;
	bool anonymous = prefix.kind == AclPrefix::Kind::ADMIN;
	if (anonymous && !prefix.marked && IsMgmtStart(prefix.rest)) {
		// the trusted gateway may write management statements unmarked; an explicit `ACL NATIVE`
		// means "plain SQL, do not interpret it" and must never be re-routed here
		mode = AclPrefix::Mode::MANAGE;
	}

	Principal principal;
	PolicyStore::AdminRights rights;
	rights.scope = AdminScope::PASSTHROUGH; // the anonymous hatch is god mode by definition
	rights.unrestricted_manage = true;
	if (anonymous) {
		if (!store.AnonymousAdminAllowed()) {
			throw BinderException("acl admin: a bare ACL ADMIN is disabled - authenticate the principal "
			                      "(ACL TOKEN '<jwt>' ACL ...) or SET GLOBAL acl_allow_anonymous_admin=true");
		}
	} else if (mode != AclPrefix::Mode::QUERY) {
		// leaving the virtual catalog - as management or as native SQL - is a granted capability
		bool is_token = prefix.kind == AclPrefix::Kind::TOKEN;
		if (!store.VerifyPrincipal(is_token, prefix.value, principal)) {
			throw BinderException("acl_rewrite: %s verification failed", is_token ? "token" : "role");
		}
		rights = store.AdminRightsOf(principal);
		if (rights.scope == AdminScope::NONE) {
			throw BinderException("acl admin: the principal has no ACL administration scope");
		}
	}

	if (mode == AclPrefix::Mode::MANAGE) {
		// the management grammar (spec 008): compiled to admin-function calls, no native parse
		auto statements = ParseMgmtBatch(prefix.rest);
		AuthorizeMgmt(statements, rights);
		return ParserOverrideResult(std::move(statements));
	}
	if (mode == AclPrefix::Mode::NATIVE && rights.scope != AdminScope::PASSTHROUGH) {
		// a manage scope administers the ACL; running SQL outside the virtual catalog is god mode
		throw BinderException("acl admin: native SQL outside the virtual catalog requires a passthrough scope");
	}

	// re-parse the remainder with the native parser (never re-entering this override)
	ParserOptions inner = options;
	inner.parser_override_setting = AllowParserOverride::DEFAULT_OVERRIDE;
	Parser parser(inner);
	parser.ParseQuery(prefix.rest);

	if (mode == AclPrefix::Mode::NATIVE) {
		return ParserOverrideResult(std::move(parser.statements)); // no rewrite: the native context
	}

	bool is_token = prefix.kind == AclPrefix::Kind::TOKEN;
	if (!store.VerifyPrincipal(is_token, prefix.value, principal)) {
		throw BinderException("acl_rewrite: %s verification failed", is_token ? "token" : "role");
	}

	RewriteStatements(parser.statements, principal, options, store);
	return ParserOverrideResult(std::move(parser.statements));
}

} // namespace

void RegisterAclParser(DBConfig &config, shared_ptr<PolicyStore> store) {
	ParserExtension extension;
	extension.parser_override = AclParserOverride;
	extension.parser_info = make_shared_ptr<AclParserInfo>(std::move(store));
	ParserExtension::Register(config, extension);
}

} // namespace acl
} // namespace duckdb
