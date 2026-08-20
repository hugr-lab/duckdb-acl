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

namespace duckdb {
namespace acl {
namespace {

struct AclPrefix {
	enum class Kind { NONE, ROLE, TOKEN, ADMIN };
	Kind kind = Kind::NONE;
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
	if (StringUtil::CIEquals(mode, "admin")) {
		prefix.kind = AclPrefix::Kind::ADMIN;
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
	if (StringUtil::CIEquals(first, "create") || StringUtil::CIEquals(first, "drop")) {
		AdminScanner ahead(text);
		ahead.Word("keyword");
		auto second = ahead.PeekWord();
		if (StringUtil::CIEquals(first, "create")) {
			return StringUtil::CIEquals(second, "virtual") || StringUtil::CIEquals(second, "role") ||
			       StringUtil::CIEquals(second, "issuer");
		}
		return StringUtil::CIEquals(second, "relation");
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
	if (StringUtil::CIEquals(keyword, "drop")) {
		s.Expect("relation");
		string vcat, vname;
		SplitVirtual(s.Dotted("a virtual name"), vcat, vname);
		return MakeAdminCall("acl_drop_relation", {Value(vcat), Value(vname)});
	}
	throw BinderException("acl admin: unknown management statement \"%s\"", keyword);
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

ParserOverrideResult AclParserOverride(ParserExtensionInfo *info, const string &query, ParserOptions &options) {
	auto prefix = ParseAclPrefix(query);
	if (prefix.kind == AclPrefix::Kind::NONE) {
		return ParserOverrideResult(); // fall through to the native parser
	}

	if (prefix.kind == AclPrefix::Kind::ADMIN && IsMgmtStart(prefix.rest)) {
		// the management grammar (spec 008): compiled to admin-function calls, no native parse
		return ParserOverrideResult(ParseMgmtBatch(prefix.rest));
	}

	// re-parse the remainder with the native parser (never re-entering this override)
	ParserOptions inner = options;
	inner.parser_override_setting = AllowParserOverride::DEFAULT_OVERRIDE;
	Parser parser(inner);
	parser.ParseQuery(prefix.rest);

	if (prefix.kind == AclPrefix::Kind::ADMIN) {
		return ParserOverrideResult(std::move(parser.statements)); // passthrough, no rewrite
	}

	auto &store = *info->Cast<AclParserInfo>().store;
	Principal principal;
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
