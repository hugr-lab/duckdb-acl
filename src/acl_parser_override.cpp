#include "acl_parser_override.hpp"

#include "acl_rewriter.hpp"
#include "duckdb/common/exception/binder_exception.hpp"
#include "duckdb/common/exception/parser_exception.hpp"
#include "duckdb/common/helper.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/parser/parser.hpp"

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

ParserOverrideResult AclParserOverride(ParserExtensionInfo *info, const string &query, ParserOptions &options) {
	auto prefix = ParseAclPrefix(query);
	if (prefix.kind == AclPrefix::Kind::NONE) {
		return ParserOverrideResult(); // fall through to the native parser
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
