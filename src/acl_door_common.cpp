#include "acl_door_common.hpp"
#include "acl_door_certificate.hpp"
#include "acl_platform.hpp"
#include "acl_name_path.hpp"
#include "acl_profile.hpp"

#include "duckdb/common/string_util.hpp"

#include <cstring>
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/main/connection.hpp"
#include "duckdb/planner/expression/bound_function_expression.hpp"

namespace duckdb {
namespace acl {

shared_ptr<PolicyStore> SharedStoreOf(ExpressionState &state) {
	return state.expr.Cast<BoundFunctionExpression>().Function().GetExtraFunctionInfo().Cast<AclScalarInfo>().store;
}

namespace {
//! A pointer, never a string (spec 088): a thread_local with a non-trivial destructor is not safe on MinGW
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
thread_local const string *author_in_scope = nullptr;
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
thread_local const string *author_roles_in_scope = nullptr;
} // namespace

AuthorScope::AuthorScope(ExpressionState &state) : author(StatementAuthor(state.GetContext())) {
	Principal principal;
	if (StatementPrincipal(state.GetContext(), principal)) {
		auto rights = StoreOf(state).AdminRightsOf(principal);
		if (rights.MayAdminister() && !rights.Policy()) {
			// the source gate bound this writer (spec 118.3: everyone below policy, the cluster bundle too); a unit
			// separator between the roles - a role name may hold a comma
			roles = StringUtil::Join(principal.roles, "\x1f");
		}
	}
	previous_author = author_in_scope;
	previous_roles = author_roles_in_scope;
	author_in_scope = &author;
	author_roles_in_scope = &roles;
}

AuthorScope::AuthorScope(const string &author_p) : author(author_p) {
	previous_author = author_in_scope;
	previous_roles = author_roles_in_scope;
	author_in_scope = &author;
	author_roles_in_scope = &roles;
}

AuthorScope::~AuthorScope() {
	author_in_scope = previous_author;
	author_roles_in_scope = previous_roles;
}

string AuthorInScope() {
	return author_in_scope ? *author_in_scope : string();
}

string AuthorRolesInScope() {
	return author_roles_in_scope ? *author_roles_in_scope : string();
}

PolicyStore &StoreOf(ExpressionState &state) {
	return *SharedStoreOf(state);
}

string RequiredArg(DataChunk &args, idx_t col, idx_t row, const char *fn, const char *what) {
	auto value = args.GetValue(col, row);
	if (value.IsNull()) {
		throw InvalidInputException("%s: %s must not be NULL", fn, what);
	}
	return value.ToString();
}

string NameKey(const string &text, const char *fn, const char *what) {
	if (text.empty()) {
		return text;
	}
	NamePath path;
	string error;
	if (!NamePath::TryFromKey(text, path, error)) {
		throw InvalidInputException("%s: the %s \"%s\" is not a name: %s", fn, what, text, error);
	}
	return path.ToKey();
}

string KeyArg(DataChunk &args, idx_t col, idx_t row, const char *fn, const char *what) {
	return NameKey(RequiredArg(args, col, row, fn, what), fn, what);
}

string CatalogKey(const string &text, const char *fn, const char *what) {
	auto key = NameKey(text, fn, what);
	if (NamePath::KeySize(key) > 1) {
		throw InvalidInputException("%s: a %s is one identifier - write \"%s\" in double quotes for a name with a "
		                            "dot in it",
		                            fn, what, text);
	}
	if (IsPlatformCatalog(key)) {
		// spec 117: the system catalog of administration is synthesized - no call names it as a catalog
		throw InvalidInputException("%s: \"%s\" is the reserved system catalog of administration, not a virtual "
		                            "catalog",
		                            fn, text);
	}
	return key;
}

string CatalogArg(DataChunk &args, idx_t col, idx_t row, const char *fn, const char *what) {
	return CatalogKey(RequiredArg(args, col, row, fn, what), fn, what);
}

string OptionalArg(DataChunk &args, idx_t col, idx_t row, const string &fallback) {
	if (col >= args.ColumnCount()) {
		return fallback;
	}
	auto value = args.GetValue(col, row);
	return value.IsNull() ? fallback : value.ToString();
}

string Trimmed(string value) {
	StringUtil::Trim(value);
	return value;
}

string JsonQuote(const string &value) {
	string out = "\"";
	for (auto c : value) {
		if (c == '"' || c == '\\') {
			out += '\\';
			out += c;
		} else if (static_cast<unsigned char>(c) < 0x20) {
			out += StringUtil::Format("\\u%04x", static_cast<int>(static_cast<unsigned char>(c)));
		} else {
			out += c;
		}
	}
	out += "\"";
	return out;
}

bool IsLocalCertificatePath(const string &arg) {
	static constexpr const char *FILE_SCHEME = "file://";
	auto trimmed = arg;
	StringUtil::Trim(trimmed);
	if (trimmed.empty() || StringUtil::StartsWith(trimmed, "-----BEGIN")) {
		return false;
	}
	if (StringUtil::Contains(trimmed, "://")) {
		return StringUtil::StartsWith(StringUtil::Lower(trimmed), FILE_SCHEME) && trimmed.size() > strlen(FILE_SCHEME);
	}
	return true;
}

string LocalCertificatePath(const string &arg) {
	static constexpr const char *FILE_SCHEME = "file://";
	auto trimmed = arg;
	StringUtil::Trim(trimmed);
	if (StringUtil::StartsWith(StringUtil::Lower(trimmed), FILE_SCHEME)) {
		return trimmed.substr(strlen(FILE_SCHEME));
	}
	return trimmed;
}

idx_t DoorCertificateRefresh(DatabaseInstance &db) {
	Value value;
	if (!DBConfig::GetConfig(db).TryGetCurrentSetting("acl_door_certificate_refresh", value) || value.IsNull()) {
		return 60;
	}
	auto seconds = value.GetValue<int64_t>();
	return seconds <= 0 ? 0 : NumericCast<idx_t>(seconds);
}

string ReadPemArg(ClientContext &context, const string &arg, const char *what, const char *fn) {
	auto trimmed = arg;
	StringUtil::Trim(trimmed);
	if (StringUtil::StartsWith(trimmed, "-----BEGIN")) {
		return trimmed; // inline PEM, handed straight to the TLS stack
	}
	Connection con(*context.db);
	auto quoted = "'" + StringUtil::Replace(trimmed, "'", "''") + "'";
	auto result = con.Query("SELECT content FROM read_text(" + quoted + ")");
	if (result->HasError()) {
		throw IOException("%s: could not read the %s from \"%s\": %s", fn, what, trimmed, result->GetError());
	}
	if (result->RowCount() != 1 || result->Collection().GetValue(0, 0).IsNull()) {
		throw IOException("%s: the %s location \"%s\" holds no single document", fn, what, trimmed);
	}
	auto content = result->Collection().GetValue(0, 0).ToString();
	// a path to the wrong file is a common mistake; say so here rather than let it reach the TLS
	// stack as the cryptic init error this helper exists to avoid
	auto head = content;
	StringUtil::Trim(head);
	if (!StringUtil::StartsWith(head, "-----BEGIN")) {
		throw InvalidInputException("%s: the %s at \"%s\" is not PEM (no -----BEGIN marker) - pass a PEM file/URI "
		                            "or inline PEM text",
		                            fn, what, trimmed);
	}
	return content;
}

string ListenHost(const string &uri) {
	auto text = uri;
	StringUtil::Trim(text);
	auto scheme = text.find("://");
	if (scheme != string::npos) {
		text = text.substr(scheme + 3); // grpc://, grpc+tls://
	} else if (StringUtil::StartsWith(StringUtil::Lower(text), "quack:")) {
		text = text.substr(6);
	}
	// A bracketed IPv6 literal carries colons inside the host, so the port is the colon AFTER the
	// closing bracket - splitting on the first colon would take one from inside the address.
	if (!text.empty() && text[0] == '[') {
		auto close = text.find(']');
		return close == string::npos ? text : text.substr(0, close + 1);
	}
	auto colon = text.find(':');
	return colon == string::npos ? text : text.substr(0, colon);
}

namespace {

bool IsLoopback(const string &host) {
	auto lowered = StringUtil::Lower(host);
	return lowered == "localhost" || lowered == "127.0.0.1" || lowered == "::1" || lowered == "[::1]";
}

} // namespace

void RefuseUnlessServable(ClientContext &context, PolicyStore &store, const char *fn, const string &host, bool has_tls,
                          bool cleartext_ok) {
	if (!store.CatalogEnabled()) {
		throw BinderException("%s: no policy source is configured - a served instance resolves every statement "
		                      "against one, so `acl_use_db` (or the function driver) comes first",
		                      fn);
	}
	if (store.CatalogAnonymousAdminAllowed()) {
		throw BinderException("%s: `acl_allow_anonymous_admin` is on, so a served client could administer the "
		                      "ACL with a bare `ACL ADMIN` - turn it off before opening the door",
		                      fn);
	}
	Value override_setting;
	if (context.TryGetCurrentSetting("allow_parser_override_extension", override_setting) &&
	    !StringUtil::CIEquals(override_setting.ToString(), "strict")) {
		throw BinderException("%s: the parser override is \"%s\", not STRICT - a served statement that failed "
		                      "to parse as ACL would fall through to plain SQL",
		                      fn, override_setting.ToString());
	}
	// TLS is what lets a door leave the machine (spec 053). Without a certificate it serves in the
	// clear, so it binds only an address that cannot leave the machine; with one, any address is the
	// operator's call - as is an explicit cleartext mode, which says a proxy terminates TLS upstream.
	// This is the one refusal a certificate lifts; the three above stand regardless.
	if (!has_tls && !cleartext_ok && !IsLoopback(host)) {
		throw BinderException("%s: without a TLS certificate the door serves in the clear, so it binds only "
		                      "localhost - pass a cert and key to serve a non-local address, or put a "
		                      "TLS-terminating proxy in front",
		                      fn);
	}
}

} // namespace acl
} // namespace duckdb
