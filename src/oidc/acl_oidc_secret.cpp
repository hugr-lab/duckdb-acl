//===----------------------------------------------------------------------===//
// acl_oidc_secret.cpp — the quack OIDC secret provider (spec 061). See header.
//
// `CREATE SECRET s (TYPE quack, PROVIDER oidc, SCOPE 'quack:host:port',
//     ISSUER 'https://kc/realms/x', CLIENT_ID 'cli', FLOW 'device' | 'password'
//     | 'client_credentials' | 'token' [, CLIENT_SECRET ...] [, USERNAME ...]
//     [, PASSWORD ...] [, TOKEN ...] [, OAUTH_SCOPE ...])`
//
// The flow menu is the admin's policy (design/016 §2): the provider offers all
// four; which ones an IdP accepts is configured there. The minted token lands
// in secret_map["token"], which quack's ConnectToServer already reads when the
// ATTACH carries no inline TOKEN — zero quack changes.
//
// Re-minting: every CREATE (OR REPLACE) SECRET yields a FRESH access token —
// the cache (spec 060) is consulted for a REFRESH token only, so a device-flow
// re-mint is silent while an access token cached past its validity can never be
// served (the review's obligation #2: expires_in is optional in RFC 6749, so an
// access token must not be trusted from the cache at all). The cache key
// includes issuer|client_id|flow|username (obligation #1), and raw credentials
// (password, client_secret) are consumed by the flow and never stored.
//===----------------------------------------------------------------------===//

#include "acl_oidc_secret.hpp"

#include "acl_oidc.hpp"
#include "duckdb.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/main/secret/secret.hpp"

#include <chrono>
#include <iostream>

namespace duckdb {
namespace acl {

namespace {

//! The named parameter, or "" — CREATE SECRET options arrive case-insensitive.
string Param(const CreateSecretInput &input, const char *name) {
	auto entry = input.options.find(name);
	if (entry == input.options.end() || entry->second.IsNull()) {
		return string();
	}
	return entry->second.ToString();
}

string Require(const CreateSecretInput &input, const char *name, const char *flow) {
	auto value = Param(input, name);
	if (value.empty()) {
		throw InvalidInputException("acl oidc secret: FLOW '%s' needs %s", flow, StringUtil::Upper(name));
	}
	return value;
}

int64_t NowSeconds() {
	return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
	    .count();
}

//! Run the configured flow and return the token set; every refusal is the
//! protocol's own, surfaced verbatim — never a silent fallback to another flow.
oidc::TokenSet Acquire(const CreateSecretInput &input, const string &flow) {
	if (flow == "token") {
		oidc::TokenSet out;
		out.access_token = Require(input, "token", "token");
		return out;
	}
	auto issuer = Require(input, "issuer", flow.c_str());
	auto client_id = Require(input, "client_id", flow.c_str());
	auto client_secret = Param(input, "client_secret");
	auto oauth_scope = Param(input, "oauth_scope");
	auto endpoints = oidc::Discover(issuer);
	if (!endpoints.Ok()) {
		throw InvalidInputException("acl oidc secret: discovery against \"%s\" failed: %s", issuer, endpoints.error);
	}
	// the cache is consulted for a refresh token ONLY (see the header comment); the key carries
	// everything that names the credential, so a collision can at worst serve the same one
	auto cache_key = issuer + "|" + client_id + "|" + flow + "|" + Param(input, "username");
	auto cached = oidc::TokenCache::Instance().Get(nullptr, cache_key, /*margin*/ 0);
	if (!cached.refresh_token.empty()) {
		auto renewed = oidc::RefreshGrant(endpoints, client_id, client_secret, cached.refresh_token);
		if (renewed.Ok()) {
			return renewed;
		}
		oidc::TokenCache::Instance().Invalidate(nullptr, cache_key); // the refresh token is spent
	}
	if (flow == "client_credentials") {
		return oidc::ClientCredentials(endpoints, client_id, client_secret, oauth_scope);
	}
	if (flow == "password") {
		auto username = Require(input, "username", "password");
		auto password = Require(input, "password", "password");
		return oidc::PasswordGrant(endpoints, client_id, client_secret, username, password, oauth_scope);
	}
	if (flow == "device") {
		auto begun = oidc::DeviceBegin(endpoints, client_id, oauth_scope);
		if (!begun.Ok()) {
			throw InvalidInputException("acl oidc secret: device authorization failed: %s", begun.error);
		}
		// the CLI is the client here: the statement waits while the user approves in a browser
		std::cerr << "To authorize, open " << begun.verification_uri << " and enter code " << begun.user_code << "\n";
		if (!begun.verification_uri_complete.empty()) {
			std::cerr << "  (or open " << begun.verification_uri_complete << " directly)\n";
		}
		return oidc::DevicePoll(endpoints, client_id, begun.device_code, begun.interval,
		                        NowSeconds() + begun.expires_in);
	}
	throw InvalidInputException(
	    "acl oidc secret: FLOW must be 'token', 'client_credentials', 'password' or 'device', not '%s'", flow);
}

unique_ptr<BaseSecret> CreateQuackOidcSecret(ClientContext &, CreateSecretInput &input) {
	auto flow = StringUtil::Lower(Param(input, "flow"));
	if (flow.empty()) {
		flow = Param(input, "token").empty() ? string() : string("token");
	}
	if (flow.empty()) {
		throw InvalidInputException(
		    "acl oidc secret: name a FLOW ('token', 'client_credentials', 'password' or 'device')");
	}
	auto minted = Acquire(input, flow);
	if (!minted.Ok()) {
		throw InvalidInputException("acl oidc secret: the %s flow was refused: %s", flow, minted.error);
	}
	if (flow != "token") {
		// keep the refresh token (and only through it, silent re-mints); the access token is
		// deliberately not served from this cache - see the header comment
		auto cache_key =
		    Param(input, "issuer") + "|" + Param(input, "client_id") + "|" + flow + "|" + Param(input, "username");
		oidc::TokenCache::Instance().Set(nullptr, cache_key, minted);
	}
	auto scope = input.scope;
	if (scope.empty()) {
		scope.emplace_back("quack:"); // the same catch-all quack's own config provider defaults to
	}
	auto secret = make_uniq<KeyValueSecret>(scope, input.type, input.provider, input.name);
	secret->secret_map["token"] = Value(minted.access_token); // the field quack's client reads
	// visible configuration, so duckdb_secrets() tells an operator what minted this token; the raw
	// credentials (password, client_secret) were consumed by the flow and are NOT stored
	for (const char *keep : {"issuer", "client_id", "flow", "username"}) {
		auto value = Param(input, keep);
		if (!value.empty()) {
			secret->secret_map[keep] = Value(value);
		}
	}
	if (flow != "token") {
		secret->secret_map["flow"] = Value(flow);
	}
	secret->redact_keys = {"token"};
	return std::move(secret);
}

} // namespace

void RegisterQuackOidcProvider(ExtensionLoader &loader) {
	// The TYPE belongs to quack (its client reads these secrets); this registers only a second
	// PROVIDER on it. duckdb validates the type at CREATE SECRET, not at registration, so the load
	// order of the two extensions does not matter - but a CREATE SECRET before quack is loaded is
	// refused by the secret manager's own type lookup.
	CreateSecretFunction function = {"quack", "oidc", CreateQuackOidcSecret};
	for (const char *name :
	     {"token", "issuer", "client_id", "client_secret", "flow", "username", "password", "oauth_scope"}) {
		function.named_parameters[name] = LogicalType::VARCHAR;
	}
	loader.RegisterFunction(std::move(function));
}

} // namespace acl
} // namespace duckdb
