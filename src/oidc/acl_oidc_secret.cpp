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
oidc::TokenSet Acquire(ClientContext &context, const CreateSecretInput &input, const string &flow,
                       string &resolved_issuer) {
	if (flow == "token") {
		oidc::TokenSet out;
		out.access_token = Require(input, "token", "token");
		return out;
	}
	auto issuer = Param(input, "issuer");
	if (issuer.empty()) {
		// spec 062: the door advertises its issuers on /.well-known/quack-auth, so ISSUER may be
		// omitted when the secret's SCOPE names a concrete door - the scheme mirrors quack's own
		// client rule (loopback speaks http, anything else https, i.e. the TLS front)
		string endpoint;
		for (auto &scope : input.scope) {
			if (scope.rfind("quack:", 0) == 0 && scope.size() > 6) {
				endpoint = scope.substr(6);
				while (!endpoint.empty() && endpoint.front() == '/') {
					endpoint.erase(endpoint.begin());
				}
				break;
			}
		}
		if (endpoint.empty()) {
			throw InvalidInputException(
			    "acl oidc secret: name ISSUER, or give SCOPE a concrete door ('quack:host:port') to discover it");
		}
		// classify the door host: an IPv6 literal is bracketed ([::1]:port), so the port colon is the
		// one after ']'; anything else splits at the first colon (the review's IPv6 finding)
		string host;
		if (!endpoint.empty() && endpoint.front() == '[') {
			auto bracket = endpoint.find(']');
			host = bracket == string::npos ? endpoint : endpoint.substr(1, bracket - 1);
		} else {
			host = endpoint.substr(0, endpoint.find(':'));
		}
		bool local = host == "localhost" || host == "127.0.0.1" || host == "::1";
		auto discovered = oidc::FetchQuackAuth((local ? "http://" : "https://") + endpoint);
		if (!discovered.Ok()) {
			throw InvalidInputException("acl oidc secret: door discovery at \"%s\" failed: %s", endpoint,
			                            discovered.error);
		}
		if (discovered.issuers.empty()) {
			throw InvalidInputException("acl oidc secret: the door advertises no issuers - name ISSUER explicitly");
		}
		if (discovered.issuers.size() > 1) {
			throw InvalidInputException("acl oidc secret: the door advertises %d issuers - name ISSUER explicitly",
			                            int(discovered.issuers.size()));
		}
		issuer = discovered.issuers.front();
	}
	resolved_issuer = issuer;
	auto client_id = Require(input, "client_id", flow.c_str());
	auto client_secret = Param(input, "client_secret");
	auto oauth_scope = Param(input, "oauth_scope");
	auto endpoints = oidc::Discover(issuer);
	if (!endpoints.Ok()) {
		throw InvalidInputException("acl oidc secret: discovery against \"%s\" failed: %s", issuer, endpoints.error);
	}
	// the cache is consulted for a refresh token ONLY (see the header comment); the key carries
	// everything that shapes the credential, so a collision can at worst serve the same one
	auto cache_key = issuer + "|" + Param(input, "client_id") + "|" + flow + "|" + Param(input, "username") + "|" +
	                 Param(input, "oauth_scope");
	auto cached = oidc::TokenCache::Instance().Get(nullptr, cache_key, /*margin*/ 0);
	if (!cached.refresh_token.empty()) {
		auto renewed = oidc::RefreshGrant(endpoints, client_id, client_secret, cached.refresh_token);
		if (renewed.Ok()) {
			if (renewed.refresh_token.empty()) {
				// RFC 6749 §6: a refresh response MAY omit the refresh token, and the old one then
				// stays valid - carry it forward or the chain dies after one replace (the review)
				renewed.refresh_token = cached.refresh_token;
			}
			return renewed;
		}
		if (renewed.error_code == "invalid_grant") {
			// the token itself is spent/revoked - only then is the chain dead. A transport failure
			// or an invalid_client (the CALLER's wrong secret) must not evict a good chain.
			oidc::TokenCache::Instance().Invalidate(nullptr, cache_key);
		}
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
		                        NowSeconds() + begun.expires_in, [&context] { return context.IsInterrupted(); });
	}
	throw InvalidInputException(
	    "acl oidc secret: FLOW must be 'token', 'client_credentials', 'password' or 'device', not '%s'", flow);
}

unique_ptr<BaseSecret> CreateQuackOidcSecret(ClientContext &context, CreateSecretInput &input) {
	auto flow = StringUtil::Lower(Param(input, "flow"));
	if (flow.empty()) {
		flow = Param(input, "token").empty() ? string() : string("token");
	}
	if (flow.empty()) {
		throw InvalidInputException(
		    "acl oidc secret: name a FLOW ('token', 'client_credentials', 'password' or 'device')");
	}
	string resolved_issuer;
	auto minted = Acquire(context, input, flow, resolved_issuer);
	if (!minted.Ok()) {
		throw InvalidInputException("acl oidc secret: the %s flow was refused: %s", flow, minted.error);
	}
	if (flow != "token" && !minted.refresh_token.empty()) {
		// keep the refresh CHAIN and nothing else: the access token is blanked (it is never served
		// from here) and the entry carries no expiry - the access token's lifetime must not kill a
		// refresh token that outlives it by hours (the review); a genuinely dead chain is
		// invalidated where the refresh fails with invalid_grant.
		oidc::TokenSet chain;
		chain.refresh_token = minted.refresh_token;
		auto chain_key = resolved_issuer + "|" + Param(input, "client_id") + "|" + flow + "|" +
		                 Param(input, "username") + "|" + Param(input, "oauth_scope");
		oidc::TokenCache::Instance().Set(nullptr, chain_key, std::move(chain));
	}
	auto scope = input.scope;
	if (scope.empty()) {
		scope.emplace_back("quack:"); // the same catch-all quack's own config provider defaults to
	}
	auto secret = make_uniq<KeyValueSecret>(scope, input.type, input.provider, input.name);
	secret->secret_map["token"] = Value(minted.access_token); // the field quack's client reads
	// visible configuration, so duckdb_secrets() tells an operator what minted this token; the raw
	// credentials (password, client_secret) were consumed by the flow and are NOT stored
	if (!resolved_issuer.empty()) {
		secret->secret_map["issuer"] = Value(resolved_issuer); // the resolved one, discovery included
	}
	for (const char *keep : {"client_id", "flow", "username"}) {
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
