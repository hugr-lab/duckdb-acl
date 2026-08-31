//===----------------------------------------------------------------------===//
// acl_oidc.hpp — the OIDC client core (spec 060, design/016)
//
// The acquisition primitives every client-side layer shares: endpoint discovery
// (RFC 8414), the POST flows (client_credentials / password / device, RFC 8628),
// refresh, and a token cache with a refresh margin. Deliberately duckdb-free
// (std + yyjson + bundled httplib in the one TU), so a standalone test can link
// it, and NEVER used by the node's verification path: the node verifies tokens,
// this module obtains them — for the quack secret provider (A1) and the door's
// admin-enabled password handshake (B3). Generalised from
// hugr-lab/mssql-extension's Azure implementation to any OIDC issuer.
//===----------------------------------------------------------------------===//

#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <utility>

namespace duckdb {
namespace acl {
namespace oidc {

//! One HTTP exchange. `error` is non-empty only on transport failure; an HTTP
//! error status arrives as `status` + `body` for the caller to interpret.
struct HttpResult {
	int status = 0;
	std::string body;
	std::string error;

	bool Ok() const {
		return error.empty() && status >= 200 && status < 300;
	}
};

//! GET / form-POST against an http(s) URL. https needs a TLS-enabled build (the
//! flight build carries OpenSSL); without one it returns a transport error that
//! says so rather than silently downgrading.
HttpResult HttpGet(const std::string &url, int timeout_seconds = 10);
HttpResult HttpPostForm(const std::string &url, const std::map<std::string, std::string> &params,
                        int timeout_seconds = 30);

//! The issuer's endpoints, discovered or assembled by the caller.
struct Endpoints {
	std::string issuer;
	std::string token_endpoint;
	std::string device_authorization_endpoint; // may be empty: not every issuer offers RFC 8628
	std::string error;                         // non-empty when discovery failed

	bool Ok() const {
		return error.empty() && !token_endpoint.empty();
	}
};

//! GET `<issuer>/.well-known/openid-configuration` (RFC 8414). The advertised
//! issuer must equal the asked-for one — a mismatch is refused, not adopted.
Endpoints Discover(const std::string &issuer_url, int timeout_seconds = 10);

//! What a token endpoint answered. `error` carries the human-readable failure;
//! `error_code` the protocol's machine code (authorization_pending, slow_down,
//! invalid_grant, ...), empty on success.
struct TokenSet {
	std::string access_token;
	std::string refresh_token; // empty when the grant returns none
	int64_t expires_at = 0;    // epoch seconds; 0 = the response carried no expiry
	std::string error;
	std::string error_code;

	bool Ok() const {
		return error.empty() && !access_token.empty();
	}
};

//! grant_type=client_credentials — the machine identity flow.
TokenSet ClientCredentials(const Endpoints &ep, const std::string &client_id, const std::string &client_secret,
                           const std::string &scope = "");

//! grant_type=password — the resource-owner flow; only where the IdP and the
//! admin allow it (design/016: an admin-enabled row of the menu, never forced).
TokenSet PasswordGrant(const Endpoints &ep, const std::string &client_id, const std::string &client_secret,
                       const std::string &username, const std::string &password, const std::string &scope = "");

//! grant_type=refresh_token — silent renewal off a previous TokenSet.
TokenSet RefreshGrant(const Endpoints &ep, const std::string &client_id, const std::string &client_secret,
                      const std::string &refresh_token);

//! The device flow's first half (RFC 8628 §3.1-3.2): what to show the user.
struct DeviceAuthorization {
	std::string device_code;
	std::string user_code;
	std::string verification_uri;
	std::string verification_uri_complete; // may be empty
	int64_t interval = 5;                  // seconds between polls
	int64_t expires_in = 600;
	std::string error;

	bool Ok() const {
		return error.empty() && !device_code.empty();
	}
};

DeviceAuthorization DeviceBegin(const Endpoints &ep, const std::string &client_id, const std::string &scope = "");

//! The device flow's second half: poll until granted, denied, the deadline, or
//! the caller's own cancellation. Honours authorization_pending (wait
//! `interval`) and slow_down (+5s, §3.5); sleeps in one-second slices so a
//! cancellation (a query interrupt) is honoured promptly. `interval` of 0
//! polls without sleeping (tests); the poll never outlives
//! `deadline_epoch_seconds`.
TokenSet DevicePoll(const Endpoints &ep, const std::string &client_id, const std::string &device_code,
                    int64_t interval_seconds, int64_t deadline_epoch_seconds,
                    const std::function<bool()> &cancelled = nullptr);

//! The cache: keyed by an owner pointer (a DatabaseInstance, a provider, ...)
//! plus a caller-chosen key; a token is served only while it has more than
//! `margin_seconds` of life left, so a consumer never receives one about to
//! die mid-use. mssql-extension's TokenCache, generalised.
class TokenCache {
public:
	static TokenCache &Instance();

	//! The cached set, or an empty one when absent / inside the margin (a stale
	//! entry is erased on read).
	TokenSet Get(const void *owner, const std::string &key, int64_t margin_seconds = 300);
	void Set(const void *owner, const std::string &key, TokenSet set);
	void Invalidate(const void *owner, const std::string &key);
	void Clear();

private:
	std::mutex mutex;
	std::map<std::pair<const void *, std::string>, TokenSet> cache;
};

} // namespace oidc
} // namespace acl
} // namespace duckdb
