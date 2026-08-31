//===----------------------------------------------------------------------===//
// acl_oidc.cpp — the OIDC client core (spec 060). See acl_oidc.hpp.
//
// The one TU that compiles duckdb's bundled httplib for this module. With
// ACL_OIDC_TLS (the flight build, which carries OpenSSL through vcpkg) it is
// compiled with CPPHTTPLIB_OPENSSL_SUPPORT — the header then lives in the
// duckdb_httplib_openssl namespace, so there is no ODR overlap with the core's
// own plain compilation (the same single-TU discipline mssql-extension uses).
//===----------------------------------------------------------------------===//

#ifdef ACL_OIDC_TLS
#define CPPHTTPLIB_OPENSSL_SUPPORT
#endif
#include "httplib.hpp"

#include "acl_oidc.hpp"
#include "yyjson.hpp"

#include <thread>

#ifdef ACL_OIDC_TLS
namespace hl = duckdb_httplib_openssl;
#else
namespace hl = duckdb_httplib;
#endif

namespace duckdb {
namespace acl {
namespace oidc {

namespace {

int64_t NowSeconds() {
	return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
	    .count();
}

struct UrlParts {
	bool https = false;
	std::string host;
	int port = 0;
	std::string path;
	std::string error;
};

//! scheme://host[:port]/path — anything else is an error, never a guess.
UrlParts ParseUrl(const std::string &url) {
	UrlParts out;
	std::string rest;
	if (url.rfind("https://", 0) == 0) {
		out.https = true;
		rest = url.substr(8);
	} else if (url.rfind("http://", 0) == 0) {
		rest = url.substr(7);
	} else {
		out.error = "unsupported URL (http:// or https:// expected): " + url;
		return out;
	}
	auto slash = rest.find('/');
	auto authority = slash == std::string::npos ? rest : rest.substr(0, slash);
	out.path = slash == std::string::npos ? "/" : rest.substr(slash);
	auto default_port = out.https ? 443 : 80;
	std::string port_text;
	if (!authority.empty() && authority.front() == '[') { // [v6]:port - the colon comes after ']'
		auto bracket = authority.find(']');
		if (bracket == std::string::npos) {
			out.error = "malformed URL authority: " + url;
			return out;
		}
		out.host = authority.substr(1, bracket - 1);
		if (bracket + 1 < authority.size()) {
			if (authority[bracket + 1] != ':') {
				out.error = "malformed URL authority: " + url;
				return out;
			}
			port_text = authority.substr(bracket + 2);
		}
	} else {
		auto colon = authority.rfind(':');
		if (colon != std::string::npos) {
			out.host = authority.substr(0, colon);
			port_text = authority.substr(colon + 1);
		} else {
			out.host = authority;
		}
	}
	if (port_text.empty()) {
		out.port = default_port;
	} else {
		// digits only, and a port-sized value - "80xyz" must refuse, not silently become 80
		for (char c : port_text) {
			if (!isdigit(static_cast<unsigned char>(c))) {
				out.error = "malformed port in URL: " + url;
				return out;
			}
		}
		auto value = port_text.size() <= 5 ? std::atoi(port_text.c_str()) : 0;
		if (value <= 0 || value > 65535) {
			out.error = "malformed port in URL: " + url;
			return out;
		}
		out.port = value;
	}
	if (out.host.empty()) {
		out.error = "malformed URL authority: " + url;
	}
	return out;
}

std::string UrlEncode(const std::string &value) {
	static const char *hex = "0123456789ABCDEF";
	std::string out;
	out.reserve(value.size());
	for (unsigned char c : value) {
		if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
			out.push_back(char(c));
		} else {
			out.push_back('%');
			out.push_back(hex[c >> 4]);
			out.push_back(hex[c & 15]);
		}
	}
	return out;
}

std::string FormEncode(const std::map<std::string, std::string> &params) {
	std::string body;
	for (auto &entry : params) {
		if (!body.empty()) {
			body.push_back('&');
		}
		body += UrlEncode(entry.first) + "=" + UrlEncode(entry.second);
	}
	return body;
}

template <class REQUEST>
HttpResult Run(const UrlParts &url, int timeout_seconds, REQUEST &&request) {
	HttpResult out;
	if (!url.error.empty()) {
		out.error = url.error;
		return out;
	}
	if (url.https) {
#ifdef ACL_OIDC_TLS
		hl::SSLClient client(url.host, url.port);
		client.set_connection_timeout(timeout_seconds);
		client.set_read_timeout(timeout_seconds);
		client.enable_server_certificate_verification(true);
		auto res = request(client);
		if (!res) {
			out.error = "https request failed: " + hl::to_string(res.error());
			return out;
		}
		out.status = res->status;
		out.body = res->body;
		return out;
#else
		out.error = "https needs a TLS-enabled build (the flight build carries OpenSSL) - this build can "
		            "reach http:// issuers only";
		return out;
#endif
	}
	hl::Client client(url.host, url.port);
	client.set_connection_timeout(timeout_seconds);
	client.set_read_timeout(timeout_seconds);
	auto res = request(client);
	if (!res) {
		out.error = "http request failed: " + hl::to_string(res.error());
		return out;
	}
	out.status = res->status;
	out.body = res->body;
	return out;
}

//! yyjson helpers over one response body
struct Json {
	duckdb_yyjson::yyjson_doc *doc = nullptr;

	explicit Json(const std::string &body) {
		doc = duckdb_yyjson::yyjson_read(body.data(), body.size(), 0);
	}
	~Json() {
		if (doc) {
			duckdb_yyjson::yyjson_doc_free(doc);
		}
	}
	std::string Str(const char *key) const {
		if (!doc) {
			return "";
		}
		auto value = duckdb_yyjson::yyjson_obj_get(duckdb_yyjson::yyjson_doc_get_root(doc), key);
		if (!value || !duckdb_yyjson::yyjson_is_str(value)) {
			return "";
		}
		return duckdb_yyjson::yyjson_get_str(value);
	}
	int64_t Int(const char *key) const {
		if (!doc) {
			return 0;
		}
		auto value = duckdb_yyjson::yyjson_obj_get(duckdb_yyjson::yyjson_doc_get_root(doc), key);
		if (!value || !duckdb_yyjson::yyjson_is_num(value)) {
			return 0;
		}
		return duckdb_yyjson::yyjson_get_sint(value);
	}
};

//! Every token endpoint answer goes through here: 2xx with an access_token is a
//! grant; anything else is the protocol's error/error_description, or the raw
//! transport failure. Nothing is inferred.
TokenSet FromTokenResponse(const HttpResult &response) {
	TokenSet out;
	if (!response.error.empty()) {
		out.error = response.error;
		return out;
	}
	Json json(response.body);
	if (response.Ok()) {
		out.access_token = json.Str("access_token");
		out.refresh_token = json.Str("refresh_token");
		auto expires_in = json.Int("expires_in");
		if (expires_in > 366 * 86400) { // a year: past that the value is nonsense, and unclamped it
			expires_in = 366 * 86400;   // could overflow the epoch arithmetic (the review's finding)
		}
		out.expires_at = expires_in > 0 ? NowSeconds() + expires_in : 0;
		if (out.access_token.empty()) {
			out.error = "the token endpoint answered 2xx without an access_token";
		}
		return out;
	}
	out.error_code = json.Str("error");
	auto description = json.Str("error_description");
	out.error = out.error_code.empty() ? ("HTTP " + std::to_string(response.status) + " from the token endpoint")
	                                   : (out.error_code + (description.empty() ? "" : (": " + description)));
	return out;
}

TokenSet PostGrant(const Endpoints &ep, const std::map<std::string, std::string> &params) {
	if (!ep.Ok()) {
		TokenSet out;
		out.error = ep.error.empty() ? "no token endpoint" : ep.error;
		return out;
	}
	return FromTokenResponse(HttpPostForm(ep.token_endpoint, params));
}

} // namespace

HttpResult HttpGet(const std::string &url, int timeout_seconds) {
	auto parts = ParseUrl(url);
	return Run(parts, timeout_seconds, [&](auto &client) { return client.Get(parts.path.c_str()); });
}

HttpResult HttpPostForm(const std::string &url, const std::map<std::string, std::string> &params, int timeout_seconds) {
	auto parts = ParseUrl(url);
	auto body = FormEncode(params);
	return Run(parts, timeout_seconds, [&](auto &client) {
		return client.Post(parts.path.c_str(), body, "application/x-www-form-urlencoded");
	});
}

Endpoints Discover(const std::string &issuer_url, int timeout_seconds) {
	Endpoints out;
	auto issuer = issuer_url;
	while (!issuer.empty() && issuer.back() == '/') {
		issuer.pop_back();
	}
	out.issuer = issuer;
	auto response = HttpGet(issuer + "/.well-known/openid-configuration", timeout_seconds);
	if (!response.Ok()) {
		out.error =
		    response.error.empty() ? ("discovery answered HTTP " + std::to_string(response.status)) : response.error;
		return out;
	}
	Json json(response.body);
	auto advertised = json.Str("issuer");
	// normalised exactly like the asked-for issuer: some IdPs canonically end in '/' (Azure AD v1)
	while (!advertised.empty() && advertised.back() == '/') {
		advertised.pop_back();
	}
	// RFC 8414: the document must speak for the issuer it was asked about — adopting a different one
	// would let a compromised document redirect every flow
	if (advertised != issuer) {
		out.error = "discovery issuer mismatch: asked \"" + issuer + "\", document says \"" + advertised + "\"";
		return out;
	}
	out.token_endpoint = json.Str("token_endpoint");
	out.device_authorization_endpoint = json.Str("device_authorization_endpoint");
	if (out.token_endpoint.empty()) {
		out.error = "discovery document carries no token_endpoint";
		return out;
	}
	// an https issuer whose document names a cleartext endpoint is a downgrade: the credentials the
	// flows POST must not travel weaker than the discovery did (the review's finding)
	if (issuer.rfind("https://", 0) == 0) {
		for (const auto *endpoint : {&out.token_endpoint, &out.device_authorization_endpoint}) {
			if (!endpoint->empty() && endpoint->rfind("https://", 0) != 0) {
				out.error = "discovery names a cleartext endpoint for an https issuer - refused: " + *endpoint;
				return out;
			}
		}
	}
	return out;
}

TokenSet ClientCredentials(const Endpoints &ep, const std::string &client_id, const std::string &client_secret,
                           const std::string &scope) {
	std::map<std::string, std::string> params {
	    {"grant_type", "client_credentials"}, {"client_id", client_id}, {"client_secret", client_secret}};
	if (!scope.empty()) {
		params["scope"] = scope;
	}
	return PostGrant(ep, params);
}

TokenSet PasswordGrant(const Endpoints &ep, const std::string &client_id, const std::string &client_secret,
                       const std::string &username, const std::string &password, const std::string &scope) {
	std::map<std::string, std::string> params {
	    {"grant_type", "password"}, {"client_id", client_id}, {"username", username}, {"password", password}};
	if (!client_secret.empty()) {
		params["client_secret"] = client_secret;
	}
	if (!scope.empty()) {
		params["scope"] = scope;
	}
	return PostGrant(ep, params);
}

TokenSet RefreshGrant(const Endpoints &ep, const std::string &client_id, const std::string &client_secret,
                      const std::string &refresh_token) {
	std::map<std::string, std::string> params {
	    {"grant_type", "refresh_token"}, {"client_id", client_id}, {"refresh_token", refresh_token}};
	if (!client_secret.empty()) {
		params["client_secret"] = client_secret;
	}
	return PostGrant(ep, params);
}

DeviceAuthorization DeviceBegin(const Endpoints &ep, const std::string &client_id, const std::string &scope) {
	DeviceAuthorization out;
	if (!ep.Ok()) {
		out.error = ep.error.empty() ? "no endpoints" : ep.error;
		return out;
	}
	if (ep.device_authorization_endpoint.empty()) {
		out.error = "the issuer advertises no device_authorization_endpoint (RFC 8628 not offered)";
		return out;
	}
	std::map<std::string, std::string> params {{"client_id", client_id}};
	if (!scope.empty()) {
		params["scope"] = scope;
	}
	auto response = HttpPostForm(ep.device_authorization_endpoint, params);
	if (!response.Ok()) {
		Json json(response.body);
		auto code = json.Str("error");
		out.error = !response.error.empty() ? response.error
		            : code.empty()          ? ("HTTP " + std::to_string(response.status))
		                                    : (code + ": " + json.Str("error_description"));
		return out;
	}
	Json json(response.body);
	out.device_code = json.Str("device_code");
	out.user_code = json.Str("user_code");
	out.verification_uri = json.Str("verification_uri");
	out.verification_uri_complete = json.Str("verification_uri_complete");
	auto interval = json.Int("interval");
	if (interval > 0) {
		out.interval = interval > 900 ? 900 : interval; // a malicious interval must not become a sleep
	}
	auto expires_in = json.Int("expires_in");
	if (expires_in > 0) {
		out.expires_in = expires_in > 86400 ? 86400 : expires_in;
	}
	if (out.device_code.empty()) {
		out.error = "device authorization answered without a device_code";
	}
	return out;
}

TokenSet DevicePoll(const Endpoints &ep, const std::string &client_id, const std::string &device_code,
                    int64_t interval_seconds, int64_t deadline_epoch_seconds) {
	auto interval = interval_seconds < 0 ? 0 : interval_seconds;
	while (true) {
		auto result = PostGrant(ep, {{"grant_type", "urn:ietf:params:oauth:grant-type:device_code"},
		                             {"client_id", client_id},
		                             {"device_code", device_code}});
		if (result.Ok()) {
			return result;
		}
		if (result.error_code == "slow_down") {
			interval = interval + 5 > 3600 ? 3600 : interval + 5; // RFC 8628 §3.5, bounded
		} else if (result.error_code != "authorization_pending") {
			return result; // denied, expired, transport - the caller's to report
		}
		// subtraction, not addition: a hostile interval must not overflow the guard into an
		// unbounded sleep (the review's finding) - the promise is that the poll never outlives
		// the deadline, whatever the server answers
		if (interval >= deadline_epoch_seconds - NowSeconds()) {
			result.error = "device flow timed out before the user approved";
			result.error_code = "expired_token";
			return result;
		}
		if (interval > 0) {
			std::this_thread::sleep_for(std::chrono::seconds(interval));
		}
	}
}

TokenCache &TokenCache::Instance() {
	static TokenCache instance;
	return instance;
}

TokenSet TokenCache::Get(const void *owner, const std::string &key, int64_t margin_seconds) {
	std::lock_guard<std::mutex> guard(mutex);
	auto entry = cache.find({owner, key});
	if (entry == cache.end()) {
		return TokenSet();
	}
	// 0 = the response carried no expiry: cached until invalidated, the caller opted into that
	if (entry->second.expires_at != 0 && entry->second.expires_at - margin_seconds <= NowSeconds()) {
		cache.erase(entry); // stale rows must not pile up for the process lifetime
		return TokenSet();
	}
	return entry->second;
}

void TokenCache::Set(const void *owner, const std::string &key, TokenSet set) {
	std::lock_guard<std::mutex> guard(mutex);
	cache[{owner, key}] = std::move(set);
}

void TokenCache::Invalidate(const void *owner, const std::string &key) {
	std::lock_guard<std::mutex> guard(mutex);
	cache.erase({owner, key});
}

void TokenCache::Clear() {
	std::lock_guard<std::mutex> guard(mutex);
	cache.clear();
}

} // namespace oidc
} // namespace acl
} // namespace duckdb
