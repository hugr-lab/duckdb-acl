// Offline JWT verification (specs/007). Crypto comes from duckdb's bundled mbedtls (RSA-PKCS1v15 +
// SHA-256 + HMAC) plus the vendored p256-m for ES256 - the trimmed mbedtls carries no ECDSA, and
// JOSE's raw r||s signatures / JWKS x||y keys are exactly p256-m's API, so no ASN.1 is involved.
// JSON via duckdb's bundled yyjson. No network IO anywhere: keys live in the issuer config.

#include "acl_token.hpp"

#include "duckdb/common/exception/binder_exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "mbedtls/base64.h"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
#include "mbedtls/sha256.h"
#include "p256-m.h"
#include "yyjson.hpp"

#include <chrono>
#include <cstring>

// p256-m declares an RNG hook for its keygen/sign paths; verification never draws from it, but the
// symbol must exist at link time. Fail closed if anything ever calls it.
extern "C" int p256_generate_random(uint8_t *, unsigned) {
	return -1;
}

namespace duckdb {
namespace acl {
namespace {

using duckdb_yyjson::yyjson_doc;
using duckdb_yyjson::yyjson_val;

[[noreturn]] void Reject(const string &reason) {
	throw BinderException("acl_rewrite: token rejected: %s", reason);
}

//! RAII over a yyjson document
struct JsonDoc {
	explicit JsonDoc(const string &text) : doc(duckdb_yyjson::yyjson_read(text.c_str(), text.size(), 0)) {
	}
	~JsonDoc() {
		if (doc) {
			duckdb_yyjson::yyjson_doc_free(doc);
		}
	}
	yyjson_val *Root() const {
		return doc ? duckdb_yyjson::yyjson_doc_get_root(doc) : nullptr;
	}
	yyjson_doc *doc;
};

bool Base64UrlDecode(const string &input, vector<uint8_t> &out) {
	string translated = input;
	for (auto &c : translated) {
		if (c == '-') {
			c = '+';
		} else if (c == '_') {
			c = '/';
		}
	}
	while (translated.size() % 4 != 0) {
		translated += '=';
	}
	out.resize(translated.size());
	size_t written = 0;
	if (mbedtls_base64_decode(out.data(), out.size(), &written,
	                          reinterpret_cast<const unsigned char *>(translated.c_str()), translated.size()) != 0) {
		return false;
	}
	out.resize(written);
	return true;
}

string JsonString(yyjson_val *value) {
	if (!value) {
		return string();
	}
	if (duckdb_yyjson::yyjson_is_str(value)) {
		return duckdb_yyjson::yyjson_get_str(value);
	}
	if (duckdb_yyjson::yyjson_is_int(value)) {
		return std::to_string(duckdb_yyjson::yyjson_get_sint(value));
	}
	if (duckdb_yyjson::yyjson_is_real(value)) {
		return std::to_string(duckdb_yyjson::yyjson_get_real(value));
	}
	if (duckdb_yyjson::yyjson_is_bool(value)) {
		return duckdb_yyjson::yyjson_get_bool(value) ? "true" : "false";
	}
	return string();
}

//! Walk a dot path ("realm_access.roles") into a JSON object
yyjson_val *JsonPath(yyjson_val *root, const string &path) {
	auto value = root;
	for (auto &part : StringUtil::Split(path, '.')) {
		if (!value || !duckdb_yyjson::yyjson_is_obj(value)) {
			return nullptr;
		}
		value = duckdb_yyjson::yyjson_obj_getn(value, part.c_str(), part.size());
	}
	return value;
}

struct ParsedJwt {
	string signing_input; // header.payload, the signed bytes
	vector<uint8_t> signature;
	string header_json;
	string payload_json;
};

bool SplitJwt(const string &token, ParsedJwt &out) {
	auto first = token.find('.');
	auto second = first == string::npos ? string::npos : token.find('.', first + 1);
	if (second == string::npos || token.find('.', second + 1) != string::npos) {
		return false;
	}
	vector<uint8_t> header, payload;
	if (!Base64UrlDecode(token.substr(0, first), header) ||
	    !Base64UrlDecode(token.substr(first + 1, second - first - 1), payload) ||
	    !Base64UrlDecode(token.substr(second + 1), out.signature)) {
		return false;
	}
	out.signing_input = token.substr(0, second);
	out.header_json = string(header.begin(), header.end());
	out.payload_json = string(payload.begin(), payload.end());
	return true;
}

//! Find the JWKS key entry to verify with: the one whose kid the token names, or - when it names none
//! - the only signing key of the right kty. Returns nullptr when there is no such key, or when the
//! config is a PEM rather than a JWKS.
//!
//! A key marked for encryption is skipped: RFC 7517 says `use` states what a key is for, and a real
//! JWKS carries both (a Keycloak realm publishes an RSA-OAEP key beside its RS256 one). And a kid that
//! matches nothing is an error rather than a reason to try another key: during a rotation that is the
//! difference between "no key with id X" and a misleading "signature verification failed".
yyjson_val *SelectJwk(yyjson_val *keys_root, const string &kid, const char *kty) {
	if (!keys_root || !duckdb_yyjson::yyjson_is_obj(keys_root)) {
		return nullptr;
	}
	auto keys = duckdb_yyjson::yyjson_obj_get(keys_root, "keys");
	if (!keys || !duckdb_yyjson::yyjson_is_arr(keys)) {
		return nullptr;
	}
	yyjson_val *only_signing = nullptr;
	idx_t signing_count = 0;
	duckdb_yyjson::yyjson_arr_iter iter;
	duckdb_yyjson::yyjson_arr_iter_init(keys, &iter);
	while (auto key = duckdb_yyjson::yyjson_arr_iter_next(&iter)) {
		auto entry_kty = JsonString(duckdb_yyjson::yyjson_obj_get(key, "kty"));
		if (entry_kty != kty) {
			continue;
		}
		auto use = JsonString(duckdb_yyjson::yyjson_obj_get(key, "use"));
		if (!use.empty() && use != "sig") {
			continue;
		}
		auto entry_kid = JsonString(duckdb_yyjson::yyjson_obj_get(key, "kid"));
		if (!kid.empty()) {
			if (entry_kid == kid) {
				return key;
			}
			continue;
		}
		only_signing = key;
		signing_count++;
	}
	return signing_count == 1 ? only_signing : nullptr;
}

vector<uint8_t> Sha256(const string &input) {
	vector<uint8_t> hash(32);
	if (mbedtls_sha256(reinterpret_cast<const unsigned char *>(input.c_str()), input.size(), hash.data(), 0) != 0) {
		Reject("hashing failed");
	}
	return hash;
}

bool ConstantTimeEquals(const vector<uint8_t> &a, const vector<uint8_t> &b) {
	if (a.size() != b.size()) {
		return false;
	}
	unsigned char diff = 0;
	for (idx_t i = 0; i < a.size(); i++) {
		diff |= a[i] ^ b[i];
	}
	return diff == 0;
}

void VerifyRs256(const ParsedJwt &jwt, const IssuerConfig &config, const string &kid, JsonDoc &keys) {
	auto hash = Sha256(jwt.signing_input);
	mbedtls_pk_context pk;
	mbedtls_pk_init(&pk);
	bool key_ready = false;
	auto trimmed = config.keys_json;
	StringUtil::Trim(trimmed);
	if (StringUtil::StartsWith(trimmed, "-----BEGIN")) {
		// PEM public key: mbedtls parses it (the buffer must include the NUL terminator)
		key_ready = mbedtls_pk_parse_public_key(&pk, reinterpret_cast<const unsigned char *>(trimmed.c_str()),
		                                        trimmed.size() + 1) == 0;
	} else if (auto jwk = SelectJwk(keys.Root(), kid, "RSA")) {
		// JWKS n/e: import the raw big-endian integers
		vector<uint8_t> n, e;
		if (!Base64UrlDecode(JsonString(duckdb_yyjson::yyjson_obj_get(jwk, "n")), n) ||
		    !Base64UrlDecode(JsonString(duckdb_yyjson::yyjson_obj_get(jwk, "e")), e)) {
			mbedtls_pk_free(&pk);
			Reject("malformed RSA JWK");
		}
		key_ready = mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) == 0 &&
		            mbedtls_rsa_import_raw(mbedtls_pk_rsa(pk), n.data(), n.size(), nullptr, 0, nullptr, 0, nullptr, 0,
		                                   e.data(), e.size()) == 0 &&
		            mbedtls_rsa_complete(mbedtls_pk_rsa(pk)) == 0;
	}
	if (!key_ready) {
		mbedtls_pk_free(&pk);
		Reject("no usable RS256 key for this issuer");
	}
	auto ok = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash.data(), hash.size(), jwt.signature.data(),
	                            jwt.signature.size()) == 0;
	mbedtls_pk_free(&pk);
	if (!ok) {
		Reject("signature verification failed");
	}
}

void VerifyEs256(const ParsedJwt &jwt, const string &kid, JsonDoc &keys) {
	auto jwk = SelectJwk(keys.Root(), kid, "EC");
	if (!jwk) {
		Reject("no usable ES256 key for this issuer");
	}
	vector<uint8_t> x, y;
	if (!Base64UrlDecode(JsonString(duckdb_yyjson::yyjson_obj_get(jwk, "x")), x) ||
	    !Base64UrlDecode(JsonString(duckdb_yyjson::yyjson_obj_get(jwk, "y")), y) || x.size() != 32 || y.size() != 32) {
		Reject("malformed EC JWK");
	}
	if (jwt.signature.size() != 64) {
		Reject("malformed ES256 signature");
	}
	uint8_t pub[64];
	std::memcpy(pub, x.data(), 32);
	std::memcpy(pub + 32, y.data(), 32);
	auto hash = Sha256(jwt.signing_input);
	if (p256_ecdsa_verify(jwt.signature.data(), pub, hash.data(), hash.size()) != 0) {
		Reject("signature verification failed");
	}
}

void VerifyHs256(const ParsedJwt &jwt, const string &kid, JsonDoc &keys) {
	auto jwk = SelectJwk(keys.Root(), kid, "oct");
	if (!jwk) {
		Reject("no usable HS256 key for this issuer");
	}
	vector<uint8_t> secret;
	if (!Base64UrlDecode(JsonString(duckdb_yyjson::yyjson_obj_get(jwk, "k")), secret) || secret.empty()) {
		Reject("malformed oct JWK");
	}
	vector<uint8_t> mac(32);
	auto info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	if (!info || mbedtls_md_hmac(info, secret.data(), secret.size(),
	                             reinterpret_cast<const unsigned char *>(jwt.signing_input.c_str()),
	                             jwt.signing_input.size(), mac.data()) != 0) {
		Reject("hmac failed");
	}
	if (!ConstantTimeEquals(mac, jwt.signature)) {
		Reject("signature verification failed");
	}
}

} // namespace

bool LooksLikeJwt(const string &token, string &issuer_out) {
	ParsedJwt jwt;
	if (!SplitJwt(token, jwt)) {
		return false;
	}
	JsonDoc header(jwt.header_json);
	JsonDoc payload(jwt.payload_json);
	if (!header.Root() || !payload.Root() || JsonString(duckdb_yyjson::yyjson_obj_get(header.Root(), "alg")).empty()) {
		return false;
	}
	issuer_out = JsonString(duckdb_yyjson::yyjson_obj_get(payload.Root(), "iss"));
	return true;
}

string JwtKid(const string &token) {
	ParsedJwt jwt;
	if (!SplitJwt(token, jwt)) {
		return string();
	}
	JsonDoc header(jwt.header_json);
	if (!header.Root()) {
		return string();
	}
	return JsonString(duckdb_yyjson::yyjson_obj_get(header.Root(), "kid"));
}

bool JwksHasKid(const string &keys_json, const string &kid) {
	if (kid.empty()) {
		return true;
	}
	JsonDoc keys(keys_json);
	if (!keys.Root()) {
		return true; // not a JWKS (a PEM, or unparseable): the verifier will say so, not the cache
	}
	auto array = duckdb_yyjson::yyjson_obj_get(keys.Root(), "keys");
	if (!array || !duckdb_yyjson::yyjson_is_arr(array)) {
		return true;
	}
	duckdb_yyjson::yyjson_val *key;
	duckdb_yyjson::yyjson_arr_iter iter;
	duckdb_yyjson::yyjson_arr_iter_init(array, &iter);
	while ((key = duckdb_yyjson::yyjson_arr_iter_next(&iter))) {
		if (JsonString(duckdb_yyjson::yyjson_obj_get(key, "kid")) == kid) {
			return true;
		}
	}
	return false;
}

JwtClaims VerifyJwt(const string &token, const IssuerConfig &config, int64_t clock_skew_seconds) {
	ParsedJwt jwt;
	if (!SplitJwt(token, jwt)) {
		Reject("not a JWT");
	}
	JsonDoc header(jwt.header_json);
	JsonDoc payload(jwt.payload_json);
	if (!header.Root() || !payload.Root()) {
		Reject("malformed JWT JSON");
	}

	// the alg allowlist decides how the signature is checked; anything else (incl. "none") is refused
	auto alg = JsonString(duckdb_yyjson::yyjson_obj_get(header.Root(), "alg"));
	auto kid = JsonString(duckdb_yyjson::yyjson_obj_get(header.Root(), "kid"));
	if (!config.algs.count(alg)) {
		Reject("algorithm \"" + alg + "\" is not allowed for this issuer");
	}
	JsonDoc keys(config.keys_json);
	if (alg == "RS256") {
		VerifyRs256(jwt, config, kid, keys);
	} else if (alg == "ES256") {
		VerifyEs256(jwt, kid, keys);
	} else if (alg == "HS256") {
		VerifyHs256(jwt, kid, keys);
	} else {
		Reject("unsupported algorithm \"" + alg + "\"");
	}

	// standard time claims, with the configured skew
	auto now =
	    std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
	auto exp = duckdb_yyjson::yyjson_obj_get(payload.Root(), "exp");
	if (!exp || !duckdb_yyjson::yyjson_is_num(exp)) {
		Reject("missing exp claim");
	}
	auto expires_at = duckdb_yyjson::yyjson_get_sint(exp);
	if (expires_at + clock_skew_seconds < now) {
		Reject("token expired");
	}
	auto nbf = duckdb_yyjson::yyjson_obj_get(payload.Root(), "nbf");
	if (nbf && duckdb_yyjson::yyjson_is_num(nbf) && duckdb_yyjson::yyjson_get_sint(nbf) - clock_skew_seconds > now) {
		Reject("token not yet valid");
	}

	// audience: the token's aud (string or array) must intersect the issuer's allowlist; a single '*'
	// entry means the issuer deliberately accepts any audience
	bool any_audience = config.audiences.size() == 1 && config.audiences[0] == "*";
	if (!config.audiences.empty() && !any_audience) {
		auto aud = duckdb_yyjson::yyjson_obj_get(payload.Root(), "aud");
		bool matched = false;
		auto check = [&](const string &value) {
			for (auto &allowed : config.audiences) {
				if (value == allowed) {
					matched = true;
				}
			}
		};
		if (aud && duckdb_yyjson::yyjson_is_arr(aud)) {
			duckdb_yyjson::yyjson_arr_iter iter;
			duckdb_yyjson::yyjson_arr_iter_init(aud, &iter);
			while (auto item = duckdb_yyjson::yyjson_arr_iter_next(&iter)) {
				check(JsonString(item));
			}
		} else {
			check(JsonString(aud));
		}
		if (!matched) {
			Reject("audience not accepted");
		}
	}

	JwtClaims result;
	// kept so a session minted from this token can be refused once it passes (spec 040)
	result.expires_at = expires_at;
	result.issuer = config.issuer;

	// the roles claim: a string or an array of strings at the configured dot path
	auto roles = JsonPath(payload.Root(), config.role_claim.empty() ? "roles" : config.role_claim);
	if (roles && duckdb_yyjson::yyjson_is_arr(roles)) {
		duckdb_yyjson::yyjson_arr_iter iter;
		duckdb_yyjson::yyjson_arr_iter_init(roles, &iter);
		while (auto item = duckdb_yyjson::yyjson_arr_iter_next(&iter)) {
			auto value = JsonString(item);
			if (!value.empty()) {
				result.raw_roles.push_back(value);
			}
		}
	} else if (roles) {
		auto value = JsonString(roles);
		if (!value.empty()) {
			result.raw_roles.push_back(value);
		}
	}

	// EntraID groups overage: the groups claim is replaced by a Graph link the extension cannot
	// follow (offline by design) - refuse loudly; resolving via Graph is the gateway's job
	auto claim_names = duckdb_yyjson::yyjson_obj_get(payload.Root(), "_claim_names");
	if (claim_names && duckdb_yyjson::yyjson_obj_get(claim_names, "groups")) {
		result.groups_overage = true;
	}

	// extra claims for acl_claim(): {"<jwt dot path>": "<claim name>"}
	if (!config.claim_map.empty()) {
		JsonDoc map_doc(config.claim_map);
		if (!map_doc.Root() || !duckdb_yyjson::yyjson_is_obj(map_doc.Root())) {
			Reject("issuer claim_map is not a JSON object");
		}
		duckdb_yyjson::yyjson_obj_iter iter;
		duckdb_yyjson::yyjson_obj_iter_init(map_doc.Root(), &iter);
		while (auto key = duckdb_yyjson::yyjson_obj_iter_next(&iter)) {
			auto path = JsonString(key);
			auto target = JsonString(duckdb_yyjson::yyjson_obj_iter_get_val(key));
			auto value = JsonPath(payload.Root(), path);
			if (value && !target.empty()) {
				result.claims[target] = JsonString(value);
			}
		}
	}
	return result;
}

} // namespace acl
} // namespace duckdb
