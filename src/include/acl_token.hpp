// Offline JWT verification (specs/007): parse + signature check (RS256/ES256/HS256) + standard
// claims, with zero network IO - keys arrive in the issuer config (JWKS or PEM), rotated by the
// gateway/admin. Pure functions over the token text; issuer lookup and role mapping stay with the
// PolicyStore, which owns the memory/catalog backends.

#pragma once

#include "acl_policy.hpp"

namespace duckdb {
namespace acl {

//! The outcome of parsing + verifying one JWT against its issuer config
struct JwtClaims {
	string issuer;
	vector<string> raw_roles;              // values of the role claim, before mapping
	case_insensitive_map_t<string> claims; // extracted via claim_map
	bool groups_overage = false;           // EntraID groups overage marker present
};

//! Structural check only: three base64url segments with a JSON header carrying an alg.
//! Returns the token's issuer so the caller can look up the config. Never throws.
bool LooksLikeJwt(const string &token, string &issuer_out);

//! Full verification: signature (per the issuer's alg/keys), exp/nbf with skew, audience, role and
//! claim extraction. Throws BinderException with a specific reason on any failure (the gateway is
//! trusted to see diagnostics); a denial must throw anyway (FALLBACK would silently re-parse).
JwtClaims VerifyJwt(const string &token, const IssuerConfig &config, int64_t clock_skew_seconds);

} // namespace acl
} // namespace duckdb
