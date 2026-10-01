// Offline JWT verification (specs/007): parse + signature check (RS256/ES256/HS256) + time claims,
// with zero network IO - the keys are handed in (spec 095: discovery or a secret). Pure functions
// over the token text; routing, the client's judgement and role mapping stay with the PolicyStore.

#pragma once

#include "acl_policy.hpp"

namespace duckdb {
namespace acl {

//! A token whose signature and time claims hold (spec 095): what its client then judges
struct VerifiedJwt {
	string issuer;       // `iss`, as routed
	string payload_json; // the claims, read by the client through TokenClaims
	string token_type;   // the header's `typ`, for a client's TOKEN TYPE
	//! The token's `exp`, as seconds since the epoch. Verified here; kept so a session minted from
	//! this token can be refused once it passes, without holding the token itself (spec 040).
	int64_t expires_at = 0;
};

//! Structural check only: three base64url segments with a JSON header carrying an alg.
//! Returns the token's issuer so the caller can look up the config. Never throws.
bool LooksLikeJwt(const string &token, string &issuer_out);

//! The `kid` of the token's header, or empty when there is none (or the token is not parseable). Used
//! to decide whether a key set needs re-reading before the token is judged (spec 023).
string JwtKid(const string &token);

//! Whether a JWKS document contains a key with this id. A JWKS that is a bare PEM, or a token with no
//! kid, answers true: there is nothing to look up, so nothing is missing.
bool JwksHasKid(const string &keys_json, const string &kid);

//! spec 071: how many keys a document holds (a PEM counts one) and the `kid`s of those that have one,
//! in the document's order - the public names of the keys, never the keys
int64_t JwksKeyIds(const string &keys_json, vector<string> &kids);

//! The signature (per the issuer's algs and keys) and exp/nbf with skew. Throws BinderException
//! with a specific reason on any failure (the gateway is trusted to see diagnostics); a denial must
//! throw anyway (FALLBACK would silently re-parse). ignore_exp (spec 059, 'connect' binding): skip
//! only the expiry comparison - the claim must still be present, and signature/nbf are always
//! enforced. Used exclusively to re-verify the bearer of an ALREADY OPEN session. Audience, roles
//! and claims are the client's to judge (acl_identity).
VerifiedJwt VerifyJwtSignature(const string &token, const string &keys_json, const case_insensitive_set_t &algs,
                               int64_t clock_skew_seconds, bool ignore_exp = false);

} // namespace acl
} // namespace duckdb
