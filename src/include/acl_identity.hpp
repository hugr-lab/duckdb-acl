// Who a token is (spec 095): the trust anchor (ISSUER), what of its tokens counts and how to read them
// (CLIENT), and which raw values become which roles (scoped role mappings). Pure model and decisions -
// no store, no source, no network - so one implementation serves the memory map, the catalog tables
// and the function driver, and the routing can be simulated exhaustively (test/cpp).

#pragma once

#include "duckdb/common/case_insensitive_map.hpp"
#include "duckdb/common/common.hpp"

#include <functional>

namespace duckdb {
namespace acl {

//! The trust anchor: a token's `iss` routes to it by URL; its keys come from discovery or a secret
struct IdentityIssuer {
	string name;
	string url;            // empty = the URL is in its secret
	string secret_service; // the tresor catalog the secret lives in (resolved at write)
	string secret;         // an `oidc_issuer` secret: URL, KEYS, KEYS_FROM, ALGS
};

//! One condition of a client's REQUIRE: all of a client's must hold
struct ClaimCondition {
	enum class Op : uint8_t { EQUALS, ONE_OF, CONTAINS, LIKE }; // not EQ/IN: windows.h defines IN
	string path;
	Op op = Op::EQUALS;
	vector<string> values; // EQ / CONTAINS / LIKE: one; IN: the list
};

//! One attribute a principal carries for RLS (`acl_claim('name')`): the first present path, or a
//! constant the token cannot override
struct AttributeDef {
	string name;
	vector<string> paths;
	bool is_constant = false;
	string constant;
};

//! Which tokens of an issuer count, and what they become
struct IdentityClient {
	string name;
	string issuer;
	vector<string> audiences; // empty = in its secret
	vector<string> azp;
	vector<ClaimCondition> conditions; // REQUIRE
	vector<string> roles_from;
	vector<string> roles_constant;
	bool unmapped_as_role = false;
	vector<AttributeDef> attributes;
	vector<string> subject; // empty = "sub"
	string token_type;
	string client_id; // empty = in its secret, or none
	vector<string> flows;
	string secret_service;
	string secret; // an `oidc_client` secret: AUDIENCES, CLIENT_ID, CLIENT_SECRET
	bool implicit = false;
};

//! A raw value of a client's (or every client of an issuer's) role claims, mapped to a role
struct IdentityMapping {
	string scope_kind; // "client" | "issuer"
	string scope_name;
	string source; // "group" | "claim-value"
	string external_value;
	string role;
};

struct IdentityModel {
	vector<IdentityIssuer> issuers;
	vector<IdentityClient> clients;
	vector<IdentityMapping> mappings;

	optional_ptr<const IdentityIssuer> Issuer(const string &name) const;
	optional_ptr<const IdentityClient> Client(const string &name) const;
};

//! The flows a client may name, and which of them a driver runs (and discovery therefore lists)
bool IsKnownFlow(const string &flow);
bool IsDriverFlow(const string &flow);

//! The issuer's discovery document location: `<url>/.well-known/openid-configuration`
string DiscoveryLocation(const string &url);

// --- the stored shapes ---------------------------------------------------------------------------

//! A stored list: a JSON array of strings, or (the v16 shape a migrated catalog carries) a csv
vector<string> ParseStoredList(const string &text);
string StoredList(const vector<string> &values);
//! A stored attribute list: a JSON array of {"name","paths"|"constant"}, or the v16 claim map
//! {"<jwt path>": "<name>"}
vector<AttributeDef> ParseStoredAttributes(const string &text);
string StoredAttributes(const vector<AttributeDef> &attributes);
vector<ClaimCondition> ParseStoredConditions(const string &text);
string StoredConditions(const vector<ClaimCondition> &conditions);

//! Apply a client spec (the JSON the SQL forms compile to) onto `client`: every key present sets
//! its field, a JSON null clears it. Unknown keys and malformed values throw.
void ApplyClientSpec(IdentityClient &client, const string &spec_json, case_insensitive_set_t *written = nullptr);
//! Apply an issuer spec ({"url", "secret", "service"}; "client" is the caller's) onto `issuer`
void ApplyIssuerSpec(IdentityIssuer &issuer, const string &spec_json, string &client_spec_json);

// --- judging a token -----------------------------------------------------------------------------

//! A verified token's payload, read by claim path. A path is first looked up as one key (a claim
//! named like a URL has dots of its own), then walked as a dot path.
class TokenClaims {
public:
	explicit TokenClaims(const string &payload_json);
	~TokenClaims();
	TokenClaims(const TokenClaims &) = delete;
	TokenClaims &operator=(const TokenClaims &) = delete;

	bool Valid() const;
	bool Present(const string &path) const;
	//! The values at a path: a string, a number or a bool as text, or every such item of an array
	vector<string> Strings(const string &path) const;
	//! The first present path's value, as text ("" when none is present)
	string First(const vector<string> &paths) const;
	//! The token's audiences (a string or an array)
	vector<string> Audiences() const;
	//! `azp`, else - for an Entra v1 token (`ver` 1.0) only - its `appid`
	string AuthorizedParty() const;
	//! An EntraID groups overage marker: `_claim_names.groups`
	bool GroupsOverage() const;

private:
	void *doc;
};

//! SQL LIKE over a value: `%` any run, `_` one character, no escape
bool LikeMatches(const string &value, const string &pattern);

//! Whether a client accepts this token: `audiences` are the client's resolved ones (its own or its
//! secret's); `why` says what refused it
bool ClientAccepts(const IdentityClient &client, const vector<string> &audiences, const TokenClaims &claims,
                   const string &token_type, string &why);

//! How specific a client is: 2 with AZP or REQUIRE, 1 explicit without either, 0 implicit
int ClientSpecificity(const IdentityClient &client);

//! The routing decision (spec 095 §3): among the accepting candidates (their specificities), the
//! index of the one most specific, or -1 with `ambiguous` set when two tie at the top (and -1 with it
//! clear when there are none)
int64_t PickClient(const vector<int> &specificities, bool &ambiguous);

//! What a client makes of a token: its roles and attributes. `known_role` says whether a role
//! exists (for UNMAPPED AS ROLE); `privileged` whether a role holds an administration scope.
struct ClientRoles {
	vector<string> roles;
	vector<string> dropped_privileged; // reached other than through the client's own mapping
};
ClientRoles RolesFor(const IdentityModel &model, const IdentityClient &client, const TokenClaims &claims,
                     const std::function<bool(const string &)> &known_role,
                     const std::function<bool(const string &)> &privileged);
case_insensitive_map_t<string> AttributesFor(const IdentityClient &client, const TokenClaims &claims);
string SubjectFor(const IdentityClient &client, const TokenClaims &claims);

// --- writing -------------------------------------------------------------------------------------

//! What a write is checked against beyond the model itself: a secret's fields (empty map + false
//! when there is no such secret of that type), and whether a role is privileged
struct IdentityCheckContext {
	std::function<bool(const string &service, const string &name, const string &type,
	                   case_insensitive_map_t<string> &fields)>
	    read_secret;
	std::function<bool(const string &role)> privileged;
	//! Whether the write changed this object ("issuer" | "client", name). A secret is read for the
	//! objects the write touched only: a service that is down must not refuse an unrelated write, and
	//! what a secret says of an untouched object is judged where it is used. Unset = every object.
	std::function<bool(const string &kind, const string &name)> touched;
};

//! The whole model as it would be after a write: names, one home per parameter, URLs unique,
//! audiences present, overlaps that are visible statically, privileged roles only through a client's
//! own mapping. Throws BinderException naming what to change.
void ValidateIdentity(const IdentityModel &model, const IdentityCheckContext &context);

} // namespace acl
} // namespace duckdb
