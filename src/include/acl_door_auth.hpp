//===----------------------------------------------------------------------===//
// acl_door_auth.hpp — the one auth-discovery document both doors serve (spec 064)
//
// The Flight door answers it to the Handshake payload `discover-auth`; the quack
// door serves it as GET /.well-known/quack-auth. One composer, so a client reads
// the same facts whichever door it asked: the issuers the node trusts, each
// issuer's OAuth client_id, and the endpoints the IdP's own OIDC discovery names.
//===----------------------------------------------------------------------===//
#pragma once

#include "acl_policy.hpp"
#include "acl_oidc.hpp"

namespace duckdb {
namespace acl {

//! An issuer's OIDC endpoints through a process-wide TTL cache: public metadata keyed by issuer
//! URL, so instances sharing a process share it safely. 300 s; a failed read 30 s — discovery
//! answers unauthenticated callers, and a dead IdP must not turn every probe into a network wait.
oidc::Endpoints DiscoverEndpointsCached(const string &issuer);

//! The discovery document: {"issuers":[{"issuer":…,"client_id":…,"token_endpoint":…,
//! "device_authorization_endpoint":…}]}. client_id is included (a public identifier); the
//! client_secret never is. An issuer whose IdP cannot be reached is still named, endpoint-less.
string DoorAuthJson(PolicyStore &store);

} // namespace acl
} // namespace duckdb
