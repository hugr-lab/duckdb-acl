//===----------------------------------------------------------------------===//
// acl_quack_embed.hpp — the embedded quack door (spec 063, design/016 A2)
//
// quack's server, compiled INTO acl rather than reached through a loopback proxy
// (the spec-062 front this replaces). The protocol machinery is quack's own,
// unchanged (third_party/quack); only the listener is acl-owned (AclQuackServer):
// it binds the PUBLIC address, terminates TLS itself, and answers the
// unauthenticated `/.well-known/quack-auth` discovery document. Everything acl
// registers here is `acl_quack_*`-named, so a standalone quack loaded alongside
// never collides (spec 063, Strategy B).
//
// This is the module's one seam, mirroring src/flight/: two registrations, called
// once at extension load. The server object graph, httplib and the serve/stop API
// (acl_quack_server.hpp) stay inside src/quack_embed/.
//===----------------------------------------------------------------------===//

#pragma once

#include "acl_policy.hpp"

namespace duckdb {

class ExtensionLoader;
class Connection;
class MaterializedQueryResult;

namespace acl {

//! Register the embedded server's SQL surface: the acl_quack_* server settings the embedded graph
//! reads, and the acl_quack_scan_data drain table function.
void RegisterAclQuackEmbed(ExtensionLoader &loader);

//! Register the door itself (spec 041/063): acl_quack_serve / acl_quack_stop, and the two callbacks
//! the server calls - acl_quack_authenticate per connection, acl_quack_authorize per statement.
void RegisterAclQuackDoor(ExtensionLoader &loader, shared_ptr<PolicyStore> store);

//! The server's drain of a client's streamed insert completed (spec 042): called from the generated
//! server TU (a sync.py patch, see there) with the INSERT's outcome, so the audit records the load
//! with its rows - or why it failed - as the session's (spec 069). Never throws.
void AclQuackDrainCompleted(Connection &connection, const string &stream_id, MaterializedQueryResult &result);

} // namespace acl
} // namespace duckdb
