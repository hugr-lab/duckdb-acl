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
class QueryResult;

namespace acl {

//! Register the embedded server's SQL surface: the acl_quack_* server settings the embedded graph
//! reads, and the acl_quack_scan_data drain table function.
void RegisterAclQuackEmbed(ExtensionLoader &loader);

//! Register the door itself (spec 041/063): acl_quack_serve / acl_quack_stop, and the two callbacks
//! the server calls - acl_quack_authenticate per connection, acl_quack_authorize per statement.
void RegisterAclQuackDoor(ExtensionLoader &loader, shared_ptr<PolicyStore> store);

//! A statement the server drove for a client completed: called from the generated server TU (a
//! sync.py patch, see there) with the outcome, on the server's statement thread. What the audit
//! wants from it is the drain of a client's streamed insert - since quack f4328c5 a statement the
//! CLIENT composes (`INSERT ... SELECT * FROM scan_data_from_quack_client(...)`) and the server runs
//! like any other - recorded as the session's ingest with its rows, or why it failed (spec 069).
//! Any other statement is ignored here (its decision was audited by the override). Never throws.
void AclQuackStatementCompleted(Connection &connection, const string &connection_id, const string &sql,
                                QueryResult &result);

} // namespace acl
} // namespace duckdb
