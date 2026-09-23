//===----------------------------------------------------------------------===//
// acl_node_load.hpp — what a node reports about its load (spec 079)
//
// One JSON document, built from the numbers admission decides with - sessions against
// acl_max_sessions, and each quack door's seated clients against its seats - so an orchestrator
// routes new sessions to a node with headroom, keeps a sticky session on its node, and reads a
// draining node as closed. Served as `acl_node_load()` (the operator's, denied to a principal like
// every acl_ function), as the quack listener's `GET /.well-known/acl-node` and as the Flight
// Handshake payload `node-load` - the last two only while `acl_metrics_endpoint` is on, like /metrics.
// Counts and states only: never a handle, a principal or an object name.
//===----------------------------------------------------------------------===//

#pragma once

#include "acl_policy.hpp"

namespace duckdb {
class ExtensionLoader;
namespace acl {

//! The document, now.
string NodeLoadJson(DatabaseInstance &db, PolicyStore &store);

//! Whether the report may be served unauthenticated (`acl_metrics_endpoint`).
bool NodeLoadServed(DatabaseInstance &db);

//! acl_node_load()
void RegisterAclNodeLoad(ExtensionLoader &loader, shared_ptr<PolicyStore> store);

} // namespace acl
} // namespace duckdb
