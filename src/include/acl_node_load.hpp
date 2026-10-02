//===----------------------------------------------------------------------===//
// acl_node_load.hpp — what a node reports about its load (spec 079)
//
// One JSON document, built from the numbers admission decides with - sessions against
// acl_max_sessions, and each quack door's seated clients against its seats - so an orchestrator
// routes new sessions to a node with headroom, keeps a sticky session on its node, and reads a
// draining node as closed. Served as `acl_node_load()` (the operator's, denied to a principal like
// every acl_ function), as the quack listener's `GET /.well-known/acl-node` and as the Flight
// Handshake payload `node-load` - the last two only while `acl_metrics_endpoint` is on, like /metrics,
// and (spec 097) only to a bearer token whose roles hold `observe`, unless the operator opened them
// with `acl_observe_unauthenticated`. Counts and states only: never a handle, a principal or an object
// name.
//===----------------------------------------------------------------------===//

#pragma once

#include "acl_policy.hpp"

namespace duckdb {
class ExtensionLoader;
namespace acl {

//! The document, now.
string NodeLoadJson(DatabaseInstance &db, PolicyStore &store);

//! Whether the pull surfaces exist at all (`acl_metrics_endpoint`).
bool NodeLoadServed(DatabaseInstance &db);

//! spec 097: the answer to one read of the load report or the metrics.
enum class ObserveVerdict : uint8_t {
	ALLOWED,         //! serve it
	OFF,             //! `acl_metrics_endpoint` is off - the route is not there (404)
	UNAUTHENTICATED, //! no bearer token, or one that does not verify (401)
	FORBIDDEN,       //! a verified principal without `observe` (403)
	UNAVAILABLE      //! the decision cannot be made - the policy source or the keys failed (503)
};

//! spec 097: whether the caller behind `authorization` (the raw `Authorization` header: `Bearer
//! <jwt>`) may read `surface` (`node_load` | `metrics`) at `door`. Emits the `door` event
//! `observe_<surface>`: a refusal is recorded (rate-limited like every refusal), a read is counted
//! (`acl.door.observe`) - a poll every second as a recorded event would drown the trail. Never throws.
ObserveVerdict ObserveAuthorize(DatabaseInstance &db, PolicyStore &store, const string &authorization, const char *door,
                                const char *surface);

//! acl_node_load()
void RegisterAclNodeLoad(ExtensionLoader &loader, shared_ptr<PolicyStore> store);

} // namespace acl
} // namespace duckdb
