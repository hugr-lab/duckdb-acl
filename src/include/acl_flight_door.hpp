//===----------------------------------------------------------------------===//
// acl_flight_door.hpp - the Arrow Flight SQL door (spec 045)
//
// Built by default (ACL_NO_FLIGHT=1 opts out): it links Arrow C++ and gRPC, which a fast local loop has no reason
// to pay for. Everything the rest of the extension needs to know is the one registration below, so
// no other translation unit sees an Arrow header.
//===----------------------------------------------------------------------===//

#pragma once

#include "acl_policy.hpp"
#include "duckdb.hpp"
#include "duckdb/main/extension/extension_loader.hpp"

namespace duckdb {
namespace acl {

//! Register `acl_flight_serve(uri[, options])` and `acl_flight_stop(uri)`. Both are the door's, not a
//! principal's - the `acl_` prefix keeps them out of a rewritten statement by construction.
void RegisterAclFlightDoor(ExtensionLoader &loader, shared_ptr<PolicyStore> store);

} // namespace acl
} // namespace duckdb
