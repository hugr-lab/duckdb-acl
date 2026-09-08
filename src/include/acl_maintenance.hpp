//! spec 039: catalog maintenance - acl_check_catalog([vcat]) (a table function: what no longer holds
//! against the source, one row per finding) and acl_repair_relation(vcat, vname, action[, spec]).
//! Both are the operator's, off the query path; registered by RegisterAclMaintenance.
#pragma once

#include "acl_policy.hpp"
#include "duckdb/main/extension/extension_loader.hpp"

namespace duckdb {
namespace acl {

void RegisterAclMaintenance(ExtensionLoader &loader, const shared_ptr<PolicyStore> &store);

} // namespace acl
} // namespace duckdb
