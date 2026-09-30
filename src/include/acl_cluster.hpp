//===----------------------------------------------------------------------===//
// acl_cluster.hpp
//
// Spec 093: the cluster profile's SQL surface - acl_cluster_extension / _attach / _detach / _setting
// (what `ACL CLUSTER …` compiles to), acl_cluster_version() and acl_cluster_items([scope]). The
// writers themselves are PolicyStore::Cluster* (acl_cluster.cpp).
//===----------------------------------------------------------------------===//

#pragma once

#include "acl_policy.hpp"

namespace duckdb {
class ExtensionLoader;

namespace acl {

void RegisterAclCluster(ExtensionLoader &loader, const shared_ptr<PolicyStore> &store);

} // namespace acl
} // namespace duckdb
