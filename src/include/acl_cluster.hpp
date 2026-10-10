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

//! spec 118: a setting the cluster bundle may put in the profile - the node's resources and tuning (an
//! allowlist); a data path, a trust or audit setting and anything else is passthrough's
bool ClusterBundleMaySet(const string &name);

} // namespace acl
} // namespace duckdb
