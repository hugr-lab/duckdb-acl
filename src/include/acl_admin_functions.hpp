// Admin setup functions (stubs, specs/001): acl_define_token/role, acl_grant_table/view,
// acl_grant_table_function[,_alias], acl_grant_scalar[,_alias], acl_deny/allow_function. They
// populate the per-instance PolicyStore; production replaces them with the read-only role-aware
// resolver behind the same PolicyStore seam.

#pragma once

#include "acl_policy.hpp"

namespace duckdb {
class ExtensionLoader;

namespace acl {

//! Register the acl_* admin scalar functions, attaching the shared policy store to each
void RegisterAclAdminFunctions(ExtensionLoader &loader, shared_ptr<PolicyStore> store);

//! spec 151: whether `name` is one of the records the rewriter emits after a principal's DDL / USE as
//! `PRAGMA <name>(…)` (acl_register_created, …, acl_session_use)
bool IsAclRecordPragma(const string &name);

} // namespace acl
} // namespace duckdb
