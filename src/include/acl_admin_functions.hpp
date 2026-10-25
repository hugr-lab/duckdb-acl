// Admin setup functions (stubs, specs/001): acl_define_token/role, acl_grant_table/view,
// acl_grant_table_function[,_alias], acl_grant_scalar[,_alias], acl_deny/allow_function. They
// populate the per-instance PolicyStore; production replaces them with the read-only role-aware
// resolver behind the same PolicyStore seam.

#pragma once

#include "acl_function_categories.hpp"
#include "acl_policy.hpp"

namespace duckdb {
class ExtensionLoader;

namespace acl {

//! Register the acl_* admin scalar functions, attaching the shared policy store to each
void RegisterAclAdminFunctions(ExtensionLoader &loader, shared_ptr<PolicyStore> store);

//! spec 072: a function spec (`name`, `schema.name`, `db.schema.name`, `"op"`, then TABLE | SCALAR) as the function
//! grants and categories read it - the key, and whether a kind was written. Refuses what they refuse (the never set,
//! platform's functions, a name written in parts that is not plain)
FunctionKey ReadFunctionSpec(const string &spec, const char *fn, bool &kind_written);

} // namespace acl
} // namespace duckdb
