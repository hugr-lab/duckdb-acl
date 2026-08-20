// Introspection over the active policy source (spec 010 part 3): `acl_*` table functions that answer
// "what does this policy source hold?" without knowing which backend it is, and without leaking
// anything a listing has no business showing (an issuer's keys are verification material, not
// metadata). Registered as table functions so a listing is a relation and composes with ordinary SQL.

#pragma once

#include "acl_policy.hpp"

namespace duckdb {
class ExtensionLoader;

namespace acl {

//! Register the acl_* introspection table functions against this instance's policy store
void RegisterAclIntrospection(ExtensionLoader &loader, shared_ptr<PolicyStore> store);

} // namespace acl
} // namespace duckdb
