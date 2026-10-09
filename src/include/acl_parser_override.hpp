// The `ACL` prefix scanner and parser_override entry (specs/001): recognizes `ACL ROLE "<role>"` /
// `ACL TOKEN '<token>'` / `ACL ADMIN`, strips exactly one prefix, verifies the principal offline,
// re-parses the remainder natively and rewrites it. FALLBACK semantics: anything unrecognized falls
// through to the native parser; a recognized prefix that fails enforcement throws (a non-success
// result would be silently re-parsed natively - an enforcement bypass).

#pragma once

#include "acl_policy.hpp"

namespace duckdb {
class DBConfig;

namespace acl {

//! Register the ACL parser override on the database config, carrying the shared policy store
void RegisterAclParser(DBConfig &config, shared_ptr<PolicyStore> store);

//! spec 114: `USE SCHEMA <name>[;]` as the one statement of the text -> `SET acl_use_schema = '<name>'`
//! (no duckdb grammar has it); any other text unchanged. The override and the Flight door read it alike.
string UseSchemaAsSet(const string &text);

} // namespace acl
} // namespace duckdb
