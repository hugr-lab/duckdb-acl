// The `ACL` prefix's parser_override entry (specs/001): reads `ACL ROLE "<role>"` / `ACL TOKEN '<token>'` /
// `ACL SESSION` / `ACL ADMIN` with a grammar rule (spec 150, acl_grammar.hpp), takes exactly one prefix, verifies
// the principal offline, parses the remainder as its own text and rewrites it. FALLBACK semantics: anything
// unrecognized falls through to the native parser; a recognized prefix that fails enforcement throws (a non-success
// result would be silently re-parsed natively - an enforcement bypass).

#pragma once

#include "acl_policy.hpp"

namespace duckdb {
class DBConfig;

namespace acl {

//! Register the ACL parser override on the database config, carrying the shared policy store
void RegisterAclParser(DBConfig &config, shared_ptr<PolicyStore> store);

//! spec 114: `USE SCHEMA <path>[;]` as the one statement of the text -> `SET acl_use_schema = '<path>'` (no duckdb
//! grammar has it), `USE <catalog>.<schema path>` of three parts or more -> `SET schema = '…'`; any other text
//! unchanged. Read on duckdb's tokens (spec 150 3g-2b). The override and the Flight door read it alike.
string UseSchemaAsSet(const string &text);

} // namespace acl
} // namespace duckdb
