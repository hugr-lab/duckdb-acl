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

//! Whether a statement drains a quack client's data stream - calls `acl_quack_scan_data` (the
//! embedded door's name, spec 063) or `scan_data_from_quack_client` (a stock quack's). The same
//! reading the override applies to every unprefixed statement (spec 042); the door's statement
//! hook asks it to tell an ingest from any other statement (spec 069).
bool StatementDrainsQuackStream(const string &sql);

} // namespace acl
} // namespace duckdb
