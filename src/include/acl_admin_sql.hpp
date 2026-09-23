//===----------------------------------------------------------------------===//
// acl_admin_sql.hpp — the ACL management grammar (spec 008) and its authorization gate
//
// `ACL ADMIN CREATE VIRTUAL CATALOG ...`, `GRANT CATALOG ... TO ROLE ...`, `ALTER ...`, `DROP ...`
// and the rest compile, with no parse-time side effects, into calls of the acl_* admin functions;
// AuthorizeMgmt then judges every compiled call against the principal's administration scope
// (spec 009) before anything runs. The parser override (acl_parser_override.cpp) is the only caller:
// it recognises the `ACL <management>` marker after a principal and hands the text here.
//===----------------------------------------------------------------------===//
#pragma once

#include "acl_policy.hpp"

namespace duckdb {
class SQLStatement;

namespace acl {

//! Whether text opens with a management statement (CREATE VIRTUAL ..., GRANT ..., ALTER ..., ...):
//! how the anonymous `ACL ADMIN` form tells a management batch from native SQL it may also carry.
bool IsMgmtStart(const string &text);

//! Compile a management batch (statements separated by `;`) into admin-function calls. Parse-time
//! only: nothing is written until the statements execute. A syntax error throws a ParserException.
//! `current_session` is the ops id of the session the batch runs under ('' off a session): what
//! `PROFILE SESSION CURRENT` names (spec 074 slice 3).
vector<unique_ptr<SQLStatement>> ParseMgmtBatch(const string &text, const string &current_session = string());

//! spec 082: whether text opens with `GRANT SECRET` / `REVOKE SECRET` - the node's secrets service,
//! not the ACL: judged by the `secrets` capability, never by an administration scope.
bool IsSecretsStart(const string &text);
//! Compile a batch of GRANT / REVOKE SECRET statements (nothing else may be in it) into the service
//! catalog's own calls; the catalog is the one each statement names or the one attached
//! (PolicyStore::SecretService).
vector<unique_ptr<SQLStatement>> ParseSecretsBatch(const string &text, PolicyStore &store);

//! The authorization gate of spec 009: every compiled call is judged against `rights` - the
//! catalog it acts on, whether it hands out access or scopes - and a refusal anywhere in the batch
//! throws before any statement runs. A call the gate does not know is refused, never waved through.
void AuthorizeMgmt(vector<unique_ptr<SQLStatement>> &statements, const PolicyStore::AdminRights &rights);

} // namespace acl
} // namespace duckdb
