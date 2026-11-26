//===----------------------------------------------------------------------===//
// acl_session_scripts.hpp - spec 181: a session's scripts, run as the node when it opens
//
// The policy keeps SQL at three levels - a resource group's, a role's, a role's grant of a group - and a session runs
// every one that applies, layered from the general to the specific, on its own connection before its first statement.
// The scripts are the administrator's: run unprefixed, as written, with the node's rights; nothing reads them first.
// The doors call this module, one place for both: Flight when it opens a session (spec 050's connection), quack when
// its CONNECT made the client's connection (a sync.py patch).
//===----------------------------------------------------------------------===//

#pragma once

#include "acl_policy.hpp"

namespace duckdb {
class Connection;
class ExtensionLoader;

namespace acl {

//! The scripts the session `handle` runs, in their order (resolved once per role set and group, cached per policy
//! version). False when they could not be read: the session is refused - the audit has the event, the door says only
//! that the session could not be prepared. An unknown session runs nothing (true, none).
bool SessionScriptsOf(PolicyStore &store, const string &handle, const string &door, vector<SessionScript> &scripts);

//! Run `scripts` on `con`, the session's own connection, outside any statement of it - first the variables
//! acl_session_roles / acl_session_groups / acl_session_group / acl_session_subject, then each script as the node.
//! False = refused: a script ON ERROR FAIL SESSION failed (the caller ends the session); a CONTINUE one that failed is
//! recorded and the rest run. Never throws.
bool RunSessionScripts(PolicyStore &store, Connection &con, const string &handle, const vector<SessionScript> &scripts,
                       const string &door);

//! Both, for a door that already holds the connection: false = refuse the session
bool PrepareSession(PolicyStore &store, Connection &con, const string &handle, const string &door);

//! acl_session_scripts(role[, group]) - the listing platform.session_scripts answers
void RegisterAclSessionScripts(ExtensionLoader &loader, const shared_ptr<PolicyStore> &store);

} // namespace acl
} // namespace duckdb
