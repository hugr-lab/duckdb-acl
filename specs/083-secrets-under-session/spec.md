# Spec 083: a compiled statement runs under the session that decided it

- **Status**: implemented
- **Date**: 2026-09-24
- **Found by**: tresor's actor.sql against real acl (f1bdff8), a Keycloak realm and the reference server
- **Fixes**: spec 082 (GRANT / REVOKE SECRET), spec 074/078 (a native batch)

## Problem

A statement runs under a session only while its connection publishes it (spec 078). acl publishes
at `QueryBegin`, taking the override's decision note, which is matched to the execution by the hash of
the text the statement carries (spec 074). Two paths produced statements with no match:

- **GRANT / REVOKE SECRET (spec 082).** The compiled `<catalog>.main.grant_secret(...)` carried no
  text, and its trail entry had no hash. The service's call therefore ran with nothing published, and
  tresor took it for the node's own work. tresor saw a GET of the grants from the node's bare identity,
  which answered 404. With admin rights at the service, this would have been an escalation: a
  principal's grant made as the node.
- **A native batch.** One trail entry carried the first statement's hash. Every later statement of
  an `ACL NATIVE` batch under a session therefore ran as the node.

## Design

- **GRANT / REVOKE SECRET.** Each compiled statement carries its own text (`query = ToString()`), and
  its trail entry carries that text's hash. The note is taken at its `QueryBegin`, and the session is
  on the connection while the service's call binds and runs.
- **NATIVE.** There is one trail entry, `native`, per statement of the batch, each with its own hash.
  So a native batch now makes one audit event per statement, not one per batch.
- The management path (`ACL <mgmt>`, spec 008) is unchanged. It runs acl's own functions, which act on
  the policy, not as anyone.

## Enforcement & security

A statement a session decided never reaches an extension that acts for sessions (tresor) as the node's
own work. The note is taken by text, so a statement nobody decided still publishes nothing.

## Tests

`test/cpp/test_acl_secrets.cpp`, scenario "under a session":

- The fake service reads `AclConnection` in its bind, as tresor's actor does.
- A GRANT and a REVOKE under `ACL SESSION` reach it as that one session.
- A gateway's per-statement prefix names no session.
- Both statements of a passthrough administrator's native batch run as the session.
- The service's own refusal reaches the client as it is (acl never answered `true` for it; tresor's
  `true` came from its own node-identity path).
- Without the fix, the first two checks fail.
