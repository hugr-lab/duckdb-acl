# Spec 181: a session's scripts - set by the policy, run as the node when a session opens

- **Status**: implemented
- **Date**: 2026-11-26
- **Author**: the owner (2026-11-26; hugr-node spec 047's session scripts, moved into the policy), with Claude

## Summary

When a client's session opens, the node runs SQL the administrator wrote on that session's own connection, before the
session's first statement. The node runs it as itself, outside acl, with full rights. The SQL might put the session's
variables, its `USE` or a local setting in place.

The scripts belong to the policy, at three levels, and every level defined runs, layered from the general to the
specific:
1. **the resource group's**, for every session its nodes serve;
2. **each role's** of the session, in the roles' names' order;
3. **each grant's**: a role's grant of the node's resource group.

A later layer runs after an earlier one, so the specific can override the general. The scripts a session runs are
resolved once per role set and group, and cached per policy version.

## Problem

- **A session's state is per connection.** In DuckDB, `USE`, `SET VARIABLE` and a plain `SET` live on one connection.
  Setup that a client should start with (a default schema, a variable its views read, a time zone) can only be put on
  that connection.
- **The state differs by who connects.** The analysts of one region want one default, the ETL another. The owner
  placed the scripts where the policy says who is who: on the resource group, the role, and the role's grant of a
  group. One cluster-wide script with conditions would do the same, but harder to read and write.
- **It is not the cluster profile's.** Boot scripts are hugr-node's profile items (its spec 047), written by the
  `cluster` bundle. A session script is about principals, so it is the policy's, written by the `policy` bundle.

## Design

### Written

```sql
ALTER RESOURCE GROUP <g> SET SESSION SCRIPT '<sql>' [ON ERROR FAIL SESSION | CONTINUE]
ALTER RESOURCE GROUP <g> DROP SESSION SCRIPT
ALTER ROLE <r> SET SESSION SCRIPT '<sql>' [ON ERROR …]
ALTER ROLE <r> DROP SESSION SCRIPT
ALTER RESOURCE GROUP <g> FOR ROLE <r> SET SESSION SCRIPT '<sql>' [ON ERROR …]   -- the grant's
ALTER RESOURCE GROUP <g> FOR ROLE <r> DROP SESSION SCRIPT
```

- **The SQL is one literal**, stored and run as written. Nothing reads it, as with hugr-node's scripts (the owner:
  unchecked). It may hold several statements.
- **`ON ERROR`**: `FAIL SESSION` is the default and refuses the session. `CONTINUE` logs and serves.
- **Who writes**: the `policy` bundle (an unrestricted `manage`), the same as for roles and resource groups.
- **A grant's script needs the grant**: `FOR ROLE r` names a role bound to the group. Revoking the grant drops its
  script, and dropping a role or a group drops what hangs on it.
- **Stored**, schema step v29 with `min_reader` 28: an older reader ignores the new columns.
  - `resource_groups.session_script` and `session_on_error`;
  - `roles.session_script` and `session_on_error`;
  - `role_resource_groups.session_script` and `session_on_error`.
- **Read**:
  - `platform.resource_groups`, `platform.roles` and `platform.role_resource_groups` gain `session_script` and
    `session_on_error`;
  - `platform.session_scripts(role[, group])` lists what a session of that role, on a node of that group, runs, in its
    order. It is the policy bundle's: the console and DBeaver show it.

### Run

- **When**: once per session, right after the session opens on its own connection and before its first statement.
  - Flight: on the session's `Connection`, under its lock, when the door makes it (and again at a takeover, spec 135).
  - quack: on the connection the door binds the session to.

  A per-statement prefix (`ACL ROLE …` from a gateway) is no session and runs none.
- **As the node, full rights** (the owner, 2026-11-26): unprefixed, on that connection. It may set what acl keeps for
  the session too, such as a virtual `USE` (`acl_session_use`) or a setting outside spec 068's list. The principal's
  own statements stay judged by acl as always.
- **What it knows**: before the scripts run, the node sets these variables on the connection:
  - `acl_session_roles` (`VARCHAR[]`);
  - `acl_session_groups` (`VARCHAR[]`): the groups the roles are in;
  - `acl_session_group`: the node's group, or else the session's charged group;
  - `acl_session_subject`: the token's subject.

  A script branches in its conditions (DuckDB has no `IF`):
  `SET VARIABLE region = (SELECT 'north' WHERE list_contains(getvariable('acl_session_roles'), 'analyst_a'))`.
- **The layers**:
  1. The group is the node's (`acl_node_group`, spec 096). On a node with no group it is the session's charged group:
     its own, or the default group for a principal in none.
  2. Then each role of the session that has a script, in name order.
  3. Then each grant of the group to one of those roles that has a script, in role name order.

  Every script defined runs, each on the same connection, so a later one sees and may override what an earlier set.
- **The cache**: the list for a role set and a group is resolved once and kept per policy version, as the known roles
  are (spec 147). A policy change empties it, so a session opened after the write runs the new scripts. Sessions
  already open keep what they ran.
- **A failure**:
  - `FAIL SESSION` refuses the session. The client gets "the session could not be prepared" and nothing more. The
    audit records a `session` event `refused`, reason `session_script`, with the script's level and owner (a group, a
    role, or a role's grant) and its error's class.
  - `CONTINUE` records a `session` event `script_failed` and serves.

  Neither the text nor the error's message is recorded: it may carry names, and a source's error a connection string.

## Security

- **A session script is the node's power on a principal's connection.** It is written by the `policy` bundle, which
  already decides what every principal reads. Through a script it could also act as the node (read any source, write
  the policy), so the bundle is to be given as passthrough is. The owner chose it: roles and groups are the policy's.
- **The principal never writes or sees it.** The roles and groups views are the policy bundle's, and the variables
  set on the connection name only the principal's own roles and groups.
- **The cache is keyed by the role set, the group and the policy version**, never by a token.

## Testing

- `test/sql/acl_session_scripts.test`:
  - the forms and refusals: a role or group that does not exist, `FOR ROLE` without the grant, `ON ERROR` words;
  - the views;
  - `platform.session_scripts` order;
  - the cache emptied by a write.
- C++ (`test_acl_session_scripts.cpp`): a session opened through `acl_session_open` on its own connection runs the
  layers in order. A variable the group's script sets is overridden by the grant's, and read by the principal's
  statement. `FAIL SESSION` refuses the session, and `CONTINUE` serves it.
- e2e: a Flight client and a quack client each read a variable their role's script set.

## Alternatives considered

- **One script, the most specific only.** With several roles, which role's wins would be a hidden rule. The owner
  chose layers, all of them.
- **In hugr-node's cluster profile** (`CLUSTER ADD SCRIPT … ON SESSION`, its spec 047's first draft). That is the
  `cluster` bundle's, and a profile is about nodes, not principals. The open node would also have none.

## Open

- ~~The door hook points (Flight's session connection, quack's) are read in the code before stage 1 is built.~~
  Read and built: see As built.

## As built

- **Stored** (schema v29, `min_reader` 28; `schema/migrations/v29.sql` adds the six columns with `IF NOT EXISTS`):
  `session_script` / `session_on_error` (NULL = `fail`, or `'continue'`) on `roles`, `resource_groups` and
  `role_resource_groups`. A re-created group, a re-defined role (`SET CLAIMS`) and a grant made again keep their
  script (the writers that DELETE + INSERT now carry it over; a re-grant inserts only a missing row); a revoke and a
  drop of the role or the group delete the rows the scripts live on.
- **Written** by `acl_set_session_script(group, role, sql[, on_error])` / `acl_drop_session_script(group, role)`
  (`PolicyStore::CatalogSessionScript`): `role` `''` = the group's, `group` `''` = the role's, both = the grant's.
  Refused: both empty, an empty script, an unknown group or role, `FOR ROLE` without the grant, a drop of a script
  that is not set, `on_error` other than `fail` / `continue`; memory mode (`RequireCatalog`, as resource groups).
  The grammar (`acl_mgmt_grammar.cpp`): `AclAlterRoleScript`, `AclAlterGroupScript` (`AclGroupForRole?`), the
  shared `AclSessionScriptChange` (`AclSetSessionScript` / `AclDropSessionScript`, `AclScriptOnError`); the SQL is an
  `AclQuotedValue` (one plain literal). The platform functions `set_session_script` / `drop_session_script` and the
  read function `session_scripts` are `PlatformRight::POLICY`, so the one authorizer judges them as the group and role
  writers (no point grant reaches them - the review's item 1 below).
- **Read**: the three platform views gain `session_script` and `session_on_error` (shown `fail` | `continue`, NULL
  without a script; a catalog admin's scoped `roles` rows carry NULLs). `platform.session_scripts(role[, group_name])`
  is `acl_session_scripts(role[, group])` (`acl_session_scripts.cpp`): `pos, level, group, role, on_error, sql`.
  Deviation from the brief's `(level, owner, on_error, sql)`: a grant's owner is two names, so `group` and `role` are
  columns of their own, and `pos` is the run order. Without a group the listing takes the one a session of that role
  would.
- **Resolved** by `CatalogBackend::SessionScripts(roles, group)`: one read of the three tables, sorted by layer then
  role name (byte order, as roles compare), cached in `session_scripts_cache` keyed by the role set (length-prefixed,
  as `RoleSig`) and the group, cleared with the other caches when the policy version moves; an answer computed across
  a version change is not kept. None in the driver contract and in memory mode.
- **The first layer's group** (`PolicyStore::SessionScriptGroup`): the node's group; else `limits.charged`; else the
  principal's one group when it has exactly one. The last step is beyond the brief's `limits.charged`: a group that
  states no `max_sessions` charges nobody, and its members would otherwise never run its script on an ungrouped node -
  the spec's "its own, or the default group for a principal in none".
- **Run** by one module, `src/acl_session_scripts.cpp` (seam `acl_session_scripts.hpp`): `SessionScriptsOf` (a
  source that throws refuses the session), `RunSessionScripts` (one `SET VARIABLE` batch for the four variables, then
  each script by `Connection::Query`, unprefixed - the override leaves a text that is no ACL statement alone), and
  `PrepareSession` for a door holding the connection. The variables are set only on a session that runs a script (a
  cookie-less Flight call with none costs nothing). After each script a transaction it left open is committed, an
  invalidated one (or a failed COMMIT) rolled back and counted its failure (the second review below).
- **Flight** (`SessionFor`): after `SessionOpen`, before `SessionBind` - so before a takeover's `TakeOverState` and
  `DeclaredViewAs`; the connection is made (`ConnFor`) only when there is a script, under its `exec` lock (or the
  takeover's `moving.hold`). A refusal closes the session and drops its connection (as `AbandonTakeover`), leaves a
  session it would have replaced alone, and answers `UNKNOWN "acl: the session could not be prepared"`. A cookie-less
  call runs the scripts each call. A LOCAL portable setting a script sets enters the state cookie (spec 135) like the
  client's own; another node runs its scripts first and replays the cookie after.
- **quack**: a `sync.py` patch of the CONNECT handler - after `CreateNewConnection`, the connection is looked up
  (`GetConnection`), its `execution_lock` held while `acl::AclQuackSessionOpened` resolves the bound session
  (`SessionHandleFor`) and runs `PrepareSession`; on false the handler disconnects, ends the session
  (`AclQuackConnectionGone`, `client`) and answers `acl: the session could not be prepared`. `acl_embed_server.cpp`
  regenerated by `sync.py`. (Superseded by the review's item 6: the scripts run before the connection is published.)
- **Gateway sessions**: `acl_session_open` runs no script. It is a scalar on the gateway's connection - a statement
  is running there, so no other statement can run on it from inside, and the gateway's later `ACL SESSION` statements
  may run on any connection it owns. The C++ test therefore opens its sessions through the quack door's real path.
- **Audit**: `PolicyStore::AuditSessionScript` - a `session` event, level DENIED, reason code `session_script`:
  `refused` (allowed false) for FAIL SESSION or scripts that could not be resolved, `script_failed` (allowed true) for
  CONTINUE; the reason names the level and owner and the error's class (`Exception::ExceptionTypeToString`), never
  the SQL nor the message. Counter `acl.sessions.script_failed{door}`; a refusal counts in `acl.sessions.refused`.
  The session the refusal ends is then closed with how `client` (the observers' contract lists no other fitting
  reason).
- **Tests**: `test/sql/acl_session_scripts.test` (forms, refusals, authorization, views, order, cascade, re-writes
  keep, the list read again after a write); `test/cpp/test_acl_session_scripts.cpp` (memory mode refused; through a
  real quack client: layers in order, variables, CONTINUE, FAIL SESSION, a write read by the next session while an
  open one keeps what it ran); the Flight e2e (`run.sh`: a Flight client reads the variable its role's script set).
  Schema pins bumped in `acl_schema_window.test`, `platform_views.test`, `platform_rights.test`,
  `acl_quoted_names.test`.

### Found by its review, fixed

1. **A point grant on the writers was the node's power.** A grant by name on `platform.set_session_script` would
   have handed a role what passthrough holds. `PolicyBundleOnly` (acl_platform: view-as and the three session-script
   calls) - `acl_grant_platform` refuses an allowing grant on them (a DENY still is), `CallsFunction` and
   `AuthorizeAdminCall` require the policy bundle whatever point grant a row says (one written before the rule), and
   the three views show `session_script` / `session_on_error` as NULL to a reader by a point grant on the view
   (`ScriptColumnsSql`). security.md says plainly that a `policy` holder, through a script, acts as the node past the
   bundle's own guards (`AuthorizeRoleTargets`, `RequireNotPolicyStore`, `AuthorizeSources`, `AuthorizeBodies`, never
   self-escalating).
2. **What the scripts left pinned every move** (spec 135): a script's temp table or the transaction it opened made
   each move refuse "lost its temp tables". `SessionConn::NoteScriptState` records, right after the scripts, their
   temp names and the open transaction's global id; `CurrentState` pins neither (the next node's scripts make them
   again) - a temp of the same name the client made after is read as the scripts' (a known limit). (Superseded by
   the second review's 1 and 2: no script transaction survives, and a temp is matched by its oid.)
3. **Scripts left no trace when they succeeded**: each one that ran is a `session` event `script_ran` (DECISIONS,
   level and owner only), counted `acl.sessions.scripts_ran{door}`.
4. **A failed script rolled back a transaction an earlier script left open**: only one the failing script opened
   (autocommit noted before it) is rolled back. (Superseded by the second review's 1: each script's transaction is
   committed or rolled back after it.)
5. **A throw between `SessionOpen` and `SessionBind` leaked the session** to the idle sweep: `OpeningSession`, an RAII
   guard in `SessionFor`, closes the handle and drops its connection unless released at the bind.
6. **quack: a slow script raced the lease sweep** and ran on a published connection. The patch now makes the
   client's `Connection`, runs the scripts (`AclQuackSessionOpened`) and only then makes the `QuackConnection` (its
   lease starts there) and publishes it under `active_connections_mutex`; an empty id back is the refusal, and
   `AclQuackSessionRefused` ends the bound session once (no `DisconnectConnection`, no second `ConnectionGone`). The
   scripts run outside the server's connection lock; the CONNECT handler's seat claim counts the client as
   authenticating meanwhile - that is the bound.
7. **Docs**: `acl_session_groups` on a node of a group is exactly that group (`ResourceLimitsOf` narrows); getvariable
   is recommended by name (its category hands out getenv and the settings too), and the C++ test grants it so.
8. **Tests added**: the Flight e2e's move part - a script's zone, variable and temp table; the client's SET carried
   across a kill wins over the script's zone, the move is not refused for the scripts' temp; a swap to the globex
   principal whose new session the script refuses leaves the old session as it was, and the refusal names no text.
   The SQL test: no grant by name (passthrough's `GRANT FUNCTION platform.set_session_script` refused), a hand-written
   point grant reaches nothing, a view reader by a point grant sees NULLs. The C++ test: `script_ran` events, and
   the refused session's `closed` event.

Smaller: `ScriptColumnsSql` sits before `TableBody`'s doc comment; the close of a refused session keeps the
observers' reason `client` and its `closed` event's reason says "refused by a session script" (`SessionClose` /
`SessionEndBound` / `SessionClosed` take a note).

### Found by its second review, fixed

1. **A script could hand the client an open transaction** (the lead's decision, within the owner's "full rights"
   rule: it may not). The client's writes landed in it and a move lost them; `TakeOverState`'s BEGIN failed inside it
   and locked the client out; a CONTINUE failure left an invalidated transaction and a connection that answered
   nothing. `SettleTransaction` (acl_session_scripts.cpp) runs after EACH script: a transaction left open is
   committed; an invalidated one, or a COMMIT that fails, is rolled back and is that script's failure under its ON
   ERROR. The first review's "roll back only what the failing script opened" and the Flight door's "script
   transaction" pin exclusion are gone: the pins are exactly the client's own.
2. **A temp table the client dropped and made again under a script's name passed as the script's.** `NoteScriptState`
   keeps each script temp's catalog entry oid (`TempCatalogEntries`; `ScanTempTables` hands the entry's oid);
   `CurrentState` pins a temp of that name with another oid. Rows the client writes into a script's own temp table do
   not carry across a move - the next node's scripts make it again (docs).
3. Docs and this spec state the commit-after-each-script rule, and that a cookie-less Flight call records one
   `script_ran` per script per call.
4. `AclQuackConnectionGone` takes the close's note; the duplicate `AclQuackSessionRefused` is gone (the patch calls
   `AclQuackConnectionGone(db, id, "client", "refused by a session script (spec 181)")`).

Tests: the C++ test - a group script ending inside BEGIN has its work committed, a CONTINUE role script failing in its
own BEGIN serves a connection that answers (the later layer ran), the same under FAIL SESSION refuses; the Flight e2e -
the script ends inside BEGIN, the client's write in autocommit carries no transaction pin and survives the move, and a
temp the client remade under the script's name pins (on a session without USE: under `USE c.stage` a short name is
read in the session's catalog before the temp catalog - spec 114's order, unchanged here); the SQL test's `session_scripts` refusals name their message.
