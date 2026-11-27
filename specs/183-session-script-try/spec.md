# Spec 183: a session script tried before it is written

- **Status**: implemented
- **Date**: 2026-11-27
- **Author**: the owner (2026-11-27, hugr-platform spec 016: "check it safely by running it - a session opened with
  the script not yet saved"), with Claude

## Summary

`platform.try_session_script(…)` runs what a session would run when it opens (spec 181), with the administrator's
edited script in its place, before the script is written. It runs on a connection of the node made for the trial and
dropped after, and nothing is stored. It answers each script that ran, and whether such a session would be served or
refused, with an error's class, message, line and column.

## Problem

- **A script is stored as written** (spec 181, the owner: unchecked), and the first to find its error is a session.
  Under `ON ERROR FAIL SESSION`, every session at that level is then refused.
- **Parsing or binding alone is not enough.** A script runs statement by statement, and a later one reads what an
  earlier one made: a temp table, a `USE`, a variable. It also runs after the layers before it. Only a run judges
  that (the owner rejected parse and `PREPARE`).
- **The client cannot tell.** The console (hugr-platform spec 016) and the DBeaver client never read SQL themselves
  (spec 150's rule), and only the node has its parser, extensions and sources.

## Design

### The function

```sql
SELECT * FROM platform.try_session_script(group_name, role, sql
    [, on_error [, session_role [, session_group]]]);
-- acl_try_session_script(group, role, sql[, on_error[, session_role[, session_group]]])
```

- **The edited script** is named as `set_session_script` names it:
  - a group's: `role` is `''`;
  - a role's: `group_name` is `''`;
  - a grant's: both.

  Its `sql` and `on_error` (`fail` | `continue`) are the form's, not the stored ones. The owner must exist, and a
  grant's binding too, exactly as the writer refuses them.
- **The session tried**:
  - `session_role` is the session's role (by default the script's role). A group's script needs no role: the
    session then has none;
  - `session_group` is the node group the session is served on (by default the script's group). Otherwise it is the
    group such a session would take (spec 181's first layer).
  - The edited script must be one this session runs: a role's script needs that role, and a group's or a grant's
    script needs that group. Otherwise the call is refused, naming why.
- **What runs**, on a connection of the node made for the trial:
  1. the variables a session's scripts see (spec 181), set as for that session:
     - `acl_session_roles` = `[session_role]` (or `[]`);
     - `acl_session_groups` = `[session_group]`, as on a node of that group, or the role's groups when no group
       decides;
     - `acl_session_group`;
     - `acl_session_subject` = NULL, because no token is behind a trial;
  2. the session's scripts in their order, as resolved from the policy (spec 181's layers), with the edited one in
     its place: its stored version replaced, or added where its layer puts it;
  3. each script exactly as a session runs it: unprefixed, as the node, its transaction settled after it (spec 181's
     second review). A failure stops the run under `FAIL SESSION` and is passed by under `CONTINUE`.

  The connection is then closed. What the scripts set on it ends with it: settings, variables, a `USE`, temp tables.
- **It answers** one row per script that ran, then one row for the session:

  | column | type | |
  | --- | --- | --- |
  | `pos` | INTEGER | the run order, from 1; NULL on the session's row |
  | `level` | VARCHAR | `group`, `role`, `grant`, or `session` |
  | `group`, `role` | VARCHAR | the script's owner |
  | `on_error` | VARCHAR | `fail` or `continue` |
  | `edited` | BOOLEAN | the form's script |
  | `ok` | BOOLEAN | it ran; on the session's row, the session would be served |
  | `error_class` | VARCHAR | the exception's type (`Parser`, `Catalog`, `Binder`, …) |
  | `message` | VARCHAR | the error's own message, or for the session row: `served` / `refused by the <level> script` |
  | `line`, `column` | INTEGER | where in that script, from 1: a parse error's own place, else the failing statement's start |

  A parse error's position is duckdb's own. Any other error is placed at the start of the statement that failed (see
  As built). The offset becomes a line and a column in characters.

### What it is not

- **No session is opened.** There is no handle, no seat, no session record and no observer (spec 078). The doors and
  `acl_sessions()` see nothing.
- **A script that acts beyond the connection acts.** The trial is a run as the node, the same run each session would
  make with the script saved. A trial runs it once, before anyone connects:
  - a write to a source is committed (spec 181: a script's transaction is committed after it);
  - `SET GLOBAL`, `ATTACH` / `DETACH`, `INSTALL` / `LOAD`, `COPY … TO`, `nextval` and an HTTP call happen.

  A rollback would not make the run safe: `SET` and `ATTACH` are not transactional, and a temp table is, so a later
  script would lose what an earlier one made. The console says this beside the button.
- **What differs from a real session**:
  - no subject;
  - no `AclConnection` (spec 078), so a secrets service acting for the session sees none;
  - the scripts run on this node, which may belong to another group than the one tried. The settings and sources of
    the node that answers are the ones the run sees.

## Enforcement & security

- **Only the policy bundle**: `PlatformRight::POLICY`, and `PolicyBundleOnly`, as for the writers, so no point grant
  reaches it. Running a script as the node is what writing one already hands out (spec 181's security: the bundle is
  given as passthrough is). A catalog's manage and a principal without administration are refused.
- **Nothing stored**: the policy is read, never written. The edited text lives only in the call. The call's statement
  event carries the text's hash, as for every management call. No `session` event is emitted, because there is no
  session.
- **The answer is the policy bundle's**: an error's message may name what the node holds, and it goes only to whoever
  could read the stored scripts.

## Testing

`test/sql/acl_session_script_try.test`:
- a role's script that binds and runs: one row ok, and the session row served;
- dependencies: a script that creates a temp table and a later statement that reads it runs ok;
- layers: a group's stored script, then the role's edited one reading the variable the group's set. The edited row
  is marked;
- the stored version replaced: the edited one runs in place of what is stored, and the stored one does not;
- a parse error on the third line: class `Parser`, line 3, the session refused under `fail`;
- a missing table under `continue`: the row's error is `Catalog`, the session served, and later scripts still run;
- nothing left:
  - the caller's connection sees none of the scripts' variables, settings or temp tables;
  - the policy is unchanged (the stored scripts' rows);
  - `acl_session_count()` is the same;
- refusals:
  - an unknown owner, and a grant without its binding;
  - a session that does not run the script (another role, or another group);
  - empty SQL, and `on_error` not `fail` or `continue`;
- rights:
  - the policy bundle passes;
  - a catalog's manage is refused, and so is a principal without administration;
  - a grant by name is refused, and a hand-written point grant reaches nothing.

## Alternatives considered

- **Parse, then `PREPARE` each statement** (the first draft). The owner rejected it: a statement bound alone
  misjudges what an earlier one makes, and it misses runtime errors.
- **A rollback around the run.** It is no safer (see above) and wrong for temp tables.
- **A real session for a test principal.** It would need a token, and it would make a session that someone could
  reach. The trial is the run alone.
- **The boot scripts' trial** (hugr-node's profile): a node boots once, and its scripts run around its sources'
  attach. Trying those needs a node of its own, and it is a spec of hugr-node and hugr-platform (a test node brought up
  with the unsaved profile).

## As built

- **Code**: `acl_try_session_script` in `src/acl_session_scripts.cpp`, beside the runner it mirrors. It reuses
  `VariablesSql` (factored out of `RunSessionScripts`) and `SettleTransaction`. The owner check is the writer's own,
  `RequireScriptOwner` (factored out of `CatalogSessionScript`), reached read-only through
  `PolicyStore::CatalogRequireScriptOwner`.
- **The platform function** is `platform.try_session_script`: `PlatformRight::POLICY`, a table function, and in
  `PolicyBundleOnly`. Its arguments in FROM are positional, as for every platform table function: `platform.try_session_script('', 'r', '<sql>', 'fail', '', 'north')`.
- **An error's place**: each script runs statement by statement, with duckdb's own loop: `IterateStatements`, each
  statement parsed after the one before it ran, so a `LOAD` may bring the grammar of the next. A parse error keeps its
  own position, read from the exception before duckdb formats it. Any other error is placed at the start of the
  statement that failed, found in the script after the one before (the parser hands each statement its own text,
  located from 0). The message is duckdb's, with its `LINE …` context. The trial changes no setting of its
  connection.
  - Found by hugr-platform's demo (check 21): the first build set `errors_as_json` on the trial's connection, and a
    platform node locks its configuration after its boot, so every trial was refused there.
  - The regression test runs under `lock_configuration`.
- **The caller's cancel**: a watcher thread passes the calling context's interrupt to the trial's connection
  (`Connection::Interrupt`), so a script stuck on a remote source ends with the call. It is checked between scripts
  too.
- **Tests**: `test/sql/acl_session_script_try.test`.
