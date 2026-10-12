# Spec 122: check a grant before writing it

- **Status**: implemented (accepted by the owner 2026-10-12)
- **Date**: 2026-10-12
- **Author**: the agent, at the owner's ask (the DBeaver plugin's grant editor, acl-clients spec 008)

## Summary

`platform.check_grant(role, catalog, object, rls, columns[, caps])` answers what writing that grant would say -
the predicate binds or not, each column / mask / field path the role would read with its type, the stored form of
the column list - and writes nothing. It runs the write's own steps, through the same code, so a check and the write
it precedes cannot disagree.

## Problem

Only the write judges a grant. An object grant's RLS is bound against the object (spec 021), its column list is
normalised and its projection probed (specs 026 / 037 / 102: masks, renamed types, field paths), its caps checked
(spec 032) - and every finding is a refusal of the write. A tool that composes the grant (the plugin's Row filter
and Columns tabs, acl-clients 008) cannot ask "is this right, and what will the role read?" before the statement:
the author edits, saves, reads the refusal, edits again. Nothing on the node answers the question without writing.

## Design

- **The call**: a read function of the `platform` catalog, in FROM like `check_catalog` / `effective_rights`
  (spec 117): `SELECT * FROM platform.check_grant('analyst', 'sales', 'customers', 'tenant = acl_claim(''t'')',
  'id, name, ssn = NULL')`. `object` empty or NULL = a catalog grant; `caps` optional (the JSON of `CAPS`). No
  grammar form: the editor composes the call, a person writes the GRANT.
- **Right**: who may write the grant may check it - `HANDS_OUT` (the `policy` bundle, a point grant on
  `platform.check_grant`); a catalog's `manage` hands out nothing (spec 009), so it checks nothing.
- **What it runs**: the steps of `CatalogSetObjectCaps` / `CatalogGrant`, factored into one plan both call, the write
  then writing what the plan produced:
  1. policy-free expressions (`RequirePolicyFreeExpressions` - no read of the policy store's tables);
  2. the column list against the catalog / object (`ValidateGrantColumns`);
  3. the caps against what they name (`manage` per object, a write verb on a function - spec 032), when given;
  4. the RLS bound against the object's source (`PredicateError` - a view's body, a table's physical name);
  5. the list normalised to its stored form (`NormaliseGrantColumns`: order, field paths checked against the type -
     spec 102) and the projection probed (`ProjectionSchema`: each column's name and exposed type).
  A catalog grant has no object: steps 1-3; its RLS and columns are not bound (the write does not bind them
  either - "a catalog-level column list is not probed", docs) and the answer says `unchecked`.
- **The answer**, one row per finding, in step order - `(item, name, type, status, message)`:
  - `item` = `rls` | `columns` | `column` | `caps`; `status` = `ok` | `refused` | `unchecked`;
  - `rls`: ok, the write's refusal text, or unchecked (a catalog grant, a source that cannot be probed - the write
    stores those with `rls_checked = false`);
  - `columns`: the list as the grant would store it (`name` = the normalised text);
  - `column`: each column the role would read - `name`, `type` (the exposed one), `message` = its mask / expression
    when it has one;
  - the first refused step ends the answer (the write would have stopped there), with the write's own message.
- **Bodies** (spec 117 `AuthorizeBodies`): the RLS and the masks are judged by the caller's function gate exactly
  as when the GRANT is written - a function the author may not call refuses the call itself (the statement's error,
  not a row), the same refusal the write would get.

## Enforcement & security

- Writes nothing: the plan runs on the store's connection with reads only (the write's `WriteWithReads` keeps its
  transaction; the check opens none and discards the statements).
- Reveals nothing the caller may not see: the probes bind against the source's schema (no rows read - the same
  probes the write runs); the caller is one who may write the grant, whose write would run them anyway.
- One judgment: the plan is the write's code; a test runs each case through both and requires the same verdict.
- No parameter is added (golden rule); a `?` in the call is refused where authz is (spec 117's rule for platform
  calls).

## Tests

- `test/sql/platform_check_grant.test`: an object grant that is right (ok rows, each column with its type, a mask
  that changes a type shown with it, a field path's narrowed STRUCT); an RLS that does not bind (refused, the write's
  message); an unknown column; RLS or columns on a scalar refused; caps `manage` on an object refused; a catalog
  grant (unchecked); the parity loop - each case then written with `GRANT OBJECT`: refused exactly when the check
  refused, and `grant_columns` holding what the check answered; a catalog admin and an ordinary role refused the
  call; a body calling a function the author may not call refused.
- The plugin side is acl-clients 008's (its tabs and their Check).

## Alternatives considered

- **Check on the client** (the owner's other option): names and brackets only; masks, types and RLS binding are the
  node's - rejected (2026-10-12).
- **A dry-run flag on GRANT** (`GRANT … CHECK ONLY`): grammar for a tool's question, and a statement that looks like
  a write; a read function says what it is.
- **Let the editor write and read the refusal**: what happens today - a refused write is the only answer.

## As built (2026-10-12)

- **One plan**: `PolicyStore::CatalogCheckObjectCaps` (the spec 032 caps judgment, moved out of the write) and
  `PlanObjectGrant` (acl_catalog_admin.cpp: the predicate bound against the object, `NormaliseGrantColumns`, the
  projection probed - `GrantProjectionStatements` now hands out what it probed) are what `CatalogSetObjectCaps`
  writes from and what `CatalogCheckGrant` answers from; the write is otherwise unchanged (same statements, same
  order). The check runs `CatalogRequireGrantTarget` first, as `acl_grant_object` does.
- **The function**: `acl_check_grant(role, vcat, vname, rls, columns[, caps])` (acl_platform_rights.cpp, a table
  function; names spelled as the write spells them - spec 116), `platform.check_grant` in `PlatformFunctions()`
  (`HANDS_OUT`, catalog argument 1). Its RLS and columns are bodies (`BodiesOf`), and a read function in FROM now
  passes `AuthorizeBodies` after `AuthorizeAdminCall` (`PlatformReadFunctionSql`) - before, the read path judged
  only the right, and no read function carried a body.
- **The answer**: `item` = `object` | `rls` | `columns` | `caps` | `column`; a refusal is the write's message
  (`ErrorData::RawMessage`), and ends the answer; the plan's refusal is `rls` when it is the predicate's, else
  `columns`. A grant without a column list answers every column the object exposes (`ExposedColumnList` - its
  declared list, else its source's - probed as a list of them all): what the role reads, and what a tool shows to
  narrow from (the plugin's Columns tab - the grantor needs no grant on the catalog to see them).
- **Tests**: `test/sql/platform_check_grant.test` - the right grant (types, a mask changing the type, a field path's
  narrowed STRUCT, the stored order), nothing written, the write then storing exactly the probed projection; the
  refusals each checked then written (RLS that does not bind, an unknown column, `manage` on an object, RLS on a
  scalar, a missing object - the write refused with the same words); a body calling a denied function refused for
  both; a catalog grant (`unchecked` columns); a catalog admin and an ordinary role refused, a point grant admitted;
  `acl_check_grant` itself in the never set.
- **For**: acl-clients spec 008's grant editor (its Row filter and Columns tabs' Check).
