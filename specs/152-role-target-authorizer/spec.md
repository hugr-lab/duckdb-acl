# Spec 152: the role-target authorizer reads names, batches and roles as the store does

- **Status**: implemented (accepted by the owner, 2026-10-25: the empty role refused everywhere, revokes too; strict
  specs; the URL reading dropped; the prepared statement proposed as a known limit)
- **Date**: 2026-10-24
- **Author**: hugr lab (found by spec 150 stage 3e's security review, and this spec's own reviews)

## Summary

Spec 117's `AuthorizeRoleTargets` keeps an administrator below passthrough from handing out administration through
identity: it refuses a mapping to a privileged role, a catalog `manage` for a role a mapping reaches, and a change of
an issuer or a client that a privileged mapping hangs on. Its readings differed from the store's in three places -
names, batches and the empty role - and each let the `policy` bundle hand out what only passthrough may. This spec
makes the authorizer read as the store does, refuses the empty role where it means nothing, and makes the issuer and
client specs as strict as their grammar.

## Problem

1. **Names compared exactly.** The store finds an issuer or a client in any case (`IdentityModel::Issuer` / `Client`,
   a mapping's scope at use - `CIEquals`); the authorizer compared them exactly, so a change written as `KC` of an
   issuer stored as `kc` was never seen as the one behind a privileged mapping. A client re-created under another
   spelling (`Catchall`) kept its mappings under the old one, and from then on the exact name passed too.
2. **A batch judged against the model before it.** Sent one after the other, a mapping to a role and a catalog
   `manage` for it refuse the second; in one batch both were admitted, in either order.
3. **The empty role.** `''` means every role for a function grant (spec 072) and nothing anywhere else, but the role
   writers stored it and the authorizer used `''` as "no role", so a mapping to `''` and a `manage` grant to `''` were
   never judged against each other.
4. **Specs with a property twice.** The function forms `acl_define_client` / `acl_alter_*` took a spec naming a key
   twice, or `attributes` with `claim_map`, and kept the last - what spec 150's 3e grammar refuses.

## Design

- Every name comparison of `privileged_behind` is `StringUtil::CIEquals` (the store's ASCII fold; names are unique in
  any case, so it never merges two objects). The comparison of a name with an issuer's URL is gone: the store never
  resolves an issuer by URL, and a short form's name is its URL, so the name comparison covers it.
- The batch is read first: each statement's target, whether it grants a catalog's `manage` and to whom, the roles the
  batch maps. Then, whatever the order, a mapping refuses a role the store holds privileged or the batch gives
  `manage` ("is given a catalog's manage by this batch"), and a `manage` grant refuses a role a stored mapping or one
  of the batch reaches. Only `manage` makes a role privileged below passthrough (the bundles and the platform's point
  grants are passthrough's to write; a schema or object grant refuses `manage`), so a batch makes no new privileged
  mapping and the repoint check reads the stored mappings.
- `RoleArg` (acl_door_common): every role argument of the admin functions - grants, revokes, `ALTER GRANT`, mappings,
  `GRANT | REVOKE ADMIN`, resource groups, the role's own definition - is required and never `''`. A function grant
  keeps `''` for every role. No stored row is rewritten.
- `ApplyClientSpec` / `ApplyIssuerSpec` (only writers call them) refuse a property named twice and a client spec
  naming both `attributes` and `claim_map`.

## Enforcement & security

Fail closed: each change only widens what is refused. Passthrough is untouched; roles still compare exactly (spec 095).
The at-use rules (a privileged role reached by an issuer-scope mapping, `AS ROLE` or a constant does not count) are
unchanged.

**Known limit (proposed, 2026-10-25):** the judgment is made when the statement is decided - at its parse. A
management statement prepared (`Connection::Prepare`, a Flight prepared statement) executes as decided, even when the
model changed between Prepare and Execute, so the order rules above are not re-read for it. It needs the `policy`
bundle and a client that prepares; what it can reach is a catalog's `manage` for a claim (less than `policy` already
holds), or - only when a passthrough administrator maps a privileged role in the window - an issuer change behind
that mapping. Recorded, not fixed (Follow-ups).

## Testing

`test/sql/platform_review.test` (D2): `ALTER ISSUER KC`, `platform.alter_issuer('Kc', …)`, `ALTER CLIENT CATCHALL`,
`CREATE OR REPLACE CLIENT Catchall ISSUER KC`, `CREATE CLIENT … ISSUER kC`, a short form `ALTER ISSUER 'TEST/IDP/D'`
refused; a client re-created as `Catchall` still behind `root`; the batches map + grant, grant + map, alter grant +
map, and the calls' batch refused; a mapping and a grant to different roles, a mapping with a grant that is no
`manage`, and a case variant of an issuer with nothing behind it admitted; `''` refused by `map_role`,
`grant_catalog`, `alter_grant`, `acl_revoke_catalog`, `acl_grant_admin`; a client spec naming `audiences` twice, or
`attributes` with `claim_map`, and an issuer spec naming `url` twice refused.

## Alternatives considered

- Judging each statement at execution, inside the acl_* writers, against the store after the batch's earlier
  statements (the rights from the decision's note, as spec 120.5's `AuthorScope` reads the author): exact, closes the
  known limit too, but every judged writer re-runs the authorizer - left for a need.
- Refusing to prepare the judged management calls: breaks Flight's prepared management path.

## Follow-ups

- The known limit: a re-judgment at execution (the first alternative) if a deployment needs it.
