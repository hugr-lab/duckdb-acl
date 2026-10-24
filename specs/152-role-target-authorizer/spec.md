# Spec 152: the role-target authorizer reads names and batches as the store does

- **Status**: implemented
- **Date**: 2026-10-24
- **Author**: hugr lab (found by spec 150 stage 3e's security review)

## Summary

Spec 117's `AuthorizeRoleTargets` keeps a non-passthrough administrator from handing out administration through
identity: it refuses a mapping to a privileged role, a catalog `manage` for a role a mapping reaches, and a change of
an issuer or a client a privileged mapping hangs on. Two of its readings differed from the store's, and each let a
`policy` administrator reach passthrough. This spec makes the authorizer read names the way the store resolves them
and judge a batch with what the batch itself maps and grants.

## Problem

1. **Names compared exactly.** The store finds an issuer or a client case-insensitively (`IdentityModel::Issuer` /
   `Client`, a mapping's scope at use - `CIEquals`), the authorizer compared `mapping.scope_name == client`,
   `each.issuer == issuer` exactly. With a client `desktop` mapped to a passthrough role `boss`,
   `ACL ROLE "pol" ALTER ISSUER KC SET URL 'test/idp/other'` (or `ALTER CLIENT DESKTOP SET AUDIENCES (…)`,
   `CREATE OR REPLACE CLIENT Desktop ISSUER KC …`, `ALTER ISSUER 'TEST/IDP/A' …` for a short form) was admitted - a
   token of the new IdP carrying `boss` then ran `ACL NATIVE`. A `CREATE OR REPLACE CLIENT Desktop` by anyone left
   the stored name `Desktop` and the mapping `desktop`, after which the exact name passed too.
2. **A batch judged against the model before it.** `MAP CLAIM 'x' FROM CLIENT f TO ROLE r; GRANT CATALOG sales TO
   ROLE r WITH (select, manage)` - each statement alone is refused (the second because r is mapped), together both
   were admitted, in either order: the claim then carried a catalog's administration.

## Design

- Every name comparison in `privileged_behind` is `StringUtil::CIEquals` - the store's fold (ASCII). It may read a
  mapping as behind an object more often than the store would, never less: an over-reading refuses, passthrough
  writes it.
- The batch's own effects are taken first: the roles its `acl_map_role` calls map and the roles its
  `acl_grant_catalog` / `acl_alter_grant` calls give `manage`. Then, whatever the order, a mapping refuses a role
  the store holds privileged or the batch gives `manage`, and a `manage` grant refuses a role a stored mapping or
  one of the batch reaches. A batch can then make no new privileged mapping, so the repoint check reads the stored
  mappings as before (only `manage` makes a role privileged below passthrough - the bundles and the platform's point
  grants are passthrough's to write).

## Enforcement & security

Fail closed: both changes only widen what the authorizer refuses. Passthrough is untouched (it writes anything);
roles still compare exactly (spec 095). The at-use rules (a privileged role reached by an issuer-scope mapping,
`AS ROLE` or a constant does not count) are unchanged.

## Testing

`test/sql/platform_rights.test`: a `policy` role, a passthrough role behind a client mapping - `ALTER ISSUER KC`,
`ALTER CLIENT DESKTOP`, `CREATE OR REPLACE CLIENT Desktop ISSUER KC`, `ALTER ISSUER 'TEST/IDP/…'` refused; the
batch `MAP …; GRANT … manage` and `GRANT … manage; MAP …` refused, each statement alone as before.

## Alternatives considered

- Judging each statement at execution, inside the acl_* functions, against the store after the batch's earlier
  statements: exact, but the rights would have to travel to the functions; the union is simpler and refuses no
  batch a reader would call harmless.
