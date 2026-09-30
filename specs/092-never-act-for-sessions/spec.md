# Spec 092: a secrets service's act_for_sessions is never callable

- **Status**: implemented
- **Date**: 2026-09-30

## Summary

tresor (its spec 015) gains `CALL <catalog>.act_for_sessions(...)`. It turns on delegation for an
already attached tresor catalog: from then on the node acts for every acl session (spec 078's
observers, a grant per session). This call is the node's own bootstrap step, and a principal must
never make it. acl puts the name in spec 072's never set, so no category and no grant by name can
admit it, in whatever catalog the service is attached as.

## Why the node needs it

The platform's node installs everything except tresor from an authenticated extension repository.
To get the repository's token, it has to attach tresor before acl is loaded. But `ACT_FOR_SESSIONS`
must come after `LOAD acl` (the ACLC 2 publisher mark). Enabling delegation by a call after
`LOAD acl` replaces a DETACH and a second ATTACH (design/017).

## Design

`act_for_sessions` joins the never set's names in `FunctionNeverCallable`:

- A name in the never set is matched in any catalog. The service catalog's name is the node's
  choice, so a match on the name is the only one that holds.
- The name is refused in each place a function name can be written: `ACL ADMIN ALTER FUNCTION
  CATEGORY … ADD`, `GRANT FUNCTION …`, and a call under a principal.
- It is `never` in `acl_function_status()` wherever it exists.

tresor refuses the call under an acl session itself, which is a second, independent check. The
node's own connection, which carries no principal, is the only caller.

## Testing

`test/cpp/test_acl_secrets.cpp` adds `act_for_sessions` to the fake service catalog (`TYPE
tresor`). It checks that:

- adding it to a category is refused, `never callable`;
- granting it by name is refused, `never callable`;
- calling it under a principal is refused, bare in the catalog and qualified `corp.main.`;
- the service hears nothing.

The test fails without the change: every refusal runs instead.
