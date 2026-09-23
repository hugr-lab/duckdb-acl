# Spec 081: the publisher mark on the session hooks (ACLC 2)

- **Status**: implemented
- **Date**: 2026-09-23
- **Contract**: duckdb-ext-common spec 007 (v0.6.0), `contracts/acl_connection.hpp`
- **Requested by**: tresor (its actor spec: `ACT_FOR_SESSIONS` must refuse where nobody publishes)

## Problem

Spec 078 publishes a statement's session on its connection and announces opens and closes to the
`AclSessionHooks` registry. Both sides `GetOrCreate` that registry, so a consumer always reaches
one. On a node without acl, or with an acl older than the contract, no statement shows a session.
A consumer that acts for the session's user then acts as the node instead, and nothing tells it.

## Design

- At load, right after reaching the registry, acl calls `MarkPublisher("duckdb-acl <build> (ACLC
  <version>)")`, where `<build>` is `EXT_VERSION_ACL`, or `dev` when there is none.
- A registry stamped with another contract version is not marked. `Reach` refuses it, and spec 078's
  `MarkRefused` path is unchanged. A consumer of the same version then sees no mark, which is the
  truth: this acl does not publish into it.
- The re-pin to duckdb-ext-common v0.6.0 moves `ACLC` from 1 to 2. A consumer built against v0.4.0
  or v0.5.0 is refused by `Reach` in both directions, as the charter intends. tresor re-pins the
  same day.

## Tests

`test/cpp/test_acl_session_hooks.cpp` has two checks:

- the registry of an instance with acl is marked, and the mark names the contract version;
- a fresh registry that nobody marked answers false, with an empty name.
