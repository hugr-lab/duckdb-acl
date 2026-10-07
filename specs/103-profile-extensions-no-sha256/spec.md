# Spec 103: a cluster profile's extension is a version and a repository - no sha256

- **Status**: implemented
- **Date**: 2026-10-07
- **Follows**: spec 093 (the cluster profile)
- **Asked by**: the owner, through the extension-repository session (kista, hugr-lab/duckdb-extension-repository
  spec 0001-architecture), 2026-10-07

## Problem

Spec 093 let an extension in the profile carry an optional `SHA256`. A node computed it on the
installed `.duckdb_extension` file, and refused (removing the file and its `.info`) on a mismatch.
That file ends with its 256-byte signature, and the repository signs each channel with its own key
and rotates keys by re-signing. So the digest:

- changes with every key rotation, and every rotation would mean editing every profile;
- differs between channels for the same code.

It adds no protection beyond what is already there:
- DuckDB verifies the signature at INSTALL and at every LOAD, against keys from the repository's
  `.well-known` discovery, pinned when the repository is created;
- the repository keeps a released version immutable: it can be yanked, never replaced, and a fix is a
  new version.

What is left is a compromised repository together with its signing key (kept in Key Vault / HSM).
The owner judged that not worth the operational cost. Keys never go into the profile either: they
come only through discovery.

## Design

- `ACL CLUSTER INSTALL | UPDATE EXTENSION … SHA256 '…'` is **refused**, not ignored: a script that still
  pins a hash must not believe it does. The message names this spec.
- `acl_cluster_extension(verb, scope, name, version, repository, comment)` loses its `sha256`
  argument.
- The profile's extension spec is `{"version": …, "repository": …}`. An item written before this spec
  keeps its `sha256` field in the stored JSON. Nothing reads it any more: the node agent must ignore
  it, and an UPDATE rewrites the item without it.
- The live apply installs and loads (`INSTALL … FROM <repo> VERSION …`, `LOAD … FROM <repo>`) with no
  digest step.

## Notes for the node agent (from the same review of the duckdb pin eb0d9df)

- An INSTALL from a user repository requires `allow_extension_repositories='allowed'` at startup; the
  default is `undecided`.
- The built-in HTTP client (an `http://` prefix) never sends `Authorization`, so a private repository
  needs https and httpfs. With httpfs loaded, an `http` repository URL is bumped to https anyway.
- An http secret's SCOPE matches by plain string prefix: emit scopes with a trailing slash
  (`https://host/tenant/channel/`).
- Moving a node between channels needs `FORCE INSTALL`, because `.info` records the repository URL.

## Tests

- C++ `test_acl_cluster_install`:
  - a `SHA256` clause is refused and leaves the profile and its version unchanged, on INSTALL and on
    UPDATE;
  - an install loads the extension and writes `{"version", "repository"}` with no hash.
- `test/sql/acl_cluster_profile.test`: the six-argument function.

## Alternatives

- **Keep sha256, computed without the signature**: stable across rotations, but a second integrity
  scheme beside DuckDB's, and the repository would have to publish it per build. It still protects
  only against a compromised repository *and* key.
- **Ignore the clause silently**: rejected - a pinned hash that does nothing is worse than none.
