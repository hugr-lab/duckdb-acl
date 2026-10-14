# Spec 127: the split's move - the platform part leaves duckdb-acl for hugr-node

- **Status**: implemented (accepted by the owner 2026-10-13: the name hugr_node)
- **Date**: 2026-10-13
- **Author**: the agent, at the owner's ask (design/080 variant 2, step 3; specs 125 / 126 prepared it)

## Summary

The platform part of today's acl - `acl_cluster.cpp` and its tests, the cluster profile, node groups' traits, drift,
the deployment and the `cluster` bundle (design/080 group A) - moves into `hugr-lab/hugr-node` (BUSL 1.1, public),
with its history. hugr-node builds **one extension** from duckdb-acl's sources (a submodule) and its own; duckdb-acl
then removes the part and is the open node. Nothing is lost: the move lands in hugr-node and passes its tests before
duckdb-acl deletes anything.

## Problem

Spec 126 left group A plugging into the core through registration points, and proved the core builds and passes
without it (`ACL_NO_CLUSTER`). The code still lives in the MIT repository; the platform release needs it in the
BUSL one, built into the platform node's extension.

## Design

### The extension hugr-node builds

- **Name `hugr_node`**: one loadable that is the platform node's whole acl - duckdb-acl's sources (every
  `acl_*` function, the doors, the parser override) plus the platform part. A platform node loads `hugr_node`
  instead of `acl` (design/017 §3.2's `INSTALL hugr_node FROM hugr; LOAD hugr_node`); the two are never loaded
  together (both would register the same functions - LOAD refuses the second). acl-otel and tresor reach acl
  through the ObjectCache contracts (spec 069 / 078), never by the extension's name, so they work beside either.
- **Why not `acl` again**: a second artifact named `acl` would make "which acl is this node running" a question of
  which repository it was installed from; a distinct name answers it in `duckdb_extensions()`.

### How duckdb-acl is built into it

- duckdb-acl keeps its build; it gains **`acl_sources.cmake`**: the source list, include directories and the
  options (Flight, the quack embed, the vcpkg dependencies) its `CMakeLists.txt` now sets inline. Its own build
  includes it unchanged.
- **An embedding hook in acl's entry**: `acl_extension.cpp` exposes `LoadAclCore(loader) -> shared_ptr<PolicyStore>`
  (today's `LoadInternal` returning the store); acl's `DUCKDB_CPP_EXTENSION_ENTRY(acl, …)` is compiled only when acl
  is its own extension (`ACL_EMBEDDED` undefined). hugr-node's entry calls `LoadAclCore`, then registers its part
  (`RegisterAclCluster(loader, store)` - spec 126's points).
- **hugr-node** has the submodules duckdb (the same pin as duckdb-acl), extension-ci-tools and duckdb-acl (a tag or a
  commit of its main); its `CMakeLists.txt` includes `duckdb-acl/acl_sources.cmake`, adds `src/` and defines
  `ACL_EMBEDDED`. Pins follow duckdb-acl's the same day (as acl-otel and tresor).

### What moves, with its history

`git filter-repo` on these paths of duckdb-acl (history kept), then into hugr-node:

- `src/acl_cluster.cpp`, `src/include/acl_cluster.hpp`;
- `test/sql/cluster/` (the 9 files of group A tests, spec 126), `test/cpp/test_acl_cluster_install.cpp`;
- the cluster part of the docs (`website/docs/management-sql.md` §ACL CLUSTER, the node-group parts of
  `serving.md`) - copied as hugr-node's docs; duckdb-acl's docs say the profile is the platform's.

What stays in duckdb-acl: the registration points, `PolicyStore::NodeTraits`, the cluster-profile tables in the
schema (v16 / v18 steps are history), `acl_placement.hpp` (the core judges placement against the traits), the specs
(093 / 096 / 118 keep their history; a line says where the code went).

### Order - nothing is lost

1. Tag `pre-platform-split` on duckdb-acl main.
2. duckdb-acl PR A: `acl_sources.cmake`, `LoadAclCore`, `ACL_EMBEDDED` - no behaviour change (merged first: hugr-node
   needs it).
3. hugr-node PR: the moved files with their history, the build, the tests (`require hugr_node`), CI. Green before 4.
4. duckdb-acl PR B: remove the moved files (`ACL_NO_CLUSTER` becomes the only build and is dropped as an option);
   the open node is the release build.

## Enforcement & security

No rule changes: the moved code is the same code, plugged into the same points; the authorizer and the audit stay in
the core of both builds. An open node (duckdb-acl) cannot grant `cluster` (spec 126) and has no profile; a platform
node (hugr_node) behaves as today's acl with the cluster part. A node never loads both.

## Tests

- duckdb-acl: the whole gate after PR B (the open node; `test/sql/cluster/` gone); after PR A unchanged.
- hugr-node: its own suite - the moved `test/sql/cluster/` (now `require hugr_node`) and a smoke that the embedded acl
  answers (`acl_*` functions present, a principal query rewritten); its CI builds linux (and the distribution matrix
  as duckdb-acl's).
- The history: `git log --follow` of `src/acl_cluster.cpp` in hugr-node reaches spec 093's first commit.

## Alternatives considered

- **Name the combined extension `acl`**: same name, two builds - the node's identity would depend on where it was
  installed from.
- **Copy the files without history**: loses who wrote what and why; the owner asked that nothing be lost.
- **hugr_node as a second loadable beside acl** (variant 3): needs the contracts in duckdb-ext-common; the owner chose
  variant 2 for the release window.

## As built - PR A (2026-10-13)

- `acl_sources.cmake`: the source list (`${ACL_ROOT}/…`), include directories, packages and options that
  `CMakeLists.txt` set inline; duckdb's paths are the build's own tree (`CMAKE_SOURCE_DIR` - the duckdb a build
  runs from, so an embedding build's own submodule, never acl's by path); `acl_configure_targets(…)` puts acl's
  compile definitions and libraries on the including build's targets. acl's `CMakeLists.txt` is the header, the
  include, the two targets, the configure call and the install.
- `LoadAclCore(loader)` (`acl_extension.hpp`) is acl's whole load, answering the store; under `ACL_EMBEDDED` acl's
  entry point and `AclExtension` are not compiled, and `RegisterAclCluster` is left to the embedder.
- Gate (macOS): both builds (with the cluster part 112 files, `ACL_NO_CLUSTER=1` 103), test-cpp, integration,
  test-flight, lints; test-e2e green but for an intermittent mssql-leg partial-load reading under RCSI (2 of 4 runs
  today) - the mssql scanner's, raised with mssql-extension; the leg is opt-in and not in CI.

## As built - the move and PR B (2026-10-13)

- **hugr-node #1**: the moved files with their history (14 commits from spec 093; `git log --follow
  src/acl_cluster.cpp` reaches it), merged with a merge commit; the build (`hugr_node` = acl built in + the platform
  part), the moved tests (`require hugr_node`), a smoke, CI. Its docs carry this repository's cluster section
  (`docs/cluster.md`), and the Flight e2e's node-group block is kept there verbatim (`test/e2e/`) until it has an e2e.
- **PR B**: `src/acl_cluster.cpp`, `src/include/acl_cluster.hpp`, `test/sql/cluster/`,
  `test/cpp/test_acl_cluster_install.cpp` removed; `ACL_NO_CLUSTER` gone (the only build is the open node);
  `RegisterAclCluster` no longer called; the fold lint's cluster entries dropped; the Flight e2e's node-group block
  moved; the docs point to hugr-node (management-sql's node groups and cluster profile, lineage, the platform catalog,
  security, serving); `acl_lineage_status()`'s hint says `SET GLOBAL`.
- **Left in the core, inert on an open node**: the audit object of an `acl_cluster_*` call (parser override), the
  resource-group drop guard over `cluster_items`, the INFRASTRUCTURE right's refusal - each reached only where the
  platform part registers those calls.
- Gate (macOS, the open node): `test/sql/*` (103 files), test-cpp, integration, test-flight, test-e2e, harness,
  lints, schema-check.

## Addendum - beside tresor in hugr_node (2026-10-14)

hugr-node spec 002 builds tresor into `hugr_node` beside acl (tresor spec 024) and removes `acl_deployment` (a
hugr_node node is a cluster node by construction). This repository's side:

- **acl's OIDC definitions are properties of its own sources**, not of the target (tresor spec 024's follow-up):
  `DUCKDB_EXT_COMMON_OIDC_NAMESPACE=acl` and, in the flight build, `DUCKDB_EXT_COMMON_OIDC_TLS=1` are set by
  `acl_sources.cmake` on `EXTENSION_SOURCES` (exactly acl's there); `acl_configure_targets` keeps `ACL_FLIGHT_ENABLED`
  and the libraries. In hugr_node the one target also compiles tresor's copy of the core (`duckdb::tresor::oidc`,
  source-level `=tresor`), which a target-wide `=acl` reached as a redefinition on every tresor TU. Checked on the
  release build's compile commands: all of acl's TUs (its sources, the quack embed, p256-m, the OIDC core) carry exactly
  the two definitions, no duckdb TU carries either; only duckdb's generated `acl_describe.c` lost them (it never read
  them).
- The comments and docs that named `acl_deployment` name the trait (`NodeTraits::cluster_node`) and hugr_node.
- **A test of the open node's identity** (`platform_views.test`): `console_info` says `standalone`, the `cluster`
  bundle is not grantable, no `drift` view and no `cluster_*` call is offered - the case that left with the cluster
  tests (spec 127 PR B) and was removed there by hugr-node spec 002.
