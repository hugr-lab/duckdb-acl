# This file is included by DuckDB's build system. It specifies which extension to load

# Spec 106: clang-cl with MSVC-built libraries.
#
# The mismatch. Since extension-ci-tools #428 (2026-10-07), windows_amd64 is compiled by clang-cl,
# while vcpkg's ports (Arrow, gRPC, ...) stay MSVC builds. Both put a string literal into a COMDAT of
# the same name (`??_C@...`), and the linker keeps one copy. MSVC aligns its copy to 16 bytes and
# reads it with `movaps`; clang-cl aligns its copy to 1.
#
# The crash. When clang-cl's copy wins and lands off a 16-byte boundary, Arrow's static initializer of
# `base64_chars` (the alphabet duckdb's blob.hpp also spells) faults before main. It comes and goes
# with the layout of .rdata.
#
# The fix. /GF- turns string pooling off for what clang-cl compiles, so its literals stay private to
# each object and every pooled literal the link selects is an MSVC one. This file is included at the
# top level before duckdb adds src/, so the option reaches duckdb's own objects, where the shared
# alphabet lives. Upstream: duckdb/extension-ci-tools#430.
if(MSVC AND CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    add_compile_options(/GF-)
endif()

# Extension from this repo
duckdb_extension_load(acl
    SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}
    LOAD_TESTS
)
# Since duckdb #26189 (the 2026-09-30 pin, spec 091) an extension is linked into duckdb only when a
# config names it with duckdb_extension_statically_link - the default flipped, DONT_LINK is gone. The
# test binary carries acl (and each opt-in block below names what it linked before the flip).
duckdb_extension_statically_link(acl)

# icu: the client-local rendering settings a session may set (spec 068 - TimeZone, Calendar) are
# ICU's, so the test binary carries it; a deployed duckdb autoloads it. In-tree, no vcpkg.
duckdb_extension_load(icu)
duckdb_extension_statically_link(icu)

# Integration builds (specs/005): also build the source scanners the integration scenarios attach
# through. Opt-in via ACL_INTEGRATION=1 so regular/release builds stay lean. Pins and patches come
# from the duckdb submodule's own extension config, so they are the versions tested against the
# exact duckdb commit we track.
if(DEFINED ENV{ACL_INTEGRATION} AND NOT MINGW AND NOT ${WASM_ENABLED})
    # postgres_scanner: duckdb-postgres's main (spec 131, ed73241 - the default application_name in a URI
    # connection string), five commits past the 2.0 branch's pin 9671d2c on the same duckdb submodule; duckdb carries
    # no patch for it. Until 2026-09-08 this was a pin of ours plus a patch restoring postgres_execute (PR #78);
    # from then to spec 131 the submodule's own include. (A pin change trips FetchContent's git-update on a stale
    # _deps clone: wipe build/*/_deps/postgres_scanner_* and rebuild - CI is always fresh.)
    duckdb_extension_load(postgres_scanner
        GIT_URL https://github.com/duckdb/duckdb-postgres
        GIT_TAG c0f5a3c0c4b68b02afbf669d36d7f0e503985c88
        SUBMODULES database-connector
    )
    # ducklake: duckdb v2.0.0's own pin, 417a911 (spec 141; ducklake's main from spec 131, ca86db0 from spec 133, 49
    # commits before it), with no patch, ours included: it calls
    # `postgres_clear_cache` (spec 128's patches/ducklake/9001 is gone). From 2026-09-17 to spec 131 the submodule's
    # own pin and patches; before that a pin of ours with three patches. Only the test build carries ducklake -
    # nothing of it reaches acl's artifact. (A pin change trips FetchContent's git-update on a stale _deps clone:
    # wipe build/*/_deps/ducklake_extension_fc-* and rebuild - CI is always fresh.)
    # Local caveat: ducklake has changed the layout of metadata version `1.1-dev1` in place before
    # (min_is_exact/max_is_exact, no version bump), so a lake a previous pin wrote can be unreadable
    # ("Referenced column ... not found"); CI starts its postgres empty, a developer's persistent
    # catalog is recreated (`DROP DATABASE ducklake_catalog; CREATE DATABASE ducklake_catalog;`).
    duckdb_extension_load(ducklake
        LOAD_TESTS
        GIT_URL https://github.com/duckdb/ducklake
        GIT_TAG 417a9117f590e8141742ac0579d02f6a90162e37
    )
    duckdb_extension_statically_link(ducklake)
    # mysql_scanner: the submodule's own pin and patches. It was disabled at the submodule's pin until
    # 2026-10-12 ("patches do not apply"); the 664aafa pin (spec 123) builds it again, so the mysql
    # scenarios run (ACL_MYSQL_DSN).
    include(${CMAKE_CURRENT_LIST_DIR}/duckdb/.github/config/extensions/mysql_scanner.cmake)
endif()

# SQL Server scanner (hugr-lab/mssql-extension) for the integration scenarios. A separate opt-in;
# its openssl/simdutf dependencies arrive through the merged vcpkg manifest. The pin is a commit on
# that repo's main built on the same duckdb (v2.0.0 since spec 141) - re-pin when it moves and the
# scenarios need something newer.
if(DEFINED ENV{ACL_INTEGRATION_MSSQL} AND NOT MINGW AND NOT ${WASM_ENABLED})
    duckdb_extension_load(mssql
        GIT_URL https://github.com/hugr-lab/mssql-extension
        GIT_TAG 6df11bceb032624cbafb4be044a7f3bf5252739a
    )
endif()

# The quack door (specs/041): duckdb's own client/server protocol, built here so the door can be
# tested against a real server rather than only through its callbacks. Opt-in via ACL_QUACK=1, since
# it pulls openssl/curl through vcpkg and quack itself is pre-release - the contract we plug into
# (its authentication/authorization callbacks) can move, and a pinned build is how we find out.
# quack needs json + autocomplete (core) and httpfs, which it pins itself; we take duckdb's own pin
# so everything builds against the commit we track.
#
# quack's pin is the duckdb submodule's own (`.github/config/extensions/quack.cmake`): f96420e since the v2.0.0 pin
# (spec 141; e7a9be3 from spec 133, 974927a from spec 090). duckdb builds it without patches since v2.0.0 (its two
# went into quack itself), and so does the embedded server (third_party/quack, the same commit; sync.py copies it as
# it is when duckdb's quack.cmake applies none). Spec 105's own client patch left with e7a9be3 (#305). The block is
# ours rather than an include of duckdb's file for two reasons: quack is never named in
# duckdb_extension_statically_link (the client must stay a loadable, or its symbols and the embed's - both define
# duckdb::QuackServer & co. - meet in one static link, spec 063 strategy B; it was DONT_LINK before duckdb #26189), and
# no LOAD_TESTS (quack's own sqllogic suite is duckdb's CI's business, not ours).
if(DEFINED ENV{ACL_QUACK} AND NOT MINGW AND NOT ${WASM_ENABLED})
    duckdb_extension_load(json)
    duckdb_extension_load(autocomplete)
    include(${CMAKE_CURRENT_LIST_DIR}/duckdb/.github/config/extensions/httpfs.cmake)
    duckdb_extension_statically_link(json autocomplete httpfs)
    duckdb_extension_load(quack
        GIT_URL https://github.com/duckdb/duckdb-quack
        GIT_TAG f96420ed46aee9c42064bdb99ddfd1230d6c0086
        SUBMODULES extension-ci-tools
    )
endif()
