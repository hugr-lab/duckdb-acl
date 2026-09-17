# This file is included by DuckDB's build system. It specifies which extension to load

# Extension from this repo
duckdb_extension_load(acl
    SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}
    LOAD_TESTS
)

# icu: the client-local rendering settings a session may set (spec 068 - TimeZone, Calendar) are
# ICU's, so the test binary carries it; a deployed duckdb autoloads it. In-tree, no vcpkg.
duckdb_extension_load(icu)

# Integration builds (specs/005): also build the source scanners the integration scenarios attach
# through. Opt-in via ACL_INTEGRATION=1 so regular/release builds stay lean. Pins and patches come
# from the duckdb submodule's own extension config, so they are the versions tested against the
# exact duckdb commit we track.
if(DEFINED ENV{ACL_INTEGRATION} AND NOT MINGW AND NOT ${WASM_ENABLED})
    # postgres_scanner: the submodule's own pin and patches. Until 2026-09-08 this was a pin of ours
    # plus a patch restoring postgres_execute (PR #78): duckdb-postgres #552 had made it an alias of
    # postgres_query, which prepares the SQL, and PostgreSQL refuses a multi-command string in a
    # prepared statement - exactly what DuckLake's postgres metadata manager flushes per commit.
    # Upstream fixed it from both sides (duckdb-postgres fffcb35, "Allow non-preparable queries in
    # postgres_query"; ducklake 7f2f82c, the batches split), and the duckdb 2.0 release branch we
    # track pins fffcb35 - so the submodule's include is the whole story again. (A pin change trips
    # FetchContent's git-update on a stale _deps clone: wipe build/*/_deps/postgres_scanner_* and
    # rebuild - CI is always fresh.)
    include(${CMAKE_CURRENT_LIST_DIR}/duckdb/.github/config/extensions/postgres_scanner.cmake)
    # ducklake: the submodule's own pin and patches again, since 2026-09-17. From 2026-09-10 to then
    # this was a pin of ours (c0a2060, ducklake's main of 2026-09-10) plus three patches in
    # patches/ducklake/ (the TableCatalogEntry columns virtual, the merge-into action pipelines, the
    # Literal API), because the branch's own pin (eb7b95d) flushed its postgres metadata as ONE
    # multi-command string - refused by a prepared statement since duckdb-postgres #552 - and
    # ducklake took the split only in 7f2f82c. The 2.0 branch now pins e8924cf (106 commits past
    # 7f2f82c) and carries the equivalents of all three upstream, with its own patch for the unified
    # QueryResult (#25477) on top - so the include is the whole story, as for postgres_scanner.
    # (A pin change trips FetchContent's git-update on a stale _deps clone: wipe
    # build/*/_deps/ducklake_extension_fc-* and rebuild - CI is always fresh.)
    # Local caveat: ducklake has changed the layout of metadata version `1.1-dev1` in place before
    # (min_is_exact/max_is_exact, no version bump), so a lake a previous pin wrote can be unreadable
    # ("Referenced column ... not found"); CI starts its postgres empty, a developer's persistent
    # catalog is recreated (`DROP DATABASE ducklake_catalog; CREATE DATABASE ducklake_catalog;`).
    include(${CMAKE_CURRENT_LIST_DIR}/duckdb/.github/config/extensions/ducklake.cmake)
    # mysql_scanner is currently disabled at the submodule pin ("patches do not apply"); flip its
    # gate here the moment the submodule re-enables it.
    set(MYSQL_SCANNER_ENABLED OFF)
    include(${CMAKE_CURRENT_LIST_DIR}/duckdb/.github/config/extensions/mysql_scanner.cmake)
endif()

# SQL Server scanner (hugr-lab/mssql-extension) for the integration scenarios. A separate opt-in;
# its openssl/simdutf dependencies arrive through the merged vcpkg manifest. The pin is a commit on
# that repo's main, which now tracks duckdb main as we do (spec 033) - re-pin when it moves and the
# scenarios need something newer.
if(DEFINED ENV{ACL_INTEGRATION_MSSQL} AND NOT MINGW AND NOT ${WASM_ENABLED})
    duckdb_extension_load(mssql
        DONT_LINK
        GIT_URL https://github.com/hugr-lab/mssql-extension
        GIT_TAG 1d74ae2c0e6c3fc963d3915784a36a7d06f0b6d1
    )
endif()

# The quack door (specs/041): duckdb's own client/server protocol, built here so the door can be
# tested against a real server rather than only through its callbacks. Opt-in via ACL_QUACK=1, since
# it pulls openssl/curl through vcpkg and quack itself is pre-release - the contract we plug into
# (its authentication/authorization callbacks) can move, and a pinned build is how we find out.
# quack needs json + autocomplete (core) and httpfs, which it pins itself; we take duckdb's own pin
# so everything builds against the commit we track.
#
# quack's pin is ONE commit past the duckdb submodule's own (984d45d in
# `.github/config/extensions/quack.cmake`): fa3f82c, quack #212 of 2026-09-14, which surfaces error
# types to the client. It builds with the four patches duckdb carries for its own pin (APPLY_PATCHES:
# the TableCatalogEntry columns virtual, a binder include, the Literal API, the unified QueryResult),
# which apply to #212 unchanged (checked 2026-09-17) - and the embedded server (third_party/quack) is
# the same commit, its copies patched the same way by sync.py. DONT_LINK is ours: the client must
# stay a loadable, or its symbols and the embed's (both define duckdb::QuackServer & co.) meet in one
# static link (spec 063, strategy B).
if(DEFINED ENV{ACL_QUACK} AND NOT MINGW AND NOT ${WASM_ENABLED})
    duckdb_extension_load(json)
    duckdb_extension_load(autocomplete)
    include(${CMAKE_CURRENT_LIST_DIR}/duckdb/.github/config/extensions/httpfs.cmake)
    duckdb_extension_load(quack
        DONT_LINK
        GIT_URL https://github.com/duckdb/duckdb-quack
        GIT_TAG fa3f82c53cf587838d55efbd24f31b0c055684a9
        SUBMODULES extension-ci-tools
        APPLY_PATCHES
    )
endif()
