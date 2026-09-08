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
    # ducklake: pinned AHEAD of the submodule's own pin (eb7b95d, 2026-07-23), which flushes its postgres
    # metadata as ONE multi-command string - refused by a prepared statement since duckdb-postgres #552,
    # and duckdb-postgres fffcb35's `prepare := false` is an opt-in the caller must take. ducklake took
    # it in 7f2f82c (2026-09-01, the batches split); 7f0ece3 is that plus its test. It targets duckdb
    # 1b3c92a - an ancestor of the 2.0 branch - and needs TWO of the branch's ducklake patches (0010,
    # the merge-into action pipelines; 0011, the TableCatalogEntry columns virtual), carried in
    # patches/ducklake/ and applied through
    # the FetchContent pre-declare (CMake keeps the first declare for a content name; the loader below
    # has no patch-dir parameter). Drop all of this for the submodule's include once the submodule's
    # own pin passes 7f2f82c. (A pin change trips FetchContent's git-update on a stale _deps clone:
    # wipe build/*/_deps/ducklake_extension_fc-* and rebuild - CI is always fresh.)
    include(FetchContent)
    if(NOT Python3_EXECUTABLE)
        find_package(Python3 COMPONENTS Interpreter REQUIRED)
    endif()
    FetchContent_Declare(
        ducklake_extension_fc
        GIT_REPOSITORY https://github.com/duckdb/ducklake
        GIT_TAG 7f0ece3aa1f5a7a9b3777874613c5c630eb9e98f
        GIT_SUBMODULES ""
        PATCH_COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_LIST_DIR}/duckdb/scripts/apply_extension_patches.py ${CMAKE_CURRENT_LIST_DIR}/patches/ducklake/
        SOURCE_SUBDIR __duckdb_no_add_subdirectory__
    )
    duckdb_extension_load(ducklake
        GIT_URL https://github.com/duckdb/ducklake
        GIT_TAG 7f0ece3aa1f5a7a9b3777874613c5c630eb9e98f
    )
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
# quack's pin is the duckdb submodule's own (`.github/config/extensions/quack.cmake`), with the
# patches duckdb carries for it (APPLY_PATCHES - at the 2.0 pin, the TableCatalogEntry columns
# virtual); the same commit the embedded server (third_party/quack) is checked out at. DONT_LINK is
# ours: the client must stay a loadable, or its symbols and the embed's (both define
# duckdb::QuackServer & co.) meet in one static link (spec 063, strategy B).
if(DEFINED ENV{ACL_QUACK} AND NOT MINGW AND NOT ${WASM_ENABLED})
    duckdb_extension_load(json)
    duckdb_extension_load(autocomplete)
    include(${CMAKE_CURRENT_LIST_DIR}/duckdb/.github/config/extensions/httpfs.cmake)
    duckdb_extension_load(quack
        DONT_LINK
        GIT_URL https://github.com/duckdb/duckdb-quack
        GIT_TAG f4328c5333e88756a97a3e53118a695252befb4e
        SUBMODULES extension-ci-tools
        APPLY_PATCHES
    )
endif()
