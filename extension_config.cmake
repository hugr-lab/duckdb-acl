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
    duckdb_extension_statically_link(ducklake)
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
# quack's pin is the duckdb submodule's own (`.github/config/extensions/quack.cmake`): 974927a, quack
# #278 of 2026-09-29 (CONNECT out of the transaction mechanism, the self-CONNECT guard, duckdb's
# v2.0-cyanoptera patches applied) - taken with the 2026-09-30 duckdb pin (spec 090). It builds with
# the patches duckdb carries for that pin (APPLY_PATCHES: the function-signature options; 0001
# touches a test only) - and
# the embedded server (third_party/quack) is the same commit, its copies patched the same way by
# sync.py. The block is ours rather than an include of duckdb's file for two reasons: quack is never
# named in duckdb_extension_statically_link (the client must stay a loadable, or its symbols and the
# embed's - both define duckdb::QuackServer & co. - meet in one static link, spec 063 strategy B; it
# was DONT_LINK before duckdb #26189), and no LOAD_TESTS (quack's own sqllogic suite is duckdb's CI's
# business, not ours).
if(DEFINED ENV{ACL_QUACK} AND NOT MINGW AND NOT ${WASM_ENABLED})
    duckdb_extension_load(json)
    duckdb_extension_load(autocomplete)
    include(${CMAKE_CURRENT_LIST_DIR}/duckdb/.github/config/extensions/httpfs.cmake)
    duckdb_extension_statically_link(json autocomplete httpfs)
    # Spec 105: our own patches to the quack CLIENT, on top of duckdb's (APPLY_PATCHES reads only duckdb's
    # directory). Each is upstream-bound and leaves when quack takes it (0001: duckdb/duckdb-quack#299).
    #   0001: count a FETCH in flight before claiming its index - the client could end a stream one batch
    #         short ("N-1 of N batches received"): CI's acl_quack_fetch_window.test, 2026-10-07.
    # duckdb's patch step refuses a clone with changes beyond its own patches ("Detected local changes"),
    # and it re-runs whenever FetchContent re-populates - so ours come OFF before duckdb_extension_load
    # and go back ON after it. A local checkout (DUCKDB_QUACK_DIRECTORY, DUCKDB_NEW_EXTENSION_BUILD) is
    # the developer's own tree and is left alone.
    file(GLOB ACL_QUACK_CLIENT_PATCHES ${CMAKE_CURRENT_LIST_DIR}/patches/quack/*.patch)
    list(SORT ACL_QUACK_CLIENT_PATCHES)
    set(ACL_QUACK_CLIENT_REVERSED ${ACL_QUACK_CLIENT_PATCHES})
    list(REVERSE ACL_QUACK_CLIENT_REVERSED)
    if(DEFINED FETCHCONTENT_BASE_DIR)
        set(ACL_QUACK_CLIENT_SRC ${FETCHCONTENT_BASE_DIR}/quack_extension_fc-src)
    else()
        set(ACL_QUACK_CLIENT_SRC ${CMAKE_BINARY_DIR}/_deps/quack_extension_fc-src)
    endif()
    if(EXISTS ${ACL_QUACK_CLIENT_SRC}/.git)
        foreach(ACL_PATCH IN LISTS ACL_QUACK_CLIENT_REVERSED)
            execute_process(COMMAND git apply --reverse --check ${ACL_PATCH} WORKING_DIRECTORY ${ACL_QUACK_CLIENT_SRC}
                            RESULT_VARIABLE ACL_PATCH_APPLIED OUTPUT_QUIET ERROR_QUIET)
            if(ACL_PATCH_APPLIED EQUAL 0)
                execute_process(COMMAND git apply --reverse ${ACL_PATCH} WORKING_DIRECTORY ${ACL_QUACK_CLIENT_SRC})
            endif()
        endforeach()
    endif()
    duckdb_extension_load(quack
        GIT_URL https://github.com/duckdb/duckdb-quack
        GIT_TAG 974927a394b188755284682b73398ed50e86316c
        SUBMODULES extension-ci-tools
        APPLY_PATCHES
    )
    FetchContent_GetProperties(quack_extension_fc SOURCE_DIR ACL_QUACK_FETCHED)
    if("${ACL_QUACK_FETCHED}" STREQUAL "")
        message(WARNING "spec 105: the quack client is not a fetched clone - patches/quack/ is NOT applied")
        set(ACL_QUACK_CLIENT_PATCHES "")
    endif()
    foreach(ACL_PATCH IN LISTS ACL_QUACK_CLIENT_PATCHES)
        execute_process(COMMAND git apply ${ACL_PATCH} WORKING_DIRECTORY ${ACL_QUACK_FETCHED}
                        RESULT_VARIABLE ACL_PATCH_RESULT)
        if(NOT ACL_PATCH_RESULT EQUAL 0)
            message(FATAL_ERROR "spec 105: ${ACL_PATCH} does not apply to the quack client at ${ACL_QUACK_FETCHED}")
        endif()
        message(STATUS "spec 105: quack client patched with ${ACL_PATCH}")
    endforeach()
endif()
