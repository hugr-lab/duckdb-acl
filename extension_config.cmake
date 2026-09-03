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
# exact duckdb commit we track - except postgres_scanner, pinned below with one patch of ours.
if(DEFINED ENV{ACL_INTEGRATION} AND NOT MINGW AND NOT ${WASM_ENABLED})
    # postgres_scanner: the submodule's own pin (c91ea57) plus ONE patch of ours. duckdb-postgres
    # #552 (2026-08-11) made postgres_execute an alias of postgres_query, which PREPAREs the SQL -
    # and PostgreSQL refuses multi-command strings in a prepared statement, which is exactly what
    # DuckLake's postgres metadata manager flushes through postgres_execute (one batched string per
    # commit). ducklake's own CI still pins duckdb-postgres from before the alias, so upstream has
    # not seen it break yet - it will on ducklake's next duckdb bump. No upstream commit both
    # compiles against the duckdb main we track (post-alias commits carry the API adaptations) and
    # still has the real postgres_execute, so patches/postgres_scanner/ restores it (PQexec, simple
    # protocol) on top of the pin. The FetchContent_Declare below wins over the one
    # register_external_extension makes for the same content name (CMake keeps the first declare),
    # which is how our PATCH_COMMAND gets in - duckdb_extension_load has no patch-dir parameter.
    # Drop all of this for the submodule's include once upstream restores postgres_execute.
    # (A patched _deps clone is dirty by design, so a later pin change trips the git-update stash
    # dance: wipe build/*/_deps/postgres_scanner_extension_fc-* and rebuild - CI is always fresh.)
    include(FetchContent)
    if(NOT Python3_EXECUTABLE)
        find_package(Python3 COMPONENTS Interpreter REQUIRED)
    endif()
    FetchContent_Declare(
        postgres_scanner_extension_fc
        GIT_REPOSITORY https://github.com/duckdb/duckdb-postgres
        GIT_TAG c91ea5779322c97dfff1940f67b3a4d5b6a1e07e
        GIT_SUBMODULES "database-connector"
        PATCH_COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_LIST_DIR}/duckdb/scripts/apply_extension_patches.py ${CMAKE_CURRENT_LIST_DIR}/patches/postgres_scanner/
        SOURCE_SUBDIR __duckdb_no_add_subdirectory__
    )
    duckdb_extension_load(postgres_scanner
        DONT_LINK
        GIT_URL https://github.com/duckdb/duckdb-postgres
        GIT_TAG c91ea5779322c97dfff1940f67b3a4d5b6a1e07e
        SUBMODULES database-connector
    )
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
# quack targets duckdb f1c54da78b (its own submodule pin, 2026-08-25), and the submodule follows it: at
# an earlier pin it needed
# `RemoteCapability::EXECUTE_STATEMENT` and the `RemoteExecute(ClientContext &,
# unique_ptr<SQLStatement>)` overload, and got neither.
if(DEFINED ENV{ACL_QUACK} AND NOT MINGW AND NOT ${WASM_ENABLED})
    duckdb_extension_load(json)
    duckdb_extension_load(autocomplete)
    include(${CMAKE_CURRENT_LIST_DIR}/duckdb/.github/config/extensions/httpfs.cmake)
    duckdb_extension_load(quack
        DONT_LINK
        GIT_URL https://github.com/duckdb/duckdb-quack
        GIT_TAG f28823ddb9b6b9c22e72176f2b8db00cbc8b6e9b
    )
endif()
