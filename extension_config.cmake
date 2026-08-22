# This file is included by DuckDB's build system. It specifies which extension to load

# Extension from this repo
duckdb_extension_load(acl
    SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}
    LOAD_TESTS
)

# Integration builds (specs/005): also build the source scanners the integration scenarios attach
# through. Opt-in via ACL_INTEGRATION=1 so regular/release builds stay lean. Pins and patches come
# from the duckdb submodule's own extension config, so they are the versions tested against the
# exact duckdb commit we track.
if(DEFINED ENV{ACL_INTEGRATION} AND NOT MINGW AND NOT ${WASM_ENABLED})
    include(${CMAKE_CURRENT_LIST_DIR}/duckdb/.github/config/extensions/postgres_scanner.cmake)
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
# quack targets duckdb e20aeb78, which is why the submodule moved there: at our previous pin it needed
# `RemoteCapability::EXECUTE_STATEMENT` and the `RemoteExecute(ClientContext &,
# unique_ptr<SQLStatement>)` overload, and got neither.
if(DEFINED ENV{ACL_QUACK} AND NOT MINGW AND NOT ${WASM_ENABLED})
    duckdb_extension_load(json)
    duckdb_extension_load(autocomplete)
    include(${CMAKE_CURRENT_LIST_DIR}/duckdb/.github/config/extensions/httpfs.cmake)
    duckdb_extension_load(quack
        DONT_LINK
        GIT_URL https://github.com/duckdb/duckdb-quack
        GIT_TAG 2ca17797acfed0e29187482700db30d0b01a7954
    )
endif()
