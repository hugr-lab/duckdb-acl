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
