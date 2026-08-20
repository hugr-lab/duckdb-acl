cmake_minimum_required(VERSION 3.5)

# Set extension name here
set(TARGET_NAME acl)

set(EXTENSION_NAME ${TARGET_NAME}_extension)
set(LOADABLE_EXTENSION_NAME ${TARGET_NAME}_loadable_extension)

project(${TARGET_NAME})

set(CMAKE_CXX_STANDARD "17" CACHE STRING "C++ standard to enforce")
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(src/include)
# vendored P-256 ECDSA (ES256 verify; duckdb's trimmed mbedtls carries no ECDSA)
include_directories(third_party/p256-m)

set(EXTENSION_SOURCES
    src/acl_admin_functions.cpp
    src/acl_extension.cpp
    src/acl_parser_override.cpp
    src/acl_policy.cpp
    src/acl_policy_catalog.cpp
    src/acl_rewriter.cpp
    src/acl_token.cpp
    third_party/p256-m/p256-m.c)

build_static_extension(${TARGET_NAME} ${EXTENSION_SOURCES})
build_loadable_extension(${TARGET_NAME} " " ${EXTENSION_SOURCES})

# JWT verification uses duckdb's bundled mbedtls (RSA/SHA-256/HMAC); link it into the loadable too,
# so the artifact stays self-contained (the host binary does not export mbedtls symbols)
target_link_libraries(${EXTENSION_NAME} duckdb_mbedtls)
target_link_libraries(${LOADABLE_EXTENSION_NAME} duckdb_mbedtls)

install(
  TARGETS ${EXTENSION_NAME}
  EXPORT "${DUCKDB_EXPORT_SET}"
  LIBRARY DESTINATION "${INSTALL_LIB_DIR}"
  ARCHIVE DESTINATION "${INSTALL_LIB_DIR}")
