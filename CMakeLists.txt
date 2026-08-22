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
    src/acl_introspection.cpp
    src/acl_parser_override.cpp
    src/acl_policy.cpp
    src/acl_policy_catalog.cpp
    src/acl_rewriter.cpp
    src/acl_token.cpp
    third_party/p256-m/p256-m.c)

# The Arrow Flight SQL door (specs/045). Opt-in via ACL_FLIGHT=1, because it links Arrow C++ and gRPC -
# 89 vcpkg ports, measured - and an ordinary build has no reason to pay for a door it does not open.
# Static targets, as the airport extension does: a loadable extension is dlopen'd RTLD_LOCAL, so what
# it needs has to be inside it.
#
# Excluded on WASM and MinGW, the way the scanners and quack are. WASM is not a maybe: the door is a
# gRPC server, and there is nothing there for it to listen on. MinGW is a maybe nobody has tested -
# Arrow and gRPC through vcpkg are an MSVC story - so it says no rather than failing somewhere deep.
if(DEFINED ENV{ACL_FLIGHT} AND NOT MINGW AND NOT ${WASM_ENABLED})
    # Arrow, its Flight libraries and gRPC come from the build's own vcpkg manifest tree, found the
    # way every other vcpkg dependency in this repo is found - the toolchain's own wrapper, nothing
    # hand-steered. Steering it by hand was tried at length and each attempt broke something else: a
    # classic-mode tree cannot be mixed with the manifest one, `CMAKE_FIND_PACKAGE_PREFER_CONFIG` makes
    # `find_package(OpenSSL)` miss vcpkg's wrapper, and pinning `<Pkg>_DIR` only moves the problem to
    # Arrow's own dependency lookups.
    #
    # Excluding the machine's prefixes below is the mechanism; `scripts/check_flight_deps.sh` is the
    # guarantee, and both are needed. Arrow's FindOpenSSLAlt.cmake on macOS *shells out to `brew`* when
    # OPENSSL_ROOT_DIR is unset, so reaching for the system is behaviour of the dependency rather than
    # an accident of our configuration - which is why the artifact gets read afterwards rather than
    # trusted.
    set(OPENSSL_USE_STATIC_LIBS ON)
    # The machine's own libraries are taken out of the search. Not belt-and-braces: without this the
    # artifact came out linked against homebrew's brotli and c-ares as *shared* objects, while the
    # static ones sat unused in the vcpkg tree - an extension that would not load on a machine without
    # homebrew. Arrow's Alt modules go looking on their own, so the exclusion has to be here rather
    # than in how we call find_package.
    foreach(system_prefix "/opt/homebrew" "/usr/local")
        if(EXISTS "${system_prefix}")
            list(APPEND CMAKE_IGNORE_PREFIX_PATH "${system_prefix}")
        endif()
    endforeach()
    find_package(Arrow CONFIG REQUIRED)
    find_package(ArrowFlight CONFIG REQUIRED)
    find_package(ArrowFlightSql CONFIG REQUIRED)
    # Named outright: Arrow's Flight libraries use gRPC's C core beyond what their own config carries
    # over, so leaving it implicit ends in unresolved grpc_* symbols at the very last step.
    find_package(gRPC CONFIG REQUIRED)

    add_subdirectory(src/flight)
    list(APPEND EXTENSION_SOURCES ${ACL_FLIGHT_SOURCES})
endif()

build_static_extension(${TARGET_NAME} ${EXTENSION_SOURCES})
build_loadable_extension(${TARGET_NAME} " " ${EXTENSION_SOURCES})

if(DEFINED ENV{ACL_FLIGHT} AND NOT MINGW AND NOT ${WASM_ENABLED})
    foreach(target ${EXTENSION_NAME} ${LOADABLE_EXTENSION_NAME})
        target_compile_definitions(${target} PRIVATE ACL_FLIGHT_ENABLED=1)
        target_link_libraries(${target}
            ArrowFlightSql::arrow_flight_sql_static
            ArrowFlight::arrow_flight_static
            Arrow::arrow_static
            gRPC::grpc++
            gRPC::grpc)
    endforeach()
endif()

# JWT verification uses duckdb's bundled mbedtls (RSA/SHA-256/HMAC); link it into the loadable too,
# so the artifact stays self-contained (the host binary does not export mbedtls symbols)
target_link_libraries(${EXTENSION_NAME} duckdb_mbedtls)
target_link_libraries(${LOADABLE_EXTENSION_NAME} duckdb_mbedtls)

install(
  TARGETS ${EXTENSION_NAME}
  EXPORT "${DUCKDB_EXPORT_SET}"
  LIBRARY DESTINATION "${INSTALL_LIB_DIR}"
  ARCHIVE DESTINATION "${INSTALL_LIB_DIR}")
