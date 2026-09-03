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
# the OIDC client core (spec 060) compiles duckdb's bundled httplib in its one TU and parses
# responses with the bundled yyjson
include_directories(duckdb/third_party/httplib duckdb/third_party/yyjson/include)

set(EXTENSION_SOURCES
    src/acl_admin_functions.cpp
    src/acl_catalog_rpc.cpp
    src/acl_extension.cpp
    src/acl_introspection.cpp
    src/acl_admin_sql.cpp
    src/acl_parser_override.cpp
    src/acl_door_auth.cpp
    src/acl_door_common.cpp
    src/oidc/acl_oidc.cpp
    src/oidc/acl_oidc_secret.cpp
    src/acl_policy.cpp
    src/acl_policy_catalog.cpp
    src/acl_rewriter.cpp
    src/acl_token.cpp
    third_party/p256-m/p256-m.c)

# The Arrow Flight SQL door (specs/045): built by default, because it is what a client with an ADBC or
# JDBC driver connects to - a feature of the extension rather than an option for people who build it
# themselves. Static targets, as the airport extension does: a loadable extension is dlopen'd
# RTLD_LOCAL, so what it needs has to be inside it.
#
# Excluded on WASM, and only there. The door is a gRPC server and there is nothing in WASM for it to
# listen on; community-extensions is told the same thing through `excluded_platforms` in
# packaging/community-extensions/description.yml. MinGW is *not* excluded: `airport` ships Arrow Flight
# through the same pipeline with only WASM excluded, so it builds there.
#
# ACL_NO_FLIGHT=1 leaves it out, for a fast local build; it drops the vcpkg step with it.
if(NOT ${WASM_ENABLED} AND NOT DEFINED ENV{ACL_NO_FLIGHT})
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
    # the OIDC core's https client (spec 060): the same vcpkg tree that feeds Arrow/gRPC carries
    # OpenSSL, so the TLS variant of the client exists exactly when the flight door does
    find_package(OpenSSL REQUIRED)

    add_subdirectory(src/flight)
    list(APPEND EXTENSION_SOURCES ${ACL_FLIGHT_SOURCES})
endif()

# The embedded quack door (specs/063): quack's own server, compiled INTO acl rather than reached
# through a loopback proxy (the spec-062 front it replaces). The server graph comes from the pinned
# `third_party/quack` submodule; only the httplib-facing files are acl-owned adapted copies
# (src/quack_embed/) - the namespace-alias shim plus the TLS + /.well-known listener. Everything acl
# registers is `acl_quack_*`-named (spec 063), so a standalone quack loaded alongside never collides.
# WASM is the only exclusion - it has nothing to listen on (there a WASM duckdb is a quack CLIENT, not
# a server). The graph is portable std/httplib, so it builds on every other target incl. MinGW, which
# only needs winsock linked by hand below (its GCC ignores httplib's MSVC `#pragma comment` link).
if(NOT ${WASM_ENABLED} AND NOT DEFINED ENV{ACL_NO_QUACK_EMBED})
    set(QUACK_SRC ${CMAKE_CURRENT_LIST_DIR}/third_party/quack/src)
    set(QUACK_EMBED ${CMAKE_CURRENT_LIST_DIR}/src/quack_embed)
    include_directories(
        ${QUACK_EMBED}/include
        ${QUACK_SRC}/include
        ${CMAKE_CURRENT_LIST_DIR}/duckdb/third_party/httplib
        ${CMAKE_CURRENT_LIST_DIR}/duckdb/extension/autocomplete/include
        ${CMAKE_CURRENT_LIST_DIR}/duckdb/third_party/mbedtls/include)
    # The embedded server = quack's protocol machinery, split two ways. PRISTINE from the submodule:
    # the transport-agnostic files that need no change. VENDORED under src/quack_embed/: the listener
    # (acl-owned: TLS + /.well-known + public bind), the registration, and the few TUs that read the
    # acl_quack_* settings / drain through acl_quack_scan_data (regenerated by src/quack_embed/sync.py).
    # The client/storage half, the extension entrypoint, quack_start_stop and the client admin table
    # functions are all excluded.
    # NB: the acl-owned copies carry an `acl_embed_` basename, NOT quack's original - a same-named .cpp
    # in two targets of one build (here and the FetchContent quack loadable) is asking for a compiler-
    # cache / build-graph mixup (a stale ccache handed quack the acl-renamed object, so the quack
    # loadable tried to register acl_quack_scan_data). Unique names make that impossible.
    set(ACL_QUACK_EMBED_SOURCES
        ${QUACK_EMBED}/acl_quack_http_server.cpp
        ${QUACK_EMBED}/acl_quack_embed.cpp
        ${QUACK_EMBED}/acl_embed_server.cpp
        ${QUACK_EMBED}/acl_embed_result_cache.cpp
        ${QUACK_EMBED}/acl_embed_fetch_collector.cpp
        ${QUACK_EMBED}/acl_embed_rebalancer_sink.cpp
        ${QUACK_EMBED}/acl_embed_scan_from_client.cpp
        ${QUACK_SRC}/quack_message.cpp
        ${QUACK_SRC}/serialize_quack_message.cpp
        ${QUACK_SRC}/quack_data_stream.cpp
        ${QUACK_SRC}/quack_rebalancer_core.cpp
        ${QUACK_SRC}/quack_uri.cpp
        ${QUACK_SRC}/quack_log.cpp)
    # quack hardcodes `duckdb_httplib::` — force-include the namespace bridge into every embed TU so
    # those names resolve onto the OpenSSL namespace when TLS is compiled in (see the shim header). The
    # force-include flag is compiler-specific: MSVC spells it /FI, GCC/Clang (incl. MinGW) -include.
    #
    # -fvisibility=hidden on GCC/Clang is the load-bearing part: the embed graph defines quack's own
    # C++ symbols (duckdb::QuackServer, QuackScanFromClientFunction::GetFunction, ...). Statically
    # linked into libduckdb they would be EXPORTED, and on Linux's flat dynamic namespace a co-loaded
    # stock `quack.duckdb_extension` binds ITS calls to those exported acl copies - so quack's init ran
    # acl's GetFunction and tried to register acl_quack_scan_data (macOS's two-level namespace hides
    # this, which is why it only failed on the Linux CI). Hiding the embed symbols keeps each image
    # bound to its own. MSVC/Windows exports only the extension entrypoint, so it needs neither.
    if(MSVC)
        set(ACL_QUACK_EMBED_COMPILE_OPTS "/FI${QUACK_EMBED}/include/acl_quack_httplib_ns.hpp")
    else()
        set(ACL_QUACK_EMBED_COMPILE_OPTS
            "-include;${QUACK_EMBED}/include/acl_quack_httplib_ns.hpp;-fvisibility=hidden;-fvisibility-inlines-hidden")
    endif()
    # TLS is compiled in exactly when the flight build's OpenSSL is present (same gate as ACL_OIDC_TLS).
    if(NOT DEFINED ENV{ACL_NO_FLIGHT})
        set(ACL_QUACK_EMBED_DEFS "CPPHTTPLIB_OPENSSL_SUPPORT")
    endif()
    set_source_files_properties(${ACL_QUACK_EMBED_SOURCES} PROPERTIES
        COMPILE_OPTIONS "${ACL_QUACK_EMBED_COMPILE_OPTS}"
        COMPILE_DEFINITIONS "${ACL_QUACK_EMBED_DEFS}")
    list(APPEND EXTENSION_SOURCES ${ACL_QUACK_EMBED_SOURCES})
    set(ACL_QUACK_EMBED_ENABLED 1)
endif()

build_static_extension(${TARGET_NAME} ${EXTENSION_SOURCES})
build_loadable_extension(${TARGET_NAME} " " ${EXTENSION_SOURCES})

if(NOT ${WASM_ENABLED} AND NOT DEFINED ENV{ACL_NO_FLIGHT})
    foreach(target ${EXTENSION_NAME} ${LOADABLE_EXTENSION_NAME})
        target_compile_definitions(${target} PRIVATE ACL_FLIGHT_ENABLED=1 ACL_OIDC_TLS=1)
        target_link_libraries(${target}
            ArrowFlightSql::arrow_flight_sql_static
            ArrowFlight::arrow_flight_static
            Arrow::arrow_static
            gRPC::grpc++
            gRPC::grpc
            OpenSSL::SSL
            OpenSSL::Crypto)
        # duckdb's bundled httplib >=0.53 loads the OS trust store in its OpenSSL TLS path
        # (tls::load_system_certs), which on macOS calls the Security framework - link it, and
        # CoreFoundation it leans on. Both the OIDC client (spec 060) and the embedded door pull it in.
        if(APPLE)
            target_link_libraries(${target} "-framework Security" "-framework CoreFoundation")
        endif()
    endforeach()
endif()

# The embedded quack door (specs/063): tell acl's own TUs (serve/stop, the extension entrypoint) that
# the embedded server is compiled in, so they call it rather than the removed spec-062 front. Off only
# under ACL_NO_QUACK_EMBED (or WASM/MinGW), where acl_quack_serve reports the door was left out.
if(DEFINED ACL_QUACK_EMBED_ENABLED)
    foreach(target ${EXTENSION_NAME} ${LOADABLE_EXTENSION_NAME})
        target_compile_definitions(${target} PRIVATE ACL_QUACK_EMBED_ENABLED=1)
        # The embedded httplib server needs winsock on Windows. MSVC gets it from httplib's own
        # `#pragma comment(lib, "ws2_32.lib")`, but GCC (MinGW) ignores that pragma, so link it by hand;
        # crypt32 is OpenSSL's Windows dependency for the RNG. Harmless duplicates under MSVC.
        if(WIN32)
            target_link_libraries(${target} ws2_32 crypt32)
        endif()
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
