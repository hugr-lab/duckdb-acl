# The MinGW leg of the distribution build. The SAME file, byte for byte, in duckdb-acl, acl-otel and tresor (hugr-node
# reads duckdb-acl's): vcpkg hashes the triplet file into every package's ABI, so one file is what lets the four
# repositories share one binary cache - change it in all of them at once.
# The registry's community `x64-mingw-static` at the baseline (2026.06.24), plus:
#   - `-Wa,-mbig-obj`: grpc 1.76's http2 transport no longer fits a COFF object without it ("can't write ... to
#     section .text ... file too big"), and neither grpc nor its port passes the flag for MinGW;
#   - a release-only build: the extensions link release alone; the debug variants (arrow, grpc, the OpenTelemetry
#     SDK) are runner time spent on nothing, and the debug build is where the object overflows first.
# Retire the flag when the registry's grpc port carries it for MinGW itself.
set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE static)
set(VCPKG_ENV_PASSTHROUGH PATH)

set(VCPKG_CMAKE_SYSTEM_NAME MinGW)

set(VCPKG_BUILD_TYPE release)
set(VCPKG_C_FLAGS "-Wa,-mbig-obj")
set(VCPKG_CXX_FLAGS "-Wa,-mbig-obj")
