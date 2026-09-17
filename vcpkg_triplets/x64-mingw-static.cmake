# The MinGW leg of the distribution build: the registry's community `x64-mingw-static` as it stands
# at the baseline (2026.06.24), plus what that baseline needs (see vcpkg_ports/README.md):
#   - `-Wa,-mbig-obj`: grpc 1.76's http2 transport no longer fits a COFF object without it
#     ("can't write ... to section .text ... file too big"), and neither grpc nor its port passes
#     the flag for MinGW;
#   - a release-only build: the extension links release alone, and the debug variant of arrow and
#     grpc is an hour of runner time spent on nothing (the debug build is also where the object
#     overflows first).
# Retire it when the registry's grpc port carries the flag for MinGW itself.
set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE static)
set(VCPKG_ENV_PASSTHROUGH PATH)

set(VCPKG_CMAKE_SYSTEM_NAME MinGW)

set(VCPKG_BUILD_TYPE release)
set(VCPKG_C_FLAGS "-Wa,-mbig-obj")
set(VCPKG_CXX_FLAGS "-Wa,-mbig-obj")
