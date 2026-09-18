# Overlay ports

vcpkg ports this repository carries on top of the registry, listed ahead of extension-ci-tools' own
in `vcpkg.json`. Each is the registry's port at the baseline the distribution build uses, plus the
one change named here; drop a port once the registry carries the fix. All three findings of the
2026.06.24 baseline (thrift, the MinGW triplet, mimalloc) are reported upstream as
extension-ci-tools #413, with the overlays here as the recipe - retire each once ci-tools carries it
or moves its images.

An overlay holds its port at the copied version whatever baseline ci-tools moves to: a baseline
whose other ports need a newer one fails loudly at vcpkg's resolve step (a version constraint, not a
silent downgrade) - re-copy the port from that baseline and re-apply the change.

## thrift

thrift 0.23.0 (vcpkg baseline 2026.06.24, the one extension-ci-tools `main` moved to on 2026-09-16)
passes bison `--file-prefix-map` unconditionally in `compiler/cpp/CMakeLists.txt` - an option bison
gained in 3.7 (2020). The `duckdb/linux_amd64` / `linux_arm64` images build with the distribution's
bison 3.0.4 (el8), which rejects the whole command line, so every distribution build that pulls
thrift (Arrow's Flight SQL does) failed on the two linux jobs from that day on; macOS (brew's bison)
and Windows (vcpkg's win_bison 3.7.4, MinGW's 3.8) were never affected. `bison-file-prefix-map.patch`
gates the flag on `BISON_VERSION VERSION_GREATER_EQUAL 3.7`; everything else is the registry's port
as it stands (`portfile.cmake`, `vcpkg.json` and the two registry patches are byte-identical to it).
Retire it when upstream thrift (or the vcpkg port) makes the same check, or when the duckdb images
carry a newer bison.

## mimalloc

mimalloc 3.3.2 (the same baseline; 2.2.4 before it) names `ERROR_COMMITMENT_MINIMUM` in its Windows
out-of-memory check, a WinError.h constant the mingw-w64 headers of the MinGW image (rtools42) do not
have - so the `windows_amd64_mingw` job failed at `prim.c` (arrow depends on mimalloc on every
platform). `mingw-error-commitment-minimum.patch` defines it (635L, WinError.h's value) when the
headers do not; everything else is the registry's port. Upstream still has the bare use (v3.5.3);
retire the port when a mimalloc guards it, or when the image's mingw-w64 knows the constant.

## Overlay triplets (`vcpkg_triplets/`)

`x64-mingw-static`: the registry's community triplet plus `-Wa,-mbig-obj` - grpc 1.76 (the same
baseline) no longer fits a COFF object on MinGW without it - and `VCPKG_BUILD_TYPE release`, since
the extension links release alone. Listed first in `vcpkg.json`'s `overlay-triplets`; the same file
lives in acl-otel, whose graph carries grpc too.
