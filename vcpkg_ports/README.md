# Overlay ports

vcpkg ports this repository carries on top of the registry, listed ahead of extension-ci-tools' own
in `vcpkg.json`. Each is the registry's port at the baseline the distribution build uses, plus the
one change named here; drop a port once the registry carries the fix.

## thrift

thrift 0.24.0 (vcpkg baseline 2026.06.24, the one extension-ci-tools `main` moved to on 2026-09-16)
passes bison `--file-prefix-map` unconditionally in `compiler/cpp/CMakeLists.txt` - an option bison
gained in 3.8. The `duckdb/linux_amd64` / `linux_arm64` images build with the distribution's bison
3.0.4 (el8), which rejects the whole command line, so every distribution build that pulls thrift
(Arrow's Flight SQL does) failed there from that day on. `bison-file-prefix-map.patch` gates the flag
on `BISON_VERSION VERSION_GREATER_EQUAL 3.8`; everything else is the registry's port as it stands.
Retire it when upstream thrift (or the vcpkg port) makes the same check, or when the duckdb images
carry a newer bison.
