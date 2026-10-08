# Spec 108: pin extension-ci-tools to f3fccb8 until #431's resource compiler is fixed

- **Status**: superseded by 110
- **Date**: 2026-10-08
- **Found by**: acl-otel's distribution build on main d689ef5 (run 37767298423), windows_amd64.
- **Temporary**: lift once upstream fixes it (reported on duckdb/extension-ci-tools#431).

## Problem

extension-ci-tools #431 (merged 2026-10-08 09:10 UTC) added clang-cl triplets for vcpkg
(`x64-windows-static-release-clangcl`), so the ports are now built by the same compiler as the
extension. Its chainload toolchain (`toolchains/scripts/clangcl.cmake`) sets the C and C++ compilers to
clang-cl but not the resource compiler. CMake falls back to clang-cl for `.rc` files, which do not
compile:

```
clang-cl: error: no such file or directory: '/c65001'
```

Every port that ships a `version.rc` fails to build, protobuf first. That breaks the Flight build's
Arrow on windows_amd64. acl-otel hit it on its first distribution run after the merge. Our own
distribution run on 7758874 started before #431 and passed, and the next one would not.

## Design

`.github/workflows/distribution.yml` pins both the reusable workflow (`@…`) and `ci_tools_version` to
f3fccb8e79f4c50b02447907207e2f3caf404946. That is the merge of #428, the clang-cl switch, without
#431. Under that commit, the vcpkg ports stay MSVC builds, and spec 106's `/GF-` keeps their pooled
literals safe from clang-cl's.

The pin goes back to `main` once #431's toolchain sets `CMAKE_RC_COMPILER`. The suggested fix is on
#431. Then spec 106's `/GF-` can go too: with the ports built by clang-cl, no MSVC literal is left to
share. That is a check, not an assumption.

## Testing

The distribution build is dispatched on this branch: windows_amd64 and the other platforms build,
and the Test step passes.

## Alternatives considered

- **Wait for the fix.** Main stays red on Windows meanwhile, and every merge ships without a Windows
  binary.
- **An overlay triplet of ours with the resource compiler set.** It depends on the overlay
  precedence between ours and ci-tools' directory, and has to be undone as well.
