# Spec 110: extension-ci-tools `main` again

- **Status**: implemented
- **Date**: 2026-10-08
- **Supersedes**: spec 108 (the temporary pin)

extension-ci-tools #432 (merged 2026-10-08, 5326077) makes clang-cl **opt-in** for the windows
job. Without the opt-in, windows_amd64 builds with MSVC again. Neither problem behind spec 108
applies there:
- #431's clang-cl vcpkg triplets left the resource compiler unset, and every port with a `.rc` file
  failed;
- #428's mix of clang-cl and MSVC hit literal-pooling alignment (spec 106).

`distribution.yml` therefore goes back to `@main` for the reusable workflow and to `ci_tools_version: main`.

Spec 106's `/GF-` stays. It is passed only when the compiler is clang-cl, so under MSVC it does
nothing, and it keeps a later opt-in safe while vcpkg's ports are MSVC builds.

## Testing

The distribution build dispatched on this branch is green on every platform, windows_amd64 included.
