# Spec 106: clang-cl and MSVC-built libraries - no shared pooled literals

- **Status**: implemented
- **Date**: 2026-10-08
- **Found by**: the distribution build's windows_amd64 leg. `unittest` died while listing the tests
  (`exit: 3221225477`, 0xC0000005) in runs 37592022263 (PR #183, twice) and 37683321499 (PR #184).

## Problem

Since extension-ci-tools #428 (2026-10-07), the leg compiles with clang-cl (Clang 20.1.8). vcpkg's ports
(Arrow, gRPC, abseil, protobuf, ...) stay MSVC builds from the binary cache. A replica of the leg
(same runner, toolchain and triplet, built with `-Z7`/`-debug`) crashed every time and gave the stack:

```
movaps xmm0, xmmword ptr [unittest!`string' (…b934)]
unittest!arrow::util::`dynamic initializer for 'base64_chars''+0xe
unittest!_initterm
```

1. Arrow's vendored `base64.cpp` initializes `static const std::string base64_chars` from the base64
   alphabet. MSVC compiled it to read the literal with `movaps`, which needs a 16-byte aligned operand.
2. The literal is pooled: a COMDAT `??_C@_0EB@NFPJKBDG@...`. duckdb's `blob.hpp` spells the same
   alphabet, so clang-cl emits a COMDAT of the same name, aligned to 1.
3. The linker keeps one copy. In the crashing image, the PDB's section contributions show that it kept
   duckdb's: `ub_duckdb_common_types.cpp.obj`, `IMAGE_SCN_ALIGN_1BYTES`, at `.rdata+0x34934`, an
   address that is not a multiple of 16.

Whether that copy lands on a 16-byte boundary depends on the layout of `.rdata`. That is why the crash
comes and goes with unrelated changes, and why main passed while two PRs failed. Before #428 no
windows_amd64 build of ours had failed this way.

## Design

`extension_config.cmake` passes `/GF-` (no string pooling) to everything clang-cl compiles there. The
condition is `MSVC AND CMAKE_CXX_COMPILER_ID STREQUAL "Clang"`. MSVC builds, MinGW and the other
platforms are untouched.

- clang-cl's literals then stay private to each object, and every pooled literal the link selects is
  an MSVC one, aligned the way MSVC's code assumes.
- duckdb includes this file at top level (`extension_build_tools.cmake`) before `add_subdirectory(src)`,
  so the option reaches duckdb's own objects, where the shared alphabet lives.
- The cost is a little duplicated read-only data per object.
- When extension-ci-tools builds the ports with the same compiler, or fixes this itself, the option
  can go. The issue for extension-ci-tools is drafted with the evidence.

## Testing

The same replica job ran with the option:

- both flavours (plain and `-Z7`) passed the distribution's Test step (75 passed, 15 skipped);
- 40 of 40 listings exited 0, with no crash dump.

In the `-Z7` image's PDB, the pooled alphabet is now contributed by Arrow's own `base64.cpp.obj`
(`IMAGE_SCN_ALIGN_16BYTES`) at `.rdata+0x27ebf0`, which is 16-byte aligned. The distribution build is
dispatched on the PR. Nothing changes on Linux or macOS, so the local gate is unaffected.
