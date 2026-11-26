# Spec 182: ES256 on Linux aarch64 - p256-m built without GCC's expensive optimizations

- **Status**: implemented
- **Date**: 2026-11-26
- **Author**: Claude (for the owner)

## Summary

On Linux arm64 every valid ES256 token was refused with `signature verification failed`. The vendored p256-m is
miscompiled by GCC 14.2.1 (el8's `gcc-toolset-14`, which the Linux build images use) on aarch64 at `-O2` and above.
The file is now built with `-fno-expensive-optimizations` by GCC, everywhere.

## Problem

- The distribution build's linux_arm64 job failed on main after spec 181 (#321): `acl_jwks.test:59` and
  `acl_jwt.test:55`, the two ES256 checks of the suite; RS256 in the same files passed, linux_amd64 passed.
- It was never spec 181. Until extension-ci-tools changed (between 2026-11-21 and 2026-11-26) the linux_arm64 job's
  test phase ran nothing (0.1 s); now it runs the suite natively, and the fault surfaced.
- Every Linux arm64 build of ours carries it, hugr-node's `hugr_node` included: an issuer that signs ES256 is refused
  there. Fail closed - nothing was admitted that should not have been.

## Design

Measured with a harness (`p256_ecdsa_verify` over the suite's token and `test/idp/rs`'s EC key) in
`quay.io/pypa/manylinux_2_28_aarch64` (the same GCC as `duckdb/linux_arm64`):

| compiler | flags | verify |
| --- | --- | --- |
| GCC 14.2.1 (Red Hat 14.2.1-11), aarch64 | `-O0`, `-O1` | ok |
| GCC 14.2.1, aarch64 | `-O2`, `-O3`, with `-fPIC`, `-flto`, `-fno-strict-aliasing`, `-fwrapv`, `-fno-inline`, `-fno-tree-vectorize` | refused (-2) |
| GCC 14.2.1, aarch64 | `-O2` / `-O3 -DNDEBUG -fPIC` `-fno-expensive-optimizations` | ok |
| GCC 14.2.1, x86_64 | `-O3 -DNDEBUG -fPIC` | ok |
| GCC 14.4.0 (Debian), aarch64 | `-O0` .. `-O3`, and `-O2` with ASan + UBSan | ok, no report |
| Apple clang, arm64 | `-O2` with UBSan (signed integer, shifts) | ok, no report |

Each `-O2` pass over `-O1` was turned off one at a time; only `-fno-expensive-optimizations` fixed it. No sanitizer
finds undefined behaviour in p256-m, so this is the compiler's (fixed by 14.4). `acl_sources.cmake` sets the option on
`p256-m.c` for GCC on every target: one file, verification once per token, and a narrower condition (arch, version)
would be one more thing to get wrong. p256-m's source stays as it was.

## Enforcement & security

A miscompiled verifier refused valid signatures; one that admitted invalid ones would have been worse, and the same
build is what would have shown it. The suite's ES256 checks are the regression: they fail without the option in the
distribution build's linux_arm64 job.

## Testing

- `acl_jwks.test`, `acl_jwt.test` in the distribution build's linux_arm64 job (dispatched on this branch before the
  merge, and on main after it).
- Re-pin in hugr-node, whose Linux arm64 build takes `acl_sources.cmake`.

## Alternatives considered

- **`-O1` for the file**: also right, but turns off more than the one pass.
- **Another compiler in the image**: the image is duckdb's.
- **Replacing p256-m**: mbedtls is trimmed without ECDSA in duckdb; no need for a second library.
