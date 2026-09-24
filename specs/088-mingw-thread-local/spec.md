# Spec 088: no thread_local with a non-trivial destructor

- **Status**: implemented
- **Date**: 2026-09-24
- **Found by**: the `windows_amd64_mingw` leg of the distribution build, twice (2026-09-22 and
  2026-09-24)

## Problem

The MinGW leg died twice in `test/sql/acl_listing_rls_only.test` with no error text, and both times
the next commit's build was green. A hand-run job (`.github/workflows/debug-mingw.yml` on the branch
`debug-mingw-crash`, never on main) built that leg the way the distribution builds it and ran the test
in a loop:

- **Plain runs.** 25 passed; the 26th ended with a segmentation fault partway through the test.
- **Under gdb.** The first run was caught. The faulting thread was a DuckDB worker being joined by
  `~DatabaseInstance`, and it faulted in `std::deque<duckdb::acl::ProfileNote>::~deque()`, called from
  `_pthread_cleanup_dest`. That is the thread-exit destructor of spec 074's
  `thread_local std::deque<ProfileNote> pending_notes`.

On MinGW, winpthreads' emulated TLS may free a thread's TLS storage before the C++ thread-exit
destructors run. A `thread_local` with a non-trivial destructor is then destroyed on freed memory. The
fault depends on allocation timing, which is why it came and went between runs and between builds.
The other platforms were never affected.

## Design

There are no `thread_local`s with non-trivial destructors. Each one is a pointer, a flag, a number or
a char buffer:

- **`pending_notes`** (acl_profile.cpp) is a `thread_local` pointer to a heap deque.
  - It is created on the first push and freed when `QueryBegin` takes the batch or when the notes are
    cleared.
  - A thread therefore ends holding nothing. A thread that ends with notes still pending leaks them,
    a few hundred bytes.
- **The deny reason** (acl_rewriter.cpp) is a `char[32]`. Every code is a short name from
  `ReasonCode()`.
- **`arrow_ingest_factory`** (acl_policy.cpp) is a pointer to a heap `shared_ptr`. It is set and taken
  within one Prepare, and a new set releases the old one.

`scripts/ci/check_thread_local.py` runs in CI's lint job. It refuses any `thread_local` in `src/`
whose type is not a pointer, `bool`, a number or a `char` buffer. On main before this spec it names
all three.

## Tests

- **On MinGW.** The same job with this spec merged in ran 150 times under gdb without a fault. Before
  the fix, it faulted on the first run.
- **The lint.** Its check fails on the old code and passes on the new.
- **Elsewhere.** The whole suite (5434 assertions) is unchanged on Linux and macOS, where the fault
  never showed.
