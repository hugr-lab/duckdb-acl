# Spec 086: re-pin duckdb-ext-common v0.7.1 - the audit gauges read under their lock

- **Status**: implemented
- **Date**: 2026-09-24
- **Contract**: duckdb-ext-common spec 009 (v0.7.1). `ACLA` stays 2, so there is no layout change.

## Problem

`AuditGauges::Snapshot()` called the readers after releasing its lock. acl's audit pipeline removes
its fill gauges in its destructor, then frees the queue and ring they read. A snapshot already under
way, such as acl-otel's export thread or `acl_metrics()`, could call one of those readers on freed
state. tresor found this while porting the code into ext-common's hooks base.

## Design

The re-pin brings the fix: the readers run under the lock, and `Remove()` waits for a running
snapshot. acl already follows the rule the header now states:

- its readers take only their own short locks (the audit queue, the ring, the store, the stream
  budget);
- `Register` runs at load and at serve, and `Remove` runs in the pipeline's destructor, none of them
  under those locks.

v0.7.0's `hooks/ext_hooks.hpp` and `contracts/tresor_audit.hpp` come with the pin. acl compiles neither.

## Tests

`test/cpp/test_acl_audit_gauges.cpp` holds a reader inside `Snapshot()`, and `Remove()` on another
thread must not return before that reader has finished. The test fails against v0.6.0 and passes
against v0.7.1. A second check confirms that a snapshot still reads fixed and dynamic gauges.
