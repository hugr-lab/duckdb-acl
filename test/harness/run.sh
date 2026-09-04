#!/usr/bin/env bash
# Run the end-to-end acl demo against the built extension and check that it did what it says.
# Usage: make   (build first), then: test/harness/run.sh
#
# The demo refuses four statements on purpose - that is the point of it - so the CLI's own exit code
# (non-zero after any error) says nothing useful. The runner judges the transcript instead: exactly
# the four announced refusals, nothing else refused, and the rows the policy promised.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DUCKDB_BIN="${DUCKDB_BIN:-$ROOT/build/release/duckdb}"
ACL_EXT="${ACL_EXT:-$ROOT/build/release/extension/acl/acl.duckdb_extension}"

if [ ! -x "$DUCKDB_BIN" ]; then
  echo "duckdb CLI not found at $DUCKDB_BIN - run 'make' first (or set DUCKDB_BIN)." >&2
  exit 1
fi
if [ ! -f "$ACL_EXT" ]; then
  echo "acl extension not found at $ACL_EXT - run 'make' first (or set ACL_EXT)." >&2
  exit 1
fi

transcript="$(mktemp)"
trap 'rm -f "$transcript"' EXIT
{ echo "LOAD '$ACL_EXT';"; cat "$(dirname "$0")/demo.sql"; } | "$DUCKDB_BIN" -unsigned 2>&1 | tee "$transcript" || true

expect() { # <regex> <what>
  if ! grep -qE "$1" "$transcript"; then
    echo "harness: expected $2" >&2
    fail=1
  fi
}
fail=0
errors="$(grep -cE '^[A-Za-z ]*Error: ' "$transcript" || true)"
if [ "$errors" -ne 4 ]; then
  echo "harness: expected exactly 4 refusals, the transcript has $errors error line(s)" >&2
  fail=1
fi
expect 'phys' 'the physical name to be refused (1/4)'
expect 'read_csv' 'the data-reading function to be refused (2/4)'
expect 'read-only relation' 'the write through the projection to be refused (3/4)'
expect 'anonymous' 'the anonymous ACL ADMIN to be refused with the hatch closed (4/4)'
expect 'user-1@globex' 'the virtual scalar to expand with the baked claim'
expect '"reason_code":"function_denied"' 'the audit to count the refused function under its code (spec 069)'
expect '"reason_code":"read_only"' 'the audit to count the refused write under its code (spec 069)'
expect '"reason_code":"mgmt_unauthorized"' 'the audit to count the refused anonymous admin under its code (spec 069)'
if [ "$fail" -ne 0 ]; then
  echo "harness: FAILED - see the transcript above" >&2
  exit 1
fi
echo "harness: ok - the four announced refusals and nothing else"
