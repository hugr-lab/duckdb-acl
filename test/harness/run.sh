#!/usr/bin/env bash
# Run the end-to-end acl demo against the built extension.
# Usage: make   (build first), then: test/harness/run.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DUCKDB_BIN="${DUCKDB_BIN:-$ROOT/build/release/duckdb}"
ACL_EXT="${ACL_EXT:-$ROOT/build/release/extension/acl/acl.duckdb_extension}"

if [ ! -x "$DUCKDB_BIN" ]; then
  echo "duckdb CLI not found at $DUCKDB_BIN — run 'make' first (or set DUCKDB_BIN)." >&2
  exit 1
fi
if [ ! -f "$ACL_EXT" ]; then
  echo "acl extension not found at $ACL_EXT — run 'make' first (or set ACL_EXT)." >&2
  exit 1
fi

{ echo "LOAD '$ACL_EXT';"; cat "$(dirname "$0")/demo.sql"; } | "$DUCKDB_BIN" -unsigned
