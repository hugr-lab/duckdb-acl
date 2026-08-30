#!/usr/bin/env bash
# Spec 047 end to end, through the real ADBC Flight SQL driver. Skips (exit 0, saying why) without a
# flight build or without the driver; ACL_ADBC_PYTHON names a python that has adbc_driver_flightsql.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
HERE="$(cd "$(dirname "$0")" && pwd)"
BUILD="${BUILD_DIR:-$ROOT/build/release}"
DUCKDB="${DUCKDB_BIN:-$BUILD/duckdb}"
ACL_EXT="${ACL_EXT:-$BUILD/extension/acl/acl.duckdb_extension}"
PORT="${ACL_ADBC_PORT:-32770}"
URI="grpc://localhost:$PORT"
PYBIN="${ACL_ADBC_PYTHON:-python3}"
TOKEN='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci50ZXN0L3MiLCJhdWQiOiJhcGk6Ly9hY2wtdGVzdCIsImV4cCI6NDEwMjQ0NDgwMCwic3ViIjoidS1hY21lIiwicm9sZXMiOlsiYW5hbHlzdCJdLCJ0aWQiOiJhY21lIn0.vzPJbHXAXfczhZwQp183JaaBLlSRSipNsSqwxoIFfng'

fail() { echo "FAIL: $*" >&2; exit 1; }
[ -x "$DUCKDB" ] || { echo "SKIP: no duckdb CLI at $DUCKDB"; exit 0; }
[ -f "$ACL_EXT" ] || { echo "SKIP: no acl extension at $ACL_EXT"; exit 0; }
have="$(echo "LOAD '$ACL_EXT'; SELECT count(*) FROM duckdb_functions() WHERE function_name='acl_flight_serve';" \
        | "$DUCKDB" -unsigned -noheader -list 2>/dev/null | tail -1 | tr -d ' ')"
[ "$have" = "1" ] || { echo "SKIP: this build has no Flight door"; exit 0; }
"$PYBIN" -c "import adbc_driver_flightsql" 2>/dev/null || { echo "SKIP: adbc_driver_flightsql is not installed (set ACL_ADBC_PYTHON)"; exit 0; }
# the readiness probe runs client.py, which needs pyarrow - without this check a missing pyarrow
# reads as "the door never came up", which is a lie about the door
"$PYBIN" -c "import pyarrow.flight" 2>/dev/null || { echo "SKIP: pyarrow is not installed in $PYBIN"; exit 0; }

TMP="$(mktemp -d)"; SERVER_PID=""
cleanup() {
	local rc=$?
	if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
		kill "$SERVER_PID" 2>/dev/null || true
		wait "$SERVER_PID" 2>/dev/null || true
	fi
	rm -rf "$TMP"
	exit $rc
}
trap cleanup EXIT INT TERM
FIFO="$TMP/ctl"; mkfifo "$FIFO"
{ echo "LOAD '$ACL_EXT';"; sed "s|\${ACL_E2E_URI}|$URI|g" "$HERE/bootstrap.sql"; echo "SELECT 1;"; } >"$TMP/server.sql"
"$DUCKDB" -unsigned <"$FIFO" >"$TMP/server.log" 2>&1 & SERVER_PID=$!
exec 3>"$FIFO"; cat "$TMP/server.sql" >&3
ready=""
for _ in $(seq 1 60); do
	kill -0 "$SERVER_PID" 2>/dev/null || { cat "$TMP/server.log" >&2; fail "the server exited early"; }
	"$PYBIN" "$HERE/client.py" "$URI" "SELECT 1" "$TOKEN" >/dev/null 2>&1 && { ready=1; break; }
	sleep 0.5
done
[ -n "$ready" ] || { cat "$TMP/server.log" >&2; fail "the door never came up on $URI"; }

"$PYBIN" "$HERE/adbc_client.py" "$URI" "$TOKEN" || fail "adbc assertions failed"
echo "SELECT acl_flight_stop('$URI');" >&3
echo "PASS: the real ADBC driver prepared, parameterized, bulk-inserted, staged through a session temp, and was confined to its slice"
