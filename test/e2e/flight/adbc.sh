#!/usr/bin/env bash
# Spec 047 end to end, through the real ADBC Flight SQL driver. Skips (exit 0, saying why) without a
# flight build or without the driver; ACL_ADBC_PYTHON names a python that has adbc_driver_flightsql.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$ROOT" # spec 095: the fixture issuers (test/idp/) are read relative to the repository root
HERE="$(cd "$(dirname "$0")" && pwd)"
BUILD="${BUILD_DIR:-$ROOT/build/release}"
DUCKDB="${DUCKDB_BIN:-$BUILD/duckdb}"
ACL_EXT="${ACL_EXT:-$BUILD/extension/acl/acl.duckdb_extension}"
PORT="${ACL_ADBC_PORT:-32770}"
URI="grpc://localhost:$PORT"
PYBIN="${ACL_ADBC_PYTHON:-python3}"
TOKEN='eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2V5In0.eyJpc3MiOiJ0ZXN0L2lkcC9zIiwiYXVkIjoiYXBpOi8vYWNsLXRlc3QiLCJleHAiOjQxMDI0NDQ4MDAsInN1YiI6InUtYWNtZSIsInJvbGVzIjpbImFuYWx5c3QiXSwidGlkIjoiYWNtZSJ9.UV5-WWUpQLp-Em8K2yLLkz-NEJgOyTAn9i9B1zpBWF3hNQVgorAVPVK48bxnrMiMm7NabgM3g945lDY31DFwxNeUKnVEe0QdRy1d1KbFh8td3Ak_mepOZ35CjPektGaOjVEpjUFxZUOj_uxYnse_y660xC0stlY8zxDrpSjNCOZRGv-vaxITv7ggOIDYAN07rmPntKe9oOYsb5g0ZkFcIEsKuHuXsL8z1crko6vIZzT9ido-xrph_WEejO5lKaPIxVe1QrB1-C5DUp8D8fnLWMJ3g426VNKWJwUyeSgh_nq1XzLyR8WcLchBQwaFAzkGivmLFmDdrDS7VUy49I8uLw'

fail() { echo "FAIL: $*" >&2; exit 1; }
[ -x "$DUCKDB" ] || { echo "SKIP: no duckdb CLI at $DUCKDB"; exit 0; }
[ -f "$ACL_EXT" ] || { echo "SKIP: no acl extension at $ACL_EXT"; exit 0; }
have="$(echo "LOAD '$ACL_EXT'; SELECT count(*) FROM duckdb_functions() WHERE function_name='acl_flight_serve';" \
        | "$DUCKDB" -unsigned -noheader -list 2>/dev/null | tail -1 | tr -d ' ')"
[ "$have" != "0" ] || { echo "SKIP: this build has no Flight door"; exit 0; }
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

# --- spec 112: a job's writes in lineage - one run per executemany, an ingest with its parent ---------
# Ask the serving process itself (its stdin is ours): one marked query, the marked csv lines back.
server_says() { # <sql> -> the csv lines of that answer
	local mark="m$$_$RANDOM$RANDOM"
	echo "SELECT acl_lineage_flush();" >&3
	echo "SELECT '$mark' AS m, * FROM ($1);" >&3
	local i
	for i in $(seq 1 100); do
		if grep -q "^$mark," "$TMP/server.log"; then
			sleep 0.2
			grep "^$mark," "$TMP/server.log" | cut -d, -f2- | tr -d '\r '
			return 0
		fi
		sleep 0.1
	done
	cat "$TMP/server.log" >&2
	fail "the serving process did not answer check $mark"
}
PARENT_RUN="01929e3a-0000-7000-8000-0000000001a2"
{ echo ".mode csv"; echo "SET GLOBAL acl_lineage_level = 'on';"; echo "SET GLOBAL acl_lineage_namespace = 'acl://e2e';"; } >&3
"$PYBIN" "$HERE/lineage_client.py" "$URI" "$TOKEN" "airflow/daily.load/$PARENT_RUN" || fail "lineage assertions failed"
# under the parent, into c.main.orders: ONE run for the five-row executemany, the ingest's run
# (`approximate` - its source is the client's stream) and ONE RUN_FAIL for the refused batch
runs="$(server_says "SELECT event_type, payload->'datasets'->(payload->'outputs'->>0)::INT->>'name' AS target, approximate, count(*) AS n FROM acl_lineage_events() WHERE (payload->'parent'->>'run_id') = '$PARENT_RUN' GROUP BY ALL")"
for want in "RUN_COMPLETE,c.main.orders,false,1" "RUN_COMPLETE,c.main.orders,true,1" "RUN_FAIL,c.main.orders,false,1"; do
	echo "$runs" | grep -qx "$want" || fail "under one parent, expected the run $want: $runs"
done
echo "  ok:   one run per executemany, a refused batch is one RUN_FAIL, and the ingest is a run with its parent"
echo "SELECT acl_flight_stop('$URI');" >&3
echo "PASS: the real ADBC driver prepared, parameterized, bulk-inserted, staged through a session temp, and was confined to its slice"
