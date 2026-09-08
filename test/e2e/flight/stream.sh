#!/usr/bin/env bash
# The Flight door streams (spec 070), end to end: a pyarrow client pulls a result the way a driver
# does and stops the way a client stops, and the server side - read through the serving process's own
# stdin - says what it heard: the first batch before the last, a cancel that interrupts, a forgotten
# cursor superseded, the row cap, a full read, and a bulk load whose client dies mid-stream.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
HERE="$(cd "$(dirname "$0")" && pwd)"
BUILD="${BUILD_DIR:-$ROOT/build/release}"
DUCKDB="${DUCKDB_BIN:-$BUILD/duckdb}"
ACL_EXT="${ACL_EXT:-$BUILD/extension/acl/acl.duckdb_extension}"
PORT="${ACL_E2E_PORT:-31740}"
URI="grpc://127.0.0.1:$PORT"

fail() { echo "FAIL: $*" >&2; exit 1; }

[ -x "$DUCKDB" ] || { echo "SKIP: no duckdb CLI at $DUCKDB"; exit 0; }
[ -f "$ACL_EXT" ] || { echo "SKIP: no acl extension at $ACL_EXT"; exit 0; }
have="$(echo "LOAD '$ACL_EXT'; SELECT count(*) FROM duckdb_functions() WHERE function_name='acl_flight_serve';" \
        | "$DUCKDB" -unsigned -noheader -list 2>/dev/null | tail -1 | tr -d ' ')"
[ "$have" != "0" ] || { echo "SKIP: this build has no Flight door"; exit 0; }
python3 -c "import pyarrow.flight" 2>/dev/null || { echo "SKIP: pyarrow is not installed"; exit 0; }

TMP="$(mktemp -d)"
SERVER_PID=""
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

{
	echo "LOAD '$ACL_EXT';"
	sed "s|\${ACL_E2E_URI}|$URI|g" "$HERE/bootstrap.sql"
	# the result the tests pull from: 200M rows nobody stores, each with a cast to make the scan cost
	# something - a full materialization would take seconds and gigabytes, a stream answers at once
	echo "SET GLOBAL acl_allow_anonymous_admin=true;"
	echo "ACL ADMIN CREATE VIRTUAL VIEW c.big AS SELECT i, i::VARCHAR AS s FROM range(200000000) t(i);"
	echo "SET GLOBAL acl_allow_anonymous_admin=false;"
	echo "SET GLOBAL acl_audit_level='all';"
	echo "SET GLOBAL acl_flight_stream_idle=2;"
	echo ".mode csv"
	echo ".headers off"
	echo "SELECT 'ready';"
} >"$TMP/server.sql"
FIFO="$TMP/ctl"
mkfifo "$FIFO"
"$DUCKDB" -unsigned <"$FIFO" >"$TMP/server.log" 2>&1 &
SERVER_PID=$!
exec 3>"$FIFO"
cat "$TMP/server.sql" >&3

ready=""
for _ in $(seq 1 60); do
	kill -0 "$SERVER_PID" 2>/dev/null || { cat "$TMP/server.log" >&2; fail "the server exited before serving"; }
	if python3 "$HERE/stream_client.py" "$URI" consume "SELECT 1 AS ok" 2>/dev/null | grep -q "'rows': 1"; then
		ready=1; break
	fi
	sleep 0.5
done
[ -n "$ready" ] || { cat "$TMP/server.log" >&2; fail "the door never came up on $URI"; }

# Ask the serving process itself (its stdin is ours): flush the audit, run one query with a marker, and
# read the marked lines back from its log. The marker keeps every check's answer apart.
server_says() { # <sql> -> the csv lines of that answer
	# a marker unique per call (this runs in a command substitution, so a counter would not persist)
	local mark="m$$_$RANDOM$RANDOM"
	echo "SELECT acl_audit_flush();" >&3
	echo "SELECT '$mark' AS m, * FROM ($1);" >&3
	local i
	for i in $(seq 1 100); do
		if grep -q "^$mark," "$TMP/server.log"; then
			sleep 0.2 # the rest of the answer, if it is more than one line
			grep "^$mark," "$TMP/server.log" | cut -d, -f2- | tr -d '\r '  # csv: no CR, no padding
			return 0
		fi
		sleep 0.1
	done
	cat "$TMP/server.log" >&2
	fail "the serving process did not answer check $mark"
}
client() { python3 "$HERE/stream_client.py" "$URI" "$@" 2>&1 | tail -1; }

echo "flight streaming e2e (spec 070)"

# --- the first batch arrives long before the last could ------------------------------------------
got="$(client first "SELECT * FROM big")"
echo "$got" | grep -q "'rows': [1-9]" || fail "no first batch: $got"
first_ms="$(echo "$got" | sed -n "s/.*'first_ms': \([0-9]*\).*/\1/p")"
[ "$first_ms" -lt 3000 ] || fail "the first batch took ${first_ms}ms - that is a materialized result, not a stream"
# ...and the cancel was heard: the query was interrupted, the stream recorded with what went out
ended="$(server_says "SELECT detail, rows FROM acl_audit_events() WHERE kind = 'door' AND detail LIKE 'stream_%' ORDER BY seq DESC LIMIT 1")"
echo "$ended" | grep -q "^stream_cancelled,[1-9]" || fail "the cancel was not heard as stream_cancelled with rows: $ended"
echo "  pass first batch in ${first_ms}ms, then the cancel is heard ($ended)"

# --- a full read ends as consumed, with its count ------------------------------------------------
got="$(client consume "SELECT * FROM orders")"
echo "$got" | grep -q "'rows': 5" || fail "the tenant's five rows: $got"
ended="$(server_says "SELECT detail, rows FROM acl_audit_events() WHERE kind = 'door' AND detail LIKE 'stream_%' ORDER BY seq DESC LIMIT 1")"
[ "$ended" = "stream_consumed,5" ] || fail "a full read is stream_consumed with its rows: $ended"
echo "  pass a full read is consumed ($ended)"

# --- a forgotten cursor is superseded by the session's next statement ---------------------------
got="$(client supersede "SELECT * FROM big")"
echo "$got" | grep -q "'ok': \[1\]" || fail "the next statement of a session with an open stream did not run: $got"
waited="$(echo "$got" | sed -n "s/.*'waited_ms': \([0-9]*\).*/\1/p")"
[ "$waited" -ge 1500 ] && [ "$waited" -lt 10000 ] || fail "the wait was ${waited}ms; acl_flight_stream_idle is 2s"
# the superseded stream's own event lands when gRPC tears its call down - a moment after the client is gone
for _ in $(seq 1 50); do
	ended="$(server_says "SELECT count(*) FROM acl_audit_events() WHERE kind = 'door' AND detail = 'stream_superseded'")"
	[ "$ended" = "1" ] && break
	sleep 0.1
done
[ "$ended" = "1" ] || fail "the idle stream was not recorded as superseded: $ended"
echo "  pass an idle stream is superseded after ${waited}ms, the next statement runs"

# --- the row cap ends the stream in a refusal -----------------------------------------------------
echo "SET GLOBAL acl_max_result_rows=1000;" >&3
got="$(client consume "SELECT * FROM big")"
echo "$got" | grep -q "exceeds acl_max_result_rows (1000)" || fail "the cap was not applied: $got"
ended="$(server_says "SELECT detail, rows >= 1000 FROM acl_audit_events() WHERE kind = 'door' AND detail = 'stream_capped'")"
[ "$ended" = "stream_capped,true" ] || fail "the cap was not recorded: $ended"
echo "SET GLOBAL acl_max_result_rows=0;" >&3
echo "  pass the row cap refuses past 1000 rows"

# --- a bulk load whose client dies mid-stream is rolled back and named ---------------------------
python3 "$HERE/stream_client.py" "$URI" ingest orders >"$TMP/ingest.out" 2>&1 &
INGEST_PID=$!
for _ in $(seq 1 50); do
	grep -q "^sent 30000" "$TMP/ingest.out" 2>/dev/null && break
	sleep 0.1
done
grep -q "^sent" "$TMP/ingest.out" || { cat "$TMP/ingest.out" >&2; fail "the ingest never started sending"; }
kill -9 "$INGEST_PID" 2>/dev/null || true
wait "$INGEST_PID" 2>/dev/null || true
for _ in $(seq 1 100); do
	ended="$(server_says "SELECT count(*) FROM acl_audit_events() WHERE kind = 'door' AND detail = 'ingest_cancelled'")"
	[ "$ended" = "1" ] && break
	sleep 0.1
done
[ "$ended" = "1" ] || fail "the killed load was not heard as ingest_cancelled: $ended"
stored="$(server_says "SELECT count(*) FROM memory.main.orders WHERE id >= 5000000")"
[ "$stored" = "0" ] || fail "a load whose client died left $stored rows - an ingest is all or nothing"
verdict="$(server_says "SELECT verdict, reason_code FROM acl_audit_events() WHERE kind = 'ingest' ORDER BY seq DESC LIMIT 1")"
[ "$verdict" = "denied,unavailable" ] || fail "the cancelled load's ingest event: $verdict"
echo "  pass a client that dies mid-load leaves nothing, and the door says which side stopped"

echo "PASS: the door streams, and hears a client that stops"
