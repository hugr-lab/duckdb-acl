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
	echo "SET GLOBAL acl_profile_level='all';"
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
# ...and the cancel was heard: the query was interrupted, the stream recorded with what went out. The
# event lands when gRPC tears the call down, a moment after the client's cancel - so it is awaited
last_stream() { server_says "SELECT detail, rows FROM acl_audit_events() WHERE kind = 'door' AND detail LIKE 'stream_%' ORDER BY seq DESC LIMIT 1"; }
await_stream() { # <regex> <what> - the newest stream event must match within 5s
	local i ended
	for i in $(seq 1 50); do
		ended="$(last_stream)"
		if echo "$ended" | grep -q "$1"; then echo "$ended"; return 0; fi
		sleep 0.1
	done
	fail "$2: $ended"
}
ended="$(await_stream "^stream_cancelled,[1-9]" "the cancel was not heard as stream_cancelled with rows")"
echo "  pass first batch in ${first_ms}ms, then the cancel is heard ($ended)"

# --- a full read ends as consumed, with its count ------------------------------------------------
got="$(client consume "SELECT * FROM orders")"
echo "$got" | grep -q "'rows': 5" || fail "the tenant's five rows: $got"
ended="$(await_stream "^stream_consumed,5$" "a full read is stream_consumed with its rows")"
echo "  pass a full read is consumed ($ended)"
# spec 074: the profile of that statement arrived when the stream ended - under the door, linked to
# the decision that admitted it, with the rows the client received
profile="$(server_says "SELECT door, statement, verdict, rows_out, decision_seq > 0 FROM acl_audit_events() WHERE kind = 'profile' ORDER BY seq DESC LIMIT 1")"
[ "$profile" = "flight,select,ok,5,true" ] || fail "the consumed stream's profile: $profile"
echo "  pass the stream's profile is linked and counts its rows ($profile)"

# --- a forgotten cursor is superseded by the session's next statement ---------------------------
# spec 074 slice 3 rides on this: while the session's second statement waits for the idle stream
# (2s), the operator switches the session's profiling off - the superseded stream's own profile
# (armed before it ran) still lands, the statement that superseded it leaves none
ACL_STREAM_PAUSE=1 python3 "$HERE/stream_client.py" "$URI" supersede "SELECT * FROM big" >"$TMP/supersede.out" 2>&1 &
SUPERSEDE_PID=$!
for _ in $(seq 1 100); do
	grep -q "^held" "$TMP/supersede.out" 2>/dev/null && break
	sleep 0.1
done
grep -q "^held" "$TMP/supersede.out" || { cat "$TMP/supersede.out" >&2; fail "the supersede client never held its stream"; }
switched="$(server_says "SELECT count(*) FROM (SELECT acl_session_profile(id, 'off') AS k FROM (SELECT unnest(regexp_extract_all(acl_sessions(), '\"id\":\s*\"([^\"]+)\"', 1)) AS id)) WHERE k")"
[ "$switched" -ge 1 ] || fail "no live session took the profile switch: $switched"
listed="$(server_says "SELECT count(*) FROM (SELECT unnest(regexp_extract_all(acl_sessions(), '\"profile_source\":\"(override)\"', 1)) AS s)")"
[ "$listed" -ge 1 ] || fail "acl_sessions() does not show the override: $listed"
# from here on: the client's warm-up and its stream's open are behind (both profiled, the level
# was `all`); what follows is the statement it runs under the switched-off session
seq_before="$(server_says "SELECT coalesce(max(seq), 0) FROM acl_audit_events()")"
wait "$SUPERSEDE_PID" 2>/dev/null || true
got="$(tail -1 "$TMP/supersede.out")"
echo "$got" | grep -q "'ok': \[1\]" || fail "the next statement of a session with an open stream did not run: $got"
waited="$(echo "$got" | sed -n "s/.*'waited_ms': \([0-9]*\).*/\1/p")"
# the client held its stream 1s (ACL_STREAM_PAUSE) before its next statement, which then waited the
# rest of the 2s idle window: the two together are the idle timeout, never an immediate answer
[ "$((waited + 1000))" -ge 1500 ] && [ "$waited" -lt 10000 ] || fail "the wait was ${waited}ms after a 1s hold; acl_flight_stream_idle is 2s"
# the superseded stream's own event lands when gRPC tears its call down - a moment after the client is gone
for _ in $(seq 1 50); do
	ended="$(server_says "SELECT count(*) FROM acl_audit_events() WHERE kind = 'door' AND detail = 'stream_superseded'")"
	[ "$ended" = "1" ] && break
	sleep 0.1
done
[ "$ended" = "1" ] || fail "the idle stream was not recorded as superseded: $ended"
echo "  pass an idle stream is superseded after ${waited}ms, the next statement runs"
# the statement that ran under the switched-off session (SELECT 1: the one statement of this window
# that touches no object) left no profile; the superseded stream's own (armed before it ran, on the
# `big` view) did land - an earlier stream's profile may land late here too, so the check is by
# shape, not by count
unprofiled="$(server_says "SELECT count(*) FROM acl_audit_events() WHERE kind = 'profile' AND seq > $seq_before AND objects::VARCHAR = '[]'")"
[ "$unprofiled" = "0" ] || fail "the switched-off session's statement was profiled ($unprofiled event(s))"
streams="$(server_says "SELECT count(*) FROM acl_audit_events() WHERE kind = 'profile' AND seq > $seq_before AND objects::VARCHAR LIKE '%big%'")"
[ "$streams" -ge 1 ] || fail "the superseded stream left no profile"
echo "  pass the operator's switch on a live session holds at the door (the stream's profile, none for the switched-off statement)"

# --- a session the operator kills takes its stream with it at the next pull ----------------------
ACL_STREAM_PAUSE=3 python3 "$HERE/stream_client.py" "$URI" killed "SELECT * FROM big" >"$TMP/killed.out" 2>&1 &
KILLED_PID=$!
for _ in $(seq 1 100); do
	grep -q "^held" "$TMP/killed.out" 2>/dev/null && break
	sleep 0.1
done
grep -q "^held" "$TMP/killed.out" || { cat "$TMP/killed.out" >&2; fail "the client never held its first batch"; }
# every live session is a departed client's but this one; the ops surface ends them all (spec 050)
killed="$(server_says "SELECT count(*) FROM (SELECT acl_session_kill(id) AS k FROM (SELECT unnest(regexp_extract_all(acl_sessions(), '\"id\":\s*\"([^\"]+)\"', 1)) AS id)) WHERE k")"
[ "$killed" -ge 1 ] || fail "no session was killed: $killed"
wait "$KILLED_PID" 2>/dev/null || true
got="$(tail -1 "$TMP/killed.out")"
echo "$got" | grep -q "the session ended" || fail "the killed session's stream did not end at the next pull: $got"
ended="$(await_stream "^stream_superseded,[1-9]" "the killed session's stream was not recorded")"
echo "  pass a killed session's stream ends at its next pull ($ended)"

# --- the row cap ends the stream in a refusal, after exactly N rows -------------------------------
echo "SET GLOBAL acl_max_result_rows=1000;" >&3
cap="$(server_says "SELECT current_setting('acl_max_result_rows')")"
[ "$cap" = "1000" ] || fail "the cap was not set: $cap"
got="$(client consume "SELECT * FROM big")"
echo "$got" | grep -q "exceeds acl_max_result_rows (1000)" || fail "the cap was not applied: $got"
echo "$got" | grep -q "'rows': 1000," || fail "the client did not receive exactly the 1000 rows before the refusal: $got"
ended="$(await_stream "^stream_capped,1000$" "the cap was not recorded with exactly its rows")"
echo "SET GLOBAL acl_max_result_rows=0;" >&3
cap="$(server_says "SELECT current_setting('acl_max_result_rows')")"
[ "$cap" = "0" ] || fail "the cap was not lifted: $cap"
echo "  pass the row cap hands out exactly 1000 rows, then refuses"

# --- spec 085: a resource group's row cap, for the sessions its role opens after the grant ------------
{
	echo "SET GLOBAL acl_allow_anonymous_admin=true;"
	echo "ACL ADMIN CREATE RESOURCE GROUP capped WITH (max_result_rows 500);"
	echo "ACL ADMIN GRANT RESOURCE GROUP capped TO ROLE analyst;"
	echo "SET GLOBAL acl_allow_anonymous_admin=false;"
} >&3
bound="$(server_says "SELECT count(*) FROM acl_role_resource_groups() WHERE \"group\" = 'capped'")"
[ "$bound" = "1" ] || fail "the group was not bound: $bound"
got="$(client consume "SELECT * FROM big")"
echo "$got" | grep -q "exceeds acl_max_result_rows (500)" || fail "the group's cap was not applied: $got"
echo "$got" | grep -q "'rows': 500," || fail "the client did not receive exactly the group's 500 rows: $got"
ended="$(await_stream "^stream_capped,500$" "the group's cap was not recorded with exactly its rows")"
{
	echo "SET GLOBAL acl_allow_anonymous_admin=true;"
	echo "ACL ADMIN DROP RESOURCE GROUP capped;"
	echo "SET GLOBAL acl_allow_anonymous_admin=false;"
} >&3
gone="$(server_says "SELECT count(*) FROM acl_resource_groups()")"
[ "$gone" = "0" ] || fail "the group was not dropped: $gone"
echo "  pass a resource group's row cap hands out exactly its 500 rows, then refuses"

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
