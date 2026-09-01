#!/usr/bin/env bash
# Spec 066 end to end: a draining Flight door keeps answering the session it already seated while a
# new client - carrying the same valid token - is refused with the draining message; acl_resume()
# seats clients again. Skips (exit 0, saying why) without a flight build or pyarrow.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
HERE="$(cd "$(dirname "$0")" && pwd)"
BUILD="${BUILD_DIR:-$ROOT/build/release}"
DUCKDB="${DUCKDB_BIN:-$BUILD/duckdb}"
ACL_EXT="${ACL_EXT:-$BUILD/extension/acl/acl.duckdb_extension}"
PORT="${ACL_DRAIN_PORT:-32771}"
URI="grpc://localhost:$PORT"
PYBIN="${ACL_ADBC_PYTHON:-python3}"
TOKEN='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci50ZXN0L3MiLCJhdWQiOiJhcGk6Ly9hY2wtdGVzdCIsImV4cCI6NDEwMjQ0NDgwMCwic3ViIjoidS1hY21lIiwicm9sZXMiOlsiYW5hbHlzdCJdLCJ0aWQiOiJhY21lIn0.vzPJbHXAXfczhZwQp183JaaBLlSRSipNsSqwxoIFfng'

fail() { echo "FAIL: $*" >&2; exit 1; }
[ -x "$DUCKDB" ] || { echo "SKIP: no duckdb CLI at $DUCKDB"; exit 0; }
[ -f "$ACL_EXT" ] || { echo "SKIP: no acl extension at $ACL_EXT"; exit 0; }
have="$(echo "LOAD '$ACL_EXT'; SELECT count(*) FROM duckdb_functions() WHERE function_name='acl_flight_serve';" \
        | "$DUCKDB" -unsigned -noheader -list 2>/dev/null | tail -1 | tr -d ' ')"
[ "$have" != "0" ] || { echo "SKIP: this build has no Flight door"; exit 0; }
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

# an operator statement fed through the fifo, awaited via its marker in the server log - the fifo is
# write-only from here, so the log is the only acknowledgement there is
operator() {
	local marker="$1" sql="$2"
	echo "SELECT '$marker' WHERE ($sql) IS NOT NULL;" >&3
	for _ in $(seq 1 40); do
		grep -q "$marker" "$TMP/server.log" && return 0
		sleep 0.25
	done
	cat "$TMP/server.log" >&2; fail "the server never acknowledged $marker"
}

# seat a durable session: the first call is handed the cookie, the second returns it and is bound
JAR="$TMP/jar"
ACL_COOKIE_JAR="$JAR" "$PYBIN" "$HERE/client.py" "$URI" "SELECT count(*) FROM orders" "$TOKEN" >/dev/null \
	|| fail "the pre-drain client could not connect"
ACL_COOKIE_JAR="$JAR" "$PYBIN" "$HERE/client.py" "$URI" "SELECT count(*) FROM orders" "$TOKEN" >/dev/null \
	|| fail "the pre-drain client could not reuse its session"
[ -s "$JAR" ] || fail "the door set no session cookie"

operator DRAIN_ENTERED "acl_drain()"

# the established session keeps working: the cookie resolves before the drain check is ever reached
ACL_COOKIE_JAR="$JAR" "$PYBIN" "$HERE/client.py" "$URI" "SELECT count(*) FROM orders" "$TOKEN" >/dev/null \
	|| fail "the established session was refused during the drain"

# a fresh client - no cookie, the SAME valid token - is refused, and told why
refusal="$("$PYBIN" "$HERE/client.py" "$URI" "SELECT 1" "$TOKEN" 2>&1)" \
	&& fail "a new client was seated during the drain"
echo "$refusal" | grep -q "draining" || fail "the refusal does not say draining: $refusal"

operator RESUME_DONE "acl_resume()::VARCHAR"

"$PYBIN" "$HERE/client.py" "$URI" "SELECT 1" "$TOKEN" >/dev/null \
	|| fail "a new client is still refused after acl_resume"

echo "SELECT acl_flight_stop('$URI');" >&3
echo "PASS: the draining door kept its seated session, refused the new client with the reason, and resumed"
