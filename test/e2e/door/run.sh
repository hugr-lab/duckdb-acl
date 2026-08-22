#!/usr/bin/env bash
# End-to-end test of the quack door with several clients and real sources (spec 043).
#
# One server process holds the attached source and serves; each client is its own process talking to it
# over the socket, because that - and not several connections inside one process - is what the door
# actually is. The clients run at the same time on purpose: what is tested is isolation under overlap,
# so the assertions are about stored rows and about what each client could see, never about exit codes.
#
# The bulk load is genuinely a *streamed* one, not a statement pushed to the server: each client builds
# its payload in a table of its own, which the server cannot see, so quack has no choice but to send the
# data. That is spec 042's drain path, and the row counts below are what proves it ran.
#
# One leg per source. A leg that cannot run says so and the run reports it: a concurrency test that
# quietly covers one source while claiming three is worse than no test.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
HERE="$(cd "$(dirname "$0")" && pwd)"
BUILD="${BUILD_DIR:-$ROOT/build/release}"
DUCKDB="${DUCKDB_BIN:-$BUILD/duckdb}"
ACL_EXT="${ACL_EXT:-$BUILD/extension/acl/acl.duckdb_extension}"

BASE_PORT="${ACL_E2E_PORT:-31700}"
SERVER_TOKEN="${ACL_E2E_SERVER_TOKEN:-e2e-server-token}"
ROWS="${ACL_E2E_ROWS:-20000}"
CLIENT_TIMEOUT="${ACL_E2E_TIMEOUT:-180}"
ONLY="${ACL_E2E_ONLY:-}"   # run just this leg, by name

# HS256 tokens for the seeded issuer (key "acl-test-hs256-secret"), one tenant each. Minted rather than
# random so a failure is reproducible; specs/043 records how they are made.
TOKEN_ACME='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci50ZXN0L3MiLCJhdWQiOiJhcGk6Ly9hY2wtdGVzdCIsImV4cCI6NDEwMjQ0NDgwMCwic3ViIjoidS1hY21lIiwicm9sZXMiOlsiYW5hbHlzdCJdLCJ0aWQiOiJhY21lIn0.vzPJbHXAXfczhZwQp183JaaBLlSRSipNsSqwxoIFfng'
TOKEN_GLOBEX='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci50ZXN0L3MiLCJhdWQiOiJhcGk6Ly9hY2wtdGVzdCIsImV4cCI6NDEwMjQ0NDgwMCwic3ViIjoidS1nbG9iZXgiLCJyb2xlcyI6WyJhbmFseXN0Il0sInRpZCI6Imdsb2JleCJ9.CitaHH8sw-ndoasm0iTvIRKq9XBJt7PDfm22IhSQZ78'

T0=$(date +%s)
note() { [ -z "${ACL_E2E_VERBOSE:-}" ] || echo "[$(( $(date +%s) - T0 ))s] $*" >&2; }
fail() { echo "FAIL: $*" >&2; exit 1; }

RAN=""
SKIPPED=""
skip_leg() { SKIPPED="$SKIPPED $1($2)"; echo "  skip $1: $2"; }

[ -x "$DUCKDB" ] || { echo "SKIP: no duckdb CLI at $DUCKDB"; exit 0; }
[ -f "$ACL_EXT" ] || { echo "SKIP: no acl extension at $ACL_EXT"; exit 0; }

QUACK_EXT="$(ls "$BUILD"/repository/*/*/quack.duckdb_extension 2>/dev/null | head -1 || true)"
[ -n "$QUACK_EXT" ] || { echo "SKIP: quack is not built - rebuild with ACL_QUACK=1"; exit 0; }
EXT_DIR="$(dirname "$QUACK_EXT")"

TMP="$(mktemp -d)"
SERVER_PID=""
kill_server() {
	if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
		kill "$SERVER_PID" 2>/dev/null || true
		wait "$SERVER_PID" 2>/dev/null || true
	fi
	SERVER_PID=""
}
cleanup() {
	local rc=$?
	# A listener that outlives a failed run poisons the next one, and spec 041 measured that a stopped
	# quack server can keep answering for a while - so the process is killed, not the socket asked nicely.
	kill_server
	[ -n "${KEEP_TMP:-}" ] || rm -rf "$TMP"
	exit $rc
}
trap cleanup EXIT INT TERM

# Can this leg reach its source? On failure the reason is printed rather than swallowed: a stale
# extension built for another duckdb pin and a database that is simply not up both look like "no", and
# telling them apart is the difference between a real skip and a leg that quietly stopped running.
probe() {
	local out
	if out="$(echo "$1" | "$DUCKDB" -unsigned 2>&1)"; then
		return 0
	fi
	echo "$(echo "$out" | grep -v '^$' | head -1 | cut -c1-140)"
	return 1
}

render() { # render <file> <VAR=value>...
	local file="$1"; shift
	local out; out="$(cat "$file")"
	local pair
	for pair in "$@"; do
		local name="${pair%%=*}" value="${pair#*=}"
		out="${out//\$\{$name\}/$value}"
	done
	printf '%s\n' "$out"
}

# leg <name> <extensions...> -- <attach sql> <physical table> <port offset>
run_leg() {
	local name="$1" loads="$2" attach="$3" table="$4" port="$5"
	local L="LOAD '$ACL_EXT'; $loads LOAD '$QUACK_EXT';"

	note "$name: starting server"
	local fifo="$TMP/$name.ctl"
	mkfifo "$fifo"
	"$DUCKDB" -unsigned <"$fifo" >"$TMP/$name.server.log" 2>&1 &
	SERVER_PID=$!
	exec 3>"$fifo"
	{
		echo "$L"
		render "$HERE/bootstrap.sql" \
			"ACL_E2E_ATTACH=$attach" "ACL_E2E_TABLE=$table" \
			"ACL_E2E_PORT=$port" "ACL_E2E_SERVER_TOKEN=$SERVER_TOKEN"
	} >&3

	# Wait for the door rather than sleeping and hoping.
	local ready="" i
	for i in $(seq 1 60); do
		if ! kill -0 "$SERVER_PID" 2>/dev/null; then
			echo "--- $name server log ---" >&2; cat "$TMP/$name.server.log" >&2
			fail "$name: the server exited before it was serving"
		fi
		if echo "$L SELECT * FROM quack_query('quack:localhost:$port', 'SELECT 1', token := '$TOKEN_ACME');" \
		   | "$DUCKDB" -unsigned >/dev/null 2>&1; then
			ready=1; break
		fi
		sleep 0.5
	done
	if [ -z "$ready" ]; then
		echo "--- $name server log ---" >&2; cat "$TMP/$name.server.log" >&2
		fail "$name: the door never came up on port $port"
	fi
	note "$name: door is up"

	local who
	for who in acme globex; do
		local token base own
		# "own" is this client's rows by id: its seeded ones, plus the range it is about to write. The
		# check cannot use `tenant` - the grant computes that column from the claim, so every row reads
		# back as the reader's own tenant and the assertion could never fail.
		case "$who" in
		acme) token="$TOKEN_ACME"; base=1000000; own="id IN (1, 3)" ;;
		globex) token="$TOKEN_GLOBEX"; base=2000000; own="id IN (2)" ;;
		esac
		own="$own OR (id >= $base AND id < $((base + ROWS)))"
		{
			echo "$L"
			render "$HERE/client.sql" \
				"ACL_E2E_PORT=$port" "ACL_E2E_TOKEN=$token" "ACL_E2E_OWN=$own" \
				"ACL_E2E_ROWS=$ROWS" "ACL_E2E_ID_BASE=$base"
		} >"$TMP/$name.$who.sql"
	done

	# Started here rather than in a function: a background process launched inside a command
	# substitution belongs to that subshell, and the wait below could not see it.
	"$DUCKDB" -unsigned -csv <"$TMP/$name.acme.sql" >"$TMP/$name.acme.out" 2>&1 &
	local pid_acme=$!
	"$DUCKDB" -unsigned -csv <"$TMP/$name.globex.sql" >"$TMP/$name.globex.out" 2>&1 &
	local pid_globex=$!

	# The deadline is polled here rather than delegated to a background `( sleep N; kill )`. Such a
	# watchdog inherits this script's stdout, and killing the subshell leaves its `sleep` orphaned and
	# still holding the pipe - so every reader of our output blocks for the whole timeout after the test
	# has already passed. Measured on this very script: the run took 0.7s, the `tail` reading it 3 minutes.
	local started deadline timed_out=""
	started=$(date +%s)
	deadline=$((started + CLIENT_TIMEOUT))
	while kill -0 "$pid_acme" 2>/dev/null || kill -0 "$pid_globex" 2>/dev/null; do
		if [ "$(date +%s)" -ge "$deadline" ]; then
			kill -9 "$pid_acme" "$pid_globex" 2>/dev/null || true
			timed_out=1
			break
		fi
		sleep 1
	done
	local rc_acme=0 rc_globex=0
	wait "$pid_acme" || rc_acme=$?
	wait "$pid_globex" || rc_globex=$?
	local elapsed=$(( $(date +%s) - started ))
	[ -z "$timed_out" ] || fail "$name: the clients were still running after ${CLIENT_TIMEOUT}s"

	for who in acme globex; do
		local rc; eval "rc=\$rc_$who"
		if [ "$rc" -ne 0 ]; then
			echo "--- $name/$who ---" >&2; cat "$TMP/$name.$who.out" >&2
			fail "$name: client $who exited with $rc"
		fi
	done
	note "$name: clients finished in ${elapsed}s"

	# --- what each client could see ---
	# `foreign_rows` is the point of the whole file: a client that ever counted a row of another tenant
	# has seen through its slice, and no other assertion here matters if that one fails.
	for who in acme globex; do
		local label line foreign seeded before after expected
		for label in seen_before seen_after; do
			line="$(grep "^$label," "$TMP/$name.$who.out" || true)"
			[ -n "$line" ] || { echo "--- $name/$who ---" >&2; cat "$TMP/$name.$who.out" >&2
				fail "$name: client $who printed no $label row"; }
			foreign="$(echo "$line" | cut -d, -f3)"
			[ "$foreign" = "0" ] || fail "$name: client $who saw $foreign rows of another tenant at $label"
		done
		# the bootstrap seeds two acme rows and one globex row, so each client's own total differs
		case "$who" in acme) seeded=2 ;; globex) seeded=1 ;; esac
		before="$(grep "^seen_before," "$TMP/$name.$who.out" | cut -d, -f2)"
		[ "$before" = "$seeded" ] || fail "$name: client $who saw $before rows before its load, expected $seeded"
		after="$(grep "^seen_after," "$TMP/$name.$who.out" | cut -d, -f2)"
		expected=$((ROWS + seeded))
		[ "$after" = "$expected" ] || fail "$name: client $who sees $after rows after its load, expected $expected"
	done

	# --- what is actually stored ---
	# Read the source directly, outside the ACL: the door's own answers cannot be the only witness to
	# what the door wrote.
	echo "$L $attach
	      SELECT count(*) AS total,
	             count(*) FILTER (WHERE tenant = 'acme') AS acme,
	             count(*) FILTER (WHERE tenant = 'globex') AS globex,
	             count(*) FILTER (WHERE tenant NOT IN ('acme','globex')) AS strays
	      FROM $table;" | "$DUCKDB" -unsigned -csv >"$TMP/$name.stored.csv" 2>&1

	local total acme globex strays
	read -r total acme globex strays <<<"$(tail -1 "$TMP/$name.stored.csv" | tr ',' ' ')"
	[ "$strays" = "0" ] || fail "$name: $strays rows stored with a tenant no client was allowed to write"
	[ "$acme" = "$((ROWS + 2))" ] || fail "$name: acme stored $acme rows, expected $((ROWS + 2))"
	[ "$globex" = "$((ROWS + 1))" ] || fail "$name: globex stored $globex rows, expected $((ROWS + 1))"
	[ "$total" = "$((ROWS * 2 + 3))" ] || fail "$name: $total rows stored in all, expected $((ROWS * 2 + 3))"

	kill_server
	RAN="$RAN $name"
	echo "  pass $name: two clients, $ROWS rows each, ${elapsed}s, no row outside its own slice"
}

# --- the legs ------------------------------------------------------------------------------------------
wanted() { [ -z "$ONLY" ] || [ "$ONLY" = "$1" ]; }

echo "door e2e (spec 043): $ROWS rows per client"

if wanted postgres; then
	PG_EXT="$EXT_DIR/postgres_scanner.duckdb_extension"
	if [ ! -f "$PG_EXT" ]; then
		skip_leg postgres "postgres_scanner is not built - rebuild with ACL_INTEGRATION=1"
	elif [ -z "${ACL_PG_DSN:-}" ]; then
		skip_leg postgres "ACL_PG_DSN is not set"
	elif ! why="$(probe "LOAD '$PG_EXT'; ATTACH '$ACL_PG_DSN' AS pg (TYPE postgres); SELECT 1;")"; then
		skip_leg postgres "$why"
	else
		run_leg postgres "LOAD '$PG_EXT';" \
			"ATTACH '$ACL_PG_DSN' AS pg (TYPE postgres);" "pg.public.e2e_orders" "$BASE_PORT"
	fi
fi

if wanted mssql; then
	MS_EXT="$EXT_DIR/mssql.duckdb_extension"
	if [ ! -f "$MS_EXT" ]; then
		skip_leg mssql "the mssql extension is not built"
	elif [ -z "${ACL_MSSQL_DSN:-}" ]; then
		skip_leg mssql "ACL_MSSQL_DSN is not set"
	elif ! why="$(probe "LOAD '$MS_EXT'; ATTACH '$ACL_MSSQL_DSN' AS ms (TYPE mssql); SELECT 1;")"; then
		skip_leg mssql "$why"
	else
		run_leg mssql "LOAD '$MS_EXT';" \
			"ATTACH '$ACL_MSSQL_DSN' AS ms (TYPE mssql);" "ms.dbo.e2e_orders" "$((BASE_PORT + 1))"
	fi
fi

if wanted ducklake; then
	LAKE_EXT="$EXT_DIR/ducklake.duckdb_extension"
	PARQUET_EXT="$EXT_DIR/parquet.duckdb_extension"
	PG_EXT="$EXT_DIR/postgres_scanner.duckdb_extension"
	if [ ! -f "$LAKE_EXT" ]; then
		skip_leg ducklake "ducklake is not built - rebuild with ACL_INTEGRATION=1"
	elif [ -z "${ACL_DUCKLAKE_DSN:-}" ]; then
		skip_leg ducklake "ACL_DUCKLAKE_DSN is not set"
	else
		LAKE_ATTACH="ATTACH '$ACL_DUCKLAKE_DSN' AS lake (DATA_PATH '$TMP/lake_data', OVERRIDE_DATA_PATH TRUE);"
		if ! why="$(probe "LOAD '$PARQUET_EXT'; LOAD '$PG_EXT'; LOAD '$LAKE_EXT'; $LAKE_ATTACH SELECT 1;")"; then
			skip_leg ducklake "$why"
		else
			run_leg ducklake "LOAD '$PARQUET_EXT'; LOAD '$PG_EXT'; LOAD '$LAKE_EXT';" \
				"$LAKE_ATTACH" "lake.main.e2e_orders" "$((BASE_PORT + 2))"
		fi
	fi
fi

echo "---"
[ -n "$RAN" ] || fail "no leg ran: nothing was proven (skipped:${SKIPPED:- none})"
echo "PASS: legs run:${RAN}${SKIPPED:+, skipped:$SKIPPED}"
