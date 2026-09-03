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
# the reader ticks through the whole load; the victim carries a load big enough to still be in flight
# when it is killed, KILL_AFTER seconds in
READER_TICKS="${ACL_E2E_READER_TICKS:-300}"
JOIN_TICKS="${ACL_E2E_JOIN_TICKS:-100}"
VICTIM_ROWS="${ACL_E2E_VICTIM_ROWS:-$((ROWS * 10))}"
KILL_AFTER="${ACL_E2E_KILL_AFTER:-1}"
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
	local name="$1" loads="$2" attach="$3" table="$4" port="$5" extra="${6:-}"
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
			"ACL_E2E_ATTACH=$attach" "ACL_E2E_TABLE=$table" "ACL_E2E_EXTRA=$extra" \
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

	# A reader of one tenant ticking through the whole load (spec 043: a reader running *during*
	# another client's drain). Every tick must count zero foreign rows; and since an ingest is one
	# statement, a tick sees either the whole of its tenant's load or none of it - never a part.
	local own_acme="id IN (1, 3) OR (id >= 1000000 AND id < $((1000000 + ROWS)))"
	{
		echo "$L"
		echo "ATTACH 'quack:localhost:$port' AS remote (TYPE quack, TOKEN '$TOKEN_ACME');"
		local t
		for t in $(seq 1 "$READER_TICKS"); do
			echo "SELECT 'tick' AS label, count(*) AS n, count(*) FILTER (WHERE NOT ($own_acme)) AS foreign_rows" \
			     "FROM remote.main.orders;"
		done
	} >"$TMP/$name.reader.sql"

	# A client that dies mid-statement (spec 043: session lifecycle across clients): a third writer, of
	# tenant globex, with a load large enough to still be in flight when it is killed. Its output is
	# never read; what is asserted is everybody else, the door afterwards, and what it left stored.
	{
		echo "$L"
		render "$HERE/client.sql" \
			"ACL_E2E_PORT=$port" "ACL_E2E_TOKEN=$TOKEN_GLOBEX" "ACL_E2E_OWN=id IN (2) OR id >= 2000000" \
			"ACL_E2E_ROWS=$VICTIM_ROWS" "ACL_E2E_ID_BASE=3000000"
	} >"$TMP/$name.victim.sql"

	# Started here rather than in a function: a background process launched inside a command
	# substitution belongs to that subshell, and the wait below could not see it.
	"$DUCKDB" -unsigned -csv <"$TMP/$name.acme.sql" >"$TMP/$name.acme.out" 2>&1 &
	local pid_acme=$!
	"$DUCKDB" -unsigned -csv <"$TMP/$name.globex.sql" >"$TMP/$name.globex.out" 2>&1 &
	local pid_globex=$!
	"$DUCKDB" -unsigned -csv <"$TMP/$name.reader.sql" >"$TMP/$name.reader.out" 2>&1 &
	local pid_reader=$!
	# through a subshell that records duckdb's own pid: the SIGKILL goes to duckdb, the subshell exits
	# normally with its status, and bash has no signalled job to announce ("Killed: 9") mid-run
	( "$DUCKDB" -unsigned -csv <"$TMP/$name.victim.sql" >"$TMP/$name.victim.out" 2>&1 &
	  echo $! >"$TMP/$name.victim.pid"; wait ) 2>/dev/null &
	local pid_victim=$!

	# The cross-source join under load (spec 043), on a leg that publishes a second object over another
	# source: one client joins its orders to its rates through the catalog, tick after tick, while the
	# writers drain into orders. Each tick is its own slice joined to its own rate and nothing else -
	# a rates row of another tenant leaking through would show as a sum that is not n x its rate.
	local pid_joiner=""
	if [ -n "$extra" ]; then
		{
			echo "$L"
			echo "ATTACH 'quack:localhost:$port' AS remote (TYPE quack, TOKEN '$TOKEN_ACME');"
			local t
			for t in $(seq 1 "$JOIN_TICKS"); do
				echo "SELECT 'join' AS label, count(*) AS n, count(*) FILTER (WHERE NOT ($own_acme)) AS foreign_rows," \
				     "coalesce(sum(r.rate), 0) AS rates" \
				     "FROM remote.main.orders o JOIN remote.main.rates r ON o.tenant = r.tenant;"
			done
		} >"$TMP/$name.joiner.sql"
		"$DUCKDB" -unsigned -csv <"$TMP/$name.joiner.sql" >"$TMP/$name.joiner.out" 2>&1 &
		pid_joiner=$!
	fi

	# The deadline is polled here rather than delegated to a background `( sleep N; kill )`. Such a
	# watchdog inherits this script's stdout, and killing the subshell leaves its `sleep` orphaned and
	# still holding the pipe - so every reader of our output blocks for the whole timeout after the test
	# has already passed. Measured on this very script: the run took 0.7s, the `tail` reading it 3 minutes.
	local started deadline timed_out="" victim_killed="" victim_in_flight=""
	started=$(date +%s)
	deadline=$((started + CLIENT_TIMEOUT))
	while kill -0 "$pid_acme" 2>/dev/null || kill -0 "$pid_globex" 2>/dev/null ||
	      kill -0 "$pid_reader" 2>/dev/null || kill -0 "$pid_victim" 2>/dev/null ||
	      { [ -n "$pid_joiner" ] && kill -0 "$pid_joiner" 2>/dev/null; }; do
		# the victim is killed KILL_AFTER seconds in - with SIGKILL, so nothing of it says goodbye to
		# the server; whether its load was still in flight at that moment is recorded, not assumed
		if [ -z "$victim_killed" ] && [ "$(date +%s)" -ge "$((started + KILL_AFTER))" ]; then
			local victim_duck
			victim_duck="$(cat "$TMP/$name.victim.pid" 2>/dev/null || true)"
			if [ -n "$victim_duck" ] && kill -0 "$victim_duck" 2>/dev/null; then
				victim_in_flight=1
				kill -9 "$victim_duck" 2>/dev/null || true
			fi
			victim_killed=1
		fi
		if [ "$(date +%s)" -ge "$deadline" ]; then
			kill -9 "$pid_acme" "$pid_globex" "$pid_reader" $pid_joiner \
				"$(cat "$TMP/$name.victim.pid" 2>/dev/null)" 2>/dev/null || true
			timed_out=1
			break
		fi
		sleep 0.25
	done
	local rc_acme=0 rc_globex=0 rc_reader=0 rc_joiner=0
	wait "$pid_acme" || rc_acme=$?
	wait "$pid_globex" || rc_globex=$?
	wait "$pid_reader" || rc_reader=$?
	[ -z "$pid_joiner" ] || wait "$pid_joiner" || rc_joiner=$?
	wait "$pid_victim" 2>/dev/null || true
	local elapsed=$(( $(date +%s) - started ))
	[ -z "$timed_out" ] || fail "$name: the clients were still running after ${CLIENT_TIMEOUT}s"
	if [ "$rc_reader" -ne 0 ]; then
		echo "--- $name/reader ---" >&2; tail -20 "$TMP/$name.reader.out" >&2
		fail "$name: the reader exited with $rc_reader"
	fi
	if [ "$rc_joiner" -ne 0 ]; then
		echo "--- $name/joiner ---" >&2; tail -20 "$TMP/$name.joiner.out" >&2
		fail "$name: the joiner exited with $rc_joiner"
	fi

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

	# --- what the reader saw, tick by tick ---
	# Zero foreign rows on every tick is the isolation claim under overlap. The count is the
	# atomicity claim: acme's load is one statement, so a tick counts the seeded 2 or the full
	# ROWS + 2 and nothing in between. Whether the ticks actually straddled the load is reported,
	# not required - a fast machine can finish the load before the reader's first tick.
	local ticks foreign_ticks low high partial overlap
	ticks="$(grep -c '^tick,' "$TMP/$name.reader.out" || true)"
	if [ "$ticks" != "$READER_TICKS" ]; then
		echo "--- $name/reader ---" >&2; tail -20 "$TMP/$name.reader.out" >&2
		fail "$name: the reader printed $ticks ticks, expected $READER_TICKS"
	fi
	foreign_ticks="$(grep '^tick,' "$TMP/$name.reader.out" | cut -d, -f3 | grep -vc '^0$' || true)"
	[ "$foreign_ticks" = "0" ] || fail "$name: the reader saw another tenant's rows on $foreign_ticks tick(s) during the load"
	low="$(grep '^tick,' "$TMP/$name.reader.out" | cut -d, -f2 | grep -c '^2$' || true)"
	high="$(grep '^tick,' "$TMP/$name.reader.out" | cut -d, -f2 | grep -c "^$((ROWS + 2))$" || true)"
	partial=$((ticks - low - high))
	[ "$partial" = "0" ] || fail "$name: the reader saw a partial load on $partial tick(s) - an ingest is one statement, a tick sees all of it or none"
	if [ "$low" -gt 0 ] && [ "$high" -gt 0 ]; then
		overlap="the reader straddled the load ($low ticks before, $high after)"
	else
		overlap="no overlap observed - the load finished before the reader's first tick"
	fi

	# --- what the joiner saw, on a leg with a second source ---
	# The same two claims as the reader's, through a join across sources, plus the rates: every own row
	# joined exactly one rate row, its own tenant's (acme's rate is 10), so the sum is n x 10 - a rates
	# row of another tenant reaching the join would multiply it.
	local joins=""
	if [ -n "$pid_joiner" ]; then
		local jforeign jpartial jbad
		joins="$(grep -c '^join,' "$TMP/$name.joiner.out" || true)"
		if [ "$joins" != "$JOIN_TICKS" ]; then
			echo "--- $name/joiner ---" >&2; tail -20 "$TMP/$name.joiner.out" >&2
			fail "$name: the joiner printed $joins ticks, expected $JOIN_TICKS"
		fi
		jforeign="$(grep '^join,' "$TMP/$name.joiner.out" | cut -d, -f3 | grep -vc '^0$' || true)"
		[ "$jforeign" = "0" ] || fail "$name: the cross-source join saw another tenant's rows on $jforeign tick(s)"
		jpartial="$(grep '^join,' "$TMP/$name.joiner.out" | cut -d, -f2 | grep -vc "^\(2\|$((ROWS + 2))\)$" || true)"
		[ "$jpartial" = "0" ] || fail "$name: the cross-source join saw a partial load on $jpartial tick(s)"
		jbad="$(grep '^join,' "$TMP/$name.joiner.out" | awk -F, '$4 != $2 * 10' | wc -l | tr -d ' ')"
		[ "$jbad" = "0" ] || fail "$name: on $jbad tick(s) the join matched a rate that is not the joiner's own (sum != n x 10)"
	fi

	# --- what is actually stored ---
	# Read the source directly, outside the ACL: the door's own answers cannot be the only witness to
	# what the door wrote. The killed client's rows are either all there or not at all - its ingest
	# was one statement, and a client dying mid-stream is the reason that matters.
	echo "$L $attach
	      SELECT count(*) AS total,
	             count(*) FILTER (WHERE tenant = 'acme') AS acme,
	             count(*) FILTER (WHERE tenant = 'globex') AS globex,
	             count(*) FILTER (WHERE tenant NOT IN ('acme','globex')) AS strays,
	             count(*) FILTER (WHERE id >= 3000000) AS victim
	      FROM $table;" | "$DUCKDB" -unsigned -csv >"$TMP/$name.stored.csv" 2>&1

	local total acme globex strays victim
	read -r total acme globex strays victim <<<"$(tail -1 "$TMP/$name.stored.csv" | tr ',' ' ')"
	[ "$strays" = "0" ] || fail "$name: $strays rows stored with a tenant no client was allowed to write"
	[ "$victim" = "0" ] || [ "$victim" = "$VICTIM_ROWS" ] ||
		fail "$name: the killed client's load is stored in part ($victim of $VICTIM_ROWS rows) - an ingest is all or nothing"
	[ "$acme" = "$((ROWS + 2))" ] || fail "$name: acme stored $acme rows, expected $((ROWS + 2))"
	[ "$globex" = "$((ROWS + 1 + victim))" ] || fail "$name: globex stored $globex rows, expected $((ROWS + 1 + victim))"
	[ "$total" = "$((ROWS * 2 + 3 + victim))" ] || fail "$name: $total rows stored in all, expected $((ROWS * 2 + 3 + victim))"
	local victim_note
	if [ -n "$victim_in_flight" ]; then
		victim_note="a client killed mid-load left $([ "$victim" = "0" ] && echo nothing || echo "its whole load")"
	else
		victim_note="the victim finished before the kill (raise ACL_E2E_VICTIM_ROWS to catch it in flight)"
	fi

	# --- the door after a client died without a goodbye ---
	echo "$L SELECT * FROM quack_query('quack:localhost:$port', 'SELECT 1', token := '$TOKEN_ACME');" \
		| "$DUCKDB" -unsigned >/dev/null 2>&1 || fail "$name: the door stopped answering after a client died mid-statement"

	kill_server
	RAN="$RAN $name"
	echo "  pass $name: two writers x $ROWS rows + a reader x $ticks ticks${joins:+ + a cross-source joiner x $joins ticks}" \
	     "+ a killed writer, ${elapsed}s; no row outside its own slice; $overlap; $victim_note; the door still answers"
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

# postgres x ducklake: the orders on postgres, the rates on the lake, joined through the catalog while
# the writers drain into postgres (spec 043: the cross-source join under load). mysql has no leg to
# pair with at this pin; mssql would be the same shape with one more source.
if wanted pair; then
	PG_EXT="$EXT_DIR/postgres_scanner.duckdb_extension"
	LAKE_EXT="$EXT_DIR/ducklake.duckdb_extension"
	PARQUET_EXT="$EXT_DIR/parquet.duckdb_extension"
	if [ ! -f "$PG_EXT" ] || [ ! -f "$LAKE_EXT" ]; then
		skip_leg pair "postgres_scanner or ducklake is not built - rebuild with ACL_INTEGRATION=1"
	elif [ -z "${ACL_PG_DSN:-}" ] || [ -z "${ACL_DUCKLAKE_DSN:-}" ]; then
		skip_leg pair "ACL_PG_DSN or ACL_DUCKLAKE_DSN is not set"
	else
		LAKE_ATTACH="ATTACH '$ACL_DUCKLAKE_DSN' AS lake (DATA_PATH '$TMP/lake_data', OVERRIDE_DATA_PATH TRUE);"
		PAIR_LOADS="LOAD '$PARQUET_EXT'; LOAD '$PG_EXT'; LOAD '$LAKE_EXT';"
		PAIR_ATTACH="ATTACH '$ACL_PG_DSN' AS pg (TYPE postgres); $LAKE_ATTACH"
		if ! why="$(probe "$PAIR_LOADS $PAIR_ATTACH SELECT 1;")"; then
			skip_leg pair "$why"
		else
			run_leg pair "$PAIR_LOADS" "$PAIR_ATTACH" "pg.public.e2e_orders" "$((BASE_PORT + 3))" \
				"DROP TABLE IF EXISTS lake.main.e2e_rates;
CREATE TABLE lake.main.e2e_rates (tenant VARCHAR, rate INTEGER);
INSERT INTO lake.main.e2e_rates VALUES ('acme', 10), ('globex', 20), ('INTRUDER', 99);
ACL ADMIN CREATE VIRTUAL TABLE c.rates AS lake.main.e2e_rates RLS (tenant = acl_claim('tenant'));"
		fi
	fi
fi

echo "---"
[ -n "$RAN" ] || fail "no leg ran: nothing was proven (skipped:${SKIPPED:- none})"
echo "PASS: legs run:${RAN}${SKIPPED:+, skipped:$SKIPPED}"
