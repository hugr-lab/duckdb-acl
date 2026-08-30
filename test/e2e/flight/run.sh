#!/usr/bin/env bash
# The Arrow Flight SQL door, end to end (spec 045).
#
# One duckdb process serves; the client is a separate process speaking Flight SQL through pyarrow -
# third-party on purpose, because a door is only proven by something that is not us. pyarrow ships
# Flight but not Flight SQL, so client.py encodes the one command it needs by hand; that is a feature
# of the test rather than a shortcut, since it means nothing about the exchange is taken on trust from
# a library that shares our assumptions.
#
# Skips (exit 0, saying why) without an ACL_FLIGHT build or without pyarrow. Fails loudly otherwise.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
HERE="$(cd "$(dirname "$0")" && pwd)"
BUILD="${BUILD_DIR:-$ROOT/build/release}"
DUCKDB="${DUCKDB_BIN:-$BUILD/duckdb}"
ACL_EXT="${ACL_EXT:-$BUILD/extension/acl/acl.duckdb_extension}"
PORT="${ACL_FLIGHT_PORT:-32700}"
URI="grpc://localhost:$PORT"

# An HS256 token for the seeded issuer: role analyst, tenant acme, exp in 2100.
TOKEN='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci50ZXN0L3MiLCJhdWQiOiJhcGk6Ly9hY2wtdGVzdCIsImV4cCI6NDEwMjQ0NDgwMCwic3ViIjoidS1hY21lIiwicm9sZXMiOlsiYW5hbHlzdCJdLCJ0aWQiOiJhY21lIn0.vzPJbHXAXfczhZwQp183JaaBLlSRSipNsSqwxoIFfng'

fail() { echo "FAIL: $*" >&2; exit 1; }

[ -x "$DUCKDB" ] || { echo "SKIP: no duckdb CLI at $DUCKDB"; exit 0; }
[ -f "$ACL_EXT" ] || { echo "SKIP: no acl extension at $ACL_EXT"; exit 0; }
have="$(echo "LOAD '$ACL_EXT'; SELECT count(*) FROM duckdb_functions() WHERE function_name='acl_flight_serve';" \
        | "$DUCKDB" -unsigned -noheader -list 2>/dev/null | tail -1 | tr -d ' ')"
if [ "$have" != "1" ]; then
	echo "SKIP: this build has no Flight door - it was built with ACL_NO_FLIGHT=1, or on WASM"
	exit 0
fi
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
	# hold the process open for the length of the run; the door lives in it
	echo "SELECT 1;"
} >"$TMP/server.sql"
# stdin is held open by a FIFO for the length of the run: the CLI exits when stdin closes, the door
# has to outlive the statements that opened it, and stopping it means sending a statement to the very
# process that serves - `acl_flight_stop` closes a door in its own process and nobody else's.
FIFO="$TMP/ctl"
mkfifo "$FIFO"
"$DUCKDB" -unsigned <"$FIFO" >"$TMP/server.log" 2>&1 &
SERVER_PID=$!
exec 3>"$FIFO"
cat "$TMP/server.sql" >&3

# Wait for the door rather than sleeping and hoping.
ready=""
for _ in $(seq 1 60); do
	if ! kill -0 "$SERVER_PID" 2>/dev/null; then
		cat "$TMP/server.log" >&2
		fail "the server exited before it was serving"
	fi
	if python3 "$HERE/client.py" "$URI" "SELECT 1 AS ok" "$TOKEN" >/dev/null 2>&1; then
		ready=1; break
	fi
	sleep 0.5
done
[ -n "$ready" ] || { cat "$TMP/server.log" >&2; fail "the door never came up on $URI"; }

# `|| true` because half of what follows is a refusal, and under `set -e` a client that exits non-zero
# would end the run before the assertion could say what it saw.
ask() { python3 "$HERE/client.py" "$URI" "$1" "${2:-$TOKEN}" 2>&1 || true; }

# --- the principal reads its own slice, and only that ---------------------------------------------
# Five acme rows out of ten seeded; the predicate is what makes the other five invisible.
got="$(ask "SELECT count(*) AS n FROM orders")"
echo "$got" | grep -q "'n': \[5\]" || fail "expected 5 rows for this tenant, got: $got"

got="$(ask "SELECT count(*) AS n FROM orders WHERE tenant = 'globex'")"
echo "$got" | grep -q "'n': \[0\]" || fail "another tenant's rows were visible: $got"

# --- the physical object is refused by the same path that refuses it anywhere ----------------------
got="$(ask "SELECT * FROM memory.main.orders")"
echo "$got" | grep -q "no access to object" || fail "the physical name was not refused: $got"

# --- a token nobody can verify does not get in -----------------------------------------------------
got="$(ask "SELECT 1" "not-a-jwt")"
echo "$got" | grep -q "authentication failed" || fail "an unverifiable token was admitted: $got"

# --- and neither does a call carrying no credentials at all -------------------------------------------
# An earlier cut remembered the session against the Flight peer, so a call without a token was answered
# from whatever had authenticated from that address and port before. Ports are reused; this is the
# assertion that keeps that from coming back.
got="$(ask "SELECT 1" "-")"
echo "$got" | grep -q "authentication failed" || fail "a call with no token was admitted: $got"

# --- the catalog RPCs answer the principal's catalog, not the instance's (spec 046) --------------
# Everything below is a listing composed as SQL and run through the same prefix, so what is really
# being asserted is that no second path to the catalog exists: the physical database the objects live
# in is `memory`, and it appears in none of these answers.
got="$(ask "@catalogs")"
[ "$got" = "{'catalog_name': ['c']}" ] || fail "GetCatalogs is not the principal's: $got"

got="$(ask "@schemas")"
echo "$got" | grep -q "'db_schema_name': \['main'\]" || fail "GetDbSchemas: $got"
case "$got" in *memory*) fail "the physical database was listed: $got";; esac

got="$(ask "@tables")"
echo "$got" | grep -q "'table_name': \['customers', 'orders'\]" || fail "GetTables: $got"
case "$got" in *memory*) fail "the physical database was listed: $got";; esac

# A filter arrives as a parameter on our side and as a protobuf field on the client's; a field number
# we got wrong would show up here as a filter that did not filter.
got="$(ask "@tables:cust%")"
echo "$got" | grep -q "'table_name': \['customers'\]" || fail "the name pattern did not narrow: $got"

got="$(ask "@table_types_filter:VIEW")"
echo "$got" | grep -q "'table_name': \[\]" || fail "a type filter for VIEW returned tables: $got"

# GetTableTypes has to come from the same rows GetTables did, or a client filters itself into nothing
got="$(ask "@types")"
[ "$got" = "{'table_type': ['BASE TABLE']}" ] || fail "GetTableTypes: $got"

# --- include_schema describes what the role reads, not what the table has -------------------------
# `ssn` is a real column of the physical customers table and is granted to nobody. It must be absent
# from the schema the client is *promised*, not only from the rows it gets (specs 026, 046).
got="$(ask "@tables_schema")"
echo "$got" | grep -q "\['id:int64', 'name:string'\]" || fail "the promised schema is wrong: $got"
case "$got" in *ssn*) fail "a column the role cannot read was in the promised schema: $got";; esac

# --- references are the foreign keys (spec 022) ---------------------------------------------------
got="$(ask "@imported:orders")"
echo "$got" | grep -q "'fk_column_name': \['customer_id'\]" || fail "imported keys: $got"
echo "$got" | grep -q "'pk_column_name': \['id'\]" || fail "imported keys, parent side: $got"
echo "$got" | grep -q "'key_sequence': \[1\]" || fail "key_sequence is not 1-based: $got"

# the same reference, from the other end
got="$(ask "@exported:customers")"
echo "$got" | grep -q "'fk_table_name': \['orders'\]" || fail "exported keys: $got"

got="$(ask "@cross:customers,orders")"
echo "$got" | grep -q "'fk_column_name': \['customer_id'\]" || fail "cross reference: $got"

# and the direction that is not a key is not one
got="$(ask "@imported:customers")"
echo "$got" | grep -q "'fk_column_name': \[\]" || fail "the parent imported something: $got"

# --- primary keys answer the DECLARED key (spec 048) ----------------------------------------------
got="$(ask "@pk:orders")"
echo "$got" | grep -q "'column_name': \['id'\]" || fail "GetPrimaryKeys did not answer the declared key: $got"
echo "$got" | grep -q "'key_sequence': \[1\]" || fail "key_sequence: $got"

# the declared key reaches the promised Arrow schema: id is a non-nullable field
got="$(ask "@tables_schema")"
echo "$got" | grep -q "'id:int64 NOT NULL'" || fail "the promised schema does not carry the key's NOT NULL: $got"

# --- text DML through DoPut(CommandStatementUpdate) - the JDBC executeUpdate wire -----------------
got="$(ask "@update:INSERT INTO orders (id, tenant, amount, customer_id) VALUES (500, 'acme', 5, 0)")"
echo "$got" | grep -q "{'count': 1}" || fail "the update wire did not land one row: $got"

got="$(ask "@update:INSERT INTO orders (id, tenant, amount, customer_id) VALUES (501, 'globex', 5, 0)")"
case "$got" in *"does not satisfy the grant"*) ;; *) fail "a cross-tenant update-wire row was not refused: $got";; esac

# --- bulk ingestion through DoPut(CommandStatementIngest) - spec 049 ------------------------------
got="$(ask "@ingest:orders:append:id,tenant,amount,customer_id:700,acme,7,0;701,acme,8,1")"
echo "$got" | grep -q "{'count': 2}" || fail "the ingest did not land two rows: $got"
got="$(ask "SELECT count(*) FROM orders WHERE id IN (700, 701)")"
echo "$got" | grep -q "\[2\]" || fail "the ingested rows did not read back: $got"
got="$(ask "@ingest:orders:append:id,tenant,amount,customer_id:710,globex,7,0")"
case "$got" in *"does not satisfy the grant"*) ;; *) fail "a cross-tenant ingest was not refused: $got";; esac
got="$(ask "SELECT count(*) FROM orders WHERE id = 710")"
echo "$got" | grep -q "\[0\]" || fail "the refused ingest left rows behind: $got"
got="$(ask "@ingest:newtab:create:id:1")"
case "$got" in *"does not create tables"*) ;; *) fail "mode create was not refused with the reason: $got";; esac
got="$(ask "@ingest:orders:replace:id:1")"
case "$got" in *"does not replace tables"*) ;; *) fail "mode replace was not refused with the reason: $got";; esac
# temporary now stages into the session (spec 050) - so a cookie-less call has nowhere to hold it;
# the session-borne success is asserted in the temp section below, where sessions are expected
got="$(ask "@ingest:stage_raw:temp:id,amount:720,1;721,2")"
case "$got" in *"lives in the session"*) ;; *) fail "a cookie-less temporary ingest was not refused: $got";; esac
got="$(ask "@ingest:orders:append:id,tenant,nope:1,acme,1")"
case "$got" in *nope*) ;; *) fail "an unknown ingest column was not named in the refusal: $got";; esac

# --- and none of them is answered without a token --------------------------------------------------
for probe in "@catalogs" "@tables" "@imported:orders"; do
	got="$(ask "$probe" "-")"
	echo "$got" | grep -q "authentication failed" || fail "$probe was answered with no token: $got"
done

# --- a C++ exception under an RPC is a named refusal, and leaves no session behind ------------------
# The second issuer's keys cannot be read and a failed read is fatal, so SessionOpen throws from under
# the door's own authentication - the review's case. gRPC would report that as "Unexpected error in
# RPC handling", which says nothing; the boundary turns it into the message the policy wrote.
FILE_TOKEN='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci50ZXN0L2ZpbGUiLCJhdWQiOiJhcGk6Ly9hY2wtdGVzdCIsImV4cCI6NDEwMjQ0NDgwMCwic3ViIjoidSIsInJvbGVzIjpbImFuYWx5c3QiXX0.xxxx'
for probe in "SELECT 1" "@tables" "@imported:orders"; do
	got="$(ask "$probe" "$FILE_TOKEN")"
	case "$got" in *"Unexpected error in RPC handling"*) fail "$probe: the exception reached gRPC unnamed: $got";; esac
	echo "$got" | grep -q "could not be read" || fail "$probe: the refusal did not say why: $got"
done

# Every RPC opens a session and must close it whichever way it leaves; after everything above -
# refusals, throws and all - the door's own count is what proves nothing was left for the sweeper.
echo "SELECT 'sessions=' || acl_session_count() AS live;" >&3
counted=""
for _ in $(seq 1 40); do
	if grep -q "sessions=" "$TMP/server.log"; then counted=1; break; fi
	sleep 0.25
done
[ -n "$counted" ] || fail "the server did not answer acl_session_count()"
grep -q "sessions=0" "$TMP/server.log" || fail "a session was left open: $(grep sessions= "$TMP/server.log")"

# --- cookie sessions persist a connection across RPCs (spec 050) ----------------------------------
# The raw client above returns no cookie, so every call was transient and the count is 0. A client
# that echoes the door's cookie keeps ONE session across calls - the foundation temp tables need.
JAR="$TMP/cookiejar"
ACL_COOKIE_JAR="$JAR" ask "SELECT 1" >/dev/null   # call 1: the door mints and sets the cookie
ACL_COOKIE_JAR="$JAR" ask "SELECT 1" >/dev/null   # call 2: the client returns it -> same session
[ -s "$JAR" ] || fail "the door never set a session cookie"
echo "SELECT 'cookielive=' || acl_session_count() AS live;" >&3
counted=""
for _ in $(seq 1 40); do
	if grep -q "cookielive=" "$TMP/server.log"; then counted=1; break; fi
	sleep 0.25
done
[ -n "$counted" ] || fail "the server did not answer the cookie session count"
grep -q "cookielive=1" "$TMP/server.log" || fail "a cookie connection did not reuse ONE session: $(grep cookielive= "$TMP/server.log")"

# --- session temp tables live on the cookie connection (spec 050) ---------------------------------
# Created through the update wire on a cookie session, resolved by a later read on the SAME session
# (the authoritative direct-scan path: the door hands the rewriter the executing context), listed by
# the session's own SHOW TABLES - and invisible to every other session, including a different
# principal riding a stolen cookie (F5), whose re-authentication ends the session and its temp.
TJ="$TMP/tempjar"
# prime the jar: the first call of a connection is transient (the client has no cookie to return
# yet), and a transient session's temp would honestly die with the call - a real driver's handshake
# RPCs prime this for free
ACL_COOKIE_JAR="$TJ" ask "SELECT 1" >/dev/null
got="$(ACL_COOKIE_JAR="$TJ" ask "@update:CREATE TEMP TABLE scratch AS SELECT r AS id FROM range(5) t(r)")"
echo "$got" | grep -q "'count':" || fail "CREATE TEMP on a cookie session failed: $got"
got="$(ACL_COOKIE_JAR="$TJ" ask "SELECT count(*) AS n FROM scratch")"
echo "$got" | grep -q "'n': \[5\]" || fail "the session's temp did not resolve on its own connection: $got"
got="$(ACL_COOKIE_JAR="$TJ" ask "SELECT name FROM (SHOW TABLES) WHERE name = 'scratch'")"
echo "$got" | grep -q "'name': \['scratch'\]" || fail "SHOW TABLES does not list the session's temp: $got"
# and the protocol's own catalog RPC agrees with SHOW TABLES - one catalog, not two
got="$(ACL_COOKIE_JAR="$TJ" ask "@tables")"
echo "$got" | grep -q "scratch" || fail "GetTables does not list the session's temp: $got"
# another connection of the SAME principal is another session, and the temp is not in it - the
# refusal is the authoritative one, because the door knows that session's temp catalog is empty
got="$(ACL_COOKIE_JAR="$TMP/otherjar" ask "SELECT * FROM scratch")"
echo "$got" | grep -q "no access to object" || fail "another session reached the temp: $got"
# a different principal on the stolen cookie earns nothing: the fingerprint mismatch closes the
# old session - temp and all - and opens their own, where the name does not exist
GLOBEX='eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJpc3MiOiAiaHR0cHM6Ly9pc3N1ZXIudGVzdC9zIiwgImF1ZCI6ICJhcGk6Ly9hY2wtdGVzdCIsICJleHAiOiA0MTAyNDQ0ODAwLCAic3ViIjogInUtZ2xvYmV4IiwgInJvbGVzIjogWyJhbmFseXN0Il0sICJ0aWQiOiAiZ2xvYmV4In0.N92ysQlqQLA2PapK-VdxsokNyXPxPlmO6YQJVQB8H6I'
got="$(ACL_COOKIE_JAR="$TJ" ask "SELECT * FROM scratch" "$GLOBEX")"
echo "$got" | grep -q "no access to object" || fail "a stolen cookie carried a temp across principals: $got"
got="$(ACL_COOKIE_JAR="$TJ" ask "SELECT * FROM scratch")"
echo "$got" | grep -q "no access to object" || fail "the temp survived a re-authentication that should have ended its session: $got"
# the raw ingest wire stages into the session too (spec 049 milestone 2, completed by spec 050)
IJ="$TMP/ingestjar"
ACL_COOKIE_JAR="$IJ" ask "SELECT 1" >/dev/null
got="$(ACL_COOKIE_JAR="$IJ" ask "@ingest:stage_raw:temp:id,amount:720,1;721,2")"
echo "$got" | grep -q "'count': 2" || fail "the temporary ingest did not land on the session: $got"
got="$(ACL_COOKIE_JAR="$IJ" ask "SELECT count(*) AS n FROM stage_raw")"
echo "$got" | grep -q "'n': \[2\]" || fail "the staged rows did not read back on the session: $got"
# a client's own BEGIN spans RPCs on the held connection - and ingest refuses to load inside a
# transaction it would not own, so a partial load can never be committed by the client
got="$(ACL_COOKIE_JAR="$IJ" ask "@update:BEGIN TRANSACTION")"
echo "$got" | grep -q "'count':" || fail "BEGIN on the session connection failed: $got"
got="$(ACL_COOKIE_JAR="$IJ" ask "@ingest:stage_txn:temp:id,amount:1,1")"
case "$got" in *"inside an open transaction"*) ;; *) fail "ingest inside a client transaction was not refused: $got";; esac
got="$(ACL_COOKIE_JAR="$IJ" ask "@update:ROLLBACK")"
echo "$got" | grep -q "'count':" || fail "ROLLBACK on the session connection failed: $got"

# drop is symmetric with resolution, on the session that owns the object
DJ="$TMP/dropjar"
ACL_COOKIE_JAR="$DJ" ask "SELECT 1" >/dev/null
got="$(ACL_COOKIE_JAR="$DJ" ask "@update:CREATE TEMP TABLE gone(id INTEGER)")"
echo "$got" | grep -q "'count':" || fail "CREATE TEMP for the drop check failed: $got"
got="$(ACL_COOKIE_JAR="$DJ" ask "@update:DROP TABLE gone")"
echo "$got" | grep -q "'count':" || fail "DROP of the session's temp failed: $got"
got="$(ACL_COOKIE_JAR="$DJ" ask "SELECT * FROM gone")"
echo "$got" | grep -q "no access to object" || fail "the dropped temp still resolves: $got"

# --- and the door closes ------------------------------------------------------------------------------
echo "SELECT acl_flight_stop('$URI');" >&3
stopped=""
for _ in $(seq 1 40); do
	if ! python3 "$HERE/client.py" "$URI" "SELECT 1" "$TOKEN" >/dev/null 2>&1; then
		stopped=1; break
	fi
	sleep 0.25
done
[ -n "$stopped" ] || fail "the door was still answering after acl_flight_stop"
grep -q "session(s) closed" "$TMP/server.log" || fail "acl_flight_stop did not report what it closed"

echo "PASS: a third-party Flight SQL client read its own slice, a cookie connection reused one session, session temp tables stayed the session's own, and the door closed"
