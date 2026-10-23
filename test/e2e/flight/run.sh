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
cd "$ROOT" # spec 095: the fixture issuers (test/idp/) are read relative to the repository root
HERE="$(cd "$(dirname "$0")" && pwd)"
BUILD="${BUILD_DIR:-$ROOT/build/release}"
DUCKDB="${DUCKDB_BIN:-$BUILD/duckdb}"
ACL_EXT="${ACL_EXT:-$BUILD/extension/acl/acl.duckdb_extension}"
PORT="${ACL_FLIGHT_PORT:-32700}"
URI="grpc://localhost:$PORT"

# An RS256 token for the seeded issuer (test/idp/s, the committed fixture key): role analyst, tenant acme, exp in 2100.
TOKEN='eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2V5In0.eyJpc3MiOiJ0ZXN0L2lkcC9zIiwiYXVkIjoiYXBpOi8vYWNsLXRlc3QiLCJleHAiOjQxMDI0NDQ4MDAsInN1YiI6InUtYWNtZSIsInJvbGVzIjpbImFuYWx5c3QiXSwidGlkIjoiYWNtZSJ9.UV5-WWUpQLp-Em8K2yLLkz-NEJgOyTAn9i9B1zpBWF3hNQVgorAVPVK48bxnrMiMm7NabgM3g945lDY31DFwxNeUKnVEe0QdRy1d1KbFh8td3Ak_mepOZ35CjPektGaOjVEpjUFxZUOj_uxYnse_y660xC0stlY8zxDrpSjNCOZRGv-vaxITv7ggOIDYAN07rmPntKe9oOYsb5g0ZkFcIEsKuHuXsL8z1crko6vIZzT9ido-xrph_WEejO5lKaPIxVe1QrB1-C5DUp8D8fnLWMJ3g426VNKWJwUyeSgh_nq1XzLyR8WcLchBQwaFAzkGivmLFmDdrDS7VUy49I8uLw'

fail() { echo "FAIL: $*" >&2; exit 1; }

[ -x "$DUCKDB" ] || { echo "SKIP: no duckdb CLI at $DUCKDB"; exit 0; }
[ -f "$ACL_EXT" ] || { echo "SKIP: no acl extension at $ACL_EXT"; exit 0; }
have="$(echo "LOAD '$ACL_EXT'; SELECT count(*) FROM duckdb_functions() WHERE function_name='acl_flight_serve';" \
        | "$DUCKDB" -unsigned -noheader -list 2>/dev/null | tail -1 | tr -d ' ')"
if [ "$have" = "0" ]; then
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

# --- EXPLAIN is a capability (spec 052): a plan names physical objects, and analyst was not granted it
got="$(ask "EXPLAIN SELECT * FROM orders")"
echo "$got" | grep -q "explain capability" || fail "EXPLAIN was not gated by the capability: $got"

# --- PIVOT through the door (spec 075): the explicit form prepares like any SELECT and answers the
# principal's slice - five acme rows, and nothing for the tenant it cannot see; the implicit form expands into
# several statements, which duckdb prepares with its result unknown (spec 128, duckdb #27108) - the door runs it at
# GetFlightInfo, and its columns are the enum domain the principal reads: acme, never globex
got="$(ask "SELECT * FROM (SELECT tenant FROM orders) PIVOT (count(*) FOR tenant IN ('acme', 'globex'))")"
echo "$got" | grep -q "'acme': \[5\]" || fail "the explicit PIVOT did not answer the tenant's slice: $got"
echo "$got" | grep -q "'globex': \[5\]" && fail "the explicit PIVOT counted another tenant's rows: $got"

got="$(ask "PIVOT (SELECT tenant FROM orders) ON tenant USING count(*)")"
echo "$got" | grep -q "'acme': \[5\]" || fail "the implicit PIVOT did not answer the tenant's slice: $got"
echo "$got" | grep -q "globex" && fail "the implicit PIVOT's columns named another tenant: $got"

# --- spec 109: a lineage parent in a header is checked where it enters - a malformed one is the call's
# error (InvalidArgument, no part of the value echoed); a well-formed one is taken
got="$(ACL_EXTRA_HEADERS="x-openlineage-parent=airflow/daily/not-a-uuid" ask "SELECT 1 AS one")"
echo "$got" | grep -q "x-openlineage-parent: expected <namespace>/<job>/<runId>" ||
	fail "a malformed lineage parent header was not refused: $got"
echo "$got" | grep -q "not-a-uuid" && fail "the refusal echoed the header's value: $got"
got="$(ACL_EXTRA_HEADERS="x-openlineage-parent=airflow/daily/01929e3a-0000-7000-8000-000000000001" ask "SELECT 1 AS one")"
echo "$got" | grep -q "'one'" || fail "a well-formed lineage parent header was refused: $got"

# --- a statement carrying a transaction id that names no open transaction is refused (spec 055) ----
# the security-critical ValidateTxnLocked path: a stolen/invented id cannot ride into a transaction
got="$(ask "@txnq:deadbeefdeadbeefdeadbeefdeadbeef:SELECT 1")"
echo "$got" | grep -q "unknown transaction" || fail "a foreign transaction id was not refused: $got"

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
echo "$got" | grep -q "'db_schema_name': \['Raw Data', 'main', 'stage', 'stage2'\]" || fail "GetDbSchemas: $got"
case "$got" in *memory*) fail "the physical database was listed: $got";; esac

got="$(ask "@tables")"
echo "$got" | grep -q "'table_name': \['Line Items', 'Order Items', 'customers', 'nested', 'orders', 'typed', 'typed_v'\]" || fail "GetTables: $got"
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

# --- spec 143: descriptions in the Arrow schema ---------------------------------------------------------------
# include_schema: each column's comment as Flight SQL's REMARKS - an alias relation's virtual comment over its
# source's, the source's where it has none - and the object's own comment on the schema
got="$(ACL_SHOW_DESCRIBED=1 ask "@tables_schema:orders")"
echo "$got" | grep -q "'amount||remarks:what was paid|'" || fail "include_schema: the column's REMARKS: $got"
echo "$got" | grep -q "'<object>|comment:the orders|'" || fail "include_schema: the object's comment: $got"
got="$(ACL_SHOW_DESCRIBED=1 ask "@tables_schema:customers")"
echo "$got" | grep -q "'name||remarks:PHYS name|'" || fail "include_schema: the source's column comment: $got"
case "$got" in *ssn*) fail "a hidden column was described: $got";; esac

# a result: the virtual object each column reads (Flight SQL's CATALOG_NAME / SCHEMA_NAME / TABLE_NAME) and its
# comment as duckdb:comment - a renamed reference too; an expression has none; GetFlightInfo promised the same
got="$(ACL_SHOW_DESCRIBED=1 ask "SELECT id, amount AS paid, amount + 1 AS more FROM orders")"
echo "$got" | grep -q "'id|c.main.orders||', 'paid|c.main.orders|comment:what was paid|', 'more|||', '<object>||'" ||
	fail "a result's origins: $got"
echo "$got" | grep -q "'__promised_same': True" || fail "GetFlightInfo's schema and DoGet's differ: $got"
case "$got" in *memory*) fail "a physical name reached the result's schema: $got";; esac
# a star over one object: its columns, and the object's comment on the schema
got="$(ACL_SHOW_DESCRIBED=1 ask "SELECT * FROM orders")"
echo "$got" | grep -q "'amount|c.main.orders|comment:what was paid|'" || fail "a star's origins: $got"
echo "$got" | grep -q "'<object>|comment:the orders|'" || fail "one object's comment on the schema: $got"
# a join, each side by its alias; a hidden column is no field, so it has no description
got="$(ACL_SHOW_DESCRIBED=1 ask "SELECT o.amount, k.name FROM orders o JOIN customers k ON o.customer_id = k.id")"
echo "$got" | grep -q "'amount|c.main.orders|comment:what was paid|', 'name|c.main.customers|comment:PHYS name|'" ||
	fail "a join's origins: $got"
# nothing read off an aggregate, a CTE's column or a set operation - nor off a bare value keyword, nor off a star
# beside an expression that makes several columns (its span shifts), nor off a name that is no column of the object
# (a lateral alias, a struct column's field), nor off a placeholder schema (a parameter in a star's relation)
for sql in "SELECT count(*) AS n FROM orders" "WITH x AS (SELECT amount FROM orders) SELECT amount FROM x" \
	"SELECT id FROM orders UNION ALL SELECT id FROM customers" "SELECT current_date AS d FROM orders" \
	"SELECT *, unnest({'a': 1, 'b': 2}) FROM orders" \
	"SELECT current_schema FROM orders" "SELECT amount + 1 AS z, z FROM orders" \
	"SELECT o.x FROM orders o, (SELECT {'x': 1} AS o) s" \
	"SELECT unnest({'a': 1, 'b': 2}), o.amount, x.* FROM orders o, (SELECT 1 AS q) x" \
	"SELECT unnest({'q': 5, 'amount': 1}), o.amount, s.* FROM orders o, (SELECT 1 AS z) s" \
	"@prepared_fields:SELECT orders.amount, x.* FROM orders, (SELECT ? AS p) x"; do
	got="$(ACL_SHOW_DESCRIBED=1 ask "$sql")"
	echo "$got" | grep -q "c.main" && fail "an origin was read off \"$sql\": $got"
done
# a prepared statement announces the same schema
got="$(ACL_SHOW_DESCRIBED=1 ask "@prepared_fields:SELECT amount FROM orders")"
echo "$got" | grep -q "'amount|c.main.orders|comment:what was paid|'" || fail "a prepared statement's origins: $got"

# --- spec 099: an ENUM goes out as an Arrow dictionary, or as utf8 where the table reads it as VARCHAR -----
# the promised schema and the stream agree either way: a client never decodes what it was not told
got="$(ACL_SHOW_SCHEMA=1 ask "SELECT tier, s FROM typed")"
echo "$got" | grep -q "'tier:dictionary<values=string" || fail "a kept ENUM did not go out as a dictionary: $got"
got="$(ACL_SHOW_SCHEMA=1 ask "SELECT tier, s FROM typed_v")"
echo "$got" | grep -q "'tier:string', 's:struct<a: string>'" || fail "an ENUM read as VARCHAR went out as: $got"
echo "$got" | grep -q "'tier': \['gold'\]" || fail "the cast ENUM's value: $got"
got="$(ask "@tables_schema:typed_v")"
echo "$got" | grep -q "\['id:int32', 'tier:string', 's:struct<a: string>'\]" || fail "the promised schema of typed_v: $got"

# --- spec 102: a struct narrowed to one field goes out with only that child --------------------------
got="$(ACL_SHOW_SCHEMA=1 ask "SELECT address FROM nested")"
echo "$got" | grep -q "'address:struct<city: string>'" || fail "the narrowed struct's Arrow schema: $got"
case "$got" in *ssn*|*S1*) fail "a hidden field reached the Flight client: $got";; esac
got="$(ask "@tables_schema:nested")"
echo "$got" | grep -q "'address:struct<city: string>'" || fail "the promised schema of the narrowed struct: $got"

# --- spec 115: what a tool reads to build names, types and its tree -----------------------------------
# SqlInfo, each value by its id: 504 identifier quote, 531 catalog term, 532 catalog at start, 513 search
# escape, 563 transactions supported
got="$(ask "@sqlinfo:504,513,531,532,563")"
echo "$got" | grep -q "504: '\"'" || fail "GetSqlInfo 504 (identifier quote): $got"
echo "$got" | grep -q "513: '\\\\\\\\'" || fail "GetSqlInfo 513 (search escape): $got"
echo "$got" | grep -q "531: 'catalog'" || fail "GetSqlInfo 531 (catalog term): $got"
echo "$got" | grep -q "532: True" || fail "GetSqlInfo 532 (catalog at start): $got"
echo "$got" | grep -q "563: True" || fail "GetSqlInfo 563 (transactions supported): $got"
got="$(ask "@sqlinfo:508")"
echo "$got" | grep -q "'NATIVE'" || fail "GetSqlInfo: keywords lack the management grammar's: $got"
echo "$got" | grep -q "'QUALIFY'" || fail "GetSqlInfo: keywords lack duckdb's reserved words: $got"
# the escape announced is the escape applied: `_` in a pattern is a literal underscore when escaped
got="$(ask '@tables:typed\_v')"
echo "$got" | grep -q "'table_name': \['typed_v'\]" || fail "GetTables with an escaped underscore: $got"
got="$(ask "@xdbc")"
echo "$got" | grep -q "'VARCHAR'" || fail "GetXdbcTypeInfo: $got"
echo "$got" | grep -q "'STRUCT'" || fail "GetXdbcTypeInfo lacks STRUCT: $got"
got="$(ask "@xdbc:3")"
echo "$got" | grep -q "'type_name': \['DECIMAL'\]" || fail "GetXdbcTypeInfo filtered by data_type: $got"
# the full type text on every field - the statement's schema and the promised one
got="$(ACL_SHOW_TYPE_NAMES=1 ask "SELECT id, address FROM nested")"
echo "$got" | grep -q "'id:INTEGER', 'address:STRUCT(city VARCHAR)'" || fail "TYPE_NAME on a result: $got"
got="$(ACL_SHOW_TYPE_NAMES=1 ask "@tables_schema:nested")"
echo "$got" | grep -q "'address:STRUCT(city VARCHAR)'" || fail "TYPE_NAME in include_schema (the narrowed type): $got"
got="$(ACL_SHOW_TYPE_NAMES=1 ask "SELECT 1.5::DECIMAL(9,2) AS d, [1, 2] AS l, MAP {'k': 1} AS m")"
echo "$got" | grep -q "'d:DECIMAL(9,2)/9/2', 'l:INTEGER\[\]', 'm:MAP(VARCHAR, INTEGER)'" || fail "TYPE_NAME of DECIMAL/LIST/MAP: $got"
got="$(ACL_SHOW_PARAM_TYPE_NAMES=1 ask "@prepared_fields:SELECT id FROM orders WHERE amount > ?::DECIMAL(9,2)")"
echo "$got" | grep -q "DECIMAL(9,2)/9/2" || fail "TYPE_NAME on a prepared statement's parameter: $got"

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

# --- spec 116: quoted names - each shown unquoted, filtered, described and keyed by the name as written --
got="$(ask "@tables:Order%")"
echo "$got" | grep -q "'db_schema_name': \['Raw Data'\], 'table_name': \['Order Items'\]" || fail "GetTables, a quoted name: $got"
got="$(ask "@tables_schema:Order Items")"
echo "$got" | grep -q "\['id:int64 NOT NULL', 'Qty:int64'\]" || fail "include_schema of a quoted table: $got"
got="$(ask 'SELECT count(*) AS n FROM "Raw Data"."order items"')"
echo "$got" | grep -q "'n': \[3\]" || fail "a quoted name read case-insensitively: $got"
got="$(ask "@pk:Raw Data/Order Items")"
echo "$got" | grep -q "'column_name': \['id'\]" || fail "GetPrimaryKeys of a quoted table: $got"
got="$(ask "@imported:Raw Data/Line Items")"
echo "$got" | grep -q "'pk_db_schema_name': \['Raw Data'\], 'pk_table_name': \['Order Items'\]" || fail "imported keys between quoted tables: $got"
echo "$got" | grep -q "'fk_column_name': \['Order Id'\]" || fail "imported keys, the quoted column: $got"
got="$(ask "@exported:Raw Data/Order Items")"
echo "$got" | grep -q "'fk_table_name': \['Line Items'\]" || fail "exported keys of a quoted table: $got"

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

# --- spec 111: DML sent as a query runs at GetFlightInfo ("GetFlightInfo: execute the query") - a
# client that never fetches does not lose the write; one that fetches gets its count once; a refusal
# is the execute's own error
got="$(ask "@nofetch:INSERT INTO orders (id, tenant, amount, customer_id) VALUES (520, 'acme', 5, 0)")"
echo "$got" | grep -q "'endpoints': 1" || fail "an unfetched DML query did not answer its FlightInfo: $got"
got="$(ask "SELECT count(*) AS n FROM orders WHERE id = 520")"
echo "$got" | grep -q "'n': \[1\]" || fail "an unfetched DML was lost: $got"
got="$(ask "INSERT INTO orders (id, tenant, amount, customer_id) VALUES (521, 'acme', 5, 0)")"
echo "$got" | grep -q "\[1\]" || fail "a fetched DML query did not answer its count: $got"
got="$(ask "SELECT count(*) AS n FROM orders WHERE id = 521")"
echo "$got" | grep -q "'n': \[1\]" || fail "a fetched DML query ran other than once: $got"
got="$(ask "@nofetch:INSERT INTO orders (id, tenant, amount, customer_id) VALUES (522, 'globex', 5, 0)")"
case "$got" in *"does not satisfy the grant"*) ;; *) fail "a refused DML query did not fail at its execute: $got";; esac
# a prepared DML announces itself as an update (an empty dataset schema: JDBC takes DoPut); a prepared
# SELECT keeps its columns
got="$(ask "@prepared_fields:INSERT INTO orders (id, tenant, amount, customer_id) VALUES (?, 'acme', 1, 0)")"
echo "$got" | grep -q "'fields': 0" || fail "a prepared DML did not announce an empty dataset schema: $got"
got="$(ask "@prepared_fields:SELECT id, amount FROM orders")"
echo "$got" | grep -q "'fields': 2" || fail "a prepared SELECT lost its dataset schema: $got"
got="$(ask "@prepared_fields:INSERT INTO orders (id, tenant, amount, customer_id) VALUES (?, 'acme', 1, 0) RETURNING id")"
echo "$got" | grep -q "'fields': [1-9]" || fail "a prepared DML with RETURNING was announced as an update: $got"

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
case "$got" in *"no schema of the catalog allows creating"*) ;; *) fail "mode create was not refused with the reason: $got";; esac
got="$(ask "@ingest:orders:replace:id:1")"
case "$got" in *"no schema of the catalog allows creating"*) ;; *) fail "mode replace was not refused with the reason: $got";; esac

# --- and a schema granted create+drop takes an ingest-created table (spec 051) ---------------------
got="$(ask "@ingest:stage.fresh:create:id,amount:800,1;801,2")"
echo "$got" | grep -q "'count': 2" || fail "mode create did not land in the staging schema: $got"
got="$(ask "SELECT count(*) AS n FROM stage.fresh")"
echo "$got" | grep -q "'n': \[2\]" || fail "the created table did not read back: $got"
got="$(ask "@ingest:stage.fresh:replace:id,amount:900,9")"
echo "$got" | grep -q "'count': 1" || fail "mode replace did not swap the table: $got"
got="$(ask "SELECT count(*) AS n FROM stage.fresh")"
echo "$got" | grep -q "'n': \[1\]" || fail "the replaced table did not read back: $got"
got="$(ask "@update:DROP TABLE stage.fresh")"
echo "$got" | grep -q "'count':" || fail "DROP of the created table failed: $got"
# create-only prices CREATE and nothing more: replace through the door is refused without drop
got="$(ask "@ingest:stage2.once:create:id:1")"
echo "$got" | grep -q "'count': 1" || fail "create into the create-only schema failed: $got"
got="$(ask "@ingest:stage2.once:replace:id:2")"
case "$got" in *"drop"*) ;; *) fail "replace without drop was not refused: $got";; esac
got="$(ask "SELECT count(*) AS n FROM stage2.once")"
echo "$got" | grep -q "'n': \[1\]" || fail "the refused replace touched the table: $got"
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

# --- a failure under the door's own authentication is a named refusal, and leaves no session behind
# The second issuer's keys cannot be read and a failed read is fatal (acl_jwks_max_stale = 0), so the
# verification fails from under the door's authentication - the review's case. gRPC would report an
# escaped exception as "Unexpected error in RPC handling", which says nothing. Since spec 069 the
# client is told no more than "authentication failed" (a token is refused the same way whatever the
# cause - spec 040), and the REASON goes where the operator reads it: a `session` event `refused`
# with reason_code `source_error` (the keys' source failed, not the principal) and the policy's text -
# a refusal is recorded at every audit level but `off`.
FILE_TOKEN='eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2V5In0.eyJpc3MiOiJ0ZXN0L2lkcC9ub2ZpbGUiLCJhdWQiOiJhcGk6Ly9hY2wtdGVzdCIsImV4cCI6NDEwMjQ0NDgwMCwic3ViIjoidSIsInJvbGVzIjpbImFuYWx5c3QiXX0.ZkEmtRT1TgFENMZbLY-eOR8PLbnzeOmzSDBwQg11JwYp2Ulqllk_eNxQa6TPRGBC68Tr4V83dFlRy6UpnZKeS-f11c1Mj_MorrJbBUsVcTYj1J7aMN755RHC1wY-fnpv3l8C4VlqmOI3TPlrEbk3cOOxRSK_k03tjJ-m_qno6apOqaKA8Hy8ozRO3nt1ZJhM5An8_GUS01e98PmRxK__3BivNzq_swkFSGbt9Rd3C-oZ8fKKO_uDY5c48Dk3xSkZUCox85Mnz4Ikz9iZEmiz53tbLsRtBQp-niKemQpTgCDVTOTMY-Mha0bQJVv-igdc34fkJSC65sjS4Wrnc-ky_Q'
for probe in "SELECT 1" "@tables" "@imported:orders"; do
	got="$(ask "$probe" "$FILE_TOKEN")"
	case "$got" in *"Unexpected error in RPC handling"*) fail "$probe: the exception reached gRPC unnamed: $got";; esac
	echo "$got" | grep -q "authentication failed" || fail "$probe: the refusal was not the named one: $got"
	echo "$got" | grep -q "could not read" && fail "$probe: the refusal told the client why (the operator's, not the client's): $got"
done
echo "SELECT acl_audit_flush();" >&3
echo "SELECT 'keysrefused=' || count(*) FROM acl_audit_events() WHERE kind = 'session' AND detail = 'refused' AND verdict = 'denied' AND reason_code = 'source_error' AND reason LIKE '%could not read%';" >&3
counted=""
for _ in $(seq 1 40); do
	if grep -q "keysrefused=" "$TMP/server.log"; then counted=1; break; fi
	sleep 0.25
done
[ -n "$counted" ] || fail "the server did not answer the refused-session count"
grep -q "keysrefused=3" "$TMP/server.log" || fail "the three refusals were not recorded with their reason: $(grep keysrefused= "$TMP/server.log")"

# Every RPC opens a session and must close it whichever way it leaves; after everything above -
# refusals, throws and all - the door's own count is 0. Since spec 054 acl_session_count reports the
# LIVE count (not the map size), so this proves no live session lingers; a transient session leaked
# here is freshly minted and therefore live and counted, which is exactly the leak worth catching.
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

# --- the node's label rides a cookie of its own (spec 134) ---------------------------------------
# Unset by default: the door sends its session cookie and nothing else. Set, every response to a call
# that does not carry acl_node=<label> sets it - a front routes the client back to this node by it - and
# the session cookie is untouched; a call carrying another node's label gets this node's.
got="$(ACL_PRINT_SET_COOKIE=1 ask "SELECT 1 AS one")"
echo "$got" | grep -q "set-cookie: acl_flight_session_id=" || fail "no session cookie came: $got"
echo "$got" | grep -q "set-cookie: acl_node=" && fail "an acl_node cookie came without a label: $got"
echo "SET GLOBAL acl_node_label='e2e-node-1'; SELECT 'labelflip' AS s;" >&3
flipped=""
for _ in $(seq 1 40); do grep -q "labelflip" "$TMP/server.log" && { flipped=1; break; }; sleep 0.25; done
[ -n "$flipped" ] || fail "the server did not set the label"
got="$(ACL_PRINT_SET_COOKIE=1 ask "SELECT 1 AS one")"
echo "$got" | grep -q "set-cookie: acl_node=e2e-node-1; HttpOnly; Path=/; SameSite=Strict" ||
	fail "the label cookie did not come: $got"
echo "$got" | grep -q "set-cookie: acl_flight_session_id=" || fail "the session cookie went missing: $got"
echo "$got" | grep -q "'one': \[1\]" || fail "the call itself did not answer: $got"
got="$(ACL_PRINT_SET_COOKIE=1 ACL_EXTRA_HEADERS="cookie=acl_node=e2e-node-1" ask "SELECT 1 AS one")"
echo "$got" | grep -q "set-cookie: acl_node=" && fail "a call carrying the label got it again: $got"
got="$(ACL_PRINT_SET_COOKIE=1 ACL_EXTRA_HEADERS="cookie=acl_node=other-node" ask "SELECT 1 AS one")"
echo "$got" | grep -q "set-cookie: acl_node=e2e-node-1;" || fail "another node's label was not replaced: $got"
# the addendum: a ticket and a prepared handle start with the label too, for a client that keeps no cookie
got="$(ask "@handles:SELECT 1 AS one")"
echo "$got" | grep -Eq "'statement': 'e2e-node-1\.[0-9A-F]{32}'" || fail "a ticket without the label: $got"
echo "$got" | grep -Eq "'prepared': 'e2e-node-1\.[0-9A-F]{32}'" || fail "a prepared handle without the label: $got"
# ...and the label is a hint, never an authority: the id is redeemed whole, by its owner only
OTHER="$(python3 "$ROOT/test/scripts/idp_fixtures.py" mint \
	'{"iss": "test/idp/s", "aud": "api://acl-test", "exp": 4102444800, "sub": "u-other", "roles": ["analyst"], "tid": "acme"}')"
got="$(ACL_OTHER_TOKEN="$OTHER" ask "@tamper:SELECT 1 AS one")"
echo "$got" | grep -q "'swapped': 'refused', 'stripped': 'refused', 'other': 'refused', 'own': {'one': \[1\]}" ||
	fail "a ticket was redeemed with another label, without one, or by another principal: $got"
echo "SET GLOBAL acl_node_label=''; SELECT 'labelunflip' AS s;" >&3
flipped=""
for _ in $(seq 1 40); do grep -q "labelunflip" "$TMP/server.log" && { flipped=1; break; }; sleep 0.25; done
[ -n "$flipped" ] || fail "the server did not clear the label"
got="$(ACL_PRINT_SET_COOKIE=1 ask "SELECT 1 AS one")"
echo "$got" | grep -q "set-cookie: acl_node=" && fail "the label cookie outlived the label: $got"
got="$(ask "@handles:SELECT 1 AS one")"
echo "$got" | grep -Eq "'statement': '[0-9A-F]{32}', 'prepared': '[0-9A-F]{32}'" || fail "an id with a label that is gone: $got"

# --- a session outlives its token's exp under the default binding (spec 059) ----------------------
# The cookie session below is established while the token is fresh; then the server's clock skew goes
# hugely negative, which makes the same bearer look long-expired to every later re-verification. Under
# acl_session_token_binding='connect' (the default) the established session keeps answering - the
# stale bearer still proves identity (signature/issuer/audience), only its staleness is forgiven;
# under 'every_use' the very same call is refused. Establishment never forgives: a fresh open under
# the skewed clock is refused in both modes.
BJ="$TMP/bindjar"
ACL_COOKIE_JAR="$BJ" ask "SELECT 1" >/dev/null          # prime: mint the cookie
ACL_COOKIE_JAR="$BJ" ask "SELECT 1" >/dev/null          # bind: the session is established, token fresh
echo "SET GLOBAL acl_jwt_clock_skew=-9999999999; SELECT 'skewflip' AS s;" >&3
flipped=""
for _ in $(seq 1 40); do grep -q "skewflip" "$TMP/server.log" && { flipped=1; break; }; sleep 0.25; done
[ -n "$flipped" ] || fail "the server did not apply the skew flip"
got="$(ACL_COOKIE_JAR="$BJ" ask "SELECT 1 AS alive")"
echo "$got" | grep -q "'alive': \[1\]" || fail "connect binding: the established session died at token exp: $got"
got="$(ACL_COOKIE_JAR="$TMP/freshjar" ask "SELECT 1")"
echo "$got" | grep -qi "authentication failed" || fail "a stale token opened a NEW session under connect: $got"
echo "SET GLOBAL acl_session_token_binding='every_use'; SELECT 'strictflip' AS s;" >&3
flipped=""
for _ in $(seq 1 40); do grep -q "strictflip" "$TMP/server.log" && { flipped=1; break; }; sleep 0.25; done
[ -n "$flipped" ] || fail "the server did not apply the strict binding"
got="$(ACL_COOKIE_JAR="$BJ" ask "SELECT 1 AS alive")"
echo "$got" | grep -qi "authentication failed" || fail "every_use binding: the stale-bearer session was not refused: $got"
echo "SET GLOBAL acl_session_token_binding='connect'; SET GLOBAL acl_jwt_clock_skew=60; SELECT 'unflip' AS s;" >&3
flipped=""
for _ in $(seq 1 40); do grep -q "unflip" "$TMP/server.log" && { flipped=1; break; }; sleep 0.25; done
[ -n "$flipped" ] || fail "the server did not restore the clock"

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
GLOBEX='eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2V5In0.eyJpc3MiOiJ0ZXN0L2lkcC9zIiwiYXVkIjoiYXBpOi8vYWNsLXRlc3QiLCJleHAiOjQxMDI0NDQ4MDAsInN1YiI6InUtZ2xvYmV4Iiwicm9sZXMiOlsiYW5hbHlzdCJdLCJ0aWQiOiJnbG9iZXgifQ.US9D_P5MEhrwKYF-K5NwGoeMGXBaK6mky8oKM57xfJvZObM_yIhEp1uJhBN5MmmRuF6EV330IwT3W8RtgarfaK0iTlpHqmjEowIbhyQnFD84xOmjbTeBpSHaIBDWS8F2ayNKaUcXZFqfIPZrImvmASDQSQggTwkCnEyGpxPP7F__7MAC2PkDAV73RVVOuAW1QwqbYCPoeydXS-sgMBU2v031ngk8On-UTeZ3ZaCwMhznOUMwQUpFkCtSmwdt2_OgvYn_PC_Mu6f7UGFbTf2kXXHy6ps6QwT6pCpKoILA3uc-sjTRz1ZwyPy2NuKwceBIwiXbKTxPz5PH9KoLYUD6sg'
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

# --- a session moves between nodes (spec 135) -----------------------------------------------------
# One node plays both: killing every session here, while each client keeps its cookies, leaves a cookie this node
# does not know - a client re-placed on another node (or one whose session died here). The session-state cookie
# carries what the session held, for its own principal only: a context that is not pinned is restored, each item
# judged again as if the client sent it; what cannot move (a transaction, temp tables) refuses the call once, and a
# lost transaction stays aborted until ROLLBACK - nothing of it runs in autocommit.
server_says() { # <tag> <sql>: the server's answer to one statement, read back from its log
	echo "SELECT '$1=' || ($2) AS said;" >&3
	for _ in $(seq 1 40); do grep -q "$1=" "$TMP/server.log" && break; sleep 0.25; done
	sed -n "s/.*$1=\([^│|]*\).*/\1/p" "$TMP/server.log" | tail -1 | tr -d ' '
}
kill_sessions() {
	local killed
	killed="$(server_says "$1" "SELECT count(*) FROM (SELECT acl_session_kill(id) AS k FROM (SELECT unnest(regexp_extract_all(acl_sessions(), '\"id\":\\s*\"([^\"]+)\"', 1)) AS id)) WHERE k")"
	[ "${killed:-0}" -ge 1 ] || fail "no session was killed ($1): $killed"
}
# state_json <jar>: the jar's session state, decoded ("NONE" without one) - what the node last said the session holds
state_json() {
	python3 - "$1" <<'PY'
import base64, sys
jar = dict(p.split("=", 1) for p in open(sys.argv[1]).read().split("; ") if "=" in p)
raw = jar.get("acl_session_state", "")
print(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)).decode() if raw else "NONE")
PY
}
# reforge <jar> <python>: rewrite the jar's state cookie (a dict `s`) - what another node, or a tampering client,
# would send
reforge() {
	python3 - "$1" "$2" <<'PY'
import base64, json, sys
path, change = sys.argv[1], sys.argv[2]
jar = dict(p.split("=", 1) for p in open(path).read().split("; ") if "=" in p)
raw = jar["acl_session_state"]
s = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
exec(change)
jar["acl_session_state"] = base64.urlsafe_b64encode(json.dumps(s, separators=(",", ":")).encode()).decode().rstrip("=")
open(path, "w").write("; ".join(f"{k}={v}" for k, v in jar.items()))
PY
}
# the moves' events are recorded at level all (a refusal at any level)
echo "SET GLOBAL acl_audit_level = 'all';" >&3

MJ="$TMP/movejar"
ACL_COOKIE_JAR="$MJ" ask "SELECT 1" >/dev/null
got="$(ACL_COOKIE_JAR="$MJ" ask "@update:CREATE TABLE stage.moved_t AS SELECT 42 AS x")"
echo "$got" | grep -q "'count':" || fail "the table for the move check was not created: $got"
got="$(ACL_COOKIE_JAR="$MJ" ask 'USE c.stage')"
echo "$got" | grep -qi "error\|denied\|refused" && fail "USE on the session failed: $got"
got="$(ACL_COOKIE_JAR="$MJ" ask "SET TimeZone = 'Asia/Tokyo'")"
echo "$got" | grep -qi "error\|denied\|refused" && fail "SET TimeZone on the session failed: $got"
grep -q "acl_session_state=" "$MJ" || fail "the door set no session-state cookie after USE and SET: $(cat "$MJ")"
got="$(ACL_COOKIE_JAR="$MJ" ask 'SELECT x FROM moved_t')"
echo "$got" | grep -q "'x': \[42\]" || fail "the short name did not resolve under USE: $got"
kill_sessions moved1
got="$(ACL_COOKIE_JAR="$MJ" ask 'SELECT x FROM moved_t')"
echo "$got" | grep -q "'x': \[42\]" || fail "a moved session did not keep its USE - a short name resolved elsewhere: $got"
# the zone a TIMESTAMPTZ is rendered in rides its Arrow type (current_setting is the door's, never a principal's)
got="$(ACL_SHOW_SCHEMA=1 ACL_COOKIE_JAR="$MJ" ask "SELECT TIMESTAMPTZ '2026-01-01 00:00:00+00' AS t")"
echo "$got" | grep -q "tz=Asia/Tokyo" || fail "a moved session did not keep its TimeZone: $got"
# the move is audited by the items' names, never their values
said="$(server_says movednamed "SELECT count(*) FROM acl_audit_events() WHERE kind = 'session' AND detail = 'moved' AND reason = 'USE, TimeZone'")"
[ "${said:-0}" -ge 1 ] || fail "the moved event does not name what it carried: $said"
said="$(server_says movedvalues "SELECT count(*) FROM acl_audit_events() WHERE kind = 'session' AND detail IN ('moved', 'move_refused') AND (reason ILIKE '%tokyo%' OR reason ILIKE '%stage%' OR reason ILIKE '%secret_cat%')")"
[ "${said:-1}" = 0 ] || fail "a move's event carries a value: $said"

# another principal's token with this jar (a stolen or shared jar): nothing of the state carries, as on a swap
kill_sessions moved2
got="$(ACL_COOKIE_JAR="$MJ" ask 'SELECT x FROM moved_t' "$GLOBEX")"
echo "$got" | grep -q "no access to object" || fail "another principal's call inherited the jar's USE: $got"

# a forged USE - a catalog the principal does not hold - is judged like the client's own USE: refused, once
FJ="$TMP/forgedjar"
ACL_COOKIE_JAR="$FJ" ask "SELECT 1" >/dev/null
ACL_COOKIE_JAR="$FJ" ask 'USE c.stage' >/dev/null
reforge "$FJ" 's["use"] = {"catalog": "secret_cat", "schema": ""}'
kill_sessions forged1
got="$(ACL_COOKIE_JAR="$FJ" ask "SELECT 1 AS one")"
echo "$got" | grep -q "the session moved to another node and could not restore its USE" ||
	fail "a forged USE was not refused at the move: $got"
said="$(server_says forgedwhy "SELECT count(*) FROM acl_audit_events() WHERE kind = 'statement' AND reason LIKE '%secret_cat%is no catalog of the principal%'")"
[ "${said:-0}" -ge 1 ] || fail "the forged USE was not judged as the principal's own USE: $said"
got="$(ACL_COOKIE_JAR="$FJ" ask "SELECT 1 AS one")"
echo "$got" | grep -q "'one': \[1\]" || fail "the connection did not work on after the refused move: $got"
# a forged setting outside the client-local list reads as unreadable: refused once, never restored
SJ="$TMP/setjar"
ACL_COOKIE_JAR="$SJ" ask "SELECT 1" >/dev/null
ACL_COOKIE_JAR="$SJ" ask "SET TimeZone = 'Pacific/Chatham'" >/dev/null
reforge "$SJ" 's["set"] = {"search_path": "memory.main"}'
kill_sessions forged2
got="$(ACL_COOKIE_JAR="$SJ" ask "SELECT 1 AS one")"
echo "$got" | grep -q "the session moved to another node and lost its session context (ROLLBACK to go on" ||
	fail "a setting outside the list was not refused: $got"
# what it held is unknown, a transaction perhaps: aborted until the client's ROLLBACK (fail closed), then it works on
got="$(ACL_COOKIE_JAR="$SJ" ask "SELECT 1 AS one")"
echo "$got" | grep -q "lost its open transaction - ROLLBACK to go on" || fail "the unreadable state was not held aborted: $got"
ACL_COOKIE_JAR="$SJ" ask "@update:ROLLBACK" >/dev/null
got="$(ACL_COOKIE_JAR="$SJ" ask "SELECT 1 AS one")"
echo "$got" | grep -q "'one': \[1\]" || fail "the connection did not work on after its ROLLBACK: $got"
# a garbled state reads as unreadable: refused once, never read partly
GJ="$TMP/garbledjar"
ACL_COOKIE_JAR="$GJ" ask "SELECT 1" >/dev/null
printf '; acl_session_state=not*base64' >>"$GJ"
kill_sessions garbled1
got="$(ACL_COOKIE_JAR="$GJ" ask "SELECT 1 AS one")"
echo "$got" | grep -q "the session moved to another node and lost its session context" ||
	fail "an unreadable state was not refused: $got"
ACL_COOKIE_JAR="$GJ" ask "@update:ROLLBACK" >/dev/null
got="$(ACL_COOKIE_JAR="$GJ" ask "SELECT 1 AS one")"
echo "$got" | grep -q "'one': \[1\]" || fail "the connection did not work on after the garbled state: $got"
# a carried setting the new node no longer admits (a session's raise above the node's bound): refused once
RJ="$TMP/rowsjar"
ACL_COOKIE_JAR="$RJ" ask "SELECT 1" >/dev/null
got="$(ACL_COOKIE_JAR="$RJ" ask "SET acl_metadata_max_rows = 500")"
echo "$got" | grep -qi "error\|denied" && fail "lowering acl_metadata_max_rows on the session failed: $got"
echo "SET GLOBAL acl_metadata_max_rows = 100;" >&3
kill_sessions rows1
got="$(ACL_COOKIE_JAR="$RJ" ask "SELECT 1 AS one")"
echo "$got" | grep -q "the session moved to another node and could not restore its acl_metadata_max_rows" ||
	fail "a setting the node no longer admits was not refused at the move: $got"
echo "SET GLOBAL acl_metadata_max_rows = 1000000;" >&3

# an open transaction pins: refused once, then aborted until ROLLBACK - never run in autocommit
PJ="$TMP/pinjar"
ACL_COOKIE_JAR="$PJ" ask "SELECT 1" >/dev/null
ACL_COOKIE_JAR="$PJ" ask 'USE c.stage' >/dev/null
got="$(ACL_COOKIE_JAR="$PJ" ask "@update:BEGIN TRANSACTION")"
echo "$got" | grep -q "'count':" || fail "BEGIN for the pin check failed: $got"
got="$(ACL_COOKIE_JAR="$PJ" ask "@update:INSERT INTO moved_t VALUES (1)")"
echo "$got" | grep -q "'count':" || fail "the first write of the transaction failed: $got"
kill_sessions pinned1
got="$(ACL_COOKIE_JAR="$PJ" ask "@update:INSERT INTO moved_t VALUES (2)")"
echo "$got" | grep -q "the session moved to another node and lost its open transaction (ROLLBACK to go on" ||
	fail "a moved session in a transaction was not refused once: $got"
state_json "$PJ" | grep -q '"transaction"' || fail "the refused move dropped the pin from the cookie: $(state_json "$PJ")"
got="$(ACL_COOKIE_JAR="$PJ" ask "@update:INSERT INTO moved_t VALUES (3)")"
echo "$got" | grep -q "lost its open transaction - ROLLBACK to go on" ||
	fail "a write after the lost transaction ran in autocommit: $got"
got="$(ACL_COOKIE_JAR="$PJ" ask "@update:ROLLBACK")"
echo "$got" | grep -q "'count':" || fail "ROLLBACK of the lost transaction failed: $got"
got="$(ACL_COOKIE_JAR="$PJ" ask 'SELECT count(*) AS n FROM moved_t WHERE x IN (1, 2, 3)')"
echo "$got" | grep -q "'n': \[0\]" || fail "a write of the lost transaction was committed: $got"
left="$(state_json "$PJ")"
echo "$left" | grep -q '"use"' || fail "the jar's state is not readable after the ROLLBACK: $left"
echo "$left" | grep -q '"transaction"' && fail "the pin outlived the ROLLBACK: $left"
# a COMMIT after the one refusal went elsewhere (a driver's ping took it) is answered, never a silent rollback
CJ="$TMP/commitjar"
ACL_COOKIE_JAR="$CJ" ask "SELECT 1" >/dev/null
ACL_COOKIE_JAR="$CJ" ask 'USE c.stage' >/dev/null
ACL_COOKIE_JAR="$CJ" ask "@update:BEGIN TRANSACTION" >/dev/null
got="$(ACL_COOKIE_JAR="$CJ" ask "@update:INSERT INTO moved_t VALUES (7)")"
echo "$got" | grep -q "'count':" || fail "the write before the COMMIT check failed: $got"
kill_sessions commit1
ACL_COOKIE_JAR="$CJ" ask "SELECT 1" >/dev/null # the one refusal, spent on a ping
got="$(ACL_COOKIE_JAR="$CJ" ask "@update:COMMIT")"
echo "$got" | grep -q "lost its open transaction - nothing of it was committed" ||
	fail "a COMMIT of the lost transaction was not answered: $got"
got="$(ACL_COOKIE_JAR="$CJ" ask 'SELECT count(*) AS n FROM moved_t WHERE x = 7')"
echo "$got" | grep -q "'n': \[0\]" || fail "a write of the lost transaction was committed: $got"
# a temp table pins too: refused once, then the connection works on
TPJ="$TMP/temppinjar"
ACL_COOKIE_JAR="$TPJ" ask "SELECT 1" >/dev/null
got="$(ACL_COOKIE_JAR="$TPJ" ask "@update:CREATE TEMP TABLE pinned_tmp(id INTEGER)")"
echo "$got" | grep -q "'count':" || fail "CREATE TEMP for the pin check failed: $got"
kill_sessions pinned2
got="$(ACL_COOKIE_JAR="$TPJ" ask "SELECT 1 AS one")"
echo "$got" | grep -q "the session moved to another node and lost its temp tables" ||
	fail "a moved session with a temp table was not refused once: $got"
got="$(ACL_COOKIE_JAR="$TPJ" ask "SELECT 1 AS one")"
echo "$got" | grep -q "'one': \[1\]" || fail "the connection did not work on after the temp pin: $got"
# a view-as pin without the call declaring the mode is never seated afresh (the 120.3 addendum's rule)
VJ="$TMP/viewasjar"
ACL_COOKIE_JAR="$VJ" ask "SELECT 1" >/dev/null
ACL_COOKIE_JAR="$VJ" ask "SET TimeZone = 'Pacific/Chatham'" >/dev/null
reforge "$VJ" 's["pinned"] = ["view_as"]'
kill_sessions viewas1
for attempt in 1 2; do
	got="$(ACL_COOKIE_JAR="$VJ" ask "SELECT 1 AS one")"
	echo "$got" | grep -q "viewed the catalog as a role and is gone - connect again" ||
		fail "a moved view-as session was seated (attempt $attempt): $got"
done
# the refusal is the pin in the client's own jar, no record of the node's: a client that drops it (its own choice)
# is seated as itself
python3 - "$VJ" <<'PY'
import sys
path = sys.argv[1]
jar = dict(p.split("=", 1) for p in open(path).read().split("; ") if "=" in p)
jar.pop("acl_session_state", None)
open(path, "w").write("; ".join(f"{k}={v}" for k, v in jar.items()))
PY
got="$(ACL_COOKIE_JAR="$VJ" ask "SELECT 1 AS one")"
echo "$got" | grep -q "'one': \[1\]" || fail "a cookie left without its state was refused by a node record: $got"
# a drain refuses the move like any new session - and the state survives it, restored after the resume
DRJ="$TMP/drainjar"
ACL_COOKIE_JAR="$DRJ" ask "SELECT 1" >/dev/null
ACL_COOKIE_JAR="$DRJ" ask 'USE c.stage' >/dev/null
kill_sessions drain1
server_says drained "SELECT count(*) FROM (SELECT 1) WHERE (acl_drain()) IS NOT NULL" >/dev/null
got="$(ACL_COOKIE_JAR="$DRJ" ask 'SELECT x FROM moved_t')"
echo "$got" | grep -q "draining" || fail "a move into a draining node was not refused as any new session: $got"
server_says resumed "SELECT count(*) FROM (SELECT 1) WHERE (acl_resume()::VARCHAR) IS NOT NULL" >/dev/null
got="$(ACL_COOKIE_JAR="$DRJ" ask 'SELECT x FROM moved_t')"
echo "$got" | grep -q "'x': \[42\]" || fail "the state did not survive the drain's refusal: $got"
# a session that died idle here takes the same path (the cookie's binding still names it)
IDJ="$TMP/idlejar"
ACL_COOKIE_JAR="$IDJ" ask "SELECT 1" >/dev/null
ACL_COOKIE_JAR="$IDJ" ask 'USE c.stage' >/dev/null
echo "SET GLOBAL acl_session_idle_timeout = 1;" >&3
sleep 3
got="$(ACL_COOKIE_JAR="$IDJ" ask 'SELECT x FROM moved_t')"
echo "SET GLOBAL acl_session_idle_timeout = 900;" >&3
echo "$got" | grep -q "'x': \[42\]" || fail "a session that died idle did not keep its USE: $got"
# and the counters count each kind
counts="$(server_says movecount "SELECT coalesce(sum(value) FILTER (WHERE name = 'acl.sessions.moved'), 0) || '/' || coalesce(sum(value) FILTER (WHERE name = 'acl.sessions.move_refused'), 0) FROM acl_metrics()")"
[ "${counts%%/*}" -ge 3 ] && [ "${counts##*/}" -ge 7 ] ||
	fail "the moves were not counted (moved / move_refused): $counts"
echo "SET GLOBAL acl_audit_level = 'decisions';" >&3

# (spec 096's node-group refusal at the door - UNAVAILABLE, the swap kept - is the platform part's: it moved to
# hugr-node with the code, duckdb-acl spec 127)

# --- spec 143: a live alias schema's object written in another case than its own is the same object - described,
# and labelled as the listing names it
echo "CREATE TABLE staging.events(kind VARCHAR); COMMENT ON COLUMN staging.events.kind IS 'what happened';" >&3
server_says made "SELECT count(*) FROM duckdb_tables() WHERE schema_name = 'staging' AND table_name = 'events'" >/dev/null
for sql in "SELECT KIND FROM stage.EVENTS" "SELECT kind FROM stage.events"; do
	got="$(ACL_SHOW_DESCRIBED=1 ask "$sql")"
	echo "$got" | grep -q "|c.stage.events|comment:what happened|'" || fail "a live alias object's origin (\"$sql\"): $got"
done
echo "DROP TABLE staging.events;" >&3

# --- spec 143: a source's tags as duckdb:tag:<key> - a DuckLake table's (DuckLake keeps a table's tags; no SQL
# statement of the release writes one, so its metadata row is written here), where the build carries DuckLake
if [ "$(server_says haslake "SELECT count(*) FROM duckdb_extensions() WHERE extension_name = 'ducklake' AND loaded")" = "1" ]; then
	LAKE="ATTACH 'ducklake:$TMP/tags.ducklake' AS lake (DATA_PATH '$TMP/tags_lake')"
	echo "$LAKE; CREATE TABLE lake.tagged(id INTEGER); INSERT INTO __ducklake_metadata_lake.ducklake_tag SELECT table_id, (SELECT max(snapshot_id) FROM __ducklake_metadata_lake.ducklake_snapshot), NULL, 'owner', 'sales' FROM __ducklake_metadata_lake.ducklake_table WHERE table_name = 'tagged'; DETACH lake; $LAKE;" >&3
	added="$(server_says tagged "SELECT acl_add_relation('c', 'tagged', 'lake.main.tagged', '', '')::VARCHAR")"; [ "$added" = "true" ] ||
		{ tail -20 "$TMP/server.log" >&2; fail "the tagged relation was not added: $added"; }
	got="$(ACL_SHOW_DESCRIBED=1 ask "@tables_schema:tagged")"
	echo "$got" | grep -q "'<object>||owner=sales'" || fail "include_schema: the source's table tags: $got"
	got="$(ACL_SHOW_DESCRIBED=1 ask "SELECT * FROM tagged")"
	echo "$got" | grep -q "'id|c.main.tagged||', '<object>||owner=sales'" || fail "a result's object tags: $got"
	server_says untagged "SELECT acl_drop_relation('c', 'tagged')::VARCHAR" >/dev/null
else
	echo "note: no DuckLake in this build - the tags leg is skipped"
fi

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

echo "PASS: a third-party Flight SQL client read its own slice, a cookie connection reused one session, session temp tables stayed the session's own, a session moved with its context or was told once what it lost, and the door closed"
