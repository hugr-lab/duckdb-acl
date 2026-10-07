#!/usr/bin/env bash
# Types through the quack door (spec 099): a real quack client ATTACHes the served catalog and reads
# structured, ENUM and JSON columns - the client builds its tables from the server's DDL and reads the
# server's vectors without a cast, so a description that disagrees with the data fails here.
#
#   - the node exposes ENUMs as VARCHAR (acl_enum_types = varchar): the client's catalog and the
#     stream both say VARCHAR, inside STRUCT / LIST / MAP / UNION too;
#   - one table keeps its ENUMs (SET TYPES (enums = keep)): the client sees the ENUM and reads it;
#   - an mssql source (when the extension and SQL Server are there): its MSSQL_VARCHAR(n) columns are
#     exposed as VARCHAR (acl_alias_types = base, the default), and a client WITHOUT mssql attaches
#     the whole catalog - one alias type in the DDL used to fail the ATTACH whole.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$ROOT" # the fixture issuer (test/idp/) is read relative to the repository root
BUILD="${BUILD_DIR:-$ROOT/build/release}"
DUCKDB="${DUCKDB_BIN:-$BUILD/duckdb}"
ACL_EXT="${ACL_EXT:-$BUILD/extension/acl/acl.duckdb_extension}"
PORT="${ACL_E2E_TYPES_PORT:-31720}"
SERVER_TOKEN="e2e-types-token"
# the seeded issuer's RS256 token (test/scripts/idp_fixtures.py mint), role analyst, tenant acme
TOKEN='eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2V5In0.eyJpc3MiOiJ0ZXN0L2lkcC9zIiwiYXVkIjoiYXBpOi8vYWNsLXRlc3QiLCJleHAiOjQxMDI0NDQ4MDAsInN1YiI6InUtYWNtZSIsInJvbGVzIjpbImFuYWx5c3QiXSwidGlkIjoiYWNtZSJ9.UV5-WWUpQLp-Em8K2yLLkz-NEJgOyTAn9i9B1zpBWF3hNQVgorAVPVK48bxnrMiMm7NabgM3g945lDY31DFwxNeUKnVEe0QdRy1d1KbFh8td3Ak_mepOZ35CjPektGaOjVEpjUFxZUOj_uxYnse_y660xC0stlY8zxDrpSjNCOZRGv-vaxITv7ggOIDYAN07rmPntKe9oOYsb5g0ZkFcIEsKuHuXsL8z1crko6vIZzT9ido-xrph_WEejO5lKaPIxVe1QrB1-C5DUp8D8fnLWMJ3g426VNKWJwUyeSgh_nq1XzLyR8WcLchBQwaFAzkGivmLFmDdrDS7VUy49I8uLw'

fail() { echo "FAIL: $*" >&2; exit 1; }

[ -x "$DUCKDB" ] || { echo "SKIP: no duckdb CLI at $DUCKDB"; exit 0; }
[ -f "$ACL_EXT" ] || { echo "SKIP: no acl extension at $ACL_EXT"; exit 0; }
SOURCE_ID="$("$DUCKDB" -noheader -csv -c "SELECT source_id FROM pragma_version();" 2>/dev/null || true)"
QUACK_EXT="$(ls "$BUILD"/repository/"${SOURCE_ID:-*}"/*/quack.duckdb_extension 2>/dev/null | head -1 || true)"
[ -n "$QUACK_EXT" ] || { echo "SKIP: quack is not built - rebuild with ACL_QUACK=1"; exit 0; }

# the mssql leg: the extension of this pin (ACL_MSSQL_EXT, or the build's repository) and a DSN
MS_EXT="${ACL_MSSQL_EXT:-$(dirname "$QUACK_EXT")/mssql.duckdb_extension}"
MS_LOAD="" MS_SQL="" MS_NOTE="mssql leg skipped"
if [ -f "$MS_EXT" ] && [ -n "${ACL_MSSQL_DSN:-}" ] &&
	echo "LOAD '$MS_EXT'; ATTACH '$ACL_MSSQL_DSN' AS ms (TYPE mssql); SELECT 1;" | "$DUCKDB" -unsigned >/dev/null 2>&1; then
	MS_LOAD="LOAD '$MS_EXT';"
	MS_SQL="ATTACH '$ACL_MSSQL_DSN' AS ms (TYPE mssql);
SELECT mssql_exec('ms', 'IF OBJECT_ID(''dbo.e2e_types'') IS NOT NULL DROP TABLE dbo.e2e_types; CREATE TABLE dbo.e2e_types(id INT, name VARCHAR(20), uname NVARCHAR(30)); INSERT INTO dbo.e2e_types VALUES (1, ''n42'', N''u42'')');
SELECT mssql_refresh_cache('ms');
ACL ADMIN CREATE VIRTUAL TABLE c.ms_types AS ms.dbo.e2e_types;"
	MS_NOTE="mssql alias types read as VARCHAR by a client without mssql"
elif [ -n "${ACL_MSSQL_DSN:-}" ]; then
	MS_NOTE="mssql leg skipped (no mssql extension at $MS_EXT, or SQL Server is not up)"
fi

TMP="$(mktemp -d)"
SERVER_PID=""
cleanup() {
	local rc=$?
	if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
		kill "$SERVER_PID" 2>/dev/null || true
		wait "$SERVER_PID" 2>/dev/null || true
	fi
	[ -n "${KEEP_TMP:-}" ] || rm -rf "$TMP"
	exit $rc
}
trap cleanup EXIT INT TERM

mkfifo "$TMP/ctl"
"$DUCKDB" -unsigned <"$TMP/ctl" >"$TMP/server.log" 2>&1 &
SERVER_PID=$!
exec 3>"$TMP/ctl"
cat >&3 <<EOF
LOAD '$ACL_EXT'; $MS_LOAD LOAD '$QUACK_EXT';
ATTACH ':memory:' AS phys;
CREATE TYPE phys.main.tier AS ENUM ('gold', 'silver');
CREATE TABLE phys.main.typed(id INTEGER, tier phys.main.tier, s STRUCT(a phys.main.tier, b INTEGER),
    l phys.main.tier[], m MAP(VARCHAR, phys.main.tier), u UNION(n INTEGER, t phys.main.tier), j JSON);
CREATE TABLE phys.main.nested(id INTEGER, items STRUCT(price INTEGER, cost INTEGER)[]);
INSERT INTO phys.main.nested VALUES (1, [{'price': 10, 'cost': 7}]);
INSERT INTO phys.main.typed VALUES (1, 'gold', {'a': 'silver', 'b': 2}, ['gold', 'silver'], MAP {'k': 'gold'},
    'silver'::phys.main.tier, '{"x": 1}');
ATTACH ':memory:' AS store;
SELECT acl_use_db('store', 'acl', true);
SET GLOBAL acl_allow_anonymous_admin=true;
SET GLOBAL acl_jwks_locations = 'test/idp/';
SELECT acl_define_issuer('test/idp/s', '{"url": "test/idp/s", "client": {"audiences": ["api://acl-test"], "roles_from": ["roles"]}}');
SET GLOBAL acl_enum_types = 'varchar';
ACL ADMIN CREATE VIRTUAL CATALOG c;
ACL ADMIN CREATE VIRTUAL TABLE c.typed AS phys.main.typed;
ACL ADMIN CREATE VIRTUAL TABLE c.kept AS phys.main.typed;
ACL ADMIN ALTER VIRTUAL TABLE c.kept SET TYPES (enums = keep);
ACL ADMIN CREATE VIRTUAL TABLE c.narrow AS phys.main.typed COLUMNS (id, s.b, l);
$MS_SQL
ACL ADMIN CREATE ROLE analyst;
ACL ADMIN GRANT CATALOG c TO ROLE analyst WITH (select, insert) MAIN;
ACL ADMIN CREATE VIRTUAL TABLE c.nested AS phys.main.nested;
ACL ADMIN GRANT TABLE c.nested TO ROLE analyst COLUMNS (id, items[].price);
SET GLOBAL acl_allow_anonymous_admin=false;
SELECT acl_quack_serve('quack:localhost:$PORT', '$SERVER_TOKEN');
EOF

CLIENT_LOAD="LOAD '$QUACK_EXT';" # never mssql: the point is a client without it
ready=""
for _ in $(seq 1 60); do
	kill -0 "$SERVER_PID" 2>/dev/null || { cat "$TMP/server.log" >&2; fail "the server exited before serving"; }
	if echo "$CLIENT_LOAD SELECT * FROM quack_query('quack:localhost:$PORT', 'SELECT 1', token := '$TOKEN');" |
		"$DUCKDB" -unsigned >/dev/null 2>"$TMP/probe.err"; then
		ready=1
		break
	fi
	sleep 0.5
done
[ -n "$ready" ] || { cat "$TMP/probe.err" "$TMP/server.log" >&2; fail "the door never came up on port $PORT"; }

{
	echo "$CLIENT_LOAD"
	echo "ATTACH 'quack:localhost:$PORT' AS remote (TYPE quack, TOKEN '$TOKEN');"
	echo "SELECT 'typed', typeof(tier), typeof(s), typeof(l), typeof(m), typeof(u), typeof(j), tier, s.a, l[2], m['k'], u, j->>'x' FROM remote.main.typed;"
	echo "SELECT 'filtered', count(*) FROM remote.main.typed WHERE tier = 'gold' AND s.a = 'silver';"
	echo "SELECT 'kept', typeof(tier), tier, s.a FROM remote.main.kept;"
	# spec 102: a struct narrowed to one field - the client's DDL and the stream agree
	echo "SELECT 'narrow', typeof(s), s.b FROM remote.main.narrow;"
	echo "SELECT 'nested', typeof(items), items[1].price FROM remote.main.nested;"
	# the served listing itself, as a client that builds its catalog reads it
	echo "SELECT 'columns', * FROM quack_query('quack:localhost:$PORT', 'SELECT data_type FROM information_schema.columns WHERE table_name = ''typed'' AND column_name = ''tier''', token := '$TOKEN');"
	[ -z "$MS_LOAD" ] || echo "SELECT 'ms', typeof(name), typeof(uname), name, uname FROM remote.main.ms_types;"
} >"$TMP/client.sql"
"$DUCKDB" -unsigned -csv -noheader <"$TMP/client.sql" >"$TMP/client.out" 2>&1 || true

expect() { # expect <label> <line>
	grep -qxF "$2" "$TMP/client.out" || { echo "--- client ---" >&2; cat "$TMP/client.out" >&2; fail "$1: expected the line: $2"; }
}
expect "ENUMs as VARCHAR at every depth, the data as described" \
	'typed,VARCHAR,"STRUCT(a VARCHAR, b INTEGER)",VARCHAR[],"MAP(VARCHAR, VARCHAR)","UNION(n INTEGER, t VARCHAR)",JSON,gold,silver,silver,gold,silver,1'
expect "a filter on the cast columns" "filtered,1"
expect "a table that keeps its ENUMs" "kept,\"ENUM('gold', 'silver')\",gold,silver"
expect "a struct narrowed to its fields" "narrow,STRUCT(b INTEGER),2"
expect "a grant narrowing a list of structs" "nested,STRUCT(price INTEGER)[],10"
expect "the listing says what the read returns" "columns,VARCHAR"
[ -z "$MS_LOAD" ] || expect "mssql alias types as their base type" "ms,VARCHAR,VARCHAR,n42,u42"

# stop the door before the process goes (spec 084), and leave the source as it was found
{
	echo "SELECT acl_quack_stop('quack:localhost:$PORT');"
	[ -z "$MS_LOAD" ] || echo "SELECT mssql_exec('ms', 'DROP TABLE dbo.e2e_types');"
} >&3
exec 3>&-
for _ in $(seq 1 20); do
	kill -0 "$SERVER_PID" 2>/dev/null || break
	sleep 0.5
done
echo "PASS: types through the door - ENUMs as VARCHAR in STRUCT/LIST/MAP/UNION, a kept ENUM, JSON, a narrowed struct; $MS_NOTE"
