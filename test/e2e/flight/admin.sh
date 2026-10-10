#!/usr/bin/env bash
# The administrator through the Flight SQL door (spec 117): no ACL NATIVE, no anonymous hatch - a
# token whose role holds the policy bundle reads the platform catalog (GetCatalogs, GetDbSchemas,
# GetTables, a view) and changes the policy with a platform call and with the bare grammar, ad hoc and
# prepared; a change is a command, run at GetFlightInfo (spec 111) even when the client never fetches.
# A principal without a grant on platform sees no platform at all.
#
# Skips (exit 0, saying why) without a Flight build or without pyarrow. Fails loudly otherwise.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$ROOT" # the fixture issuers (test/idp/) are read relative to the repository root
HERE="$(cd "$(dirname "$0")" && pwd)"
BUILD="${BUILD_DIR:-$ROOT/build/release}"
DUCKDB="${DUCKDB_BIN:-$BUILD/duckdb}"
ACL_EXT="${ACL_EXT:-$BUILD/extension/acl/acl.duckdb_extension}"
PORT="${ACL_FLIGHT_ADMIN_PORT:-32716}"
URI="grpc://localhost:$PORT"

# RS256 tokens of the seeded issuer (test/idp/s): role analyst (data only), role boss (the policy bundle)
ANALYST='eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2V5In0.eyJpc3MiOiJ0ZXN0L2lkcC9zIiwiYXVkIjoiYXBpOi8vYWNsLXRlc3QiLCJleHAiOjQxMDI0NDQ4MDAsInN1YiI6InUtYWNtZSIsInJvbGVzIjpbImFuYWx5c3QiXSwidGlkIjoiYWNtZSJ9.UV5-WWUpQLp-Em8K2yLLkz-NEJgOyTAn9i9B1zpBWF3hNQVgorAVPVK48bxnrMiMm7NabgM3g945lDY31DFwxNeUKnVEe0QdRy1d1KbFh8td3Ak_mepOZ35CjPektGaOjVEpjUFxZUOj_uxYnse_y660xC0stlY8zxDrpSjNCOZRGv-vaxITv7ggOIDYAN07rmPntKe9oOYsb5g0ZkFcIEsKuHuXsL8z1crko6vIZzT9ido-xrph_WEejO5lKaPIxVe1QrB1-C5DUp8D8fnLWMJ3g426VNKWJwUyeSgh_nq1XzLyR8WcLchBQwaFAzkGivmLFmDdrDS7VUy49I8uLw'
BOSS='eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2V5In0.eyJpc3MiOiJ0ZXN0L2lkcC9zIiwiYXVkIjoiYXBpOi8vYWNsLXRlc3QiLCJleHAiOjQxMDI0NDQ4MDAsInN1YiI6InUtYm9zcyIsInJvbGVzIjpbImJvc3MiXSwidGlkIjoiYWNtZSJ9.WWyV4WmSaXLuLcpW0kszQA0-kcT_Ox_0x73RRyzm3_OUQ5YQ6siegTRjWXHrwS7oSgURdvTpw1J4HZGuZfy7NZAS5ueIw6PVzjIujiHpLHMrGF6qbzuV8TOjcZavxM50LB_g6NVMx6CWkraMH43pQ7KQtimGvUIqrIqodSmRKeTsNjeJVuCZqXJBwOJqXybOnrhm9yz6Pm6Lg92pWUgyW7tNongP8rCZ8Ht6TG_5A3gPAD1Kksh850_TXabo9TzlEHhS-ZNKBnCdPYwRFOt9soSkrfOj_BiIcD1Txis8SXMVN6lfqz_uWm7Gsy6ir8LvgSADSFGygMzdcquskiRz0w'

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

FIFO="$TMP/ctl"
mkfifo "$FIFO"
"$DUCKDB" -unsigned <"$FIFO" >"$TMP/server.log" 2>&1 &
SERVER_PID=$!
exec 3>"$FIFO"
cat >&3 <<SQL
LOAD '$ACL_EXT';
CREATE TABLE orders AS SELECT i AS id, CASE WHEN i % 2 = 0 THEN 'acme' ELSE 'globex' END AS tenant FROM range(10) t(i);
ATTACH ':memory:' AS store;
SELECT acl_use_db('store', 'acl', true);
SET GLOBAL acl_allow_anonymous_admin=true;
SET GLOBAL acl_jwks_locations = 'test/idp/';
SELECT acl_define_issuer('test/idp/s', '{"url": "test/idp/s", "client": {"audiences": ["api://acl-test"], "roles_from": ["roles"], "attributes": {"tid": "tenant"}}}');
ACL ADMIN CREATE VIRTUAL CATALOG c COMMENT 'the data';
ACL ADMIN CREATE VIRTUAL TABLE c.orders AS memory.main.orders RLS (tenant = acl_claim('tenant'));
ACL ADMIN CREATE ROLE analyst;
ACL ADMIN GRANT CATALOG c TO ROLE analyst MAIN;
ACL ADMIN CREATE ROLE boss;
ACL ADMIN GRANT ADMIN policy TO ROLE boss;
-- a privileged role is reached only through the client's own mapping (spec 095)
ACL ADMIN MAP CLAIM 'boss' FROM CLIENT 'test/idp/s' TO ROLE boss;
SET GLOBAL acl_allow_anonymous_admin=false;
SELECT acl_flight_serve('$URI');
SELECT 1;
SQL

ready=""
for _ in $(seq 1 60); do
	if ! kill -0 "$SERVER_PID" 2>/dev/null; then
		cat "$TMP/server.log" >&2
		fail "the server exited before it was serving"
	fi
	if python3 "$HERE/client.py" "$URI" "SELECT 1 AS ok" "$ANALYST" >/dev/null 2>&1; then
		ready=1; break
	fi
	sleep 0.5
done
[ -n "$ready" ] || { cat "$TMP/server.log" >&2; fail "the door never came up on $URI"; }

ask() { python3 "$HERE/client.py" "$URI" "$1" "${2:-$BOSS}" 2>&1 || true; }

# --- a principal without a grant on platform sees no platform ------------------------------------------
got="$(ask "@catalogs" "$ANALYST")"
[ "$got" = "{'catalog_name': ['c']}" ] || fail "GetCatalogs of a non-admin: $got"
got="$(ask "SELECT * FROM platform.roles" "$ANALYST")"
echo "$got" | grep -q 'no access to object \\"platform.roles\\"\|no access to object "platform.roles"' || fail "a non-admin read a platform view: $got"
got="$(ask "CREATE ROLE intruder" "$ANALYST")"
echo "$got" | grep -q "no ACL administration scope" || fail "a non-admin administered: $got"

# --- the admin's tree: platform is a catalog like any other ---------------------------------------------
got="$(ask "@catalogs")"
[ "$got" = "{'catalog_name': ['platform']}" ] || fail "GetCatalogs of the admin: $got"
got="$(ask "@schemas")"
echo "$got" | grep -q "'catalog_name': \['platform'\], 'db_schema_name': \['main'\]" || fail "GetDbSchemas: $got"
got="$(ask "@tables:grants")"
echo "$got" | grep -q "'catalog_name': \['platform'\]" || fail "GetTables does not list platform.grants: $got"
echo "$got" | grep -q "'table_type': \['VIEW'\]" || fail "platform.grants is not a view: $got"
got="$(ask "@tables_schema:grants")"
echo "$got" | grep -q "caps:struct<select: bool" || fail "the promised schema of platform.grants is not typed: $got"
got="$(ask "SELECT catalog, comment FROM platform.catalogs")"
echo "$got" | grep -q "'catalog': \['c'\], 'comment': \['the data'\]" || fail "a platform view: $got"
got="$(ask "SELECT bundles FROM platform.console_info()")"
echo "$got" | grep -q "'bundles': \[\['policy'\]\]" || fail "console_info: $got"

# --- and it changes the policy without ACL NATIVE: a call and the bare grammar, ad hoc and prepared ----
got="$(ask "SELECT platform.create_role('made_adhoc')")"
echo "$got" | grep -q "'create_role': \[True\]" || fail "an ad-hoc platform call: $got"
got="$(ask "@prepared:SELECT platform.create_role('made_prepared')")"
echo "$got" | grep -q "'create_role': \[True\]" || fail "a prepared platform call: $got"
got="$(ask "CREATE ROLE made_bare")"
echo "$got" | grep -qi "error" && fail "the bare grammar: $got"
got="$(ask "@prepared:GRANT CATALOG c TO ROLE made_bare WITH (select)")"
echo "$got" | grep -qi "error" && fail "the prepared bare grammar: $got"
# spec 111: a change is a command - it runs at GetFlightInfo, so a client that never fetches keeps it
got="$(ask "@nofetch:SELECT platform.create_role('made_nofetch')")"
echo "$got" | grep -q "'endpoints': 1" || fail "the unfetched call: $got"
got="$(ask "@prepared_nofetch:CREATE ROLE made_prepared_nofetch")"
echo "$got" | grep -q "'endpoints': 1" || fail "the unfetched prepared statement: $got"
got="$(ask "SELECT list(role ORDER BY role) AS r FROM platform.roles WHERE role LIKE 'made_%'")"
echo "$got" | grep -q "'r': \[\['made_adhoc', 'made_bare', 'made_nofetch', 'made_prepared', 'made_prepared_nofetch'\]\]" ||
	fail "the changes did not all land: $got"
got="$(ask "SELECT role, catalog FROM platform.grants WHERE role = 'made_bare'")"
echo "$got" | grep -q "'catalog': \['c'\]" || fail "the prepared GRANT did not land: $got"

# --- what the policy bundle is not --------------------------------------------------------------------
got="$(ask "ACL NATIVE SELECT 1")"
echo "$got" | grep -q "requires a passthrough scope" || fail "the policy bundle ran native SQL: $got"
got="$(ask "GRANT ADMIN passthrough TO ROLE boss")"
echo "$got" | grep -q "requires a passthrough scope" || fail "the policy bundle escalated: $got"
got="$(ask "SELECT * FROM platform.sessions")"
echo "$got" | grep -q 'platform.sessions' || fail "the policy bundle read a node view: $got"
got="$(ask "SELECT platform.create_role(r) FROM (VALUES ('per_row')) t(r)")"
echo "$got" | grep -q "call it at the top level" || fail "a per-row call was not refused: $got"

echo "SELECT acl_flight_stop('$URI');" >&3
echo "PASS: an administrator read the platform catalog through the Flight door and changed the policy with a call and with the bare grammar, ad hoc and prepared, fetched or not; a non-admin saw no platform"
