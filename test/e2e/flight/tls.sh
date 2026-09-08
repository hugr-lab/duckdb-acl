#!/usr/bin/env bash
# The Flight SQL door over TLS (spec 053).
#
# A door with a certificate may leave the machine; without one it binds localhost only. This proves
# both: the cleartext door refuses a non-local bind, and a TLS door serves it and answers a real
# client that verifies the server's certificate. Self-signed cert generated here; the client trusts
# exactly it, which is what a served deployment does with a real CA chain.
#
# Skips (exit 0, saying why) without an ACL_FLIGHT build, without pyarrow, or without openssl.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
HERE="$(cd "$(dirname "$0")" && pwd)"
BUILD="${BUILD_DIR:-$ROOT/build/release}"
DUCKDB="${DUCKDB_BIN:-$BUILD/duckdb}"
ACL_EXT="${ACL_EXT:-$BUILD/extension/acl/acl.duckdb_extension}"
PORT="${ACL_FLIGHT_TLS_PORT:-32798}"

# The same seeded HS256 token the plain e2e uses: role analyst, tenant acme, exp 2100.
TOKEN='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci50ZXN0L3MiLCJhdWQiOiJhcGk6Ly9hY2wtdGVzdCIsImV4cCI6NDEwMjQ0NDgwMCwic3ViIjoidS1hY21lIiwicm9sZXMiOlsiYW5hbHlzdCJdLCJ0aWQiOiJhY21lIn0.vzPJbHXAXfczhZwQp183JaaBLlSRSipNsSqwxoIFfng'

fail() { echo "FAIL: $*" >&2; exit 1; }

[ -x "$DUCKDB" ] || { echo "SKIP: no duckdb CLI at $DUCKDB"; exit 0; }
[ -f "$ACL_EXT" ] || { echo "SKIP: no acl extension at $ACL_EXT"; exit 0; }
have="$(echo "LOAD '$ACL_EXT'; SELECT count(*) FROM duckdb_functions() WHERE function_name='acl_flight_serve';" \
        | "$DUCKDB" -unsigned -noheader -list 2>/dev/null | tail -1 | tr -d ' ')"
[ "$have" != "0" ] || { echo "SKIP: this build has no Flight door"; exit 0; }
python3 -c "import pyarrow.flight" 2>/dev/null || { echo "SKIP: pyarrow is not installed"; exit 0; }
command -v openssl >/dev/null 2>&1 || { echo "SKIP: openssl is not installed"; exit 0; }

TMP="$(mktemp -d)"
SERVER_PID=""
cleanup() {
	local rc=$?
	[ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null && wait "$SERVER_PID" 2>/dev/null || true
	rm -rf "$TMP"
	exit $rc
}
trap cleanup EXIT INT TERM

# a self-signed cert for localhost - the client will trust exactly this one
openssl req -x509 -newkey rsa:2048 -keyout "$TMP/key.pem" -out "$TMP/cert.pem" -days 2 -nodes \
	-subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" >/dev/null 2>&1 \
	|| fail "openssl could not generate a cert"

# the shared policy setup - seeded exactly as the plain e2e
setup() {
	cat <<SQL
LOAD '$ACL_EXT';
CREATE TABLE orders AS SELECT i AS id, CASE WHEN i%2=0 THEN 'acme' ELSE 'globex' END AS tenant FROM range(6) t(i);
ATTACH ':memory:' AS store;
SELECT acl_use_db('store','acl',true);
SET GLOBAL acl_allow_anonymous_admin=true;
SELECT acl_define_issuer('https://issuer.test/s','{"keys":[{"kty":"oct","k":"YWNsLXRlc3QtaHMyNTYtc2VjcmV0"}]}','api://acl-test','HS256','roles','{"tid":"tenant"}');
ACL ADMIN CREATE VIRTUAL CATALOG c;
ACL ADMIN CREATE VIRTUAL TABLE c.orders AS memory.main.orders;
ACL ADMIN CREATE ROLE analyst;
ACL ADMIN GRANT CATALOG c TO ROLE analyst WITH (select) MAIN;
ACL ADMIN GRANT TABLE c.orders TO ROLE analyst RLS 'tenant = acl_claim(''tenant'')';
SET GLOBAL acl_allow_anonymous_admin=false;
SET allow_parser_override_extension='strict';
SQL
}

# one-shot helper: run the setup plus one statement, capture everything, let the CLI exit
oneshot() { { setup; echo "$1"; } | "$DUCKDB" -unsigned 2>&1 || true; }

# --- a cleartext door on a non-local address is refused (the guarantee TLS lifts) ------------------
clear_out="$(oneshot "SELECT acl_flight_serve('grpc://0.0.0.0:$PORT');")"
case "$clear_out" in
	*"binds only localhost"*) ;;
	*) fail "a cleartext non-local bind was not refused: $clear_out";;
esac

# --- a cert without a key (or the reverse) is refused before the socket is touched -----------------
guard_out="$(oneshot "SELECT acl_flight_serve('grpc://localhost:$PORT', '$TMP/cert.pem', NULL);")"
case "$guard_out" in
	*"needs both a certificate and a key"*) ;;
	*) fail "cert-without-key was not refused: $guard_out";;
esac

# --- a path to a non-PEM file is refused with the PEM reason, not a cryptic gRPC error -------------
echo "not a certificate" >"$TMP/garbage.txt"
pem_out="$(oneshot "SELECT acl_flight_serve('grpc://localhost:$PORT', '$TMP/garbage.txt', '$TMP/key.pem');")"
case "$pem_out" in
	*"is not PEM"*) ;;
	*) fail "a non-PEM cert file was not refused with the PEM reason: $pem_out";;
esac

# --- inline PEM (the -----BEGIN branch) initializes a TLS door too ---------------------------------
# a one-shot serve returns the uri on a successful bind, then the CLI exits; we assert it came up
inline_out="$(oneshot "SELECT acl_flight_serve('grpc://localhost:$((PORT+1))', read_text('$TMP/cert.pem'), read_text('$TMP/key.pem'));")"
case "$inline_out" in
	*"grpc://localhost:$((PORT+1))"*) ;;
	*) fail "an inline-PEM TLS door did not initialize: $inline_out";;
esac

# --- the TLS door on the same non-local address comes up ------------------------------------------
{ setup; echo "SELECT acl_flight_serve('grpc://0.0.0.0:$PORT', '$TMP/cert.pem', '$TMP/key.pem');"; echo "SELECT 1;"; } >"$TMP/server.sql"
FIFO="$TMP/ctl"
mkfifo "$FIFO"
"$DUCKDB" -unsigned <"$FIFO" >"$TMP/server.log" 2>&1 &
SERVER_PID=$!
exec 3>"$FIFO"
cat "$TMP/server.sql" >&3

ready=""
for _ in $(seq 1 60); do
	if ! kill -0 "$SERVER_PID" 2>/dev/null; then cat "$TMP/server.log" >&2; fail "server exited before serving"; fi
	if ACL_TLS_ROOT="$TMP/cert.pem" python3 "$HERE/client.py" "grpc+tls://localhost:$PORT" "SELECT 1 AS ok" "$TOKEN" >/dev/null 2>&1; then
		ready=1; break
	fi
	sleep 0.5
done
[ -n "$ready" ] || { cat "$TMP/server.log" >&2; fail "the TLS door never came up on $PORT"; }

ask() { ACL_TLS_ROOT="$TMP/cert.pem" python3 "$HERE/client.py" "grpc+tls://localhost:$PORT" "$1" "${2:-$TOKEN}" 2>&1 || true; }

# the principal reads its own slice over TLS - the whole ACL still applies through the encrypted door
got="$(ask "SELECT count(*) AS n FROM orders")"
echo "$got" | grep -q "'n': \[3\]" || fail "expected 3 acme rows over TLS, got: $got"

# a client that does NOT trust the cert cannot connect (TLS verifies the server). The trusting
# client succeeded on this exact port/token immediately above, so the only changed variable is the
# missing root cert - and the rejection must be a TLS/certificate one, not a generic failure
got="$(python3 "$HERE/client.py" "grpc+tls://localhost:$PORT" "SELECT 1" "$TOKEN" 2>&1 || true)"
case "$got" in
	*[Cc]ertificate*|*[Hh]andshake*|*SSL*|*Ssl*|*ssl*|*TLS*|*[Vv]erif*) ;;
	*) fail "an untrusting client was not rejected specifically by TLS: $got";;
esac

echo "PASS: the door served Flight SQL over TLS on a non-local address, refused the same bind in the clear, and verified the server to the client"
