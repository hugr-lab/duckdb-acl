#!/usr/bin/env bash
# The Flight door's auth discovery and password handshake (spec 064).
#
# A fake IdP (stdlib python, sharing no code with the door) serves OIDC discovery and a password
# grant. The door: answers `discover-auth` over the Handshake unauthenticated; exchanges a BasicAuth
# handshake for the IdP's token, verifies it offline and hands it back as the bearer; surfaces the
# IdP's own refusal when the grant is denied there; and refuses the password over a cleartext door
# before anything reads it. The plain bearer path stays as it was.
#
# Skips (exit 0, saying why) without an ACL_FLIGHT build, pyarrow, or openssl.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
HERE="$(cd "$(dirname "$0")" && pwd)"
BUILD="${BUILD_DIR:-$ROOT/build/release}"
DUCKDB="${DUCKDB_BIN:-$BUILD/duckdb}"
ACL_EXT="${ACL_EXT:-$BUILD/extension/acl/acl.duckdb_extension}"
PORT="${ACL_FLIGHT_AUTH_PORT:-32796}"
PLAIN_PORT="${ACL_FLIGHT_AUTH_PLAIN_PORT:-32797}"
IDP_PORT="${ACL_FAKE_IDP_PORT:-32795}"
URI="grpc+tls://localhost:$PORT"
PLAIN_URI="grpc://localhost:$PLAIN_PORT"
IDP="http://localhost:$IDP_PORT"

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
IDP_PID=""
cleanup() {
	local rc=$?
	[ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null && wait "$SERVER_PID" 2>/dev/null || true
	[ -n "$IDP_PID" ] && kill "$IDP_PID" 2>/dev/null && wait "$IDP_PID" 2>/dev/null || true
	rm -rf "$TMP"
	exit $rc
}
trap cleanup EXIT INT TERM

# the IdP first: the door discovers against it live
python3 "$HERE/fake_idp.py" "$IDP" "$IDP_PORT" &
IDP_PID=$!
for _ in $(seq 1 40); do
	curl -s "$IDP/.well-known/openid-configuration" >/dev/null 2>&1 && break
	sleep 0.25
done
curl -s "$IDP/.well-known/openid-configuration" | grep -q token_endpoint || fail "the fake IdP never came up"

openssl req -x509 -newkey rsa:2048 -keyout "$TMP/key.pem" -out "$TMP/cert.pem" -days 2 -nodes \
	-subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" >/dev/null 2>&1 \
	|| fail "openssl could not generate a cert"

FIFO="$TMP/ctl"
mkfifo "$FIFO"
"$DUCKDB" -unsigned <"$FIFO" >"$TMP/server.log" 2>&1 &
SERVER_PID=$!
exec 3>"$FIFO"
cat >&3 <<SQL
LOAD '$ACL_EXT';
CREATE TABLE orders AS SELECT i AS id, CASE WHEN i%2=0 THEN 'acme' ELSE 'globex' END AS tenant FROM range(6) t(i);
ATTACH ':memory:' AS store;
SELECT acl_use_db('store','acl',true);
SET GLOBAL acl_allow_anonymous_admin=true;
ACL ADMIN CREATE ISSUER '$IDP' KEYS '{"keys":[{"kty":"oct","k":"YWNsLXRlc3QtaHMyNTYtc2VjcmV0"}]}' AUDIENCES 'api://acl-test' ALGS 'HS256' ROLE CLAIM 'roles' CLAIM MAP (tid => tenant) CLIENT ID 'acl-door';
ACL ADMIN CREATE VIRTUAL CATALOG c;
ACL ADMIN CREATE VIRTUAL TABLE c.orders AS memory.main.orders;
ACL ADMIN CREATE ROLE analyst;
ACL ADMIN GRANT CATALOG c TO ROLE analyst WITH (select) MAIN;
ACL ADMIN GRANT TABLE c.orders TO ROLE analyst RLS 'tenant = acl_claim(''tenant'')';
SET GLOBAL acl_allow_anonymous_admin=false;
SELECT acl_flight_serve('$URI', '$TMP/cert.pem', '$TMP/key.pem');
SELECT acl_flight_serve('$PLAIN_URI');
SELECT 1;
SQL

ask() { python3 "$HERE/auth_client.py" "$@" 2>&1 || true; }

ready=""
for _ in $(seq 1 60); do
	if ! kill -0 "$SERVER_PID" 2>/dev/null; then
		cat "$TMP/server.log" >&2
		fail "the server exited before it was serving"
	fi
	got="$(ask "$URI" discover --tls-roots "$TMP/cert.pem")"
	case "$got" in *issuers*) ready=1; break;; esac
	sleep 0.5
done
[ -n "$ready" ] || { cat "$TMP/server.log" >&2; fail "the door never came up on $URI"; }

# --- B2: discovery answers unauthenticated, from the live policy -----------------------------------
got="$(ask "$URI" discover --tls-roots "$TMP/cert.pem")"
echo "$got" | grep -q "\"issuer\":\"$IDP\"" || fail "discovery does not name the issuer: $got"
echo "$got" | grep -q '"client_id":"acl-door"' || fail "discovery does not carry the client_id: $got"
echo "$got" | grep -q "\"token_endpoint\":\"$IDP/token\"" || fail "discovery does not carry the IdP's token endpoint: $got"
echo "$got" | grep -q "\"device_authorization_endpoint\":\"$IDP/device\"" || fail "the device endpoint the IdP advertises is missing: $got"
case "$got" in *client_secret*) fail "discovery leaked a client secret field: $got";; esac

# --- B3: the password handshake earns the slice ----------------------------------------------------
got="$(ask "$URI" password alice wonder "SELECT count(*) AS n FROM orders" --tls-roots "$TMP/cert.pem")"
echo "$got" | grep -q "'n': \[3\]" || fail "the password handshake did not read the tenant's slice: $got"

# a wrong password is the IdP's refusal, surfaced - not a mystery timeout, not a success
got="$(ask "$URI" password alice nope "SELECT 1" --tls-roots "$TMP/cert.pem")"
case "$got" in *"refused the password grant"*) ;; *) fail "a wrong password was not refused with the IdP's answer: $got";; esac

# an IdP with ROPC off refuses by protocol; the door hands that refusal on
got="$(ask "$URI" password noropc x "SELECT 1" --tls-roots "$TMP/cert.pem")"
case "$got" in *"refused the password grant"*) ;; *) fail "the ROPC-off refusal was not surfaced: $got";; esac

# --- the cleartext door refuses the password before anything reads it ------------------------------
got="$(ask "$PLAIN_URI" password alice wonder "SELECT 1")"
case "$got" in *"needs a TLS door"*) ;; *) fail "a cleartext door accepted a password handshake: $got";; esac

# --- and the plain bearer path is exactly as it was ------------------------------------------------
TOKEN="$(python3 - "$IDP" <<'PY'
import base64, hashlib, hmac, json, sys, time
b64 = lambda raw: base64.urlsafe_b64encode(raw).rstrip(b"=")
h = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
c = b64(json.dumps({"iss": sys.argv[1], "aud": "api://acl-test", "exp": int(time.time()) + 3600,
                    "sub": "direct", "roles": ["analyst"], "tid": "acme"}).encode())
sig = b64(hmac.new(b"acl-test-hs256-secret", h + b"." + c, hashlib.sha256).digest())
print((h + b"." + c + b"." + sig).decode())
PY
)"
got="$(ask "$URI" bearer "$TOKEN" "SELECT count(*) AS n FROM orders" --tls-roots "$TMP/cert.pem")"
echo "$got" | grep -q "'n': \[3\]" || fail "the plain bearer path regressed: $got"

echo "SELECT acl_flight_stop('$URI'); SELECT acl_flight_stop('$PLAIN_URI');" >&3

echo "PASS: discovery answered unauthenticated from the live policy, the password handshake earned the tenant's slice, the IdP's refusals were surfaced, the cleartext door refused, and the bearer path held"
