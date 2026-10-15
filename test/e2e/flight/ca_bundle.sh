#!/usr/bin/env bash
# The node's own IdP requests trust ca_cert_file (spec 130).
#
# A test CA signs a localhost certificate; the fake IdP of spec 064 serves https with it, and nothing but
# ca_cert_file tells the node about the CA. The door's discovery and its password grant (the OIDC core's own
# client) reach the IdP with the CA set and are refused at discovery without it - verification stays on, and
# an endpoint learned under the CA is not served once it is gone. The quack provider secret (spec 061), the
# same client on a client process, mints with the CA and fails at discovery without it.
#
# Skips (exit 0, saying why) without an ACL_FLIGHT build, pyarrow, openssl or the quack loadable (ACL_QUACK=1).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$ROOT" # spec 095: the fixture issuers (test/idp/) are read relative to the repository root
HERE="$(cd "$(dirname "$0")" && pwd)"
BUILD="${BUILD_DIR:-$ROOT/build/release}"
DUCKDB="${DUCKDB_BIN:-$BUILD/duckdb}"
ACL_EXT="${ACL_EXT:-$BUILD/extension/acl/acl.duckdb_extension}"
PORT="${ACL_FLIGHT_CA_PORT:-32799}"
IDP_PORT="${ACL_FAKE_IDP_TLS_PORT:-32800}"
URI="grpc+tls://localhost:$PORT"
IDP="https://localhost:$IDP_PORT"

fail() { echo "FAIL: $*" >&2; exit 1; }

[ -x "$DUCKDB" ] || { echo "SKIP: no duckdb CLI at $DUCKDB"; exit 0; }
[ -f "$ACL_EXT" ] || { echo "SKIP: no acl extension at $ACL_EXT"; exit 0; }
have="$(echo "LOAD '$ACL_EXT'; SELECT count(*) FROM duckdb_functions() WHERE function_name='acl_flight_serve';" \
        | "$DUCKDB" -unsigned -no-agent -noheader -list 2>/dev/null | tail -1 | tr -d ' ')"
[ "$have" != "0" ] || { echo "SKIP: this build has no Flight door"; exit 0; }
python3 -c "import pyarrow.flight" 2>/dev/null || { echo "SKIP: pyarrow is not installed"; exit 0; }
command -v openssl >/dev/null 2>&1 || { echo "SKIP: openssl is not installed"; exit 0; }
# the extension repository is keyed by duckdb's source id: only the one the CLI was built from loads
SOURCE_ID="$("$DUCKDB" -no-agent -noheader -csv -c "SELECT source_id FROM pragma_version();" 2>/dev/null || true)"
QUACK_EXT="$(ls "$BUILD"/repository/"${SOURCE_ID:-*}"/*/quack.duckdb_extension 2>/dev/null | head -1 || true)"
[ -n "$QUACK_EXT" ] || { echo "SKIP: quack is not built - rebuild with ACL_QUACK=1"; exit 0; }

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

# the CA and the one localhost certificate the IdP and the door both serve
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$TMP/ca.key" -out "$TMP/ca.pem" -days 1 -subj /CN=acl-e2e-ca \
	2>/dev/null || fail "openssl could not make the CA"
openssl req -newkey rsa:2048 -nodes -keyout "$TMP/tls.key" -out "$TMP/tls.csr" -subj /CN=localhost 2>/dev/null
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\n' >"$TMP/san.cnf"
openssl x509 -req -in "$TMP/tls.csr" -CA "$TMP/ca.pem" -CAkey "$TMP/ca.key" -CAcreateserial -out "$TMP/tls.crt" \
	-days 1 -extfile "$TMP/san.cnf" 2>/dev/null || fail "openssl could not sign the certificate"

python3 "$HERE/fake_idp.py" "$IDP" "$IDP_PORT" "$TMP/tls.crt" "$TMP/tls.key" &
IDP_PID=$!
for _ in $(seq 1 40); do
	curl -s --cacert "$TMP/ca.pem" "$IDP/.well-known/openid-configuration" >/dev/null 2>&1 && break
	sleep 0.25
done
curl -s --cacert "$TMP/ca.pem" "$IDP/.well-known/openid-configuration" | grep -q token_endpoint \
	|| fail "the fake IdP never came up over https"

FIFO="$TMP/ctl"
mkfifo "$FIFO"
"$DUCKDB" -unsigned -no-agent <"$FIFO" >"$TMP/server.log" 2>&1 &
SERVER_PID=$!
exec 3>"$FIFO"
cat >&3 <<SQL
LOAD '$ACL_EXT';
SET GLOBAL ca_cert_file = '$TMP/ca.pem';
CREATE TABLE orders AS SELECT i AS id, CASE WHEN i%2=0 THEN 'acme' ELSE 'globex' END AS tenant FROM range(6) t(i);
ATTACH ':memory:' AS store;
SELECT acl_use_db('store','acl',true);
SET GLOBAL acl_allow_anonymous_admin=true;
ACL ADMIN CREATE ISSUER '$IDP' AUDIENCES 'api://acl-test' ROLE CLAIM 'roles' CLAIM MAP (tid => tenant) CLIENT ID 'acl-door' FLOWS (password);
ACL ADMIN CREATE VIRTUAL CATALOG c;
ACL ADMIN CREATE VIRTUAL TABLE c.orders AS memory.main.orders;
ACL ADMIN CREATE ROLE analyst;
ACL ADMIN GRANT CATALOG c TO ROLE analyst WITH (select) MAIN;
ACL ADMIN GRANT TABLE c.orders TO ROLE analyst RLS 'tenant = acl_claim(''tenant'')';
SET GLOBAL acl_allow_anonymous_admin=false;
SELECT acl_flight_serve('$URI', '$TMP/tls.crt', '$TMP/tls.key');
SELECT 1;
SQL

ask() { python3 "$HERE/auth_client.py" "$@" --tls-roots "$TMP/ca.pem" 2>&1 || true; }

ready=""
for _ in $(seq 1 60); do
	if ! kill -0 "$SERVER_PID" 2>/dev/null; then
		cat "$TMP/server.log" >&2
		fail "the server exited before it was serving"
	fi
	got="$(ask "$URI" discover)"
	case "$got" in *issuers*) ready=1; break;; esac
	sleep 0.5
done
[ -n "$ready" ] || { cat "$TMP/server.log" >&2; fail "the door never came up on $URI"; }

# --- the door: discovery and the password grant reach an IdP only the CA vouches for ----------------------
got="$(ask "$URI" discover)"
echo "$got" | grep -q "\"token_endpoint\":\"$IDP/token\"" \
	|| fail "discovery against the https IdP did not carry its token endpoint: $got"
got="$(ask "$URI" password alice wonder "SELECT count(*) AS n FROM orders")"
echo "$got" | grep -q "'n': \[3\]" || fail "the password handshake did not reach the https IdP: $got"

# --- without the CA the same handshake is refused at discovery: verification stays on, and the endpoint
#     learned under the CA is not served once it is gone ------------------------------------------------------
echo "SET GLOBAL ca_cert_file = '';" >&3
refused=""
for _ in $(seq 1 40); do
	got="$(ask "$URI" password alice wonder "SELECT 1")"
	case "$got" in *"OIDC discovery against $IDP failed"*) refused=1; break;; esac
	sleep 0.25
done
[ -n "$refused" ] || fail "the handshake was not refused at discovery without the CA: $got"
echo "SELECT acl_flight_stop('$URI');" >&3

# --- the quack provider secret: the same client, on a client process ------------------------------------------
mint() { # <ca_cert_file>
	"$DUCKDB" -unsigned -no-agent -noheader -list -c "LOAD '$ACL_EXT'; LOAD '$QUACK_EXT'; SET ca_cert_file = '$1';
CREATE SECRET s (TYPE quack, PROVIDER oidc, ISSUER '$IDP', CLIENT_ID 'acl-door', FLOW 'password',
                 USERNAME 'alice', PASSWORD 'wonder');
SELECT 'minted ' || count(*) FROM duckdb_secrets() WHERE name = 's';" 2>&1 || true
}
got="$(mint "$TMP/ca.pem")"
echo "$got" | grep -q "^minted 1$" || fail "the provider secret did not mint against the https IdP with the CA: $got"
got="$(mint "")"
case "$got" in *"discovery against \"$IDP\" failed"*) ;; *) fail "the provider secret was not refused at discovery without the CA: $got";; esac

echo "PASS: with ca_cert_file the door's discovery and password grant and the provider secret reached an IdP behind a private CA, and without it each was refused at discovery"
