#!/usr/bin/env bash
# A door picks up a renewed certificate (spec 140).
#
# Both doors (Flight, quack) are served from files laid out as Kubernetes lays out a projected or csi volume:
# tls.crt and tls.key are links into ..data, and a renewal swaps ..data in one rename. With
# acl_door_certificate_refresh = 1 the script proves, reading the served certificate's serial with openssl:
#   1. both doors serve certificate A;
#   2. after a swap to B both serve B, and a Flight connection opened on A goes on working;
#   3. a broken pair (B's certificate, another key) is not taken: both keep serving B, the load report says
#      key_mismatch, and the audit has the door's certificate_refresh_failed;
#   4. a good pair again (A) is taken, and the refusal is over;
#   5. a door served from inline PEM, and one served while the refresh is 0, are not watched: they keep their
#      pair through a swap;
#   6. a door that cannot make its anchor (no writable TMPDIR) serves as before, and the load report says
#      anchor_unavailable.
#
# Skips (exit 0, saying why) without an ACL_FLIGHT build, without pyarrow, or without openssl.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$ROOT" # spec 095: the fixture issuers (test/idp/) are read relative to the repository root
HERE="$(cd "$(dirname "$0")" && pwd)"
BUILD="${BUILD_DIR:-$ROOT/build/release}"
DUCKDB="${DUCKDB_BIN:-$BUILD/duckdb}"
ACL_EXT="${ACL_EXT:-$BUILD/extension/acl/acl.duckdb_extension}"
PORT="${ACL_CERT_RELOAD_PORT:-32830}" # Flight; quack on +1, the inline-PEM door on +2, the unwatched one on +3

# The same seeded RS256 token the plain e2e uses: role analyst, tenant acme, exp 2100.
TOKEN='eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2V5In0.eyJpc3MiOiJ0ZXN0L2lkcC9zIiwiYXVkIjoiYXBpOi8vYWNsLXRlc3QiLCJleHAiOjQxMDI0NDQ4MDAsInN1YiI6InUtYWNtZSIsInJvbGVzIjpbImFuYWx5c3QiXSwidGlkIjoiYWNtZSJ9.UV5-WWUpQLp-Em8K2yLLkz-NEJgOyTAn9i9B1zpBWF3hNQVgorAVPVK48bxnrMiMm7NabgM3g945lDY31DFwxNeUKnVEe0QdRy1d1KbFh8td3Ak_mepOZ35CjPektGaOjVEpjUFxZUOj_uxYnse_y660xC0stlY8zxDrpSjNCOZRGv-vaxITv7ggOIDYAN07rmPntKe9oOYsb5g0ZkFcIEsKuHuXsL8z1crko6vIZzT9ido-xrph_WEejO5lKaPIxVe1QrB1-C5DUp8D8fnLWMJ3g426VNKWJwUyeSgh_nq1XzLyR8WcLchBQwaFAzkGivmLFmDdrDS7VUy49I8uLw'

fail() {
	echo "FAIL: $*" >&2
	[ -z "${TMP:-}" ] || [ ! -f "$TMP/server.log" ] || { echo "--- the server's output:" >&2; tail -40 "$TMP/server.log" >&2; }
	exit 1
}

[ -x "$DUCKDB" ] || { echo "SKIP: no duckdb CLI at $DUCKDB"; exit 0; }
[ -f "$ACL_EXT" ] || { echo "SKIP: no acl extension at $ACL_EXT"; exit 0; }
have="$(echo "LOAD '$ACL_EXT'; SELECT count(*) FROM duckdb_functions() WHERE function_name='acl_flight_serve';" \
        | "$DUCKDB" -unsigned -no-agent -noheader -list 2>/dev/null | tail -1 | tr -d ' ')"
[ "$have" != "0" ] || { echo "SKIP: this build has no Flight door"; exit 0; }
python3 -c "import pyarrow.flight" 2>/dev/null || { echo "SKIP: pyarrow is not installed"; exit 0; }
command -v openssl >/dev/null 2>&1 || { echo "SKIP: openssl is not installed"; exit 0; }

TMP="$(mktemp -d)"
SERVER_PID=""
HOLD_PID=""
cleanup() {
	local rc=$?
	[ -n "$HOLD_PID" ] && kill "$HOLD_PID" 2>/dev/null || true
	[ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null && wait "$SERVER_PID" 2>/dev/null || true
	rm -rf "$TMP"
	exit $rc
}
trap cleanup EXIT INT TERM

# --- a CA and two certificates for localhost it signs, plus a key of nobody's ----------------------------------
openssl req -x509 -newkey rsa:2048 -keyout "$TMP/ca.key" -out "$TMP/ca.pem" -days 2 -nodes -subj "/CN=reload-ca" \
	>/dev/null 2>&1 || fail "openssl could not make the CA"
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\n' >"$TMP/san.ext"
issue() { # <name>: <name>/tls.crt and <name>/tls.key, signed by the CA
	mkdir -p "$TMP/$1"
	openssl req -newkey rsa:2048 -keyout "$TMP/$1/tls.key" -out "$TMP/$1/req.csr" -nodes -subj "/CN=localhost" \
		>/dev/null 2>&1 || fail "openssl could not make the request $1"
	openssl x509 -req -in "$TMP/$1/req.csr" -CA "$TMP/ca.pem" -CAkey "$TMP/ca.key" -CAcreateserial -days 2 \
		-extfile "$TMP/san.ext" -out "$TMP/$1/tls.crt" >/dev/null 2>&1 || fail "openssl could not sign $1"
	rm -f "$TMP/$1/req.csr"
}
issue a
issue b
mkdir -p "$TMP/broken"
cp "$TMP/b/tls.crt" "$TMP/broken/tls.crt"
openssl genrsa -out "$TMP/broken/tls.key" 2048 >/dev/null 2>&1 || fail "openssl could not make the stray key"
serial_of() { openssl x509 -noout -serial -in "$1" | cut -d= -f2; }
SERIAL_A="$(serial_of "$TMP/a/tls.crt")"
SERIAL_B="$(serial_of "$TMP/b/tls.crt")"

# --- the files as Kubernetes writes them: links into ..data, swapped in one rename -----------------------------
LIVE="$TMP/live"
mkdir -p "$LIVE"
point() { # <name>: ..data -> that directory, atomically (the kubelet's atomic writer)
	python3 - "$LIVE" "$TMP/$1" <<'PY'
import os, sys
live, target = sys.argv[1], sys.argv[2]
tmp = os.path.join(live, "..data_tmp")
if os.path.lexists(tmp):
    os.remove(tmp)
os.symlink(target, tmp)
os.replace(tmp, os.path.join(live, "..data"))
for name in ("tls.crt", "tls.key"):
    link = os.path.join(live, name)
    if not os.path.lexists(link):
        os.symlink(os.path.join("..data", name), link)
PY
}
point a

setup() {
	cat <<SQL
.mode list
LOAD '$ACL_EXT';
CREATE TABLE orders AS SELECT i AS id, CASE WHEN i%2=0 THEN 'acme' ELSE 'globex' END AS tenant FROM range(6) t(i);
ATTACH ':memory:' AS store;
SELECT acl_use_db('store','acl',true);
SET GLOBAL acl_allow_anonymous_admin=true;
SET GLOBAL acl_jwks_locations = 'test/idp/';
SELECT acl_define_issuer('test/idp/s', '{"url": "test/idp/s", "client": {"audiences": ["api://acl-test"], "roles_from": ["roles"], "attributes": {"tid": "tenant"}}}');
ACL ADMIN CREATE VIRTUAL CATALOG c;
ACL ADMIN CREATE VIRTUAL TABLE c.orders AS memory.main.orders;
ACL ADMIN CREATE ROLE analyst;
ACL ADMIN GRANT CATALOG c TO ROLE analyst WITH (select) MAIN;
ACL ADMIN GRANT TABLE c.orders TO ROLE analyst RLS 'tenant = acl_claim(''tenant'')';
SET GLOBAL acl_allow_anonymous_admin=false;
SET allow_parser_override_extension='strict';
SET GLOBAL acl_door_certificate_refresh = 1;
SELECT acl_flight_serve('grpc+tls://localhost:$PORT', '$LIVE/tls.crt', '$LIVE/tls.key');
SELECT acl_quack_serve('quack:localhost:$((PORT+1))', 'server-token', '$LIVE/tls.crt', '$LIVE/tls.key');
SELECT acl_flight_serve('grpc+tls://localhost:$((PORT+2))', (SELECT content FROM read_text('$TMP/a/tls.crt')),
    (SELECT content FROM read_text('$TMP/a/tls.key')));
SET GLOBAL acl_door_certificate_refresh = 0;
SELECT acl_flight_serve('grpc+tls://localhost:$((PORT+3))', '$LIVE/tls.crt', '$LIVE/tls.key');
SET GLOBAL acl_door_certificate_refresh = 1;
SELECT 'served' AS state;
SQL
}

FIFO="$TMP/ctl"
mkfifo "$FIFO"
"$DUCKDB" -unsigned -no-agent <"$FIFO" >"$TMP/server.log" 2>&1 &
SERVER_PID=$!
exec 3>"$FIFO"
setup >&3

# served_serial <port> [alpn]: the serial of the certificate the door hands a new connection
served_serial() {
	local alpn=()
	[ -z "${2:-}" ] || alpn=(-alpn "$2")
	openssl s_client -connect "localhost:$1" -servername localhost ${alpn[@]+"${alpn[@]}"} </dev/null 2>/dev/null |
		openssl x509 -noout -serial 2>/dev/null | cut -d= -f2
}
flight_serial() { served_serial "$1" h2; }
quack_serial() { served_serial "$1"; }

for _ in $(seq 1 60); do
	if ! kill -0 "$SERVER_PID" 2>/dev/null; then cat "$TMP/server.log" >&2; fail "the server exited before serving"; fi
	grep -q '^served$' "$TMP/server.log" && break
	sleep 0.5
done
grep -q '^served$' "$TMP/server.log" || { cat "$TMP/server.log" >&2; fail "the doors never came up"; }

# eventually <seconds> <what> <command...>
eventually() {
	local within="$1" what="$2"
	shift 2
	for _ in $(seq 1 $((within * 2))); do
		"$@" && return 0
		sleep 0.5
	done
	fail "not within ${within}s: $what"
}
is() { [ "$($1 "$2")" = "$3" ]; }

# load_report: the last acl_node_load() the server answered, asked through its own stdin
load_report() {
	local mark="report-$RANDOM-$RANDOM"
	echo "SELECT '$mark' AS mark; SELECT acl_node_load() AS r; SELECT '$mark-end' AS mark;" >&3
	for _ in $(seq 1 20); do
		grep -q "^$mark-end$" "$TMP/server.log" && break
		sleep 0.25
	done
	sed -n "/^$mark\$/,/^$mark-end\$/p" "$TMP/server.log" | grep '"certificates"' | tail -1
}
# certificate <report> <door> <python expression over the door's entry c>
certificate() {
	python3 - "$1" "$2" "$3" <<'PY'
import json, sys
report, door, cond = json.loads(sys.argv[1]), sys.argv[2], sys.argv[3]
entries = [c for c in report["certificates"] if c["door"] == door]
sys.exit(0 if any(eval(cond) for c in entries) else 1)
PY
}

# --- 1. both doors serve A ------------------------------------------------------------------------------------
is flight_serial "$PORT" "$SERIAL_A" || fail "the Flight door does not serve A: $(flight_serial "$PORT")"
is quack_serial "$((PORT + 1))" "$SERIAL_A" || fail "the quack door does not serve A: $(quack_serial "$((PORT + 1))")"
report="$(load_report)"
certificate "$report" flight 'c["watched"] and c["not_after"] and c["error"] is None' ||
	fail "the load report does not show the Flight door's watched certificate: $report"
certificate "$report" quack 'c["watched"] and c["not_after"] and c["error"] is None' ||
	fail "the load report does not show the quack door's watched certificate: $report"
certificate "$report" flight 'not c["watched"]' ||
	fail "the load report does not show an unwatched Flight door (inline PEM, refresh 0): $report"

# a connection opened on A, held across the swap: it queries again once told to
{ python3 - "grpc+tls://localhost:$PORT" "$TMP/ca.pem" "$TOKEN" "$TMP/go" "$TMP/held.out" <<'PY' 
import os, sys, time
import pyarrow.flight as flight
uri, root, token, go, out = sys.argv[1:6]
def varint(n):
    b = b""
    while True:
        low, n = n & 0x7F, n >> 7
        b += bytes([low | (0x80 if n else 0)])
        if not n:
            return b
def field(number, payload):
    return bytes([(number << 3) | 2]) + varint(len(payload)) + payload
def statement(sql):  # an Any-wrapped CommandStatementQuery, as client.py encodes it
    return field(1, b"type.googleapis.com/arrow.flight.protocol.sql.CommandStatementQuery") + field(2, field(1, sql.encode()))
client = flight.FlightClient(uri, tls_root_certs=open(root, "rb").read())
options = flight.FlightCallOptions(headers=[(b"authorization", ("Bearer " + token).encode())])
def ask():
    info = client.get_flight_info(flight.FlightDescriptor.for_command(statement("SELECT count(*) AS n FROM orders")), options)
    return client.do_get(info.endpoints[0].ticket, options).read_all().to_pydict()["n"][0]
first = ask()
while not os.path.exists(go):
    time.sleep(0.2)
second = ask()
open(out, "w").write("%s %s\n" % (first, second))
PY
} 2>"$TMP/held.err" &
HOLD_PID=$!

# --- 2. a swap to B: both doors serve B, the held connection goes on -----------------------------------------
sleep 1
point b
eventually 15 "the Flight door serves B" is flight_serial "$PORT" "$SERIAL_B"
eventually 15 "the quack door serves B" is quack_serial "$((PORT + 1))" "$SERIAL_B"
touch "$TMP/go"
wait "$HOLD_PID" || fail "the connection held across the swap failed: $(tail -5 "$TMP/held.err")"
HOLD_PID=""
[ "$(cat "$TMP/held.out")" = "3 3" ] || fail "the held connection read $(cat "$TMP/held.out"), want 3 3"
is flight_serial "$((PORT + 2))" "$SERIAL_A" || fail "the inline-PEM door took the swap"
is flight_serial "$((PORT + 3))" "$SERIAL_A" || fail "the door served while the refresh was 0 took the swap"

# --- 3. a broken pair is not taken -----------------------------------------------------------------------------
point broken
broken_reported() {
	local r
	r="$(load_report)"
	certificate "$r" flight 'c["watched"] and c["error"] == "key_mismatch"' &&
		certificate "$r" quack 'c["watched"] and c["error"] == "key_mismatch"'
}
eventually 15 "the load report says key_mismatch for both doors" broken_reported
is flight_serial "$PORT" "$SERIAL_B" || fail "the Flight door took a broken pair: $(flight_serial "$PORT")"
is quack_serial "$((PORT + 1))" "$SERIAL_B" || fail "the quack door took a broken pair: $(quack_serial "$((PORT + 1))")"
mark="audit-$RANDOM"
echo "SELECT '$mark' AS mark; SELECT door FROM acl_audit_events() WHERE kind = 'door' AND detail = 'certificate_refresh_failed' ORDER BY door; SELECT '$mark-end' AS mark;" >&3
eventually 10 "the audit answered" grep -q "^$mark-end$" "$TMP/server.log"
events="$(sed -n "/^$mark\$/,/^$mark-end\$/p" "$TMP/server.log" | grep -E '^(flight|quack)$' | sort -u | tr '\n' ' ')"
[ "$events" = "flight quack " ] || fail "the audit's certificate_refresh_failed events are '$events', want both doors"
grep -q 'BEGIN' "$TMP/server.log" && fail "PEM text reached the server's output"

# --- 4. a good pair again is taken, and the refusal is over --------------------------------------------------
point a
eventually 15 "the Flight door serves A again" is flight_serial "$PORT" "$SERIAL_A"
eventually 15 "the quack door serves A again" is quack_serial "$((PORT + 1))" "$SERIAL_A"
recovered() {
	local r
	r="$(load_report)"
	certificate "$r" flight 'c["watched"] and c["error"] is None' && certificate "$r" quack 'c["watched"] and c["error"] is None'
}
eventually 15 "the load report clears the refusal" recovered

# --- 6. a door that cannot watch still serves: no private directory for its anchor (TMPDIR unwritable) ----------
fallback="$(TMPDIR=/nonexistent/acl-anchor "$DUCKDB" -unsigned -no-agent -list 2>&1 <<SQL || true
LOAD '$ACL_EXT';
ATTACH ':memory:' AS store;
SELECT acl_use_db('store','acl',true);
SET allow_parser_override_extension='strict';
SET GLOBAL acl_door_certificate_refresh = 1;
SELECT acl_flight_serve('grpc+tls://localhost:$((PORT + 4))', '$LIVE/tls.crt', '$LIVE/tls.key') AS bound;
SELECT acl_node_load() AS r;
SELECT acl_flight_stop('grpc+tls://localhost:$((PORT + 4))') AS stopped;
SQL
)"
case "$fallback" in
	*Error*) fail "a door without a writable TMPDIR did not serve: $fallback" ;;
esac
certificate "$(echo "$fallback" | grep '"certificates"' | tail -1)" flight 'not c["watched"] and c["error"] == "anchor_unavailable"' ||
	fail "the load report does not say why the door reads its pair once: $fallback"

echo "PASS: both doors took a renewed certificate for new connections, kept serving through a broken one and said so, left an inline or unwatched door alone, and a door that could not watch served as before"
