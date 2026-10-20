#!/usr/bin/env bash
# Spec 066 end to end: a draining Flight door keeps answering the session it already seated while a
# new client - carrying the same valid token - is refused with the draining message; acl_resume()
# seats clients again. Skips (exit 0, saying why) without a flight build or pyarrow.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$ROOT" # spec 095: the fixture issuers (test/idp/) are read relative to the repository root
HERE="$(cd "$(dirname "$0")" && pwd)"
BUILD="${BUILD_DIR:-$ROOT/build/release}"
DUCKDB="${DUCKDB_BIN:-$BUILD/duckdb}"
ACL_EXT="${ACL_EXT:-$BUILD/extension/acl/acl.duckdb_extension}"
PORT="${ACL_DRAIN_PORT:-32771}"
URI="grpc://localhost:$PORT"
PYBIN="${ACL_ADBC_PYTHON:-python3}"
TOKEN='eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2V5In0.eyJpc3MiOiJ0ZXN0L2lkcC9zIiwiYXVkIjoiYXBpOi8vYWNsLXRlc3QiLCJleHAiOjQxMDI0NDQ4MDAsInN1YiI6InUtYWNtZSIsInJvbGVzIjpbImFuYWx5c3QiXSwidGlkIjoiYWNtZSJ9.UV5-WWUpQLp-Em8K2yLLkz-NEJgOyTAn9i9B1zpBWF3hNQVgorAVPVK48bxnrMiMm7NabgM3g945lDY31DFwxNeUKnVEe0QdRy1d1KbFh8td3Ak_mepOZ35CjPektGaOjVEpjUFxZUOj_uxYnse_y660xC0stlY8zxDrpSjNCOZRGv-vaxITv7ggOIDYAN07rmPntKe9oOYsb5g0ZkFcIEsKuHuXsL8z1crko6vIZzT9ido-xrph_WEejO5lKaPIxVe1QrB1-C5DUp8D8fnLWMJ3g426VNKWJwUyeSgh_nq1XzLyR8WcLchBQwaFAzkGivmLFmDdrDS7VUy49I8uLw'

fail() { echo "FAIL: $*" >&2; exit 1; }
[ -x "$DUCKDB" ] || { echo "SKIP: no duckdb CLI at $DUCKDB"; exit 0; }
[ -f "$ACL_EXT" ] || { echo "SKIP: no acl extension at $ACL_EXT"; exit 0; }
have="$(echo "LOAD '$ACL_EXT'; SELECT count(*) FROM duckdb_functions() WHERE function_name='acl_flight_serve';" \
        | "$DUCKDB" -unsigned -noheader -list 2>/dev/null | tail -1 | tr -d ' ')"
[ "$have" != "0" ] || { echo "SKIP: this build has no Flight door"; exit 0; }
"$PYBIN" -c "import pyarrow.flight" 2>/dev/null || { echo "SKIP: pyarrow is not installed in $PYBIN"; exit 0; }

TMP="$(mktemp -d)"; SERVER_PID=""
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
FIFO="$TMP/ctl"; mkfifo "$FIFO"
{ echo "LOAD '$ACL_EXT';"; sed "s|\${ACL_E2E_URI}|$URI|g" "$HERE/bootstrap.sql"; echo "SELECT 1;"; } >"$TMP/server.sql"
"$DUCKDB" -unsigned <"$FIFO" >"$TMP/server.log" 2>&1 & SERVER_PID=$!
exec 3>"$FIFO"; cat "$TMP/server.sql" >&3
ready=""
for _ in $(seq 1 60); do
	kill -0 "$SERVER_PID" 2>/dev/null || { cat "$TMP/server.log" >&2; fail "the server exited early"; }
	"$PYBIN" "$HERE/client.py" "$URI" "SELECT 1" "$TOKEN" >/dev/null 2>&1 && { ready=1; break; }
	sleep 0.5
done
[ -n "$ready" ] || { cat "$TMP/server.log" >&2; fail "the door never came up on $URI"; }

# an operator statement fed through the fifo, awaited via its marker in the server log - the fifo is
# write-only from here, so the log is the only acknowledgement there is
operator() {
	local marker="$1" sql="$2"
	echo "SELECT '$marker' WHERE ($sql) IS NOT NULL;" >&3
	for _ in $(seq 1 40); do
		# the marker as a result's cell, never in a refusal's echo of the statement
		grep -Eq "│ *$marker *│" "$TMP/server.log" && return 0
		sleep 0.25
	done
	cat "$TMP/server.log" >&2; fail "the server never acknowledged $marker"
}

# spec 066's addendum: an operator - the operate bundle, its role reached through the client's own mapping (spec 095)
operator OPS_ROLE "acl_define_role('ops', '{}')"
operator OPS_SCOPE "acl_grant_admin('ops', 'operate')"
operator OPS_MAP "acl_map_role('client', 'test/idp/s', 'claim-value', 'ops', 'ops')"
OPS_TOKEN="$("$PYBIN" "$ROOT/test/scripts/idp_fixtures.py" mint \
	'{"iss": "test/idp/s", "aud": "api://acl-test", "exp": 4102444800, "sub": "u-ops", "roles": ["ops"], "tid": "acme"}')"
# the node's own rights seat a call (the addendum): a point grant on platform.resume, the operate bundle with a deny
# on resume (it still ends sessions - but resumes nothing), the observe bundle (it watches the drain); the policy
# bundle holds none of them
operator RESUMER_ROLE "acl_define_role('resumer', '{}')"
operator RESUMER_GRANT "acl_grant_platform('resumer', 'function', 'resume')"
operator RESUMER_MAP "acl_map_role('client', 'test/idp/s', 'claim-value', 'resumer', 'resumer')"
operator NORESUME_ROLE "acl_define_role('noresume', '{}')"
operator NORESUME_SCOPE "acl_grant_admin('noresume', 'operate')"
operator NORESUME_DENY "acl_grant_platform('noresume', 'function', 'resume', 'false')"
operator NORESUME_MAP "acl_map_role('client', 'test/idp/s', 'claim-value', 'noresume', 'noresume')"
mint() {
	"$PYBIN" "$ROOT/test/scripts/idp_fixtures.py" mint \
		"{\"iss\": \"test/idp/s\", \"aud\": \"api://acl-test\", \"exp\": 4102444800, \"sub\": \"u-$1\", \"roles\": [\"$1\"], \"tid\": \"acme\"}"
}
operator OBSERVER_ROLE "acl_define_role('observer', '{}')"
operator OBSERVER_SCOPE "acl_grant_admin('observer', 'observe')"
operator OBSERVER_MAP "acl_map_role('client', 'test/idp/s', 'claim-value', 'observer', 'observer')"
operator POLICY_ROLE "acl_define_role('policyonly', '{}')"
operator POLICY_SCOPE "acl_grant_admin('policyonly', 'policy')"
operator POLICY_MAP "acl_map_role('client', 'test/idp/s', 'claim-value', 'policyonly', 'policyonly')"
RESUMER_TOKEN="$(mint resumer)"
NORESUME_TOKEN="$(mint noresume)"
OBSERVER_TOKEN="$(mint observer)"
POLICY_TOKEN="$(mint policyonly)"
# server_true <marker> <condition>: the condition holds on the server, awaited via its marker in the log
server_true() {
	echo "SELECT '$1' WHERE ($2);" >&3
	for _ in $(seq 1 40); do
		grep -Eq "│ *$1 *│" "$TMP/server.log" && return 0
		sleep 0.25
	done
	cat "$TMP/server.log" >&2; fail "the server never acknowledged $1"
}

# seat a durable session: the first call is handed the cookie, the second returns it and is bound
JAR="$TMP/jar"
ACL_COOKIE_JAR="$JAR" "$PYBIN" "$HERE/client.py" "$URI" "SELECT count(*) FROM orders" "$TOKEN" >/dev/null \
	|| fail "the pre-drain client could not connect"
ACL_COOKIE_JAR="$JAR" "$PYBIN" "$HERE/client.py" "$URI" "SELECT count(*) FROM orders" "$TOKEN" >/dev/null \
	|| fail "the pre-drain client could not reuse its session"
[ -s "$JAR" ] || fail "the door set no session cookie"

# spec 134's addendum: a client that keeps no cookie holds what it was handed - a statement's ticket, a prepared
# statement - and redeems it on a draining node, as a connection-long session keeps working
held="$("$PYBIN" "$HERE/client.py" "$URI" "@ticket_out:SELECT count(*) AS n FROM orders" "$TOKEN")" ||
	fail "a cookie-less client could not take a ticket: $held"
ticket="$(echo "$held" | sed -n "s/.*'ticket': '\([0-9a-f]*\)'.*/\1/p")"
held="$("$PYBIN" "$HERE/client.py" "$URI" "@prepare_out:SELECT count(*) AS n FROM orders" "$TOKEN")" ||
	fail "a cookie-less client could not prepare: $held"
prepared="$(echo "$held" | sed -n "s/.*'prepared': '\([0-9a-f]*\)'.*/\1/p")"
[ -n "$ticket" ] && [ -n "$prepared" ] || fail "no ticket or prepared handle to hold"

operator DRAIN_ENTERED "acl_drain()"

got="$("$PYBIN" "$HERE/client.py" "$URI" "@redeem:$ticket" "$TOKEN" 2>&1)" || fail "a held ticket was refused during the drain: $got"
echo "$got" | grep -q "'n': \[5\]" || fail "the held ticket's rows: $got"
got="$("$PYBIN" "$HERE/client.py" "$URI" "@prepared_run:$prepared" "$TOKEN" 2>&1)" ||
	fail "a held prepared statement was refused during the drain: $got"
echo "$got" | grep -q "'n': \[5\]" || fail "the held prepared statement's rows: $got"

# the established session keeps working: the cookie resolves before the drain check is ever reached
ACL_COOKIE_JAR="$JAR" "$PYBIN" "$HERE/client.py" "$URI" "SELECT count(*) FROM orders" "$TOKEN" >/dev/null \
	|| fail "the established session was refused during the drain"

# a fresh client - no cookie, the SAME valid token - is refused, and told why
refusal="$("$PYBIN" "$HERE/client.py" "$URI" "SELECT 1" "$TOKEN" 2>&1)" \
	&& fail "a new client was seated during the drain"
echo "$refusal" | grep -q "draining" || fail "the refusal does not say draining: $refusal"

# re-authenticating the SEATED connection as another principal is a session swap - close, then open.
# A draining node must refuse the swap BEFORE the close: the globex token is refused...
GLOBEX_TOKEN="$("$PYBIN" "$ROOT/test/scripts/idp_fixtures.py" mint \
	'{"iss": "test/idp/s", "aud": "api://acl-test", "exp": 4102444800, "sub": "u-globex", "roles": ["analyst"], "tid": "globex"}')"
swap="$(ACL_COOKIE_JAR="$JAR" "$PYBIN" "$HERE/client.py" "$URI" "SELECT 1" "$GLOBEX_TOKEN" 2>&1)" \
	&& fail "a session swap was allowed during the drain"
echo "$swap" | grep -q "draining" || fail "the swap refusal does not say draining: $swap"
# ...and the seated session survived the attempt (half a swap - the close without the open - would
# be drain ending a session, which it never does)
ACL_COOKIE_JAR="$JAR" "$PYBIN" "$HERE/client.py" "$URI" "SELECT count(*) FROM orders" "$TOKEN" >/dev/null \
	|| fail "the refused swap killed the seated session"

# the drain's own right is seated call by call (the addendum), and a draining node hands out no session cookie: a
# client that keeps the door's cookie (a driver) stays cookie-less there, so its DoGet redeems by its bearer and a
# statement its GetFlightInfo ran is answered, never told "draining" after it ran
OJAR="$TMP/ops-jar"
got="$(ACL_COOKIE_JAR="$OJAR" "$PYBIN" "$HERE/client.py" "$URI" "KILL SESSION '000000000000'" "$OPS_TOKEN" 2>&1)" ||
	fail "a cookie-keeping operator's management call on the draining node: $got"
echo "$got" | grep -q "False" || fail "the call's answer: $got"
! grep -q "acl_flight_session_id" "$OJAR" 2>/dev/null || fail "a draining node handed out a session cookie"
# a cookie the client brings (a connection-long session) is refused, the operator's too
JAR2="$TMP/stale-jar"
printf 'acl_flight_session_id=%s' "$(printf '0%.0s' $(seq 1 32))" >"$JAR2"
kept="$(ACL_COOKIE_JAR="$JAR2" "$PYBIN" "$HERE/client.py" "$URI" "SELECT 1" "$OPS_TOKEN" 2>&1)" &&
	fail "an operator's connection-long session was seated during the drain"
echo "$kept" | grep -q "draining" || fail "the operator's connection-long refusal does not say draining: $kept"
# a console's read of the draining node: two calls (a GetFlightInfo seated by the addendum, a DoGet redeeming its
# ticket), the node's state as it is - the seated analyst's session, not the call's own
got="$("$PYBIN" "$HERE/client.py" "$URI" "SELECT draining, sessions_live FROM platform.node_load" "$OPS_TOKEN" 2>&1)" ||
	fail "an operator's read of the draining node: $got"
echo "$got" | grep -q "'draining': \[True\]" || fail "the load report does not say draining: $got"
echo "$got" | grep -q "'sessions_live': \[1\]" || fail "the load report counted the call's own session: $got"
got="$("$PYBIN" "$HERE/client.py" "$URI" "SELECT count(*) AS n FROM platform.sessions" "$OPS_TOKEN" 2>&1)" ||
	fail "an operator's sessions list: $got"
echo "$got" | grep -q "'n': \[1\]" || fail "the sessions list shows the call's own session: $got"
# the node's own rights are seated call by call; the policy bundle alone, and a token that does not verify, are
# refused as the drain
"$PYBIN" "$HERE/client.py" "$URI" "SELECT 1" "$RESUMER_TOKEN" >/dev/null ||
	fail "a point grant on platform.resume was not seated for its call"
got="$("$PYBIN" "$HERE/client.py" "$URI" "SELECT draining FROM platform.node_load" "$OBSERVER_TOKEN" 2>&1)" ||
	fail "the observe bundle was not seated to watch the drain: $got"
echo "$got" | grep -q "'draining': \[True\]" || fail "the observer's load report: $got"
got="$("$PYBIN" "$HERE/client.py" "$URI" "KILL SESSION '000000000000'" "$NORESUME_TOKEN" 2>&1)" ||
	fail "operate with a deny on resume was not seated to end sessions: $got"
echo "$got" | grep -q "False" || fail "its KILL SESSION: $got"
got="$("$PYBIN" "$HERE/client.py" "$URI" "RESUME NODE" "$NORESUME_TOKEN" 2>&1)" && fail "a deny on resume resumed the node"
echo "$got" | grep -q "denied" || fail "the deny on resume, as the authorizer says it: $got"
got="$("$PYBIN" "$HERE/client.py" "$URI" "SELECT 1" "$POLICY_TOKEN" 2>&1)" && fail "the policy bundle alone was seated"
echo "$got" | grep -q "draining" || fail "the policy bundle's refusal does not say draining: $got"
got="$("$PYBIN" "$HERE/client.py" "$URI" "SELECT 1" "${OPS_TOKEN%?????}AAAAA" 2>&1)" && fail "a forged token was seated"
echo "$got" | grep -q "draining" || fail "a forged token's refusal does not say draining: $got"
# the seats are decisions of the audit's - on record at the default level - and the forged token's its own refusal
echo "SELECT acl_audit_flush();" >&3
server_true SEATS_DECIDED "(SELECT count(*) FROM acl_audit_events() WHERE kind = 'session' AND detail = 'opened' \
	AND level = 'decisions' AND reason LIKE 'seated while draining%') >= 4"
server_true FORGED_PRINCIPAL "(SELECT count(*) FROM acl_audit_events() WHERE kind = 'session' AND detail = 'refused' \
	AND reason_code = 'principal') >= 1"
# a console's DRAIN NODE on the draining node answers what remains to drain, its own call's session not among them:
# the seated analyst's session alone
got="$("$PYBIN" "$HERE/client.py" "$URI" "DRAIN NODE" "$OPS_TOKEN" 2>&1)" || fail "an operator's DRAIN NODE call: $got"
echo "$got" | grep -q "\[1\]" || fail "DRAIN NODE counted its own call's session: $got"
# an operator holding no session on the node resumes it with a call, as a console does with the person's token -
# while the analyst connecting beside it is still refused
refusal="$("$PYBIN" "$HERE/client.py" "$URI" "SELECT 1" "$TOKEN" 2>&1)" \
	&& fail "a new analyst was seated during the drain"
echo "$refusal" | grep -q "draining" || fail "the analyst's refusal does not say draining: $refusal"
resumed="$("$PYBIN" "$HERE/client.py" "$URI" "RESUME NODE" "$OPS_TOKEN" 2>&1)" ||
	fail "the operator was not seated on the draining node to resume it: $resumed"
echo "$resumed" | grep -qi "true" || fail "RESUME NODE did not resume: $resumed"

"$PYBIN" "$HERE/client.py" "$URI" "SELECT 1" "$TOKEN" >/dev/null \
	|| fail "a new client is still refused after the operator's RESUME NODE"

echo "SELECT acl_flight_stop('$URI');" >&3
echo "PASS: the draining door kept its seated session and a cookie-less client's held ticket and prepared statement, refused the new client with the reason, refused an operator's connection-long session and seated its one call, which resumed it"
