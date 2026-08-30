#!/usr/bin/env bash
# Serve one live node for real client tools (spec 057): DBeaver over Flight SQL JDBC, an ADBC client,
# a duckdb+quack client. Seeds the runbook's policy, prints the connection material, and holds the
# node until Ctrl+C. See RUNBOOK.md next to this script for what to do in each tool.
#
#   test/live/serve.sh              # Flight cleartext on localhost:32700 (+ quack if built)
#   test/live/serve.sh --tls        # Flight over grpc+tls on 0.0.0.0:32700 with a self-signed cert
#   ACL_LIVE_PORT=... ACL_LIVE_QUACK_PORT=... to move the ports
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
HERE="$(cd "$(dirname "$0")" && pwd)"
BUILD="${BUILD_DIR:-$ROOT/build/release}"
DUCKDB="${DUCKDB_BIN:-$BUILD/duckdb}"
ACL_EXT="${ACL_EXT:-$BUILD/extension/acl/acl.duckdb_extension}"
QUACK_EXT="$(ls "$BUILD"/extension/quack/quack.duckdb_extension 2>/dev/null || true)"
PORT="${ACL_LIVE_PORT:-32700}"
QPORT="${ACL_LIVE_QUACK_PORT:-31700}"
TLS=""
[ "${1:-}" = "--tls" ] && TLS=1

[ -x "$DUCKDB" ] || { echo "no duckdb CLI at $DUCKDB - run 'make' first" >&2; exit 1; }
[ -f "$ACL_EXT" ] || { echo "no acl extension at $ACL_EXT - run 'make' first" >&2; exit 1; }

TOKEN_ANALYST_ACME='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci50ZXN0L3MiLCJhdWQiOiJhcGk6Ly9hY2wtdGVzdCIsImV4cCI6NDEwMjQ0NDgwMCwic3ViIjoidS1hY21lIiwicm9sZXMiOlsiYW5hbHlzdCJdLCJ0aWQiOiJhY21lIn0.vzPJbHXAXfczhZwQp183JaaBLlSRSipNsSqwxoIFfng'
TOKEN_ANALYST_GLOBEX='eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJpc3MiOiAiaHR0cHM6Ly9pc3N1ZXIudGVzdC9zIiwgImF1ZCI6ICJhcGk6Ly9hY2wtdGVzdCIsICJleHAiOiA0MTAyNDQ0ODAwLCAic3ViIjogInUtZ2xvYmV4IiwgInJvbGVzIjogWyJhbmFseXN0Il0sICJ0aWQiOiAiZ2xvYmV4In0.N92ysQlqQLA2PapK-VdxsokNyXPxPlmO6YQJVQB8H6I'
TOKEN_VIEWER='eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJpc3MiOiAiaHR0cHM6Ly9pc3N1ZXIudGVzdC9zIiwgImF1ZCI6ICJhcGk6Ly9hY2wtdGVzdCIsICJleHAiOiA0MTAyNDQ0ODAwLCAic3ViIjogInUtdmlld2VyIiwgInJvbGVzIjogWyJ2aWV3ZXIiXSwgInRpZCI6ICJhY21lIn0.wwCW65Avnzt1nhjOcvOdZjjQmF3G-vPL1BigusZtIR8'

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT INT TERM

FLIGHT_URI="grpc://localhost:$PORT"
FLIGHT_ARGS="'grpc://localhost:$PORT'"
JDBC_ENC="useEncryption=false"
if [ -n "$TLS" ]; then
	command -v openssl >/dev/null || { echo "openssl is needed for --tls" >&2; exit 1; }
	openssl req -x509 -newkey rsa:2048 -keyout "$TMP/key.pem" -out "$TMP/cert.pem" -days 7 -nodes \
		-subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" >/dev/null 2>&1
	FLIGHT_URI="grpc+tls://localhost:$PORT"
	FLIGHT_ARGS="'grpc://0.0.0.0:$PORT', '$TMP/cert.pem', '$TMP/key.pem'"
	JDBC_ENC="useEncryption=true&disableCertificateVerification=true"
fi

QUACK_SERVE="SELECT 'quack door: not built (rebuild with ACL_QUACK=1)' AS quack;"
if [ -n "$QUACK_EXT" ]; then
	QUACK_SERVE="LOAD '$QUACK_EXT'; SELECT acl_quack_serve('quack:localhost:$QPORT', 'live-server-token');"
fi

{
	echo "LOAD '$ACL_EXT';"
	sed -e "s|\${LIVE_FLIGHT_ARGS}|$FLIGHT_ARGS|" -e "s|\${LIVE_QUACK_SERVE}|$QUACK_SERVE|" "$HERE/bootstrap.sql"
} >"$TMP/server.sql"

cat <<INFO
=== the live node (spec 057) =====================================================================
Flight SQL door:   $FLIGHT_URI
DBeaver JDBC URL:  jdbc:arrow-flight-sql://localhost:$PORT/?$JDBC_ENC
                   (driver: org.apache.arrow:flight-sql-jdbc-driver; auth: driver property
                    token = <one of the tokens below>)
INFO
if [ -n "$QUACK_EXT" ]; then
	cat <<INFO
quack door:        ATTACH 'quack:localhost:$QPORT' AS remote (TYPE quack, TOKEN '<token>');
INFO
fi
cat <<INFO

tokens (HS256, demo issuer, exp 2100):
  analyst @ acme:    $TOKEN_ANALYST_ACME
  analyst @ globex:  $TOKEN_ANALYST_GLOBEX
  viewer  @ acme:    $TOKEN_VIEWER

Walk RUNBOOK.md. Ctrl+C stops the node.
==================================================================================================
INFO

# not exec: the EXIT trap must still clean TMP (the TLS key lives there) when duckdb exits
"$DUCKDB" -unsigned -init "$TMP/server.sql" 2>&1
