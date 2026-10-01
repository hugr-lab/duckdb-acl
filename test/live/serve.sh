#!/usr/bin/env bash
# Serve one live node for real client tools (spec 057): DBeaver over Flight SQL JDBC, an ADBC client,
# a duckdb+quack client. Seeds the runbook's policy, prints the connection material, and holds the
# node until Ctrl+C. See RUNBOOK.md next to this script for what to do in each tool.
#
#   test/live/serve.sh                # both doors (flight cleartext-localhost + quack if built)
#   test/live/serve.sh flight         # the Flight SQL door only (ADBC / JDBC / DBeaver)
#   test/live/serve.sh flight --tls   # ... over grpc+tls on 0.0.0.0 with a self-signed cert
#   test/live/serve.sh quack          # the quack door only
#   ACL_LIVE_PORT=... ACL_LIVE_QUACK_PORT=... to move the ports
#
# VS Code: the tasks in .vscode/tasks.json run exactly these (Terminal > Run Task...).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" # spec 095: the demo issuer (test/idp/s) is read relative to the repository root
HERE="$(cd "$(dirname "$0")" && pwd)"
BUILD="${BUILD_DIR:-$ROOT/build/release}"
DUCKDB="${DUCKDB_BIN:-$BUILD/duckdb}"
ACL_EXT="${ACL_EXT:-$BUILD/extension/acl/acl.duckdb_extension}"
QUACK_EXT="$(ls "$BUILD"/extension/quack/quack.duckdb_extension 2>/dev/null || true)"
PORT="${ACL_LIVE_PORT:-32700}"
QPORT="${ACL_LIVE_QUACK_PORT:-31700}"

MODE="all"
TLS=""
for arg in "$@"; do
	case "$arg" in
		flight|quack|all) MODE="$arg" ;;
		--tls) TLS=1 ;;
		*) echo "usage: test/live/serve.sh [flight|quack|all] [--tls]" >&2; exit 1 ;;
	esac
done

[ -x "$DUCKDB" ] || { echo "no duckdb CLI at $DUCKDB - run 'make' first" >&2; exit 1; }
[ -f "$ACL_EXT" ] || { echo "no acl extension at $ACL_EXT - run 'make' first" >&2; exit 1; }
if [ "$MODE" = "quack" ] && [ -z "$QUACK_EXT" ]; then
	echo "the quack extension is not built - rebuild with ACL_QUACK=1 GEN=ninja make" >&2
	exit 1
fi
[ "$MODE" = "quack" ] && [ -n "$TLS" ] && echo "note: --tls is the Flight door's; the quack door listens in the clear behind a proxy" >&2

TOKEN_ANALYST_ACME='eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2V5In0.eyJpc3MiOiJ0ZXN0L2lkcC9zIiwiYXVkIjoiYXBpOi8vYWNsLXRlc3QiLCJleHAiOjQxMDI0NDQ4MDAsInN1YiI6InUtYWNtZSIsInJvbGVzIjpbImFuYWx5c3QiXSwidGlkIjoiYWNtZSJ9.UV5-WWUpQLp-Em8K2yLLkz-NEJgOyTAn9i9B1zpBWF3hNQVgorAVPVK48bxnrMiMm7NabgM3g945lDY31DFwxNeUKnVEe0QdRy1d1KbFh8td3Ak_mepOZ35CjPektGaOjVEpjUFxZUOj_uxYnse_y660xC0stlY8zxDrpSjNCOZRGv-vaxITv7ggOIDYAN07rmPntKe9oOYsb5g0ZkFcIEsKuHuXsL8z1crko6vIZzT9ido-xrph_WEejO5lKaPIxVe1QrB1-C5DUp8D8fnLWMJ3g426VNKWJwUyeSgh_nq1XzLyR8WcLchBQwaFAzkGivmLFmDdrDS7VUy49I8uLw'
TOKEN_ANALYST_GLOBEX='eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2V5In0.eyJpc3MiOiJ0ZXN0L2lkcC9zIiwiYXVkIjoiYXBpOi8vYWNsLXRlc3QiLCJleHAiOjQxMDI0NDQ4MDAsInN1YiI6InUtZ2xvYmV4Iiwicm9sZXMiOlsiYW5hbHlzdCJdLCJ0aWQiOiJnbG9iZXgifQ.US9D_P5MEhrwKYF-K5NwGoeMGXBaK6mky8oKM57xfJvZObM_yIhEp1uJhBN5MmmRuF6EV330IwT3W8RtgarfaK0iTlpHqmjEowIbhyQnFD84xOmjbTeBpSHaIBDWS8F2ayNKaUcXZFqfIPZrImvmASDQSQggTwkCnEyGpxPP7F__7MAC2PkDAV73RVVOuAW1QwqbYCPoeydXS-sgMBU2v031ngk8On-UTeZ3ZaCwMhznOUMwQUpFkCtSmwdt2_OgvYn_PC_Mu6f7UGFbTf2kXXHy6ps6QwT6pCpKoILA3uc-sjTRz1ZwyPy2NuKwceBIwiXbKTxPz5PH9KoLYUD6sg'
TOKEN_VIEWER='eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2V5In0.eyJpc3MiOiJ0ZXN0L2lkcC9zIiwiYXVkIjoiYXBpOi8vYWNsLXRlc3QiLCJleHAiOjQxMDI0NDQ4MDAsInN1YiI6InUtdmlld2VyIiwicm9sZXMiOlsidmlld2VyIl0sInRpZCI6ImFjbWUifQ.SiXcR8NX0S95O0FeUkCPmdaUPAt7E6D4DXT60k3a21yiIMekP5I-XGY1K5tIEr_5XttG4WPpoYTq9Dt5dF4elM365178laj6Nldj9572MpSF4v5h-lIGvBQd7p0xdyj_lghwYMniy9b7sb-MNX_VpOlQRw1NG_-A5fPD_KIlDA2aOK1d8x8boJlE6hXfpyvKeeDkccqxxs9MMZF6iincDIkvFLUoTacJdBosdpm1YgrZ7p2UId3HZYZdeQod0DkCLtkerngW61VNoAdCSGyZVabD0aJ5Pe2YfzrXpSgbz6FATFeZmKAHWp5O-pQbkNfiO1ZUOEDSxCNppJxYgaCkOw'

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT INT TERM

FLIGHT_SERVE="SELECT 'flight door: not started (quack-only mode)' AS flight;"
FLIGHT_URI="grpc://localhost:$PORT"
JDBC_ENC="useEncryption=false"
if [ "$MODE" != "quack" ]; then
	FLIGHT_ARGS="'grpc://localhost:$PORT'"
	if [ -n "$TLS" ]; then
		command -v openssl >/dev/null || { echo "openssl is needed for --tls" >&2; exit 1; }
		openssl req -x509 -newkey rsa:2048 -keyout "$TMP/key.pem" -out "$TMP/cert.pem" -days 7 -nodes \
			-subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" >/dev/null 2>&1
		FLIGHT_URI="grpc+tls://localhost:$PORT"
		FLIGHT_ARGS="'grpc://0.0.0.0:$PORT', '$TMP/cert.pem', '$TMP/key.pem'"
		JDBC_ENC="useEncryption=true&disableCertificateVerification=true"
	fi
	FLIGHT_SERVE="SELECT acl_flight_serve($FLIGHT_ARGS);"
fi

HTTPFS_EXT="$(ls "$BUILD"/extension/httpfs/httpfs.duckdb_extension 2>/dev/null || true)"
HTTPFS_LOAD="LOAD httpfs;"
[ -n "$HTTPFS_EXT" ] && HTTPFS_LOAD="LOAD '$HTTPFS_EXT';"

QUACK_SERVE="SELECT 'quack door: not started' AS quack;"
if [ "$MODE" != "flight" ] && [ -n "$QUACK_EXT" ]; then
	# quack's crypto needs httpfs loaded (the same `require httpfs` its integration tests carry)
	QUACK_SERVE="$HTTPFS_LOAD LOAD '$QUACK_EXT'; SELECT acl_quack_serve('quack:localhost:$QPORT', 'live-server-token');"
elif [ "$MODE" = "all" ] && [ -z "$QUACK_EXT" ]; then
	QUACK_SERVE="SELECT 'quack door: not built (rebuild with ACL_QUACK=1)' AS quack;"
fi

# spec 057, optional: hook a real Keycloak issuer. Set ACL_LIVE_KEYCLOAK to the realm base URL
# (e.g. http://localhost:18070/realms/master); its keys are found by the realm's OIDC discovery over
# httpfs (spec 095), roles come from realm_access.roles (spec 007), and a `tenant` user attribute
# drives the RLS.
KC_ISSUER="-- ACL_LIVE_KEYCLOAK not set: only the demo issuer is defined"
KC_PRELOAD=""
# the demo issuer's discovery is a fixture of the repository (spec 095)
KC_LOCATIONS="SET GLOBAL acl_jwks_locations = 'test/idp/';"
if [ -n "${ACL_LIVE_KEYCLOAK:-}" ]; then
	KC_REALM="${ACL_LIVE_KEYCLOAK%/}"
	KC_AUD="${ACL_LIVE_KC_AUDIENCE:-account}"
	KC_TENANT="${ACL_LIVE_KC_TENANT_CLAIM:-tenant}"
	KC_PRELOAD="$HTTPFS_LOAD"  # the realm's discovery and JWKS are read at verify time
	# the realm's own URL is the one network location this node reads keys from (spec 071): a local
	# Keycloak over http is admitted by name, never by scheme
	KC_LOCATIONS="SET GLOBAL acl_jwks_locations = 'https://, test/idp/, $KC_REALM/';"
	KC_ISSUER="ACL ADMIN CREATE ISSUER '$KC_REALM' AUDIENCES ('$KC_AUD') ROLE CLAIM 'realm_access.roles' CLAIM MAP '{\"$KC_TENANT\": \"tenant\"}';"
fi

{
	echo "LOAD '$ACL_EXT';"
	[ -n "$KC_PRELOAD" ] && echo "$KC_PRELOAD"
	[ -n "$KC_LOCATIONS" ] && echo "$KC_LOCATIONS"
	sed -e "s|\${LIVE_FLIGHT_SERVE}|$FLIGHT_SERVE|" -e "s|\${LIVE_QUACK_SERVE}|$QUACK_SERVE|" \
	    -e "s|\${LIVE_KEYCLOAK_ISSUER}|$KC_ISSUER|" "$HERE/bootstrap.sql"
} >"$TMP/server.sql"

echo "=== the live node (spec 057) ====================================================================="
if [ "$MODE" != "quack" ]; then
	cat <<INFO
Flight SQL door:   $FLIGHT_URI
DBeaver JDBC URL:  jdbc:arrow-flight-sql://localhost:$PORT/?$JDBC_ENC
                   (driver: org.apache.arrow:flight-sql-jdbc-driver; auth: driver property
                    token = <one of the tokens below>)
INFO
fi
if [ "$MODE" != "flight" ] && [ -n "$QUACK_EXT" ]; then
	cat <<INFO
quack door:        ATTACH 'quack:localhost:$QPORT' AS remote (TYPE quack, TOKEN '<token>');
INFO
fi
cat <<INFO

tokens (RS256, demo issuer, exp 2100):
  analyst @ acme:    $TOKEN_ANALYST_ACME
  analyst @ globex:  $TOKEN_ANALYST_GLOBEX
  viewer  @ acme:    $TOKEN_VIEWER
INFO
if [ -n "${ACL_LIVE_KEYCLOAK:-}" ]; then
	cat <<INFO

Keycloak issuer wired: ${ACL_LIVE_KEYCLOAK%/}
  get a token, then pass it like the demo ones above:
  curl -s -d grant_type=password -d client_id=<client> -d username=<user> -d password=<pw> \\
       ${ACL_LIVE_KEYCLOAK%/}/protocol/openid-connect/token | python3 -c 'import json,sys;print(json.load(sys.stdin)["access_token"])'
  (the user needs a realm role named analyst or viewer, and a `tenant` claim - see RUNBOOK.md)
INFO
fi
cat <<INFO

Walk RUNBOOK.md. Ctrl+C stops the node.
==================================================================================================
INFO

# not exec: the EXIT trap must still clean TMP (the TLS key lives there) when duckdb exits
"$DUCKDB" -unsigned -init "$TMP/server.sql" 2>&1
