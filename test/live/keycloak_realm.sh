#!/usr/bin/env bash
# Create (or converge) the standing dev realm for the live node (spec 057/061): a realm, a public
# client speaking password + device flow, the demo roles and tenant-attributed users - everything the
# provider round trip and the runbook need, reproducibly. Idempotent: re-running converges.
#
# Credentials come from the repo .env: KEY_CLOAK_HOST, KEY_CLOAK_PORT, KEY_CLOAK_ADMIN_USER,
# KEY_CLOAK_ADMIN_PASS. Keycloak 26 lessons baked in: the declarative user profile drops unmanaged
# attributes unless enabled (the tenant claim would silently vanish), and a user without
# email/names/cleared-requiredActions cannot password-grant ("Account is not fully set up").
#
#   test/live/keycloak_realm.sh            # create/converge realm 'acl-dev'
#   ACL_KC_REALM=other test/live/keycloak_realm.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
# read only the KEY_CLOAK_* lines: the .env carries non-shell values (vcpkg cache config), so
# sourcing it wholesale breaks
env_get() { grep -E "^$1=" "$ROOT/.env" 2>/dev/null | head -1 | cut -d= -f2-; }
KEY_CLOAK_HOST="${KEY_CLOAK_HOST:-$(env_get KEY_CLOAK_HOST)}"
KEY_CLOAK_PORT="${KEY_CLOAK_PORT:-$(env_get KEY_CLOAK_PORT)}"
KEY_CLOAK_ADMIN_USER="${KEY_CLOAK_ADMIN_USER:-$(env_get KEY_CLOAK_ADMIN_USER)}"
KEY_CLOAK_ADMIN_PASS="${KEY_CLOAK_ADMIN_PASS:-$(env_get KEY_CLOAK_ADMIN_PASS)}"
KC="http://${KEY_CLOAK_HOST:-localhost}:${KEY_CLOAK_PORT:-18070}"
REALM="${ACL_KC_REALM:-acl-dev}"
: "${KEY_CLOAK_ADMIN_USER:?set KEY_CLOAK_ADMIN_USER in .env}"
: "${KEY_CLOAK_ADMIN_PASS:?set KEY_CLOAK_ADMIN_PASS in .env}"

say() { echo "  $*"; }
TOKEN=$(curl -sf -d grant_type=password -d client_id=admin-cli \
	-d "username=$KEY_CLOAK_ADMIN_USER" -d "password=$KEY_CLOAK_ADMIN_PASS" \
	"$KC/realms/master/protocol/openid-connect/token" | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')
AUTH="Authorization: Bearer $TOKEN"
R="$KC/admin/realms/$REALM"

code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$KC/admin/realms" -H "$AUTH" \
	-H "Content-Type: application/json" \
	-d "{\"realm\":\"$REALM\",\"enabled\":true,\"oauth2DeviceCodeLifespan\":600}")
say "realm $REALM: $([ "$code" = 201 ] && echo created || echo "exists ($code)")"

# KC 26: unmanaged user attributes are dropped unless the profile allows them - without this the
# tenant attribute never reaches the token and RLS slices to nothing
curl -sf "$R/users/profile" -H "$AUTH" | python3 -c '
import json,sys; p=json.load(sys.stdin); p["unmanagedAttributePolicy"]="ENABLED"; print(json.dumps(p))' |
	curl -sf -o /dev/null -X PUT "$R/users/profile" -H "$AUTH" -H "Content-Type: application/json" --data @-
say "user profile: unmanaged attributes enabled"

code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$R/clients" -H "$AUTH" -H "Content-Type: application/json" -d '{
	"clientId":"acl-cli","publicClient":true,"directAccessGrantsEnabled":true,"standardFlowEnabled":false,
	"attributes":{"oauth2.device.authorization.grant.enabled":"true"},
	"protocolMappers":[{"name":"tenant","protocol":"openid-connect","protocolMapper":"oidc-usermodel-attribute-mapper",
		"config":{"user.attribute":"tenant","claim.name":"tenant","jsonType.label":"String","access.token.claim":"true"}}]}')
say "client acl-cli (password+device, tenant mapper): $([ "$code" = 201 ] && echo created || echo "exists ($code)")"

for role in analyst viewer; do
	code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$R/roles" -H "$AUTH" -H "Content-Type: application/json" -d "{\"name\":\"$role\"}")
	say "role $role: $([ "$code" = 201 ] && echo created || echo "exists ($code)")"
done

# username / password / tenant / role
make_user() {
	local name="$1" pass="$2" tenant="$3" role="$4"
	# full representation every time: a partial PUT resets fields, and missing email/names leave the
	# account "not fully set up" for the password grant (KC 26)
	local body="{\"username\":\"$name\",\"enabled\":true,\"emailVerified\":true,\"email\":\"$name@$REALM.local\",
		\"firstName\":\"${name}\",\"lastName\":\"user\",\"requiredActions\":[],
		\"attributes\":{\"tenant\":[\"$tenant\"]}}"
	local code
	code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$R/users" -H "$AUTH" -H "Content-Type: application/json" -d "$body")
	local uid
	uid=$(curl -sf "$R/users?username=$name" -H "$AUTH" | python3 -c 'import json,sys; u=json.load(sys.stdin); print(u[0]["id"] if u else "")')
	curl -sf -o /dev/null -X PUT "$R/users/$uid" -H "$AUTH" -H "Content-Type: application/json" -d "$body"
	curl -sf -o /dev/null -X PUT "$R/users/$uid/reset-password" -H "$AUTH" -H "Content-Type: application/json" \
		-d "{\"type\":\"password\",\"value\":\"$pass\",\"temporary\":false}"
	local rid
	rid=$(curl -sf "$R/roles/$role" -H "$AUTH" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
	curl -s -o /dev/null -X POST "$R/users/$uid/role-mappings/realm" -H "$AUTH" -H "Content-Type: application/json" \
		-d "[{\"id\":\"$rid\",\"name\":\"$role\"}]"
	say "user $name (tenant=$tenant, role=$role): $([ "$code" = 201 ] && echo created || echo converged)"
}
make_user analyst1 "${ACL_KC_ANALYST1_PASS:-analyst1-pass}" acme analyst
make_user analyst2 "${ACL_KC_ANALYST2_PASS:-analyst2-pass}" globex analyst
make_user viewer1 "${ACL_KC_VIEWER1_PASS:-viewer1-pass}" acme viewer

cat <<INFO

realm ready: $KC/realms/$REALM
  issuer for the node:  ACL ADMIN CREATE ISSUER '$KC/realms/$REALM'
                          KEYS FROM '$KC/realms/$REALM/protocol/openid-connect/certs'
                          AUDIENCES ('account') ALGS (RS256)
                          ROLE CLAIM 'realm_access.roles' CLAIM MAP '{"tenant": "tenant"}';
  provider secret:      CREATE SECRET kc (TYPE quack, PROVIDER oidc, SCOPE 'quack:<host>:<port>',
                          ISSUER '$KC/realms/$REALM', CLIENT_ID 'acl-cli',
                          FLOW 'password', USERNAME 'analyst1', PASSWORD '<pass>');
                        -- or FLOW 'device' for the browser login
  serve with it:        ACL_LIVE_KEYCLOAK=$KC/realms/$REALM test/live/serve.sh flight
INFO
