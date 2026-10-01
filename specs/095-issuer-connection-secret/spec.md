# Spec 095: issuers and clients - which tokens are trusted, and what they become

- **Status**: implemented
- **Date**: 2026-10-01
- **Design**: design/018-identity-model (v3), design/017-hugr-platform §3.6a

## Summary

A token becomes a principal in three steps, and each step gets an object of its own:

1. **`ISSUER`**: trusting the IdP.
   - It has a name and a URL.
   - Its keys and algorithms come from OIDC discovery by default, or from a secret.
2. **`CLIENT`**: which tokens of that issuer count, and how to read them.
   - It decides by audiences, `azp` and conditions on claims.
   - From the token it reads the role sources, the attributes that RLS predicates use, and the
     subject (used for audit only).
   - It may describe how a token is obtained: a client id and flows.
3. **Role mappings**, scoped to a client or an issuer: raw values become our roles. Grants go only to
   roles.

**The simple case stays one statement.** `CREATE ISSUER '<url>' AUDIENCES … ROLE CLAIM …` creates
the issuer and its implicit client (named after the issuer). Several clients per IdP, conditions, constants and
confidential clients are the same objects written explicitly. An installation grows from one form
into the other without re-creating anything.

**Credentials and key material live in tresor only.** A confidential client's `CLIENT_SECRET`,
pasted keys and algorithm overrides go in a secret kept by the node's secrets service: a catalog of
type `tresor`, the same service as spec 082. Such a secret is never kept in the policy catalog, nor
in the node's own memory or `local_file` secret storage. tresor makes them rotatable and independent
of users: the storage's TTL is the freshness bound, and a rotation needs no policy write. A secret is
attached explicitly by name and is never matched by scope.

## Problem

- **Credentials are stored in the policy catalog.** `issuers.client_secret` (spec 064) keeps a
  confidential client's secret there, against "credentials are written nowhere" (design/017 §3.6a).
  Pasted keys live there too, and an HS256 `oct` key is a shared secret.
- **One issuer has one token shape.** It has one role claim, one claim map and one client id. Real
  IdPs serve several applications whose tokens differ in shape:
  - Keycloak mappers are per client;
  - Entra has v1 and v2 apps.
- **Role mappings are global to an issuer.** An unmapped raw value that names an existing role
  becomes that role. That is unsafe once the IdP is not our own.
- **A discoverable issuer still had to be told where its keys were.**

## Design

### 1. `ISSUER`: the trust anchor

```sql
CREATE ISSUER kc URL 'https://kc/realms/acme';                     -- keys and algs by discovery
CREATE ISSUER kc URL 'https://kc/realms/acme' FROM SECRET kc_conn;  -- overrides from tresor
CREATE ISSUER kc FROM SECRET kc_conn IN corp;                       -- the URL in the secret too
ALTER  ISSUER kc SET URL '…' | SET FROM SECRET s [IN c] | DROP FROM SECRET;
DROP   ISSUER [IF EXISTS] kc;   -- refused while an explicit client names it; takes its implicit
                                -- client and every mapping scoped to either
```

- **Name and URL.**
  - The name is the key, and references use it.
  - A URL is **unique** among issuers, so a token's `iss` routes to at most one issuer.
  - The URL is on the issuer **or** in its secret, never both. A policy catalog can then be the same
    in every environment, with the URL in each environment's secret.
- **Keys:**
  1. the secret's `KEYS` (a JWKS document) or `KEYS_FROM` (a location, spec 023), when the secret has
     them; these fields exist only in secrets;
  2. otherwise OIDC discovery: `<url>/.well-known/openid-configuration` → `jwks_uri`. The document's
     `issuer` must equal the URL.
  - Caching: the discovery document and the JWKS are cached **by location**, under spec 023's
    refresh rules; `acl_jwks_cache()` shows one row per location with the issuer that read it last,
    and `acl_jwks_refresh([issuer])` drops what one issuer read.
  - A key verifies only tokens routed to its own issuer. `iss` is re-checked after the signature is
    verified.
- **Algorithms:**
  1. the secret's `ALGS`, when it has them;
  2. keys from the secret without `ALGS`: RS256 and ES256;
  3. otherwise the discovery document's `id_token_signing_alg_values_supported` ∩ {RS256, ES256} -
     refused by name when that is empty;
  4. RS256 when the document lists none.
  - HS256 only with pasted `KEYS` in a secret whose `ALGS` names it - a key read from a location is
    never a shared secret - and `none` never.
- **Network locations.** Every location the node fetches is bound by `acl_jwks_locations` (spec 071):
  the discovery document and `KEYS_FROM`, whether they come from the issuer or from a secret. A
  secret cannot send the node outside the operator's list.

### 2. `CLIENT`: acceptance and token shape

```sql
CREATE CLIENT desktop ISSUER kc
    AUDIENCES ('account') AZP ('acl-desktop')
    ROLES FROM ('realm_access.roles', 'groups')
    ATTRIBUTES (tenant = 'tenant', email = ('email', 'upn'))
    CLIENT ID 'acl-desktop' FLOWS (authcode, device);

-- a confidential client: its CLIENT_SECRET is in tresor
CREATE PERSISTENT SECRET kc_door IN corp (TYPE oidc_client, CLIENT_ID 'acl-door', CLIENT_SECRET '…');
CREATE CLIENT door ISSUER kc AUDIENCES ('account') AZP ('acl-door')
    ROLES FROM ('realm_access.roles') FLOWS (password) FROM SECRET kc_door;

CREATE CLIENT etl ISSUER github AUDIENCES ('acl-node')
    REQUIRE (sub LIKE 'repo:hugr-lab/etl:%', repository_owner = 'hugr-lab')
    ROLES CONSTANT ('etl_writer') ATTRIBUTES (pipeline = CONSTANT 'etl');

ALTER CLIENT desktop SET <clause> … | DROP FROM SECRET;   -- a list clause is replaced whole
DROP CLIENT [IF EXISTS] desktop;                           -- with its mappings
```

| clause | where it lives | meaning |
| --- | --- | --- |
| `AUDIENCES (…)` | client or its secret | **Required**, non-empty. The token's `aud` must intersect it. |
| `AZP (…)` | client | The token's `azp` (Entra v1: `appid`) must be in the list. |
| `REQUIRE (…)` | client | Conditions on claims; all must hold: `path = v`, `path IN (…)`, `v IN path` (array contains), `path LIKE 'p%'` / `'%s'`. |
| `ROLES FROM (…)` | client | Claim paths whose values are role candidates (union; each a string or an array). |
| `ROLES CONSTANT (…)` | client | Roles every token of this client gets. |
| `UNMAPPED IGNORE` / `UNMAPPED AS ROLE` | client | What an unmapped candidate does (§4). Default `IGNORE`; `AS ROLE` for the implicit client. |
| `ATTRIBUTES (…)` | client | `name = 'path'`, `= ('path', 'fallback', …)` or `= CONSTANT 'v'`; read as `acl_claim('name')`. |
| `SUBJECT 'path'` / `('path', …)` | client | The principal's subject, for audit and the session fingerprint only. Default `sub`. |
| `TOKEN TYPE 'at+jwt'` | client, optional | Refuse a token with another `typ` (RFC 9068: no ID token as an access token). |
| `CLIENT ID '…'` | client or its secret | The OAuth client used to obtain tokens. |
| `CLIENT_SECRET` | **secret only** (tresor) | A confidential client's secret. |
| `FLOWS (…)` | client | `password` (the door's handshake, spec 064), `authcode` and `device` (drivers), `client_credentials`. |
| `FROM SECRET s [IN c]` | client | An `oidc_client` secret in tresor that holds the fields above. |

A client without `FLOWS` only accepts tokens: tokens of its shape are verified, but neither the node
nor a driver obtains one through it. An external application or a CI job is such a client.

### 3. Routing a token to exactly one client

1. **Route and verify.** Parse the token, route `iss` to its issuer by URL, and verify the signature
   with that issuer's keys and algorithms. Re-check `iss`, then check `exp` and `nbf` with spec 007's
   skew.
2. **Find the candidates.** A client of that issuer is a candidate when:
   - `aud` intersects its `AUDIENCES`;
   - `azp` is in its `AZP`, if `AZP` is set;
   - every `REQUIRE` condition holds.
3. **The most specific candidate wins.** Specificity is:
   - 2 for a client with `AZP` or `REQUIRE`;
   - 1 for an explicit client with neither;
   - 0 for the implicit client of the short form.
4. **Ties and no match are refused (fail closed).** Two candidates of equal specificity are refused
   as **ambiguous**. No candidate is refused too: *"no client of issuer X accepts this token"*.
5. **Overlaps are refused at write where they can be seen.** A write is refused when two clients of
   one issuer have the same specificity, overlapping audiences, and either overlapping `AZP` or no
   `AZP` and no `REQUIRE` on both.
   - `REQUIRE` cannot be compared statically, so for those clients ambiguity is judged at use.
   - The same goes for audiences that come from secrets, which can change.

### 4. Roles: what grants see

1. **Candidates**: the values at every `ROLES FROM` path, as strings.
2. **Mapping**: each candidate is looked up in the client's own mappings and in its issuer's
   mappings (§5). It yields every role it is mapped to.
3. **Unmapped candidates**:
   - `UNMAPPED IGNORE` drops them;
   - `UNMAPPED AS ROLE` keeps one as the role of the same name, if that role exists (today's
     behaviour).
4. **Constants**: `ROLES CONSTANT` are added.
5. **An empty set of roles is a refusal**: *"no recognized roles"*.

**Privileged roles.** A role that holds an administration scope (spec 009: `manage` or
`passthrough`) is reached **only through an explicit mapping on the client itself**:

| path to a privileged role | at write | at use |
| --- | --- | --- |
| issuer-scope mapping | refused | dropped |
| `UNMAPPED AS ROLE` | — | never yields one |
| `ROLES CONSTANT` | refused | — |
| a role that becomes privileged later | — | dropped |

**Defaults differ by form.**
- The implicit client of the short form uses `UNMAPPED AS ROLE`, so a single own IdP whose roles are
  named like ours needs no mappings.
- An explicit `CREATE CLIENT` uses `UNMAPPED IGNORE`.
- The platform's onboarding of a customer's IdP always writes `IGNORE`.

**Attributes.** These are the claims RLS reads (`acl_claim('name')`), and they replace `CLAIM MAP`.
A `CONSTANT` attribute cannot be overridden by the token: that is the ceiling a customer's IdP cannot
pass (§9).

### 5. Role mappings

```sql
MAP GROUP '8f3c…' FROM CLIENT desktop TO ROLE finance;   -- an identifier (an Entra group GUID)
MAP CLAIM 'sales'  FROM CLIENT desktop TO ROLE analyst;  -- a claim value
MAP CLAIM 'sales'  FROM ISSUER kc      TO ROLE analyst;  -- every client of kc
DROP MAP …;
```

- A mapping is scoped to a client or to an issuer; there is no global mapping.
- A candidate is looked up only in its own client's and issuer's mappings. Customer A's `admin`
  group never passes through customer B's mapping.
- `GROUP` versus `CLAIM` stays as spec 007 wrote it.

### 6. The short form: one issuer, one application

```sql
CREATE ISSUER 'https://kc/realms/acme' AUDIENCES ('account') ROLE CLAIM 'realm_access.roles'
    [CLAIM MAP '{"tenant": "tenant"}'] [CLIENT ID 'acl-desktop' [FLOWS (…)]]
    [FROM SECRET kc [IN c]] [CLIENT FROM SECRET kc_client [IN c]];
MAP GROUP 'sales' FROM ISSUER 'https://kc/realms/acme' TO ROLE analyst;
```

A quoted URL in place of a name is the short form; any client clause on `CREATE ISSUER` (a named
one too) creates its implicit client. It creates:
- the issuer, named by its URL (or the name given, with `URL '<url>'`);
- its implicit client, **named after the issuer** (client names are global, so two short forms do
  not collide), with:
  - `AUDIENCES` as given;
  - `ROLES FROM` the role claim (default `roles`);
  - `ATTRIBUTES` from the claim map;
  - the `CLIENT ID`;
  - `FLOWS` as given, or - when it is created, never on a later ALTER - `password` when the client's
    secret carries a `CLIENT_SECRET`, `authcode, device` for a public client id, none without one;
  - `UNMAPPED AS ROLE`.

`ALTER ISSUER '<url>' SET …` edits both objects; `ALTER CLIENT` and `DROP CLIENT` refuse the implicit
client. Adding explicit clients does not remove it; it keeps catching the tokens that no more
specific client takes. `DROP ISSUER` takes its implicit client and every mapping scoped to either,
and is refused while an explicit client names the issuer.

`CREATE` refuses an existing issuer or client, `OR REPLACE` overwrites it, `IF NOT EXISTS` keeps it
(spec 013); the functions default to `replace`, as the legacy forms always upserted.

### 7. Secrets live in tresor

| type | fields | redacted |
| --- | --- | --- |
| `oidc_issuer` | `URL`, `KEYS`, `KEYS_FROM`, `ALGS` | `KEYS` |
| `oidc_client` | `AUDIENCES`, `CLIENT_ID`, `CLIENT_SECRET` | `CLIENT_SECRET` |

- **Only tresor.**
  - A `FROM SECRET s [IN c]` is read from the secret storage of the node's secrets service: a catalog
    of type `tresor`, chosen exactly as spec 082 chooses it (`PolicyStore::SecretService`). That is
    `IN c` when written, otherwise the one attached; none or several are refused with what to write.
  - A secret of the same name in the node's memory or `local_file` storage is **never** read. A
    credential cannot come from a place nobody rotates or audits.
  - Without a secrets service, an issuer or client written without `FROM SECRET` still works fully.
    That covers discovery, a public client and token-only acceptance. Only a client secret, pasted
    keys and algorithm overrides need tresor.
- **Types.** acl registers both types, so `CREATE SECRET … IN corp (TYPE oidc_client, …)` validates
  them. tresor stores any registered type (tresor spec 005). Creating one under a principal goes
  through spec 082: the `secrets` capability, retargeted to the service.
- **Attachment is by name only** (`FROM SECRET`); nothing is matched by scope. The service is
  recorded with the name, so moving between services is an explicit `ALTER`.
- **One home per parameter.**
  - `URL`, `AUDIENCES` and `CLIENT_ID` sit on the object **or** in its secret. Having both is refused
    at write.
  - `KEYS`, `KEYS_FROM`, `ALGS` and `CLIENT_SECRET` exist only in secrets.
- **Read at use, rotated in tresor.**
  - The secret is read when a token is verified or a grant runs, on a connection of the store's own -
    so the service sees the node as the caller, never a principal's session. tresor's cache is the
    freshness bound; `policy_version` is not involved.
  - A rotated `CLIENT_SECRET` or key takes effect with no policy write.
  - A write checks that the named secret exists in the service and has the right type - for the
    objects the write touches only: a service that is down must not refuse an unrelated write, and
    what a secret says of an untouched object is judged where it is used (a parameter in both
    places is refused there too, fail closed).
  - A service that goes away fails its own issuers closed - their URL is unknown, a token for them is
    refused naming them - and every other issuer keeps working.
- **Fail closed.** When a needed secret, the service or a discovery document cannot be read:
  - verification refuses with `source_error`;
  - the handshake refuses and names the issuer;
  - `discover-auth` omits that issuer or client.
- **A change through a secret is visible.** When an issuer's or client's *resolved* connection
  changes (URL, key source, algorithms; audiences, client id), the node emits one `policy` event with
  detail `connection_changed` where it next resolves it (level `decisions`).
  - The event names the object (`objects`) and carries a fingerprint (`reason`), never values.
  - A change of "whom we let in" made in tresor is then visible in acl's audit too.
  - A swapped pasted key IS a connection change (whoever holds the new key mints the issuer's tokens,
    an escalation from the `secrets` capability to whatever the issuer's clients map); a rotated
    `CLIENT_SECRET` is not. The change is noticed where the node next resolves the object - one made
    while a node was down, or reverted between two uses, shows as none on it. tresor audits its own
    writes.

### 8. What the doors and drivers see

- **`discover-auth` (Flight, spec 064) and `/.well-known/quack-auth` (spec 062):**

  ```json
  {"issuers": [{"name": "kc", "issuer": "https://kc/realms/acme", "token_endpoint": "…",
                "device_authorization_endpoint": "…",
                "clients": [{"name": "desktop", "client_id": "acl-desktop", "flows": ["authcode", "device"]}]}]}
  ```

  - Every issuer the node can resolve now is listed (`authorization_endpoint` too when the IdP names
    one); an issuer whose URL is in a secret that cannot be read is left out.
  - Its clients with a client id and a driver flow (`authcode`, `device`) are listed, with only those
    flows; a client whose secret cannot be read is left out.
  - A `client_id` is not a secret, even when it is kept in one. A `CLIENT_SECRET` is never sent.
- **The password handshake** runs as **the one** client of the node that has `password` - several are
  refused, never tried in turn (that would send customer B's users' passwords to customer A's token
  endpoint) - with its `CLIENT_SECRET` read from tresor for the call only, and only when the IdP's
  token endpoint is on `acl_jwks_locations`. The resulting token is then routed (§3) like any other.
  A driver naming its IdP (a username realm or a handshake option) is the follow-up for several.
- **Discovery** never reads a client secret, and is cached for 10 s within one policy version: its
  callers are unauthenticated, and each answer would otherwise be a read of the secrets service.
- **acl-jdbc** (hugr-lab/acl-clients) moves to the new document shape and picks a client with the
  flow it runs. It lands together with this spec.

### 9. Several customers on one node: a deployment pattern, not a concept

There is no "tenant" object; the model has roles and attributes only. Isolation is built from the
pieces above:
- each customer's IdP is an issuer, or a broker's client per customer with `REQUIRE` on the broker's
  claim;
- its clients use `UNMAPPED IGNORE`;
- its roles come only from its client's mappings;
- a `CONSTANT` attribute (`org = CONSTANT 'acme'`) is what the RLS predicates read.

Entra's multi-tenant issuer template (`…/{tid}/v2.0`) is a later spec. It extends the issuer's URL
and keeps this routing (design/018 §5).

### 10. Listings

`acl_issuers()`, `acl_clients()` and `acl_role_mappings()` list what is stored, as the other
operator listings do (catalog mode): a value kept in a secret is NULL there, beside the secret's
service and name - a listing never reads a secret, so it never shows one. Where the keys actually
came from is `acl_jwks_cache()` (the locations read, per issuer).

### 11. Schema v17

```sql
issuers(name PK, url, secret_service, secret)
clients(name PK, issuer, audiences, azp, requires, roles_from, roles_constant, unmapped,
        attributes, subject, token_type, client_id, flows, secret_service, secret, implicit BOOLEAN)
role_mappings(scope_kind, scope_name, source, external_value, role)  -- source: group | claim-value
```

- List-valued columns are JSON, as `caps` and `columns` are elsewhere. The reader also accepts the
  v16 shapes the migration copies over as they were - a csv list, a claim map object - so the step
  needs no JSON functions of the engine; a later write of the row stores the JSON form.
- **The step is strict** (`v17.sql`, `-- min_reader: 17`). Each existing issuer becomes the short
  form:
  - issuer `<url>`, named by it;
  - an implicit client of the same name with its audiences, role claim, claim map and client id
    (flows `password, authcode, device` when it had a public client id, as the door used to run it;
    `password` when it had a client secret);
  - its mappings move to the implicit client's scope (`client:<url>`): it was the issuer's only
    client, so they mean what they meant - a mapping to a role with an admin scope included, which is
    allowed from a client only;
  - an issuer without audiences (v16: no check) becomes a client that accepts no token until its
    audiences are named - fail closed, and no other write is blocked by it (a write judges what it
    touches).
- **Dropped:** `keys_json`, `algs`, `jwks_uri` and `client_secret`.
  - An issuer that relied on pasted keys or a pasted secret needs a tresor secret after migrating,
    and the step's header says so.
  - An audience `*` no longer means "any": a client names the audiences it accepts.
  - The product has no external users, so nothing more is kept.

### 12. Other surfaces

- **Admin functions.** `acl_define_issuer(name, spec_json[, mode])`, `acl_alter_issuer(name, spec)`,
  `acl_drop_issuer(name[, mode])`, `acl_define_client(name, issuer, spec_json[, mode])`,
  `acl_alter_client`, `acl_drop_client`, `acl_map_role(scope_kind, scope, source, value, role)`,
  `acl_drop_role_mapping(…)` - the JSON specs are what the SQL forms compile to, with the same checks.
- **Memory mode** keeps the same model (an immutable copy swapped per write). It reads discovery,
  documents and tresor secrets through the instance the store has held since load (spec 082), and
  reads the `acl_jwt_*` / `acl_jwks_*` settings too - before, it had none and could not read
  documents at all.
- **The function-driver source (spec 008)**: the optional slots `issuers`, `clients` and
  `role_mappings`, called with no arguments, the tables' columns in order (the old `issuer(iss)` and
  `role_mappings(issuer, values)` are gone); read once per policy version.
- **The quack `PROVIDER oidc` secret (spec 061)** reads the door's discovery document, so it follows
  §8.

## Enforcement & security

- **No credential and no key material outside tresor.** The policy catalog, the node's own secret
  storages and every listing hold none.
- **`AUDIENCES` is required on every client.** This closes confused-deputy acceptance of a token
  issued for another API.
- **One issuer per URL, exactly one client per token.** Ambiguity is refused at write where it can be
  seen and at use otherwise. Matches are never unioned.
- **Keys and algorithms are bounded.**
  - Keys are bound to their issuer.
  - The algorithm set is closed: never `none`, and HS256 only from a secret.
  - Every fetched location is on the node's own list (spec 071).
- **Roles come only from three explicit sources:** a client's or its issuer's mappings, explicit
  unmapped handling, and explicit constants. A privileged role needs an explicit mapping on the
  client itself.
- **`CONSTANT` attributes cannot be overridden by a token.**
- **Writing an issuer's or client's secret can change which tokens are accepted.**
  - That right belongs to the secrets service: tresor's admins, and acl's `secrets` capability
    (spec 082).
  - acl audits such a change as `connection_changed`.

## Testing

- **Test issuers are fixtures**: `test/idp/<name>/.well-known/openid-configuration` + `jwks.json`,
  read relative to the repository root (where the runners start) and admitted by
  `SET GLOBAL acl_jwks_locations = 'test/idp/'`; tokens are signed with the committed fixture keys
  (`test/scripts/idp_fixtures.py mint`, and `remint` moved every existing test token: `iss`
  `https://issuer.test/<x>` → `test/idp/<x>`, HS256 → RS256, a broken signature kept broken).
  `test/idp/{liar,nojwks,hsonly,noalgs}` are the misbehaving IdPs.
- **`test/sql/acl_identity.test`**: no key or credential in `CREATE ISSUER`; the short form and its
  implicit client; `CREATE` / `IF NOT EXISTS`; a privileged role refused as an unmapped value, as an
  issuer-scope mapping and as a constant, and reached through the client's own mapping; one URL per
  issuer; `AUDIENCES` required; two clients told apart by `azp` with their own roles and attributes;
  `UNMAPPED IGNORE` for an explicit client; a `CONSTANT` attribute over the token's; the subject's
  first path on the session event; overlap refused at write; a catch-all client; two `REQUIRE`
  clients both matching refused at use; `REQUIRE` `IN` / contains / `LIKE`; `ROLES CONSTANT`;
  `TOKEN TYPE`; `ALTER CLIENT` and the implicit client's refusal of it; `FROM SECRET` without a
  service; an unknown issuer; `DROP` cascades and refusals; the round trip through the catalog.
- **`test/sql/acl_jwks.test`** (discovery: two reads cached, reuse, `acl_jwks_refresh`, an unknown
  `kid`, a document of somebody else, no `jwks_uri`, HS256-only, no algorithms listed, an absent
  document) and **`acl_jwks_locations.test`** (the default refuses a local discovery, the cache row
  and the `keys` event, `..`, a location taken off the list, `''`, the operator's surface).
- **`test/sql/acl_schema_window.test`**: a v16-shaped catalog (pasted keys, a client secret, an
  issuer-keyed mapping) migrated to v17 - the short form, the dropped columns, the scoped mapping, and
  a token that then verifies by discovery through the migrated mapping.
- **`test/cpp/test_acl_identity_routing.cpp`** (src/acl_identity.cpp compiled in): `PickClient` over
  every specificity pattern of up to five candidates; `LIKE`; acceptance (array audiences, `azp`,
  every condition kind, a URL-named claim, `TOKEN TYPE`); roles (scopes, `UNMAPPED`, the privileged
  rule on every path); attributes; the stored shapes incl. v16's; the write checks (one URL,
  overlaps, `REQUIRE` judged at use, audiences, roles, constants, scopes, flows, a secret, untouched
  objects not read, both places).
- **`test/cpp/test_acl_identity_secrets.cpp`** (a fake `tresor` catalog + storage): HS256 from a
  pasted key with `ALGS`, only with `ALGS`; a rotation with no policy write and no
  `connection_changed`; one home; a missing or wrong-typed secret; `KEYS` + `KEYS_FROM`; the node's
  memory secret never read; `KEYS_FROM` under the location list and its change audited as
  `connection_changed`; an `oidc_client` with audiences, id and secret - routed, listed without it,
  redacted; a confidential implicit client's `password` default; two services and `IN`; a detached
  service failing only its issuers.
- **Every existing test that defines an issuer moved to the new form** - the suite is the regression
  test; `acl_issuer_client.test` (spec 064's client on the issuer) is superseded by
  `acl_identity.test`.
- **e2e**: `test/e2e/flight/auth.sh` - the fake IdP signs RS256 and publishes `jwks_uri`, so the door
  verifies the password grant's token by discovery over http; discovery lists the short form's client.
  The other Flight and door e2e and the harness run on the fixtures (each script starts at the
  repository root).
- **Migration** v16 → v17 by `make schema-check` (162 columns match) and the window test.

Not covered here: the live Keycloak runbook (keys by discovery is what it now does; it was not re-run
for this change) and the acl-jdbc driver against the new discovery shape (hugr-lab/acl-clients).

## Alternatives considered

- **Several issuers per URL, told apart by audience.** Rejected. Clients belong to one IdP, and a
  second issuer duplicated trust and mappings where only the token's shape differs. One issuer per
  URL also keeps routing by `iss` deterministic, as Kubernetes does.
- **Secrets from any storage (memory, `local_file`).** Rejected (owner). A credential must be
  rotatable and independent of users, and only tresor gives both.
- **Matching secrets by scope.** Rejected. A stray secret with a wide scope would silently re-key
  every issuer.
- **Unioning every matching client** (Confluent's auto pool mapping). Rejected. Each new client would
  silently widen access.
- **A tenant object.** Rejected (owner). Tenancy is a deployment pattern built from issuers, clients,
  scoped mappings and constant attributes.
- **Multi-client verification in hugr-node (BUSL).** Rejected (owner). Verification is enforcement,
  which stays open. A seam that lets another extension supply the principal would be the most
  sensitive path in the system.
- **An expression language now.** Deferred. Declarative conditions and mappings cover the known
  cases. A later `EXPRESSION '<sql over claims>'` (design/018 §2.6) adds derived attributes.

## Decided during implementation (2026-10-01)

- The implicit client is named after its issuer (not `default`): client names are global, so two
  short forms never collide, and `MAP … FROM CLIENT '<url>'` names it.
- `ALTER CLIENT` sets clauses (a list replaced whole) and `DROP FROM SECRET`; no per-item add/drop.
- `DROP ISSUER` takes the implicit client and every mapping scoped to the issuer or to it; `DROP
  CLIENT` takes its mappings - a scope owns its mappings.
- The privileged-role filter at use drops the role (the result is "no recognized roles" when nothing
  else is left); it is not an audit event of its own.
- The listings show what is stored and never read a secret.
- `PolicyStore::IssuerUrl` swallows a service failure for routing: one broken service must not refuse
  every token.

From the review (three adversarial passes over the diff):
- **A write judges what it changes.** Clients, overlapping pairs and mappings the write did not touch
  are not judged again - otherwise a migrated client without audiences, or a role made an
  administrator after it was mapped issuer-wide, blocked every identity write with no single
  statement to repair it. References (a client's issuer, a mapping's scope) are always checked.
- `CREATE OR REPLACE ISSUER` starts over like `DROP`: the implicit client and the mappings scoped to
  the issuer or to it go. `CREATE OR REPLACE CLIENT` that moves a client to another issuer drops its
  mappings (a group id means something at one IdP only).
- `principal.issuer` is the IdP's URL, not the issuer's name: the audit and a secrets service acting
  for sessions key a user by `<issuer>|<subject>`, which must change when a name is pointed at another
  IdP. `SUBJECT` is therefore identity-relevant beyond the audit; the docs say keep it a claim the IdP
  owns.
- `appid` stands in for `azp` only on an Entra v1 token (`ver` 1.0). A quoted `CLAIM MAP '<json>'`
  is parsed, never spliced into the spec. A `REQUIRE` value may be a bare `true` or number. A
  fractional `nbf` is honoured (it read as 0 before). A new `FROM SECRET` without `IN` goes to the one
  service attached, never silently to the previous secret's.
- Known, not changed: on a catalog engine without serializable transactions two concurrent identity
  writes are each validated against what they read (duckdb's `policy_version` bump conflicts one of
  them); `DROP ROLE` deletes mappings by exact role spelling (as before 095).

## Follow-ups

- acl-jdbc (hugr-lab/acl-clients) reads the new discovery shape - `clients[]` per issuer - and picks
  a client with the flow it runs.

- The Entra multi-tenant issuer template with a required `tid` restriction (design/018 §5).
- `EXPRESSION` for derived attributes and conditions.
- hugr-node onboarding: generating issuers and clients with safe defaults, and IdP provisioning.
