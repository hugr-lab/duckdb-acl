# Spec 071: where a node reads its keys from - the KEYS FROM allowlist, and what the cache holds

- **Status**: draft
- **Date**: 2026-09-08
- **Author**: hugr-lab

## Summary

`KEYS FROM '<location>'` (spec 023) makes the **node** read a document its administrator named,
through duckdb's filesystem: a file, an https URL, anything httpfs or an attached filesystem can
reach. Spec 023 wrote the consequence down and left it open: "defining an issuer now makes the
server read a location its administrator chose … an allowlist of permitted prefixes is the way to
close it if a deployment cares". This spec closes it. A GLOBAL setting, **`acl_jwks_locations`**
(default `https://`), lists the prefixes a key document's location may start with; a location
outside the list is refused where it is written (`CREATE|ALTER ISSUER … KEYS FROM`,
`acl_define_issuer`, `acl_alter_issuer`) and again where it would be read (a token of that issuer is
rejected, the refusal audited as a `keys` event) - the operator's setting binds the node whatever
the policy catalog says, and a catalog shared by several nodes cannot make one of them read what it
was not told to. Beside it, the cache spec 023 left invisible gets its listing:
**`acl_jwks_cache()`** answers, per issuer that reads its keys, the location, whether it is allowed
now, when the document was last read, its age, the last attempt, the last error, and which key ids
it holds; **`acl_jwks_refresh([issuer])`** drops the cached document(s) so the next token re-reads.

## Problem

1. **Reach.** An administrator with `manage` (catalog-scoped or not) can point an issuer's keys at
   `/etc/…`, at `http://169.254.169.254/…`, at an internal host: the node opens it as itself. No
   content is disclosed - the document is parsed as keys and nothing else - but reachability shows
   through the error text, and the node's network position and credentials are lent to whoever
   writes issuers. Spec 023 called it "a mild probe" and named the allowlist as the close.
2. **Trust.** Whoever can write an issuer's key location decides whose tokens verify. That is true
   of pasted keys too (`manage` is trusted that far, spec 009), but a location is quieter than a
   paste: `KEYS FROM 'https://evil/…'` reads as configuration, and it can be repointed by a node's
   own filesystem (a file under a path the attacker writes). An operator-owned list of origins makes
   the trusted sources of keys a fact about the deployment, not about the policy rows.
3. **Blindness.** The cache (spec 023) has no listing: an operator cannot see when an issuer's keys
   were last read, whether the last read failed, or which `kid`s the node currently trusts - the
   questions a rotation incident asks first.

## Design

### `acl_jwks_locations` - the prefixes a location may start with

- GLOBAL, VARCHAR, default **`https://`**: a comma-separated list of prefixes; a location is allowed
  when it starts with one of them, compared as written (write the scheme in lower case; a path
  prefix ends with `/` to mean the directory and not every name that begins with it).
  `'https://, /etc/acl/jwks/'` admits any https URL and the files under that directory;
  `'https://login.microsoftonline.com/, https://kc.corp/realms/'` pins the origins; `''` admits no
  location at all - keys are pasted or nothing.
- The default is the safe one: keys over cleartext http are keys anyone on the path can replace,
  and a file is a location the deployment must vouch for by name. A deployment that reads a local
  JWKS lists its directory once; the tests and runbooks of this repository do.
- Like every `acl_*` GLOBAL setting it is the operator's: a principal's `SET` is refused (spec 068's
  gate), a session-scoped `SET` would change nothing.

### Refused where it is written, and again where it would be read

- **Write** (`CatalogDefineIssuer`, which both the define and the alter paths end in): a `jwks_uri`
  outside the list is refused - `acl admin: KEYS FROM "<location>" is outside acl_jwks_locations
  (<list>) - list its prefix there first, or paste the keys` - and nothing is written. The
  management batch's refusal is audited as every management refusal is.
- **Read** (`ResolveIssuerKeys`, before any document is opened): the location is judged again
  against the setting *as it is now on this node*. Outside it, the token is rejected -
  `acl_rewrite: token rejected: the keys of issuer "<iss>" are at "<location>", which is outside
  acl_jwks_locations (<list>) - list its prefix there, or paste the keys` (reason `policy_error`:
  the policy names a source this node does not read) - and a `keys` event `refresh_failed`
  carries the reason. The cached document, if any, is **not** used: an operator who took a location
  off the list meant now, not after `acl_jwks_max_stale`. Why both: the setting can change after
  the write, and a policy catalog is shared by every node of a fleet while the setting is each
  node's own - the write-time check is the early, clear refusal, the read-time check is the one
  that binds.

### `acl_jwks_cache()` - what the node trusts right now

A table function, the operator's (an `acl_*` name: denied to a principal), one row per issuer whose
keys are read from a location (from the policy catalog), joined with the node's cache:

| column | meaning |
| --- | --- |
| `issuer` | the issuer |
| `location` | its `KEYS FROM` |
| `allowed` | whether the location passes `acl_jwks_locations` on this node, now |
| `fetched_at` | when the document was last read successfully (NULL: never on this node) |
| `age_seconds` | seconds since then (NULL: never) |
| `last_tried_at` | the last attempt, successful or not (NULL: none) |
| `error` | the last attempt's error, NULL when it succeeded |
| `keys` | keys in the cached document (a PEM counts one; NULL: nothing cached) |
| `kids` | the `kid`s of those keys, in the document's order (a key without one is not listed) |

Never the keys themselves - a `kid` is the public name of a key, the material stays where spec 023
put it. Memory mode has no catalog and no cache: the function answers no rows.

### `acl_jwks_refresh([issuer])` -> BIGINT

Drops the cached document of one issuer, or of every issuer, and answers how many were dropped; the
next token of that issuer reads the location again (subject to the allowlist), whatever
`acl_jwks_refresh_interval` says. The operator's, like the listing. It is the rotation-incident
verb: "stop trusting what you read before" without repointing the issuer.

## Enforcement & security

- **Fail closed, on the node's terms.** The read-time check is the enforcement; the write-time
  check is a courtesy. A location outside the list is never opened, and a cached document from a
  location no longer on the list is never used. The default admits https only.
- **The setting is not the policy's to change.** GLOBAL, read through the instance, refused to a
  principal by spec 068's `SET` gate like every `acl_*` setting; a management statement cannot
  write it (settings are not management SQL). A catalog-scoped `manage` therefore cannot widen
  where the node reads from - it can only name locations inside what the operator allowed.
- **Nothing new is disclosed.** The refusal names the location (the administrator wrote it) and
  the list (the operator wrote it) - to the administrator or the operator. A principal never sees
  either: a token rejected for this reason is `authentication failed` through a door (spec 069's
  rule for `SessionOpen`), and the reason is in the audit.
- **The listing is the operator's** and carries no key material; `acl_issuers()` still has no key
  column (spec 023's test), and neither has this.
- Prefix matching is textual on purpose: no URL normalisation means no normalisation bugs. A
  prefix that is too short (`https://` alone admits every https host) is the operator's choice,
  documented as such.

## Testing

`test/sql/acl_jwks_locations.test` (a JWKS file under the test directory, the HS256 token of
`test/sql/acl_jwks.test`):

- with the default, `CREATE ISSUER … KEYS FROM '<file>'` is refused naming the list; so is an
  `http://` location; `acl_alter_issuer(…, 'jwks_uri', '/etc/x')` too;
- `SET GLOBAL acl_jwks_locations = 'https://, <dir>/'`: the issuer is written, the token verifies,
  `acl_jwks_cache()` shows the issuer with `allowed = true`, one key, no kid, no error, an age;
- the list narrowed to `https://`: the same token is rejected naming the location and the list,
  `acl_jwks_cache()` says `allowed = false`, and a `keys` event `refresh_failed` carries the reason
  (the audit at `denied`); widened back, the token verifies from the cache;
- `acl_jwks_refresh()` drops the entry (returns 1, the cache row loses its `fetched_at`), the next
  token re-reads (a rotated document is seen at once with `acl_jwks_refresh_interval` at its
  default);
- `''` admits nothing: a write is refused, a read is refused;
- a principal is denied `acl_jwks_cache()`, `acl_jwks_refresh()` and `SET acl_jwks_locations`.

The existing fixtures that read a JWKS from a file (`acl_jwks.test`, `acl_audit.test`, the Flight
e2e's bootstrap, the live runbook's Keycloak issuer) list their locations, which is the point.

## Alternatives considered

- **Require `passthrough` for `KEYS FROM`** (spec 023's other option): moves the decision to the
  wrong owner - the location's *legitimacy* is the deployment's fact, not a scope of the policy
  writer; and it would not bind a shared catalog to one node's environment.
- **A default of "unrestricted"** for compatibility: there is no deployment to be compatible with
  before the first release, and the safe default is the one nobody has to remember to set.
- **Normalised URL matching** (host allowlists, wildcards): more to get wrong; a prefix list
  expresses every deployment we know of.
- **A forced re-read in `acl_jwks_refresh`**: a token's verification is the read; dropping the
  cache makes the next one read, which is the same effect without a second code path.

## Follow-ups

- A `keys` audit event for `acl_jwks_refresh` itself (an operator dropped what the node trusted):
  today it is the next read's `refreshed` event; spec 069's `admin` kind could carry the verb.
