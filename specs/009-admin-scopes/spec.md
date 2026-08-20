# Spec 009: ACL administration scopes (god mode by grant)

- **Status**: implemented
- **Date**: 2026-08-20
- **Author**: hugr-lab

## Summary

Phase 4, the last of the role-aware resolver (design: `design/002-role-aware-resolver`, local).
`ACL ADMIN` stops being "whoever reached the socket": administering the ACL becomes a granted
capability. A verified principal administers through `ACL ROLE "r" ADMIN …` / `ACL TOKEN '<jwt>'
ADMIN …` when its roles carry a scope — `manage` (the spec-008 management grammar, optionally
restricted to one virtual catalog) or `passthrough` (unrestricted; the actual god mode). The
anonymous `ACL ADMIN` hatch stays for the gateway itself, but with a policy source enabled it must
be opened deliberately (`acl_allow_anonymous_admin`).

## Problem

`ACL ADMIN` was an unconditional passthrough resting on one deployment invariant ("only the gateway
connects"). That is fine for the gateway's own maintenance, but it left two gaps: administration
could not be delegated (a platform admin arriving through quack/ADBC with a token had no way to
manage policy), and the escape hatch could not be closed in a hardened deployment.

## Design

- **Syntax — the client writes the marker.** The gateway only prepends the principal, so whatever
  the client wants beyond an ordinary query it must ask for itself. After the principal prefix the
  remainder is read as:

  | remainder | meaning | needs |
  | --- | --- | --- |
  | `<sql>` | rewritten inside the principal's virtual catalog | nothing (as before) |
  | `ACL <mgmt>` | an ACL management statement | `manage` or `passthrough` |
  | `ACL NATIVE <sql>` | plain SQL **outside** the virtual catalog — god mode | `passthrough` |

  `ACL ADMIN …` is the gateway's own anonymous form of the same thing: `ADMIN` *is* the native
  context, so `ACL ADMIN <sql>` stays a passthrough, while `ACL ADMIN ACL <mgmt>` (or a bare
  management statement, which the trusted gateway may still write unmarked) manages the ACL.
  Choosing a marker grants nothing by itself — the scope check follows, so an ordinary user asking
  for `ACL NATIVE` is refused.
- **Scopes live where the right belongs.** Managing *one* catalog is a **capability of the catalog
  grant** — `acl_grant_catalog(role, vcat, '{"manage": true}')` / `GRANT CATALOG c TO ROLE r CAPS
  '{"manage": true}'` — so a role manages as many catalogs as it was granted, and managing a catalog
  does not imply reading it (`{"manage": true}` without `select` is a legitimate operator grant).
  `acl.admins(role PK, scope)` carries only the **global** scopes: `manage` (the grammar over every
  catalog, plus the statements that belong to no catalog — `CREATE VIRTUAL CATALOG`, `CREATE ROLE`,
  `CREATE ISSUER`, `MAP …`) and `passthrough` (anything, including native SQL). Granted with
  `acl_grant_admin(role, scope)` / `acl_revoke_admin(role)` or `ACL ADMIN GRANT ADMIN <scope> TO ROLE
  r` / `REVOKE ADMIN FROM ROLE r`. A principal's effective scope is the strongest over its roles and
  grants; a `manage` scope never leaves the virtual catalog (`ACL NATIVE` is `passthrough` only) and
  never hands out scopes.
- **ALTER** (new statements + `acl_alter_*` functions): a partial change of an **existing** object —
  a missing target is an error, unlike the `ADD`/`GRANT` upserts, and every property not named keeps
  its value (the replacement form follows the resulting content, exactly as for `ADD`). The
  statement kind must match the object (`ALTER VIRTUAL VIEW` on a table is refused — it would drop
  the table's RLS and projection while the catalog still displayed them), `SET MAIN` takes
  `true`/`false` only, an issuer's `AUDIENCES` may not be emptied (use `'*'` to accept any audience
  deliberately), and the read-modify-write runs as **one transaction on one connection**, so
  concurrent ALTERs cannot lose an RLS predicate or a column mask. One `SET`
  per statement; several changes are several statements in one batch. Object forms carry the
  `VIRTUAL` marker so they never shadow duckdb's own `ALTER TABLE/VIEW`, which still passes through:

  ```sql
  ACL ADMIN ALTER VIRTUAL TABLE sales.orders SET COLUMNS 'id,amount' | SET RLS '...' | SET PHYS pg.public.orders;
  ACL ADMIN ALTER VIRTUAL VIEW sales.stats SET AS 'SELECT ...';
  ACL ADMIN ALTER VIRTUAL SCHEMA sales.raw SET PHYS pg.public;
  ACL ADMIN ALTER VIRTUAL TABLE FUNCTION sales.report SET MACRO '...' | SET ALIAS 'range';
  ACL ADMIN ALTER VIRTUAL SCALAR sales.shout SET MACRO '...';
  ACL ADMIN ALTER VIRTUAL CATALOG sales SET COMMENT '...';
  ACL ADMIN ALTER ROLE analyst SET CLAIMS 'tenant=acme';
  ACL ADMIN ALTER ISSUER '...' SET KEYS|AUDIENCES|ALGS|ROLE CLAIM|CLAIM MAP '...';
  ACL ADMIN ALTER GRANT CATALOG sales TO ROLE analyst SET CAPS '{"select": true}' | SET MAIN true;
  ```
- **Multi-statement batches**: one prefix covers the whole batch — one principal, one mode. A
  management batch is authorized **statement by statement at parse time**, so a refusal anywhere in
  it executes nothing (verified: the statements before an unauthorized one do not land). Execution
  itself is *not* atomic — a batch that passes authorization but fails at runtime leaves the earlier
  statements applied, exactly like a plain SQL batch. Modes cannot be mixed inside a batch: the
  marker is read once, right after the prefix, so a later `ACL NATIVE`/management statement is just
  text and fails to parse.
- **Authorization of a management batch** is read off the compiled call itself — one table maps each
  `acl_*` admin function to the constant argument holding its catalog, so the check cannot drift
  away from the grammar; a call the table does not know is refused rather than treated as unscoped.
  A `manage` scope may never hand out scopes (`acl_grant_admin` / `acl_revoke_admin` require
  `passthrough`): no self-escalation.
- **Anonymous `ACL ADMIN`**: allowed unconditionally in the in-memory dev mode (nothing to protect
  yet); with a catalog or the function-driver enabled it requires
  `acl_allow_anonymous_admin=true`. All three extension settings are read through the
  `DatabaseInstance` (the parser override has no client context), so they are registered with
  `SetScope::GLOBAL` — a session-scoped `SET` would have reported success and changed nothing.
- **Bootstrap** needs no special machinery: the admin functions are ordinary SQL functions, so the
  gateway (which owns the connection) calls `acl_grant_admin('platform', 'passthrough')` once, then
  closes the anonymous hatch. Locking yourself out is recoverable the same way — the gateway can
  re-open the flag.
- **Function-driver**: per-catalog manage arrives with the ordinary `role_catalogs` caps; the
  optional `admin_scopes(roles) → (role, scope, vcat)` slot serves the global scopes (absent slot =
  no global administration through that source).

## Enforcement & security

**The extension's own functions are not callable from a query.** Every `acl_*` function is denied by
the rewriter's function seam, so a principal cannot run `SELECT acl_grant_admin('me','passthrough')`
(which defeated the whole model — found by review, and open since spec 001 for `acl_grant_table` and
friends). They stay available in the native context, which is not rewritten; virtual names resolve
before the seam, so a granted vfunc named `acl_*` still works.

**Handing out access is privilege administration.** A catalog-scoped `manage` edits its catalogs'
content but may not run `GRANT|REVOKE CATALOG` or `ALTER GRANT` — otherwise it would grant itself
`select` on the catalog it manages, one statement away from reading everything the instance can
reach. Those need an unrestricted manage (or passthrough), as do admin-scope grants.

**No widening by accident.** `AdminRights` keeps `unrestricted_manage` as its own flag instead of an
empty-string sentinel inside the catalog set, an empty `vcat` is refused at grant time and ignored
when reading, a catalog-scoped row in `acl.admins` stays catalog-scoped, and catalogs are matched
**exactly** — the policy source compares `vcat` with SQL `=`, so a case-insensitive check would
authorize a genuinely different catalog.

**A nested `ACL …` is text, never a second entry.** Exactly one prefix is stripped (spec 001) and the
inner parse runs with the override disabled, so `ACL ROLE "r" ACL NATIVE ACL ADMIN CREATE VIRTUAL
CATALOG x` reaches duckdb's own parser as `ACL ADMIN CREATE …` and fails there — no re-entry, no
mode laundering. A `manage` scope never gets that far: the scope check refuses `ACL NATIVE` first.

**What a `manage` scope really is.** Manage over catalog C means "may expose, through C, anything the
DuckDB instance can reach" — the grammar's `phys` targets are not themselves restricted. Combined
with a read grant on C that is a real (and intended) capability, so manage scopes belong to trusted
operators; a physical allowlist per scope is possible future work.

Every path fails closed: an unverified token never reaches the scope question; a principal without a
scope is refused; a `manage` scope cannot run native SQL, cannot touch catalogs it was not granted,
cannot run non-catalog-specific statements unless unrestricted, and cannot escalate. The anonymous
hatch is off by default the moment a real policy source exists. Nothing about the rewrite path
changed — a non-`ADMIN` prefix behaves exactly as before.

## Testing

`test/sql/acl_admin_scopes.test` (125 assertions), including a regression block for every finding of
the PR review (admin functions denied in a query and working natively, no self-grant of read, a
catalog-scoped `acl.admins` row staying scoped, empty catalog names refused, exact catalog matching,
`ALTER` kind validation, `SET MAIN` validation, revocation clearing per-catalog manage, an explicit
`ACL NATIVE` never re-routed, and audiences that cannot be silently emptied): the dev-mode hatch, its closure once a catalog is
enabled and reopening by setting, bootstrap of the first admins, refusal for a principal without a
scope (while its plain queries still work), catalog-restricted `manage` granted as a catalog capability — including a role managing **two**
catalogs and losing one on revoke, and managing a catalog it cannot read — (allowed in its catalog,
refused in another, refused for non-catalog-specific statements, refused for native SQL, refused for
scope grants), unrestricted `manage`, `passthrough` doing all of it, revocation, the same door for a
JWT principal (including a per-catalog scope and an expired token refused before scope checks),
the external door (`ACL <mgmt>` allowed, catalog-restricted, refused without a scope; `ACL NATIVE`
refused for a manage scope and for a scope-less role; ordinary queries still rewritten in the
virtual catalog for a passthrough principal), multi-statement batches (a management batch applied
whole; refusal at any position executing nothing — including an escalation hidden at the end; modes
not mixable; a native batch running every statement; partial application on a runtime error), nested
`ACL` prefixes failing in duckdb's parser with nothing created (and refused earlier for a manage
scope), the `ALTER` forms (partial change, preserved neighbours, missing-target
errors, catalog-scoped `ALTER`, and duckdb's own `ALTER TABLE` still passing through), and closing
the hatch again. Existing suites gained the explicit `SET GLOBAL
acl_allow_anonymous_admin=true` wherever they use the bare hatch with a policy source — the
migration this spec implies.

## Alternatives considered

- **Keeping `ACL ADMIN` unconditional** — leaves delegation impossible and the hatch un-closable;
  the deployment invariant alone cannot express "this token may manage the sales catalog".
- **Detecting management statements by their keywords, with no marker** (the first cut of this
  spec): convenient — a client just writes `GRANT CATALOG …` — but the safety argument is "no
  management form is valid duckdb SQL", which depends on duckdb's grammar never growing `GRANT`,
  `CREATE VIRTUAL …` or similar. A silent mis-read is exactly the class of risk this project avoids,
  so the marker is explicit; the unmarked form survives only for the trusted gateway's own
  `ACL ADMIN`.
- **An `ADMIN` keyword after the principal** (`ACL TOKEN '…' ADMIN …`) — "admin" is too generic a
  word to reserve at the head of client SQL, and it conflated two different requests (manage the ACL
  vs run native SQL); `ACL` / `ACL NATIVE` names them separately.
- **Deriving the authorized catalog from the grammar rather than the compiled call** — duplicates
  knowledge across twelve parse sites; reading it off the call keeps one source of truth.
- **Keeping per-catalog manage in `acl.admins(role, scope, vcat)`** (the first cut): its primary key
  is the role, so a role could manage exactly one catalog — a second grant silently replaced the
  first. Manage is a right *over a catalog*, and the catalog grant already has the right shape
  (`PRIMARY KEY (role, vcat)`), so the two places collapsed into one.

## Follow-ups

- The full `DROP` surface (catalog, role, issuer, schema alias, function, grant) — a separate spec;
  `DROP RELATION` from spec 008 is the only one today.
- Audit trail of administration statements (who changed what) — a gateway or catalog-side concern.
- `acl.admins` in the airport-go / function-driver contract docs when those land.
