# Backlog — the one list of open items

Rebuilt 2026-09-03 from the two backlogs that had grown apart (this file, compiled 2026-08-30 for the
single-node phase, and the local `design/BACKLOG.md`), cross-checked against the status of every spec
001–067. Each spec keeps its own follow-ups; this is the list that must actually be *cleared*, in one
place. When something is fixed, delete the entry — the spec keeps the history. The local
`design/BACKLOG.md` carries the longer reasoning behind the open items; `design/RELEASE-PLAN.md`
carries the order we work them in.

Classes: **blocker** — before the first release (after duckdb 2.0); **pre-release** — worth doing
before if cheap; **later** — development, after the release.

---

## Blockers

1. **Documentation.** `docs/` is 476 lines and covers none of: the `ACL ADMIN` grammar (all forms,
   COLUMNS/RLS/CAPS, quoting rules of spec 065, references of spec 022) and the `acl_*` equivalents;
   starting and stopping the doors (`acl_flight_serve/stop`, `acl_quack_serve/stop`, TLS forms,
   preconditions, session knobs, `acl_sessions`/`acl_session_kill`, drain of spec 066); auth
   (issuers/JWKS, client_id, discovery, the password handshake); the policy catalog (`acl_use_db`,
   schema versions and migrations); deployment invariants; the accepted risks of spec 065; the
   error-prefix contract; and one paragraph deciding **what a live alias means when the source
   grows** — a catalog-wide `ssn = NULL` does not cover an `ssn_backup` added later, and a schema
   alias shows a whole new table. Memory mode leaves the quickstart (it cannot serve, list or read a
   JWKS); the eight legacy wrappers are labelled legacy.
2. **Spec 043 — concurrency and isolation across roles** is still a draft. The release's headline
   (two doors, many clients) has never been tested with more than one client: a session's principal
   never leaking into another connection's statement, one role's RLS slice staying its own while
   another writes next to it, a bulk ingest under one role not showing another role rows it may not,
   the per-statement (not per-stream) atomicity of a drained stream. Proven under load, under
   sanitizers, against real sources.
3. **Audit** (decided 2026-09-03: in the release). An event per engine decision — principal
   (subject/roles), statement class, objects and capability, verdict with reason, a correlation id
   supplied by the caller, **never data**; where it is written, how it is read, how it cannot become
   a DoS vector. The cluster repo depends on this existing; it cannot reconstruct it. After 043.
4. **Management and native SQL through the doors.** What `ACL <mgmt>`, `ACL ADMIN …` and
   `ACL NATIVE …` do when they arrive through a door rather than on the node's own connection; is a
   passthrough principal driving `acl_quack_stop`/`acl_flight_serve`/`acl_drain` over a door the
   operator path or a surface to narrow (spec 066 made `acl_drain` reachable that way deliberately);
   do refusals leak; are policy writes scoped correctly over a served session. Tests, fail-closed.
5. **Client-local settings.** The statement gate refuses `SET` outright, so a principal cannot set
   its time zone — and a `TIMESTAMPTZ` rendered in the server's zone is a *wrong answer*. A small
   allowlist of session-local, render-only settings, enforced in the gate and in Flight's
   `SetSessionOptions`.
6. **One migration (v13)**: `CatalogDropRelation` reads before it writes and then writes twice,
   outside the one-transaction shape the other writers use — a half-applied drop leaves access the
   admin believes is gone; `role_object_caps` gains the `kind` column that turns the same-name
   guard into a key; the write-only `schema_aliases` shadow table goes (written in four places, read
   nowhere; "kept for a rollback" — there was no release to roll back to). Plus the check the
   migration README promises and nothing runs: a catalog migrated from n−1 and one created at n have
   the same columns in the same order.
7. **Review findings of 2026-09-03** (each small, each real):
   - `PolicyStore::SessionOpen`'s JWT branch does not merge role-default claims (memory
     `role_claims` and `CatalogLoadRoleClaims`), unlike `VerifyPrincipal`/`VerifyJwtPrincipal`: the
     same token yields different claims through a door than through a gateway prefix, and an RLS
     predicate on a role-default claim bakes NULL — zero rows through both doors, full rows through
     the gateway. Route `SessionOpen` through the verifier.
   - `acl_jwt_clock_skew` is registered without a scope (session), read through the instance:
     `SET` reports success and changes nothing. `acl_max_sessions` falls back to 10000 against a
     registered default of 1000.
   - Two doors, three duplicated helpers that already disagree: `JsonEscape` (`acl_sessions()`)
     emits control bytes raw — invalid JSON from a claim value — where `JsonQuote` escapes them;
     `ReadPem` exists twice; the serve preconditions are inline in `acl_quack_serve`, which — unlike
     Flight — **binds a non-localhost address in the clear without refusing**. One
     `acl_door_common` for all three.
   - `MintId`/`MintCookieId` (the Flight session cookie is a bearer credential) mint without the
     guard `MintHandle` carries against MinGW's deterministic `std::random_device` — a supported
     target. One shared CSPRNG helper.
   - The door registries are process-wide with no instance identity: `acl_flight_stop` from
     instance B closes B's sessions while A's door dies; `AclQuackServerCount()` is process-wide, so
     A never clears `door_open`. A `weak_ptr<DatabaseInstance>` on the door, per-instance counts, a
     two-instance test.
8. **Release mechanics.** No publication exists: `distribution.yml` builds nine platforms and
   publishes nothing. A release job over its artifacts — `SHA256SUMS.txt`, GitHub release
   (pre-release on a `-` in the tag), build-provenance attestation. Two `description.yml` with
   different versions and a memory-mode `hello_world` become one; `README.md` teaches catalog mode;
   the stale `ACL_FLIGHT=1` references go (the flags are default-on now). The duckdb pin: track
   `main` until the 2.0 tag, then pin to it; first release after 2.0, community-extensions alongside.

## Pre-release, if cheap

- **The schema renders only for the schema name `acl`** (`scripts/gen_schema.py` hard-substitutes
  it); an operator with another name edits a generated file its header forbids editing.
- **File the duckdb-postgres upstream issue** (draft at
  `design/notes/duckdb-postgres-upstream-issue-draft.md`) and plan the retirement of
  `patches/postgres_scanner/0001-restore-postgres-execute.patch` once upstream restores
  `postgres_execute`; ducklake will hit the same on its next duckdb bump.
- **The listing marks a broken object** instead of narrowing it: while a declared-list object is dead
  (a source column vanished), `duckdb_columns()` quietly describes a narrower object no query
  returns. The cheap two-thirds of spec 039.
- **Spec 039 — catalog maintenance** (`acl_check_catalog([vcat])`, `acl_repair_relation(…)`): the
  named compensating control for spec 065's accepted risk. **The spec file does not exist yet.**
- **A principal's functions surface** (`duckdb_functions()` / `information_schema.routines`): a
  virtual table function is callable but appears in no listing, so an agent browsing the catalog
  cannot learn it exists or its signature; params and result columns are already stored.
- **Error-prefix contract**: `acl:`, `acl admin:`, `acl catalog:`, `acl_rewrite:`, `acl_flight_serve:`
  … three conventions, undocumented, and `acl_rewrite:` fires from `SessionOpen` where nothing is
  rewritten; IO/socket failures throw `BinderException`. Fix and write down before clients match on it.
- **The Flight door has no sqllogictest coverage** (only e2e, skipped on PRs): serve-argument
  validation is reachable from SQL; `DoorAuthJson` has no test at all.
- **`test/harness/run.sh` exits 1** (intentional denials under `set -e`) — the first five minutes.
- Refactors before release (design/RELEASE-PLAN.md phase 4): the `ACL ADMIN` grammar out of
  `acl_parser_override.cpp` (`AuthorizeMgmt` is invisible there); `acl_policy_catalog.cpp` split
  into read path / admin writers / listings / validators; the quack door lifecycle next to its
  server; `door_open` atomic; `acl_schema_sql.hpp` out of the public headers.

## Later

- **The Flight door materializes every result** before streaming and holds the session's `exec`
  lock while doing it; a lazy `RecordBatchReader` and an `acl_max_result_rows` mirroring ingest.
- **Write-time shape inference for views and table functions** (parse + PREPARE at save, read the
  result columns) so they opt into spec 065's clean refusals without a hand-typed list.
- **Nested virtual schemas are presented flat** (`parent_schema_oid` NULL); fine until a virtual
  catalog actually nests.
- **JWKS**: an allowlist for `KEYS FROM` locations and a listing of what the cache holds.
- **Mid-ingest failure semantics**: if the process dies mid-ingest, the client must be told to
  restart rather than silently receive a partial load.
- **The session-identity sweep, the nice version**: `current_setting`/`getvariable` are *denied*
  (safe); answering them under the principal is the in-statement half of settings, with item 5.
- `oidc::TokenCache` is process-global with a dead `owner` parameter; `catalog` pointer read
  unsynchronized (setup-time only; TSan will report it); the nine mutexes have no written order;
  `FunctionAllowed`'s denylist lookup takes the store lock per function reference.
- `acl_refresh_schema` does not re-probe grant projections; a view over a dropped object is not
  detected; `acl_refresh_schema_objects` and an object's own list — unverified. Spec 039's family.
- Temp objects in the columns surfaces and `SHOW ALL TABLES` (spec 050 exclusions); `GetXdbcTypeInfo`
  (spec 046) — when a tool needs them. Physical-PK import at `CREATE VIRTUAL TABLE` and
  `duckdb_constraints()` as a principal surface (spec 048).
- mTLS (spec 053); savepoints (spec 055); pin-on-demand pooling (spec 050 alternative).
- Spec 022's left-open list: importing physical FKs, cross-catalog references, m2m through a junction.
- COPY and locations as catalog objects (design/007 §4); sqlite/mysql as policy catalogs; driver
  enumeration slots; recording view-over-view dependencies (spec 018).
- Optimising the metadata surfaces (spec 035): a connect that attaches a catalog pays ~90 ms, all of
  it planning `information_schema` SQL; cache at resolve first, then the generated SQL; materialised
  cache tables belong to the BUSL version. Both doors reach the surfaces through one path (spec 046),
  so it stays one item.
- Cleanup after spec 038 (spec 036's ordering rule is vestigial); NULL oids in the surfaces (small
  if a client keys on them).
- MySQL integration is skipped (patches do not apply at the pin); `container_name:` fixed in compose;
  255 characters for SQL Server key columns is a guess.
- Untested drift cells (catalog-level alias, DML under drift, metadata in the dead state) — after the
  live-alias decision in item 1.
- **PEG / grammar extension — closed until upstream lands a grammar-registration API** (decision
  2026-09-03, spec 067 pinned today's semantics; no question posted). Reopen when
  `ParserCache::GetMatcher` stops building only `CreateDefault()`.
- Licensing (BUSL Change Date and Licence, Additional Use Grant, CLA/DCO) — the owner's, with counsel.

## Done (for orientation; the specs keep the history)

Leak audit → 052. Quack's own functions denied → 041. `acl_require_prefix` → unnecessary
(040/041/050). Transactions through the doors → 055 (reversing the 2026-08-27 deferral). Temp tables
→ 050; quack staging → 056. Declared virtual keys → 048. TLS on Flight → 053. Session reason → 054.
Live validation → 057. Name-tight refusals, COLUMNS unquoting, `sql` never NULL,
`is_insertable_into` from caps, write-time list validation → 065. DuckLake↔PostgreSQL → PR #78
(duckdb-postgres #552; one patch of ours). Graceful shutdown / drain → 066. Foreign syntax under the
prefix → 067. Migration loader → resolved by decision (the extension refuses an older stamp and points
at `v<n>.sql`; v11, v12 applied for real); schema version = 12. Distribution on every merge to main →
PR #84. The whole `test/sql` in CI + schema-check + sync.py drift → PR #85. Windows/MSVC → covered by
the distribution matrix on merge. PEG spike → design/014; ADBC driver spike → design/012.
