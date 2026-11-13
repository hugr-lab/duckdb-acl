# Backlog — the one list of open items

Rebuilt 2026-09-03 from the two backlogs that had grown apart, cleaned 2026-10-07 against specs
001–102: every blocker of the first list is done (the docs site, spec 087; audit, 069; v13; the
2026-09-03 review findings; e2e and the harness in CI; the release job with SHA256SUMS and
attestations), and what is struck below is gone. Each spec keeps its own follow-ups; this is the list
that must actually be *cleared*. When something is fixed, delete the entry — the spec keeps the
history. `design/RELEASE-PLAN.md` carries the order we work them in.

Classes: **release** — the owner's steps to the first release (after duckdb 2.0); **platform** — the
large pieces beyond the extension; **open** — worth doing, small to medium; **later** — when a user
needs it.

---

## Release (the owner's)

- Licensing: BUSL Change Date and Licence, Additional Use Grant, CLA/DCO - with counsel.
- An rc tag through the release job (`distribution.yml`: one file per platform, `SHA256SUMS.txt`,
  provenance attestations, pre-release on a `-`).
- Re-pin duckdb to the `v2.0.0` tag when it is cut (and acl-otel, tresor the same day), then the
  community-extensions submission (`packaging/community-extensions/description.yml`).

## Platform

Designed in `design/017-hugr-platform` (local), the owner's decisions in its §7. What duckdb-acl itself
owes phase 1 is done: `config.applied/target` in the load report (096), the `observe` scope (097),
the cluster profile (093) and the schema window (094). The rest lives in new repositories:

- **The node agent `hugr_node`** (`hugr-lab/hugr-node`, BUSL, a C++ duckdb extension on the same pin):
  - `hugr_node_join` under workload identity: the signed profile, applied in 009's order;
  - the extension veto (`OnBeginExtensionLoad`) and `lock_configuration`;
  - heartbeat; executing hot / drain→apply / restart (spec 066's `acl_drain`).
- **The control plane** (`hugr-lab/hugr-platform`, BUSL, Go):
  - one organisation, node pools, signed profiles, heartbeat, API (phase 1);
  - the stateless front / router and autoscale come with phase 2.
- **The extension repository** (`hugr-lab/duckdb-extension-repository`, open source):
  - duckdb's versioned layout, `/.well-known/duckdb-extension-repo.json`;
  - mirror / pull-through / publish, everything re-signed with our key;
  - public vs private extensions (a token through an http secret, tresor-issued);
  - air-gapped bundles.
- **Before the platform's release: RLS for versioned tables** (DuckLake, Iceberg; the owner, 2026-11-05). A grant says,
  per role, which versions of a time-travel table the role reads:
  - only the current one (any `AT (…)` refused);
  - strictly one snapshot (the rewrite pins `AT (VERSION => n)`, any other refused);
  - a date range (an `AT (TIMESTAMP => t)` / `AT (VERSION => v)` admitted only inside it).
  It needs the grant's syntax and the rewrite of `BaseTableRef::at_clause`, which spec 139 already walks. It also
  covers the reads that name a version some other way: a scan function's version argument, and the snapshot listings.
- **Still open with the owner**:
  - 017 §7.4: rebuild others' extensions, or mirror the official binaries;
  - §7.9: the repository's licence;
  - §7.3: where the signing key lives (HSM / Key Vault) and how it rotates;
  - the pin checks of §3.4: does `INSTALL` honour http secrets, and is it only through httpfs?

## Open

- **A management statement that returns rows, prepared over Flight, loses them** (found 2026-11-04 by spec 150 3g-1's
  re-review): `[ACL] CHECK VIRTUAL CATALOG c` (a table call) and `GRANT | REVOKE SECRET` (the service's table call)
  are commands to the door (spec 111: run at GetFlightInfo; behind a client's marker too since 150 3g-1); ad hoc the kept result is delivered at DoGet, but
  prepared, `AnswersOnlyCount` announces an empty dataset schema and JDBC reads an update - acl-clients 007.3's bug,
  fixed there for `SELECT * FROM platform.check_catalog(…)`. A fix announces the call's result schema.

- **An `acl_*` admin call over many rows writes from parallel threads** (found 2026-10-25 by spec 150 3f's review):
  `SELECT acl_function_category_add(category, list(...)) FROM … GROUP BY category` with many groups runs the writes
  on several threads and fails with `acl catalog: version bump failed: … Conflict on update!` after some groups
  committed. One aggregate row (the docs' bulk form) is not affected; `SET threads = 1` is the workaround. A fix
  serializes the catalog writes of one statement, or refuses a write outside the first row's thread.

- **A Flight door left serving aborts the process at exit** (found 2026-10-20 by spec 140's `tls.sh` fix): the
  CLI that served a door and exits without `acl_flight_stop` ends in `libc++abi: terminating`. `ServedDoors` is a
  function-static, destroyed with a serving thread still joinable in it. quack's registry has been leaked, with an
  `atexit` stop, since spec 084; the Flight door wants the same. hugr-node stops its doors on SIGTERM, so a node
  never meets it.

- **Lineage follow-ups (spec 107):**
  - the quack drain's writes (`DrainStreamUnderPrincipal`);
  - schema grants re-sending tags;
  - a Flight e2e of the `x-openlineage-*` headers;
  - the acl-otel OpenLineage transport (its own spec, e2e against Marquez).

- **A virtual function call ignores its qualifier** (spec 098 review): the rewriter resolves calls by
  the bare name, so `c.main.shout()` or `phys.main.shout()` reach the MAIN catalog's `shout`, and
  another granted catalog's functions cannot be called at all. No widening (it is the principal's
  own function), but the written name is not the one resolved.
- **Two parsers for one `params` column** (spec 098 review): the listing's `SplitParams` (depth-aware,
  quoted names, defaults) and `CatalogBackend::ParseDeclaration` (splits at every comma, so
  `DECIMAL(10, 2)` breaks; a lone word is a type) - the reference check (`TO FUNCTION f(param => col)`)
  and the listing can disagree on names. One shared parser.
- **The listings scan every attached catalog** (`information_schema.columns` for the table surfaces,
  `duckdb_functions()` for spec 098): an unreachable scanner catalog fails a principal's listing with
  the scanner's own error text.
- **The Flight door has no sqllogictest coverage beyond `acl_flight_serve.test`**: `DoorAuthJson` has
  no test of its own (the e2e covers it end to end).
- **The standalone `schema/acl_schema.sql` is rendered for the schema name `acl`**: the extension
  takes any name (`acl_use_db(db, schema)`), the file for another engine does not.
- **Spec follow-ups**:
  - 098: the result columns of a virtual table function, `acl_function_columns([name])`.
  - 099: the type gate in the file readers' column-type parameters (`read_csv(types := …)`,
    `read_json(columns := …)`) - the readers are in no role's default category.
  - 099: the mssql leg of `test/e2e/door/types.sh` needs an mssql build of the current pin.
  - 102: writes through an object-declared narrowing (it is read-only: the object stores the
    compiled expression); a `[]` narrowing is read-only by design; LATERAL in a write statement's
    subqueries is not walked; the write expression grows ~2^depth.
  - 150 4a (the owner, 2026-11-06: follow-ups): `REVOKE CATALOG` leaves the role's schema grants of that catalog
    (`role_schemas`), so a later `GRANT CATALOG … CAPS '{}'` gives the schema's reads back - the revoke should take
    them with the object grants; a `GRANT` / `DENY` to a role nobody defined is accepted (a role may come from claims
    alone), so a deny under a misspelt role restricts nobody - refuse or warn when the role is unknown.
  - Role names compare as duckdb compares identifiers (the owner, 2026-11-06: its own spec, after 4a): case-insensitive
    quoted or not, the spelling kept as created; two roles differing only by case cannot coexist (as catalogs, spec
    116); a token's role claims match the same way (`Admin` reaches role `admin`). Today roles compare exactly
    everywhere but the role mappings' duplicate check and DROP MAP (case-insensitive) and the memory store's platform
    grants - one rule for all of them, with the migration step that refuses existing case collisions.
  - An issuer whose URL comes from its `oidc_issuer` secret cannot be moved back to a URL of its own by `ALTER ISSUER`
    (found 2026-11-06 by acl-clients spec 008): `SET URL '…'` is refused as both, `DROP FROM SECRET` as no URL - the
    move the other way is one statement (`SET URL '' FROM SECRET s`), the way back has no form.
  - (spec 158 takes it: COLUMNS becomes duckdb's select list, a star a live one) A grant's mask that is a star (`COLUMNS (id, note = *)`, `COLUMNS(*)`, `t.*`) is accepted where written and every
    read of the object then fails at bind (`STAR expression is not supported here`) - fails closed, but the write
    should refuse it (spec 148's `OneExpression` and the projection probe let it through; found by spec 150 4e's
    review). Same review: `GRANT SCHEMA … COLUMNS ()` (an empty list) is accepted while a non-empty one is refused, and
    a mask `#2` reads the physical table's column by position - neither widens; decide whether to refuse them.
  - A catalog grant's list stored before spec 150 4e naming a column twice (`ssn, ssn = 'm'`) reads the column unmasked
    (`GrantUnion::Add` merges one role's duplicates as two roles'), while `"ssn" = 'm'` beside `ssn` reads masked (the
    tree path) and the screens say masked. 4e refuses such a list where written; the stored rows are not re-judged -
    decide whether the read should take the narrower reading (found by 4e's second re-review).
  - A physical column whose name holds `.` or `[` (Parquet's `odd.col`) cannot be declared in an object's own
    `COLUMNS`: a stored declared name is read as a path when it holds one, so spec 150 4f refuses `"a.b"` there (before
    4f it declared the path `a.b`, which read nothing). An object without a list, or a grant's list (where such a name
    is stored quoted), exposes it; decide whether `relation_columns` should store a quoted name.
  - (spec 158 takes it) An object's own list, found by spec 150 4f's review (both pre-existing): a star (`COLUMNS (id, x = *)`, `* AS x`,
    `x = COLUMNS('s.*')`) passes spec 148 and exposes every source column, and a grant's mask `x = *` on such an object
    reads source columns the object never declared (the grant-side star is the item above); a NULL mark on a path
    (`s.x NOT NULL`) is silently dropped (keyed by the path, the column is `s`); a name written twice
    (`"n", "n" = upper("n")`) reads `n` and `n_1` - a grant's list refuses that since 4e.
  - Spec 159 (next): a policy text binds only to its own source. An RLS / projection item whose column the source lost
    binds to a column of a relation the principal puts before the object (duckdb's implicit lateral join): `SELECT
    logs.* FROM (SELECT 'eu' AS region) s, logs` reads the rows the RLS hid; a DELETE's RLS binds to the target's alias
    row (found by spec 157's review). Qualify every policy column with an alias only the read has.
  - `acl_check_catalog`'s `grant_exposes_nothing` skips object grants under a live schema alias (spec 157: the guard
    covers them, the check reads only `relations`).
  - A broken projection's errors name physical columns past spec 155's scrub: duckdb's `Column "x" in REPLACE list not
    found` (a cast / mask over a dropped column), and `DELETE … RETURNING k` heads its column with the physical `id`.
  - Spec 155's scrub is lost when its registry evicts a text: a principal that sends 65,536 other statements before
    executing its prepared statement reads duckdb's raw error (physical column names) - found by spec 157's re-review.
- **Issue #175**: the cluster profile's `DEPENDS ON` cycle check scoped to the edges one node runs.

## Later

- **A rolled-back DROP that stands, made recoverable** (spec 154; the owner, 2026-11-06: after the release). A
  principal's DROP rolled back after any other write to the policy store stands, fail closed - only the
  `record_not_undone` event names it. The owner's model: keep the DROP's before-image durably, report it in
  `acl_check_catalog` (a finding with the statement to paste) and restore it on an operator's explicit command - a
  schema step (a table of images) and a management statement.

- **Write-time shape inference for views and table functions** (parse + PREPARE at save, read the
  result columns) so they opt into spec 065's clean refusals without a hand-typed list.
- **Nested virtual schemas are presented flat** (`parent_schema_oid` NULL); fine until a virtual
  catalog actually nests.
- **The session-identity sweep, the nice version**: `current_setting`/`getvariable` are *denied*
  (safe); answering them under the principal is the in-statement half of settings (spec 068).
- `oidc::TokenCache` (duckdb-ext-common) is process-global with a dead `owner` parameter; `catalog` pointer read
  unsynchronized (setup-time only; TSan will report it); the nine mutexes have no written order;
  `FunctionAllowed`'s denylist lookup takes the store lock per function reference.
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
- Untested drift cells (catalog-level alias, DML under drift, metadata in the dead state); the
  live-alias decision itself is written in `website/docs/security.md` §7.
- **PEG / grammar extension — closed until upstream lands a grammar-registration API** (decision
  2026-09-03, spec 067 pinned today's semantics; no question posted). Reopen when
  `ParserCache::GetMatcher` stops building only `CreateDefault()`.

## Done (for orientation; the specs keep the history)

Leak audit → 052. Quack's own functions denied → 041. `acl_require_prefix` → unnecessary
(040/041/050). Transactions through the doors → 055 (reversing the 2026-08-27 deferral). Temp tables
→ 050; quack staging → 056. Declared virtual keys → 048. TLS on Flight → 053. Session reason → 054.
Live validation → 057. Name-tight refusals, COLUMNS unquoting, `sql` never NULL,
`is_insertable_into` from caps, write-time list validation → 065. DuckLake↔PostgreSQL → PR #78
(duckdb-postgres #552; one patch of ours). Graceful shutdown / drain → 066. Foreign syntax under the
prefix → 067. Client-local settings (TimeZone/Calendar on a session) → 068. Management and native SQL over a session (scope-gated, passthrough = the operator path over a door) → pinned in test_acl_session.cpp. Migration loader → resolved by decision (the extension refuses an older stamp and points
at `v<n>.sql`; v11, v12 applied for real); schema version = 12. Distribution on every merge to main →
PR #84. The whole `test/sql` in CI + schema-check + sync.py drift → PR #85. Windows/MSVC → covered by
the distribution matrix on merge. PEG spike → design/014; ADBC driver spike → design/012. The first
list's blockers: docs → 087 (website/docs), audit → 069, v13 (one-transaction drops, the shadow table gone), review findings of
2026-09-03, e2e and harness in CI, the release job. Flight streaming and `acl_max_result_rows` → 070;
a cancelled ingest rolls back → 070; the JWKS allowlist → 071; types under the ACL → 099; fields of
structured types → 102; `duckdb_types()` → 099.
