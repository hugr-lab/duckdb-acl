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
- **Still open with the owner**:
  - 017 §7.4: rebuild others' extensions, or mirror the official binaries;
  - §7.9: the repository's licence;
  - §7.3: where the signing key lives (HSM / Key Vault) and how it rotates;
  - the pin checks of §3.4: does `INSTALL` honour http secrets, and is it only through httpfs?

## Open

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
- **Issue #175**: the cluster profile's `DEPENDS ON` cycle check scoped to the edges one node runs.

## Later

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
