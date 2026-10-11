# Spec 120: maintenance - the missing forms, effective rights, exposures, view-as, export, created_by

- **Status**: accepted, **120.1, 120.2, 120.3, 120.5 implemented** (see *As built*; 120.4 after the release) (by the owner 2026-10-11: the order 120.1 → 120.5; export after the release; view-as for
  policy / passthrough first; created_by as written)
- **Date**: 2026-10-11
- **Author**: Claude (design/079 with the owner)
- **Follows**: specs 009, 011/012 (grants, caps), 016, 022 (references), 039 (the check), 085 (resource groups),
  095 (mappings), 116, 117 (platform), 118.3 (sources), 119. Phase 1 of design/079 (the console's maintenance tabs).

## Summary

What a console needs to maintain a policy it did not write: the management forms still missing, a role's
**effective rights** on an object and which grant decides them, a physical object's **exposures**, the tree **as a
role sees it** (metadata only), the policy as **management SQL**, and **who created** an object - with the check
finding 118.3 deferred. In stages, a PR each; nothing changes what already works.

## Stages (proposed)

1. **120.1 - the missing forms** (mostly grammar over existing writers).
2. **120.2 - effective rights and exposures** (table functions over what the resolver already computes).
3. **120.3 - view-as** (a session mode).
4. ~~**120.4 - export**~~ - after the release (owner, 2026-10-11).
5. **120.5 - created_by** (schema v22) and the `source_not_granted` finding.

## Design

### 1. The missing forms (120.1)
| Form | Over |
| --- | --- |
| `ALTER FUNCTION CATEGORY c SET COMMENT '…'` | new `acl_comment_function_category(c, comment)` - the category must exist |
| `ALTER RESOURCE GROUP g SET (limits …)` | `acl_alter_resource_group(g, 'limits', json)` - a new field; the comment kept |
| `ALTER ROLE r SET COMMENT '…'` | new `acl_comment_role(role, comment)` (the `roles.comment` column exists, written '' today) |
| `REVOKE TABLE | VIEW | OBJECT c.n FROM ROLE r` | new `acl_revoke_object(role, vcat, vname)` - deletes `role_object_caps` + its `grant_columns`, like `CatalogRevoke` |
| `ALTER VIRTUAL REFERENCE c.n SET COMMENT | CARDINALITY | OPTIONAL …` + `COMMENT ON VIRTUAL REFERENCE` | read-merge-write over `CatalogAddReference` |
Each with its `platform.*` function and right (spec 117), docs, tests.

### 2. Effective rights and exposures (120.2)
- `platform.effective_rights(role, catalog[, object])` (policy: any role; a catalog admin: its catalogs) - per object:
  caps, the **deciding level** (`object` / `schema <path>` / `catalog`, the first non-null term of the resolver's own
  `CapsExpr` coalesce), MAIN, RLS (the AND of the levels), the projection and masks (`GrantPolicy::Narrow`). Answered
  by `ResolveTable(Principal{roles: {r}})` and one sibling expression for the deciding level - the resolver's answer,
  never a second implementation.
- `platform.exposures([source[, schema[, object]]])` (policy, cluster, passthrough; a catalog admin over its granted
  sources) - per physical object / schema: the virtual objects reading it (relation phys, schema alias / expansion,
  function target, a view / macro body naming it - the DETACH check's own queries, lifted), and per role holding a
  grant on that virtual object its deciding level and caps. Read at query time; no source probe.

### 3. View-as (120.3) - a session mode (owner, 2026-10-10: a second connection, minimal first)
- On a session of its own, an admin runs `SET SESSION VIEW AS ROLE '<r>'` (`RESET SESSION VIEW AS` leaves it). From
  then on the session's statements are rewritten **as role r**: every metadata surface, Flight catalog RPC and
  platform listing answers what r sees; **any data read, write or DDL is refused** (`acl: a view-as session reads
  metadata only`). The mode lives on the session record (not the `Principal` contract - no contract bump).
- Who: `policy` / `passthrough` for any role. A catalog admin: not in this first version (r's tree spans catalogs
  the admin does not administer).
- The console opens a second connection and sets it once; the tree is built by the same code.

### 4. Export (120.4) - after the release
`platform.export_script([catalog])` - rows `(seq, kind, name, statement)` in dependency order: catalogs, schemas,
relations (columns, types, keys, RLS, comments), functions, references, roles and claims, grants (catalog / schema /
object, columns, masks), function categories and grants, resource groups, issuers / clients / mappings (secret
NAMES only, never a value), admin bundles, platform and source grants; with a catalog - only what belongs to it.
Each statement is the management grammar that recreates the row (`NamePath::ToGrammar` for names), and re-running
the script on an empty policy reproduces it (tested by round trip). Not the cluster profile (its own listing).

### 5. created_by and `source_not_granted` (120.5)
- Schema v22: `created_by VARCHAR` on relations, schemas, functions, references - the author's subject
  (`<iss>|<sub>`, or the role for a gateway `ACL ROLE`; NULL for the operator and the anonymous gateway). The parser
  override appends the author to the compiled call (as AuthorizeBodies already knows it); the writers store it.
  Existing rows stay NULL.
- `acl_check_catalog` adds `source_not_granted`: an object a catalog admin created (created_by set, the author not
  policy / passthrough when it wrote it) whose physical source is outside the sources granted to the author's
  roles NOW - with the `GRANT SOURCE …` to run. Showing only; nothing is taken back.

## Not here
- A per-node metadata cache (after the release); the DBeaver plugin itself (acl-clients 007).
- Follow-up (owner, 2026-10-11): the `admin` audit event names the object a management call defines (`<vcat>.<vname>`,
  its kind, its source - as cluster items carry `<kind>:<name>`), so authorship reaches acl_otel whatever the
  statement's note did (`created_by` is NULL when a client parses between a batch's parse and its execution).

## Enforcement & security
- Effective rights, exposures and view-as answer metadata only; view-as refuses every data path; its listings are
  the role's - an admin sees no more than the role could, and only a policy-level admin may take another role's view.
- Export never carries a secret value; it is policy-level (a catalog admin: its catalog only).
- created_by is a fact for the check, never a right (no ownership - owner, design/079 App. A).

## Testing
Per stage: the grammar forms and their platform calls (rights, refusals); effective rights equal to what a read
as the role gets (masks, RLS, deciding level per level); exposures for each reader kind; view-as listings equal to
the role's own, every data path refused; export round trip; created_by written and the finding raised / not raised.

## Alternatives considered
- view-as as navigation functions (`view_as(role, path)`) - a second tree beside the real one (owner chose the
  session mode).
- Ownership instead of created_by - rejected (design/079: no owner, no self-grant path).

## As built

### 120.1 (2026-10-11)
- Grammar + writers: `ALTER ROLE r SET COMMENT` → `acl_comment_role` (`CatalogCommentRole`; `CatalogDefineRole` keeps a
  role's comment on a re-define); `REVOKE TABLE|VIEW|OBJECT c.n FROM ROLE r` → `acl_revoke_object` (`role_object_caps`
  + `grant_columns` of that object; HANDS_OUT); `ALTER VIRTUAL REFERENCE c.n SET COMMENT|CARDINALITY|OPTIONAL` and
  `COMMENT ON VIRTUAL REFERENCE` → `acl_alter_reference` (CATALOG; validated as the create does); `ALTER RESOURCE GROUP
  g SET (limits) | SET COMMENT` → `acl_alter_resource_group` fields `limits` (only the named ones) / `comment`
  (`ResourceLimitsJson` shared with CREATE); `ALTER FUNCTION CATEGORY c SET COMMENT` → `acl_comment_function_category`.
  Platform functions `comment_role`, `revoke_object`, `alter_reference`.
- **No ALTER MAP** (decided while building): a mapping is only its key, so the change is `DROP MAP` + `MAP` - two
  existing statements; one call would have needed its own privileged-target check (spec 095).
- Found: `CatalogBackend::WriteWithReads` committed without the `written` policy event `Write` emits - fixed (a
  resource group's create, a role's re-define … were not audited as writes).
- Tests: `test/sql/acl_maintenance_forms.test`; `acl_node_group.test`'s unknown-property message.
- Review (three passes): `ALTER FUNCTION CATEGORY … SET COMMENT` compiled to the create and made a missing category -
  now `acl_comment_function_category`, which requires it; `ALTER RESOURCE GROUP … SET (…)` judged only the named limits -
  the merged window_start / window_max is now judged as CREATE does, read and written in one transaction; every new
  writer checks its target inside its write transaction (a concurrent DROP refuses, never a silent no-op); `WriteWithReads`
  refuses the function-driver source by name, as `Write` does. Low, left: one limit cannot be unset back to the node's
  through ALTER (re-create the group); a no-op `DROP … IF EXISTS` bumps the version and is now a `written` event.


### 120.2 (2026-10-11)
- `src/acl_platform_rights.cpp`: `acl_effective_rights(role, vcat[, vname])` and `acl_exposures(source[, schema[,
  object]])`, table functions; platform `effective_rights` (CATALOG, its catalog argument judged - read as a KEY,
  `CatalogKey`, as the authorizer reads it) and `exposures` (POLICY - the design's "cluster, passthrough; a catalog
  admin over its granted sources" is left for later: passthrough holds it already, the rest needs a narrowing by
  granted sources). `PlatformReadFunctionSql` checks a read function's declared arities (it allowed at most one).
- The deciding level: `CatalogBackend::GrantDecision` - the resolver's own CapsExpr / SchemaCapsExpr, grants CTE
  and object-grant join by key, plus the row SchemaCapsExpr picks (to name it, `(inherited)` when materialized);
  `main` = the flag AND `main_ok.unique_main`. RLS and `writable` are `ResolveTable`'s for a principal holding only
  that role (a view's: its grants' predicates, which ApplyGrantPolicy folds into its query); `columns` the role's own
  `columns` listing (`MetadataListingSql`, one per call, scoped to the catalog); `masks` the masks its grants state
  on those columns; `refused` the resolver's refusal. Objects under a live alias that the role holds a grant on are
  rows of their own.
- Exposures: a relation's `phys`, a live alias' `phys_path` (asked inside it, decided on the alias path + the rest),
  a function's target, and the tables named by a view's SQL, a function's template, a computed column
  (`relation_columns.expr`), a relation's RLS and a grant's RLS / mask expressions (`kind = 'grant'`, that role only) -
  PARSED, never bound (a scanner's bind would reach the source): FROM, joins, subqueries, a PIVOT's `IN (SELECT …)`;
  `t` / `x.t` completed by the node's default database / a database's default schema. A body that does not parse
  falls back to the DETACH check's text match. Not followed: what a physical view / macro reads in turn; a
  passthrough role reaches every source outside the policy. An empty schema is any schema (an alias then is not
  reported - whether its schema holds the object is the source's).
- Review (three passes) found and fixed: the catalog argument read as a raw part named another catalog than the one
  the authorizer judged (`'"a.b"'` vs `"""a.b"""` - a catalog admin read the other's rights); a first `Decide` that
  re-read the grant tables diverged from the resolver (an empty longer schema prefix, MAIN with two MAIN catalogs,
  the columns, a view's RLS, object grants under an alias); exposures missed computed columns, RLS and grant masks,
  two-part physical names, unqualified body names, and shifted a NULL middle argument; a view's caps differed
  between the two functions.
- Measured (`test/bench/rights_scale.py`: 20 sources x 150 tables as expansions = 3000 declared relations, 500
  views with a join and a subquery, 10 roles x 50 object grants with a mask, laptop): the first build asked the
  deciding level one query per row - a whole source's exposures 5.6 s (2000 rows), a catalog's effective rights
  10.0 s (3500 rows). `GrantDecisions(role, vcat, names)` asks it once per (catalog, role) for every name - the same
  expressions over a VALUES list: one table's exposures 0.21 s, a whole source's 0.23 s, one object's effective
  rights 0.19 s, the whole catalog's 0.27 s. What is left is a floor, not per row: exposures parses every stored body
  (~1000 here) per call, effective_rights reads the role's columns listing (spec 119's cost: one table's columns
  0.22 s at this scale). No cache: a parse cache would need the policy version for its invalidation, for 0.2 s on
  an operator's call; the listing's own cost is the per-node metadata cache after the release.
- Tests: `test/sql/platform_effective_rights.test`; bench `test/bench/rights_scale.py`.

### 120.3 (2026-10-11)
- Grammar `SET SESSION VIEW AS ROLE '<r>'` / `RESET SESSION VIEW AS` (and `platform.view_as(role)`, POLICY) compile to
  `acl_session_view_as(role)` (`''` leaves). The call takes NO session argument: it acts on the session its statement
  runs under (the AclConnection the override publishes, spec 078) - a session id argument would let a policy holder
  put somebody else's session into a stronger role's view. Under a per-statement prefix there is none, refused.
- The role is kept on the session record (`Session::view_as`), not on the Principal contract. The override reads it
  (`ViewAsOf`): management other than the view-as calls, secrets and `ACL NATIVE` are refused (`a view-as session
  reads metadata only`); a query batch is rewritten for `VerifyPrincipal(role)` - what `ACL ROLE "r"` gets, claims
  included - with the session kept, and the audit keeps the session's principal (`detail = view_as`). RESET is
  judged as the session's own principal, so the mode is always left the way it was entered.
- The rewriter's `metadata_only` (from the same record): statements other than SELECT / PRAGMA / SET / transaction /
  CALL refused; outside a DESCRIBE (`describing`) every object read, every table function but the metadata surfaces
  (`duckdb_*`, `acl_keys`, `acl_function_columns`, `acl_references`) and every virtual scalar call refused, and
  SUMMARIZE. The metadata surfaces, the platform views and the Flight catalog RPCs answer as the role.
- A view never shows more than the viewer may read: below passthrough, a role holding administration
  (`AdminRights::Privileged()` - a bundle, a catalog's manage, a point grant) is refused at SET (`AuthorizeRoleTargets`) -
  else a policy holder would read the node / cluster views through an operate or passthrough role's view; a point
  grant on `platform.view_as` does not reach the mode (the policy bundle's only). Judged again on EVERY batch
  (`ViewAsOf`): a viewer that lost the policy bundle, or a viewed role that came to hold administration, ends the
  mode, so a revocation never leaves a session reading as the role.
- The one decision is the override's and is handed to the rewriter (`RewriteStatements(…, metadata_only)`), never
  read a second time. In the mode: the viewer's USE does not apply and `USE` is refused (the record is the viewer's);
  the session's temp tables are the viewer's and are not listed nor resolved; a function of an attached catalog
  (a physical macro, a service's function - the gate's key outside `system`) is refused, a system function runs;
  the INGEST prefix and the quack drain are refused. Flight: a reservation carries the mode it was made in (the
  owner's `\x1c` suffix, `FlightDoorState::Owns`) - a statement prepared with the session's own rights does not run
  inside the view, nor one prepared in the view after RESET; a result kept at GetFlightInfo (the SET itself) is
  answered whatever the mode is now.
- Review (three passes) found: a policy holder read `platform.sessions` / `audit_events` / the cluster views by
  viewing a passthrough role; a point grant reached the mode; a revoked viewer stayed in it; a virtual table function
  named `acl_references` / `acl_keys` returned rows (the exemption was by the written name - now a virtual hit is
  refused whatever its name); a physical scalar macro granted to the role read rows; the viewer's USE and temps
  carried into the view; a Flight statement prepared before the mode ran inside it. Each is a test.
- Not here (minimal first, owner): a catalog admin's view; the mode in `acl_sessions()` / `platform.sessions`; the
  viewed role in the audit event (its detail is `view_as`); a token's claims (the view is the role's, as
  `ACL ROLE` - one role, its default claims). An open stream started before the SET keeps streaming; quack's
  client-side prepared statements were not probed.
- Tests: `test/cpp/test_acl_view_as.cpp` (listings as the role, each refused path, another session untouched,
  RESET / platform.view_as, who may, a privileged role, a point grant, a revocation mid-view),
  `test/e2e/flight/admin.sh` + `view_as_client.py` (GetCatalogs / GetTables as the role, a read refused, a statement
  prepared before the mode refused inside it).

### 120.5 (2026-10-11)
- Schema v22 (min_reader 21 - nullable columns at the end; a v21 build reads by name and never writes a newer
  catalog): `created_by` and `created_roles` on relations, schemas, functions, references. `created_roles` was not in
  the design: the finding judges "the sources granted to the author's roles NOW", and a token's roles are nowhere
  else - the roles are kept only when the source gate (spec 118.3) bound the author (it administers, below policy),
  so a policy author, the operator and a principal's own CREATE never raise the finding.
- The author: not an appended argument to every compiled call (the design's) but the decision itself - the note the
  override leaves for the statement (spec 074) carries the principal; `AuthorScope` around the creating admin
  functions reads it (`StatementAuthor`, `AuthorOf`: `<issuer>|<subject>`, or the role for `ACL ROLE`); none for the
  anonymous gateway or the operator's own SQL. A principal's own CREATE / CREATE VIEW is a follow-up of the rewrite
  (no note of its own): the rewriter names the author as `acl_register_*`'s last argument (acl_* is the never set - a
  principal cannot write it). A redefinition keeps the stored pair (`CreatedByLit`); a rename is an UPDATE.
- `acl_check_catalog` adds `source_not_granted` (`PolicyStore::SourcesNotGranted`): per object with `created_roles`,
  its physical names (phys, an alias' phys_path, a function alias' attached database) and the tables its bodies name
  (view / template / RLS / computed columns / a reference's expression - `StoredBodyTables`, parsed) outside
  `GrantedSources` of those roles now - with `GRANT SOURCE <db>.<schema> TO ROLE <r>`; nothing is taken back.
- `platform.relations / schemas / functions / references` show `created_by`.
- Found while building: a parse nested in a batch's own decision (the source gate's `GetTableNames` probe of a view
  or function body, spec 118.3) pushed a profile boundary in front of the batch's notes - the definition then ran with
  no note (no profile event, no AclConnection session, no author). `PushProfileNote` drops a trailing boundary.
- Review (three passes): `created_roles` is the CURRENT definition's writer, not the first author's - a definition
  the operator or policy rewrote kept the catalog admin's roles, and the finding's repair then widened that role for a
  source it never chose; the source-gated set is everyone below policy (`!Policy()`, the cluster bundle too - it was
  `SeesAllSources`, the listing predicate); the finding reads a relation's RLS, its computed columns and a reference's
  expression too (grants are policy's - never gated); a function alias names a source only when its first part is an
  attached database (a builtin's alias raised a finding no repair could clear); roles are joined by `\x1f` (a role
  name may hold a comma); roles that are gone or administer nothing get "redefine or drop the object", never a grant
  to a name the next role may take; the repair names a role that still administers. Spec 118.3's gate now judges
  `acl_refresh_schema_objects` (by the expansion's origin) - a refresh added records over a revoked source. The
  driver mode's read-only refusal is no longer preceded by a failing lookup.
- Review (author): the ALTER writers (relation, schema alias, function, reference) and REPAIR record their writer -
  without it a re-point cleared `created_roles` and laundered the object out of the finding; `AuthorScope` restores the
  scope it found.
- Left (owner's call): the author is read from the decision's note at execution, so a client that parses another
  statement between a batch's parse and its execution (the duckdb CLI's agent mode plans every statement first) loses
  it - `created_by` / `created_roles` are then NULL ("unknown"), never another principal's, and the finding does not
  rise for that object. The robust form is the design's (the author appended to every compiled call), at the price of
  every creating function's signature. The same loss, before this spec, takes such a statement's profile and its
  AclConnection session.
- Left: the stored author is read on the store's own connection, outside the write's transaction (a concurrent
  definer may record the other's author - a fact, never a right); the legacy grant wrappers write no author; an
  expansion's own schema row is not judged (its records are, one finding each).
- Tests: `test/sql/acl_created_by.test` (each author, a redefinition, the platform view, the finding raised and gone,
  each review case, the note regression).
