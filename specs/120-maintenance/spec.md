# Spec 120: maintenance - the missing forms, effective rights, exposures, view-as, export, created_by

- **Status**: accepted, **120.1 implemented** (see *As built*) (by the owner 2026-10-11: the order 120.1 → 120.5; export after the release; view-as for
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
| `ALTER FUNCTION CATEGORY c SET COMMENT '…'` | `acl_create_function_category(c, comment)` (re-create updates only the comment) |
| `ALTER RESOURCE GROUP g SET (limits …)` | `acl_alter_resource_group(g, 'limits', json)` - a new field; the comment kept |
| `ALTER ROLE r SET COMMENT '…'` | `acl_alter_role` gains `comment` (the `roles.comment` column exists, written '' today) |
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
  (`ResourceLimitsJson` shared with CREATE); `ALTER FUNCTION CATEGORY c SET COMMENT` → `acl_create_function_category`.
  Platform functions `comment_role`, `revoke_object`, `alter_reference`.
- **No ALTER MAP** (decided while building): a mapping is only its key, so the change is `DROP MAP` + `MAP` - two
  existing statements; one call would have needed its own privileged-target check (spec 095).
- Found: `CatalogBackend::WriteWithReads` committed without the `written` policy event `Write` emits - fixed (a
  resource group's create, a role's re-define … were not audited as writes).
- Tests: `test/sql/acl_maintenance_forms.test`; `acl_node_group.test`'s unknown-property message.

