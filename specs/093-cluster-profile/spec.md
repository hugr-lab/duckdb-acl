# Spec 093: the cluster profile in the policy catalog

- **Status**: implemented
- **Date**: 2026-09-30
- **Design**: design/017-hugr-platform §3.1a, §3.2a, §3.6a

## Summary

Every node already reads one shared policy catalog, versioned by `policy_version`. This spec adds
the **shared part of the node bootstrap** to that catalog: which extensions a node runs, which
sources it attaches, which settings it carries. It also adds a management syntax, `ACL CLUSTER …`,
which writes an item, bumps a `config_version`, and applies the item on the node that ran the
statement.

acl (MIT) owns the *description* of the desired state, exactly as it owns the policy. It does not
converge a fleet. Converging (tick, drain, restart, readiness, rollback) belongs to the node agent
`hugr_node` (BUSL). A node without the agent applies only what was done on it.

## Problem

A node's engine state is private to its process: extensions, attached sources, settings. Today it
comes from whatever boot script started the node (design/009 §1). Two nodes of one cluster can
drift, a new node has to be told everything again, and "add a source to the cluster" means N boot
scripts and N restarts.

## Design

### Storage (schema v16)

```sql
CREATE TABLE <cluster_items>(
    "scope"   ACL_KEY_TEXT,   -- '' = the whole cluster; otherwise a resource group's name (spec 095)
    "kind"    ACL_KEY_TEXT,   -- 'extension' | 'source' | 'setting'
    "name"    ACL_KEY_TEXT,   -- extension name, source alias, setting name
    "spec"    VARCHAR,        -- JSON, per kind (below); never a credential
    "class"   VARCHAR,        -- 'hot' | 'drain' | 'restart' - how a change of it is applied (design §3.2a)
    "version" BIGINT,         -- the config_version that last wrote it
    "pos"     BIGINT,         -- creation order: the tie-breaker of the start order
    "comment" VARCHAR,
    PRIMARY KEY ("scope", "kind", "name"));

CREATE TABLE <cluster_deps>(      -- a source that needs another source attached first (current rows only)
    "scope" ACL_KEY_TEXT, "name" ACL_KEY_TEXT, "depends_on" ACL_KEY_TEXT,
    PRIMARY KEY ("scope", "name", "depends_on"));

INSERT INTO <meta> ... 'config_version', '0'
```

**Desired state only, no history.** The policy catalog holds the profile as it is now, as it holds
the policy. It neither grows nor needs maintenance.

- **The agent's diff.** `hugr_node` keeps the profile it applied and compares it with the current
  one. A new node applies the current profile.
- **History, diff and rollback belong to the orchestrator**, which issues the changes. Before a
  statement it reads `acl_cluster_items()`, and it keeps the previous state itself: the last N
  changes in memory, then its own store. A rollback is the inverse `ACL CLUSTER` statement composed
  from that.
- **Who changed what goes to the audit**, and through acl-otel to OpenTelemetry and to tables (an
  acl-otel sink with filter, transform and retention; one mechanism for query logs, decisions and
  cluster changes, specified there). The audit carries the change's **identity**, never the item's
  spec: a source's path is a physical name, and the audit contract carries none (spec 069).

`config_version` is a counter of its own, not `policy_version`: a policy change must not look like an
infrastructure change to a reconciler, and the reverse (answers design/009's open question).

`spec` per kind:

- `extension`: `{"version": "1.4.2", "repository": "hugr", "sha256": "…"}`. `repository` is the name
  of a trusted repository (`duckdb_extension_repositories()`, duckdb 2.0). `sha256` is optional; when
  written, a node refuses a binary that differs.
- `source`: `{"type": "postgres", "path": "host=… dbname=…", "secret": "pg_sales", "options":
  {"READ_ONLY": true}}`. `secret` names a secret the node resolves (tresor), never its material.
- `setting`: `{"value": "48GB"}`.

### Syntax

The client writes it after the principal prefix, like any management form (spec 009). The gateway's
anonymous form is `ACL ADMIN CLUSTER …`.

```sql
ACL CLUSTER INSTALL EXTENSION spatial VERSION '1.4.2' [FROM hugr] [SHA256 '…'] [IN GROUP g] [COMMENT '…']
ACL CLUSTER UPDATE EXTENSION spatial VERSION '1.5.0' [SHA256 '…'] [IN GROUP g]
ACL CLUSTER REMOVE EXTENSION spatial [IN GROUP g]
ACL CLUSTER ATTACH '<path>' AS sales (TYPE postgres, SECRET pg_sales [, READ_ONLY] [, <option> …])
    [DEPENDS ON (other_source, …)] [IN GROUP g]
ACL CLUSTER DETACH sales [CASCADE] [FORCE] [IN GROUP g]
ACL CLUSTER SET memory_limit = '48GB' [IN GROUP g]
ACL CLUSTER RESET memory_limit [IN GROUP g]
```

Listing surface (table functions, the operator's):

- `acl_cluster_items([scope])` — the profile as stored;
- `acl_cluster_version()` — the current `config_version`.

### Start order and dependencies

A node applies the profile in this order:

1. settings;
2. extensions;
3. secrets (the tresor catalog);
4. **sources, in dependency order**;
5. the policy catalog.

There are no manual positions: a list order edited from several places does not survive. The rules:

- **Extensions follow from `TYPE`.** A source's extensions are derived from it (`postgres` →
  `postgres_scanner`, `ducklake` → `ducklake` plus the metadata backend's scanner). They do not
  have to be written.
- **Sources name the sources they need** with `DEPENDS ON (…)`. Example: a DuckLake whose metadata
  lives in an attached catalog, or a duckdb file read through another attach. Sources are ordered
  topologically; ties go by `pos` (creation order).
- **Checked at write time.** A dependency on an unknown source, or one that would close a cycle, is
  refused. So is a dependency across scopes other than group → cluster: a group's source may depend
  on a cluster source, never the reverse.

```sql
ACL CLUSTER ATTACH 'ducklake:postgres:host=… dbname=lake_meta' AS lake
    (TYPE ducklake, DATA_PATH 'abfss://…', SECRET lake_meta) DEPENDS ON (meta_pg);
```

### Removal

- **`REMOVE EXTENSION` is `restart` class.** duckdb cannot unload an extension from a running
  process. The item leaves the profile; nodes stop loading it at their next start, and the agent
  rolls the restart through drain. It is refused while a source of the profile needs it (by its
  `TYPE`), and the refusal names the source.
- **`DETACH` removes the source from the profile**, so new and restarted nodes do not attach it. It
  also detaches it on this node: `hot` when unused, otherwise left to the agent's drain. It is
  refused while something else references it:
  - **another source's `DEPENDS ON`**: `CASCADE` detaches the dependents too, and the answer lists
    every source it removed;
  - **a virtual object of the policy** reading from it (relations, schemas, functions over
    `sales.…`): the policy goes first (design §3.2a), and the refusal names the objects. `FORCE`
    detaches anyway, and `acl_check_catalog` then reports them as `source_missing`.

### What one statement does

1. **Checks** (below). A refusal writes nothing.
2. **Writes** the item (upsert, or delete for a removal) and bumps `config_version`, in one catalog
   transaction.
3. **Applies it on this node when its class is `hot`**:
   - `INSTALL … FROM <repo>` + `LOAD`;
   - `ATTACH … (SECRET …)`;
   - `DETACH` (`hot` while unused; in use, it is refused here and left to the agent's drain).

   If the local apply fails, the catalog transaction is rolled back. The item that reaches the cluster
   has worked on at least one node, the one that wrote it (a built-in canary).
4. **Answers** one row: `version`, `class`, `applied_here` (bool), and `note`. The note is, for example,
   "restart class - the agent rolls it out".

Classes are fixed per verb and kind (design §3.2a):

| change | class |
| --- | --- |
| install extension, attach, detach | hot |
| update or remove extension, `SET` of a setting, re-pointing a source (`ATTACH` over an existing alias with another path) | restart / drain |
| the policy (roles, grants, issuers) | not a profile item at all |

### Enforcement & security

- **Capability.** An infrastructure change needs **`passthrough`** (spec 009: the infrastructure
  admin). `manage` is not enough, and a catalog-scoped admin never has it.
- **No credentials, anywhere** (the owner's rule; design §3.6a). A write is refused when:
  - the path, parsed as a conninfo `k=v` list or as a URI, carries a key or a userinfo from the deny
    list: `password`, `passwd`, `pwd`, `passfile`, `secret`, `client_secret`, `token`,
    `bearer_token`, `access_token`, `key_id`, `secret_access_key`, `account_key`, `sas_token`, `sig`,
    or `user:pass@`;
  - an option or a setting value is one of those keys;
  - `SECRET` is missing where the source type needs a credential. It is refused with a sentence
    naming the secret to create.

  The check is on keys, not on guessing values. The refusal quotes the key, never the value.
- **Settings.** The bootstrap fixes the hardening: `allow_unsigned_extensions`,
  `allow_community_extensions`, `allow_extension_repositories`, `allow_persistent_secrets`,
  `allow_unredacted_secrets`, `lock_configuration`, `extension_repository_directory`,
  `allow_parser_override_extension`, `enable_external_access`. None of these is a profile item:
  `ACL CLUSTER SET` refuses them. Any other GLOBAL setting may be profiled; a session-scoped one is
  refused.
- **A user-provided repository's extension is installed apart.** duckdb puts it under
  `<extension directory>/repositories/<repository>/`, lists it nowhere in `duckdb_extensions()`, and
  loads it only with `LOAD <name> FROM <repository>`. So the live apply loads it that way, and so
  must the node agent at every start. `sha256` is computed on that file. On a mismatch the file (and
  its `.info`) is removed before the refusal, so no later `LOAD` finds a binary the profile refused.
- **Extensions come only from a trusted repository.** `FROM` must name a USER_PROVIDED repository
  that exists on the node. A path or URL is refused, and so is the core/community fallback. The
  install records the key fingerprint duckdb verified. `sha256`, when given, is checked after the
  download and before `LOAD`.
- **Audit goes to OpenTelemetry, not to a table.** Each `ACL CLUSTER` statement is one `admin` event
  (spec 069), accepted or refused. Only existing fields are used, so the contract layout does not
  change:
  - `objects`: the item as `<kind>:<name>` (`source:sales`, `extension:spatial`,
    `setting:memory_limit`), with capability `cluster`;
  - `detail`: `<verb> <scope|cluster> v<config_version> <class>`.

  Never the item's spec. A path is a physical name, and a spec could hold what the lint missed.
- **Fleet events are the agent's.** "Node X applied v42", "failed on item Y", "drained for Z" and the
  rollout's progress come from `hugr_node` as a new event kind `cluster`. `AuditEvent::kind` is a
  string, so a new value changes no layout and needs no `CONTRACT_VERSION` bump. acl-otel maps it.
  How the agent hands events to the pipeline is the agent's spec.
- **A node without the agent never converges silently.** `acl_cluster_items()` shows what the
  cluster wants; what this node has is `duckdb_extensions()` / `duckdb_databases()`. The diff is the
  agent's job and its report (spec 095 adds `config.applied/target` to the load report).

### Interaction

- **Group scope** (`IN GROUP g`) requires the resource group to exist (spec 085). Spec 095 makes
  a group a set of nodes.
- **`lock_configuration` interplay.** After a node's bootstrap the configuration is locked, so a
  `SET` item is `restart` class: it cannot be applied live. `INSTALL`/`LOAD`/`ATTACH` are not
  settings and stay hot under the lock.
- **Function-driver policy sources** (spec 008) have no cluster items. The statements are refused
  there with a sentence saying so.

## Testing

- **sqllogictest `acl_cluster_profile.test`** (77 assertions):
  - no catalog, no profile;
  - ATTACH: written, applied here, versioned, listed with its dependencies and options; re-pointing
    is drain class and not applied;
  - dependencies: an unknown source and a cycle are refused, and a refused write writes nothing;
  - the credential lint:
    - `password=` in a conninfo;
    - `user:password@` in a URI;
    - `sig=` in a SAS URL;
    - a `PASSWORD` option;
    - a postgres source without `SECRET`;
    - the refusal carrying the key, never the value (anchored full match);
  - settings: GLOBAL ones are written as restart class; the hardening (`allow_unsigned_extensions`,
    `lock_configuration`) and unknown settings are refused; RESET;
  - group scope: an unknown group is refused, a known one scopes the item;
  - extensions:
    - no trusted repository, `core`, a path, or a missing VERSION: refused;
    - REMOVE of an item not in the profile: refused;
  - DETACH:
    - a dependent needs CASCADE;
    - a policy reading through the source (a virtual table) needs FORCE;
    - CASCADE FORCE detaches both, on the node too;
  - authorization: `manage` is refused, `passthrough` admitted;
  - audit: the admin event's object is `source:<alias>` with capability `cluster`;
  - a live ATTACH that fails rolls the write back (version and items unchanged).
- **C++ `test_acl_cluster_install`**: a trusted repository, a local directory in duckdb's versioned
  layout holding this build's postgres_scanner:
  - a wrong `sha256` refuses before LOAD, removes the download, and leaves the profile and its version
    unchanged;
  - the right one installs, `LOAD … FROM` the repository (its functions registered), and writes the
    item;
  - a second INSTALL is refused;
  - UPDATE and REMOVE are restart class and not applied live.

  Skipped in a build without that loadable (a plain build).
- **Schema.** `make schema-check`: the hand-applied v16 schema works, and a catalog migrated from
  v15 by `schema/migrations/v16.sql` matches a fresh one.
- **Not here.** Attaching the docker postgres through a secret from the node's secrets service is
  the node agent's end to end (the secret comes from tresor there).
## Alternatives considered

- **The profile in the control plane's own store**, pushed or pulled over its API. Rejected (owner,
  2026-09-30): it needs a second channel next to the catalog every node already reads; profile and
  policy could not change in one transaction; and it breaks the design/009 rule of "no push, no
  per-node access".
- **Profile items as free SQL (a bootstrap script in the catalog).** Rejected: a script cannot be
  diffed or classified, nor linted for credentials by key.

## Open for review

1. `ACL CLUSTER` vs `ACL ADMIN CLUSTER` for the principal form. The draft uses the principal form
   `ACL CLUSTER …` and keeps `ACL ADMIN CLUSTER …` for the gateway's anonymous one, as the other
   management verbs do.
2. The local-apply-or-rollback rule: is "the writing node is the canary" wanted, or should a write
   always be pure description, applied only by the agent?
3. Are source *options* free, or an allowlist per scanner type (the credential lint is a deny list)?
4. Start order: dependencies only (`DEPENDS ON` + creation order), or also an explicit position?
   The draft says dependencies only.
