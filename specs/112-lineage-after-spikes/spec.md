# Spec 112: lineage, after the client spikes

- **Status**: accepted
- **Date**: 2026-10-09
- **Follows**: spec 107 (lineage), spec 109 (the parent), acl-otel spec 018 (the transport)
- **Found by**: the Spark / dbt / Python spikes of 2026-10-09 (a node with acl + acl-otel, Marquez)
- **Decisions (owner, 2026-10-09)**:
  - the naming rule of §1 is accepted, and `acl_lineage_namespace` is never tailored to an engine;
  - physical sources keep their own namespace;
  - a rollback is `RUN_ABORT`;
  - the namespace is the cluster's (a cluster-profile item), not the node group's; without it no
    lineage is sent, which is also the way to turn lineage off;
  - linking sources and federations into one graph is the platform's (hugr_node), and acl gives it an
    extension point (§9). The platform design: 017 §3.7, 019 §11.

## Problem

Three real clients wrote and read through a node that sent its lineage to Marquez. The facts reached
the backend, but they do not join the clients' own lineage, and some of them are wrong:

1. **Names do not line up.**
   - The node names a virtual dataset `acl://<ns>/<vcat>` :: `<object>`: the catalog is in the namespace.
   - Spark's OpenLineage integration names the same table by its JDBC rule, `<scheme>://<host:port>` ::
     `<catalog>.<schema>.<table>`, and its namespace resolver maps the host to a name of the operator's
     choosing.
   - dbt-ol names it `duckdb://…` :: `<attach alias>.<schema>.<table>`.
   - The graphs stay apart, and symlinks do not help: Marquez ignores them for identity.
2. **One run per row.** A DoPut batch (Spark `executeBatch`, DBAPI `executemany`) executes once per
   parameter row, and each execution is a run. One Spark write of 10 rows gave 10 runs, so a million
   rows give a million.
3. **An empty run for a write into a schema.** A write whose target sits in a virtual schema (`CREATE
   VIRTUAL SCHEMA … AS`, granted `INTO`) comes out with inputs, outputs and edges all empty and
   `approximate`. That is where dbt writes.
4. **Flight ingest has no lineage** (`adbc_ingest`). Its `x-openlineage-*` headers are not read, so
   spec 109's check is not applied there either.
5. **Noise under a declared parent.**
   - Spark's schema probes (`SELECT * … WHERE 1=0`) and existence check become runs.
   - The quack client's catalog refreshes (`duckdb_tables()`, `duckdb_views()`, `duckdb_schemas()`)
     become runs too, with the listings as inputs. Five events per dbt model instead of one.
6. **A rolled-back write is reported `RUN_COMPLETE`.** The run is emitted at the statement's end, not
   at its transaction's.
7. **Field types are empty** (`"type": ""`) in every dataset schema the node sends.

## Design

**1. Names** (the owner's decision). A virtual dataset is namespace `<acl_lineage_namespace>` and name
`<vcat>.<schema>.<object>`, with the schema always written (`main` included). This is OpenLineage's own
convention for a SQL endpoint.

- **The namespace is the cluster's** (owner, 2026-10-09). Virtual catalogs live in a policy catalog
  that several node groups may serve, and the same object must not split into one dataset per group.
  - **Where it is set.** It is set once for the cluster, as a cluster-profile item:
    `ACL CLUSTER SET acl_lineage_namespace = 'acl://prod'` (spec 093). The policy catalog holds it
    and every node applies the same value. A node without a cluster sets it with `SET GLOBAL` in its
    bootstrap; on the platform, the orchestrator sets it.
  - **No default.** With no namespace the node sends **no lineage**, however `acl_lineage_level` is set.
    - This doubles as the off switch: clearing the namespace stops lineage everywhere in the cluster,
      while the level stays as the operator left it.
    - It guarantees that two clusters never merge their virtual catalogs in one backend by accident.
    - The node says why, so the silence is visible. In `acl_lineage_events()` it is one notice (no
      payload) per change of state. `acl_lineage_status()` answers `on`, `off`, or `no namespace: set
      acl_lineage_namespace`, and acl-otel's status shows the same.
  - **The node group** stays in the run's facet (`node_group`). It is no longer in the namespace.

- **Spark** lines up when its namespace resolver maps the door's `host:port` to the node's namespace,
  which is configured on Spark's side.
- **dbt** lines up when the node is attached under the virtual catalog's name; its namespace still
  needs a mapping in the catalog.
- **A Python job** names datasets itself.
- **Physical datasets** stay `<ns>/source/<alias>` :: `<schema>.<table>`. A source is not the node,
  and the operator relates it to the real address in the catalog.
- **A virtual table function** is `<ns>` :: `<vcat>.<schema>.<function>`, with dataset type
  `TABLE_FUNCTION`.
- **Job namespaces** (`<ns>/client/<door>`) do not change.
- **No migration.** The static picture is re-sent under the new names (`acl_lineage_resend()`, or
  acl-otel's bootstrap). Old names stay in the backend as orphans, and the docs say how to clear them.

**2. One run per DoPut batch.** `DoPutPreparedStatementUpdate` opens a batch scope on the connection.
Inside it every execution counts towards one run (the same job, the same edges). At the scope's end
the run is handed to the worker once, `RUN_FAIL` if any execution failed. A prepared statement
executed once is still one run.

**3. A write into a schema.** I will find the root cause in the worker's mirror: the target's
canonical name from a live schema alias, versus where the scratch places it. It gets the regression
test spec 107 lacked: CTAS and INSERT into a schema alias granted `INTO`.

**4. Flight ingest.** `DoPutCommandStatementIngest` reads the call's lineage context
(`LineageOfCall`, which also applies spec 109's check). The `ACL INGEST` statement captures a job
like any write: the target and its fields, sources the client's (spec 107's ingest fallback).

**5. No runs for what reads nothing.**
- **A metadata surface** is never a declared read: `duckdb_*()`, `information_schema`, `SHOW`,
  `DESCRIBE`. Spec 098's `MetadataSurfaceOf` already knows which they are.
- **A read that cannot return a row** is not a run:
  - a WHERE that folds to a constant false (`1=0`, `false`);
  - `LIMIT 0`;
  - Spark's existence check `SELECT 1 FROM t WHERE 1=0`.

  This is judged on the bound plan, after constant folding.

**6. Transactions.** Inside a client's explicit transaction, a run waits on the connection
(`ClientContextState::TransactionCommit` / `TransactionRollback`):
- **Commit** hands the runs to the worker as they are.
- **Rollback** sends them as **`RUN_ABORT`**, OpenLineage's `ABORT`.
- **Autocommit** is unchanged: the statement is its transaction.

`RUN_ABORT` is a new `event_type` value. It is not a layout change of the contract (the field is
already a string), but acl-otel must render it, so it gets a line in acl-otel.

**7. Field types.**
- A runtime run's target fields carry the types the mirror had, the types the principal reads.
- A definition's fields carry the probed types.
- Nested fields carry their children (the contract's `fields`).

**9. A source's lineage identity: an extension point, not a federation.** A source a node gives
access to is often filled by others (Spark, the operator's ETL) with OpenLineage of their own. They
name it by its real address, per OpenLineage's naming spec (`postgres://pg.prod:5432` ::
`sales.public.orders`), while the node names it by its ATTACH alias. Joining the two, and joining
platforms in a federation, is the platform's work (hugr_node, design 017 §3.7 / 019 §11). acl only
makes it possible:

- **The contract** (duckdb-ext-common, its own header and version, a PR there first). A registry of
  source-identity providers in the ObjectCache. Given an attached catalog (its name and its type), a
  provider answers an identity: a namespace and a name prefix, for example `postgres://pg.prod:5432` +
  `sales`.
  - hugr_node registers a provider for its sources and for type `hugr`. For `hugr` the answer is the
    remote cluster's namespace, so a physical dataset of A *is* B's virtual dataset.
- **acl asks the registry** whenever it names a physical dataset: the definitions' edges, the
  physical runs, NAMESPACE events. With an identity, the dataset is `<namespace>` ::
  `<prefix>.<schema>.<table>`. Without one, it stays `<ns>/source/<alias>` :: `<schema>.<table>`.
- **Declared by the operator** (owner, 2026-10-09). An ATTACH is native, done by the node's bootstrap
  before the doors open or when the bootstrap changes, so the identity is declared next to it or on
  it:
  - **`acl_lineage_source(alias, identity)`** is the base: an `acl_` function (spec 072's never set,
    the operator's alone). `acl_lineage_source(alias, NULL)` clears it.
    - It is kept in the instance's memory like the ATTACH itself. The bootstrap sets it again at every
      start, and nothing is written to the policy catalog.
    - It can be called before or after the ATTACH, because it is read at every lineage event.
  - **`ATTACH … LINEAGE '<identity>'`** is the sugar, in our parser override (which sees every
    statement).
    - A trailing `LINEAGE '<x>'` on an ATTACH is taken off, and the statement compiles to the native
      `ATTACH …` followed by `SELECT acl_lineage_source('<alias>', '<x>')`, the alias from the parsed
      ATTACH.
    - Nothing happens at parse time. The second statement runs only if the ATTACH did.
    - A `DETACH` of the alias clears its identity (the pre-optimize hook already sees DETACH).
    - In a cluster profile, `ACL CLUSTER ATTACH … LINEAGE '…'` compiles the same way.
  - **Never a credential.** Userinfo in the identity is refused.
  - **Order.** A provider from the registry (hugr_node) comes first, then the declared identity, then
    the alias form.
  - **A change of identity** takes effect at the next event. `acl_lineage_resend()` re-sends the
    definitions under the new names.
- **acl never derives an identity** from a DSN or a secret: a host behind a proxy is not the host
  others see, and a secret is not acl's to parse.

**8. Spec and docs corrections.**
- Spec 107's symlinks are dropped.
- Its `<schema>.<object>` becomes the rule of §1.
- `website/docs/lineage.md`:
  - the names;
  - the Spark resolver recipe;
  - attaching dbt's node under the virtual catalog's name;
  - `RUN_ABORT`.

## Enforcement & security

Nothing here reads or grants more. A name carries no more than spec 107's did. The batch and
transaction scopes hold only facts the node already had, on the connection that made them, and they
end with the connection.

## Testing

- **`test/sql/acl_lineage.test`.**
  - The new names: virtual, physical, a function.
  - A write into a schema alias (CTAS and INSERT) with its edges.
  - No run for a metadata surface or a `WHERE 1=0` read under a parent.
  - Field types.
  - A transaction: commit gives the runs, rollback gives `RUN_ABORT`.
- **The Flight e2e.**
  - One run for an `executemany` of N rows (DoPut).
  - Ingest gives a run with its target and the parent from a header.
  - A malformed header on ingest is refused.
- **The spike environment again.**
  - Spark with the namespace resolver: the Spark and node datasets are one node in Marquez.
  - dbt: the CTAS has edges, and the model build has no listing runs.
  - Python: one run per `executemany`.
- **acl-otel.** `RUN_ABORT` renders as `ABORT` (its own small change).
- **The namespace.**
  - No lineage while `acl_lineage_namespace` is empty, whatever the level; the status says why.
  - Set through `ACL CLUSTER SET`, every node of the cluster sends under it.
- **The identity registry.**
  - A test provider (C++, through the contract header) renames a source's physical datasets.
  - `acl_lineage_source()` renames them, called before or after the ATTACH, and NULL clears it.
  - `ATTACH … LINEAGE '…'` renames them; a failed ATTACH records nothing; a DETACH clears it.
  - The cluster item `ACL CLUSTER ATTACH … LINEAGE` does the same.
  - Userinfo is refused.
  - A principal cannot call the function: it is in the never set.
  - With neither, the alias form stays.

## Alternatives considered

- **Tailoring `acl_lineage_namespace` per engine.** The owner refused it: several engines share a
  node.
- **Symlinks for the engines' names.** Marquez ignores them for identity, and the node does not know
  the engines' addresses.
- **Dropping a rolled-back run.** The run did happen and failed to commit. `ABORT` is OpenLineage's
  word for it.
