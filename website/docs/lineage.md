# Lineage for OpenLineage

A node emits **lineage facts** (spec 107) for what is defined on it and for what is written through it.
The facts are column-level and field-level edges with OpenLineage's transformation types; acl-otel
renders them as OpenLineage events and facets. A data catalog
(Marquez, DataHub, Purview, OpenMetadata) shows from them:

- what each virtual table and view is made of, down to the fields of a struct;
- which roles see which fields, plain or masked;
- what wrote into what, and on behalf of which pipeline step.

The node only makes the facts. The transport to an OpenLineage backend belongs to
[acl-otel](https://github.com/hugr-lab/acl-otel). Nothing a statement or an admin write does waits on
it: the work runs on one worker thread of the node; the statement's own thread only copies the
statement, and only when the statement is in scope. Lineage needs a policy catalog (`acl_use_db`)
and a namespace (`acl_lineage_namespace`, below): without one nothing is sent, whatever the level.

## What is emitted

| event | when | what it says |
| --- | --- | --- |
| `DATASET` | a virtual table, view or table function is created, altered, repaired or dropped | the object's fields and their edges to the physical columns, its lifecycle, the per-role tags |
| `DATASET` (no lifecycle) | a catalog or object grant changes | the affected objects again, with the new per-role tags |
| `DATASET` | the operator's own SQL (or `ACL NATIVE`) creates, alters or drops a physical table or view | a physical view's body lineage; a table's schema |
| `NAMESPACE` | `ATTACH` / `DETACH` of a source - the operator's, or a cluster item's | the source's namespace (below) and its type |
| `RUN_COMPLETE` / `RUN_FAIL` / `RUN_ABORT` | a write - INSERT / UPDATE / DELETE / MERGE / CREATE TABLE AS, one per execution (a `PREPARE` is none) | the target's fields, typed, and where each came from |
| `RUN_COMPLETE` / `RUN_FAIL` / `RUN_ABORT` | a Flight `executemany` (one DoPut of N parameter rows) | ONE run for the batch - `RUN_FAIL` if any row failed |
| `RUN_COMPLETE` / `RUN_FAIL` / `RUN_ABORT` | Flight ingest (`adbc_ingest`), with the call's lineage headers | the target and the fields written - their source is the client's stream (`approximate`) |
| `RUN_COMPLETE` / `RUN_FAIL` (inputs only) | a SELECT that declared itself a step of an external job | the datasets it read |

**Transactions.** A write inside a client's explicit transaction is sent when the transaction ends:
`COMMIT` sends its runs as they are, `ROLLBACK` sends them as `RUN_ABORT` (OpenLineage's `ABORT`). A
statement that fails is `RUN_FAIL` at once. In autocommit the statement is its transaction.

A plain SELECT, DESCRIBE, SHOW, EXPLAIN, a listing and `COPY TO` are never emitted. Under a declared
parent, a read that reads nothing is not a run either: one of only the metadata surfaces
(`duckdb_tables()`, `information_schema`, a DESCRIBE - a client's catalog refresh), and one whose plan
cannot return a row (`WHERE 1=0`, `LIMIT 0` - a client's schema probe). Not yet emitted: writes through
the quack door's streamed ingest (`SEND_DATA`), and a `GRANT SCHEMA` does not re-send the tags.

## Names

- **A runtime event speaks the principal's names**: the virtual catalog, table and columns as the
  client wrote them. How a virtual object is built from physical ones is already in the catalog, from
  its `DATASET` event.
- **Datasets** (namespace + name), OpenLineage's convention for a SQL endpoint:
  - virtual: `<ns>` + `<vcat>.<schema>.<object>`, the schema always written - `acl://prod` +
    `sales.main.orders`; a virtual table function the same, of type `TABLE_FUNCTION`;
  - physical: `<ns>/source/<alias>` + `<schema>.<table>`, or the source's own name when it has an
    identity (below).
- **The namespace is the cluster's.** `<ns>` is `acl_lineage_namespace`. It has no default: with none
  the node sends **no lineage**, and `acl_lineage_status()` says so (`on`, `off`, or `no namespace:
  …`). Set it once for the cluster - `ACL CLUSTER SET acl_lineage_namespace = 'acl://prod'` - or in a
  single node's bootstrap with `SET GLOBAL`. Clearing it is the cluster-wide off switch (a setting item: each node takes it as the node agent rolls the profile out), and it keeps
  two clusters from merging their virtual catalogs in one backend by accident. The node group is in
  the run's facet, not in the name.
- **Job namespaces** are `<ns>/client/<door>`.
- **Renamed?** Re-send the static picture under the new names with `acl_lineage_resend()`. The old
  names stay in the backend as orphans; delete them in the backend's own way.

## A source's identity

Others fill a source too - Spark, the operator's ETL - and name it by its real address, per
OpenLineage's naming (`postgres://pg.prod:5432` + `sales.public.orders`), while the node knows it by
its ATTACH alias. Declare the address, and the node names the source's datasets the same way:

```sql
ATTACH 'dbname=sales host=pg.prod' AS pg (TYPE postgres, SECRET pg_reader)
    LINEAGE 'postgres://pg.prod:5432/sales';
-- or, separately (before or after the ATTACH):
SELECT acl_lineage_source('pg', 'postgres://pg.prod:5432/sales');
```

Then `pg.public.orders` is `postgres://pg.prod:5432` + `sales.public.orders`, in every edge, run and
`NAMESPACE` event. The identity is `<scheme>://<host:port>[/<database>]`; it is a name and never a
credential - userinfo, a query string or a fragment (`user:password@`, `?password=`, `#…`) is refused. The node never derives it from a DSN or a secret: a host
behind a proxy is not the host others see.

- It lives in the node's memory, like the ATTACH it describes: the bootstrap declares it at every
  start. `acl_lineage_source(alias, NULL)` clears it, and a `DETACH` ends it.
- In a cluster profile: `ACL CLUSTER ATTACH '…' AS pg (TYPE postgres, SECRET s) LINEAGE '…'`.
- A platform extension may name sources itself through the `acl_lineage_sources` registry
  (duckdb-ext-common); its answer comes first, then the declared identity, then the alias form.

## An edge

Each target field lists its sources. A source carries OpenLineage's transformation:

| transformation | type / subtype |
| --- | --- |
| a column taken as it is | `DIRECT/IDENTITY` |
| an expression, a cast, a computed column | `DIRECT/TRANSFORMATION` |
| an aggregate | `DIRECT/AGGREGATION` |
| join, filter, group and sort keys | `INDIRECT/JOIN`, `FILTER`, `GROUP_BY`, `SORT` - on the whole target |
| window partition and order keys | `INDIRECT/WINDOW` - on the field the window computes |
| a `CASE` condition | `INDIRECT/CONDITIONAL` - on its field |
| an object's mask | `masking: true` |
| an object's RLS predicate | `INDIRECT/FILTER` from the columns it reads - never its text |

A grant's own predicate and masks are per role, so they are the role's tags (below), not edges.

A field path follows the `COLUMNS` spelling of spec 102: `address.city`, `items[].price` (an
element read through `unnest` or an index is `[]`). An event that could not derive every edge
exactly (a table function, a source that does not bind) says `approximate`.

## Roles

OpenLineage has no roles; it has tags. A virtual dataset carries, for each role that holds it:

- `acl.role.<role>` = its capabilities, on the dataset;
- `acl.role.<role>` = `visible` or `masked`, per field path;
- `acl.role.<role>.rls` = `true` when a predicate applies.

A field the role does not see has no tag of that role.

## External jobs: dbt, Spark, Airflow

A pipeline reads virtual datasets, transforms them in its own engine, and writes back through the node.
Its own OpenLineage events reference the node's datasets; the node's write events reference the
pipeline's run as their **parent**. The parent is OpenLineage's `OPENLINEAGE_PARENT_ID`
(`<namespace>/<job>/<runId>`), passed by any of these:

| channel | how |
| --- | --- |
| a session setting | `SET acl_lineage_parent = '…'`, `acl_lineage_root_parent`, `acl_lineage_job` - on a session of the client's own |
| a Flight call | headers `x-openlineage-parent`, `x-openlineage-root-parent`, `x-openlineage-job` |
| a quack request | the same headers, from an http secret: `CREATE SECRET (TYPE http, SCOPE 'https://<door>', EXTRA_HTTP_HEADERS MAP {'x-openlineage-root-parent': '…', 'x-openlineage-job': '…'})` |
| the gateway | `ACL … LINEAGE PARENT '…' [ROOT '…'] [JOB '…'] <statement>` |

A request's headers take precedence over the session's settings.

**A parent is checked where it enters** (spec 109). It must have the form `<namespace>/<job>/<runId>`,
with a UUID as the runId: OpenLineage's parent facet requires one, and a backend refuses an event
that carries anything else.

- **The marker and `SET`.** A malformed value refuses the statement or the SET, with a message that
  repeats nothing of the value.
- **A Flight header.** A malformed value fails the call with `InvalidArgument`.
- **A quack header.** quack cannot return a message here, so a malformed value is ignored: the
  statement runs with no parent. A `door` event `lineage_parent_invalid` is written once per
  connection, and every occurrence is counted in `acl.lineage.parent_invalid`.

`JOB` is free text.

- **The headers of an http secret** are set once per attached connection: put there what is constant
  for the connection (the root run, the job), and leave the parent - which changes per step - to SET.
- **SET carries a step's own parent.** A dbt pre-hook on a quack-attached node:

  ```sql
  FROM quack_query_by_name('node', 'SET acl_lineage_parent = ''{{ env_var("OPENLINEAGE_PARENT_ID") }}''');
  ```

  A plain `SET` would run on the client.

### Lining the names up

A pipeline's own events and the node's join in the backend only when both name a dataset the same.

- **Spark** (OpenLineage's Spark integration, through the acl JDBC driver `jdbc:acl://<door>`) names a
  table `acl://<host>:<port>` + the name it was given. Write table names in three parts
  (`sales.main.orders`), and add a namespace resolver that maps the door's address to the node's
  namespace - for `acl_lineage_namespace = 'acl://prod'`:

  ```properties
  spark.openlineage.dataset.namespaceResolvers.prod.type=pattern
  spark.openlineage.dataset.namespaceResolvers.prod.regex=door\.corp:32010
  ```

  The matched part is replaced by the resolver's name, so `acl://door.corp:32010` becomes `acl://prod`
  - the node's namespace. (`hostList` keeps the port.) Spark's reads and writes are then the node's
  datasets.
- **dbt** (dbt-ol, the duckdb adapter with the node attached through quack) names a model
  `duckdb://<path>` + `<attach alias>.<schema>.<table>`. Attach the node under the virtual catalog's
  name (`alias: sales`), and the names are the node's; the namespace is dbt-ol's own, to be related to
  the node's in the catalog.
- **A Python job** (or anything that emits for itself) uses the node's names directly.

Without a parent, a run belongs to the job `acl_lineage_job`, or `sql:<hash of the normalized
statement>`, in the namespace `<ns>/client/<door>` (`acl://dev/client/flight` for the namespace `acl://dev`).

## Settings

| setting | default | |
| --- | --- | --- |
| `acl_lineage_level` | `off` | `on` emits |
| `acl_lineage_namespace` | `''` | the cluster's namespace, e.g. `acl://prod`; `''` = no lineage is sent |
| `acl_lineage_identity` | `client` | `none`; `client` = the door, issuer, roles, node group; `subject` adds the token's `sub` |
| `acl_lineage_sql` | `off` | `normalized`: the SQL facet, the statement as written with every constant a `?` |
| `acl_lineage_physical` | `true` | `false` drops physical datasets and their edges |
| `acl_lineage_max_edges` | `4096` | edges per event before it is `truncated` |
| `acl_lineage_buffer` | `1000` | events `acl_lineage_events()` holds |

All are GLOBAL and can be cluster-profile items.

## For the operator

- `acl_lineage_status()` - `on`, `off`, or why nothing is sent.
- `acl_lineage_source(alias, identity)` - a source's identity (above).
- `acl_lineage_events()` - the ring: one row per event, the payload as JSON.
- `acl_lineage_flush()` - waits for the worker (runs and static events) and the audit queue.
- `acl_lineage_resend([vcat])` - sends every object's `DATASET` event again (tables, views, table
  functions), for a transport that starts on an empty catalog.
- The counters `acl.lineage.events`, `acl.lineage.approximate` and `acl.lineage.dropped` (the
  worker's queue holds 1000 items; past that an item is dropped and counted).

None of these is a principal's.

## How it is safe

- **No principal ever reads lineage.** It goes to the sinks that ask for it, never to the audit file
  or `acl_audit_events()`.
- **Never in a payload:** a value, a literal, a claim, a token, a session handle, a mask's or a
  predicate's text, and the statement's text unless `acl_lineage_sql = 'normalized'`.
- **A runtime run is computed off the statement's path.** The worker mirrors what the principal
  reads (names and types) into an empty, scratch DuckDB without external access and with no
  extension of the node's loaded but the built-in function sets. It binds the statement there and
  never executes it.
