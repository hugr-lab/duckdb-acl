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
| `NAMESPACE` | `ATTACH` / `DETACH` of a source - the operator's, or a cluster item's | the source's namespace (below), its alias as the name, and its type |
| `RUN_COMPLETE` / `RUN_FAIL` / `RUN_ABORT` | a write - INSERT / UPDATE / DELETE / MERGE / CREATE TABLE AS, and a SELECT whose CTE writes (`WITH w AS (INSERT … RETURNING …) SELECT …`); one per execution (a `PREPARE` is none) | the target's fields, typed, and where each came from |
| `RUN_COMPLETE` / `RUN_FAIL` / `RUN_ABORT` | a client's `ALTER TABLE|VIEW … RENAME TO` (spec 113) | the old name in, the new name out, each field `DIRECT/IDENTITY` - with a `DATASET` `DROP` of the old name and, where a record exists, a `CREATE` of the new one (how dbt's `__dbt_tmp` swap holds together) |
| `RUN_COMPLETE` / `RUN_FAIL` / `RUN_ABORT` | a Flight `executemany` (one DoPut of N parameter rows) | ONE run for the batch - `RUN_FAIL` if any row failed |
| `RUN_COMPLETE` / `RUN_FAIL` / `RUN_ABORT` | Flight ingest (`adbc_ingest`), with the call's lineage headers | the target and the fields written - their source is the client's stream (`approximate`) |
| `RUN_COMPLETE` / `RUN_FAIL` / `RUN_ABORT` | a quack client's streamed load (`SEND_DATA`: the client sends `INSERT … FROM scan_data_from_quack_client(…)` under its session) | the target only (`approximate`): the rows came from the client |
| `RUN_COMPLETE` / `RUN_FAIL` (inputs only) | a SELECT under a declared **parent** (a `JOB` or `ROOT` alone does not make it a run) | the datasets it read |

Over quack an `executemany` is one run per row: the protocol sends it as one statement per row.

**Transactions.** A write inside a client's explicit transaction is sent when the transaction ends:
`COMMIT` sends its runs as they are, `ROLLBACK` sends them as `RUN_ABORT` (OpenLineage's `ABORT`). A
statement that fails is `RUN_FAIL` at once. In autocommit the statement is its transaction.

A plain SELECT, DESCRIBE, SHOW, EXPLAIN, a listing and `COPY TO` are never emitted. Under a declared
parent, a read that reads nothing is not a run either:

- one of only the metadata surfaces (`duckdb_tables()`, `information_schema`, a DESCRIBE - a client's
  catalog refresh);
- one whose plan cannot return a row (`WHERE 1=0`, `LIMIT 0` - a client's schema probe);
- one that names no dataset (`SELECT 1`, or a read the worker could not bind).

A write always emits its run, approximate when its sources could not be derived.

A physical definition the operator rolls back with its transaction sends nothing.

Not yet emitted:

- a `GRANT SCHEMA` does not re-send the tags;
- a schema expansion (`CREATE VIRTUAL SCHEMA … FROM`, `acl_refresh_schema_objects`) sends no
  `DATASET` for the records it writes, and a live alias (`AS`) has no records - `acl_lineage_resend()`
  sends the expanded objects;
- a virtual table function's `DATASET` carries no per-role tags.

Approximate for now:

- a runtime call of a virtual table function;
- a CTE write with a parameter in its result (no target either);
- a statement read under a nested `USE` (spec 114: the worker cannot `USE` a nested schema, so the run
  has no inputs).

## Names

- **A runtime event speaks the principal's names**: the virtual catalog, table and columns as the
  client wrote them. How a virtual object is built from physical ones is already in the catalog, from
  its `DATASET` event.
- **Datasets** (namespace + name), OpenLineage's convention for a SQL endpoint:
  - virtual: `<ns>` + `<vcat>.<schema>.<object>`, the schema always written - `acl://prod` +
    `sales.main.orders`; a virtual table function the same, of type `TABLE_FUNCTION`. The node
    accepts the name back: a query of `sales.main.orders` reads the root object `sales.orders`;
  - a name part holding `.` or `"` is quoted, as the node keys it (spec 116): `sales."a.b".Sink`;
  - a statement read under a `USE` (spec 114) is named in full, as the `USE` qualified it;
  - physical: `<ns>/source/<alias>` + `<schema>.<table>`, or the source's own name when it has an
    identity (below).
- **The namespace is the cluster's.** `<ns>` is `acl_lineage_namespace`. It has no default: with none
  the node sends **no lineage**, and `acl_lineage_status()` says so (`on`, `off`, or `no namespace:
  …`). Set it in the node's bootstrap with `SET GLOBAL acl_lineage_namespace = 'acl://prod'` - on a
  platform node ([hugr-node](https://github.com/hugr-lab/hugr-node)) the cluster profile sets it once for the cluster. Clearing it is the cluster-wide off switch (a setting item: each node takes it as the node agent rolls the profile out), and it keeps
  two clusters from merging their virtual catalogs in one backend by accident. The node group is in
  the run's facet, not in the name.
- **Job namespaces** are `<ns>/client/<door>`, where `<door>` is `flight`, `quack`, `session`
  (a session the gateway opened with `acl_session_open()`) or `gateway` (a per-statement prefix). A run's job is
  `acl_lineage_job` (the marker, the header or the SET), or `sql:<hash of the normalized statement>`.
  A parent only adds the parent facet; it does not change the job.
- **Physical runs** (`ACL NATIVE`, the operator's own DML / CTAS) are the job `physical:<operation>`
  in `<ns>/client/<door>` (`<ns>/client/operator` without a door), with no parent and no client.
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
`NAMESPACE` event. The identity is exactly `<scheme>://<host[:port]>[/<path>]` - a path's `/` become `.` in the
dataset name's prefix. It is a name and never a credential: `@`, `?`, `#`, `%`, `\` and control
characters are refused anywhere (`user:password@`, `?password=`, `#…`), and the scheme is letters,
digits, `+`, `-`, `.`. The node never derives it from a DSN or a secret: a host
behind a proxy is not the host others see.

- It lives in the node's memory, like the ATTACH it describes: the bootstrap declares it at every
  start. `acl_lineage_source(alias, NULL)` clears it; a `DETACH`, or a new ATTACH of the alias, ends it.
  Declared before its ATTACH, it binds to the first attachment of that alias.
- On a platform node, the cluster profile's `ACL CLUSTER ATTACH … LINEAGE '…'` (hugr-node) declares it.
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
| a Flight call | headers `x-openlineage-parent`, `x-openlineage-root-parent`, `x-openlineage-job`; or `SetSessionOptions` with the three settings |
| a quack request | the same headers, from an http secret: `CREATE SECRET (TYPE http, SCOPE 'https://<door>', EXTRA_HTTP_HEADERS MAP {'x-openlineage-root-parent': '…', 'x-openlineage-job': '…'})` |
| the gateway | `ACL … LINEAGE PARENT '…' ROOT '…' JOB '…' <statement>` - `LINEAGE` once, then any of the three, each at most once, in any order |

A request's headers take precedence over the session's settings.

**A parent is checked where it enters** (spec 109). It must have the form `<namespace>/<job>/<runId>`,
with a UUID as the runId: OpenLineage's parent facet requires one, and a backend refuses an event
that carries anything else.

- **The marker and `SET`.** A malformed value refuses the statement or the SET, with a message that
  repeats nothing of the value. A marker value over 512 bytes is refused whole (a cut would lose its
  runId).
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

A run belongs to the job `acl_lineage_job`, or `sql:<hash of the normalized statement>`, in the
namespace `<ns>/client/<door>` (`acl://dev/client/flight` for the namespace `acl://dev`), with or
without a parent.

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

All are GLOBAL and can be cluster-profile items (restart class): `acl_lineage_namespace`, `_level`,
`_max_edges` and `_buffer` are on the `cluster` bundle's list; `_identity`, `_sql` and `_physical`
are `passthrough`'s.

A client's own context is three session settings, set only on a session of the client's own
(spec 068's allowlist):

| setting | |
| --- | --- |
| `acl_lineage_parent` | the parent run, `<namespace>/<job>/<UUID>` |
| `acl_lineage_root_parent` | the root run, the same form |
| `acl_lineage_job` | the job name, free text |

## For the operator

- `acl_lineage_status()` - `on`, `off`, or why nothing is sent; an `observe` admin reads the same
  as the view `platform.lineage_status` (status, sending, level, namespace).
- `acl_lineage_source(alias, identity)` - a source's identity (above).
- `acl_lineage_events()` - the ring: one row per event - `ts, seq, node, event_type, job_namespace,
  job_name, run_id, parent, approximate, truncated, payload` (the payload as JSON).
- `acl_lineage_flush()` - waits for the worker (runs and static events) and the audit queue.
- `acl_lineage_resend([vcat])` - sends every object's `DATASET` event again (tables, views, table
  functions), for a transport that starts on an empty catalog.
- The counters `acl.lineage.events{event_type}`, `acl.lineage.approximate`, `acl.lineage.dropped`
  (the worker's queue holds 1000 items; past that an item is dropped and counted),
  `acl.lineage.errors` (a worker job that failed) and `acl.lineage.parent_invalid{door}`.

None of these is a principal's - but the one below.

## A catalog's definitions, on demand

A backend that takes no `DATASET` event - OpenMetadata, as of 2.0.5 - can still learn what each virtual
object is made of: `acl_lineage_definitions([catalog])` answers it as rows, walked when it is called (the
same walk as the `DATASET` event, never the ring), one row per edge:

```sql
SELECT catalog, schema, object, field, source_namespace, source_name, source_field, type, subtype, masking
FROM acl_lineage_definitions('sales');
-- sales  main  orders  city   acl://prod/source/pg  main.orders  address.city  DIRECT    IDENTITY     false
-- sales  main  totals  total  acl://prod/source/pg  main.orders  amount        DIRECT    AGGREGATION  false
-- sales  main  totals         acl://prod/source/pg  main.orders  tenant        INDIRECT  GROUP_BY     false
```

The columns: `catalog, schema, object, object_type` (TABLE / VIEW), `namespace` (`acl_lineage_namespace`),
`field` (empty: an edge to the whole object - a filter, join or group key), `source_namespace`, `source_name`,
`source_field` - the names of [Names](#names) and [a source's identity](#a-sources-identity), a source without one
as `<namespace>/source/<alias>` - `type`, `subtype`, `masking` (the object's own mask over that column), and
`approximate` (the definition did not bind exactly). An object with no edge (constants only) has one row with no
source. Tables and views; a table function's lineage is its `DATASET` event's.

- **The operator** reads every catalog (no argument) or one.
- **A principal** reads it only where its catalog grant names the explicit capability **`lineage`** - never in the
  unstated default, never implied (`GRANT CATALOG sales TO ROLE om_connector WITH (select, lineage)`): an edge
  names the physical objects a definition is made of, as a plan does. And only what the role sees: an object it
  cannot select, or a column it does not see, has no row. The call is answered by the node from the principal's
  own listings - the role needs no administration and no `ACL NATIVE`.
- It needs a policy catalog and a lineage namespace; `acl_lineage_level` may be off (nothing is sent, the
  definitions still answer).

## How it is safe

- **No principal reads lineage events.** They go to the sinks that ask for them, never to the audit file
  or `acl_audit_events()`. A principal reads a catalog's definitions only under the explicit `lineage`
  capability, and only what it sees (above).
- **Never in a payload:** a value, a literal, a claim, a token, a session handle, a mask's or a
  predicate's text, and the statement's text unless `acl_lineage_sql = 'normalized'`.
- **A runtime run is computed off the statement's path.** The worker mirrors what the principal
  reads (names and types) into an empty, scratch DuckDB without external access and with no
  extension of the node's loaded but the built-in function sets. It binds the statement there and
  never executes it.
