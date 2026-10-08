# Lineage for OpenLineage

A node emits **lineage facts** (spec 107) for what is defined on it and for what is written through it.
The facts are column-level and field-level edges, shaped like OpenLineage's facets. A data catalog
(Marquez, DataHub, Purview, OpenMetadata) shows from them:

- what each virtual table and view is made of, down to the fields of a struct;
- which roles see which fields, plain or masked;
- what wrote into what, and on behalf of which pipeline step.

The node only makes the facts. The transport to an OpenLineage backend belongs to
[acl-otel](https://github.com/hugr-lab/acl-otel). Nothing a statement does waits on it: the statement's
own thread only copies the statement, and only when the statement is in scope.

## What is emitted

| event | when | what it says |
| --- | --- | --- |
| `DATASET` | a virtual table, view or table function is created, altered, repaired or dropped | the object's fields and their edges to the physical columns, its lifecycle, the per-role tags |
| `DATASET` (no lifecycle) | a catalog or object grant changes | the affected objects again, with the new per-role tags |
| `DATASET` | the operator's own SQL (or `ACL NATIVE`) creates, alters or drops a physical table or view | a physical view's body lineage; a table's schema |
| `NAMESPACE` | `ATTACH` / `DETACH` of a source - the operator's, or a cluster item's | `acl://<ns>/source/<alias>` and the source's type |
| `RUN_COMPLETE` / `RUN_FAIL` | a write - INSERT / UPDATE / DELETE / MERGE / CREATE TABLE AS, ingest through either door | the target's fields and where each came from |
| `RUN_COMPLETE` / `RUN_FAIL` (inputs only) | a SELECT that declared itself a step of an external job | the datasets and fields it read |

A plain SELECT, DESCRIBE, SHOW, EXPLAIN, a listing and `COPY TO` are never emitted.

## Names

- **A runtime event speaks the principal's names**: the virtual catalog, table and columns as the
  client wrote them. How a virtual object is built from physical ones is already in the catalog, from
  its `DATASET` event.
- **Datasets:**
  - virtual: `acl://<ns>/<vcat>` + `<schema>.<object>`;
  - physical: `acl://<ns>/source/<alias>` + `<schema>.<table>`.
  - `<ns>` is `acl_lineage_namespace`, by default `acl://<acl_node_group or "default">`.
- **Sources.** Each source is a namespace of its own. Relate it to the real address (host, database)
  in your catalog; the node does not know it - it may live in a secret.

## An edge

Each target field lists its sources. A source carries OpenLineage's transformation:

| transformation | type / subtype |
| --- | --- |
| a column taken as it is | `DIRECT/IDENTITY` |
| an expression, a cast, a computed column | `DIRECT/TRANSFORMATION` |
| an aggregate | `DIRECT/AGGREGATION` |
| join, filter, group, sort and window keys | `INDIRECT/JOIN`, `FILTER`, `GROUP_BY`, `SORT`, `WINDOW` - on the whole target |
| a `CASE` condition | `INDIRECT/CONDITIONAL` - on its field |
| an object's mask | `masking: true` |
| an RLS or grant predicate | `INDIRECT/FILTER` from the columns it reads - never its text |

A field path follows the `COLUMNS` spelling of spec 102: `address.city`, `items[].price`.

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
| a quack request | the same headers, from an http secret: `CREATE SECRET (TYPE http, SCOPE 'https://<door>', EXTRA_HTTP_HEADERS MAP {'x-openlineage-parent': '…'})` |
| the gateway | `ACL … LINEAGE PARENT '…' [ROOT '…'] [JOB '…'] <statement>` |

A request's headers take precedence over the session's settings.

- **The headers of an http secret** are set once per attached connection.
- **SET carries a step's own parent.** A dbt pre-hook on a quack-attached node:

  ```sql
  FROM quack_query_by_name('node', 'SET acl_lineage_parent = ''{{ env_var("OPENLINEAGE_PARENT_ID") }}''');
  ```

  A plain `SET` would run on the client.

Without a parent, a run belongs to the job `acl_lineage_job`, or `sql:<hash of the normalized
statement>`, in the namespace `acl://<ns>/client/<door>`.

## Settings

| setting | default | |
| --- | --- | --- |
| `acl_lineage_level` | `off` | `on` emits |
| `acl_lineage_namespace` | `''` | the namespace prefix; `''` = `acl://<acl_node_group or default>` |
| `acl_lineage_identity` | `client` | `none`; `client` = issuer, roles, node group; `subject` adds the token's `sub` |
| `acl_lineage_sql` | `off` | `normalized`: the SQL facet, the statement as written with every constant a `?` |
| `acl_lineage_roles` | `tags` | `datasets`: a dataset per role instead |
| `acl_lineage_physical` | `true` | `false` drops physical datasets and their edges |
| `acl_lineage_max_edges` | `4096` | edges per event before it is `truncated` |
| `acl_lineage_buffer` | `1000` | events `acl_lineage_events()` holds |

All are GLOBAL and can be cluster-profile items.

## For the operator

- `acl_lineage_events()` - the ring: one row per event, the payload as JSON.
- `acl_lineage_flush()` - waits for the worker and the audit queue.
- `acl_lineage_resend([vcat])` - sends every object's `DATASET` event again, for a transport that
  starts on an empty catalog.

None of these is a principal's.

## How it is safe

- **No principal ever reads lineage.** It goes to the sinks that ask for it, never to the audit file
  or `acl_audit_events()`.
- **Never in a payload:** a value, a literal, a claim, a token, a session handle, a mask's or a
  predicate's text, and the statement's text unless `acl_lineage_sql = 'normalized'`.
- **A runtime run is computed off the statement's path.** The worker mirrors what the principal
  reads (names and types) into an empty, scratch DuckDB without external access. It binds the
  statement there and never executes it.
