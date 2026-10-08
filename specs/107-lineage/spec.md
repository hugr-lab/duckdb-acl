# Spec 107: lineage - what the node defines and what it writes, as facts for OpenLineage

- **Status**: draft
- **Date**: 2026-10-08
- **Author**: owner + Claude
- **Follows**: the owner's discussion of 2026-10-08 (design/021-lineage, local). The specs it builds on:
  - 069 (the audit contract) and 074 (the execution profile and its `QueryEnd` hook);
  - 026 / 039 (the probes at write time) and 068 (the client-settings allowlist);
  - 093 (cluster items) and 095 (clients);
  - 099 (exposed types) and 102 (field paths).

## Summary

The node emits **lineage facts**: column-level and field-level edges, in the shape of OpenLineage's
`ColumnLineageDatasetFacet`, for what is defined on it and for what is written through it:

- virtual DDL;
- physical DDL;
- grants;
- the sources it attaches;
- DML;
- ingest.

Plain reads are not emitted. The one exception is a read inside an external job that has declared
itself.

A runtime event names what the client wrote, **before the rewrite**: the virtual catalog, table and
columns. How a virtual object is built from physical ones is already in the catalog, from the static
events. External pipelines (dbt over quack, Spark over Flight, Airflow / Python) work on top of that
static picture. Their own OpenLineage events reference our virtual datasets, and our write events
reference their runs as the parent.

The facts are a new kind in the audit contract. The transport to OpenLineage lives in acl-otel and is
specified separately. Nothing on the query path waits on it.

## Problem

An operator wants the virtual catalog in their data catalog (Marquez / DataHub / Purview / OpenMetadata):

- what each virtual table or view is made of, down to the fields of a struct;
- which roles see which fields, masked or plain;
- what wrote into what, and on behalf of which pipeline step.

Today the audit records only the objects a decision touched and their capabilities. It has no
columns, no edges and no definitions, and by its contract (069) never a physical name.

The community extension `duck_lineage` has the right hook, but does not fit:

- it sees only a physical plan;
- it re-parses the statement on the hot path;
- it injects an operator into the plan;
- it ships curl inside the node;
- it has no masking, no field paths, no roles and no remote pushdown.

## Design

### 1. Scope (owner's decisions)

| emitted | as |
|---|---|
| virtual DDL: `acl_add_relation` / `_view` / `_table_function[_alias]`, `ALTER VIRTUAL …`, `acl_drop_relation`, `REPAIR VIRTUAL TABLE` | static `DatasetEvent` with lineage and `lifecycleStateChange` |
| grants that change what a role sees: catalog / object grants, masks, field narrowing (102), revokes | static `DatasetEvent`: the per-role tags of the objects affected (§4) |
| `ATTACH` / `DETACH` of sources, and cluster items (093) | the source's namespace (§3) |
| physical DDL: CREATE / ALTER / DROP of tables and views, through a granted schema (016 / 051), `ACL NATIVE`, or an operator's unprefixed SQL | static `DatasetEvent`; for a view, the body's lineage |
| DML: INSERT / UPDATE / DELETE / MERGE / CTAS, into virtual or physical targets | runtime `RunEvent`, column lineage on the target |
| ingest: Flight (049 / 050 / 051) and quack (042) | runtime `RunEvent`: the target table, source "client" |
| a read by a declared external job (§6) | runtime `RunEvent` with inputs only |

**Not emitted:**

- a plain SELECT;
- DESCRIBE / SHOW / EXPLAIN;
- listings;
- `COPY TO`;
- SET / PRAGMA.

### 2. The fact

```
edge = target(dataset, field_path) <- source(dataset, field_path),
       transformation { type: DIRECT | INDIRECT,
                        subtype: IDENTITY | TRANSFORMATION | AGGREGATION | JOIN | GROUP_BY | FILTER
                               | SORT | WINDOW | CONDITIONAL,
                        masking: bool }
```

- A field path is spec 102's: `address.city`, `items[].price`.
- An INDIRECT edge without a target field applies to the whole target.
- A mask is `DIRECT/TRANSFORMATION, masking=true`.
- A computed column and an exposed-type cast (099) are `DIRECT/TRANSFORMATION`.
- An RLS or grant predicate is `INDIRECT/FILTER` from the columns it reads. Never its text, never a
  claim.

**Dataset names:**

- **virtual:** `acl://<namespace>/<vcat>` + `<schema>.<object>`;
- **physical:** `acl://<namespace>/source/<alias>` + `<schema>.<table>`;
- **file:** `file://…`;
- **function:** the function's dataset (`fn:` + qualified name).

`<namespace>` is the setting `acl_lineage_namespace` (GLOBAL, a cluster profile item, default
`acl://<acl_node_group or "default">`). Virtual datasets carry `symlinks` to the door names:
`quack://<host:port>` and `arrow-flight-sql://<host:port>` with `<vcat>.<schema>.<object>`. A catalog
that understands symlinks then joins them with the names external engines use. Anywhere else, the
mapping is manual, as for sources (§3).

### 3. Sources

ATTACH / DETACH, and the cluster items that attach, register a namespace
`acl://<namespace>/source/<alias>` with a facet `{type, alias}`. Its datasets get
`lifecycleStateChange` on DETACH.

Nothing finer is derived: every type has its own URL form, a database is not always there, and a
host may live in a secret. The operator relates a namespace to the real address in the catalog
itself.

### 4. Static events

The writing node emits them, once per change. They are not tied to the `policy written` event,
which every node of a cluster sees.

- **Object edges.**
  - The object's definition (declared columns, computed columns, object masks, view SQL) is bound at
    write time against its sources. The probes of 026 / 039 already bind it, so no extra bind is
    added.
  - The walker (§5.3) takes the edges `virtual field <- physical field`.
  - A virtual table function is a function dataset, with a symlink to the physical one. Its inputs
    are known only when it is a bindable SQL macro; otherwise it is opaque.
- **Per-role visibility as tags.** OpenLineage has no roles; it has `tags`, on a dataset and, with
  `field`, on a field. The tags are:
  - `acl.role.<role>` = `visible` | `masked` per field path. A field hidden from a role has no tag of
    that role.
  - `acl.role.<role>` = the capabilities, on the dataset.
  - `acl.role.<role>.rls` = `true` when a predicate applies.
  - A grant mask adds its input edges with `masking=true`, tagged with the role.
  - With `acl_lineage_roles = datasets`, the node emits one dataset per role instead: `…@<role>`, with
    a symlink to the canonical one and only the visible edges. The default is `tags`.
- **Physical view.** Its body is bound at CREATE, and its lineage is taken from that plan.
- **DROP.** `lifecycleStateChange=DROP`, no edges.

### 5. Runtime events

#### 5.1 Capture on the hot path, nothing more

**Virtual statements.** `parser_override` decides by statement type whether the statement is in
scope: DML, CTAS, or a read under a declared parent. Only then does it queue:

- a `Copy()` of the AST before the rewrite;
- the canonical names of the objects it resolved;
- a snapshot of their exposed schemas, as the role reads them (already in `TablePolicy`: names and
  types after 099 / 102);
- the lineage context (§6) and the decision's `seq`.

**The pre-optimize hook** (`OptimizerExtension::pre_optimize_function`) serves two purposes.

- For a queued virtual statement, it records the output names and types of each table-function
  `LogicalGet`, and nothing else (§5.2).
- It also captures the physical statements, which have no rewrite: `ACL NATIVE`, a granted schema's
  DDL, or the operator's unprefixed SQL.

- the root operator type is checked first, and everything out of scope returns;
- for statements in scope, the walker runs on the bound plan right there. These are writes and DDL,
  rare and administrative.

**Ingest.** The doors' existing ingest events carry the target and the columns.

#### 5.2 Shadow bind, off the hot path

A lineage worker takes the queued copy and replaces every virtual reference with
`acl_lineage_shadow('<canonical>', <snapshot id>)`. This is a table function whose bind returns the
snapshot's schema, field paths included.

The worker then binds the copy without executing it, on a connection of the store's own. The
shadows are fully qualified, so the search path does not matter. The walker (§5.3) reads the result.
Its `LogicalGet`s are the virtual datasets, so the edges come out in the principal's names.

**Every other table function call** in the copy (an admitted `read_parquet`, a scanner function) is
also replaced, by an opaque shadow. Its schema is the one the statement's own bind produced: the
pre-optimize hook (§5.1) records the output names and types of each table-function `LogicalGet`, in
plan order. So the shadow bind never calls a bind that reads a file or a source.

- **DML target.**
  - INSERT: the column list ↔ the source projection.
  - UPDATE `SET f = expr`: the field ↔ its expression.
  - MERGE: per branch.
  - DELETE: the target, and FILTER edges from its WHERE.
- **What a shadow cannot stand for** (a virtual table function with complex substitution, a call the
  hook's record does not match): the edge goes to the function dataset or to the whole object,
  marked `approximate`.
- **Remote pushdown** (DuckDB 2.0's `RemotePushdownOptimizer`). It runs on our rewritten AST before
  bind; for quack it turns a subtree into
  `quack_query_by_name('<catalog>', '<SQL>'[, use_transaction, refresh_catalog])`. In the shadow
  plan, that is a `LogicalGet` with the SQL text in its parameters.
  - The worker parses that text (no bind) for `approximate` edges into the remote catalog's dataset.
  - When the remote side is an acl node, it emits its own lineage, linked by the parent (§6).

#### 5.3 The walker

The walker goes bottom-up over the bound plan and maps each `ColumnBinding` to its sources and a
transformation. The handlers:

- Get, Projection, Filter, Join (incl. ASOF and positional);
- Aggregate, Window;
- SetOperation, CTE and recursive CTE;
- Pivot, Unnest;
- DML operators, Create.

The transformation per binding:

| plan element | transformation |
|---|---|
| a column reference | IDENTITY |
| an expression | TRANSFORMATION |
| an aggregate | AGGREGATION |
| join / filter / group / sort / window keys | INDIRECT edges of their subtype |
| `CASE` | CONDITIONAL |

`struct_extract` / `struct_extract_at` / `list_transform` with a constant key extend the field path;
a key that is not constant falls back to the whole column. The walker's shape follows `duck_lineage`'s
`ColumnLineageExtractor`, with subtypes and paths added. It is ours (MIT); nothing is linked from it.

### 6. Who and on whose behalf

**Job and parent.**

- `acl_lineage_job` - the job's name.
- `acl_lineage_parent` - OpenLineage's `OPENLINEAGE_PARENT_ID` format, `<namespace>/<job>/<runId>`.
- `acl_lineage_root_parent` - optional.

A client sets them through the channels the trace already has (069):

- the session settings on spec 068's allowlist. This spec grows the list by these three: they change
  the event's metadata, never what a statement reads or costs. On a session of the client's own
  only, as for the trace;
- Flight headers: `x-openlineage-parent`, `x-openlineage-root-parent`, `x-openlineage-job`. A
  header takes precedence over the session setting, per call;
- **quack request headers**, under the same names. A quack client sends them through an http secret
  with `EXTRA_HTTP_HEADERS` scoped to the door, read by httpfs into the request parameters. Our
  embedded server reads them through a new `sync.py` hunk, and a header takes precedence over the
  session. The client caches the parameters per attached connection, so headers carry the
  connection's context (the pipeline, the root parent) and SET carries the step's: dbt runs
  `FROM quack_query_by_name('<attached>', 'SET acl_lineage_parent = ''…''')` in a pre-hook, which
  reaches the same server session (probed 2026-10-08);
- a gateway prefix marker `LINEAGE PARENT '<id>' [JOB '<name>']`, each marker at most once, like
  TRACE.

**Without a parent:**

- the run belongs to the job `acl_lineage_job`, or `sql:<hash of the normalized text>`;
- the job's namespace is `acl://<namespace>/client/<client>`, the 095 client name.

**A declared read.** A SELECT with a parent emits a child run of that job with `inputs` only: the
virtual datasets and fields it read.

**Identity.** A run facet `acl` (producer `hugr-lab/duckdb-acl`). Its content follows
`acl_lineage_identity` = `none | client | subject`, default `client`:

- `client`: client, issuer, roles, door and node group;
- `subject`: adds `sub` as it is (owner's decision).

### 7. The SQL facet

`acl_lineage_sql` = `off` (default) | `normalized`.

- The text is rendered from our AST before the rewrite, so it is virtual and as the client wrote it.
- Every constant is `?`: no values, and no literal ever leaves the node (069).
- `dialect` = `duckdb`.

### 8. Contract and surfaces

- **The contract** (`duckdb-ext-common/contracts/acl_audit.hpp`, its charter R4: a PR there first,
  then the re-pin):
  - a kind `lineage` whose payload is `AuditLineage`: run, job and parent; inputs and outputs as
    datasets with schema (nested fields), symlinks and tags; the edges; lifecycle; `approximate`;
    `truncated`;
  - `CONTRACT_VERSION` 2 → 3, and acl-otel follows the same day;
  - the contract's rule "never physical names" gets one stated exception: physical names may appear
    **only** in a `lineage` payload, and only for the operator's sinks.
- **Delivery.**
  - Lineage events go to sinks that subscribe to the kind (`AuditSink::WantsLineage()`, default
    false) and to their own ring.
  - They never go to the base JSON-lines audit file or to `acl_audit_events()`. An auditor's file
    keeps its contract.
- **Settings:**
  - `acl_lineage_level` = `off` (default) | `on` - GLOBAL, a cluster item;
  - `acl_lineage_namespace`, `acl_lineage_identity`, `acl_lineage_sql`, `acl_lineage_roles` - GLOBAL,
    cluster items;
  - `acl_lineage_physical` = `true` (default) | `false` - drops physical datasets and edges, for a
    catalog that must not see the topology.
- **Functions:**
  - `acl_lineage_events()` - the ring, the operator's (a `manage` scope);
  - `acl_lineage([vcat])` - the static layer now, as rows; it lets acl-otel or the control plane
    re-send the static picture on demand;
  - `acl_lineage_dataset(object)` - the canonical namespace and name of a virtual object, for a
    client configuring its own integration. It reveals no more than the name it was given, and is
    admitted to principals through the function categories, like any other function;
  - the first two and every `acl_lineage_*` setting are in the never set for principals.
- **Bounds.**
  - At most `acl_lineage_max_edges` per event (default 4096), then `truncated`.
  - The lineage queue is bounded; drops are counted (`acl.lineage.dropped`) and recorded as a
    `lineage` event `dropped` with the count.
  - Metrics: `acl.lineage.events{kind}`, `acl.lineage.approximate`, `acl.lineage.shadow_us`.

## Enforcement & security

- **Nothing on the query path waits.** The hot path holds an AST copy, for statements in scope only.
  The bind, the walk, the names, the JSON and the transport are off it.
- **No principal reads lineage.** The functions and settings above are in the never set, except
  `acl_lineage_dataset`. Lineage reaches only subscribing sinks.
- **The shadow bind executes nothing and reads nothing.** Every relation in the copy is a shadow
  whose bind returns a recorded schema - a virtual object's from the policy snapshot, a table
  function's from the statement's own bind. No foreign bind (file, scanner) runs again. It runs as
  the node, but it binds a statement the principal was already allowed to run, and touches no data.
- **Never in a payload:**
  - literals (the SQL facet normalizes them);
  - claim values;
  - mask or predicate text (a mask is `masking=true` with the role's tag);
  - tokens, session handles;
  - the text of a statement unless `acl_lineage_sql` is `normalized`.
- **Physical names** appear only in lineage, and can be turned off (`acl_lineage_physical`).
- **The context settings** (`acl_lineage_parent` / `job`) are metadata. A client can name any parent
  - that is the protocol's trust model, as with `traceparent`. They cannot widen what a statement
  reads.
- **A failure stays off the decision.** A failed shadow bind or walk is an `approximate` event and a
  counted error; it never fails the client's statement.

## Testing

**sqllogictest** (`test/sql/acl_lineage.test`, memory store and catalog store), reading
`acl_lineage_events()`:

- **Static.**
  - A virtual table with a declared column, a computed column, an object mask and an exposed-type
    cast: the edges and their transformations.
  - A virtual view over a join: the edges through the join, and the JOIN keys as INDIRECT.
  - Field narrowing (102) for two roles: the tags per field path; a hidden field without a tag.
  - A grant mask: `masking=true` and the role's tag.
  - REVOKE: the tags updated.
  - DROP: lifecycle only.
  - ATTACH / DETACH: the namespace.
- **Runtime.**
  - `INSERT INTO v(a, b) SELECT x, upper(y) FROM w`: IDENTITY + TRANSFORMATION, in virtual names.
  - UPDATE `SET address.city = …` (102): a field-level target.
  - MERGE per branch; DELETE with FILTER; CTAS into a granted schema; an aggregate (AGGREGATION + GROUP_BY).
  - A physical INSERT through `ACL NATIVE`: physical names.
- **Not emitted.** A plain SELECT, DESCRIBE, SHOW, `COPY TO`: no event.
- **Context.**
  - SET `acl_lineage_parent` / `job`: the parent and job on the event.
  - A principal setting anything outside the allowlist: refused, as today.
- **Privacy.**
  - No literal in a normalized SQL facet.
  - No claim value or mask text anywhere in the payload.
  - With `acl_lineage_physical=false`, no physical dataset.
  - A principal calling `acl_lineage_events()`: refused (never set).
- **Off-path.**
  - A failing shadow bind yields `approximate` and the client's statement succeeds.
  - A full queue drops and counts.

**Integration** (`test/sql/integration/`):

- quack: the request headers and the `quack_query_by_name` SET, both reaching the run;
- remote pushdown over quack: the `approximate` edges and the remote dataset;
- Flight ingest: the run with its target.

**C++** (`test/cpp/test_acl_lineage_walker.cpp`, standalone, as the others): the walker over plans
bound from SQL on an in-memory database - the handlers, field paths through `struct_extract` and
`list_transform`, the edge cap, and a shadow bind that runs no foreign bind (a counting table
function proves it is never bound twice).

## Alternatives considered

- **Find the virtual boundary in the physical plan,** by the shape of `ReadFrom()` or by subquery
  aliases. The owner's principle makes it unnecessary: runtime speaks virtual names. It was also
  fragile: child binders are not reachable from the hook - `Binder` has a parent, no children.
- **A sentinel operator in the plan** for START / COMPLETE (`duck_lineage`). We already have
  `QueryEnd` (074), and the plan is a security boundary.
- **OpenLineage, HTTP or Kafka inside acl.** The transport belongs beside OTel in acl-otel (017 §3.7),
  off the node's process concerns.
- **Every SELECT.** Volume and noise: the static layer already says what a read can see. Declared jobs
  cover the reads that matter.
- **Lineage in the audit file.** It would break the contract's "no physical names" for every auditor.
  It is a separate kind with opt-in delivery instead.

## Follow-ups

- **acl-otel:** the OpenLineage transport (HTTP / Kafka / file), RunEvent / DatasetEvent assembly,
  re-sending the static picture from `acl_lineage()`, and an e2e against Marquez.
- **quack upstream:** forwarding a statement's `traceparent` and session options per request. That
  would let a federated node link its remote runs without a secret per neighbour. The owner writes it.
- **acl-clients:** the JDBC driver and ADBC helpers set the `x-openlineage-*` headers from Spark's
  config or Airflow's `OPENLINEAGE_PARENT_ID`.
- **The explicit lineage facet** (an OpenLineage proposal that supersedes the column-lineage facet):
  switch when it lands. The edge model is the same.
