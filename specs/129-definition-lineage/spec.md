# Spec 129: a catalog's definition lineage, on demand

- **Status**: implemented (owner, 2026-10-14: the `lineage` capability; a source without an identity named
  `acl://<ns>/source/<alias>`)
- **Date**: 2026-10-14
- **Author**: the agent - roadmap item 2 (owner, 2026-10-12: OpenMetadata with hugr-node / duckdb-acl); the node side
  of acl-clients spec 005 (the OpenMetadata connector)

## Problem

OpenMetadata takes no OpenLineage `DatasetEvent` (acl-clients spec 005, the 2026-10-09 spike; still true at 2.0.5,
2026-10-08). So what a node knows statically - which source columns each virtual object is made of (spec 107's
definition lineage) - never reaches it: the events go to acl-otel's transport and OpenMetadata answers them 400. The
connector of spec 005 has to ask the node for it, and today there is nothing to ask: `acl_lineage_resend([vcat])`
re-emits the events into the pipeline, it answers nothing.

## Design

- **`acl_lineage_definitions([catalog])`** - a table function: one row per definition edge of every virtual object
  of a catalog (all the caller may read without one), computed when it is called - the same `WalkDefinition` over
  the object's definition as the `DATASET` event, never the ring:

  `catalog, schema, object, object_type (TABLE / VIEW / FUNCTION), field (a field path, '' = the whole object),
  source_namespace, source_name, source_field, type (DIRECT / INDIRECT), subtype, masking, approximate`

  The names are spec 112's: a virtual object as `<vcat>.<schema>.<object>` under `acl_lineage_namespace`; a physical
  source under its identity (`<scheme>://<host:port>[/<db>]`, spec 112 §9) when one is declared, else
  `acl://<ns>/source/<alias>` - what OpenMetadata's `namespaceToServiceMapping` and its own connectors' FQNs meet.
- **A principal's surface**, like `acl_references()` (spec 022): substituted before the function gate, never the
  `acl_*` call itself. A connector reads it as the service principal it is - no admin scope, no `ACL NATIVE`.
- **Gate** (owner, 2026-10-14): an edge names physical objects, as a plan does (spec 052) - a new explicit
  capability **`lineage`** on a catalog grant - never in the unstated default, never inherited (like
  `explain`, `temp`, `secrets`) - and only the objects the role may `select`: a role reads the lineage of what it
  sees, in a catalog that was granted it. A mask is reported (`masking`), the masked expression never is.
- Under the operator (no prefix) it answers every catalog, as `acl_check_catalog` does.

## Enforcement & security

- No value, no definition text, no predicate: edges and names only (the `DATASET` event's content). An object's own
  RLS is part of its definition, so a whole-object INDIRECT/FILTER edge names the physical column it filters on -
  never the predicate; the physical names are what `lineage` grants. A grant's RLS and masks are per role and not
  part of a definition: not reported (acl-clients spec 005's later per-role tags).
- A field the role does not see (spec 102) has no row; an object it may not select has none.
- The `lineage` capability is explicit, granted per catalog; the function is refused under a principal without it.

## Testing

- sqllogictest: a view and a RENAME-form table over a memory source - the edges (identity and transformation,
  a struct field path, a masked column flagged); without `lineage` refused; an object the role cannot select absent;
  a hidden field absent.
- acl-clients spec 005 (the connector) on top: OpenMetadata in docker, the entities and the definition lineage written.

## Decisions (owner, 2026-10-14)

1. The gate is the explicit `lineage` capability per catalog, not an admin right: a read-only connector needs none.
2. A physical source without a declared identity is named `acl://<ns>/source/<alias>`, as the events name it; the
   edge is kept (OpenMetadata matches it once the source gets an identity).

## Alternatives considered

- **The OpenLineage JSON per object** (the `DATASET` payload as is): the connector would parse OpenLineage only to
  write OpenMetadata's lineage API; rows are what both it and an operator's SQL read.
- **Read the lineage ring** (`acl_lineage_events()`): the ring holds what happened recently, not the catalog's
  current definitions.

## As built

- `acl_lineage_definitions()`, `(VARCHAR)`, `(VARCHAR[])` (acl_lineage.cpp): the rows computed at init - per relation
  of the catalogs `PolicyStore::RelationDefinitionWalk` (moved out of `EmitDefinitionLineageNow`, which now calls it:
  one reading of a definition for the event and the rows), `LineageFromWalk` for the names. Tables and views; a
  table function's lineage stays its event's. `acl_lineage_physical = false` drops the physical edges here too.
- Under a principal: `BuildLineageDefinitionsSubquery` (rewriter) - one constant catalog name or none; the catalogs
  from `PrincipalCatalogsWithCap(principal, "lineage")` (any catalog grant, the explicit cap); the operator's list
  form over them, `IN` the principal's own `tables` and `columns` listings (the whole-object edge kept when the object
  is listed). Parsed outside the template cache. The substituted call is never gated again (the rewriter's own SQL).
- `lineage` joins the platform catalog's `caps` STRUCT (`platform.grants` and the other caps columns).
- Names: a source with a declared identity is named OpenLineage's way (spec 112 §9: `postgres://host:port` and
  `<db>.<schema>.<table>`), one without as `<namespace>/source/<alias>`.
- Tests: `test/sql/acl_lineage_definitions.test` - memory mode refused, no namespace refused, the operator's edges
  (identity, a nested field, a transformation, an aggregation, the group key as a whole-object edge), the mask over
  the source's column flagged, a constant without an edge, a declared identity; a principal without `lineage` refused,
  a catalog it reads but holds no `lineage` on refused, the list form refused, a hidden column and an unselectable
  view absent. `platform_views.test` with the wider `caps`.
- Found by the gate, unrelated: `acl_quack_seats.test` read the `at_capacity` refusal counter without
  `acl_audit_flush()` (counters are derived on the audit's thread) - once 0 of 1; flushed first now, as #220 did for
  the ring.
- Gate (macOS, with mssql): the build, `test/sql/*` (104 files), test-cpp, test-integration (17), test-flight (8),
  test-e2e (postgres, mssql, ducklake, pair; types), harness, clang-format, fold, thread_local, schema-check.
- Follow-ups: the DBeaver plugin offers `lineage` in its grant editor (acl-clients); the connector (acl-clients
  spec 005).
