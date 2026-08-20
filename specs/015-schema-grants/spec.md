# Spec 015: schema-level grants and materialised caps inheritance

- **Status**: implemented
- **Date**: 2026-08-20
- **Author**: hugr-lab

## Summary

A grant lands on a catalog or on one object; there is nothing in between. This spec adds the middle:
`GRANT SCHEMA sales.raw TO ROLE analyst WITH (select, insert)` — one grant for a whole schema,
including objects that appear in it later. Schemas nest, so inheritance has to be decided; it is
**materialised at write time** rather than walked per query, with an `inherited` flag that makes the
difference between "took the parent's capabilities" and "was given exactly those" recoverable.

Part 3 of design 004. A schema grant carries **capabilities only** — no RLS, no column list.

## Problem

After spec 012 an unstated capability means every data capability, so a catalog grant is broad and an
object grant is narrow, with no way to say "these tables, and the ones that will appear here". Worse,
a schema that grows — an expansion refreshed, or a live alias whose source gained a table — needs a
new object grant per object, so the grant lags behind the catalog it describes.

## Design

### Capabilities only

```sql
GRANT SCHEMA sales.raw TO ROLE analyst WITH (select, insert) [COMMENT 'the ingest lane'];
REVOKE SCHEMA sales.raw FROM ROLE analyst;
```

No RLS and no columns at the schema level, deliberately: a column list only means something for a
particular object, and a schema-wide predicate needs a column every table happens to have — the
multi-tenant case that motivates it is already served by the **catalog** level (spec 011), and the
specific case by the object level. So policy stays two-level (catalog → object) and the schema level
adds exactly one thing: capabilities.

`manage` is refused at this level: administering the ACL is scoped per catalog (spec 009), and a
schema-scoped manage would need a provenance rule for every management statement.

### Nesting, and why inheritance is materialised

`sales.raw.eu.orders` has several schema ancestors. Capabilities take **the most specific level that
states them**, and a level that states none inherits from the nearest ancestor that does — the rule
spec 012 already applies to object grants, one level up.

That inheritance is **computed when a grant or a schema changes**, not when a query runs: grants
change rarely, resolution runs constantly, and the stored row then answers "what does this role
actually have here?" for introspection without recomputation. Correctness rests on four rules:

- **`inherited BOOLEAN`** on the row. Without it "took the parent's capabilities" and "was given
  exactly those" are indistinguishable, and the next change to the parent either overwrites explicit
  grants or silently skips the ones that were inheriting;
- **the cascade stops at explicit rows**: a subtree under a row someone granted explicitly inherits
  from *it*, not from further up;
- **one idempotent operation** does all of it — `RematerializeSchemaCaps(vcat, path)`, "rebuild this
  subtree from the nearest ancestor that states capabilities". Grants call it, schema DDL calls it,
  and drift repair is the same call again. Idempotence is what makes the last one possible;
- **completeness**: every schema of a granted subtree gets a row, so nothing has to be recomputed on
  read.

### Resolution

`CapsExpr` gains one term between the object grant and the catalog grant: the capabilities of the
**longest schema prefix** of the written name that the role holds. Materialisation means the value is
already flattened, so this picks one row rather than composing a chain:

```
coalesce(nullif(object caps, ''), nullif(schema caps, ''), catalog caps)
```

A schema grant does not by itself make a name resolve — that is what the catalog grant and the
object records do (specs 006 and 014). It decides what may be done with what already resolves.

## Enforcement & security

The materialised rows are a cache of a decision, not a second source of truth for *access*: a role
with no catalog grant resolves nothing regardless of what a schema row says, because the grants CTE
still drives the join. `manage` never appears at this level, so no amount of schema granting can
produce administration rights. And because the cascade is one idempotent operation, a partially
applied change is repairable by running it again rather than by hand-editing rows.

## Testing

`test/sql/acl_schema_grants.test` (77 assertions): a schema grant covering the objects of a schema and the ones a
`REFRESH` adds afterwards; an object grant beating it and the schema grant beating the catalog's;
nesting — a grant on `raw` reaching `raw.eu.orders`, and a grant on `raw.eu` beating it for that
subtree; an explicit grant on a child stopping the cascade from the parent; `inherited` telling the
two apart in the stored rows; re-running the materialisation changing nothing (idempotence);
`REVOKE SCHEMA` re-pointing the subtree at the next ancestor; a schema created after the grant
picking it up; `manage` refused; and a role with no catalog grant still resolving nothing.

## Alternatives considered

- **Composing the chain at read time**: correct but pays the walk on every cache miss, and leaves
  "what does this role effectively have on this schema?" as a computation rather than a row.
- **A level column on `role_object_caps`** instead of a table: a schema grant has its own life
  (comment, and later the `INTO` target of DDL), and half the columns would stay empty.
- **Policy (RLS/columns) at the schema level**: see above — the two levels that exist already cover
  the cases, and a schema-wide predicate is a fail-closed trap when a table lacks the column.

## Follow-ups

- `create`/`drop` capabilities and the DDL path (part 4) attach to this level: "may this role create
  objects in this schema" is a schema-level question, and the `INTO` target belongs on this row.
- Introspection (spec 010 part 3) should read the materialised rows rather than recompute.
