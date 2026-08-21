# Spec 016: DDL through the ACL — `create`, `drop`, and where the object lands

- **Status**: implemented
- **Date**: 2026-08-20
- **Author**: hugr-lab

## Summary

Until now a principal's statement could only read and write rows: the statement gate refuses anything
that is not `SELECT`/`INSERT`/`UPDATE`/`DELETE`/`MERGE`/`EXPLAIN`. This spec lets a role **create and
drop objects** through a virtual name, gated by two new capabilities and pointed at a physical target
its grant chooses — so an ingest role can materialise a table in a staging schema while everyone else
sees the same virtual schema read-only.

Part 4 of design 004, and the first time a principal's query writes to the catalog.

## Problem

Everything an ingest or transformation path needs to *make* — a landing table, a derived view — has
to be created by the gateway operator out of band, then registered as a virtual object, then granted.
The role that owns the pipeline cannot do it, and the ACL has no vocabulary for "may create here".

## Design

### Two capabilities, and what they mean at each level

| capability | on a catalog grant | on a schema grant |
| --- | --- | --- |
| `create` | may create **schemas** in it | may create **objects** in it |
| `drop` | may drop schemas | may drop objects |

They do **not** inherit across those levels — the right to add a schema is not the right to fill it,
and the reverse is equally true. Inside the schema level they inherit like any capability (spec 015),
because there the meaning is the same at every depth. Concretely: object DDL asks for a **schema**
grant that states `create` (or `drop`); a catalog grant that states them says nothing about objects.

`drop` is separate from `create` deliberately: deleting is worse than making. An ingest role that may
land tables but not remove anyone else's is the common case, and a cleanup role with `drop` and no
`create` is the mirror of it.

### Where the object lands: the grant decides

The schema declaration says *what the schema is*; the grant says where **this role** puts what it
creates. One schema can then be read-only for most and an ingest target for one, without a second
virtual schema:

```sql
GRANT SCHEMA sales.vs TO ROLE ingest  WITH (select, insert, create, drop) INTO phys.staging;
GRANT SCHEMA sales.vs TO ROLE curator WITH (create) VIRTUAL ONLY;
GRANT SCHEMA sales.raw TO ROLE analyst WITH (select, create);   -- target = the declaration
```

- **`INTO db.schema`** — the physical schema this role creates in, checked to exist when granted;
- **`VIRTUAL ONLY`** — the role may only register objects that already exist physically; a `CREATE`
  of something that is not there is refused. This is the curator who documents, never materialises;
- **no clause** — the target follows the schema's declaration: an alias creates in the schema it
  aliases, an expansion in its `origin`.

### What a statement does

```sql
ACL ROLE "ingest" CREATE TABLE vs.landing(id INTEGER, payload VARCHAR);
ACL ROLE "ingest" DROP TABLE vs.landing;
```

The name is resolved as a virtual one, the statement is retargeted at the physical schema, and the
catalog is updated to match the kind of schema:

| schema kind | physical | catalog |
| --- | --- | --- |
| **alias** | created in the aliased schema | nothing — the alias shows it immediately |
| **expansion** | created in `origin` (or `INTO`) | one `alias`-form record, marked with the schema's origin, so `REFRESH` and `PRUNE` treat it like the rest |

The record is written **after** the DDL, as a second statement of the same batch: if creating the
physical object fails, no record is left behind. The reverse order would leave the catalog claiming
an object nobody made.

`DROP TABLE` through a virtual name is the user-facing drop: it removes the physical object **and**
its record. `ACL ADMIN DROP VIRTUAL TABLE` remains the administrative one — it forgets the record and
leaves the physics alone. Two verbs, two meanings, both explicit.

### A body reads before it writes

`CREATE TABLE … AS SELECT` performs a read, and that read is gated exactly like any other: the select
side goes through the normal rewrite, so a role holding `create` cannot copy a physical table it has
no access to into a schema it owns. Without this the capability would be an exfiltration primitive —
`CREATE TABLE mine.stolen AS SELECT * FROM phys.main.secrets` — which is why the check lives here and
not in a follow-up.

`CREATE VIEW` was refused here and is allowed by **spec 018**: a view is an object of the catalog in
its own right, its body resolved once with its author's rights and its claims left as markers. The
worry recorded here — "the body would carry this principal's claims to everyone" — was half right:
baking claims is indeed wrong (and is not done), while freezing the author's *policy* is exactly what
a view is for.

### Fail-closed rules

- a `CREATE` naming a schema the role holds no `create` on is refused before anything is created;
- `VIRTUAL ONLY` refuses a `CREATE` whose physical object does not already exist — otherwise the
  clause would be a suggestion;
- `CREATE OR REPLACE` and `IF NOT EXISTS` keep duckdb's meaning for the physical object, and the
  record follows what actually happened;
- a name that resolves to an existing **virtual** object is refused rather than shadowed;
- the ACL never creates in a schema the grant did not name: with no `INTO` and an alias declaration
  pointing outside the catalog, the target is that alias' schema and nothing else.

## Enforcement & security

This is the first path where a principal's statement writes to the policy catalog, so the write is
constrained in three ways: it happens only after the physical DDL succeeded, it can only add a record
for the object just created, and its shape is fixed (`alias` form, the schema's origin) — a principal
cannot choose a form, a projection or an RLS clause. Administration (spec 009) is untouched: `create`
is a data capability, not a manage scope, and no amount of DDL produces one.

## Testing

`test/sql/acl_ddl.test` (82 assertions): a `CREATE TABLE … AS SELECT` over a table the role cannot
read refused while one over a table it can read succeeds, `CREATE VIEW` refused; a role with `create`
on a schema making a table and reading it back; the
same statement refused for a role without it; an alias schema needing no record while an expansion
gets one with the right origin (and `REFRESH`/`PRUNE` then treating it like any other record);
`INTO` sending the object to a different physical schema than the declaration; `VIRTUAL ONLY`
registering an existing object and refusing a real `CREATE`; `DROP TABLE` removing both while
`ACL ADMIN DROP VIRTUAL TABLE` removes only the record; `drop` refused without the capability;
catalog-level `create` not standing in for the schema-level one; and a failed physical `CREATE`
leaving no record behind.

## Alternatives considered

- **Creating in the schema the name resolves to, always**: then a schema is either read-only or a
  target for everyone, and the ingest case needs a duplicate virtual schema per writer.
- **Writing the record first**: a failed DDL would leave the catalog describing an object that does
  not exist — the one inconsistency this design cannot repair automatically.
- **One `ddl` capability** instead of `create`/`drop`: hands out deletion with creation, which is the
  combination operators most often do not want.

## Follow-ups

- `CREATE SCHEMA` / `DROP SCHEMA` through the catalog-level `create`/`drop`, and the auto-grant to
  the role that created a schema (design 004: a materialised row, not an implicit rule).
- Temporary tables for ingest paths (`temp` capability) — recorded separately.
- ~~`CREATE VIEW` through the ACL~~ — spec 018.
