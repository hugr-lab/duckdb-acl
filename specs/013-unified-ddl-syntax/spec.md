# Spec 013: one DDL syntax for the virtual catalog

- **Status**: implemented
- **Date**: 2026-08-20
- **Author**: hugr-lab

## Summary

Management SQL grew statement by statement, so it reads like three languages at once: `ADD TABLE …
AS v.n` next to `CREATE VIRTUAL CATALOG`, bodies as quoted strings with doubled quotes, columns as a
CSV string, capabilities as JSON, predicates as a string. This spec makes it one language —
`CREATE` / `ALTER` / `DROP` / `COMMENT ON` / `GRANT` / `REVOKE`, inline bodies, real lists — and
replaces the silent upsert of `ADD` with explicit existence semantics. The old forms keep working.

This is the first of four parts implementing design 004; the rest (schemas as objects, schema-level
grants, DDL through ACL) all add clauses to *this* grammar, which is why it goes first.

## Problem

```sql
-- today
ACL ADMIN ADD TABLE phys.main.orders AS sales.orders COLUMNS 'id,amount,ssn=NULL' RLS 'tenant = acl_claim(''tenant'')';
ACL ADMIN GRANT CATALOG sales TO ROLE analyst CAPS '{"select": true}' MAIN;
```

- **`ADD` is a silent upsert.** A typo in the name creates a second object instead of changing the
  intended one, and nothing says so. That is tolerable while only an operator writes these; it stops
  being tolerable in part 4, where a role with `create` runs DDL through the ACL.
- **Bodies are quoted strings**, so every `'` in a predicate doubles: `'tenant = acl_claim(''tenant'')'`.
  It is unreadable, and it is the single most common source of mistakes when writing policy by hand.
- **Lists are not lists**: `COLUMNS '<csv>'`, `CAPS '<json>'`, `AUDIENCES '<csv>'` — three encodings
  for the same idea, none of which the parser checks.
- `ADD` exists only because `CREATE TABLE` is duckdb's; the `VIRTUAL` marker already solves that
  (`CREATE VIRTUAL TABLE` cannot collide), so the verb can be the SQL one.

## Design

### The statements

```sql
CREATE [OR REPLACE] VIRTUAL CATALOG sales [COMMENT '…'];
CREATE VIRTUAL CATALOG IF NOT EXISTS sales;

CREATE VIRTUAL TABLE sales.orders AS phys.main.orders
  [ COLUMNS (order_id = id, total = amount) ]        -- renames: writable (spec 010 part 2b)
  [ COLUMNS (id, amount, ssn = NULL) ]               -- projection/masks: read-only subquery
  [ RLS (tenant = acl_claim('tenant')) ]
  [ COMMENT '…' ];

CREATE VIRTUAL VIEW sales.stats [(orders BIGINT, top INTEGER)] AS
  SELECT count(*) AS orders, max(amount) AS top FROM phys.main.orders;

CREATE VIRTUAL TABLE FUNCTION sales.report(threshold INTEGER) RETURNS TABLE (id INTEGER, amount INTEGER) AS
  SELECT id, amount FROM phys.main.orders WHERE amount >= acl_arg(1);
CREATE VIRTUAL TABLE FUNCTION sales.rng ALIAS OF range;

CREATE VIRTUAL SCALAR sales.shout(text VARCHAR) RETURNS VARCHAR AS upper(acl_arg(1));
CREATE VIRTUAL SCALAR sales.lc ALIAS OF lower;

CREATE ROLE analyst [CLAIMS (tenant = 'acme')];
CREATE ISSUER 'https://…' KEYS '…' [AUDIENCES ('api://hugr')] [ALGS (RS256, ES256)]
  [ROLE CLAIM 'groups'] [CLAIM MAP (tid => tenant, oid => user_id)];

GRANT CATALOG sales TO ROLE analyst WITH (select, insert) [MAIN] [RLS (…)] [COLUMNS (…)];
GRANT TABLE sales.orders TO ROLE analyst WITH (select) COLUMNS (tenant = acl_claim('tenant'), id);
```

`ALTER VIRTUAL … SET <property>` and `DROP VIRTUAL …` keep their shape; `DROP` gains `IF EXISTS`.

### The three rules that make it one language

1. **Inline bodies.** Everything after `AS` (or inside `RLS (…)` / `COLUMNS (…)`) is taken verbatim,
   scanned with quote and paren awareness up to the statement's end. No doubled quotes. The quoted
   form stays valid — a gateway generating SQL programmatically prefers it.
2. **Lists are lists.** `COLUMNS (…)`, `WITH (…)`, `CLAIMS (…)`, `AUDIENCES (…)`, `ALGS (…)`,
   `CLAIM MAP (a => b)`. CSV/JSON remain the storage format and the admin functions' input, so
   nothing about the catalog schema changes here.
3. **Existence is explicit.** `CREATE` fails if the object exists, `CREATE OR REPLACE` overwrites,
   `CREATE … IF NOT EXISTS` skips, `DROP … IF EXISTS` makes nothing-to-drop silent. The legacy
   `ADD …` forms keep upserting, so no existing script changes behaviour. `ALTER` stays strict and
   gets **no** `IF EXISTS`: an `ALTER` that silently changed nothing looks exactly like one that
   worked, which is worse than an error. This also repairs a gap - spec 010 said a missing target is
   an error, and every kind said so except the relation drop, which returned success quietly.

### What it compiles to

Nothing new underneath: the grammar keeps compiling to the same admin functions (spec 008), which
keeps parse-time free of side effects and keeps authorization (spec 009) in one place. Two additions
are needed there:

- the `acl_add_*` functions gain a trailing **mode** argument (`upsert` / `create` / `replace` /
  `skip`), defaulting to `upsert` so every current call keeps its meaning;
- the mode is checked against `CatalogObjectExists(vcat, vname, kind)` - a function's kind is part of
  its identity, so a table function and a scalar may share a name. The check and the write are two
  steps inside one admin call rather than one transaction: with the single-gateway deployment
  invariant that is safe, but a second concurrent writer would make `create` a race, and the fix is
  to move both into `WriteWithReads` (which is how `ALTER` already reads before writing).

### Unknown capabilities

Design 004 decided an unknown capability in `WITH (…)` is a warning, not an error: the vocabulary
will grow (`create`, `drop`, `temp`), and a grant written against a newer version should not fail.
There is no warning channel out of a scalar function, so: it is **stored as written and enforces
nothing**, and introspection (spec 010 part 3) is where it becomes visible — an unknown capability
that silently vanished would be worse than one that is visibly inert.

## Enforcement & security

The grammar is a front-end: authorization, provenance and the admin-scope rules of spec 009 are
unchanged, and every new form resolves to a management call the existing `ProvenanceOf` table already
knows. The one security-relevant change is the existence semantics: `CREATE` refusing to overwrite
removes the "typo creates a second object" failure, which part 4 turns from an annoyance into a way
for a role with `create` to shadow an existing name.

## Testing

`test/sql/acl_ddl_syntax.test`: every statement in both spellings (new and legacy) producing the same
stored rows; an inline predicate with single quotes stored identically to its doubled-quote twin;
`CREATE` on an existing object refused (and the refusal changing nothing), `OR REPLACE` overwriting,
`IF NOT EXISTS` keeping what is there, the same three answers from every kind, a table function and a
scalar of one name coexisting, `DROP` on a missing object refused and `IF EXISTS` silent, and the
legacy `ADD` still upserting; `WITH (select, insert)` producing
the same caps JSON as `CAPS '{…}'`; an unknown capability accepted, stored and enforcing nothing;
`ALIAS OF` for both function kinds; and the existing suites unchanged, since they are written in the
legacy syntax and must stay green.

## Alternatives considered

- **Replacing the old forms outright**: the gateway generates them and every existing test uses them;
  a flag day buys nothing when both can be accepted.
- **Parsing bodies ourselves** instead of taking them verbatim: we would have to track duckdb's
  expression grammar forever, and the body is already validated by the probe on the write path.
- **Keeping `ADD` as the verb** and adding modifiers to it: leaves two vocabularies in one language,
  which is the problem being fixed.

## Follow-ups

- The write-mode check and the write are two steps inside one admin call; moving them into one
  transaction (`WriteWithReads`) would make `create` safe against a second concurrent writer.


Parts 2–4 of design 004 extend this grammar: `CREATE VIRTUAL SCHEMA … FROM …` / `REFRESH` (schemas as
objects), `GRANT SCHEMA … WITH (…)` (schema-level caps and their materialised inheritance), and
`INTO` / `VIRTUAL ONLY` (DDL through ACL).
