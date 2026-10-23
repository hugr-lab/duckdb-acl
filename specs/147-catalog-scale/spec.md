# Spec 147: a big virtual catalog - what it costs, and what that showed

- **Status**: accepted (the owner, 2026-10-23: "да целиком можно двумя pr" - PR 1: fixes 1, 4, 7; PR 2: 2, 3, 5, 6)
- **Date**: 2026-10-23
- **Author**: hugr lab (the owner, 2026-10-23: "10к таблиц/функций представлений, причем замер как по памяти так и по
  времени ddl/dml и при запросах данных и при большом количестве ролей")

## Summary

`test/bench/catalog_scale.py` builds ONE virtual catalog - 10,000 tables, 10,000 views and 10,000 table functions over
100 schemas, on 10,000 physical tables of 11 columns - and a policy of 1,000 roles: each a catalog grant with a row
filter and a column list, ten object grants each (10,000 rows). It measures, as principals holding 1, 10 and 100 of
the roles: the policy's writes as the catalog grows, the node's memory, reads and DML cold and warm, the listings, and
what a policy write costs the next read. Most of it scales; seven places do not. This spec records the numbers and
fixes those seven.

## Method

Every measured step is its own CLI process (`/usr/bin/time` for its maximum RSS, `duckdb_memory()` at its end); a
process that only opens the sources and the policy is measured the same way and subtracted. The policy is written in
chunks of 1,000 statements, a process each, so a write's cost is seen as the catalog grows. A gateway principal
(`ACL TOKEN`, RS256, the issuer by discovery). macOS arm64, release build, main at 3260795.

## Results

**Writes** (per statement, the catalog growing from empty):

| what | count | ms each (first chunk → last) |
|---|---|---|
| role | 1,000 | 1.7 |
| catalog grant (RLS + list), before any object | 1,000 | 3.2 |
| virtual table | 10,000 | 54 → 70 |
| virtual view | 10,000 | 30 → 46 |
| table function | 10,000 | 45 → 51 |
| object grant (list) | 10,000 | 52 |
| catalog grant with RLS, at full size | 5 | **8,757** |

The policy catalog file: 21 MiB. The node with the sources and the policy open: 0.25 s, 314 MiB.

**Reads and DML** (first = the object's first resolution, warm = cached; a gateway statement, `ACL TOKEN`):

| statement | 1 role | 10 roles | 100 roles |
|---|---|---|---|
| a table, first / warm | 44 / 1 ms | 53 / 5 ms | 138 / 44 ms |
| a view | 27 / 1 ms | 34 / 6 ms | 69 / 45 ms |
| a table function | 14 / 1 ms | 19 / 5 ms | 62 / 45 ms |
| a join of two tables | 55 / 1 ms | 69 / 5 ms | 107 / 46 ms |
| INSERT under the row filter | 57 / 1 ms | 69 / 5 ms | 154 / 45 ms |
| UPDATE / DELETE | 39 / 1, 27 / 1 ms | 44 / 4, 31 / 5 ms | 89 / 55, 73 / 43 ms |
| 2,000 distinct tables, one statement each | 28 ms each | 33 ms | 75 ms |
| a policy write, then the next statement | 54 → 42 ms | 75 → 56 ms | 58 → 132 ms |

(The same 2,000 reads written natively: 0.1 ms each.)

**Memory**: what the ACL holds beyond the same reads written natively (`SELECT count(*) FROM (SELECT c0, c1, tenant
FROM t WHERE tenant = 0)`), by the number of distinct objects read: 1,000 → +78 MiB, 4,000 → +107 MiB, 8,000 → +118
MiB - bounded (the resolver's caches hold 4,096 entries, the templates 256). The rest of a node's RSS is duckdb's
buffer pool holding what was read (2 GiB of `BASE_TABLE` after 8,000 tables) - under its memory limit.

**Listings** (30,000 objects; warm time, the process's maximum RSS):

| listing | rows | 1 role | 10 roles | 100 roles |
|---|---|---|---|---|
| `information_schema.tables` | 20,000 | 0.13 s, 0.5 GiB | 0.19 s, 0.9 GiB | 0.86 s, **5.0 GiB** |
| `information_schema.columns` of one table | 4 | 0.75 s, 0.6 GiB | 0.86 s, 1.4 GiB | 3.1 s, **8.9 GiB** |
| `information_schema.columns` of one schema | 800 | 0.74 s, 0.6 GiB | 0.94 s, 1.4 GiB | 2.8 s, **9.3 GiB** |
| `information_schema.columns` | 80,000 | 0.86 s, 1.5 GiB | 1.15 s, 2.3 GiB | 4.0 s, **9.9 GiB** |
| `duckdb_tables()` | 10,000 | 1.0 s, 1.2 GiB | 1.3 s, 2.1 GiB | 4.2 s, **10.8 GiB** |
| `SHOW ALL TABLES` | 20,000 | 0.62 s, 1.0 GiB | 0.80 s, 1.7 GiB | 3.4 s, **9.4 GiB** |
| `duckdb_functions()` | - | **over 120 s** | over 120 s | over 120 s |

**After PR 1** (the same catalog, warm unless said; before → after):

| what | 1 role | 10 roles | 100 roles |
|---|---|---|---|
| a warm statement (gateway) | 1 → 0-1 ms | 5 → 0-1 ms | 44 → 2 ms |
| 2,000 distinct tables, each | 28 → 28 ms | 33 → 28 ms | 75 → 31 ms |
| `information_schema.tables` | 0.13 s → 0.07 s | 0.19 → 0.09 s | 0.86 s, 5.0 GiB → 0.26 s, 0.66 GiB |
| columns of one table | 0.75 → 0.54 s | 0.86 → 0.60 s | 3.1 s, 8.9 GiB → 1.5 s, 1.3 GiB |
| `information_schema.columns` (80,000) | 0.86 → 0.68 s | 1.15 → 0.69 s | 4.0 s, 9.9 GiB → 1.8 s, 2.2 GiB |
| `duckdb_tables()` | 1.0 → 0.76 s | 1.3 → 0.79 s | 4.2 s, 10.8 GiB → 1.9 s, 1.9 GiB |
| `SHOW ALL TABLES` | 0.62 → 0.52 s | 0.80 → 0.54 s | 3.4 s, 9.4 GiB → 1.6 s, 1.6 GiB |
| `duckdb_functions()` first / again | > 120 s → 0.44 / 0.04 s | > 120 s → 0.80 / 0.04 s | > 120 s → 3.7 / 0.04 s, 0.5 GiB |

The first functions listing of a role set still resolves functions x roles pairs (1 million with 100 roles). Writes are
PR 2's.

## Findings

1. **`duckdb_functions()` / `acl_function_columns()` resolve every visible function on its own**
   (`CallableFunctions`, spec 098/115): one policy query per function on a cold cache - minutes at 10,000 functions,
   2 s at 300.
2. **A catalog grant with a row filter probes the predicate against every relation** (`CatalogPredicateChecked`,
   spec 027: two probe queries each) - 0.3 ms a relation, 8.8 s a grant at 20,000 relations.
3. **A relation's write scans the source's whole catalog**: `SpellPhysical` (spec 116) and `PhysicalObjectExists`
   filter `duckdb_tables()` / `duckdb_views()`, which enumerate every table of every attached database first - a
   table's write 14 ms over 1,000 physical tables, 54-70 ms over 10,000.
4. **A gateway statement asks the policy, per claimed role, whether the role exists** (`RolesFor` → `RoleKnown` →
   `CatalogBackend::KnownRoles`, uncached; the rights beside it are cached): a warm statement 1 ms with one role, 5 ms
   with ten, 44 ms with a hundred. A session pays it once, at open.
5. **An object's first resolution grows with the catalog** (10 ms at 900 objects, 28 ms at 30,000; 75 ms with 100
   roles): the resolver's query folds every name it compares (`KeyFoldSql`, spec 116) over the whole `relations` /
   grants tables. Paid once per object, role set and policy version - and again for every object after any policy
   write.
6. **A write spells its name against every stored name of its catalog** (`NamesUnder`, five folded scans) - the slow
   growth of every write (a view 30 → 46 ms over 10,000).
7. **A listing's memory grows with objects × roles**: `gcolumns_all` (spec 145) joins every relation with every grant
   row of the principal's roles - 20,000 x 100 = 2 million rows, each with its caps chain (`SchemaCapsExpr`, a
   correlated subquery a row) and both lists, then a self-`NOT EXISTS` and a per-column `EXISTS` over them: 9-11 GiB
   and 3-4 s a listing with 100 roles, though the hundred grants carry ONE column list between them.

Found on the way, a correctness defect of its own: a view read under a catalog-wide column list naming a column the
view does not have fails (`Referenced column "c1" not found`) - the grant's items become the view's explicit
projection. Spec 144's follow-up named the struct-path form of it; this is the plain one. Its own spec (148).

## Design (the fixes)

1. **Functions listed in one resolution, as rows of a table function** (PR 1). The cost was three things, found in
   turn:
   - **One resolution each.** `CatalogBackend::ResolveFunctions(principal, keys)` runs the resolver's query 256 stored
     keys at a time (rows = functions x roles, so a chunk bounds what one read holds). The rows of one function go
     through the same per-row step `ResolveFunction` uses (`FunctionPolicyFrom`: caps, the select rows'
     `GrantUnion`, `ApplyFunctionGrantPolicy`, spec 146's note).
   - **SQL text.** The listing wrote each function as its own `SELECT ... UNION ALL` branch: the planner's
     decorrelation over 10,000 of them ran for minutes, and one `VALUES` of 10,000 rows took 8 s and 3 GiB to parse.
     So the rows come from `acl_principal_function_rows(roles, quack_door, columns)`: a table function in the never set,
     reached by the substitution with the principal's own roles as constants, answering 2,048 rows a chunk. Its oids
     are computed as the SQL writes them (duckdb's `Hash<string_t>`).
   - **A `DESCRIBE` per function.** `NarrowedColumns` bound the grant's wrap over every narrowed function to learn
     what is left of its declared columns. Now, as the owner asked, it reads the stored facts instead: the declared
     columns, in order, whose name the united list (`TablePolicy::granted_items`) names. A mask is typed by its text (a
     constant, a cast); one that reads a column is bound once per mask and shape. A mask naming no declared column lists
     nothing, as the read refuses. The row filter is not judged, as for a relation.

   The callable list is kept whole per role set and policy version (`callable_cache`), because 10,000 functions would
   cycle the per-name cache (4,096) on every call. `VisibleFunctions` groups the (function, role) pairs before it reads
   each function once.
   PR 2 moves the probe of an object grant's mask on a function to the grant's write, as spec 026 does for relations.
   Review of PR 1:
   - A mask is bound as ONE parsed expression, from its printed form. Its text spliced into the DESCRIBE ran a FROM
     written after it - a table function, as the node.
   - A cast is bound too: its written type (`INT8`, `TEXT`, `DECIMAL`) is not the bound one.
   - A masked column is named as the grant spells it, because REPLACE renames it.
   - `RoleSig` length-prefixes each role. It used to join them with `,`, so the role `a,b` and the role set {a, b}
     shared every cache keyed by it - the objects', the functions', the rights' and this listing's. That was older
     than this spec, and the review reproduced a read through it.
   - The new caches keep nothing computed across a version change.
   - In function mode, known roles compare as the driver spells them.
2. **The catalog grant's probe in one bind per chunk**: the predicate is judged against up to 200 relations at once
   (`SELECT 1 FROM (<source> WHERE false) WHERE <rls> UNION ALL …`); a chunk that binds is judged; one that does not is
   probed one by one as now (a source that does not bind judges nothing; the predicate failing on one is `false`).
3. **A physical name looked up, not listed**: `SpellPhysical` and `PhysicalObjectExists` ask the catalog
   (`Catalog::GetEntry` on the database and schema, case-insensitively, as `PhysicalObjectReadings` does since spec
   137) instead of filtering `duckdb_tables()` / `duckdb_views()`.
4. **Known roles cached per policy version** (PR 1): `KnownRoles` answers from a map beside `rights_cache` (roles exact,
   as they compare), cleared with it.
5. **The resolver's comparisons through a folded key column**: a generated column (or an index) with the folded key on
   `relations`, `functions`, `role_object_caps`, `schemas`, kept by the writers - the comparisons read it instead of
   folding every row. (Measured before deciding: if (5) is a schema step, it is the v24 step with `min_reader` 23.)
6. **`NamesUnder` reads the same folded column.**
7. **A listing computes per object what is per object** (PR 1, measured: the profile of a tables listing with 100
   roles had 127 million intermediate rows, 16 GB). Three changes:
   - `objects` is a semi-join (`EXISTS` over the roles' grants), so the comment marks, name parts and type facts are
     computed once per relation, not per (relation, role) pair before a `DISTINCT`.
   - The write-only fallback of `gcolumns` joins the distinct readers (`greaders`) instead of a self-join of the pairs,
     and a column's visibility reads the distinct lists (`glists`), not one row per role.
   - A level of the caps chain no row of the principal's roles holds is left out (`PrincipalCapsLevels`: any object
     grant, any schema grant with caps). Its term is NULL for every row, and the schema level is a correlated read per
     pair.

   The pairs remain, as narrow rows. Folding roles by grant shape is not needed after this. A listing as a chunked
   table function with filter pushdown (the owner's direction: 2,048-row chunks, the WHERE's constants and a join's
   dynamic filters - min/max ranges, bloom - deciding which objects are computed at all) is the next step if a
   catalog outgrows this.

## Enforcement & security

Every fix keeps the verdict: (1) runs the same per-row step over the same rows; (2) asks the same question of each
relation and falls back to the one-by-one probe whenever a chunk does not bind; (3) finds the same entry duckdb's own
bind would; (4) caches what the policy says until its version changes, as every other resolver cache; (5)/(6) compare
the same folded keys; (7) unites the same lists - the union of a set of rows is the union of its distinct rows, and a
level no row holds contributes NULL to every chain it is left out of. The function rows' table function is an `acl_*`
name (the never set): a principal cannot call it with other roles; the substitution writes its own. Its oids equal the
listings' (a test joins them). Tests pin each verdict as written today.

## Testing

- The bench: `test/bench/catalog_scale.py` (defaults = the numbers above), its results in this spec after the fixes.
- `acl_catalog_scale.test` (PR 1):
  - 300 table functions, past a resolution chunk, with a `{}` object grant and a scalar under a list. The listing
    leaves out exactly those.
  - A function's listed columns equal `DESCRIBE` of its read under a plain item, a constant mask, a cast mask and a
    mask that reads a column.
  - The rows' oids join `duckdb_databases()`'s, and every function oid is distinct.
  - A policy write is seen by the next listing.
  - A relation one role reads and another holds `{}` on is listed once, then not at all once the reader goes.
  - A claimed role the policy does not know is no role until a write makes it one.
- PR 2: a catalog grant's `rls_checked` over relations where some do not bind, one where the predicate fails, a chunk
  boundary; a physical name spelled in another case adopted; an object grant's mask on a function probed at write.

## Alternatives considered

- **Bigger caches** for (5): the first touch stays the cost; a write still empties them.
- **Skipping spec 027's probe for catalog grants**: drops a check the model relies on.

## Follow-ups

- Spec 148 (security, next): a grant's mask, computed column or RLS text must parse as exactly one expression with nothing
  after it. The write-time check (`ParseExpressionList`, the author's gate, the source gate) drops a `FROM ...` written
  after a mask, and spec 026's probe splices the text into a statement it runs. The read refuses it (the statement
  does not parse); the probes at write do not.
- Spec 149: the view read under a catalog-wide column list (above).
- spec 119's wrap: a cheap filter outside it is evaluated before its `error()`, so a listing cut by `LIMIT node+1`
  answers short instead of refusing (older, reproduced by the review).
- A listing prepared at the protocol level keeps the caps-chain levels decided at its rewrite, as every prepared read
  keeps its rewrite's policy.
