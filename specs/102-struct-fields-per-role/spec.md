# Spec 102: fields of structured types per role

- **Status**: implemented (2026-10-07; accepted by the owner 2026-10-06, decisions at the end)
- **Date**: 2026-10-06
- **Follows**: spec 099 (types under the ACL, its follow-up), spec 011 (grant levels and the union of
  roles), spec 026 (a grant's projection is probed where it is written), spec 037/038 (a grant hides
  and masks, it never names or computes), the owner's discussion 2026-10-02 ("можно ли ограничить
  видимость полей структурных типов и их маскирование под роли?")

## Summary

A grant's `COLUMNS` list may name **fields** of a `STRUCT` column, at any depth, and through a
`LIST` / `ARRAY` of structs: `COLUMNS (id, address.city, address.geo.lat, items[].price, address.ssn = NULL)`.
A listed path keeps that field and drops the struct's other fields. `path = expr` masks one field.
The grant compiles to the expressions duckdb already has (`struct_pack`, `struct_update`,
`list_transform`), so everything spec 011/026/038 does for columns holds for fields: levels
intersect, roles unite, the projection is probed, and the listings describe what the role reads.

## Problem

Today a struct column is all or nothing. A grant shows it whole or masks it whole (`address = NULL`).
A role that may see a customer's city but not the customer's tax id inside the same `address`
needs a view per role, or a computed column the operator writes and keeps in step with the source
by hand. Nested data from document sources (MongoDB-shaped JSON, Parquet with nested schemas,
ducklake) makes this the common case, not the edge. The GraphQL layer planned over the catalog
needs the same per-field narrowing.

## Design

### 1. Paths in a COLUMNS item

```
item     := path | path '=' expression
path     := column ( '.' field | '[]' )*
```

- `address.city` - the field `city` of the struct column `address`;
- `address.geo.lat` - nested;
- `items[].price` - the field `price` of every element of the list/array `items` (`[]` steps into
  the element);
- a name is matched case-insensitively, like a column; a quoted part (`address."Zip Code"`) is a name.

The head of a path is the column. Everything spec 037 says about a column still holds for it: it
must be one the object exposes (judged where the grant is written), and the list is stored in the
object's order.

### 2. What a set of paths means: a tree per column

A grant's items for one column form a tree:

| written | the role reads |
| --- | --- |
| `address` | the whole struct |
| `address.city, address.zip` | `STRUCT(city, zip)`: only those fields, in the source's field order |
| `address, address.ssn = NULL` | the whole struct with `ssn` replaced (`struct_update`) |
| `address.ssn = NULL` alone | `STRUCT(ssn)` holding the mask - a mask lists its path like a bare one |
| `items[].price` | `LIST(STRUCT(price))` |
| `address.geo` + `address.geo.lat` | `geo` whole (the wider wins inside one grant, as `address` + `address.city` does) |

Compiled per column, NULL-preserving:

```sql
-- address.city, address.geo.lat
CASE WHEN address IS NULL THEN NULL ELSE
  struct_pack(city := address.city,
              geo := CASE WHEN address.geo IS NULL THEN NULL ELSE struct_pack(lat := address.geo.lat) END)
END AS address
-- address, address.ssn = NULL
struct_update(address, ssn := NULL) AS address
-- items[].price
list_transform(items, lambda __acl_e: struct_pack(price := __acl_e.price)) AS items
```

These are ordinary projection items, the same shape a column mask has today.

### 3. Levels and roles, at field granularity

- **Levels (spec 011, catalog → object) intersect trees.** An object grant may narrow a field set
  further or mask harder. It never re-exposes a field the catalog grant dropped.
- **Roles (spec 011's union) unite trees.** A field one role reads unmasked is read unmasked; two
  roles' field sets merge (`{city}` ∪ `{zip}` = `{city, zip}`). Two different masks on one field are
  refused, as two different column masks are today. The union happens on the trees, before
  compiling: two roles' `struct_pack` expressions are never compared as text.

### 4. Writes (owner: partial writes allowed)

A narrowed struct column stays writable, and a write touches only what the role sees. The rewrite
wraps the written value `v` (an INSERT's value, an UPDATE's SET, both branches of a MERGE). Measured
at the eb0d9df pin: an INSERT of a struct with missing fields fills them with NULL by name, and
`struct_update` keeps the fields it does not name.

| statement | `address` narrowed to `{city, zip}`, `address.tenant = acl_claim('tenant')` masked |
| --- | --- |
| UPDATE `SET address = v` | `address = struct_update(address, city := v.city, zip := v.zip, tenant := <mask>)`. Hidden fields keep their stored values. |
| INSERT `v` | `struct_pack(city := v.city, zip := v.zip, tenant := <mask>)`. Hidden fields are NULL (duckdb's cast by name). |

- **A field mask is an injected value**, exactly as a column mask is in spec 011: the role reads the
  mask and writes it, whatever it sent.
- **A written field the role cannot see is refused, never dropped** (spec 011's rule for columns). The
  wrapper checks `struct_keys(v)` against the visible names and raises `error()` naming no hidden
  field, the same way spec 024 confines a row. A visible field the value lacks is duckdb's own binder
  error ("could not find key").
- **Nested paths** apply the same at each level. A NULL stored parent is built with `struct_pack`
  rather than updated (`struct_update(NULL, …)` is NULL).
- **List elements** (`items[]…`) cannot be matched element by element: is the written list's third
  element the stored third? So a column narrowed through `[]` is **not writable**, and the relation's
  other columns stay writable. The refusal is named.
- RLS confinement (spec 024) still judges the whole physical row being written.

### 5. Description, data and the clients

- The grant's projection is probed where it is written (spec 026), so `grant_columns` stores the
  narrowed type (`STRUCT(city VARCHAR)`). `information_schema.columns`, `duckdb_tables().sql` and
  `DESCRIBE` describe what the role reads, and a quack client binds the same DDL the stream carries.
- Flight's Arrow schema is the result's: a struct with only the visible children.
- Spec 099's exposure rules apply after the tree: an ENUM field kept by a path is cast like any ENUM.
  Its cast sits above the row filter; the path reads the exposed value.
- The listings' column filter (`gcolumns`, `stated(...)`) reads the head of each path, so a column
  whose fields are listed is listed.

### 6. Predicates

RLS reads the physical row (spec 099's placement), so a predicate may use a hidden field
(`address.country = acl_claim('country')`) while the role does not see it. This is the same as a
hidden column today.

### 7. The object's own COLUMNS list

The same syntax in an object's declaration (`ADD TABLE … COLUMNS (id, address.city)`) is compiled
where the object is written, checked against the source's type (decision 4): the column becomes
the expression that reads only those fields (`CompileDeclaredPaths`), and the object is the
projection form. **As built, a column narrowed by the object's own list is read-only.** The write
path rebuilds a tree from the grant, and the object stores the compiled expression, so writes go
through a narrowing that a grant states over a plain alias object. Keeping the object's paths as
paths (and teaching the listings, the drift check and the probes to read them) is a follow-up, if an
operator needs to write through an object-declared narrowing.

### 8. The catalog check

`acl_check_catalog` judges a path the way it judges a column (spec 039):
- `grant_column_missing` - a path whose field the source no longer has, on a bare path;
- `mask_broken` - a field mask that names a missing field, or does not bind (`types_incompatible` if it
  binds only before spec 099's casts).

### 9. As built (2026-10-07)

- `acl_field_paths.hpp` (header-only, `test/cpp/test_acl_field_paths.cpp`):
  - `ParseFieldPath` and the per-column `FieldNode` tree;
  - `IntersectNodes` (levels) and `UniteNodes` (roles);
  - `CompileNode` (read) and `CompileWrite` (write);
  - `ProjectedType` (what a listing describes).
- `GrantPolicy::Narrow` and `GrantUnion::Add` take the tree path only when a list holds a path, so
  today's column lists behave exactly as before. A name without `.` / `[`, or one that does not read
  as a path, is a column whatever it holds (`odd name`, `od'd`). The object's check then names a
  wrong one (spec 037's message).
- `ApplyGrantPolicy` reads a narrowed column through the compiled tree, over its physical source.
  A writable narrowed column goes to `TablePolicy::field_writes`. A tree with a `[]` step is not
  writable.
- The rewriter folds a narrowed column in four places:
  - an UPDATE's SET and a MERGE's update branch: `struct_update` of the stored value;
  - an INSERT's projection and a MERGE's insert branch: `struct_pack`;
  - a drained stream, by position.
- RETURNING refuses a narrowed column: the stored struct carries the hidden fields. SET / WHERE / ON
  read it through its tree (section 10).
- Listings: the type of a column a grant projects is `acl_listed_type(source_type, column,
  roles)`. It folds the roles' catalog/object lists and unites them as the resolver does, then
  applies the tree to the source's (exposed, spec 099) type; a mask's type comes from its role's
  probe. Two roles narrowing one struct differently are described as the union they read. Before,
  the listing took one role's probed type, which was also the pre-existing behaviour for two roles
  masking one column with different result types.
- The fields of a union come in the order the roles' lists merge (role name order, each role's
  fields in the source's order). The description and the data agree on it.
- A written value is read once per field it feeds (the written expression is substituted per
  field). A volatile expression (`random()`) evaluates per field.
- A visible field the written value lacks is duckdb's own binder error (`Could not find key "zip"`).
  It names the role's own field, never a hidden one.
- `acl_check_catalog`: a path that no longer binds is `grant_column_missing` (bare) or `mask_broken`
  (masked).

### 10. Review (2026-10-07): found and fixed

Three adversarial passes. Each fix below has a regression test in `test/sql/acl_struct_fields.test`.

- **A write statement read the physical row** (it predates this spec: a hidden *column* leaked the
  same way, specs 011/020). An UPDATE's SET or WHERE, a DELETE's WHERE, and a MERGE's ON and branch
  conditions could copy a hidden field or column into a visible one, or use it as an oracle
  (`UPDATE c SET note = hidden`, `DELETE … WHERE address.ssn = …`). Now a DML statement's own
  expressions see the target as the principal reads it (`MapReadable`, over
  `TablePolicy::visible_columns` / `narrowed_reads`):
  - a narrowed column is read through its tree, so a hidden field does not resolve;
  - a masked column is read as its mask;
  - a column outside the projection is refused.
  
  Where something else might own a name, an unqualified name that is not one of the target's plainly
  readable columns is refused: it must be qualified, since the binder would give it to the target
  whenever the other relation lacks it. "Something else" is another relation of the statement
  (UPDATE … FROM, DELETE … USING, MERGE), or the FROM of a subquery the name sits in. A subquery in
  SET / WHERE / ON is walked too (a second review pass found `SET note = (SELECT hidden)` and
  `WHERE EXISTS (SELECT 1 WHERE hidden = …)` still read the row): a name it does not own is the target's
  (correlated), judged as above. A name qualified by another relation of the statement or of the
  subquery's FROM is left to it. A lambda's parameters are their own; a derived table's body is its own
  scope (no LATERAL). A dotted name whose head is a hidden column (`address.ssn` with `address` not
  granted) is that column, refused. A masked column reads as its mask (even one computed from the
  row). A refusal names the virtual column.
- **`MERGE … WHEN MATCHED THEN UPDATE SET *` / `UPDATE BY NAME`** wrote every column the source carried,
  past the whole column policy (pre-existing). These forms are now refused under a column policy, like
  a merge's listless INSERT.
- **A field mask that reads the row** (`address.ssn = left(address.ssn, 1) || '***'`) was written
  through and destroyed the stored value. Like a column mask (spec 011), it is a mask and not an
  assignment, so a write through that column is refused.
- **The listing failed open**: when the read refuses a principal (two roles masking one field
  differently), `acl_listed_type` answered the source's full type. It now answers `"NULL"`.
- **The wider item now wins at every depth.** `address, address.geo.lat` keeps all of `geo`, and
  `items, items[].cost = 0` keeps `price`.
- **A masked field that left the source** is appended by `struct_update`; the listing now describes
  that append too. `acl_check_catalog` reports a path whose field is gone by checking the column's
  type, at the catalog level as well: a path never intersects away silently, its reads refuse.
- **A column named with a dot** (`"odd.col"`, common in Parquet/JSON sources) is a column, not a path.
  The grant stores it quoted.
  - **Compatibility:** a grant written before this spec that lists a dotted column unquoted reads as a
    path after the upgrade. `acl_check_catalog` names it, and writing the grant again fixes it.
- **A grant spelled in another case** (`ADDRESS.CITY`) listed the column twice, one copy with the full
  type. The column's name is now the object's.
- **An object's own list**:
  - it emits a column once, whatever the order of its items;
  - a field mask in it is refused, since a field mask belongs to a grant;
  - a refusal names the virtual column.

Behaviour, stated:
- `UPDATE … SET address = NULL` sets the visible fields to NULL and keeps the hidden ones (an INSERT of
  NULL inserts a NULL struct).
- A mask that changes a field's type makes the column unwritable: the cast to the stored struct fails.
- The written value is substituted once per field, and the NULL-stored branch repeats it per level,
  so the generated expression grows with depth (about 2^depth for nested narrowings).
- A principal's roles unite per object, capabilities included (spec 011). A field one role may only
  read is writable through a role that holds `update` on the column with that field visible. That is
  the union's rule, not a field rule.

## Enforcement & security

- A hidden field is not in the projection, so nothing that reads the relation sees it: `SELECT *`,
  `struct_extract`, `to_json(address)`, `DESCRIBE`, the listings, the Arrow schema, quack's DDL.
- A path is parsed, never spliced: every part is an identifier, quoted when emitted. A path with
  anything else (`address.city || x`) is refused where the grant is written. Only the part after `=`
  is an expression, exactly as a column mask's is.
- The tree union is deterministic, and a conflict refuses, never picks.
- What is not narrowed: a `MAP` (its keys are data, not schema) and a `UNION` member. They are
  shown or masked whole; a path into one is refused where the grant is written.

## Testing

- `test/sql/acl_struct_fields.test`:
  - paths, nested, list elements, NULL structs, masks with and without the whole;
  - levels intersect and roles unite (`{city}` ∪ `{zip}`); conflicting masks refused;
  - writes refused on a narrowed column and allowed on the others;
  - every listing and `typeof` agree;
  - `to_json(address)` shows no hidden field;
  - the check findings.
- quack e2e (`test/e2e/door/types.sh`): a narrowed struct and a list of structs attach and read with
  the DDL matching the stream.
- Flight: the Arrow schema of a narrowed struct.

## Alternatives considered

- **A view per role**: the status quo, and the maintenance problem.
- **Masks only (no whitelist)**: it hides values but keeps the field's existence and name visible.
  A field's name can itself be the secret (`hiv_status`).
- **Paths as JSON pointers** (`address/city`): this is not SQL. The dotted form is what duckdb
  itself reads.

## Decisions (owner, 2026-10-06)

1. List elements are written `items[].price`.
2. `address, address.ssn = NULL` is the whole struct with `ssn` masked (`struct_update`). A path alone
   is a whitelist.
3. Writes to a narrowed column are allowed, partially (section 4). List-element paths make the column
   read-only.
4. Paths are accepted in an object's own `COLUMNS` too (one parser).
5. MAP and UNION are out of scope: shown or masked whole. A path into one is refused where it is
   written.
