# Spec 102: fields of structured types per role

- **Status**: accepted (owner, 2026-10-06; decisions at the end)
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

The same syntax in an object's declaration (`ADD TABLE … COLUMNS (id, address.city)`) is sugar for the
expression the operator could write today (`address = struct_pack(...)`), and it makes the
relation's other columns keep their writability (decision 4). The parser is shared. A declared list
whose only non-rename entries are paths stays in the writable alias form, and its narrowed columns
are written through section 4's wrapper.

### 8. The catalog check

`acl_check_catalog` judges a path the way it judges a column (spec 039):
- `grant_column_missing` - a path whose field the source no longer has, on a bare path;
- `mask_broken` - a field mask that names a missing field, or does not bind (`types_incompatible` if it
  binds only before spec 099's casts).

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
