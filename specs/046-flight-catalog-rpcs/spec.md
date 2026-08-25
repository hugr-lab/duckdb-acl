# Spec 046: the Flight door answers the catalog it is asked about

- **Status**: draft
- **Date**: 2026-08-25
- **Author**: hugr-lab

## Summary

The Flight SQL door (spec 045) answers statements and nothing else. A driver that connects to it can
run SQL but cannot ask *what is there* — every ADBC and JDBC client opens by calling `GetTables`,
`GetDbSchemas` and their siblings, and gets `NotImplemented`. This adds those RPCs, answered from the
principal's own catalog: not by reading the physical catalog from inside the door, but by composing
ordinary SQL against the surfaces spec 010 and spec 035 already replace, running it through the same
`ACL SESSION` prefix every other statement takes, and reshaping the rows into the fixed schemas the
protocol defines.

## Problem

**A door you cannot browse is a door most tools will not walk through.** DBeaver, Tableau, an ADBC
notebook and every JDBC-shaped client begin with a catalog round trip; the tree in the sidebar *is*
`GetTables`. Today `FlightSqlServerBase` answers all of them with `NotImplemented`, so the door works
only for a client that already knows the names — which is the client we do not have to serve, because
it could equally use a gateway.

The quack door has never had this problem: quack's introspection is SQL, so it arrives at the parser
with a prefix on it and the ACL answers it like any other statement. The Flight door is the one place
where a *protocol* asks the question instead of a statement, and where the answer therefore has to be
composed by us.

That is the trap this spec is written to avoid. There are two obvious ways to fill in those RPCs: ask
the `PolicyStore` directly for the principal's objects, or ask the database the same question a client
would. The first is shorter and wrong — it creates a second path to the same facts, one that does not
go through the rewriter, and every future change to what a role may see would have to be made twice
and could disagree once.

## Design

### Every RPC is a statement the principal could have written

Each catalog RPC composes SQL, hands it to `PolicyStore::SessionSql` exactly as
`GetFlightInfoStatement` does, and executes the result. The door contains no knowledge of grants,
masks, schemas or visibility. It contains a mapping from a Flight command to a `SELECT`, and a mapping
from a result set to a fixed Arrow schema.

That gives the property the design is for: **there is one implementation of "what can this role see",
and the door is not it.** Spec 035's surfaces already answer `information_schema.tables`,
`information_schema.schemata` and `information_schema.columns` as the principal's own listing, with
physical facts stripped (`estimated_size`, the oids, `has_primary_key`) and a grant's projection folded
in (spec 026). When those listings are optimised — they are the 70 ms of spec 043's connect
benchmark — both doors get it at once, because there is only one thing to optimise.

| RPC | the statement behind it |
| --- | --- |
| `GetCatalogs` | `SELECT DISTINCT catalog_name FROM information_schema.schemata ORDER BY 1` |
| `GetDbSchemas` | `SELECT catalog_name, schema_name FROM information_schema.schemata` + filters |
| `GetTables` | `SELECT table_catalog, table_schema, table_name, table_type FROM information_schema.tables` + filters |
| `GetTableTypes` | `SELECT DISTINCT table_type FROM information_schema.tables ORDER BY 1` |
| `GetPrimaryKeys` | none — answers empty, see below |
| `GetImportedKeys` | `acl_references()` where the reference's `from` end is the named table |
| `GetExportedKeys` | `acl_references()` where the reference's `to` end is the named table |
| `GetCrossReference` | `acl_references()` where both ends are the named tables |

`GetTableTypes` is deliberately derived from the listing rather than returning the constants
`'BASE TABLE'`/`'VIEW'`: the protocol says the values a client may pass to `GetTables(table_types=…)`
are the ones `GetTableTypes` returned, so the two must come from the same rows or a client can filter
itself into an empty answer.

### Filters are bound, never concatenated

`db_schema_filter_pattern` and `table_name_filter_pattern` are SQL `LIKE` patterns chosen by the
client. They are bound as statement parameters (`WHERE table_schema LIKE $1`) rather than quoted into
the text. This is not the rewriter adding parameters to somebody's statement — the golden rule is
about a *user's* `$1` being the only one in a query the rewriter touched — it is the door writing its
own statement, in which the only parameters are its own.

Flight's filter semantics are followed as written, including the corner: a **null** catalog means no
filter, an **empty string** means "objects with no catalog". Every object in a virtual catalog has one,
so an empty string correctly returns nothing.

### `include_schema` comes from the columns listing, in one query

With `include_schema`, each row carries `table_schema`: the serialized IPC schema of that table. It is
built from **one** additional statement — the same `information_schema.columns` listing, filtered the
same way — rather than one statement per table:

```sql
SELECT table_catalog, table_schema, table_name, column_name, data_type, ordinal_position
FROM information_schema.columns  -- + the GetTables filters
ORDER BY table_catalog, table_schema, table_name, ordinal_position
```

The `data_type` strings become `LogicalType`s through duckdb's own
`TransformStringToLogicalType(str, context)`, and the types and names become an Arrow schema through
`ArrowConverter::ToArrowSchema` — the same converter the statement path already uses. No zero-row
chunk and no execution: `ToArrowSchema` takes types and names, not data.

**This is not a second implementation of duckdb's type mapping.** The string was produced by
`LogicalType::ToString()` and is parsed back by duckdb's own parser; the round trip is already
load-bearing in this repository, because spec 035 synthesizes `duckdb_tables().sql` as
`CREATE TABLE …(<column> <type>, …)` from these very strings and a quack client *parses and binds* it.
A test asserts the round trip over every type in the fixture, so a type that cannot survive it fails
here rather than in a client.

The obvious alternative — preparing `SELECT * FROM <name> LIMIT 0` per table, the way spec 025 answers
`DESCRIBE` — is rejected for three reasons, and the third is the one that settles it:

1. It is N+1: a statement per object, when the listing already has every column of every object.
2. Binding a view means binding *its* SQL, which reaches the physical sources. Under spec 005's
   integration setup that is a postgres, a mysql and a sqlserver touched once per view, at the moment
   a client opens its sidebar — the worst possible time to make a catalog round trip expensive.
3. **A virtual table function can never be reached that way at all.** Its result depends on its
   arguments, so there is no `SELECT * FROM f LIMIT 0` to prepare. Its result columns *are* stored,
   in `object_columns` with `kind = 'table'`, as type strings — so the string path is the only one
   that works uniformly for a table, a view and a function, and the one to build on.

Views are covered by construction: the columns listing describes a non-alias form from its stored
schema, which is what a virtual view is.

What the client is told it will receive is still what it will receive — a hidden column is absent, a
masked column carries the mask's type, a computed column the physical object never had is present
(spec 026) — because it is the same listing `DESCRIBE` and `information_schema.columns` answer with.

### References are the foreign keys

Spec 022's references are declared join paths between virtual objects — visible only when both ends
and every column they name are visible, and never enforced. That is precisely what the key RPCs
describe, so they are answered from them:

- **imported** keys of `T` — the references whose `from` end is `T` (`T` holds the referencing columns)
- **exported** keys of `T` — the references whose `to` end is `T`
- `pk_*` columns come from the `to` end, `fk_*` from the `from` end, `key_sequence` from the position
  within the reference, and both `fk_key_name` and `pk_key_name` are the reference's name
- `update_rule` and `delete_rule` are `3` (no action). They are `uint8 NOT NULL` in the protocol and a
  reference enforces nothing, so "no action" is the only honest constant

Two kinds of reference produce no key rows: one whose far end is a **table function** (a lateral call
is not a foreign key) and one declared with `ON EXPRESSION` and no column pairs (there is nothing to
put in `key_sequence`). They stay visible through `acl_references()`, which is the surface that can
describe them.

**One enabling change to spec 022's surface.** `acl_references()` renders `from_columns` and
`to_columns` with `string_agg`, which is right for a human and for an agent reading a hint. Pairing
them by position needs lists, and splitting a joined string on `', '` would break on a column name
containing one. Two columns are therefore added — `from_column_list` and `to_column_list`, the same
values as `list(... ORDER BY pos)`. Additive, so nothing that reads the surface today changes.

### The rows become the protocol's shape, not duckdb's

The response schemas are fixed by Flight SQL — taken from `SqlSchema::GetTablesSchema()` and friends
rather than written out here, so they cannot drift from the Arrow version we link. The door casts in
SQL to the duckdb types whose Arrow layout matches (`INTEGER` → `int32`, `UTINYINT` → `uint8`,
`VARCHAR` → `utf8`) and imports the resulting array *against the protocol's schema*, the same
`ArrowConverter` path `DoGetStatement` already uses.

That works only if the physical layout is what the protocol expects, and two instance settings can
change it: `arrow_large_buffer_size` turns `utf8` into `large_utf8`, and `produce_arrow_string_view`
turns it into `string_view`. A catalog answer therefore builds its client properties explicitly
instead of inheriting the instance's — a client's tree must not depend on how the server was
configured for something else.

### The ticket is the command

For a statement, the door mints an opaque ticket and remembers the SQL behind it (spec 045). A catalog
RPC needs none of that: the command *is* the request, so the ticket is the serialized command and
`FlightSqlServerBase` decodes it back for us in `DoGet`. Nothing is remembered between the two calls,
so these RPCs add no state, cannot exhaust `MAX_TICKETS`, and cannot be replayed to read as somebody
else — `DoGet` composes under whoever fetches, exactly as the statement path does.

`GetFlightInfo*` for a catalog command does not run any SQL at all: the schema is a protocol constant,
so it authenticates, returns the fixed schema and a ticket, and leaves the work to `DoGet`.

### Functions are not tables, and are not answered here

Flight SQL defines no RPC for functions — JDBC has `getFunctions` and ODBC has `SQLProcedures`, but the
protocol this door speaks has no equivalent. So there is nothing in this spec for a virtual table
function or a virtual scalar function to be returned *through*, and `GetTables` deliberately does not
list them: a parameterized function is not something a client can `SELECT * FROM`, and putting one in
the table list would produce a sidebar entry that fails when clicked.

That leaves a real gap, and it is worth naming rather than leaving implied. A principal today can
discover *that* a table function is reachable — `acl_references()` names one as the far end of a
reference (spec 022) — but cannot discover its signature or the columns it returns. Both are already
stored: `functions.params` holds the declared parameters, and `object_columns` with `kind = 'table'`
or `'scalar'` holds the result columns, either declared with `RETURNS` or probed from a macro
template. What is missing is a *surface* — `duckdb_functions()` and `information_schema.routines`
answered as the principal's own, the way spec 035 did it for the table surfaces.

That is spec 047, not this one: it is a SQL surface that both doors and every gateway client would
use, and tying it to a Flight RPC that does not exist would put it in the wrong place.

### Where it lives

`src/flight/acl_flight_catalog.cpp` holds the command → SQL mapping and the result → batch mapping;
`acl_flight_door.cpp` keeps the server class and delegates. The SQL composition is a free function in
`namespace duckdb::acl` so a C++ test can check the text it produces without a server.

## Enforcement & security

**Authentication first, on every call.** Each RPC begins with `SessionFor(context)` — the same
per-call token check the statement path uses (spec 045: a session is never bound to the peer). An
unauthenticated caller learns nothing, including whether a catalog exists.

**The door has no second way in.** Every row it returns came out of a statement that carried an
`ACL SESSION` prefix and went through the rewriter. There is no code path from the door to the
physical catalog, so no bug in the door can widen what a role sees; the worst it can do is show the
role less than it may see, or fail.

**Primary keys answer empty, on purpose.** Spec 035 already decided that `has_primary_key`,
`index_count` and the oids are properties of the *physical* table and not facts about the virtual one.
`GetPrimaryKeys` follows that rule rather than contradicting it from a different surface. The natural
way to fill it in later is the one spec 022 already established for references — a declared virtual
key, granting nothing and enforcing nothing — and that is left to a follow-up rather than smuggled in
as a physical constraint.

**References carry their own gate.** Spec 022 makes a reference visible only when both ends are
visible and every column it names is a column the role can see. The key RPCs inherit that unchanged,
because they read the same surface.

**Filter patterns are parameters.** A `table_name_filter_pattern` never reaches the parser as text, so
there is nothing to escape and nothing to get wrong.

## Testing

**C++ (`test/cpp/test_acl_flight_catalog_sql.cpp`)** — the composition is a pure function, so it is
checked without a server: that each command produces the expected statement, that a null filter and an
empty-string filter differ, that `table_types` becomes an `IN` list, and that a pattern appears as a
parameter reference rather than as text.

**End to end (`test/e2e/flight/`)** — the existing pyarrow client gains catalog calls, against the
bootstrap two roles already share:

- `GetTables` under `analyst` lists only the objects that role is granted, and under a second role a
  different set — the isolation assertion is on names the two roles do not share, not on a column
  either could compute
- `GetDbSchemas` and `GetCatalogs` agree with what `GetTables` returned
- `GetTableTypes` returns exactly the values `GetTables` produced
- `GetTables(include_schema=True)` on a table with a hidden column does not carry that column, and
  carries a masked column with the mask's type
- `GetImportedKeys` on the child of a declared reference returns its pairs in order; the same
  reference appears as `GetExportedKeys` of the parent; a reference to a table function returns nothing
- with no token, every one of them fails the same way a statement does

**Regression** — `test/sql/acl.test` covers the two new `acl_references()` columns, since that surface
is reachable without a door.

## Alternatives considered

- **Read the `PolicyStore` from inside the door.** Shorter, and it creates a second answer to "what may
  this role see" that does not pass through the rewriter. Rejected: it is exactly the duplication this
  spec exists to prevent.
- **Answer `NotImplemented` and let clients use `information_schema` over SQL.** Some tools do fall
  back; most do not, and the ones that matter build their tree from the RPCs.
- **Build `include_schema` by preparing `SELECT * FROM <name> LIMIT 0` per table.** Accurate, and the
  way spec 025 answers `DESCRIBE` — but N+1, it binds view SQL against remote sources at sidebar-open
  time, and it can never describe a parameterized table function. See above.
- **A ticket table for catalog commands, as for statements.** Unnecessary state: the command is small,
  self-describing, and safe to round-trip through the client.

## Follow-ups

- **`GetSqlInfo` and `GetXdbcTypeInfo`.** They describe the *server*, not the data, which is why they
  are not in this spec — and also why they need their own look: server metadata is the one surface that
  does not pass through a principal's prefix at all. Some drivers call `GetSqlInfo` at connect and
  degrade without it.
- **Declared virtual keys**, filling `GetPrimaryKeys` the way references filled the foreign ones — for
  virtual tables, views *and* table functions, since all three are things a client is handed rows from
  and none of them has a physical key to borrow. Tracked in `specs/BACKLOG.md`.
- **A surface for functions** (spec 047, below). Nothing in this spec publishes them, and `GetTables`
  deliberately does not list them.
- **`DoPut`** — ingest through the Flight door, which spec 042's ledger has already thought about for
  the other one.
- **Caching.** Every catalog RPC re-runs the listing. Spec 043 measured the metadata surfaces at 70 ms;
  a client that opens a tree makes several of these calls in a row. Whatever caches them should cache
  them for both doors, which is the same argument this spec makes about building them.
