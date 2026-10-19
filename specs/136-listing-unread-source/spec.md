# Spec 136: a listing says which source it could not read

- **Status**: accepted (the owner, 2026-10-19: «По спекам ок» - the mark names the source, as written)
- **Date**: 2026-10-19
- **Author**: Claude (with the owner)

## Summary

A listing reads only the physical facts of the sources it answers about (spec 119). A source that fails is left out
so the rest of the listing still answers: its objects are listed with no columns and no type, and nothing says why.
A client sees empty tables. An operator sees nothing at all.

The owner, 2026-10-18 (design/082, A2, before the release): the listing says it. Each object over a source that could
not be read carries a mark in its comment, the way a broken declared list does (spec 039). The node also emits an
audit event and counts it.

## Problem

`acl_physical_tables` / `acl_physical_columns` (`src/acl_platform_sources.cpp`) catch a source's failure and drop its
rows: `// a source that cannot answer is left out`.

- A Postgres that is down, a SQL Server login that expired, a DuckLake whose catalog is unreachable: a principal's
  `information_schema.tables` still lists the virtual objects over them, from the policy. Their physical facts are
  missing:
  - `table_type` and the type columns are NULL;
  - `information_schema.columns` lists no columns for them.
- DBeaver shows such a table as one with no columns, and an agent's MCP listing gets the same picture. Neither can
  tell "this table has no columns" from "its source is down".
- The operator's surfaces (`acl_check_catalog`, the audit, `/metrics`) are silent: the failure is swallowed on the
  query path.
- `platform.attached` (spec 118.3) leaves a failing source out of the admin's tree in the same way.

## Design

### The reader reports what it could not read

The physical reader keeps its rule: a failing source never fails the listing. It now also says which sources failed.
A third table function from the same reader, `acl_physical_unread(keys)`, answers one row per key whose read threw:
`(database_name, schema_name, error_class)`.

- `error_class` is the exception's type (`Exception::ExceptionTypeToString`: `IO`, `Connection`, `Permission`,
  `Catalog`, ...). It is never the message: a source's error can carry a host, a user, a path (the rule of spec
  069's ingest errors).
- A key whose database is not attached at all answers `Catalog` with "not attached". An object over a detached
  source is the same case to a reader.
- **One read per source per statement.** The three functions share a cache of the reader's results: for each key,
  its facts or its failure. The cache lives in the client context's state and is keyed by the running query.
  - Whichever of them runs first in a statement reads a key; the others answer from the cache. DuckDB orders the
    subqueries as it plans them, so no order is assumed.
  - The cache ends with the query.
  - This also stops one listing from reading a source once per inlined subquery, as it does today: `itables` and
    `icolumns` are inlined where they are joined (spec 119), each its own call. A down source then costs its timeout
    once, not once per subquery.
- Never on the function gate's open list: like its two siblings it is the listing's, substituted by the rewriter,
  and refused when a principal names it.

### The listing marks the objects over it

`MetadataListingSql` joins the failed keys like `physcols` (spec 039's broken mark). The comment of an object whose
physical catalog and schema failed becomes:

```
acl: source <database> could not be read (<class>) - its columns are not listed; <the object's own comment>
```

- **Surfaces:**
  - `information_schema.tables` (`TABLE_COMMENT`) and `duckdb_tables()` / `duckdb_views()` (`comment`), under a
    principal;
  - `platform.attached`'s schema rows for the admin.
- **Precedence:** the broken mark of spec 039 needs the source's columns, so the two never meet on one object. The
  unread mark wins: nothing about the declared list is known.
- **Columns surfaces** list nothing for such an object, as today. The tables surface is where the reason is said.
- **The Flight catalog RPCs** (`GetTables`) carry no comment in Flight SQL's schema. The mark reaches a client that
  reads the SQL listings (DBeaver through its plugin, `information_schema` readers). The RPCs stay as they are.
- **The narrowing** (spec 119) is untouched: the failed keys are those of the sources the narrowed listing read.

### The operator sees it

- **An audit event `policy` / `source_unreadable`**, carrying the source's database key and the class, with no
  principal's data.
  - It is floored to one per source and class per minute, as `acl_audit_denials_per_second` floors refusals.
  - It is counted regardless: `acl.listing.sources_unreadable{class}`. The attribute values come from a bounded set,
    the exception types.
  - A source is a database the node attached, so its key is the operator's name and no principal's data.
- **`acl_check_catalog`** already probes every relation's source off the query path (spec 039 `source_missing`).
  Nothing is added there: this spec is about the moment a listing meets the failure.

## Enforcement & security

- **No error text reaches a principal or the audit, only the exception's type.** A source's message can name a
  host, a login or a path.
- **The mark is said only for an object the principal already sees:** the join runs inside the principal's listing,
  after its policy CTEs.
  - A principal learns that a source of its own object failed, and of which class. That is less than a read of the
    object would tell it: a read fails with the source's error itself.
  - The source's database name in the mark is the physical key the object resolves to. It is the same thing a
    principal's `DESCRIBE` or a failed read would disclose.
  - The owner accepted the mark as written, naming the source (2026-10-19).
- **No new parameters** (the golden rule). `acl_physical_unread` takes the same constant key list its siblings take.
- **Fail-safe direction:** a failure still never fails the listing, which is spec 119's rule. Only the silence goes.

## Testing

- **sqllogictest** (`test/sql/acl_listing_unread_source.test`):
  - A DuckDB file attached as a source, a virtual table over it, a principal granted it.
  - DETACH the source: `information_schema.tables` lists the table with the mark (`Catalog`, not attached),
    `information_schema.columns` lists none of its columns, and the rest of the listing is unchanged.
  - Attach a database whose catalog read throws (an attach whose file is replaced by garbage, or a test hook in the
    reader): the mark names its class, never the message.
  - The object's own comment follows the mark.
  - The mark under a narrowed listing (`WHERE table_schema = …`): the narrowed read's failures only.
  - `acl_physical_unread` named by a principal is refused.
  - The audit ring has one `source_unreadable` per source per minute, and the counter counts each.
- **The admin's `platform.attached`:** the failed source's schema row is marked.
- **Integration** (`test/sql/integration/`, with the scanners): a Postgres source whose server is stopped. The mark
  says `IO` or `Connection` (whichever the scanner throws), and the text of the scanner's error, its host, is nowhere
  in the result.

## Alternatives considered

- **Failing the whole listing.** spec 119 chose the opposite on purpose: one source down must not blind a client to
  every other.
- **A warning channel.** DuckDB results have none, and Flight SQL has none for a statement's rows. A comment is what
  every client already shows.
- **The error's message in the mark.** It can carry a host, a login or a path. The class is what a reader acts on,
  and the operator's own surfaces read the source directly.
- **A column of its own** (`acl_source_status`) on the tables surfaces. It would widen the shapes that duckdb's own
  views have, which the listings keep (spec 025).

## Follow-ups

- The console (hugr-platform 003) can show the unread sources from the counter and the events.
- The Flight catalog RPCs could carry the mark if Flight SQL's `GetTables` grows a remarks column.
