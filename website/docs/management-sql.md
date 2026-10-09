# Management SQL reference

The policy of the extension - virtual catalogs, the objects in them, roles, issuers and grants - is
administered with a small SQL grammar. Every statement of it compiles, with no side effect at parse
time, into a call of one `acl_*` administration function (`SELECT acl_<fn>(<constants>)`), which then
runs through the normal bind -> execute path. The grammar and the functions are therefore the same
operation; use whichever a script is easier to write in. Both are listed here, family by family.

## Where management SQL runs

A statement is administered from behind one of the `ACL` prefixes:

| Written as                                          | Who writes it              | What it needs                                                                                                                                                       |
| --------------------------------------------------- | -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ACL ADMIN <management statement>` (or, marker explicit, `ACL ADMIN ACL …`) | the gateway, anonymously | in the in-memory dev store: always allowed; once a policy source is enabled (`acl_use_db` / `acl_use_functions`): `SET GLOBAL acl_allow_anonymous_admin = true` |
| `ACL ADMIN <plain sql>` / `ACL ADMIN ACL NATIVE <sql>` | the gateway                | native SQL outside the virtual catalog, not rewritten; as above                                                                                                     |
| `ACL ROLE "r" ACL <management statement>`           | a principal                | a `manage` or `passthrough` administration scope (see *Batches and authorization*)                                                                                  |
| `ACL TOKEN '<jwt>' ACL <management statement>`      | a principal                | the same; `ACL SESSION '<handle>' ACL …` is the door's equivalent                                                                                                   |
| `ACL ROLE "r" ACL NATIVE <sql>`                     | a principal                | `passthrough` only                                                                                                                                                  |

`ACL ADMIN` is the native context: a statement after it that is not a management form (`CREATE
TABLE`, `INSERT`, `SELECT`, duckdb's own `ALTER TABLE` or `COMMENT ON TABLE`) is plain SQL. The
management forms are recognized by their first words - `ADD`, `GRANT`, `REVOKE`, `MAP`, `CREATE
[OR REPLACE] VIRTUAL|ROLE|ISSUER|CLIENT`, `ALTER VIRTUAL|ROLE|ISSUER|CLIENT|GRANT`, `DROP VIRTUAL|RELATION|
REFERENCE|ROLE|ISSUER|CLIENT|MAP`, `COMMENT ON VIRTUAL`, `ANALYZE VIRTUAL`, `CHECK VIRTUAL`, `REPAIR VIRTUAL` -
and a typo after one of those
is an error, never a fallthrough into native SQL.

The `acl_*` functions themselves can only be called in the native context (`ACL ADMIN SELECT
acl_…(…)`, `ACL … ACL NATIVE SELECT acl_…(…)`, or a plain connection). A principal's own query may
not name any of them.

Writing policy needs a catalog policy source enabled with `acl_use_db`. The function driver
(`acl_use_functions`) is read-only and refuses every write; without any source the store is
in-memory, where `CREATE ROLE`, `acl_define_token` and the legacy wrappers work and the virtual
catalog forms refuse.

## Notation

- `<catalog>.<name>` - a virtual name. The first component is the virtual catalog, the rest the
  path inside it: `sales.raw.orders` is object `raw.orders` of catalog `sales`. Written bare and
  dotted; identifier characters are `A-Z a-z 0-9 _`.
- `<phys>` - a physical path such as `phys.main.orders`, written dotted or as a quoted string.
- `<role>`, `<catalog>` - bare words. An issuer or a client - a bare word, or a quoted string (an
  issuer named by its URL).
- Quoted values take `'…'` or `"…"`; a doubled quote is a literal one.
- A body (after `AS` or `MACRO`) is either a quoted string or written inline to the end of the
  statement; inline text is read quote- and parenthesis-aware, so a `;` inside a literal or a
  parenthesised list does not end it.
- A list is written `( … )` or as the legacy quoted csv/JSON string; both are accepted wherever a
  list is taken. `WITH (select, insert)` and `CAPS '{"select": true, "insert": true}'` store the same.
- Keywords are case-insensitive. Statements of a batch are separated by `;`.
- Write modes on `CREATE`: `CREATE` refuses an existing object, `CREATE OR REPLACE` overwrites,
  `CREATE … IF NOT EXISTS` keeps what is there. The legacy `ADD` forms always upsert. Where a
  function takes a `mode` argument the values are `create`, `replace`, `skip` and `upsert` (or
  omitted, which is `upsert`). `DROP … IF EXISTS` makes a missing target silent; `ALTER` has no
  `IF EXISTS` - a missing target is an error.

## Choosing the policy source

There is no SQL form; these are called directly.

```sql
SELECT acl_use_db('aclcat');                 -- read policy from the ATTACHed database 'aclcat', schema 'acl'
SELECT acl_use_db('aclcat', 'acl', true);    -- init := true creates/migrates the managed schema first
SELECT acl_use_functions('{"policy_version": "pol_version", "role_catalogs": "pol_role_catalogs",
  "relations": "pol_relations", "relation_columns": "pol_columns", "schema_aliases": "pol_aliases",
  "functions": "pol_functions", "role_claims": "pol_claims",
  "function_categories": "pol_fcats", "function_category_members": "pol_fmembers", "function_grants": "pol_fgrants"}');
```

- `acl_use_db(db[, schema[, init]])` - `schema` defaults to `acl`; `init` defaults to false. A
  catalog whose `schema_version` does not match the build is refused by name.
- `acl_use_functions(slot_map_json)` - the six slots `policy_version`, `role_catalogs`, `relations`,
  `relation_columns`, `schema_aliases`, `functions` are required; every named function must be a
  registered table function. The two sources are exclusive: the last call wins. The three function
  category slots (spec 072) - `function_categories()`, `function_category_members()`,
  `function_grants()`, listings with no arguments and the columns the tables have - are declared
  together or not at all; without them the shipped seed decides what a principal may call.
- Both refuse while `allow_parser_override_extension` is `DEFAULT`, because nothing would be enforced.

## Virtual catalogs

```
CREATE [OR REPLACE] VIRTUAL CATALOG [IF NOT EXISTS] <catalog> [COMMENT '<text>']
ALTER VIRTUAL CATALOG <catalog> SET COMMENT '<text>'
DROP VIRTUAL CATALOG [IF EXISTS] <catalog> [CASCADE]
```

A virtual catalog is a shared tree of virtual names with their definitions; roles are granted
catalogs, never objects of their own. Dropping one always removes its definitions; grants held on it
by roles are removed only with `CASCADE`, otherwise the drop fails and names the roles.

```sql
ACL ADMIN CREATE VIRTUAL CATALOG sales COMMENT 'orders and customers';
ACL ADMIN DROP VIRTUAL CATALOG sales CASCADE;
```

Functions: `acl_create_catalog(vcat[, comment[, mode]])`, `acl_alter_catalog(vcat, comment)`,
`acl_drop_catalog(vcat[, cascade[, mode]])`.

## Virtual tables

```
CREATE [OR REPLACE] VIRTUAL TABLE [IF NOT EXISTS] <catalog>.<name> AS <phys>
    [COLUMNS (<item>, …)] [RLS (<predicate>)] [PRIMARY KEY (<column>, …)] [COMMENT '<text>']
ADD TABLE <phys> AS <catalog>.<name> [COLUMNS (<item>, …)] [RLS (<predicate>)]        -- legacy, upsert
```

The four clauses after `AS <phys>` come in any order. A `COLUMNS` item is one of:

| Item                       | Meaning                                                                                      |
| -------------------------- | -------------------------------------------------------------------------------------------- |
| `name`                     | expose the physical column                                                                   |
| `new_name = column`        | rename                                                                                       |
| `name = <expression>`      | a mask (`ssn = NULL`) or a computed column (`total = amount * 2`), evaluated over the physical row |
| `name NOT NULL` / `name NULL` | expose and declare nullability (spec 048); `name = <expr> NOT NULL` is the promise that lets a masked column be a key |
| `"odd name"`               | a quoted identifier means the name it quotes (spec 065); a quoted name containing `,` or `=` is refused |

Any column not listed is hidden. With no `COLUMNS` and no `RLS` the relation is an **alias**
(RENAME in place, writable); a list made only of bare names and renames keeps the alias form; a mask,
a computed column or an `RLS` predicate makes it a read-only **subquery**. `RLS` is a predicate over
the physical columns, AND-ed into every read and write; `acl_claim('<name>')` inside it is replaced
by the principal's claim. `PRIMARY KEY` is declared, never enforced; it may name only columns the
declaration has, and a masked or explicitly nullable column is refused as a key. The physical
`<phys>` is not checked at write time: a source attached later is fine.

```sql
ACL ADMIN CREATE VIRTUAL TABLE sales.created AS phys.main.orders_physical
    COLUMNS (id, amount) RLS (amount > 0) COMMENT 'positive orders';
ACL ADMIN CREATE VIRTUAL TABLE c.orders AS phys.main.orders
    COLUMNS (id = pk, tenant = internal_tenant, "odd name" = "odd name");
ACL ADMIN CREATE VIRTUAL TABLE c.masked AS phys.main.orders
    COLUMNS (id = CASE WHEN id > 0 THEN id END NOT NULL, tenant) PRIMARY KEY (id);
ACL ADMIN ADD TABLE phys.main.orders_physical AS sales.orders COLUMNS (id, amount, ssn = NULL) RLS (tenant = acl_claim('tenant'));
```

Function: `acl_add_relation(vcat, vname, phys, columns_csv, rls[, comment[, mode[, pk_csv]]])` -
`columns_csv` is the item list as csv (`id, ssn = NULL`), `pk_csv` the key columns.

Related: `ALTER VIRTUAL TABLE`, `DROP VIRTUAL TABLE` / `DROP RELATION`, `COMMENT ON VIRTUAL TABLE`
below.

## Virtual views

```
CREATE [OR REPLACE] VIRTUAL VIEW [IF NOT EXISTS] <catalog>.<name> [(<column> <TYPE> [NOT NULL | NULL], …)]
    [PRIMARY KEY (<column>, …)] [COMMENT '<text>'] AS <select>
ADD VIEW <catalog>.<name> [(<column> <TYPE>, …)] AS <select>                             -- legacy, upsert
```

A view is a full SELECT in physical names, always read-only and always wrapped as a subquery.
`acl_claim('<name>')` in the body is replaced per principal. A declared column list is stored as the
view's shape instead of probing the body at write time; `PRIMARY KEY` and `COMMENT` come before
`AS`, in either order, because the body runs to the end of the statement.

```sql
ACL ADMIN CREATE VIRTUAL VIEW sales.mine AS SELECT id, amount FROM phys.main.orders_physical WHERE tenant = acl_claim('tenant');
ACL ADMIN CREATE VIRTUAL VIEW c.stats (day VARCHAR NOT NULL, total INTEGER) PRIMARY KEY (day)
    AS 'SELECT tenant AS day, sum(amount)::INTEGER AS total FROM phys.main.orders GROUP BY 1';
ACL ADMIN CREATE VIRTUAL VIEW sales.created_view (n BIGINT) COMMENT 'row count' AS SELECT count(*) AS n FROM phys.main.orders_physical;
```

Function: `acl_add_view(vcat, vname, select_sql[, returns[, comment[, mode[, pk_csv]]]])` -
`returns` is the declared column list (`day VARCHAR NOT NULL, total INTEGER`).

### Column types (spec 099)

How a column's type is exposed - in the rows and in every listing alike - is the node's setting,
overridden per object:

| | values | node setting (`SET GLOBAL`, or the cluster profile) | default |
| --- | --- | --- | --- |
| an extension's alias type (`MSSQL_VARCHAR(n)`) | `base` (its base type) / `keep` | `acl_alias_types` | `base` |
| an ENUM, at any depth of a struct, list, map, array or union | `varchar` / `keep` | `acl_enum_types` | `keep` |

```sql
ACL ADMIN ALTER VIRTUAL TABLE c.accounts SET TYPES (enums = varchar);
ACL ADMIN ALTER VIRTUAL TABLE c.legacy SET TYPES (aliases = keep, enums = default);  -- default = the node's
```

A key not written keeps its value; an operator's redefinition (`ALTER … SET RLS`, `CREATE OR REPLACE
VIRTUAL …`) keeps both - a principal's own `CREATE` registers a fresh record, as it does its comment.
The cast sits above the row filter: predicates read the physical values, the projection and masks
the exposed ones. The types are probed where the object is written and stored (`relation_types`); `SET TYPES`
and `ANALYZE VIRTUAL TABLE` probe them again. `base` is what lets a quack client without the source's
extension attach the catalog at all; `keep` is for clients that have it. `varchar` hides an ENUM's
labels from readers (see the security model).

## Virtual schemas

```
CREATE [OR REPLACE] VIRTUAL SCHEMA [IF NOT EXISTS] <catalog>.<path> AS <phys schema> [COMMENT '<text>']    -- live alias
CREATE [OR REPLACE] VIRTUAL SCHEMA [IF NOT EXISTS] <catalog>.<path> FROM <phys schema> [COMMENT '<text>']  -- expansion
ADD SCHEMA <phys schema> AS <catalog>.<path>                                                            -- legacy alias, upsert
ALTER VIRTUAL SCHEMA <catalog>.<path> SET PHYS <phys schema>
ALTER VIRTUAL SCHEMA <catalog>.<path> REFRESH [PRUNE]
DROP VIRTUAL SCHEMA [IF EXISTS] <catalog>.<path> [CASCADE]
```

- `AS <phys>` records a **live alias**: any name under the prefix resolves through it in place, a
  table added physically is visible at once, and nothing under it can be excluded.
- `FROM <phys>` records an **expansion**: the physical schema is read once, at write time, and one
  alias-form relation record is written per object it holds. A table created physically later is
  invisible until `REFRESH`. Records may then be edited or dropped individually; a record an admin
  changed with `ALTER` stays part of the expansion, one rewritten with `CREATE OR REPLACE` leaves it.
- `REFRESH` adds records for objects that appeared and never rewrites an existing one; records
  dropped on purpose are not re-added. `PRUNE` also removes records whose physical object is gone,
  but only the ones the expansion itself produced. The call returns how many records changed.
  `REFRESH` on a live alias is an error.
- `SET PHYS` retargets an alias. A path may nest (`sales.raw.eu`).
- An expansion's records are relations of the catalog in their own right, so the schema is dropped
  with them only under `CASCADE`; without it the drop fails and says how many would be orphaned.

```sql
ACL ADMIN CREATE VIRTUAL SCHEMA sales.raw AS phys.main COMMENT 'everything in main, live';
ACL ADMIN CREATE VIRTUAL SCHEMA sales.curated FROM phys.main;
ACL ADMIN ALTER VIRTUAL SCHEMA sales.curated REFRESH PRUNE;
ACL ADMIN DROP VIRTUAL SCHEMA sales.curated CASCADE;
```

Functions: `acl_add_schema_alias(vcat, path, phys[, comment[, mode]])`,
`acl_expand_schema(vcat, path, phys[, comment[, mode]])`,
`acl_alter_schema_alias(vcat, path, phys)`, `acl_refresh_schema_objects(vcat, path[, prune])`
(returns BIGINT), `acl_drop_schema_alias(vcat, path[, mode[, cascade]])`.

## Virtual functions

```
CREATE [OR REPLACE] VIRTUAL TABLE FUNCTION [IF NOT EXISTS] <catalog>.<name>[(<param> <TYPE>, …)]
    [RETURNS [TABLE] (<column> <TYPE> [NOT NULL | NULL], …)] [PRIMARY KEY (<column>, …)] [COMMENT '<text>']
    AS <select template>
  | ALIAS OF <physical function> [COMMENT '<text>']

CREATE [OR REPLACE] VIRTUAL SCALAR [IF NOT EXISTS] <catalog>.<name>[(<param> <TYPE>, …)]
    [RETURNS <TYPE>] [COMMENT '<text>']
    AS <expression template>
  | ALIAS OF <physical function> [COMMENT '<text>']

ADD TABLE FUNCTION <catalog>.<name>[(<param> <TYPE>, …)] [RETURNS [TABLE] (<column> <TYPE>, …)]
    MACRO <select template> | ALIAS [OF] <physical function>                              -- legacy, upsert
ADD SCALAR <catalog>.<name>[(<param> <TYPE>, …)] [RETURNS <TYPE>]
    MACRO <expression template> | ALIAS [OF] <physical function>                          -- legacy, upsert
```

Two forms per kind. A **macro** (`AS` / `MACRO`) is a template in physical names: `acl_arg(n)` stands
for the caller's n-th argument, `acl_claim('<name>')` for a claim; a table-function macro expands as
a read-only subquery, a scalar macro as an expression. An **alias** (`ALIAS OF`) retargets the call
to a physical function in place. The parameter list types the probe that derives the result schema;
a declared `RETURNS` replaces the probe. `PRIMARY KEY` is accepted on a table function only, after
`RETURNS`, and describes the result; a scalar cannot carry one. The clause order is as written above:
parameters, `RETURNS`, `PRIMARY KEY`, `COMMENT`, then the body or `ALIAS OF`. A table function and a
scalar of the same name are different objects.

```sql
ACL ADMIN CREATE VIRTUAL TABLE FUNCTION sales.created_fn(threshold INTEGER) RETURNS TABLE (id INTEGER) COMMENT 'big orders'
    AS SELECT id FROM phys.main.orders_physical WHERE amount >= acl_arg(1);
ACL ADMIN CREATE VIRTUAL TABLE FUNCTION c.perday(m INTEGER)
    RETURNS (id INTEGER NOT NULL, amount INTEGER NOT NULL) PRIMARY KEY (id)
    AS 'SELECT id, amount FROM phys.main.orders WHERE amount >= acl_arg(1)';
ACL ADMIN CREATE VIRTUAL TABLE FUNCTION sales.created_rng ALIAS OF range;
ACL ADMIN CREATE VIRTUAL SCALAR sales.created_scalar(text VARCHAR) RETURNS VARCHAR AS upper(acl_arg(1));
ACL ADMIN ADD SCALAR sales.tag MACRO acl_arg(1) || '@' || acl_claim('tenant');
```

Functions: `acl_add_table_function(vcat, vname, sql_template[, params, returns[, comment[, mode[, pk_csv]]]])`,
`acl_add_table_function_alias(vcat, vname, target[, '', '', comment[, mode]])`,
`acl_add_scalar(vcat, vname, expr_template[, params, returns[, comment[, mode]]])`,
`acl_add_scalar_alias(vcat, vname, target[, '', '', comment[, mode]])`. `params` is the parameter
list text (`threshold INTEGER`), `returns` the result declaration (`id INTEGER, amount INTEGER` for a
table function, `VARCHAR` for a scalar); the two empty strings of the alias forms are the unused
parameter and result slots.

## References

```
CREATE [OR REPLACE] VIRTUAL REFERENCE [IF NOT EXISTS] <catalog>.<name>
    FROM <object> TO <object> ON (<from column> = <to column>, …) | ON EXPRESSION '<sql>'
    [CARDINALITY many_to_one | one_to_many | one_to_one | many_to_many] [OPTIONAL]
    [JOIN asof | positional] [COMMENT '<text>']

CREATE [OR REPLACE] VIRTUAL REFERENCE [IF NOT EXISTS] <catalog>.<name>
    FROM <object> TO FUNCTION <table function>[(<param> => <from column>, …)]
    [ON (<from column> = <result column>, …) | ON EXPRESSION '<sql>'] [CARDINALITY …] [OPTIONAL] [JOIN …] [COMMENT '<text>']

DROP [VIRTUAL] REFERENCE [IF EXISTS] <catalog>.<name>
```

A reference is a declared join path between two objects of one virtual catalog - a hint an agent
reads through `acl_references([object])`. It is never enforced and grants nothing; a principal sees
it only when both ends and every column it names are visible. Ends are virtual names, written with or
without the reference's own catalog in front (`FROM orders` and `FROM c.orders` are the same in
`c.…`). `ON (…)` lists column pairs; `ON EXPRESSION '…'` is arbitrary SQL in which every column must
be qualified by its end. Exactly one of the two is written for a relation end. For a `TO FUNCTION`
end the parenthesis is the argument substitution - which column of the source row feeds which
parameter, checked against the declared signature - and `ON` names columns of the function's result;
either may stand alone. `CARDINALITY` and `JOIN` accept only the values listed. `OPTIONAL` says the
far side may be absent. The trailing clauses come in any order.

```sql
ACL ADMIN CREATE VIRTUAL REFERENCE c.orders_customer FROM c.orders TO c.customers
    ON (customer_id = id) CARDINALITY many_to_one COMMENT 'the ordering customer';
ACL ADMIN CREATE VIRTUAL REFERENCE c.order_rate FROM orders TO rates
    ON EXPRESSION 'orders.amount >= rates.rate' CARDINALITY many_to_one OPTIONAL JOIN asof;
ACL ADMIN CREATE VIRTUAL REFERENCE c.cust_orders FROM customers TO FUNCTION orders_of(cust => id)
    CARDINALITY one_to_many COMMENT 'the orders of this customer';
ACL ADMIN DROP VIRTUAL REFERENCE IF EXISTS c.by_secret;
```

Functions: `acl_add_reference(vcat, name, from, to[, to_kind, args, pairs, expr, cardinality, optional, join_method, comment, mode])`
with `to_kind` `relation` (default) or `function`, `args` the substitution text (`cust => id`),
`pairs` the pair list (`customer_id = id`), `optional` `'true'`/`'false'`; `acl_drop_reference(vcat, name[, mode])`.

## Roles

```
CREATE [OR REPLACE] ROLE [IF NOT EXISTS] <role> [CLAIMS (<name> = '<value>', …) | CLAIMS '<name>=<value>,…']
ALTER ROLE <role> SET CLAIMS (<name> = '<value>', …) | '<name>=<value>,…'
DROP ROLE [IF EXISTS] <role>
```

A role is an internal name that grants attach to. Its claims are defaults: they are what
`acl_claim('<name>')` answers under the bare `ACL ROLE "r"` form, and under a token they fill in only
what the token's claim map did not supply (explicit token claims win). `ALTER` replaces the whole
list. Dropping a role takes its grants, object capabilities, admin scope and mappings with it.

```sql
ACL ADMIN CREATE ROLE analyst CLAIMS (tenant = 'acme');
ACL ADMIN CREATE ROLE IF NOT EXISTS analyst;
ACL ADMIN ALTER ROLE analyst SET CLAIMS 'tenant=globex';
ACL ADMIN DROP ROLE IF EXISTS nobody;
```

Functions: `acl_define_role(role, claims_csv[, mode])`, `acl_alter_role(role, claims_csv)`,
`acl_drop_role(role[, mode])`.

## Issuers and clients

```
CREATE [OR REPLACE] ISSUER [IF NOT EXISTS] <name | '<url>'> [URL '<url>'] [FROM SECRET <s> [IN <service>]]
    [<client clause> …] [CLIENT FROM SECRET <s> [IN <service>]]
ALTER ISSUER <name> SET [URL '<url>'] [FROM SECRET <s> [IN <service>]] [<client clause> …]
ALTER ISSUER <name> DROP FROM SECRET | DROP CLIENT FROM SECRET
DROP ISSUER [IF EXISTS] <name>

CREATE [OR REPLACE] CLIENT [IF NOT EXISTS] <name> ISSUER <issuer> <client clause> … [FROM SECRET <s> [IN <service>]]
ALTER CLIENT <name> SET <client clause> … | DROP FROM SECRET
DROP CLIENT [IF EXISTS] <name>

<client clause> := AUDIENCES ('<aud>', …) | AZP ('<azp>', …)
    | REQUIRE (<path> = '<v>' | <path> IN ('<v>', …) | '<v>' IN <path> | <path> LIKE '<p>', …)
    | ROLES FROM ('<path>', …) | ROLES CONSTANT ('<role>', …) | ROLE CLAIM '<path>'
    | UNMAPPED IGNORE | UNMAPPED AS ROLE
    | ATTRIBUTES (<name> = '<path>' | <name> = ('<path>', …) | <name> = CONSTANT '<v>', …)
    | CLAIM MAP (<jwt path> => <name>, …) | CLAIM MAP '<json>'
    | SUBJECT '<path>' | SUBJECT ('<path>', …) | TOKEN TYPE '<typ>'
    | CLIENT ID '<id>' | FLOWS (password | authcode | device | client_credentials, …)
```

An issuer is the trust anchor of one IdP (spec 095); a client is which of its tokens count and what
they become. The model, the routing and the role rules are in
[authentication.md](authentication.md#issuers-and-clients-spec-095).

- **The short form.** A quoted URL in place of a name, with client clauses, is one issuer and its
  implicit client of the same name - `UNMAPPED AS ROLE`, flows `authcode, device` for a public client
  id (`password` when its `CLIENT FROM SECRET` carries a `CLIENT_SECRET`), set when it is created.
  The door's password flow is otherwise written explicitly, and only one client of a node may run it.
  `ALTER ISSUER` changes the implicit client too; `ALTER CLIENT` / `DROP CLIENT` refuse it.
- **No key and no credential here.** `KEYS`, `ALGS` and `CLIENT SECRET` are refused and name where
  they go: an `oidc_issuer` (`URL`, `KEYS`, `KEYS_FROM`, `ALGS`) or `oidc_client` (`AUDIENCES`,
  `CLIENT_ID`, `CLIENT_SECRET`) secret of the node's secrets service, named by `FROM SECRET`. Without
  them the keys come from the issuer's OIDC discovery.
- **Write checks**: one URL per issuer; every client has audiences (on it or in its secret); a
  parameter is on the object or in its secret, never both; two clients of one issuer that would
  accept the same tokens are refused (judged at use when `REQUIRE` is involved); `FLOWS` needs a
  client id; a role with an administration scope is never a `ROLES CONSTANT` nor mapped for every
  client of an issuer. A named secret must exist in the service, with the right type.
- `CREATE` refuses an existing issuer or client, `OR REPLACE` overwrites it, `IF NOT EXISTS` keeps it
  (spec 013). `DROP ISSUER` and `CREATE OR REPLACE ISSUER` take its implicit client and every mapping
  scoped to either (`DROP` is refused while an explicit client names the issuer); `DROP CLIENT` takes
  its mappings, and so does a `CREATE OR REPLACE CLIENT` that moves it to another issuer.
- A write judges what it changes: a client or mapping it did not touch is not refused again (a role
  made an administrator after it was mapped issuer-wide stops counting at use, it does not block the
  next write).

```sql
ACL ADMIN CREATE ISSUER 'https://kc/realms/x' AUDIENCES ('account') ROLE CLAIM 'realm_access.roles'
    CLAIM MAP (tid => tenant) CLIENT ID 'acl-cli';
ACL ADMIN CREATE ISSUER kc URL 'https://kc/realms/y';
ACL ADMIN CREATE CLIENT desktop ISSUER kc AUDIENCES ('account') AZP ('acl-desktop')
    ROLES FROM ('realm_access.roles') ATTRIBUTES (tenant = 'tenant') CLIENT ID 'acl-desktop' FLOWS (authcode, device);
ACL ADMIN CREATE CLIENT door ISSUER kc AUDIENCES ('account') AZP ('acl-door') ROLES FROM ('roles')
    FLOWS (password) FROM SECRET kc_door IN corp;
ACL ADMIN ALTER CLIENT desktop SET UNMAPPED AS ROLE;
ACL ADMIN DROP CLIENT door;
```

Functions: `acl_define_issuer(name, spec_json[, mode])`, `acl_alter_issuer(name, spec_json)`,
`acl_drop_issuer(name[, mode])`, `acl_define_client(name, issuer, spec_json[, mode])`,
`acl_alter_client(name, spec_json)`, `acl_drop_client(name[, mode])` - the specs are the JSON the
SQL forms compile to (authentication.md). Listings: `acl_issuers()`, `acl_clients()`.

Every location the node reads keys from - the discovery document, its JWKS, a secret's `KEYS_FROM` -
must start with a prefix in `acl_jwks_locations` (GLOBAL, default `https://`; `..` is refused
anywhere), judged where it is read (specs 071, 095).

## Role mappings

```
MAP GROUP | CLAIM '<value>' FROM CLIENT <client> | ISSUER <issuer> TO ROLE <role>
DROP MAP GROUP | CLAIM '<value>' FROM CLIENT <client> | ISSUER <issuer> TO ROLE <role>
```

A mapping turns a value found at a client's `ROLES FROM` paths into a role: `GROUP` for a group
identifier (an EntraID GUID), `CLAIM` for a plain claim value - scoped to one client, or to every
client of one issuer. One value may map to several roles; a token's roles are the union. A role that
holds an administration scope is mapped `FROM CLIENT` only.

```sql
ACL ADMIN MAP GROUP 'g-0001' FROM CLIENT desktop TO ROLE analyst;
ACL ADMIN MAP CLAIM 'ops' FROM ISSUER kc TO ROLE operator;
ACL ADMIN DROP MAP GROUP 'g-0001' FROM CLIENT desktop TO ROLE analyst;
```

Functions: `acl_map_role(scope_kind, scope, source, external_value, role)` and
`acl_drop_role_mapping(scope_kind, scope, source, external_value, role)`; `scope_kind` = `client` |
`issuer`, `source` = `group` | `claim-value`. Listing: `acl_role_mappings()`.

## Catalog grants

```
GRANT CATALOG <catalog> TO ROLE <role>
    [WITH (<capability>, …) | CAPS '<json>'] [MAIN] [RLS (<predicate>)] [COLUMNS (<item>, …)]
ALTER GRANT CATALOG <catalog> TO ROLE <role>
    SET CAPS '<json>' | SET RLS '<predicate>' | SET COLUMNS '<list>' | SET MAIN true | false
REVOKE CATALOG <catalog> FROM ROLE <role>
```

The grant that makes a catalog resolve for a role. Clauses after the role come in any order.

- **Capabilities.** `WITH (…)` is the list form of `CAPS '{"select": true, …}'`. A grant that states
  nothing holds every data capability - `select`, `insert`, `update`, `delete`, `merge` - and never
  `manage`; `CAPS '{}'` holds none. The capabilities outside that default are explicit-only and never
  implied: `manage` (administer this catalog, see below), `create`/`drop` (create/drop schemas in it),
  `temp` (session temp tables on the Flight door), `explain` (EXPLAIN) and `secrets` (the node's
  secrets service, see below), each held only when named.
  An unknown name is stored as written and enforces nothing.
- **`MAIN`** marks the catalog whose objects the role addresses unqualified. A principal with more than
  one main catalog across its roles resolves only qualified names.
- **`RLS`** is the grant's own predicate, AND-ed onto every object of the catalog for this role (and
  onto the object's own). **`COLUMNS`** is the grant's own column list, intersected with the object's;
  a name the object hides cannot be re-exposed here. A grant narrows, it never widens. Across roles the
  effective policy is the union, so a role without a narrowing grant lifts it for a principal holding
  both. A catalog-level column list is not probed for its types.
- `CAPS '{"manage": true}'` is the catalog-scoped administration scope: the role may run the
  management grammar over this catalog's content (and only that - see *Batches and authorization*).
  Managing a catalog does not imply reading it.
- `ALTER GRANT` changes one property and keeps the rest; its values are always quoted strings, and
  `MAIN` takes `true` or `false` only.

```sql
ACL ADMIN GRANT CATALOG sales TO ROLE analyst WITH (select, insert) MAIN;
ACL ADMIN GRANT CATALOG sales TO ROLE compliance CAPS '{"select": true}' MAIN RLS 'tenant = acl_claim(''tenant'')';
ACL ADMIN GRANT CATALOG c TO ROLE fnarrow WITH (select, explain) MAIN COLUMNS (amount, tenant);
ACL ADMIN ALTER GRANT CATALOG sales TO ROLE analyst SET CAPS '{"select": true, "manage": true}';
ACL ADMIN REVOKE CATALOG sales FROM ROLE auditor;
```

Functions: `acl_grant_catalog(role, vcat, caps_json[, is_main[, rls, columns]])`,
`acl_alter_grant(role, vcat, field, value)` with `field` = `caps` | `rls` | `columns` | `main`,
`acl_revoke_catalog(role, vcat)` - the revoke also removes the role's object grants and probed grant
columns in that catalog.

## Schema grants

```
GRANT SCHEMA <catalog>.<path> TO ROLE <role> [WITH (<capability>, …) | CAPS '<json>']
    [INTO <phys schema> | VIRTUAL ONLY] [COMMENT '<text>']
REVOKE SCHEMA <catalog>.<path> FROM ROLE <role>
```

The middle level of the grant chain: capabilities for everything under a schema path, including
objects that appear in it later. It carries capabilities only - `RLS` and `COLUMNS` parse but are
refused, and `manage` is refused at this level. Capabilities resolve by the longest granted prefix of
a name (`object -> schema -> catalog`); a level that states none inherits from the nearest ancestor
that does, and the inheritance is materialised when a grant or a schema changes. `REVOKE` re-points
the subtree at the next ancestor. A schema grant does not make names resolve - the role still needs
the catalog grant.

`create`/`drop` on a schema grant are the right to create/drop **objects** in it (on the catalog
grant they mean schemas; neither implies the other). Where a role's `CREATE` lands is the grant's
decision: `INTO <phys schema>` names the physical schema (checked to exist); `VIRTUAL ONLY` lets the
role only register objects that already exist physically; neither follows the schema declaration (an
alias creates in what it aliases, an expansion in its origin). A principal's own DDL then records the
object through `acl_register_created` / `acl_register_existing` / `acl_register_view`, which a
principal cannot call directly.

```sql
ACL ADMIN GRANT SCHEMA sales.raw TO ROLE analyst WITH (select) COMMENT 'raw zone, read only';
ACL ADMIN GRANT SCHEMA sales.vs TO ROLE ingest WITH (select, insert, create, drop);
ACL ADMIN GRANT SCHEMA sales.vs TO ROLE lander WITH (select, create) INTO phys.staging;
ACL ADMIN GRANT SCHEMA sales.vs TO ROLE curator WITH (select, create) VIRTUAL ONLY;
ACL ADMIN REVOKE SCHEMA sales.raw.eu FROM ROLE analyst;
```

**What a principal's DDL may say** (spec 113 - so a stock dbt project runs unchanged):

- **Names** are `[<vcat>.]<schema path>.<object>`. The first part is a catalog when it names one the
  principal holds a grant on (any of them, not only the MAIN one - with several catalogs the
  three-part name picks one); otherwise the name is a path in the MAIN catalog. Schemas nest: the
  object's home is the longest granted schema prefix. A first part that is both a catalog of the
  principal and a schema of its MAIN catalog is refused as ambiguous.
- **`CREATE [OR REPLACE] TABLE|VIEW`** and **`DROP TABLE|VIEW [IF EXISTS]`** in the home; `CASCADE`
  is taken off, so a drop never reaches past the one object (an object with dependents refuses).
- **`CREATE SCHEMA IF NOT EXISTS`** on a schema the principal holds is a no-op; without `IF NOT
  EXISTS` it is "already exists"; a schema it does not hold is refused - schemas are the operator's.
- **`ALTER TABLE|VIEW … RENAME TO`** in the same home, priced at `create` + `drop` on it: the new name
  must not be a record of the catalog, an object carrying the operator's declarations (a predicate,
  columns, keys, references, a grant by name) keeps its name, an expansion's record follows the
  object, and a rename is a lineage `DROP` + `CREATE`. Every other `ALTER` is refused.
- dbt through quack: the `table`, `view` and `incremental` (`append`) materializations run as they
  are. `delete+insert` / `merge` incremental strategies fail in the quack client itself (`DELETE`
  through an attached quack catalog is not planned there), before the node sees them.

Functions: `acl_grant_schema(role, vcat, path, caps_json[, comment[, into, virtual_only]])`,
`acl_revoke_schema(role, vcat, path)`, and the repair call
`acl_rematerialize_schema_caps(vcat[, path])`, which rebuilds a subtree's inherited rows from the
nearest ancestor that states capabilities (function only).

## Object grants

```
GRANT TABLE | VIEW | OBJECT <catalog>.<name> TO ROLE <role>
    [WITH (<capability>, …) | CAPS '<json>'] [RLS (<predicate>)] [COLUMNS (<item>, …)]
```

The three keywords are the same statement: the name may be a table, a view, a table function or a
scalar of the catalog (not a bare schema alias). An object grant refines the catalog grant for this
role: capabilities it does not state are inherited from the catalog grant, never widened by omission;
`CAPS '{}'` takes every capability away. `RLS` is AND-ed onto the catalog grant's predicate and the
object's own; `COLUMNS` intersects, and a bare name the object does not expose is refused. On a view
the policy applies to the view's output, on a table function to its result; `RLS`/`COLUMNS` on a
scalar is refused. The target must exist. When the grant states columns, its projection is bound
where it is written and stored, so `DESCRIBE` and `information_schema.columns` describe what the
role reads (a mask that changes a type, a computed column the object never had).

A `COLUMNS` item with a value on a writable table is an assignment as well as a mask:
`tenant = acl_claim('tenant')` is added to an `INSERT` when absent, overrides a supplied value, and
is applied to an `UPDATE`'s `SET`.

There is no `REVOKE` for an object grant; write it again with `CAPS '{}'`, or revoke the catalog.

### Fields of a structured column (spec 102)

A `COLUMNS` item may name **fields** of a `STRUCT` column, at any depth, and through a list of
structs. Paths work in a catalog grant, an object grant, and an object's own `COLUMNS`. A field mask
(`address.ssn = …`) is a grant's only.

| item | the role reads |
| --- | --- |
| `address.city, address.zip` | `STRUCT(city, zip)`: only those fields (a NULL struct stays NULL) |
| `address.geo.lat` | `STRUCT(geo STRUCT(lat))` |
| `address, address.ssn = '***'` | the whole struct with `ssn` masked |
| `items[].price` | `LIST(STRUCT(price))`: every element narrowed |

```sql
ACL ADMIN GRANT TABLE c.customers TO ROLE support COLUMNS (id, address.city, address.zip, orders[].total);
ACL ADMIN GRANT TABLE c.customers TO ROLE audit  COLUMNS (id, address, address.tax_id = '***');
```

- **Checked where it is written.** Every step is checked against the column's type and must be a
  STRUCT field or `[]` of a list. A path into a `MAP` or a `UNION` is refused: those are shown or
  masked whole. The fields are stored in the source's order.
- **Levels and roles.** Levels narrow: an object grant never re-exposes a field the catalog grant
  dropped. A principal's roles unite: `{city}` and `{zip}` read `{city, zip}`, a visible field beats a
  masked one, and two different masks on one field are refused. Every listing, `DESCRIBE`, the DDL a
  quack client binds, and the Arrow schema describe what is read.
- **Writes.** A column a grant narrows stays writable, and a write touches only what the role sees:
  - an `UPDATE`/`MERGE` keeps the stored values of the hidden fields;
  - an `INSERT` leaves them NULL;
  - a masked field is assigned (like a column mask);
  - a written value that carries a field the role cannot see is refused.

  `RETURNING` cannot read the column. A column narrowed through `[]`, or by the object's own
  `COLUMNS`, is read-only. A field mask that reads the row (`left(ssn, 1) || '***'`) is a mask and not
  an assignment, so it makes the column read-only too. `SET address = NULL` sets the visible fields to
  NULL and keeps the hidden ones.
- **A write statement reads what the role reads.** In an `UPDATE`'s `SET` and `WHERE`, a `DELETE`'s
  `WHERE` and a `MERGE`'s conditions:
  - a narrowed column has only its visible fields;
  - a masked column is its mask;
  - a column the grant does not list is refused.
  
  Beside another relation (`UPDATE … FROM`, `DELETE … USING`, `MERGE`), qualify the other relation's
  columns. A `MERGE`'s `UPDATE SET *` / `UPDATE BY NAME` is refused under a column policy: name the
  columns.

```sql
ACL ADMIN GRANT TABLE c.orders TO ROLE narrow WITH (select, update, delete, merge) RLS (tenant = acl_claim('tenant'));
ACL ADMIN GRANT TABLE sales.orders TO ROLE analyst WITH (select) RLS (amount > 50) COLUMNS (id, amount);
ACL ADMIN GRANT TABLE c.orders TO ROLE inj WITH (select, insert, update)
    RLS (tenant = acl_claim('tenant')) COLUMNS (id, amount, tenant = acl_claim('tenant'));
ACL ADMIN GRANT TABLE sales.shout TO ROLE ingest CAPS '{"select": true}';   -- read on one function only
```

Function: `acl_grant_object(role, vcat, vname, caps_json[, rls, columns])`.

## Function categories

What a principal may call (spec 072). A function's key is `database.schema.name` plus its kind -
`scalar` (the default: scalars, aggregates, windows, macros) or `TABLE` (a function in FROM). A
**category** is a named set of keys; a call is admitted when its key is in a category granted to one
of the principal's roles (or to all roles) or is granted by name; a deny anywhere wins; a key in no
category is refused. The shipped categories are seeded once, when the catalog is created, and never
touched again by the extension: `base`, `generators`, `node_facts`, `json`, `icu`, `spatial`, `inet`,
`h3`, `hashfuncs`, `a5`, `geosilo` are every role's from the start; `readers`, `meta`, `environment`,
`node`, `plan` are nobody's until granted. A function of a newly loaded extension, a builtin a pin
bump adds, a macro an admin creates: in no category, refused, until put somewhere -
`SELECT * FROM acl_function_status() WHERE status = 'uncategorized'` is the screen. A principal reads
its own side of it through `duckdb_functions()`: what it may call, and nothing else (spec 098).

```sql
CREATE FUNCTION CATEGORY <name> [COMMENT '<text>']
ALTER FUNCTION CATEGORY <name> ADD (<function> [, …]) | DROP (<function> [, …])
DROP FUNCTION CATEGORY [IF EXISTS] <name>

GRANT  FUNCTION CATEGORY <name> TO ROLE <role> | TO ALL ROLES
DENY   FUNCTION CATEGORY <name> TO ROLE <role> | TO ALL ROLES
REVOKE FUNCTION CATEGORY <name> FROM ROLE <role> | FROM ALL ROLES

GRANT  FUNCTION <function> TO ROLE <role> | TO ALL ROLES
DENY   FUNCTION <function> TO ROLE <role> | TO ALL ROLES
REVOKE FUNCTION <function> FROM ROLE <role> | FROM ALL ROLES
```

A `<function>` is `name`, `schema.name` or `database.schema.name` - a bare name is `system.main`,
where every builtin lives - optionally followed by `TABLE`; an operator is double-quoted (`"+"`,
`"IS DISTINCT FROM"`). A member or an admitting grant must name a function this node has, unless the
kind was written explicitly: that is how a fleet-shared catalog records a function of an extension
the writing node does not carry. The never set - `acl_*`, `ducklake_*`, `quack_*`, `arrow_scan*`,
`query`, `query_table`, `json_execute_serialized_sql`, a scanner's `*_query` / `*_execute` /
`*_attach` - is refused where it is written: only `ACL NATIVE` runs those.

```sql
ACL ADMIN CREATE FUNCTION CATEGORY sequences COMMENT 'read and advance a sequence';
ACL ADMIN ALTER FUNCTION CATEGORY sequences ADD (nextval, currval, setval);
ACL ADMIN GRANT FUNCTION CATEGORY sequences TO ROLE etl;
ACL ADMIN GRANT FUNCTION CATEGORY readers TO ROLE etl;          -- unconfined: any path the node can read
ACL ADMIN DENY FUNCTION read_text TABLE TO ROLE etl;            -- readers, but not this one
ACL ADMIN GRANT FUNCTION lake.main.peek TABLE TO ROLE analyst;  -- an admin's macro: only by a grant on its key
ACL ADMIN DENY FUNCTION CATEGORY base TO ROLE quarantine;       -- takes back what every role holds
ACL ADMIN REVOKE FUNCTION CATEGORY spatial FROM ALL ROLES;      -- spatial is nobody's from now on
ACL ADMIN DROP FUNCTION CATEGORY IF EXISTS sequences;           -- with its members and grants
```

The bulk form is the native mode: `ACL NATIVE SELECT acl_function_category_add('myext', list(function_name))
FROM duckdb_functions() WHERE function_name LIKE 'myext_%';`. A category acts in every catalog a role
holds, so these statements take an unrestricted `manage` scope - a catalog-scoped one is refused as
"not catalog-specific".

## Secrets

The node's secrets are kept by a secrets service attached to it - a catalog of type `tresor`
(`ATTACH 'tresor:<host>' AS corp`) - never by the node's own secret manager. A principal manages them
under the explicit **`secrets`** capability of its MAIN catalog grant (`WITH (select, secrets) MAIN`);
an administration scope does not include it (spec 082):

```sql
ACL GRANT  SECRET <name> TO   ROLE | GROUP <principal> [FROM | IN <catalog>]
ACL REVOKE SECRET <name> FROM ROLE | GROUP <principal> [FROM | IN <catalog>]
CREATE [PERSISTENT] SECRET [<name>] [IN <catalog>] (TYPE …, …)
DROP [PERSISTENT] SECRET <name> [FROM <catalog>]
```

- **The catalog** is the one written, which must be a secrets service; otherwise the one attached. None,
  or several unnamed, is refused with what to write.
- **GRANT / REVOKE SECRET** follow the principal prefix with the `ACL` marker (`ACL TOKEN '…' ACL GRANT
  SECRET …`; unmarked after the gateway's `ACL ADMIN`) and compile to the service's own calls,
  `<catalog>.main.grant_secret('<name>', 'role:<r>', ['use'])` / `revoke_secret(…)`. A secret is granted
  to a role or a group, never to one user, and only its use. A batch holds nothing else.
- **CREATE / DROP SECRET** keep the secret in the service. `TEMPORARY` is refused (a temporary secret
  would serve every statement on the node after it), and so is any storage that is not a service.
  A secret's parameters are constants - literals and lists of them: duckdb evaluates them on the node,
  so a call there (`SECRET getenv('…')`) would store what the node knows.
- **The service decides too.** It manages only for a principal it knows as an administrator (tresor's
  spec 009); the capability is acl's half of the gate.
- **A direct call** into the service catalog (`corp.whoami()`, `corp.main.secrets()`) is the function
  gate's like any other: the operator puts what a role may call in a category - `ALTER FUNCTION CATEGORY
  secrets_service ADD (corp.main.whoami TABLE, corp.main.secrets TABLE)` - and grants it. Manage through
  the statements above, which also need `secrets`, rather than by categorizing `grant_secret`. quack's
  own `whoami()` (the system catalog's) stays never callable.
- No secret value is written to an audit or profile event: a decision names the service and the
  secret's name with capability `secrets`.

## Resource groups

```sql
CREATE [OR REPLACE] RESOURCE GROUP <group> [WITH] (<limit> <value>, …) [DEFAULT] [COMMENT '<text>']
ALTER RESOURCE GROUP <group> SET DEFAULT | DROP DEFAULT
DROP RESOURCE GROUP [IF EXISTS] <group>
GRANT  RESOURCE GROUP <group> TO   ROLE <role>
REVOKE RESOURCE GROUP <group> FROM ROLE <role>
```

A resource group is a set of named limits bound to roles (spec 085). It is resolved once when a
session opens, and a limit it does not name is the node's setting.

| limit | what it limits | 0 means |
| --- | --- | --- |
| `window_start` | the quack fetch window at the start of a stream (`acl_quack_fetch_window`) | no window |
| `window_max` | how far that window grows (`acl_quack_fetch_window_max`) | no cap |
| `batch_bytes` | the quack batch target (`acl_quack_target_batch_bytes`); a size like `'32MiB'` is accepted | - |
| `max_result_rows` | the rows a Flight stream hands out before its refusal (`acl_max_result_rows`) | unlimited |
| `queue_priority` | the order in the stream budget's line; higher goes first, and waiting raises it | - |
| `max_sessions` | the live sessions charged to this group | unlimited |

- **Validation.** A name outside the table is refused, and so is a negative value. Only
  `queue_priority` may be negative.
- **Several groups.** A principal whose roles are in several groups gets the most generous value of
  each limit, the same rule capabilities follow. The session is charged to the group that allows the
  most sessions. A group that limits none leaves the session uncharged.
- **Node settings.** A group may exceed the node's settings. The node's capacity bounds, which are
  `acl_node_stream_budget`, the quack seats and `acl_max_sessions`, still hold for everyone.
- **Re-creating.** A re-create replaces the group's limits, and the roles bound to it stay bound. A
  drop removes the group's bindings, and so does dropping a role.
- **Authorization.** A group acts on the whole node, so these statements need an unrestricted `manage`
  scope.
- **Listings.** `acl_resource_groups()` and `acl_role_resource_groups()` list the groups (with
  `is_default`) and their bindings. `acl_sessions()` shows each session's `groups` and its
  `charged_group`.
- **Functions.** The admin functions behind the statements are `acl_create_resource_group(group,
  limits_json[, comment[, is_default]])`, `acl_alter_resource_group(group, 'default', 'true' |
  'false')`, `acl_drop_resource_group(group[, 'skip'])`, `acl_grant_resource_group(role, group)` and
  `acl_revoke_resource_group(role, group)`.

**A group is also a set of nodes** (spec 096). A node belongs to the group its deployment names with
`SET GLOBAL acl_node_group = '<group>'` (in its bootstrap; never from the policy, never under a
principal). A node of a group serves the sessions of principals that hold the group, **with that
group's limits only**, and refuses the others with `wrong_resource_group`, naming the groups that
would serve them - so a front sends the client to the right node. A node without a group serves
everyone, as before: a single node needs none of this. A node whose group the policy does not have
serves nobody new until it does (fail closed). The gateway's `ACL TOKEN` / `ACL ROLE` path is not
placed; `manage` and `passthrough` are placed like anyone.

- **The default group** (`DEFAULT`, or `ALTER RESOURCE GROUP g SET DEFAULT`): a principal whose roles
  are in no group is its member - for placement and for its limits. At most one group is the
  default: marking a second is refused, naming the current one. A re-create without `DEFAULT` keeps
  the mark; `DROP DEFAULT` removes it. Without a default group, ungrouped principals are served by
  ungrouped nodes only.
- **Dropping a group** with cluster profile items (`IN GROUP g`) is refused, naming them: remove its
  part of the profile first.
- **Names compare as written**: `General` is not `general`, in `acl_node_group` as in the bindings.

## Cluster profile

```sql
CLUSTER INSTALL EXTENSION <name> VERSION '<v>' [FROM <repository>] [IN GROUP <group>] [COMMENT '<text>']
CLUSTER UPDATE  EXTENSION <name> VERSION '<v>' [IN GROUP <group>]
CLUSTER REMOVE  EXTENSION <name> [IN GROUP <group>]
CLUSTER ATTACH '<path>' AS <alias> (TYPE <type> [, SECRET <secret>] [, <option> [<value>]] …)
        [LINEAGE '<identity>'] [DEPENDS ON (<alias>, …)] [IN GROUP <group>] [COMMENT '<text>']
CLUSTER DETACH <alias> [CASCADE] [FORCE] [IN GROUP <group>]
CLUSTER SET <setting> = <value> [IN GROUP <group>]
CLUSTER RESET <setting> [IN GROUP <group>]
```

The cluster profile is the shared part of every node's bootstrap (spec 093): which extensions a node
runs, which sources it attaches and which settings it carries. It lives in the policy catalog as
desired state, next to the policy, and a `config_version` counts its changes. With `IN GROUP` an item
belongs to the nodes of one resource group (spec 096: the nodes whose `acl_node_group` it is); without
it, to the whole cluster. A group's item overrides the cluster's item of the same kind and name, and
is applied live only on a node of that group - written from any other node, it answers
`applied_here = false` with the note "item of resource group g - …; the group's nodes roll it out".
A group's source named like a cluster's is a re-point on the group's nodes (drain class), and
detaching it brings the cluster's back there, never a `DETACH`; a detach (and its `CASCADE`) follows
the scope - a group's item depends on the cluster's source of a name only while the group has none of
its own.
`LINEAGE '<scheme>://<host:port>[/<database>]'` names the source in lineage as others know it (spec
112, [lineage](lineage.md#a-sources-identity)): the item's spec carries it as `lineage`, and a node
attaches the source with it (`ATTACH … LINEAGE '…'`). It is a name, never a credential.
`acl_cluster_effective()` lists what applies to *this* node (the cluster's items with its group's over
them, each with the scope it came from); `acl_cluster_applied(version)` is the node agent saying which
profile version this node has converged to, which the load report shows (`config.applied` against
`config.target`).

A statement does four things:

1. It checks the change. A refusal writes nothing.
2. It writes the item and bumps `config_version`, in one catalog transaction.
3. It applies the change **on this node** when that can be done live.
4. It answers `{version, class, applied_here, note}`.

If the live apply fails, the write is rolled back. So an item reaches the cluster only once it has
worked on the node that wrote it.

The class says how each kind of change reaches a running node:

| change | class |
| --- | --- |
| `INSTALL EXTENSION`, `ATTACH`, `DETACH` of an unused source | hot, applied here at once |
| `ATTACH` over an existing alias (re-pointing), `DETACH` of a source in use | drain |
| `UPDATE` / `REMOVE EXTENSION`, `SET` / `RESET` | restart |

duckdb cannot unload an extension from a running process. A node's configuration is locked after its
bootstrap. The node agent rolls drain and restart changes out; acl only describes them.

- **No credentials, anywhere.** A path with a credential key is refused. That covers a conninfo
  `password=`, a URI's `user:password@`, a SAS `sig=` and the like, and so does an option with such a
  key. A postgres, mysql or mssql source must name a `SECRET`, and the node resolves it from its
  secrets service. The refusal names the key, never its value.
- **The node's hardening is not a profile item.** `allow_unsigned_extensions`, `lock_configuration`,
  `allow_persistent_secrets`, `allow_extension_repositories`, the extension and secret directories
  and the like are refused. Only a GLOBAL setting may be profiled.
- **Extensions come from a trusted repository.** `FROM` names a repository created with duckdb's
  `CREATE EXTENSION REPOSITORY`; with exactly one, it may be left out. A path, a URL, `core` and
  `community` are refused, and `VERSION` is required.
  - duckdb installs such an extension under `repositories/<repository>/` and loads it with
    `LOAD <name> FROM <repository>`.
  - Integrity is the repository's signature, which duckdb verifies against the repository's
    pinned keys at every `INSTALL` and `LOAD`, together with a version that never changes once
    released. A profile does not pin a hash: one would change with every key rotation of the
    repository. `SHA256` is refused (spec 103).
- **Start order.** A node applies the profile in this order: settings, extensions, secrets, sources,
  the policy catalog.
  - Sources are ordered by `DEPENDS ON`, and by creation order where nothing orders them.
  - A dependency on an unknown source, or one that would make a cycle, is refused.
  - A source's extension follows from its `TYPE`, and `REMOVE EXTENSION` is refused while a source
    needs it.
- **Removing a source.**
  - `DETACH` is refused while another source depends on it. `CASCADE` removes the dependents too.
  - It is also refused while the policy reads through it: a virtual table, schema or function over
    `<alias>.…`. `FORCE` detaches anyway, and `acl_check_catalog` then reports `source_missing`.
- **Authorization.** The profile is the cluster's infrastructure, so every `CLUSTER` statement needs
  a **passthrough** scope. `manage` is not enough.
- **Audit.** Each statement is one `admin` event. Its object is the item, as `source:<alias>`,
  `extension:<name>` or `setting:<name>`, with capability `cluster`. The item's spec is never in the
  event, because a path is a physical name.
- **Listings.** `acl_cluster_items([group])` lists the profile: scope, kind, name, spec (JSON),
  class, version, depends_on and comment. `acl_cluster_version()` answers the counter.
- **Functions.** The admin functions behind the statements are:
  - `acl_cluster_extension(verb, group, name, version, repository, comment)`;
  - `acl_cluster_attach(group, alias, path, type, secret, options_json, depends_on_csv, comment)`;
  - `acl_cluster_detach(group, alias, cascade, force)`;
  - `acl_cluster_setting(verb, group, name, value)`.

## Administration scopes

```
GRANT ADMIN observe | manage | passthrough TO ROLE <role>
REVOKE ADMIN FROM ROLE <role>
```

The global scopes - a role holds one; granting another **replaces** it, so `GRANT ADMIN observe` on a
role that holds `manage` takes the `manage` away (grant the reading scope to a role of its own).
`observe` (spec 097) reads the node's load report and `/metrics` and administers nothing; `manage`
and `passthrough` imply it. `manage` is the management grammar over every catalog plus the statements that
belong to no catalog (roles, issuers, mappings, catalogs themselves, grants). `passthrough` is
anything, including `ACL NATIVE` SQL outside the virtual catalog. Granting or revoking a scope needs
`passthrough` - a `manage` scope never hands out scopes, and no scope is self-granted. Managing one
catalog is not granted here but with `GRANT CATALOG … CAPS '{"manage": true}'`.

```sql
ACL ROLE "platform" ACL GRANT ADMIN manage TO ROLE auditor;
ACL ADMIN REVOKE ADMIN FROM ROLE sales_owner;
```

Functions: `acl_grant_admin(role, scope)`, `acl_revoke_admin(role)`.

## Profiling a session

```
PROFILE SESSION CURRENT | '<ops id>' ON | ALL | SAMPLED | OFF
```

The operator's profile level on one live session (spec 074): what its statements' execution
profiles are recorded at from its next statement on - `ON` / `ALL` every statement, `SAMPLED` the
ones whose trace context carries the sampled flag, `OFF` clears the override so the registered
policy's rule and the node's `acl_profile_level` decide again. `CURRENT` is the session the
statement runs under (an `ACL SESSION` prefix - a client connected through a door); off a session
it is a refusal. Another session is named by its ops id from `acl_sessions()`, which also shows the
level in force and who decided it (`profile_level`, `profile_source` = `instance` / `policy` /
`override`). A session is the node's, not a catalog's: the statement needs an unrestricted `manage`
scope. An operator's own connection (no session) uses `SET SESSION acl_profile_level = ...`
instead, which outranks the node's `SET GLOBAL` on that connection alone.

```sql
ACL SESSION 'h…' ACL PROFILE SESSION CURRENT ON;
ACL ADMIN PROFILE SESSION '62F31C2A7615' SAMPLED;
ACL ADMIN PROFILE SESSION '62F31C2A7615' OFF;
```

Function: `acl_session_profile(id, level)` (`''` clears).

## Comments

```
COMMENT ON VIRTUAL TABLE | VIEW | SCHEMA | TABLE FUNCTION | SCALAR <catalog>.<name> [COLUMN <column>] IS '<text>'
```

Documents a virtual object or one of its columns. The target - and, with `COLUMN`, the column in the
object's stored schema - must exist; an object whose schema is unknown is refreshed first (below). A
comment survives a definition change and goes with its object when that is dropped. The `CREATE`
forms take the same comment inline (`COMMENT '<text>'`), and `ALTER VIRTUAL CATALOG … SET COMMENT`
comments a catalog.

```sql
ACL ADMIN COMMENT ON VIRTUAL VIEW sales.stats IS 'per-tenant totals';
ACL ADMIN COMMENT ON VIRTUAL VIEW sales.stats COLUMN top IS 'the largest order';
ACL ADMIN COMMENT ON VIRTUAL SCHEMA sales.raw IS 'raw zone';
```

Function: `acl_comment(vcat, vname, kind, column, comment)` with `kind` = `relation` (table or view)
| `schema` | `table` (table function) | `scalar`; `column` empty for the object itself.

## Refreshing stored schemas

```
ANALYZE VIRTUAL CATALOG <catalog>
ANALYZE VIRTUAL [TABLE [FUNCTION] | VIEW | SCALAR] <catalog>.<name>
```

Query-defined objects (views, macros, projections) have their schema derived by binding the
definition when it is written and stored. When the physical schema moves under them, `ANALYZE
VIRTUAL` re-derives it for one object or for every object of a catalog and returns how many were
re-probed. Alias-form objects read their schema live and never need it. An expansion's object *list*
is refreshed with `ALTER VIRTUAL SCHEMA … REFRESH` instead.

```sql
ACL ADMIN ANALYZE VIRTUAL CATALOG sales;
```

Function: `acl_refresh_schema(vcat[, vname])` (returns BIGINT).

## Checking and repairing a catalog

```
CHECK VIRTUAL CATALOG <catalog>
REPAIR VIRTUAL TABLE <catalog>.<name> REMAP (<column> = <expression>, …)
REPAIR VIRTUAL TABLE <catalog>.<name> DROP MISSING COLUMNS [AND MASKS]
```

The source changes under the catalog - a column dropped or renamed, a table gone, a view's
dependency moved - and nothing on a principal's query path may look (spec 065). `CHECK VIRTUAL
CATALOG` is the administrator's look, off the query path: it probes every stored fact of the catalog
against the source and answers **one row per finding** - `vcat`, `kind` (`table`, `view`,
`function`, `schema`, `grant`, `reference`), `object`, `role` (a grant's, else NULL), `problem`,
`detail` (our sentence; it may name the physical column or path - this is the admin's surface) and
`repair` (the statement that mends it, ready to paste). It writes nothing. The problems:

| problem | what no longer holds | the repair it names |
| --- | --- | --- |
| `source_missing` | the relation's physical source does not bind (dropped, renamed) | `ALTER VIRTUAL TABLE … SET PHYS` / `DROP VIRTUAL TABLE` |
| `column_missing` | a declared `COLUMNS` entry whose expression no longer binds against the source | `REPAIR VIRTUAL TABLE … REMAP (…)` or `… DROP MISSING COLUMNS` |
| `definition_broken` | a view's SQL, a macro's template (with its declared parameter types), or an alias's target function does not bind / exist | `CREATE OR REPLACE VIRTUAL VIEW … AS` / `acl_alter_function` |
| `schema_stale` | a query-defined object's stored (derived) schema - a view's, a macro's, or a declared-list table's projection - differs from what its definition binds to now | `ANALYZE VIRTUAL …` (re-derives a table's projection too since spec 039, keeping its marks and column comments) |
| `rls_broken` / `rls_unchecked` | a predicate (object or grant) fails to bind / was accepted unchecked and binds now (spec 027) | `… SET RLS`, a re-grant / `ANALYZE VIRTUAL CATALOG` |
| `grant_column_missing` | a bare item of a grant's `COLUMNS` list matches no column of the object (an object grant), or of any object of the catalog (a catalog grant) | `acl_grant_object(…)` / `ALTER GRANT CATALOG … SET COLUMNS` |
| `mask_broken` | a `name = expr` grant item names a column the object does not expose, or its expression does not bind - every read of that object by that role refuses (spec 038) | the same |
| `schema_missing` | a schema alias's or expansion's physical schema has no schema behind it | `ALTER VIRTUAL SCHEMA … SET PHYS` / `DROP VIRTUAL SCHEMA` |
| `expansion_stale` | an expansion's source has tables it did not record (and did not exclude), or records whose source is gone | `ALTER VIRTUAL SCHEMA … REFRESH [PRUNE]` |
| `reference_dangling` | a reference's end object, or a column it names, is not in the catalog (catalog facts only) | `DROP VIRTUAL REFERENCE` |
| `types_stale` | the source's column types differ from the type facts stored with the object (spec 099) - a retyped column, or a source that did not exist when the object was written | `ANALYZE VIRTUAL TABLE …` / `… VIEW …` |
| `enum_domain_exposed` | an object with an ENUM column whose labels are exposed (`enums = keep`) while a predicate - the object's or a grant's - narrows its rows (a view's own `WHERE` is not seen) | `ALTER VIRTUAL TABLE … SET TYPES (enums = varchar)` |
| `types_incompatible` | a declared entry or a grant's mask that binds over the source but not over the exposed type (`enum_code(tier)` once ENUMs are VARCHAR) - every read refuses | `… SET TYPES (enums = keep)`, or rewrite the expression |
| `types_mismatch` | a declared entry that makes a type of its own (`CAST(x AS ENUM(…))`) - described as the exposed type, read as its own | `REPAIR VIRTUAL TABLE … REMAP (n = CAST(… AS <type>))` |

A bare alias (no declared list) has no contract beyond "binds", so only `source_missing` can be
found on it - declaring `COLUMNS` is the opt-in to `column_missing`, as it is to spec 065's clean
refusals. A column *added* to the source is not a finding: it appears live under a whole-table grant
by design (docs/security.md, "a grant on the source's future").

`REPAIR VIRTUAL TABLE` mends a declared list on purpose, and **never drops a mask silently**:

- `REMAP (ssn = ssn_v2, …)` gives the named entries new expressions, each probed to bind before
  anything is written (a name the list does not declare, or an expression that does not bind, is
  refused and nothing changes); the grants' projections on the object are re-probed after.
- `DROP MISSING COLUMNS` removes every entry whose expression no longer binds. It is **refused**
  while an object grant on that object masks one of those names (`… would orphan the mask(s) on
  "ssn" (role "analyst") - REMAP the column, alter those grants, or DROP MISSING COLUMNS AND MASKS`).
  A catalog grant's mask is not touched either way: it protects the column on every other object,
  and spec 038 refuses this object's reads for it - which `CHECK` reports as `mask_broken`.
- `DROP MISSING COLUMNS AND MASKS` also removes exactly those mask items from the object grants
  that carried them, by name; the count includes them. The mask protected a column that no longer
  exists; what the administrator acknowledges is that a column of that name is gone for good.

Both return how many entries changed (`0` when nothing was missing). A view has nothing to repair
here (`ANALYZE VIRTUAL VIEW` re-derives, `CREATE OR REPLACE VIRTUAL VIEW` redefines), and a bare
alias has no list to mend.

While a declared-list object is broken, the tables listings a principal sees (`information_schema.
tables`, `duckdb_tables()`) carry the mark in the object's comment - `acl: broken -
declared column(s) ssn no longer exist in the source` - rather than quietly describing a narrower
object; the columns surface keeps the contract as written. A role whose grant *masks* the vanished
column (`ssn = NULL`) never reads it and keeps its rows; a role whose grant reads it gets the binder
error spec 065 accepted. The mark judges declared entries that read a bare source column - a
computed column written as an expression, a constant or one of SQL's bare-word functions
(`current_user`, `current_date`, …) is not judged; write anything else that is not a column with
parentheses or a cast so it cannot be mistaken for one.

```sql
ACL ADMIN CHECK VIRTUAL CATALOG sales;
ACL ADMIN REPAIR VIRTUAL TABLE sales.customers REMAP (ssn = ssn_v2);
ACL ADMIN REPAIR VIRTUAL TABLE sales.customers DROP MISSING COLUMNS AND MASKS;
```

Functions: `acl_check_catalog([vcat])` (a table function; no argument walks every catalog),
`acl_repair_relation(vcat, vname, action[, spec])` (returns BIGINT; `action` is `remap` with the
list in `spec`, `drop_missing`, or `drop_missing_and_masks`). Both are the administrator's: denied to
a principal, and under a role's management scope confined to the catalogs it manages (the
no-argument function form, which walks every catalog, is the operator's own connection's - the
management grammar always names one).

## ALTER

`ALTER` changes one property of an existing object: a missing target is an error (there is no `IF
EXISTS`), every property not named keeps its value, and one statement carries one `SET`. The object
forms carry the `VIRTUAL` marker so duckdb's own `ALTER TABLE` stays native.

| Statement                                                                                        | Function                                                    |
| ------------------------------------------------------------------------------------------------ | ----------------------------------------------------------- |
| `ALTER VIRTUAL CATALOG <c> SET COMMENT '…'`                                                      | `acl_alter_catalog(vcat, comment)`                          |
| `ALTER VIRTUAL TABLE <c>.<n> SET PHYS <phys>`                                                    | `acl_alter_relation(vcat, vname, 'phys', value)`            |
| `ALTER VIRTUAL TABLE <c>.<n> SET COLUMNS (<item>, …)`                                            | `acl_alter_relation(vcat, vname, 'columns', csv)`           |
| `ALTER VIRTUAL TABLE <c>.<n> SET RLS (<predicate>)`                                              | `acl_alter_relation(vcat, vname, 'rls', predicate)`         |
| `ALTER VIRTUAL TABLE <c>.<n> SET PRIMARY KEY (<column>, …)` / `DROP PRIMARY KEY`                 | `acl_set_key(vcat, vname, 'relation', pk_csv)` (empty = drop) |
| `ALTER VIRTUAL TABLE <c>.<n> SET TYPES (aliases = …, enums = …)` (or `VIEW`)                  | `acl_alter_relation(vcat, vname, 'types', list)` (spec 099) |
| `ALTER VIRTUAL VIEW <c>.<n> SET AS <select>`                                                     | `acl_alter_relation(vcat, vname, 'view', sql)`              |
| `ALTER VIRTUAL VIEW <c>.<n> SET PRIMARY KEY (…)` / `DROP PRIMARY KEY`                            | `acl_set_key(vcat, vname, 'relation', pk_csv)`              |
| `ALTER VIRTUAL SCHEMA <c>.<path> SET PHYS <phys schema>`                                         | `acl_alter_schema_alias(vcat, path, phys)`                  |
| `ALTER VIRTUAL SCHEMA <c>.<path> REFRESH [PRUNE]`                                                | `acl_refresh_schema_objects(vcat, path, prune)`             |
| `CHECK VIRTUAL CATALOG <c>`                                                                        | `SELECT * FROM acl_check_catalog(vcat)` (spec 039)                                      |
| `REPAIR VIRTUAL TABLE <c>.<n> REMAP (<v> = <expr>, …)` / `DROP MISSING COLUMNS [AND MASKS]`          | `acl_repair_relation(vcat, vname, 'remap', list)` / `(…, 'drop_missing[_and_masks]')`   |
| `ALTER VIRTUAL TABLE FUNCTION <c>.<n> SET MACRO <select>` / `SET ALIAS [OF] <fn>`                | `acl_alter_function(vcat, vname, 'table', 'macro' or 'alias', definition)` |
| `ALTER VIRTUAL TABLE FUNCTION <c>.<n> SET PRIMARY KEY (…)` / `DROP PRIMARY KEY`                  | `acl_set_key(vcat, vname, 'table', pk_csv)`                 |
| `ALTER VIRTUAL SCALAR <c>.<n> SET MACRO <expression>` / `SET ALIAS [OF] <fn>`                    | `acl_alter_function(vcat, vname, 'scalar', 'macro' or 'alias', definition)` |
| `ALTER ROLE <r> SET CLAIMS (…)`                                                                  | `acl_alter_role(role, claims_csv)`                          |
| `ALTER ISSUER <i> SET …` / `ALTER CLIENT <c> SET …`                                               | `acl_alter_issuer(name, spec)` / `acl_alter_client(name, spec)` |
| `ALTER GRANT CATALOG <c> TO ROLE <r> SET CAPS '…'` / `SET RLS '…'` / `SET COLUMNS '…'` / `SET MAIN true` / `SET MAIN false` | `acl_alter_grant(role, vcat, field, value)` |

`ALTER VIRTUAL VIEW` on a table (or the reverse) is refused. The `SET PHYS`, `SET COLUMNS` and `SET
RLS` forms take a list in parentheses or quoted; `ALTER GRANT` takes quoted values only. Redefining an
object with `CREATE OR REPLACE` or `ALTER` carries its comment, declared key and nullability marks
unless the statement states them; a key whose column the new shape no longer has lapses.

```sql
ACL ADMIN ALTER VIRTUAL TABLE c.two SET COLUMNS (order_id = id, total = amount);
ACL ADMIN ALTER VIRTUAL TABLE c.orders SET PRIMARY KEY (id, tenant);
ACL ADMIN ALTER VIRTUAL VIEW c.daily SET AS 'SELECT tenant AS day, count(*)::INTEGER AS total FROM phys.main.orders GROUP BY 1';
ACL ADMIN ALTER VIRTUAL TABLE FUNCTION c.report SET MACRO 'SELECT id, amount FROM phys.main.orders WHERE amount > acl_arg(1)';
```

## DROP

A drop removes a definition from the policy and leaves the physical object alone (a principal's own
`DROP TABLE` through a virtual name, under the `drop` capability, is the one that removes both).
Without `IF EXISTS` a missing target is an error.

| Statement                                                        | Function                                                 |
| ---------------------------------------------------------------- | -------------------------------------------------------- |
| `DROP VIRTUAL CATALOG [IF EXISTS] <c> [CASCADE]`                 | `acl_drop_catalog(vcat, cascade, mode)`                  |
| `DROP VIRTUAL TABLE [IF EXISTS] <c>.<n>` / `DROP VIRTUAL VIEW …` / `DROP RELATION [IF EXISTS] <c>.<n>` | `acl_drop_relation(vcat, vname, mode)`       |
| `DROP VIRTUAL SCHEMA [IF EXISTS] <c>.<path> [CASCADE]`           | `acl_drop_schema_alias(vcat, path, mode, cascade)`       |
| `DROP VIRTUAL TABLE FUNCTION [IF EXISTS] <c>.<n>`                | `acl_drop_function(vcat, vname, 'table', mode)`          |
| `DROP VIRTUAL SCALAR [IF EXISTS] <c>.<n>`                        | `acl_drop_function(vcat, vname, 'scalar', mode)`         |
| `DROP [VIRTUAL] REFERENCE [IF EXISTS] <c>.<name>`                | `acl_drop_reference(vcat, name, mode)`                   |
| `DROP ROLE [IF EXISTS] <r>`                                      | `acl_drop_role(role, mode)`                              |
| `DROP ISSUER [IF EXISTS] <i>`                                    | `acl_drop_issuer(name, mode)` (its implicit client and mappings) |
| `DROP CLIENT [IF EXISTS] <c>`                                    | `acl_drop_client(name, mode)` (its mappings)             |
| `DROP MAP GROUP '<v>' FROM CLIENT|ISSUER <n> TO ROLE <r>` (or `MAP CLAIM`) | `acl_drop_role_mapping(kind, scope, source, external, role)` |

`mode` is `skip` for `IF EXISTS`, otherwise empty. Dropping an object takes its stored schema,
comments, declared key and every reference that names it with it; a schema dropped with `CASCADE`
takes those of its expanded records too.

## Batches and authorization

- **One prefix per batch.** The prefix names one principal (or the anonymous gateway) and one mode
  for every statement after it; a second `ACL …` inside the text is not a prefix. Under `ACL ADMIN`
  the first statement decides whether the batch is management or native SQL: `ACL ADMIN CREATE ROLE
  r; SELECT 1;` is refused for mixing.
- **Parsed and authorized statement by statement, before anything runs.** A management batch compiles
  to one function call per statement; each call is checked against the principal's rights at parse
  time, and a refusal anywhere executes nothing. Execution itself is not atomic: a batch that passes
  and then fails at runtime leaves the earlier statements applied, like any SQL batch.
- **What each scope may do** (spec 009):

  | Scope                                                               | May run                                                                                                                                                         |
  | ------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
  | anonymous `ACL ADMIN` (where allowed)                               | everything, native SQL included                                                                                                                                 |
  | `passthrough` (`GRANT ADMIN passthrough`)                           | everything, native SQL included                                                                                                                                 |
  | global `manage` (`GRANT ADMIN manage`)                              | every management statement except `GRANT ADMIN` / `REVOKE ADMIN`; no `ACL NATIVE`                                                                               |
  | `observe` (`GRANT ADMIN observe`)                                   | no management statement and no `ACL NATIVE` - it reads the load report and `/metrics` (spec 097)                                                               |
  | catalog-scoped `manage` (`GRANT CATALOG c … CAPS '{"manage": true}'`) | statements whose target names one of its catalogs; **not** `GRANT`/`REVOKE CATALOG`, `GRANT`/`REVOKE SCHEMA`, `GRANT TABLE`/`VIEW`/`OBJECT`, `ALTER GRANT`, `DROP VIRTUAL CATALOG` (handing out or taking away access is privilege administration), and not the statements that belong to no catalog (roles, issuers, mappings, `CREATE VIRTUAL CATALOG`) |

  Catalog names are compared exactly, case included. A `manage` scope can create anything the
  duckdb instance can reach under its catalogs, so it belongs to trusted operators.
- **Anonymous administration** is the gateway's escape hatch: always on in the in-memory dev store,
  and off by default once a policy source is enabled (`SET GLOBAL acl_allow_anonymous_admin = true`
  turns it on; the setting is global, a session `SET` changes nothing). The doors refuse to serve
  while it is on. The usual bootstrap is one `GRANT ADMIN passthrough TO ROLE platform` through the
  hatch, then closing it.

## Function reference

All functions are registered by the extension; unless noted they return `BOOLEAN` and take
`VARCHAR` arguments. Optional arguments are in brackets; `mode` is the write mode of the *Notation*
section.

**Policy source**

| Function                                   | Purpose                                                                       |
| ------------------------------------------ | ----------------------------------------------------------------------------- |
| `acl_use_db(db[, schema[, init BOOLEAN]])` | read policy from an ATTACHed database (schema `acl`; `init` creates/migrates) |
| `acl_use_functions(slot_map_json)`         | read policy from registered table functions (read-only)                       |

**Virtual catalog content**

| Function                                                                                              | Purpose                                                                 |
| ----------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| `acl_create_catalog(vcat[, comment[, mode]])`                                                         | create a virtual catalog                                                |
| `acl_alter_catalog(vcat, comment)`                                                                    | set its comment                                                         |
| `acl_drop_catalog(vcat[, cascade BOOLEAN[, mode]])`                                                   | drop it; `cascade` removes the grants on it                             |
| `acl_add_relation(vcat, vname, phys, columns_csv, rls[, comment[, mode[, pk_csv]]])`                  | virtual table over a physical one                                       |
| `acl_add_view(vcat, vname, select_sql[, returns[, comment[, mode[, pk_csv]]]])`                       | virtual view                                                            |
| `acl_alter_relation(vcat, vname, field, value)`                                                       | change `phys` / `columns` / `rls` / `view`                              |
| `acl_drop_relation(vcat, vname[, mode])`                                                              | drop a table or view definition                                         |
| `acl_add_schema_alias(vcat, path, phys[, comment[, mode]])`                                           | live schema alias                                                       |
| `acl_expand_schema(vcat, path, phys[, comment[, mode]])`                                              | schema expansion (one record per object, now)                           |
| `acl_alter_schema_alias(vcat, path, phys)`                                                            | retarget an alias                                                       |
| `acl_refresh_schema_objects(vcat, path[, prune BOOLEAN])` -> BIGINT                                   | re-read an expansion's source; records changed                          |
| `acl_drop_schema_alias(vcat, path[, mode[, cascade BOOLEAN]])`                                        | drop a schema; `cascade` takes its expanded records                     |
| `acl_add_table_function(vcat, vname, sql_template[, params, returns[, comment[, mode[, pk_csv]]]])`   | table-function macro                                                    |
| `acl_add_table_function_alias(vcat, vname, target[, '', '', comment[, mode]])`                        | table-function alias                                                    |
| `acl_add_scalar(vcat, vname, expr_template[, params, returns[, comment[, mode]]])`                    | scalar macro                                                            |
| `acl_add_scalar_alias(vcat, vname, target[, '', '', comment[, mode]])`                                | scalar alias                                                            |
| `acl_alter_function(vcat, vname, kind, form, definition)`                                             | redefine: `kind` `table`/`scalar`, `form` `macro`/`alias`               |
| `acl_drop_function(vcat, vname, kind[, mode])`                                                        | drop a function definition                                              |
| `acl_set_key(vcat, vname, kind[, pk_csv])`                                                            | declared primary key; `kind` `relation`/`table`; empty list drops it    |
| `acl_comment(vcat, vname, kind, column, comment)`                                                     | comment an object (`column` empty) or a column                          |
| `acl_refresh_schema(vcat[, vname])` -> BIGINT                                                         | re-derive stored schemas; objects re-probed                             |
| `acl_check_catalog([vcat])` (table function)                                                          | what no longer holds against the source, one row per finding (spec 039) |
| `acl_repair_relation(vcat, vname, action[, spec])` -> BIGINT                                          | mend a declared list: `remap`, `drop_missing`, `drop_missing_and_masks` |
| `acl_add_reference(vcat, name, from, to[, to_kind, args, pairs, expr, cardinality, optional, join_method, comment, mode])` | declare a join path                                |
| `acl_drop_reference(vcat, name[, mode])`                                                              | drop it                                                                 |
| `acl_register_created(vcat, vname, phys[, origin])`                                                   | internal: the record a principal's own `CREATE` writes                  |
| `acl_register_existing(vcat, vname, phys[, origin])`                                                  | internal: the `VIRTUAL ONLY` form (refuses a missing physical object)   |
| `acl_register_view(vcat, vname, body)`                                                                | internal: the record a principal's own `CREATE VIEW` writes             |
| `acl_rematerialize_schema_caps(vcat[, path])`                                                         | rebuild a subtree's inherited schema capabilities                       |

**Grants and scopes**

| Function                                                                       | Purpose                                                                  |
| ------------------------------------------------------------------------------ | ------------------------------------------------------------------------ |
| `acl_grant_catalog(role, vcat, caps_json[, is_main BOOLEAN[, rls, columns]])`  | grant a catalog; empty `caps_json` = every data capability, `'{}'` = none |
| `acl_alter_grant(role, vcat, field, value)`                                    | change `caps` / `rls` / `columns` / `main` of a catalog grant             |
| `acl_revoke_catalog(role, vcat)`                                               | revoke it, with the role's object grants in it                            |
| `acl_grant_schema(role, vcat, path, caps_json[, comment[, into, virtual_only BOOLEAN]])` | schema grant                                                     |
| `acl_revoke_schema(role, vcat, path)`                                          | revoke it                                                                 |
| `acl_grant_object(role, vcat, vname, caps_json[, rls, columns])`               | object grant (table, view or function)                                    |
| `acl_grant_admin(role, scope)`                                                 | global scope `manage` / `passthrough`                                     |
| `acl_revoke_admin(role)`                                                       | drop the role's global scope                                              |
| `acl_session_profile(id, level)`                                               | the operator's profile level on a live session; `''` clears (spec 074)    |

**Principals**

| Function                                                                                                                   | Purpose                                                  |
| -------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------- |
| `acl_define_role(role, claims_csv[, mode])`                                                                                | role with default claims                                 |
| `acl_alter_role(role, claims_csv)`                                                                                         | replace its claims                                       |
| `acl_drop_role(role[, mode])`                                                                                              | drop it and everything attached to it                    |
| `acl_define_issuer(name, spec_json[, mode])`                                                                              | an issuer, and its implicit client when the spec has one (spec 095) |
| `acl_alter_issuer(name, spec_json)` / `acl_drop_issuer(name[, mode])`                                                     | change / drop it (with its implicit client and mappings) |
| `acl_define_client(name, issuer, spec_json[, mode])` / `acl_alter_client` / `acl_drop_client`                              | a client of an issuer                                    |
| `acl_map_role(scope_kind, scope, source, external_value, role)`                                                           | map `group` / `claim-value` to a role, per client or issuer |
| `acl_drop_role_mapping(scope_kind, scope, source, external_value, role)`                                                  | drop a mapping                                           |
| `acl_define_token(token, role, claims_csv)`                                                                                | **legacy, dev**: bind a non-JWT token to a role in memory |

**Legacy wrappers** - the pre-catalog API, kept for dev and test scripts. Without a policy source
they fill the in-memory store; with a catalog they write the same content into the implicit virtual
catalog `default`, granted to the role as its main catalog.

| Function                                                        | Purpose                                                          |
| --------------------------------------------------------------- | ---------------------------------------------------------------- |
| `acl_grant_table(role, vname, phys, cols_csv, rls, caps_csv)`   | **legacy**: table policy for one role (`caps_csv` defaults to `select`) |
| `acl_grant_view(role, vname, select_sql)`                       | **legacy**: view for one role                                    |
| `acl_grant_table_function(role, vname, sql_template)`           | **legacy**: table-function macro                                 |
| `acl_grant_table_function_alias(role, vname, target)`           | **legacy**: table-function alias                                 |
| `acl_grant_scalar(role, vname, expr_template)`                  | **legacy**: scalar macro                                         |
| `acl_grant_scalar_alias(role, vname, target)`                   | **legacy**: scalar alias                                         |
| `acl_deny_function(name)` / `acl_allow_function(name)`          | **legacy**: a grant by name to every role, denied or allowed, for both kinds (spec 072) |
| `acl_create_function_category(name[, comment])` / `acl_drop_function_category(name)` | spec 072: a category of the operator's own; dropping one takes its members and grants with it |
| `acl_function_category_add(category, members)` / `acl_function_category_remove(category, members)` | spec 072: members as a list or a csv of `[db.schema.]name [TABLE]` (default `system.main`, default scalar); the never set is refused |
| `acl_grant_function_category(role, category[, allowed])` / `acl_revoke_function_category(role, category)` | spec 072: role `''` is every role; `allowed = 'false'` is a deny, which wins |
| `acl_grant_function(role, spec[, allowed])` / `acl_revoke_function(role, spec)` | spec 072: a grant by name admits the key whatever its categories (an admin's macro: `'lake.main.peek TABLE'`); a deny by name refuses it whatever they grant |
| `acl_function_status([role])` (table function) | spec 072: every function of the node with its categories and status (`never` / `categorized` / `uncategorized`), `present` for members this node has no function for; with a role, `allowed` and `decided_by` |

**Doors and sessions** - registered alongside the admin functions; they are the operator's and the
door's, never a principal's, and have no management-SQL form. `acl_flight_serve` / `acl_flight_stop`
are registered elsewhere and documented with the Flight door.

| Function                                                                   | Returns  | Purpose                                                        |
| -------------------------------------------------------------------------- | -------- | -------------------------------------------------------------- |
| `acl_quack_serve(uri, token[, mode])` / `(uri, token, cert, key[, mode])`, `acl_quack_stop(uri)` | VARCHAR | open the quack door (`mode` `embedded` / `plain`); close it and, if it was the last door, sweep its sessions |
| `acl_quack_authenticate(session_id, client_token, server_token)`, `acl_quack_authorize(connection_id, query)` | BOOLEAN, VARCHAR | the door's per-connection and per-statement callbacks (prefixed SQL, or NULL to refuse) |
| `acl_session_open(token)`, `acl_session_sql(handle, sql)`, `acl_session_reason(handle)` | VARCHAR | mint a handle (NULL if the token fails), prefix a statement (NULL if unusable), `live`/`expired`/`idle`/`unknown` |
| `acl_session_close(handle)`, `acl_session_kill(id)`                        | BOOLEAN  | end a session by handle, or by the ops id `acl_sessions()` shows |
| `acl_sessions()`                                                           | VARCHAR  | live sessions as JSON: ops ids (never handles), door, audit level in force and its source |
| `acl_session_sweep()`, `acl_session_count()`                               | BIGINT   | drop dead sessions / count live ones                            |
| `acl_drain()`, `acl_resume()`, `acl_drain_status()`                        | BIGINT, BOOLEAN, VARCHAR | stop seating new clients, resume, `draining`/`serving` |
