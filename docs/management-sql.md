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
[OR REPLACE] VIRTUAL|ROLE|ISSUER`, `ALTER VIRTUAL|ROLE|ISSUER|GRANT`, `DROP VIRTUAL|RELATION|
REFERENCE|ROLE|ISSUER|MAP`, `COMMENT ON VIRTUAL`, `ANALYZE VIRTUAL` - and a typo after one of those
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
- `<role>`, `<catalog>` - bare words. `'<issuer>'` - always a quoted string.
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
  "functions": "pol_functions", "function_gate": "pol_gate", "role_claims": "pol_claims"}');
```

- `acl_use_db(db[, schema[, init]])` - `schema` defaults to `acl`; `init` defaults to false. A
  catalog whose `schema_version` does not match the build is refused by name.
- `acl_use_functions(slot_map_json)` - the six slots `policy_version`, `role_catalogs`, `relations`,
  `relation_columns`, `schema_aliases`, `functions` are required; every named function must be a
  registered table function. The two sources are exclusive: the last call wins.
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

## Issuers

```
CREATE ISSUER '<issuer>' KEYS '<jwks or PEM>' | KEYS FROM '<uri>'
    [AUDIENCES ('<aud>', …) | AUDIENCES '<csv>'] [ALGS (RS256 | ES256 | HS256, …) | ALGS '<csv>']
    [ROLE CLAIM '<path>'] [CLAIM MAP (<jwt path> => <claim>, …) | CLAIM MAP '<json>']
    [CLIENT ID '<id>' [CLIENT SECRET '<secret>']]
ALTER ISSUER '<issuer>' SET KEYS '<jwks or PEM>' | SET KEYS FROM '<uri>' | SET AUDIENCES '<csv>' | SET ALGS '<csv>'
    | SET ROLE CLAIM '<path>' | SET CLAIM MAP '<json>' | SET CLIENT ID '<id>' | SET CLIENT SECRET '<secret>'
DROP ISSUER [IF EXISTS] '<issuer>'
```

An issuer is what makes an `ACL TOKEN '<jwt>'` verify offline. The clauses come in the order shown.

- `KEYS` pastes a JWKS (RSA `n`/`e`, EC P-256 `x`/`y`, `oct` `k`) or a PEM public key; `KEYS FROM`
  names a document to read them from through duckdb's own filesystem - an `https` URL (needs
  `httpfs`) or a file refreshed out of band. Exactly one of the two; setting either with `ALTER`
  clears the other. A fetched document is reused for `acl_jwks_refresh_interval` seconds (300),
  re-read on an unknown `kid`, and kept up to `acl_jwks_max_stale` seconds (3600) after a failed read.
- `AUDIENCES` is the allowlist the token's `aud` must intersect; omitted, no audience check is made.
  `ALTER … SET AUDIENCES` refuses an empty list - write `'*'` to accept any audience deliberately.
- `ALGS` defaults to `RS256`; anything outside the allowlist, including `none`, is refused.
- `ROLE CLAIM` is the dot path to the roles claim (`roles`, `realm_access.roles`, `groups`); default
  `roles`. Its values are the external names `MAP …` translates.
- `CLAIM MAP` says which token claims become `acl_claim()` values: `(tid => tenant)` makes the
  token's `tid` answer `acl_claim('tenant')`.
- `CLIENT ID` is the app registration the node runs the OAuth password grant as and what auth
  discovery advertises; `CLIENT SECRET` only for a confidential client and never without an id.
  Clearing the id clears the secret. `acl_issuers()` lists the id and never the secret.
- `CREATE ISSUER` has no write mode: an issuer of the same name is redefined (`CREATE OR REPLACE
  ISSUER` is accepted and means the same; `IF NOT EXISTS` is not). `exp`/`nbf` are judged with the
  global setting `acl_jwt_clock_skew` (60 s).

```sql
ACL ADMIN CREATE ISSUER 'https://issuer.test/claims' KEYS '{"keys":[{"kty":"oct","k":"YWNsLXRlc3QtaHMyNTYtc2VjcmV0"}]}'
    AUDIENCES ('api://acl-test', 'api://other') ALGS (RS256, ES256) ROLE CLAIM 'roles' CLAIM MAP (tid => tenant, oid => user_id);
ACL ADMIN CREATE ISSUER 'https://issuer.test/hs' KEYS FROM '/etc/acl/jwks.json'
    AUDIENCES ('api://acl-test') ALGS (HS256) ROLE CLAIM 'roles';
ACL ADMIN ALTER ISSUER 'https://issuer.test/hs' SET CLIENT ID 'door-app';
ACL ADMIN DROP ISSUER 'https://issuer.test/hs';
```

Functions: `acl_define_issuer(issuer, keys_json, audiences_csv, algs_csv, role_claim, claim_map_json[, jwks_uri[, client_id[, client_secret]]])`
(`keys_json` empty when `jwks_uri` is given), `acl_alter_issuer(issuer, field, value)` with `field`
one of `keys`, `jwks_uri`, `audiences`, `algs`, `role_claim`, `claim_map`, `client_id`,
`client_secret`, `acl_drop_issuer(issuer[, mode])`.

## Role mappings

```
MAP GROUP '<group id>' FROM ISSUER '<issuer>' TO ROLE <role>
MAP CLAIM '<value>' FROM ISSUER '<issuer>' TO ROLE <role>
DROP MAP GROUP | CLAIM '<value>' FROM ISSUER '<issuer>' TO ROLE <role>
```

A mapping turns a value found at the issuer's role claim into an internal role: `GROUP` for a group
identifier (an EntraID GUID), `CLAIM` for a plain claim value. One value may map to several roles; a
token's roles are the union. An unmapped value counts only if it is itself a known role; a token that
ends with no roles is refused.

```sql
ACL ADMIN MAP GROUP 'g-0001' FROM ISSUER 'https://issuer.test/x' TO ROLE analyst;
ACL ADMIN MAP CLAIM 'ops' FROM ISSUER 'https://issuer.test/d' TO ROLE analyst2;
ACL ADMIN DROP MAP GROUP 'g-1' FROM ISSUER 'https://issuer.test/d' TO ROLE analyst;
```

Functions: `acl_map_role(issuer, source, external_value, role)` and
`acl_drop_role_mapping(issuer, source, external_value, role)`, `source` = `group` | `claim-value`.

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
  `temp` (session temp tables on the Flight door) and `explain` (EXPLAIN), each held only when named.
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

```sql
ACL ADMIN GRANT TABLE c.orders TO ROLE narrow WITH (select, update, delete, merge) RLS (tenant = acl_claim('tenant'));
ACL ADMIN GRANT TABLE sales.orders TO ROLE analyst WITH (select) RLS (amount > 50) COLUMNS (id, amount);
ACL ADMIN GRANT TABLE c.orders TO ROLE inj WITH (select, insert, update)
    RLS (tenant = acl_claim('tenant')) COLUMNS (id, amount, tenant = acl_claim('tenant'));
ACL ADMIN GRANT TABLE sales.shout TO ROLE ingest CAPS '{"select": true}';   -- read on one function only
```

Function: `acl_grant_object(role, vcat, vname, caps_json[, rls, columns])`.

## Administration scopes

```
GRANT ADMIN manage | passthrough TO ROLE <role>
REVOKE ADMIN FROM ROLE <role>
```

The global scopes. `manage` is the management grammar over every catalog plus the statements that
belong to no catalog (roles, issuers, mappings, catalogs themselves, grants). `passthrough` is
anything, including `ACL NATIVE` SQL outside the virtual catalog. Granting or revoking a scope needs
`passthrough` - a `manage` scope never hands out scopes, and no scope is self-granted. Managing one
catalog is not granted here but with `GRANT CATALOG … CAPS '{"manage": true}'`.

```sql
ACL ROLE "platform" ACL GRANT ADMIN manage TO ROLE auditor;
ACL ADMIN REVOKE ADMIN FROM ROLE sales_owner;
```

Functions: `acl_grant_admin(role, scope)`, `acl_revoke_admin(role)`.

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
| `ALTER VIRTUAL VIEW <c>.<n> SET AS <select>`                                                     | `acl_alter_relation(vcat, vname, 'view', sql)`              |
| `ALTER VIRTUAL VIEW <c>.<n> SET PRIMARY KEY (…)` / `DROP PRIMARY KEY`                            | `acl_set_key(vcat, vname, 'relation', pk_csv)`              |
| `ALTER VIRTUAL SCHEMA <c>.<path> SET PHYS <phys schema>`                                         | `acl_alter_schema_alias(vcat, path, phys)`                  |
| `ALTER VIRTUAL SCHEMA <c>.<path> REFRESH [PRUNE]`                                                | `acl_refresh_schema_objects(vcat, path, prune)`             |
| `ALTER VIRTUAL TABLE FUNCTION <c>.<n> SET MACRO <select>` / `SET ALIAS [OF] <fn>`                | `acl_alter_function(vcat, vname, 'table', 'macro' or 'alias', definition)` |
| `ALTER VIRTUAL TABLE FUNCTION <c>.<n> SET PRIMARY KEY (…)` / `DROP PRIMARY KEY`                  | `acl_set_key(vcat, vname, 'table', pk_csv)`                 |
| `ALTER VIRTUAL SCALAR <c>.<n> SET MACRO <expression>` / `SET ALIAS [OF] <fn>`                    | `acl_alter_function(vcat, vname, 'scalar', 'macro' or 'alias', definition)` |
| `ALTER ROLE <r> SET CLAIMS (…)`                                                                  | `acl_alter_role(role, claims_csv)`                          |
| `ALTER ISSUER '<iss>' SET <field> '…'`                                                           | `acl_alter_issuer(issuer, field, value)`                    |
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
| `DROP ISSUER [IF EXISTS] '<iss>'`                                | `acl_drop_issuer(issuer, mode)` (takes its mappings)     |
| `DROP MAP GROUP '<v>' FROM ISSUER '<iss>' TO ROLE <r>` (or `MAP CLAIM`) | `acl_drop_role_mapping(issuer, source, external, role)` |

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

**Principals**

| Function                                                                                                                   | Purpose                                                  |
| -------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------- |
| `acl_define_role(role, claims_csv[, mode])`                                                                                | role with default claims                                 |
| `acl_alter_role(role, claims_csv)`                                                                                         | replace its claims                                       |
| `acl_drop_role(role[, mode])`                                                                                              | drop it and everything attached to it                    |
| `acl_define_issuer(issuer, keys_json, audiences_csv, algs_csv, role_claim, claim_map_json[, jwks_uri[, client_id[, client_secret]]])` | JWT issuer (exactly one of keys / location) |
| `acl_alter_issuer(issuer, field, value)`                                                                                   | change one issuer field                                  |
| `acl_drop_issuer(issuer[, mode])`                                                                                          | drop it and its mappings                                 |
| `acl_map_role(issuer, source, external_value, role)`                                                                       | map `group` / `claim-value` to a role                    |
| `acl_drop_role_mapping(issuer, source, external_value, role)`                                                              | drop a mapping                                           |
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
| `acl_deny_function(name)` / `acl_allow_function(name)`          | **legacy**: deny/allow a physical function by name (in memory without a source, a `function_gate` row with a catalog) |

**Doors and sessions** - registered alongside the admin functions; they are the operator's and the
door's, never a principal's, and have no management-SQL form. `acl_flight_serve` / `acl_flight_stop`
are registered elsewhere and documented with the Flight door.

| Function                                                                   | Returns  | Purpose                                                        |
| -------------------------------------------------------------------------- | -------- | -------------------------------------------------------------- |
| `acl_quack_serve(uri, token[, mode])` / `(uri, token, cert, key[, mode])`, `acl_quack_stop(uri)` | VARCHAR | open the quack door (`mode` `embedded` / `plain`); close it and, if it was the last door, sweep its sessions |
| `acl_quack_authenticate(session_id, client_token, server_token)`, `acl_quack_authorize(connection_id, query)` | BOOLEAN, VARCHAR | the door's per-connection and per-statement callbacks (prefixed SQL, or NULL to refuse) |
| `acl_session_open(token)`, `acl_session_sql(handle, sql)`, `acl_session_reason(handle)` | VARCHAR | mint a handle (NULL if the token fails), prefix a statement (NULL if unusable), `live`/`expired`/`idle`/`unknown` |
| `acl_session_close(handle)`, `acl_session_kill(id)`                        | BOOLEAN  | end a session by handle, or by the ops id `acl_sessions()` shows |
| `acl_sessions()`                                                           | VARCHAR  | live sessions as JSON (ops ids, never handles)                  |
| `acl_session_sweep()`, `acl_session_count()`                               | BIGINT   | drop dead sessions / count live ones                            |
| `acl_drain()`, `acl_resume()`, `acl_drain_status()`                        | BIGINT, BOOLEAN, VARCHAR | stop seating new clients, resume, `draining`/`serving` |
