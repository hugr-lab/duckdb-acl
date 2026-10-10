-- The server side of the Flight SQL door e2e (spec 045), run by test/e2e/flight/run.sh in a process
-- that stays alive for the length of the run. The client is a separate process speaking Flight SQL -
-- a third-party one, on purpose: a door is only proven by something that is not us.

CREATE TABLE orders AS
    SELECT i AS id, CASE WHEN i % 2 = 0 THEN 'acme' ELSE 'globex' END AS tenant, i * 10 AS amount,
           i % 3 AS customer_id
    FROM range(10) t(i);

-- a second object, so a listing has something to be a listing *of*, and a reference has two ends.
-- `ssn` is granted to nobody: it is what proves a hidden column is hidden from the schema a client is
-- promised, not only from its rows (spec 046).
CREATE TABLE customers AS
    SELECT i AS id, 'name' || i AS name, 'ssn-' || i AS ssn FROM range(3) t(i);

-- spec 051: a physical home a role may build in through ingest create/replace - and a second one
-- granted create WITHOUT drop, so the replace refusal has a stage of its own
CREATE SCHEMA staging;
CREATE SCHEMA staging2;

-- spec 099: an ENUM column, read as it is by one virtual table and as VARCHAR by the other
CREATE TYPE tier AS ENUM ('gold', 'silver');
CREATE TABLE typed AS SELECT 1 AS id, 'gold'::tier AS tier, {'a': 'silver'::tier} AS s;
-- spec 102: a struct a grant narrows to one field
CREATE TABLE nested AS SELECT 1 AS id, {'city': 'A', 'ssn': 'S1'} AS address;

-- spec 116: a schema and tables named the way SQL allows - a space, mixed case - and a reference
-- between them, so the catalog RPCs and the key RPCs answer quoted names
CREATE SCHEMA "Raw Data";
CREATE TABLE "Raw Data"."Order Items" AS SELECT i AS id, i * 2 AS "Qty" FROM range(3) t(i);
CREATE TABLE "Raw Data"."Line Items" AS SELECT i AS line, i % 3 AS "Order Id" FROM range(6) t(i);

ATTACH ':memory:' AS store;
SELECT acl_use_db('store', 'acl', true);

SET GLOBAL acl_allow_anonymous_admin=true;
SET GLOBAL acl_jwks_locations = 'test/idp/';  -- spec 095: the fixture issuers' discovery, read from the repository root
SELECT acl_define_issuer('test/idp/s', '{"url": "test/idp/s", "client": {"audiences": ["api://acl-test"], "roles_from": ["roles"], "attributes": {"tid": "tenant"}}}');
-- A second issuer whose discovery document does not exist, with a failed read fatal at once. A token naming it makes SessionOpen *throw* - keys are resolved before anything is verified
-- - which is the review's case: a C++ exception from under the door's own authentication, and the
-- one the boundary has to turn into a named refusal rather than "Unexpected error in RPC handling".
-- the location is allowed, the document is not there (spec 071)
ACL ADMIN CREATE ISSUER 'test/idp/nofile'
    AUDIENCES ('api://acl-test') ROLE CLAIM 'roles';
SET GLOBAL acl_jwks_max_stale = 0;
ACL ADMIN CREATE VIRTUAL CATALOG c;
-- the key needs no COLUMNS list (a bare list is a projection, which is read-only) - and the key
-- itself is what promises id NOT NULL
ACL ADMIN CREATE VIRTUAL TABLE c.orders AS memory.main.orders PRIMARY KEY (id);
ACL ADMIN CREATE VIRTUAL TABLE c.customers AS memory.main.customers;
ACL ADMIN CREATE VIRTUAL REFERENCE c.orders_customer FROM orders TO customers
    ON (customer_id = id) CARDINALITY many_to_one COMMENT 'the ordering customer';
ACL ADMIN CREATE VIRTUAL TABLE c.typed AS memory.main.typed;
ACL ADMIN CREATE VIRTUAL TABLE c.typed_v AS memory.main.typed;
ACL ADMIN ALTER VIRTUAL TABLE c.typed_v SET TYPES (enums = varchar);
ACL ADMIN CREATE VIRTUAL TABLE c.nested AS memory.main.nested;
ACL ADMIN CREATE VIRTUAL TABLE c."Raw Data"."Order Items" AS memory."Raw Data"."Order Items" PRIMARY KEY (id);
ACL ADMIN CREATE VIRTUAL TABLE c."Raw Data"."Line Items" AS memory."Raw Data"."Line Items";
ACL ADMIN CREATE VIRTUAL REFERENCE c."Line To Order" FROM "Raw Data"."Line Items" TO "Raw Data"."Order Items"
    ON ("Order Id" = id);
ACL ADMIN CREATE ROLE analyst;
-- temp is explicit (spec 050): session temp tables ride on it, and nothing else grants them
ACL ADMIN GRANT CATALOG c TO ROLE analyst WITH (select, insert, temp) MAIN;
-- one role, many tenants: the slice comes from the token's claim
ACL ADMIN GRANT TABLE c.orders TO ROLE analyst
    CAPS '{"select": true, "insert": true}'
    RLS 'tenant = acl_claim(''tenant'')';
ACL ADMIN GRANT TABLE c.customers TO ROLE analyst WITH (select) COLUMNS (id, name);
ACL ADMIN GRANT TABLE c.nested TO ROLE analyst WITH (select) COLUMNS (id, address.city);
-- spec 051: create prices CREATE, drop prices REPLACE and DROP - a live-alias schema as the home
ACL ADMIN CREATE VIRTUAL SCHEMA c.stage AS memory.staging;
ACL ADMIN GRANT SCHEMA c.stage TO ROLE analyst WITH (select, insert, create, drop);
ACL ADMIN CREATE VIRTUAL SCHEMA c.stage2 AS memory.staging2;
ACL ADMIN GRANT SCHEMA c.stage2 TO ROLE analyst WITH (select, insert, create);
SET GLOBAL acl_allow_anonymous_admin=false;

SELECT acl_flight_serve('${ACL_E2E_URI}');
