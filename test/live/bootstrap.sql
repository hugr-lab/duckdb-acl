-- The live-validation node (spec 057): one served instance real client tools connect to, seeded with
-- everything the runbook walks through. Started by serve.sh, which substitutes the ${LIVE_*} values.

CREATE TABLE orders AS
    SELECT i AS id, CASE WHEN i % 2 = 0 THEN 'acme' ELSE 'globex' END AS tenant, i * 10 AS amount,
           i % 3 AS customer_id
    FROM range(10) t(i);

-- `ssn` is granted to nobody: the runbook checks it is absent from the tool's column tree, not only
-- from the rows.
CREATE TABLE customers AS
    SELECT i AS id, 'name' || i AS name, 'ssn-' || i AS ssn FROM range(3) t(i);

-- the staging home (spec 051): create prices CREATE, drop prices REPLACE and DROP
CREATE SCHEMA staging;

ATTACH ':memory:' AS store;
SELECT acl_use_db('store', 'acl', true);

SET GLOBAL acl_allow_anonymous_admin=true;
SELECT acl_define_issuer('https://issuer.test/s',
    '{"keys":[{"kty":"oct","k":"YWNsLXRlc3QtaHMyNTYtc2VjcmV0"}]}',
    'api://acl-test', 'HS256', 'roles', '{"tid": "tenant"}');
ACL ADMIN CREATE VIRTUAL CATALOG c;
ACL ADMIN CREATE VIRTUAL TABLE c.orders AS memory.main.orders PRIMARY KEY (id);
ACL ADMIN CREATE VIRTUAL TABLE c.customers AS memory.main.customers;
ACL ADMIN CREATE VIRTUAL REFERENCE c.orders_customer FROM orders TO customers
    ON (customer_id = id) CARDINALITY many_to_one COMMENT 'the ordering customer';

-- analyst: the full working role - reads its slice, writes under the predicate, stages, EXPLAINs
ACL ADMIN CREATE ROLE analyst;
ACL ADMIN GRANT CATALOG c TO ROLE analyst WITH (select, insert, temp, explain) MAIN;
-- COLUMNS lists all four (so it restricts nothing) but gives the write path a publish order - which
-- is what a quack SEND_DATA drain auto-names its positional stream against: without it, an unnamed
-- INSERT under a predicate is refused (spec 024/042), and quack's drain is always unnamed because
-- the column list does not travel over the wire. The Flight door's adbc_ingest names columns itself,
-- so it needs neither - but the one grant serves both doors.
ACL ADMIN GRANT TABLE c.orders TO ROLE analyst
    CAPS '{"select": true, "insert": true}'
    RLS 'tenant = acl_claim(''tenant'')'
    COLUMNS 'id,tenant,amount,customer_id';
ACL ADMIN GRANT TABLE c.customers TO ROLE analyst WITH (select) COLUMNS (id, name);
ACL ADMIN CREATE VIRTUAL SCHEMA c.stage AS memory.staging;
ACL ADMIN GRANT SCHEMA c.stage TO ROLE analyst WITH (select, insert, create, drop);

-- viewer: select on orders and nothing else - every other step of the runbook is a refusal here
ACL ADMIN CREATE ROLE viewer;
ACL ADMIN GRANT CATALOG c TO ROLE viewer CAPS '{}' MAIN;
ACL ADMIN GRANT TABLE c.orders TO ROLE viewer WITH (select) RLS 'tenant = acl_claim(''tenant'')';

-- an optional real issuer (spec 057): serve.sh fills this with a Keycloak issuer when
-- ACL_LIVE_KEYCLOAK is set, else it is a no-op. A Keycloak realm role named `analyst`/`viewer`
-- resolves to the same ACL role by name (unmapped raw roles match a known role), and a `tenant`
-- claim (a user attribute + protocol mapper) drives the RLS the demo tokens drive with `tid`.
${LIVE_KEYCLOAK_ISSUER}
SET GLOBAL acl_allow_anonymous_admin=false;

${LIVE_FLIGHT_SERVE}
${LIVE_QUACK_SERVE}
SELECT 'the live node is up' AS status;
