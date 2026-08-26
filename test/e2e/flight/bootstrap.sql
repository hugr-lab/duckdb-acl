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

ATTACH ':memory:' AS store;
SELECT acl_use_db('store', 'acl', true);

SET GLOBAL acl_allow_anonymous_admin=true;
SELECT acl_define_issuer('https://issuer.test/s',
    '{"keys":[{"kty":"oct","k":"YWNsLXRlc3QtaHMyNTYtc2VjcmV0"}]}',
    'api://acl-test', 'HS256', 'roles', '{"tid": "tenant"}');
-- A second issuer whose keys live in a document that does not exist, with a failed read fatal at
-- once. A token naming it makes SessionOpen *throw* - keys are resolved before anything is verified
-- - which is the review's case: a C++ exception from under the door's own authentication, and the
-- one the boundary has to turn into a named refusal rather than "Unexpected error in RPC handling".
ACL ADMIN CREATE ISSUER 'https://issuer.test/file' KEYS FROM '/nonexistent/acl-e2e-jwks.json'
    AUDIENCES ('api://acl-test') ALGS (HS256) ROLE CLAIM 'roles';
SET GLOBAL acl_jwks_max_stale = 0;
ACL ADMIN CREATE VIRTUAL CATALOG c;
ACL ADMIN CREATE VIRTUAL TABLE c.orders AS memory.main.orders;
ACL ADMIN CREATE VIRTUAL TABLE c.customers AS memory.main.customers;
ACL ADMIN CREATE VIRTUAL REFERENCE c.orders_customer FROM orders TO customers
    ON (customer_id = id) CARDINALITY many_to_one COMMENT 'the ordering customer';
ACL ADMIN CREATE ROLE analyst;
ACL ADMIN GRANT CATALOG c TO ROLE analyst WITH (select) MAIN;
-- one role, many tenants: the slice comes from the token's claim
ACL ADMIN GRANT TABLE c.orders TO ROLE analyst
    CAPS '{"select": true}'
    RLS 'tenant = acl_claim(''tenant'')';
ACL ADMIN GRANT TABLE c.customers TO ROLE analyst WITH (select) COLUMNS (id, name);
SET GLOBAL acl_allow_anonymous_admin=false;

SELECT acl_flight_serve('${ACL_E2E_URI}');
