-- The server side of the Flight SQL door e2e (spec 045), run by test/e2e/flight/run.sh in a process
-- that stays alive for the length of the run. The client is a separate process speaking Flight SQL -
-- a third-party one, on purpose: a door is only proven by something that is not us.

CREATE TABLE orders AS
    SELECT i AS id, CASE WHEN i % 2 = 0 THEN 'acme' ELSE 'globex' END AS tenant, i * 10 AS amount
    FROM range(10) t(i);

ATTACH ':memory:' AS store;
SELECT acl_use_db('store', 'acl', true);

SET GLOBAL acl_allow_anonymous_admin=true;
SELECT acl_define_issuer('https://issuer.test/s',
    '{"keys":[{"kty":"oct","k":"YWNsLXRlc3QtaHMyNTYtc2VjcmV0"}]}',
    'api://acl-test', 'HS256', 'roles', '{"tid": "tenant"}');
ACL ADMIN CREATE VIRTUAL CATALOG c;
ACL ADMIN CREATE VIRTUAL TABLE c.orders AS memory.main.orders;
ACL ADMIN CREATE ROLE analyst;
ACL ADMIN GRANT CATALOG c TO ROLE analyst WITH (select) MAIN;
-- one role, many tenants: the slice comes from the token's claim
ACL ADMIN GRANT TABLE c.orders TO ROLE analyst
    CAPS '{"select": true}'
    RLS 'tenant = acl_claim(''tenant'')';
SET GLOBAL acl_allow_anonymous_admin=false;

SELECT acl_flight_serve('${ACL_E2E_URI}');
