-- The server side of the door e2e (spec 043). Run by test/e2e/door/run.sh in a process that stays
-- alive for the length of the run; the clients are separate processes talking to it over the socket.
--
-- Source-agnostic: run.sh substitutes the ATTACH for whichever source this leg is, and the physical
-- name that source publishes under. Everything here is the operator's own work, done before anyone is
-- served - attach the source, own the table this run writes to, describe the policy, then open the door.

-- --- the source ------------------------------------------------------------------------------------
${ACL_E2E_ATTACH}

-- The run owns its data: a table of this test's own, dropped and rebuilt at the start, so a rerun is
-- clean and a leftover row can neither pass for a bug nor hide one.
DROP TABLE IF EXISTS ${ACL_E2E_TABLE};
CREATE TABLE ${ACL_E2E_TABLE} (id INTEGER, tenant VARCHAR, amount INTEGER);
INSERT INTO ${ACL_E2E_TABLE} VALUES (1, 'acme', 100), (2, 'globex', 200), (3, 'acme', 300);

-- --- policy ------------------------------------------------------------------------------------------
ATTACH ':memory:' AS store;
SELECT acl_use_db('store', 'acl', true);

SET GLOBAL acl_allow_anonymous_admin=true;

SELECT acl_define_issuer('https://issuer.test/s',
    '{"keys":[{"kty":"oct","k":"YWNsLXRlc3QtaHMyNTYtc2VjcmV0"}]}',
    'api://acl-test', 'HS256', 'roles', '{"tid": "tenant"}');

ACL ADMIN CREATE VIRTUAL CATALOG c;
ACL ADMIN CREATE VIRTUAL TABLE c.orders AS ${ACL_E2E_TABLE};
ACL ADMIN CREATE ROLE analyst;
ACL ADMIN GRANT CATALOG c TO ROLE analyst WITH (select, insert) MAIN;

-- One role, many tenants: the slice comes from the token's claim, not from the role name. The grant
-- both confines reads (RLS) and assigns the tenant on write, so a client cannot place a row outside
-- its own slice even by trying - which is what the run then checks by reading the stored rows.
ACL ADMIN GRANT TABLE c.orders TO ROLE analyst
    CAPS '{"select": true, "insert": true}'
    RLS 'tenant = acl_claim(''tenant'')'
    COLUMNS 'id,tenant=acl_claim(''tenant''),amount';

-- A leg may publish a second object over another source (the cross-source join under load): run.sh
-- renders the statements here, or nothing.
${ACL_E2E_EXTRA}

SET GLOBAL acl_allow_anonymous_admin=false;

-- the audit's counters through the door's own listener (spec 069): run.sh reads GET /metrics after
-- the clients are done and checks the loads and the sessions it caused are counted
SET GLOBAL acl_metrics_endpoint=true;

-- --- the door ------------------------------------------------------------------------------------
SELECT acl_quack_serve('quack:localhost:${ACL_E2E_PORT}', '${ACL_E2E_SERVER_TOKEN}');
