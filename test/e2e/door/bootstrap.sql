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

SET GLOBAL acl_jwks_locations = 'test/idp/';  -- spec 095: the fixture issuers' discovery, read from the repository root
SELECT acl_define_issuer('test/idp/s', '{"url": "test/idp/s", "client": {"audiences": ["api://acl-test"], "roles_from": ["roles"], "attributes": {"tid": "tenant"}}}');

ACL ADMIN CREATE VIRTUAL CATALOG c;
ACL ADMIN CREATE VIRTUAL TABLE c.orders AS ${ACL_E2E_TABLE};
ACL ADMIN CREATE ROLE analyst;
ACL ADMIN GRANT CATALOG c TO ROLE analyst WITH (select, insert) MAIN;
-- spec 117: the role also holds a view of the platform catalog - which quack must never show it (quack
-- loads a catalog whole; the console is Flight / JDBC). A role holding anything of platform is reached
-- only through its client's own mapping (spec 095), so the token's role value is mapped explicitly.
ACL ADMIN GRANT VIEW platform.sessions TO ROLE analyst;
ACL ADMIN MAP CLAIM 'analyst' FROM CLIENT 'test/idp/s' TO ROLE analyst;

-- One role, many tenants: the slice comes from the token's claim, not from the role name. The grant
-- both confines reads (RLS) and assigns the tenant on write, so a client cannot place a row outside
-- its own slice even by trying - which is what the run then checks by reading the stored rows.
ACL ADMIN GRANT TABLE c.orders TO ROLE analyst
    CAPS '{"select": true, "insert": true}'
    RLS 'tenant = acl_claim(''tenant'')'
    COLUMNS 'id,tenant=acl_claim(''tenant''),amount';

-- spec 114: a second catalog the role holds (not MAIN), for a client's USE through the door
ACL ADMIN CREATE VIRTUAL CATALOG m;
ACL ADMIN CREATE VIRTUAL VIEW m.hello AS 'SELECT 7 AS v';
-- spec 115: a nested schema, as quack loads it (through the parent oids)
ACL ADMIN CREATE VIRTUAL VIEW m.raw.eu.deep AS 'SELECT 8 AS v';
ACL ADMIN GRANT CATALOG m TO ROLE analyst WITH (select);
-- spec 116: a catalog, a schema and a view named the way SQL allows, as quack loads them
ACL ADMIN CREATE VIRTUAL CATALOG "Sales Mart";
ACL ADMIN CREATE VIRTUAL VIEW "Sales Mart"."Raw Data"."Order Items" AS 'SELECT 9 AS v';
ACL ADMIN GRANT CATALOG "Sales Mart" TO ROLE analyst WITH (select);

-- A leg may publish a second object over another source (the cross-source join under load): run.sh
-- renders the statements here, or nothing.
${ACL_E2E_EXTRA}

SET GLOBAL acl_allow_anonymous_admin=false;

-- the audit's counters through the door's own listener (spec 069): run.sh reads GET /metrics after
-- the clients are done and checks the loads and the sessions it caused are counted
SET GLOBAL acl_metrics_endpoint=true;
-- spec 097: the metrics answer a bearer holding `observe`; this harness is about the door under load,
-- not who reads its counters, so it scrapes without one - the operator's explicit opt-out
SET GLOBAL acl_observe_unauthenticated=true;

-- --- the door ------------------------------------------------------------------------------------
SELECT acl_quack_serve('quack:localhost:${ACL_E2E_PORT}', '${ACL_E2E_SERVER_TOKEN}');
