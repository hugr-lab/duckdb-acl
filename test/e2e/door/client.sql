-- One client of the door e2e (spec 043), run as its own process against the served instance.
-- run.sh substitutes the ${ACL_E2E_*} values; the token decides which tenant this client is.
--
-- Output is machine-checked by run.sh, so every result carries a label and nothing else is printed.
--
-- Isolation is judged by `id`, not by `tenant`, and that is deliberate. The grant computes `tenant` as
-- the principal's own claim, so it reads back as this client's tenant whatever is stored - a check on
-- that column could never fail, which is worse than no check at all. `id` is neither masked nor
-- injected: each client's rows live in a range of its own, so a row from anywhere else is visible as
-- itself. What is *stored* under each tenant is checked separately by run.sh, reading the source
-- directly, outside the ACL.

ATTACH 'quack:localhost:${ACL_E2E_PORT}' AS remote (TYPE quack, TOKEN '${ACL_E2E_TOKEN}');

-- What this client can see before anyone writes: its own seeded rows and nothing else.
SELECT 'seen_before' AS label, count(*) AS n,
       count(*) FILTER (WHERE NOT (${ACL_E2E_OWN})) AS foreign_rows
FROM remote.main.orders;

-- The bulk load. The payload lives in a table of this client's own, which the server cannot see, so
-- quack has to stream it - this is spec 042's drain path and not a statement pushed to the server.
-- The tenant column is filled with a value this client is NOT allowed to write, so a row stored with
-- it would prove the grant's assignment did not happen.
CREATE TABLE payload AS
    SELECT ${ACL_E2E_ID_BASE} + i AS id, 'INTRUDER' AS tenant, i AS amount
    FROM range(${ACL_E2E_ROWS}) t(i);

INSERT INTO remote.main.orders SELECT * FROM payload;

-- What this client sees afterwards: its own rows, including the ones it just wrote, and nothing of
-- whatever the other clients were doing at the same time.
SELECT 'seen_after' AS label, count(*) AS n,
       count(*) FILTER (WHERE NOT (${ACL_E2E_OWN})) AS foreign_rows
FROM remote.main.orders;

-- spec 114: a quack client's own USE is its local catalog; the node's is set through quack_query_by_name
-- and kept on this client's session - a short name then reads the catalog it chose
FROM quack_query_by_name('remote', 'USE m');
SELECT 'use' AS label, * FROM quack_query_by_name('remote', 'SELECT current_database() || ''.'' || v FROM hello');
FROM quack_query_by_name('remote', 'USE c');
-- spec 115: another catalog's nested schema, read through quack's own catalog (remote.<vcat>.<a>.<b>.<t>)
SELECT 'nested' AS label, v FROM remote.m.raw.eu.deep;
SELECT 'use_back' AS label, * FROM quack_query_by_name('remote', 'SELECT current_database()');
