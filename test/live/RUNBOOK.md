# The live-validation runbook (spec 057)

The single-node phase ends with eyes on real tools, not only our own harnesses. Start the node:

```sh
make                       # if not built yet
test/live/serve.sh         # or: test/live/serve.sh --tls
```

It prints the URIs and three tokens (`analyst@acme`, `analyst@globex`, `viewer@acme`) and stays up
until Ctrl+C. Everything scripted below the GUI steps is already pinned by CI (`make test-flight`,
the quack integration tests); this runbook is the human pass over the same ground.

The one rule for reading results: **every number a tool shows must be explainable by the token you
pasted** - `analyst@acme` sees 5 of the 10 seeded orders, `analyst@globex` the other 5, and neither
ever sees `customers.ssn` anywhere, including in the column tree.

## DBeaver (the Arrow Flight SQL JDBC driver - what spec 047 targets)

Setup once: Database > Driver Manager > New - class `org.apache.arrow.driver.jdbc.ArrowFlightJdbcDriver`,
artifact `org.apache.arrow:flight-sql-jdbc-driver:<current>` from Maven. New connection with the JDBC
URL `serve.sh` printed; put the token in driver properties as `token`.

| # | Do | Expect |
|---|----|--------|
| 1 | Connect with `analyst@acme` | connects; the tree shows **one** database `c` with `main` and `stage` - never `memory`, `store`, or the server's own catalogs |
| 2 | Expand `c.main.customers` columns | `id`, `name` - **no `ssn`** (hidden from the promised schema, spec 026/046) |
| 3 | `SELECT * FROM orders` | 5 rows, all `tenant = 'acme'` |
| 4 | `SELECT * FROM orders WHERE tenant = 'globex'` | 0 rows - the predicate, not an error |
| 5 | `INSERT INTO orders (id, tenant, amount, customer_id) VALUES (100, 'acme', 1, 0)` | 1 row; re-run #3 shows it |
| 6 | same INSERT with `'globex'` | refused: *the row does not satisfy the grant on "orders"* |
| 7 | `EXPLAIN SELECT * FROM orders` | a plan (analyst holds `explain`); the physical name in it is the capability's point, spec 052 |
| 8 | Turn off auto-commit; INSERT an acme row; rollback; re-run #3 | the row is gone (spec 055 through the real driver) |
| 9 | `CREATE TEMP TABLE scratch AS SELECT * FROM orders` then `SELECT count(*) FROM scratch` | 5 - the session temp lives on this connection (spec 050); a second connection cannot see it |
| 10 | `CREATE TABLE stage.bulk AS SELECT * FROM orders` then `DROP TABLE stage.bulk` | both pass - the staging schema grants create+drop (spec 051) |
| 11 | Reconnect with `viewer@acme`; repeat #5 | refused: *insert on "orders" is not allowed*; #7 refused: *EXPLAIN needs the explain capability* |
| 12 | Reconnect with `analyst@globex`; run #3 | the **other** 5 rows; row 100 from step 5 is not among them |
| 13 | Connect with a garbage token | *authentication failed* - and nothing more |

## ADBC (python - scripted in CI, manual spot-check here)

```python
import adbc_driver_flightsql.dbapi as dbapi
from adbc_driver_flightsql import DatabaseOptions
conn = dbapi.connect("grpc://localhost:32700", db_kwargs={
    DatabaseOptions.AUTHORIZATION_HEADER.value: "Bearer <analyst@acme token>",
    DatabaseOptions.WITH_COOKIE_MIDDLEWARE.value: "true"})
cur = conn.cursor()
cur.execute("SELECT count(*) FROM orders"); print(cur.fetchall())   # [(5,)]
import pyarrow as pa
cur.adbc_ingest("stage_tmp", pa.table({"id":[1],"tenant":["acme"],"amount":[1],"customer_id":[0]}),
                temporary=True)                                      # session staging, spec 050
cur.execute("SELECT count(*) FROM stage_tmp"); print(cur.fetchall()) # [(1,)]
```

The full scripted pass is `make test-flight` (`run.sh`, `adbc.sh`, `tls.sh`).

## quack (duckdb CLI as the client)

```sql
-- in a second duckdb -unsigned, with quack available:
ATTACH 'quack:localhost:31700' AS remote (TYPE quack, TOKEN '<analyst@acme token>');
SELECT count(*) FROM remote.main.orders;                  -- 5
CREATE TABLE payload AS SELECT 200 + i AS id, 'acme' AS tenant, i AS amount, 0 AS customer_id
    FROM range(1000) t(i);
INSERT INTO remote.main.orders SELECT * FROM payload;     -- the SEND_DATA drain, spec 042
SELECT count(*) FROM remote.main.orders;                  -- 1005
CREATE TABLE remote.stage.load(id INT, tenant VARCHAR);   -- staging schema, specs 051/056
INSERT INTO remote.stage.load SELECT id, tenant FROM payload;
DROP TABLE remote.stage.load;
```

The scripted pass is `test/sql/integration/acl_quack_*.test` and `test/e2e/door/run.sh`.

## What a refusal must look like

Wherever a step is refused, the tool shows our sentence (*"...is not allowed"*, *"does not satisfy
the grant"*, *"authentication failed"*, *"EXPLAIN needs the explain capability"*) - never a stack
trace, never a physical object name the role cannot see, and never *"Unexpected error in RPC
handling"* (the boundary of spec 045 exists to prevent exactly that one).
