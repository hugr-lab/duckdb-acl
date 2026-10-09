"""Spec 112 through the real ADBC Flight SQL driver: what a job's writes become in lineage.

Run by adbc.sh after the door's lineage is on. Each call carries the job's parent run in the
x-openlineage-parent header (what a driver sets from OPENLINEAGE_PARENT_ID); adbc.sh then asks the
serving process what acl_lineage_events() holds for that parent.
"""
import sys
import adbc_driver_flightsql.dbapi as dbapi
import pyarrow as pa
from adbc_driver_flightsql import DatabaseOptions

uri, token, parent = sys.argv[1], sys.argv[2], sys.argv[3]
HEADER = DatabaseOptions.RPC_CALL_HEADER_PREFIX.value + "x-openlineage-parent"

def connect(lineage_parent):
    conn = dbapi.connect(uri, db_kwargs={DatabaseOptions.AUTHORIZATION_HEADER.value: f"Bearer {token}",
                                         DatabaseOptions.WITH_COOKIE_MIDDLEWARE.value: "true",
                                         HEADER: lineage_parent})
    conn.adbc_connection.set_autocommit(True)
    return conn

failures = 0
def check(name, ok, detail=""):
    global failures
    print(("  ok:   " if ok else "  FAIL: ") + name + (": " + str(detail)[:160] if detail else ""))
    if not ok:
        failures += 1

with connect(parent) as conn:
    cur = conn.cursor()
    # spec 112 §2: five rows of one executemany are one DoPut - one run, not five
    cur.executemany("INSERT INTO orders (id, tenant, amount, customer_id) VALUES (?, ?, ?, ?)",
                    [(900 + i, "acme", i, 0) for i in range(5)])
    # spec 112 §4: a bulk ingest is a write with its call's lineage context
    n = cur.adbc_ingest("orders", pa.table({"id": [910, 911], "tenant": ["acme", "acme"], "amount": [1, 2],
                                            "customer_id": [0, 1]}), mode="append")
    check("the ingest landed", n == 2, n)
    # ... and a batch with a row the grant refuses is one RUN_FAIL (the whole batch rolled back)
    try:
        cur.executemany("INSERT INTO orders (id, tenant, amount, customer_id) VALUES (?, ?, ?, ?)",
                        [(940, "acme", 1, 0), (941, "globex", 1, 0)])
        check("a refused batch fails", False, "the batch was written")
    except Exception as ex:
        check("a refused batch fails", "does not satisfy the grant" in str(ex), ex)

# a write inside a CTE, prepared with a parameter its result type rides on: the door does not submit it
# to learn its schema (that ran the INSERT a second time). Its schema stays unknown, which this driver
# refuses - the write may fail, but it never lands twice (the review's finding). Under a parent of its
# own: the runs of the parent above are counted exactly
with connect("airflow/daily.cte/01929e3a-0000-7000-8000-0000000001c7") as conn:
    cur = conn.cursor()
    try:
        cur.execute("WITH w AS (INSERT INTO orders (id, tenant, amount, customer_id) VALUES (930, 'acme', 1, 0) "
                    "RETURNING id) SELECT id, ? AS tag FROM w", ("t",))
        cur.fetchall()
    except Exception:
        pass
    cur.execute("SELECT count(*) FROM orders WHERE id = 930")
    n = cur.fetchall()
    check("a CTE write prepared with a parameter never lands twice", n in ([(0,)], [(1,)]), n)
    # the documented form: the parameter cast to its type gives the statement a schema - it runs once
    # and its rows come back
    cur.execute("WITH w AS (INSERT INTO orders (id, tenant, amount, customer_id) VALUES (931, 'acme', 1, 0) "
                "RETURNING id) SELECT id, ?::VARCHAR AS tag FROM w", ("t",))
    got = cur.fetchall()
    cur.execute("SELECT count(*) FROM orders WHERE id = 931")
    n = cur.fetchall()
    check("a CTE write with a typed parameter returns its rows and lands once", got == [(931, "t")] and n == [(1,)],
          (got, n))

# spec 109 on the ingest path: a malformed parent is the call's error, the stream never lands
with connect("airflow/daily/not-a-uuid") as conn:
    cur = conn.cursor()
    try:
        cur.adbc_ingest("orders", pa.table({"id": [920], "tenant": ["acme"], "amount": [1], "customer_id": [0]}),
                        mode="append")
        check("a malformed lineage parent on ingest is refused", False, "the stream was written")
    except Exception as ex:
        check("a malformed lineage parent on ingest is refused", "x-openlineage-parent" in str(ex), ex)

sys.exit(1 if failures else 0)
