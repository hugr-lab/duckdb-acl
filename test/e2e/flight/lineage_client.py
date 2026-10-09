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
