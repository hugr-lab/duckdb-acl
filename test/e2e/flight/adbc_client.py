"""Spec 047 through the real ADBC Flight SQL driver - the client DBeaver and Power BI embed.

Assertions, not a survey: each check exits non-zero on the first failure and says what it saw.
The globex token is minted here (HS256 over the test secret) so the stolen-handle check can ask
as a different principal without a second fixture.
"""
import base64, hashlib, hmac, json, sys
import adbc_driver_flightsql.dbapi as dbapi
from adbc_driver_flightsql import DatabaseOptions

uri, acme_token = sys.argv[1], sys.argv[2]

def mint(tenant):
    b64 = lambda raw: base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    head = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = b64(json.dumps({"iss": "https://issuer.test/s", "aud": "api://acl-test", "exp": 4102444800,
                           "sub": "u-" + tenant, "roles": ["analyst"], "tid": tenant}).encode())
    sig = b64(hmac.new(b"acl-test-hs256-secret", f"{head}.{body}".encode(), hashlib.sha256).digest())
    return f"{head}.{body}.{sig}"

def connect(token):
    return dbapi.connect(uri, db_kwargs={
        DatabaseOptions.AUTHORIZATION_HEADER.value: f"Bearer {token}",
        # design/015: the cookie makes the connection a session, which staging lives in
        "adbc.flight.sql.rpc.with_cookie_middleware": "true",
    })

failures = 0
def check(name, ok, detail=""):
    global failures
    print(("  ok:   " if ok else "  FAIL: ") + name + (": " + str(detail)[:160] if detail else ""))
    if not ok:
        failures += 1

with connect(acme_token) as conn:
    cur = conn.cursor()
    # --- parameterized queries: the client's own parameters, inside the principal's slice ---------
    cur.execute("SELECT count(*) FROM orders WHERE amount >= ?", (40,))
    check("parameterized ? answers the slice", cur.fetchall() == [(3,)])
    cur.execute("SELECT count(*) FROM orders WHERE amount >= $1", (40,))
    check("parameterized $1 answers the slice", cur.fetchall() == [(3,)])
    # the same cursor keeps working - the poisoned-cursor sequence from the survey, now clean
    cur.execute("SELECT count(*) FROM orders")
    check("the cursor survives (no poison)", cur.fetchall() == [(5,)])

    # --- executemany: rows land under the grant, and the predicate judges each row on write -------
    cur.executemany("INSERT INTO orders (id, tenant, amount, customer_id) VALUES (?, ?, ?, ?)",
                    [(300, "acme", 1, 0), (301, "acme", 2, 1)])
    cur.execute("SELECT count(*) FROM orders WHERE id >= 300")
    check("executemany rows landed", cur.fetchall() == [(2,)])
    # one batch, one outcome: the good row and the cross-tenant row travel in the SAME executemany,
    # and the refusal must take the whole batch with it - a partial commit plus a client retry is a
    # duplicated row (the review's scenario)
    try:
        cur.executemany("INSERT INTO orders (id, tenant, amount, customer_id) VALUES (?, ?, ?, ?)",
                        [(310, "acme", 1, 0), (311, "globex", 1, 0)])
        check("cross-tenant executemany refused", False, "the batch was written")
    except Exception as ex:
        check("cross-tenant executemany refused", "does not satisfy the grant" in str(ex), ex)
    cur.execute("SELECT count(*) FROM orders WHERE id IN (310, 311)")
    check("and the refusal took the whole batch (no partial commit)", cur.fetchall() == [(0,)])

    # --- bulk ingestion (spec 049): the real driver's adbc_ingest, confined like any write --------
    import pyarrow as pa
    batch = pa.table({"id": [400, 401], "tenant": ["acme", "acme"], "amount": [1, 2],
                      "customer_id": [0, 1]})
    n = cur.adbc_ingest("orders", batch, mode="append")
    check("adbc_ingest append landed", n == 2, n)
    cur.execute("SELECT count(*) FROM orders WHERE id IN (400, 401)")
    check("the ingested rows read back", cur.fetchall() == [(2,)])
    try:
        cur.adbc_ingest("orders", pa.table({"id": [410], "tenant": ["globex"], "amount": [1],
                                            "customer_id": [0]}), mode="append")
        check("cross-tenant ingest refused", False, "the stream was written")
    except Exception as ex:
        check("cross-tenant ingest refused", "does not satisfy the grant" in str(ex), ex)
    cur.execute("SELECT count(*) FROM orders WHERE id = 410")
    check("and nothing of the refused stream landed", cur.fetchall() == [(0,)])
    try:
        cur.adbc_ingest("brand_new", batch, mode="create")
        check("mode create refused with the reason", False, "a table was created")
    except Exception as ex:
        check("mode create refused with the reason", "does not create tables" in str(ex), ex)

    # --- milestone 2: temporary staging + a text MERGE - the decided upsert flow ------------------
    stage = pa.table({"id": [300, 950], "amount": [42, 9]})
    n = cur.adbc_ingest("stage1", stage, mode="create", temporary=True)
    check("temporary staging landed", n == 2, n)
    cur.execute("SELECT count(*) FROM stage1")
    check("the credential reads its own staging", cur.fetchall() == [(2,)])
    cur.execute("MERGE INTO orders USING stage1 ON orders.id = stage1.id "
                "WHEN MATCHED THEN UPDATE SET amount = stage1.amount "
                "WHEN NOT MATCHED THEN INSERT (id, tenant, amount, customer_id) "
                "VALUES (stage1.id, 'acme', stage1.amount, 0)")
    cur.fetchall()  # the flight driver prepares on execute and runs on fetch - fetch, so it runs
    cur.execute("SELECT amount FROM orders WHERE id = 300")
    check("merge updated the matched row from staging", cur.fetchall() == [(42,)])
    cur.execute("SELECT count(*) FROM orders WHERE id = 950")
    check("merge inserted the unmatched row from staging", cur.fetchall() == [(1,)])
    try:
        cur.adbc_ingest("stage2", stage, mode="create", temporary=True, db_schema_name="main")
        check("temporary with a schema refused", False, "it was accepted")
    except Exception as ex:
        check("temporary with a schema refused", "takes no catalog or schema" in str(ex), ex)
    cur.execute("DROP TABLE stage1")
    cur.fetchall()
    try:
        cur.execute("SELECT count(*) FROM stage1")
        check("the dropped staging no longer resolves", False, "it still answered")
    except Exception as ex:
        check("the dropped staging no longer resolves", "no access" in str(ex), ex)

    # --- get_info comes from the registered SqlInfo ------------------------------------------------
    info = conn.adbc_get_info()
    check("get_info vendor", info.get("vendor_name") == "duckdb-acl", info.get("vendor_name"))

# --- two principals through the same prepared SQL see their own slices ---------------------------
with connect(acme_token) as acme, connect(mint("globex")) as globex:
    a = acme.cursor(); g = globex.cursor()
    a.execute("SELECT count(*) FROM orders WHERE tenant = 'acme'")
    acme_rows = a.fetchall()[0][0]
    g.execute("SELECT count(*) FROM orders WHERE tenant = 'acme'")
    check("globex cannot see acme rows through the same SQL", g.fetchall() == [(0,)])
    # spec 049: another session's staging is not a name here (and another principal, another session)
    a.execute("SELECT count(*) FROM orders")  # acme re-stages under its own fingerprint
    acme.cursor().adbc_ingest("iso_stage", pa.table({"id": [1]}), mode="create", temporary=True)
    try:
        g.execute("SELECT count(*) FROM iso_stage")
        check("another credential's staging is invisible", False, "globex read it")
    except Exception as ex:
        check("another credential's staging is invisible", "no access" in str(ex), ex)
    g.execute("SELECT count(*) FROM orders")
    globex_rows = g.fetchall()[0][0]
    check("the two principals see different slices", acme_rows > 0 and globex_rows != acme_rows,
          f"acme={acme_rows} globex={globex_rows}")

print("PASS" if failures == 0 else f"FAIL ({failures})")
sys.exit(0 if failures == 0 else 1)
