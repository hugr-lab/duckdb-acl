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
    # the cookie is what makes a connection ONE session on the door (spec 050) - the same middleware
    # every production deployment of this driver would enable
    return dbapi.connect(uri, db_kwargs={DatabaseOptions.AUTHORIZATION_HEADER.value: f"Bearer {token}",
                                         DatabaseOptions.WITH_COOKIE_MIDDLEWARE.value: "true"})

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
        check("mode create refused with the reason", "no schema of the catalog allows creating" in str(ex), ex)

    # --- spec 050: a temporary ingest target lives in the session ---------------------------------
    # The staging pattern spec 049 promised: bulk rows into a session temp, then ordinary SQL moves
    # them into the granted table under every rule the grant carries - and the staging table is
    # invisible to every other connection, then gone with this one.
    stage = pa.table({"id": [510, 511], "tenant": ["acme", "acme"], "amount": [7, 8],
                      "customer_id": [0, 1]})
    n = cur.adbc_ingest("stage", stage, temporary=True)
    check("temporary ingest landed in the session", n == 2, n)
    cur.execute("SELECT count(*) FROM stage")
    check("the session reads its own staging table", cur.fetchall() == [(2,)])
    cur.execute("INSERT INTO orders (id, tenant, amount, customer_id) "
                "SELECT id, tenant, amount, customer_id FROM stage")
    cur.fetchall()  # a DML through the query wire executes on the fetch - redeem the ticket
    cur.execute("SELECT count(*) FROM orders WHERE id IN (510, 511)")
    check("staged rows moved into the granted table as ordinary SQL", cur.fetchall() == [(2,)])
    with connect(acme_token) as other:
        try:
            other.cursor().execute("SELECT * FROM stage")
            check("another connection cannot see the staging table", False, "it answered")
        except Exception as ex:
            check("another connection cannot see the staging table", "no access to object" in str(ex), ex)

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
    g.execute("SELECT count(*) FROM orders")
    globex_rows = g.fetchall()[0][0]
    check("the two principals see different slices", acme_rows > 0 and globex_rows != acme_rows,
          f"acme={acme_rows} globex={globex_rows}")

print("PASS" if failures == 0 else f"FAIL ({failures})")
sys.exit(0 if failures == 0 else 1)
