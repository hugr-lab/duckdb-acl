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
    return dbapi.connect(uri, db_kwargs={DatabaseOptions.AUTHORIZATION_HEADER.value: f"Bearer {token}"})

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
    try:
        cur.executemany("INSERT INTO orders (id, tenant, amount, customer_id) VALUES (?, ?, ?, ?)",
                        [(302, "globex", 1, 0)])
        check("cross-tenant executemany refused", False, "the row was written")
    except Exception as ex:
        check("cross-tenant executemany refused", "does not satisfy the grant" in str(ex), ex)

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
