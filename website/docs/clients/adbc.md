# ADBC (python)

```python
import adbc_driver_flightsql.dbapi as dbapi
from adbc_driver_flightsql import DatabaseOptions

conn = dbapi.connect("grpc://<host>:<port>", db_kwargs={
    DatabaseOptions.AUTHORIZATION_HEADER.value: "Bearer <access token>",
    DatabaseOptions.WITH_COOKIE_MIDDLEWARE.value: "true",   # one session per connection (spec 050)
})
```

- **A user name and password** instead of a token: `db_kwargs={"username": ..., "password": ...}`
  (over `grpc+tls://`). The door runs the IdP's password grant for you (spec 064). ADBC's Go core
  sends the BasicAuth value without base64 padding, which the door accepts since spec 089.
- Runnable examples in Python, Go, .NET and Java, each with a token or a password, are in
  [hugr-lab/acl-clients](https://github.com/hugr-lab/acl-clients).
- The cookie middleware is what makes the connection one server-side session: session temp tables,
  transactions (DBAPI manual-commit works, spec 055) and `adbc_ingest` (append / temporary staging,
  specs 049/050) all ride on it.
- In **Azure / Microsoft Fabric** the environment mints the token:
  `notebookutils.credentials.getToken(<audience>)` or `azure-identity`'s `DefaultAzureCredential`,
  passed as the same Bearer header. The node verifies an Entra token like any other issuer.
- A DML executed through `cursor.execute()` runs when its result is read - call `fetchall()` before
  a commit/rollback so the write lands inside the transaction (an ADBC dbapi laziness, not the
  server's).
