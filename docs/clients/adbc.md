# ADBC (python)

```python
import adbc_driver_flightsql.dbapi as dbapi
from adbc_driver_flightsql import DatabaseOptions

conn = dbapi.connect("grpc://<host>:<port>", db_kwargs={
    DatabaseOptions.AUTHORIZATION_HEADER.value: "Bearer <access token>",
    DatabaseOptions.WITH_COOKIE_MIDDLEWARE.value: "true",   # one session per connection (spec 050)
})
```

- The cookie middleware is what makes the connection one server-side session: session temp tables,
  transactions (DBAPI manual-commit works, spec 055) and `adbc_ingest` (append / temporary staging,
  specs 049/050) all ride on it.
- In **Azure / Microsoft Fabric** the environment mints the token:
  `notebookutils.credentials.getToken(<audience>)` or `azure-identity`'s `DefaultAzureCredential`,
  passed as the same Bearer header. The node verifies an Entra token like any other issuer.
- A DML executed through `cursor.execute()` runs when its result is read - call `fetchall()` before
  a commit/rollback so the write lands inside the transaction (an ADBC dbapi laziness, not the
  server's).
