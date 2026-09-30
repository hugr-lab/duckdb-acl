# DBeaver (JDBC)

Two ways to connect. Use the first when the users sign in through a browser. The second works with
the stock Arrow driver and no extra jar.

## The duckdb-acl driver: sign in through the browser

[hugr-lab/acl-clients](https://github.com/hugr-lab/acl-clients) ships `jdbc:acl://host:port`, a
driver that signs the user in and then connects through Arrow's Flight SQL driver. It asks the door
which issuer and client to use (the Handshake's `discover-auth`, spec 064), so a connection needs
only host and port. It supports four sign-ins:

- the **browser**: authorization code with PKCE, redirected back to `127.0.0.1`;
- a **device code**, for machines without a browser;
- **user and password**, through the IdP's password grant;
- a **token**, used as given.

Tokens are kept between connections and refreshed silently.

Driver setup, once:

1. Database > Driver Manager > New: class `io.github.hugrlab.acl.jdbc.AclDriver`, URL template
   `jdbc:acl://{host}:{port}`, library `acl-jdbc-<version>-all.jar`.
2. Add `--add-opens=java.base/java.nio=ALL-UNNAMED` below `-vmargs` in `dbeaver.ini`, for Arrow's
   memory layer.

Leave Username/Password empty and Connect opens the IdP's login page. Fill them in to use the
password sign-in instead. The issuer's client (its `CLIENT ID`) must be a public client that allows
PKCE with a `http://127.0.0.1/*` redirect, and the device grant if device codes are wanted. The
repository's README has the full list of properties.

## The stock Arrow driver

Database > Driver Manager > New: class `org.apache.arrow.driver.jdbc.ArrowFlightJdbcDriver`, Maven
artifact `org.apache.arrow:flight-sql-jdbc-driver:<current>`. URL:
`jdbc:arrow-flight-sql://<host>:<port>/?useEncryption=true`. Add
`&disableCertificateVerification=true` only against a self-signed development door.

- **Username / Password** (spec 064): DBeaver's native fields. The door runs the IdP's password grant
  as the issuer's `CLIENT ID` and hands the token back to the driver. This needs a TLS door, and the
  IdP must allow the grant.
- **A token**: driver property `token` = `<access token>`, with Username/Password left empty. It must
  be replaced when it expires.

## Either way

What you see is the policy:
- only the virtual catalog in the tree;
- hidden columns absent from the column list;
- your row slice;
- refusals in plain sentences.

Transactions work with auto-commit off (spec 055). `EXPLAIN` needs the `explain` capability
(spec 052).
