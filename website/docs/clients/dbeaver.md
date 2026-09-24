# DBeaver (Arrow Flight SQL JDBC)

Works today with the stock Apache Arrow driver and a bearer token; a browser-login driver is planned.

## Driver setup (once)

Database > Driver Manager > New: class `org.apache.arrow.driver.jdbc.ArrowFlightJdbcDriver`, Maven
artifact `org.apache.arrow:flight-sql-jdbc-driver:<current>`.

## Connection

- URL: `jdbc:arrow-flight-sql://<host>:<port>/?useEncryption=false` (or
  `useEncryption=true&disableCertificateVerification=true` against a self-signed TLS door).
- Driver property `authorization` = `Bearer <access token>` - the driver forwards user properties as
  Flight call headers, and the door reads exactly that header. Leave Username/Password empty.
- The server answers the driver's connect-time Handshake (spec 058); on an older build Test
  Connection fails with "This service does not have an authentication mechanism enabled".

What you see is the policy: only the virtual catalog in the tree, hidden columns absent from the
column list, your row slice, refusals in plain sentences. Transactions work with auto-commit off
(spec 055); `EXPLAIN` needs the `explain` capability (spec 052).

## Planned

- Username/Password in DBeaver's native fields with the server exchanging them at the IdP
  (admin-enabled; design/016 B3) - the stock driver, no manual token.
- A custom driver with browser login (auth-code+PKCE) and silent refresh (design/016 block C).
