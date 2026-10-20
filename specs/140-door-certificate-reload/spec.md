# Spec 140: a door picks up a renewed certificate

- **Status**: implemented (accepted by the owner 2026-10-20)
- **Date**: 2026-10-20
- **Author**: Claude (with the owner)

## Summary

Both doors read their certificate and key once, when they are served. hugr-platform spec 005 (the owner's decision 6,
2026-10-20) has cert-manager's csi-driver issue each node pod its own door certificate. The csi-driver generates the
key in the pod, keeps it out of etcd, and renews the certificate in place at two thirds of its life. Before this spec
the renewal reached a door only at the node's next start. Now a door served from local files takes a renewed pair for
its new connections: no restart, and no connection cut.

## Problem

- **Flight.** `acl_flight_serve(uri, cert, key)` puts the PEM it reads into `FlightServerOptions::tls_certificates`.
  Arrow Flight's gRPC transport turns that into `grpc::SslServerCredentials` once, at `Init`
  (`arrow/flight/transport/grpc/grpc_server.cc`), and offers no other credentials.
- **quack.** `acl_quack_serve(uri, token, cert, key)` builds httplib's `SSLServer` from the PEM once.
- **Both** read the pair through `ReadPemArg`: inline PEM, or a location `read_text` reads. hugr-node passes the
  csi-driver's paths (`/etc/hugr/tls/tls.crt` and `tls.key`).
- **The failure**: a node that lives longer than its certificate serves an expired one. The front and the console
  then refuse it at the handshake, and the console shows the door's `notAfter`, but nothing renews it.

## Design

- **What is watched.** A pair given as **local file paths** is watched (`IsLocalCertificatePath`: no scheme but
  `file://`). Inline PEM, and a location duckdb's filesystem reads remotely, are read once, as before: there is nothing
  to watch, or nothing cheap to watch.
- **The interval** is `acl_door_certificate_refresh`: GLOBAL, in seconds, default 60, and 0 means read once as
  before. A 720h certificate renews 240h before it expires, so a minute is far inside the margin.
- **The watcher** (`DoorCertificateWatcher`, `src/flight/acl_door_certificate.cpp`, built with the flight build's
  OpenSSL) re-reads both files every interval:
  - when their content changed, it judges the pair whole (`CheckCertificatePair`): the first certificate parses, the
    key parses, and `X509_check_private_key` says the key is the certificate's;
  - a good pair goes to the door's swap; a refused one is reported once;
  - a pair read between the two files' writes gets a second look at the next check before it counts as broken: the
    csi-driver swaps both at once, through `..data`.
- **Flight.** Arrow has no option for credentials that change. The door reaches gRPC through Arrow's
  `builder_hook`, which runs after Arrow has added its own listening port:
  - **Arrow's own location** becomes a Unix socket in a directory the door makes with mode `0700`. The door unlinks
    it right after `Init`: the listener stays open, but no path is left to connect to.
  - **The hook adds the public `host:port`** with SSL credentials made by gRPC's certificate-config fetcher
    (`grpc_ssl_server_credentials_create_options_using_config_fetcher`, the C API that reloads a server's
    certificate without interrupting it). gRPC calls it at start and for new handshakes.
    - It hands out a new config only when the watcher has set a pair that checked (`FlightCertificateFeed`).
    - Otherwise it answers UNCHANGED, so gRPC keeps the last pair it took.
    - The pair stays in memory: no copy of the key on disk.
    - No client certificate is requested, as with Arrow's credentials before.
  - **One server**: the auth handler, the middleware and the sessions stay as they are, unchanged.
  - **Not gRPC's `FileWatcherCertificateProvider`**, which the draft proposed. The e2e found that it takes a
    renewal whose key does not match its certificate, after which every new handshake fails. Only a pair that has
    been judged whole reaches gRPC now.
- **quack.** httplib's `SSLServer::update_certs_pem` swaps the pair under the server's own context lock, so new
  handshakes take the new pair. It sets the certificate, then the key, so only a pair already judged whole is handed
  to it. The watcher is stopped before the listener when the door goes.
- **It is said, never silent:**
  - a `door` event `certificate_refresh_failed` (reason code `unavailable`), with the class only, never a file's
    content;
  - the load report (`acl_node_load()`) gains `certificates`: per served TLS door, `door` (`flight` or `quack`),
    `watched`, `not_after`, `refreshed_at` (unix seconds), and `error` (a class: `unreadable`,
    `certificate_unparsable`, `key_unparsable`, `key_mismatch`, `refused_by_door`).

## Enforcement & security

- **The Unix listener** is in a `0700` directory owned by the node's user, and it is unlinked right after `Init`, the
  directory with it. Nothing can connect to it.
- **The TLS settings stay**: no client certificates, gRPC's defaults otherwise, as Arrow's credentials had them.
- **The key never leaves memory**: the fetcher hands gRPC the PEM from the watcher's memory, and nothing writes it
  anywhere.
- **What is read**: only the paths the operator gave to `acl_flight_serve` / `acl_quack_serve`. No new location is
  read, and nothing a principal writes can name one: both functions are denied to a principal.
- **A refresh never widens anything.** It replaces one pair with another for the same door. The certificate's names
  are its issuer's concern (hugr-platform spec 005: the operator sets them).

## Testing

- **`test/e2e/flight/certificate_reload.sh`** (in `make test-flight`). A test CA signs certificates A and B, and the
  files are laid out as the kubelet lays them: links into `..data`, swapped in one rename. With a refresh of 1 s it
  checks the following, reading the served serial with `openssl s_client`:
  1. both doors serve A, and the load report shows them watched;
  2. after a swap to B both serve B, and a Flight connection opened on A goes on querying;
  3. a broken pair (B's certificate, another key) is not taken: both keep B, the load report says `key_mismatch`, the
     audit has both doors' `certificate_refresh_failed`, and no PEM reaches the output;
  4. A again is taken, and the refusal clears;
  5. a door served from inline PEM, and one served while the refresh was 0, keep A through the swap.
- **Found on the way**: `tls.sh` called `read_text` as a scalar, which fails to bind, and its check matched the uri
  inside that error. It now reads the PEM through a subquery and refuses an error.

## Alternatives considered

- **gRPC's `FileWatcherCertificateProvider`**: refused by the e2e (above).
- **Patch Arrow to take a certificate provider** (a vcpkg overlay): the cleanest API, but a patch to carry on every
  Arrow bump, for one setting.
- **Restart the door on a renewal**: bind a new server on the same port (gRPC sets `SO_REUSEPORT` on Linux), then
  shut the old one down. That cuts long streams at the shutdown deadline.
- **Long-lived certificates, renewed by a node's restart**: nothing restarts by itself (hugr-platform spec 001), so
  this only moves the failure later.

## Follow-ups

- hugr-platform spec 005: its chart's groups use `tls.csi` once this lands in hugr-node's pin.
