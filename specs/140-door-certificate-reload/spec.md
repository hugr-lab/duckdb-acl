# Spec 140: a door picks up a renewed certificate

- **Status**: draft
- **Date**: 2026-10-20
- **Author**: Claude (with the owner)

## Summary

Both doors read their certificate and key once, when they are served. hugr-platform spec 005 (the owner's decision 6,
2026-10-20) has cert-manager's csi-driver issue each node pod its own door certificate. The csi-driver generates the
key in the pod, keeps it out of etcd, and renews the certificate in place at two thirds of its life. Today the
renewal reaches a door only at the node's next start. With this spec, a door served from local files takes a renewed
pair for its new connections: no restart, and no connection cut.

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

- **What is watched.** A pair given as **local file paths** is watched. Inline PEM, and a location duckdb's
  filesystem reads remotely, are read once, as today: there is nothing to watch, or nothing cheap to watch.
- **The interval** is `acl_door_certificate_refresh`: GLOBAL, in seconds, default 60, and 0 means read once as
  before. A 720h certificate renews 240h before it expires, so a minute is far inside the margin.
- **Flight.** gRPC's own `grpc::experimental::FileWatcherCertificateProvider`
  (`grpcpp/security/tls_certificate_provider.h`; gRPC 1.76 in our vcpkg) re-reads a key and certificate every
  interval and gives new handshakes the newest valid pair. Arrow has no option for it. The door reaches it through
  Arrow's `builder_hook`, which runs after Arrow has added its own listening port:
  - **Arrow's own location** becomes a Unix socket in a directory the door makes with mode `0700`. The door unlinks
    it right after `Init`: the listener stays open, but no path is left to connect to.
  - **The hook adds the public `host:port`** with `grpc::experimental::TlsServerCredentials` over the file watcher:
    TLS 1.2 at least, no client certificate, as Arrow's credentials have today.
  - **One server**: the auth handler, the middleware and the sessions stay as they are, unchanged.
- **quack.** httplib's `SSLServer::update_certs_pem` swaps the pair under the server's own context lock, so new
  handshakes take the new pair. A door served from paths re-reads them on the same interval. It swaps only when the
  content changed and the pair parses and matches.
- **A broken renewal** is not taken. A pair that does not parse, or whose key does not match its certificate, leaves
  the last good pair serving. gRPC's watcher does the same; its tests confirm it here.
- **It is said, never silent:**
  - a `door` event `certificate_refresh_failed`, with the class only (never a path's content);
  - the load report (`acl_node_load()`) gains `certificates`: per served door (`flight`, `quack`), `not_after`,
    `refreshed_at`, and `error` (a class).

## Enforcement & security

- **The Unix listener** is in a `0700` directory owned by the node's user, and it is unlinked after `Init`. Nothing
  can reach it, and the door removes the directory at stop.
- **The TLS settings stay**: minimum version, no client certificates, the same ciphers as gRPC's defaults today.
- **What is read**: only the paths the operator gave to `acl_flight_serve` / `acl_quack_serve`. No new location is
  read, and nothing a principal writes can name one: both functions are denied to a principal.
- **A refresh never widens anything.** It replaces one pair with another for the same door. The certificate's names
  are its issuer's concern (hugr-platform spec 005: the operator sets them).

## Testing

- **An e2e per door** (`test/e2e/flight/`, beside `run.sh`), with a test CA in the script:
  - serve from files holding certificate A; a new connection sees A's serial;
  - rewrite the files with B, the way the csi-driver swaps `..data`; after the interval a new connection sees B,
    while a connection opened on A, and a stream on it, carry on;
  - write a broken pair; new connections still see B, and the load report shows the error class;
  - with `acl_door_certificate_refresh = 0`, A stays.
- **quack** in the same script, over `GET /.well-known/quack-auth` with `curl --cacert`.
- **A C++ test**: inline PEM and a remote location are never watched.

## Alternatives considered

- **Patch Arrow to take a certificate provider** (a vcpkg overlay): the cleanest API, but a patch to carry on every
  Arrow bump, for one setting.
- **Restart the door on a renewal**: bind a new server on the same port (gRPC sets `SO_REUSEPORT` on Linux), then
  shut the old one down. That cuts long streams at the shutdown deadline.
- **Long-lived certificates, renewed by a node's restart**: nothing restarts by itself (hugr-platform spec 001), so
  this only moves the failure later.

## Follow-ups

- hugr-platform spec 005: its chart's groups use `tls.csi` once this lands in hugr-node's pin.
