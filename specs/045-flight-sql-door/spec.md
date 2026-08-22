# Spec 045: the Flight SQL door

- **Status**: implemented (first cut)
- **Date**: 2026-08-22
- **Author**: hugr-lab

## Summary

A second door, on the protocol the ADBC and JDBC drivers speak. quack proved the shape (spec 041): a
door is two thin things over the session contract of spec 040 — turn a token into a handle once, put
`ACL SESSION '<handle>'` in front of every statement after that — and everything else is somebody
else's protocol. This adds an **in-process Arrow Flight SQL server**, started by a function the way
`acl_quack_serve` is, so that a client with an ordinary driver can connect to a DuckDB and get exactly
its own slice.

## Problem

quack is DuckDB's own protocol and nothing else speaks it. The clients people actually have — ADBC,
JDBC, anything that talks Flight SQL — cannot reach a served instance at all today. And the gateway
model does not help them: a client that connects for itself cannot prefix its statements, which is the
whole reason spec 040 exists.

## Design

### The decision this spec fixes: Arrow C++, not a hand-rolled server

Two ways to serve Flight SQL from an extension, and the choice is a build decision rather than an
architectural one — the contract above the transport is the same either way.

- **Arrow C++** (`arrow[core,flightsql]` from vcpkg): 89 ports, 11m26s from cold on a developer laptop,
  154 MB of libraries and 91 MB of headers. Of that weight almost none is Flight — `libarrow_flight.a`
  is 2.9 MB and `libarrow_flight_sql.a` under one — it is `libgrpc.a` at 42 MB and `libarrow.a` at 23,
  plus 63 boost ports the vcpkg port pulls unconditionally.
- **gRPC and protobuf alone**, with Flight SQL generated from its `.proto` and IPC written through
  nanoarrow: **10 ports** (abseil, c-ares, grpc, lz4, openssl, protobuf, re2, utf8-range, zlib, zstd).
  Compression and TLS are already inside that ten, so the light path is genuinely light on
  dependencies.

**Arrow C++, and the deciding reason is performance we would otherwise have to re-derive.** Arrow's
Flight server registers a custom serializer with gRPC that writes the IPC body straight into gRPC's
buffers, bypassing protobuf. Hand-rolling the transport means either matching that trick or copying
every batch an extra time — a cost invisible on small data and decisive on large. Re-deriving a
transport is also the wrong place for this project to be original; the same reasoning made us wrap
quack rather than write a server (spec 041).

The risk that made this worth measuring at all — whether such a dependency load is even viable in a
loadable DuckDB extension — is answered by precedent: the `airport` extension links
`Arrow::arrow_static` and `ArrowFlight::arrow_flight_static` with no symbol-visibility or dlopen
workarounds, and is distributed through community extensions. So it builds, it links, and it ships.

Accepted costs, stated plainly: a vcpkg binary cache stops being a convenience for CI and becomes a
requirement, and the whole thing sits behind `ACL_FLIGHT=1` so an ordinary build never pays for it —
the pattern spec 041 established for quack. Measured after wiring it up: the loadable extension goes
from 36 MB to 49 MB, so the door itself costs about 13 MB of artifact.

**Contained, and the way round is worth writing down.** The merged-manifest step keeps only
`dependencies` from each extension's `vcpkg.json` and drops manifest *features*, so declaring Arrow as
a plain dependency would make every integration build install 89 ports for a door it is not opening.
But the merge exists to combine *several loaded extensions'* dependencies, and a flight-only build
loads none — it has nothing to merge. So it skips the merge and takes this repo's own manifest with the
`flight` feature switched on, while `ACL_INTEGRATION` and `ACL_QUACK` keep the merged path exactly as
before. Verified by running the merge script on our manifest: the feature does not survive it, which
is precisely why it is the right place to put Arrow.

The one combination left unhandled is both at once — an integration *and* flight build — which nothing
needs today and which would want the feature and the merge together.

### Everything is carried, and it is checked rather than intended

The artifact must contain what it needs. An extension that links the machine's libraries is one that
behaves differently on the next machine and does not load at all on a machine without them.

That is harder to hold than it sounds, because Arrow goes looking on its own: its config resolves
protobuf, abseil, gRPC, re2, brotli and the rest with further `find_package` calls, and its
`FindOpenSSLAlt.cmake` on macOS **shells out to `brew`** when `OPENSSL_ROOT_DIR` is unset. So the
machine's prefixes are taken out of the search (`CMAKE_IGNORE_PREFIX_PATH`), and — because a switch
that is assumed is worth little — `scripts/check_flight_deps.sh` reads the built artifact and fails if
anything outside the OS is linked. `make check-flight-deps` runs it.

**It earned itself immediately.** The first artifact that built and loaded cleanly turned out to link
homebrew's brotli and c-ares as *shared objects*, while the static ones sat unused in the vcpkg tree —
and an earlier one had linked a homebrew OpenSSL, which only surfaced when a cleared cache stopped
hiding it. Neither was visible in the build log; both are one line of output from the check. What
ships now links `libSystem`, `libc++`, `libbz2`, `libresolv` and CoreFoundation, and nothing else.

### What the build taught, which is the point of a spike

- **One tree has to answer for everything.** Arrow's config file resolves its own dependencies —
  protobuf, abseil, re2, gRPC — with further `find_package` calls, and left to the default search they
  land wherever. On a developer machine with homebrew that produced a link line mixing two Arrows'
  worth of libraries with gRPC missing entirely. Prepending the build's own vcpkg prefix and ignoring
  `/opt/homebrew` is what makes it one tree; the `<Pkg>_DIR` hints make the failure mode legible when
  it is wrong.
- **CMake caches the wrong answer.** Once a configure has resolved `Protobuf_DIR` to homebrew, fixing
  the search order changes nothing until those cache entries are cleared. Worth knowing before
  concluding that a correct fix did not work.
- **gRPC must be linked by name.** Arrow's Flight libraries reach past what their own config carries
  over, and the shortfall appears only at the last link step as unresolved `grpc_*` symbols.
- **Mixing a classic-mode vcpkg tree with the build's manifest tree does not work** — tried, and it
  fails as Arrow's targets file referring to packages the other tree does not have. The dependency has
  to come through the build's own manifest, which is also the honest way round.
- **Steering `find_package` by hand backfires.** `CMAKE_FIND_PACKAGE_PREFER_CONFIG` makes
  `find_package(OpenSSL)` miss vcpkg's own wrapper; cutting the system paths out with
  `CMAKE_FIND_USE_*` does not survive that wrapper either; pinning `<Pkg>_DIR` only moves the problem
  into Arrow's own lookups. What works is what the rest of this repo does — a plain
  `find_package(... CONFIG REQUIRED)` under the vcpkg toolchain, as `mssql-extension` does for
  simdutf and OpenSSL — plus excluding the machine's prefixes, plus the check.

### Where it lives

`src/flight/`, with its own CMake fragment. The door will grow a session middleware, a ticket registry,
the catalog RPCs and an ingest path, and none of that belongs beside the rewriter; it is also the one
part of the build that can be absent entirely, and a directory keeps that boundary visible instead of
spreading it through a source list.

### The door itself

Arrow's `FlightSqlServerBase` has exactly the two seams a door needs, so ours is an override of each:

- **`GetFlightInfoStatement(context, StatementQuery, descriptor)`** is where the client's SQL arrives.
  We take the session handle bound to this call, compose the prefixed statement the way
  `acl_session_sql` does, and plan *that*. A client that has no live session gets a refusal here, and
  nothing about the policy is decided in this function — it only prefixes, exactly as quack's
  authorization callback does.
- **`DoGetStatement(context, StatementQueryTicket)`** is where the rows go out. The statement was
  already rewritten under the principal when its ticket was made, so this is Arrow's own path with a
  DuckDB result on the other end.

  **The ticket carries an opaque id and nothing else.** Arrow's own examples put the query text into
  the ticket, and a Flight ticket is handed to the client — so a ticket carrying our composed statement
  would hand the session handle to the very party it authenticates. The rewritten statement stays on the
  server in a map keyed by a random id, which is the same shape as the session handle itself and for the
  same reason.

**The credential is per call, and the door keeps no session between calls.** The token arrives in the
call headers, is verified with `acl_session_open` (spec 040), used, and closed before the call returns.

The first cut did the obvious thing instead — verify once, remember the handle against the Flight peer,
and let a later call without a token use it — and that is a hole: the peer is `ipv4:host:port`, ports are
reused, and a client landing on a recycled port would inherit the previous one's session. gRPC metadata
is per call and every Flight SQL driver sends credentials that way, so requiring it each time costs a
JWT verification (~10µs, spec 043's benchmark) and removes the question. It also means a door under load
leaves nothing behind for spec 044's sweeper to find.

Arrow does ship a `ServerSessionMiddleware` with `GetSession()` and `GetCallHeaders()`, and it is where
a longer-lived session would belong if one is ever wanted — worth knowing, unused for now.

**A ticket stands for the question, not for the answer.** It holds an opaque id; the server keeps the
client's *own* SQL against it, unprefixed. Not the composed statement, for a reason found by breaking
it: the prefix names a session, and the session must be alive when the statement is **parsed**, which
happens later and more than once. So each use composes afresh, under whoever is fetching — which also
means a ticket that reached another principal returns *their* slice rather than the asker's.

**TLS is ours here**, unlike quack — and until it lands the door **binds localhost only**, refusing any
other address rather than handing out data in the clear over a protocol meant to cross machines. Flight is meant to be exposed, Arrow supports TLS directly, and a
door that hands out data over a protocol drivers use from other machines should not depend on a reverse
proxy being remembered.

**Starting it refuses the same four things** `acl_quack_serve` refuses (spec 041): no policy source,
anonymous admin on, the parser override not `STRICT`, and — here — no TLS material unless the operator
says plainly that it is a local socket.

### What the first cut is, and is not

Minimal on purpose, because the point of the first cut is that the transport works in-process and the
prefix reaches the rewriter. **It does**: a third-party pyarrow client connects with a JWT, and reads
exactly its own slice — five of ten seeded rows, the rest invisible to the grant's predicate. A
physical name is refused by the same rewriter that refuses it anywhere, and a token nobody can verify
does not get in.

- **in**: `acl_flight_serve(uri)` / `acl_flight_stop(uri)`, a session from the call headers,
  `GetFlightInfoStatement` and `DoGetStatement` for a plain query, results converted from DuckDB chunks
  through the C ABI;
- **not in**: prepared statements, `DoPut` ingest (spec 042's problem again, in another protocol —
  and it deserves the same measurement rather than an assumption), the Flight SQL catalog methods
  (`GetTables`, `GetDbSchemas`, …), and multiple endpoints for parallel fetch.

The catalog methods are the next thing to build, and they are the same problem spec 035 solved for
`information_schema`: Flight SQL has its own metadata RPCs (`GetTables`, `GetDbSchemas`, `GetCatalogs`,
…), and each must show the principal's objects and nothing else. Checked rather than assumed: Arrow's
`FlightSqlServerBase` answers `NotImplemented` for every RPC not overridden, so an unimplemented one
refuses on its own — there is nothing to guard against while they are missing, only work to do to make
them answer.

**And they go through the same machinery quack's introspection does — decided now, before either
exists in two shapes.** Under quack, introspection is already ordinary SQL: a client asks
`information_schema.columns`, the rewriter substitutes spec 035's surfaces, and the answer is built
over the policy catalog. A Flight RPC should therefore be a *thin adapter*: compose the SQL those
surfaces already answer, run it as the principal through the normal path, and shape the result into the
form Flight SQL prescribes.

Two reasons, and the second is the one that matters. Performance is one place to fix instead of two —
spec 043 measured `information_schema.columns` at 70 ms through the door, nearly the whole cost of a
connect, and that work should not be duplicated into a second protocol only to be optimised twice. But
the real reason is that a second route to metadata is a second place deciding what a principal may see,
and therefore a second place it can diverge. Twice this project has already found a path that answered
a client while bypassing the rewriter (spec 041, twice over); one mechanism under both doors is how a
third is avoided.

A concrete place divergence would have been likely: `GetTables` with `include_schema` wants each
table's Arrow schema, meaning column *types* — and the types a role sees are not the physical ones,
since a mask may change them. Spec 026 stores exactly that in `grant_columns` so that
`information_schema.columns` and `DESCRIBE` describe the same thing. An RPC implemented on its own
would very likely have read the physical types and quietly disagreed with what the role can read.

## Enforcement & security

- **The door decides nothing.** It turns a token into a handle and puts a prefix on a statement; the
  policy is resolved in the rewriter, per statement, as for any other principal. A component that
  cannot widen access is one less thing to trust.
- **Fail closed at the seams.** No session, an expired one, a statement that will not compose: a
  refusal, never an unprefixed execution. This is where quack's lesson applies directly — spec 041
  found a path that *asked* for authorization and then ran a statement of its own, and the rule that
  came out of it is that a path which does not carry our rewritten SQL must be refused rather than
  authorized. Every Flight SQL RPC gets held to that.
- **A DoPut that we have not implemented must refuse**, for the same reason: an ingest path that
  bypasses the rewrite is precisely the hole spec 041 measured.

## Testing

Following spec 041's split, since it worked: the parts that need no server proven as ordinary SQL, the
round trip proven live behind `ACL_FLIGHT=1`, and both in CI — the door gets a job of its own there
rather than a step in the Linux one, because 89 vcpkg ports have nothing to do with the scanners and
would make the integration job's timing unreadable. That job also runs `make check-flight-deps` before
it runs anything, since an artifact that borrowed a library from the runner would pass every test on
the runner and fail everywhere else.

**It runs on merges and on request, not on pull requests** — the same shape the macOS job has, and for
the same reason: a cold build measured 98 minutes on a runner. That choice is what keeps the plain
Actions cache sufficient. The repository's cache budget is 10 GB with eviction by age, and this build's
share is well over a gigabyte competing with the integration cache and seven release ccaches; a job
that runs rarely fills it rarely enough not to fight for room. A pull request that needs the door
checked dispatches the workflow by hand.

A package feed on GitHub Packages was tried first, since an Actions cache written by a pull request is
visible to that pull request alone. It works, but it wants mono and a `packages: write` permission to
solve a problem that not running on pull requests removes — dependencies that do not earn their keep.

- `test/sql/acl_flight_door.test` — the start-up refusals, and the functions denied to a principal.
- `test/sql/integration/acl_flight_serve.test` — a live server in one process, a client connecting with
  a JWT and reading its own slice, a physical name refused, an unverifiable token refused at the
  handshake, and an unimplemented RPC refusing rather than answering.
- The e2e harness of spec 043 gains a Flight leg once the round trip stands, since isolation between
  clients is a property of the door and not of the protocol.

## Alternatives considered

- **gRPC and protobuf alone** — ten ports instead of 89, and the reason it lost is written above.
  Worth revisiting only if Arrow's weight becomes an obstacle to distribution, and the contract above
  the transport is what makes revisiting possible.
- **A separate binary next to DuckDB**, as gizmosql is. Rejected earlier and still rejected: the server
  must start in-process, so that one DuckDB with a bootstrap script becomes a server.
- **Two extensions, one per door.** community-extensions takes a git ref, so one extension with an
  opt-in flag is what fits.

## Follow-ups

- **Ingest through Flight SQL** (`DoPut`), which is spec 042's question in another protocol.
- **The Flight SQL catalog RPCs**, which are spec 035's surfaces again — and which the benchmark of
  spec 043 says are the expensive part of a connect, so they should be built with that already known.
- **Parallel endpoints.** Flight's model allows a `FlightInfo` to name several endpoints; that is where
  the cluster design of `design/010-serving-clients` would attach, and it is deliberately out of scope
  until one door works.
