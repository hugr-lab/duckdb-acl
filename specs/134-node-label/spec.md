# Spec 134: the node's label in its sessions' names

- **Status**: implemented
- **Date**: 2026-10-18
- **Author**: Claude (with the owner)

## Summary

Behind a front — the platform's balancer, or any balancer with cookie affinity — every request of a client's session
has to reach the node that holds the session. The front keeps no table of sessions. Instead, the node names its
sessions with its own label, and the front routes by the name alone.

- A GLOBAL setting, `acl_node_label`, holds the label.
- Both doors set one cookie, `acl_node=<label>`.
- The quack door's connection ids start with `<label>.`.
- An empty label keeps today's behaviour.

## Problem

Neither door's session name says which node holds the session:

- a Flight session is named by the door's random cookie `acl_flight_session_id` (spec 050);
- a quack connection is named by quack's random hex connection id.

So a stateless front has nothing to route by, and a front that keeps a table needs state shared between its replicas.

quack makes this sharper. A client opens up to 64 parallel HTTP connections per logical connection, one per FETCH in
flight, and an L4 balancer spreads them over the front's replicas. Only a name that every request carries can keep
them on one node. Two such names exist:

- duckdb/duckdb-quack#297 (the owner's, open) makes the client keep `Set-Cookie` per logical connection and send
  `Cookie` and `X-Quack-Connection-Id` on every request;
- a stock client without it still sends the connection id in the message header at the start of every body.

## Design

- **Setting** `acl_node_label`: GLOBAL only, default `''`.
  - The value must be a DNS-1123 label: 1–63 characters of `[a-z0-9-]`, starting and ending with a letter or
    digit. The validator refuses anything else.
  - It is the node's identity, like its group, and never a cluster profile item.
  - It is read when a name is minted, so set it in the bootstrap before the doors serve. A change applies to names
    minted after it.
- **The cookie, on both doors**: `acl_node=<label>; HttpOnly; Path=/; SameSite=Strict`, with the same attributes as
  the Flight session cookie.
  - It is sent on a response whenever the label is set and the request's `Cookie` does not already carry
    `acl_node=<label>`. That covers a new client, a client re-seated from another node, and a changed label.
  - Flight: the door's cookie middleware (`src/flight/acl_flight_door.cpp`) sends it beside the session cookie,
    which is unchanged.
  - quack: the door's own HTTP server (`src/quack_embed/acl_quack_http_server.cpp`, not generated) sends it on
    every `/quack` response.
- **The quack connection id** is `<label>.<32 hex digits>` (uppercase, as quack mints them). A label cannot contain
  `.`, so the first `.` ends it.
  - `GenerateConnectionId` in the embedded server mints it, through one `sync.py` hunk that calls
    `acl::AclQuackConnectionIdPrefix(db)`.
  - The id stays opaque to the client and to quack, and nothing in acl parses it.
  - Size: quack bounds a SEND_DATA header to 256 bytes as `64 + connection_id + stream_id`. With the longest label
    that is 64 + 96 + 36 (a UUID) = 196, within the bound.
- **The load report** (`acl_node_load()`, `GET /.well-known/acl-node`, the Flight `node-load`) adds `"label"`, null
  when unset. An operator or the orchestrator can then match a report to the name it routes by.
- **The front** (hugr-platform, not here) routes a request to the node with that label:
  - by the `acl_node` cookie;
  - for quack, by the id's prefix, read from `X-Quack-Connection-Id` or from the message header.

  It maps label to address through k8s. Nothing in acl depends on a front.

## Enforcement & security

- **The label is a routing hint, never an authority.** The node reads an incoming `acl_node` value only to compare
  it with its own. It never writes that value to an event or a log, and never decides anything by it.
- **A rewritten label only picks the node.** A client that changes the label reaches another node. That node
  verifies its token like any other, and placement (spec 096) refuses a principal outside the node's group.
- **The label is public.** It names a pod; it is never a secret and never derived from one.
- **The secrets are unchanged.** The session cookie, the session handle and the random part of the connection id are
  still 128 bits from the door's CSPRNG.
- No query parameters are added and the rewriter is untouched.

## Testing

- **`test/cpp/test_acl_node_label.cpp`** (header-only, no instance)
  - which labels are DNS labels (63 characters is the longest; `.`, `_`, upper case, a leading or trailing `-`
    refused);
  - a Cookie header is read by name, never as a substring;
  - when the label's Set-Cookie is sent: without a label never, with one only to a request that does not carry
    it, another node's replaced;
  - the id prefix, and that the longest id fits quack's SEND_DATA header.
- **`test/sql/acl_node_label.test`**
  - the validator refuses `Node_1`, `a.b`, a leading `-` and 64 characters, and accepts 63;
  - the setting is GLOBAL only;
  - `acl_node_load()` shows the label, or null when unset.
- **Flight** (`test/e2e/flight/run.sh`, a pyarrow client that prints every `set-cookie`)
  - without a label only the session cookie comes;
  - with one, a call without cookies gets `acl_node=<label>; HttpOnly; Path=/; SameSite=Strict` beside the
    session cookie;
  - a call carrying the label gets none, a call carrying another label gets this node's;
  - after the label is cleared, none again.
- **quack** (`test/cpp/test_acl_quack_embed.cpp`, the embedded server and a real quack client in one process)
  - a bare `POST /quack` answers `Set-Cookie: acl_node=<label>; ...`, none to a request carrying it, this node's to
    one carrying another, none without a label;
  - a labelled connection reads its slice, and quack's own debug log shows every message of it riding an id that
    matches `<label>\.[0-9A-F]{32}`;
  - under a 63-character label a streamed write (SEND_DATA) goes through and lands.
- The existing door suites stay green.

## Alternatives considered

- **The front sets its own route cookie.** This works for Flight. But quack without #297 keeps no cookies, and the
  connection id is the node's anyway. One rule for both doors is simpler (owner, 2026-10-18).
- **A session → node table in the front.** That is state shared between the front's replicas.
- **The pod IP as the label.** IPs are reused by later pods, and an IP is an internal address.
- **The label inside the Flight session cookie's value.** That changes the session cookie's format; a separate
  cookie leaves it alone.
- **Reusing `acl_node_id`.** That is the node's name on audit events and metrics: free-form, and by default
  `<hostname>:<pid>`, with `:` and `.` in it. A routing name needs a constrained form and must be empty by default,
  so that no cookie is sent where nobody routes.
- **In hugr-node.** It needs a new seam in acl to decorate names, which is more code than the feature. An open node
  behind any cookie-affinity balancer wants it too.

## Follow-ups

- **After the release** (the phase-1 doc, the row «фронт»):
  - labels inside tickets and prepared handles;
  - pinning a session only by its state;
  - releasing free sessions at drain;
  - a loud refusal of a foreign node's label (design/082 F1);
  - a Location directly to the node for in-cluster services.
- **hugr-node**: set `acl_node_label` from the pod (the Downward API) at bootstrap.
