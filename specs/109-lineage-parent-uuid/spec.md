# Spec 109: a lineage parent is checked where it enters

- **Status**: implemented
- **Date**: 2026-10-08
- **Follows**: spec 107 (lineage), acl-otel spec 018 (the OpenLineage transport)

## Problem

A client declares the external run a statement belongs to, in `OPENLINEAGE_PARENT_ID` form
(`<namespace>/<job>/<runId>`). Spec 107 takes the value as given. The only checks are that it has
three parts and is at most 512 bytes. `'airflow/daily/0190-run'` is accepted.

OpenLineage's ParentRunFacet declares `runId` a UUID, and a backend that parses it (Marquez does)
refuses the whole event. acl-otel therefore leaves such a parent out (`parent_dropped`, spec 018). The
run then lands outside the pipeline it belongs to, and nobody tells the client: a dbt or Airflow job
wired up wrong looks as if it worked.

## Design

One check, `LineageRunRefCheck(text, error)`: `<namespace>/<job>/<runId>`, where the namespace and the
job are non-empty and the runId is a UUID (8-4-4-4-12 hex, any version). Every channel that takes a
parent or a root parent applies it at the point of entry:

| channel | on a malformed value |
| --- | --- |
| `ACL … LINEAGE PARENT '…' [ROOT '…']` | the statement is refused at parse: `ACL LINEAGE PARENT: expected <namespace>/<job>/<runId>, the runId a UUID` |
| `SET acl_lineage_parent` / `acl_lineage_root_parent` | the SET is refused with the same text |
| Flight `x-openlineage-parent` / `-root-parent` | the call is answered `InvalidArgument` with the same text |
| quack `x-openlineage-parent` / `-root-parent` | not used. quack's authorization callback cannot carry a message back, and refusing the statement for a header would read as an authorization failure. Instead there is one `door` event `lineage_parent_invalid` per connection, and the counter `acl.lineage.parent_invalid` |

- `JOB` and `acl_lineage_job` stay free text (bounded as before). An empty value still means none.
- `ParseLineageRunRef` keeps its parse. A value that reaches it has been checked, and the producer's
  payload never carries a non-UUID parent.

## Enforcement & security

Nothing here grants or refuses access. A value refused at the marker or SET is the client's own,
and the message echoes no part of it (no reflection). The bounds of spec 107 stay.

## Testing

- `test/sql/acl_lineage.test`:
  - the marker with a non-UUID runId, two parts, or an empty job is refused;
  - a UUID is accepted and reaches the payload;
  - the existing cases move to UUIDs.
- The SET on a session (the 068 path, C++ door test): refused, then a UUID accepted.
- Flight: a header with a non-UUID gives InvalidArgument (the Flight e2e's header case, spec 107's
  follow-up, lands here).
- quack (`test/sql/integration/acl_lineage_quack.test`): a non-UUID header produces the door event,
  and the statement runs with no parent.

## Alternatives considered

- **Drop silently at the node, as acl-otel does.** This is what happens today, and it is what this spec
  removes.
- **Accept any runId, and let the transport mint a UUID from it** (a v5 of the text). The run would
  then point at a parent nobody created; the backend shows a dangling link. Worse than a refusal.

## As built (2026-10-08)

- `LineageRunRefCheck` (`acl_lineage.cpp`) is the one check. Its message is a fixed sentence, so it
  never echoes the value.
- **Marker:** checked in the parser override on the raw value, before it is bounded. A value over
  512 bytes is refused whole, because the cut would lose its runId.
- **SET:** a check callback on `acl_lineage_parent` / `_root_parent`. Under `ACL SESSION` the rewriter
  checks too, **before** `SetSessionTrace`: duckdb runs the callback only after the rewrite, and a
  value already on the session's record would make every later statement of the session refused
  (review F1).
- **Flight:** `LineageOfCall` answers an `arrow::Status`, and its 3 callers return it as is.
- **quack:** `AclQuackNoteRequestLineage` blanks a malformed parent or root, keeps the job, adds to
  `acl.lineage.parent_invalid{door=quack}`, and writes the door event once per connection
  (`PolicyStore::quack_lineage_reported`, cleared with the connection).
  - It notes only a connection the door bound a session to. A request names its connection id before
    quack checks it, so an id nobody authenticated would otherwise stay in the maps for good.
  - Both maps are cleared when the last door stops.
- **Tests:**
  - `test/sql/acl_lineage.test`: the marker, ROOT, a two-part value, no echo, a value over 512
    bytes, a free JOB, the SET on a bare connection;
    the existing cases now use UUIDs;
  - `test/sql/integration/acl_lineage_quack.test`:
    - a malformed parent or root header gives one door event, the counter, no parent and no root,
      and the job is kept;
    - a malformed `SET` on the session is refused, and the next statement runs under the parent the
      session had;
  - `test/e2e/flight/run.sh`: a malformed header gives InvalidArgument without echo; a UUID is
    taken. `client.py` gains `ACL_EXTRA_HEADERS`.
