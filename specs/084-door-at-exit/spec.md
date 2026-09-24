# Spec 084: a door nobody stopped does not crash the process at exit

- **Status**: implemented
- **Date**: 2026-09-24
- **Follows**: spec 079's follow-up ("pre-existing, found here"), spec 063

## Problem

A quack door's connections hold its `DatabaseInstance`. A door nobody stopped therefore keeps its
instance alive after the caller releases it (the `DuckDB` object or the CLI's database), until the
process ends.

acl kept its doors in a static map. At exit, the static destructors destroyed that map, the map
destroyed the server, the server destroyed its connections, and the last connection destroyed the
instance. The instance closed its attached databases, and a quack client's catalog runs httpfs's curl
client destructor. The curl statics were created later than the map (at the client's `ATTACH`), so
they had been destroyed earlier. The process aborted with `mutex lock failed: Invalid argument`.

Reproduction: serve, `ATTACH 'quack:…' AS r (TYPE quack, TOKEN …)` in the same process, and exit
without `acl_quack_stop`. Exit status 134, every time.

## Design

- **The registry and its mutex are never destroyed** (`Servers()` / `ServersLock()`, allocated once
  with `new`). This is stock quack's shape: its per-instance map lives in the instance's config, so
  the same cycle leaks at exit there. A door is torn down only by `acl_quack_stop` or by the reclaim
  of a later serve on the same address, both unchanged.
- **At exit a door stops accepting.** An `atexit` handler registered at the first serve calls
  `StopAccepting()` on every door, which ends the listener and releases the port. It destroys nothing,
  so it touches no static that may already be gone.
- **Consequence: no final checkpoint.** An instance behind a door nobody stopped is left as the process
  leaves it. A persistent database is then not checkpointed at exit, and its WAL replays at the next
  open. The shutdown order the docs already give still applies: drain, stop the doors, close (spec
  066). With that order the instance closes normally.

## Tests

`test/cpp/test_acl_quack_exit.cpp` runs the reproduction in a child process (the same binary with
`--child`), three times:

- the child serves, attaches a quack client to its own door, reads through it, and returns from `main`;
- each run must exit with status 0;
- without the fix, every run aborts (SIGABRT).

The test is skipped without a quack build, as the other door tests are.

## Alternatives

- **A hook when the instance closes.** It never fires: the door's own connections keep the instance
  alive.
- **Stopping the door when the caller's last connection closes.** Rejected: an embedding may serve while
  holding only its `DuckDB` object, and it would lose its door.
- **Tearing the doors down fully in the `atexit` handler.** Rejected: statics created after the first
  serve, such as the curl client's, are already destroyed by then. That is the same crash, moved
  earlier.
