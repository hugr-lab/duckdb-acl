# Spec 057: live validation - the phase ends with eyes on real tools

- **Status**: implemented
- **Date**: 2026-08-30
- **Author**: hugr-lab

## Summary

The closing item of the single-node backlog: real client tools - DBeaver over the Arrow Flight SQL
JDBC driver, an ADBC client, a duckdb+quack client - each walk one scenario against a served node,
and every number and every refusal they show is explainable by the token pasted in. The scripted
legs already exist and run in CI (`make test-flight` drives the real ADBC driver and a third-party
Flight client; the quack integration tests and the door e2e drive real quack clients). What this spec
adds is the **human pass**: `test/live/serve.sh` starts one seeded node (Flight door, TLS optional,
quack door where built) and prints the connection material; `test/live/RUNBOOK.md` is the
step-by-step per tool, each step with its expected outcome - including what a refusal must read like.

## Problem

Every guarantee so far was proven by harnesses we wrote. A GUI tool exercises paths no harness does -
the catalog tree, the driver's metadata calls in the order the tool makes them, auto-commit toggles,
error rendering - and the phase's definition of done was "eyes on real tools". There was no supported
way to stand up a node for that, and no script of what to check.

## Design

- **`test/live/serve.sh [flight|quack|all] [--tls]`** - one command to a live node, and the doors
  are separable: `flight` serves only the Flight SQL door (ADBC/JDBC/DBeaver), `quack` only the quack
  door, `all` (default) both. It seeds the runbook's policy (an RLS-sliced `orders`, a column-hidden
  `customers`, a staging schema with create+drop, the `temp` and `explain` capabilities on `analyst`,
  a minimal `viewer` for refusal steps), serves the chosen door(s) (`--tls` switches Flight to
  `grpc+tls` on `0.0.0.0` with a self-signed cert - spec 053's path), prints the URIs, the DBeaver
  JDBC URL, and three tokens, and holds until Ctrl+C. Ports move with `ACL_LIVE_PORT` /
  `ACL_LIVE_QUACK_PORT`.
- **VS Code tasks** (`.vscode/tasks.json`) run each server in its own terminal panel - *Serve: Flight
  SQL door*, *Serve: quack door*, *Serve: both doors*, *Serve: Flight over TLS* - alongside the
  existing build/test tasks; `make serve-flight` / `serve-quack` / `serve-live` are the CLI twins.
- **A real IdP is opt-in** (`ACL_LIVE_KEYCLOAK=<realm-url>`): the node then defines a second issuer
  that fetches the realm's JWKS over httpfs (spec 023), verifies RS256 (spec 007), takes roles from
  `realm_access.roles` and maps a `tenant` claim to the RLS - the demo HS256 issuer stays alongside.
  A Keycloak realm role named `analyst`/`viewer` resolves to the ACL role by name (the unmapped-role
  rule), so no `acl_map_role` is needed. `test/live/mint_token.py` mints the demo tokens; the runbook
  has the Keycloak-console setup and the token-fetch curl.
- **`test/live/RUNBOOK.md`** - the walk: 13 DBeaver steps (tree shows only the virtual catalog, `ssn`
  absent from the column tree, the slice, the predicate refusal, EXPLAIN under its capability,
  manual-commit rollback through the real driver, session temp, staging create/drop, the viewer's
  refusals, the other tenant's disjoint slice, a garbage token), an ADBC spot-check (the scripted
  pass is CI's), a quack client pass (the drain, the staging schema), and the rule for refusals: our
  sentence, never a stack trace, never a physical name the role cannot see, never "Unexpected error
  in RPC handling".
- **JDBC stays a runbook, not a script**: no Java toolchain on the dev machine, and the tool under
  test is DBeaver itself - a headless JDBC leg would test the driver, not the tool. If a Java
  environment appears, the runbook's steps 3-8 are the script to write.

## Enforcement & security

Nothing changes - this spec ships a demo server script and a document. `serve.sh` seeds a demo-only
issuer (the same HS256 test secret every fixture uses) and demo tokens with 2100 expiry: it is a
validation rig, not a deployment template, and says so. The TLS variant generates a throwaway
self-signed cert in a temp dir removed on exit.

## Testing

`serve.sh` itself is smoke-tested by construction of this spec (the Flight probe answers the acme
slice through the seeded node; the quack door line prints where built). The runbook's scripted
counterparts are the existing CI: `make test-flight` (run.sh / adbc.sh / tls.sh) and the quack
integration + door e2e suites. The runbook is executed by a person, which is its entire point.

## Alternatives considered

- **A headless JDBC leg via a downloaded driver jar** - deferred, not rejected: it would pin the
  driver, but item 12's subject is the tools people use, and the GUI part cannot be scripted anyway.
- **Docker-compose with DBeaver/CloudBeaver** - heavier than the thing it validates; the runbook
  with one shell script keeps the loop short.

## Follow-ups

- A scripted JDBC leg when a Java toolchain is available (runbook steps 3-8 are the outline).
- Power BI / another ADBC-embedding tool, when one is at hand - the ADBC section already covers the
  driver they embed.
