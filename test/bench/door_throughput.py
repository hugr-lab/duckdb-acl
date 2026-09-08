#!/usr/bin/env python3
"""Reads and writes through the quack door, with parallel clients (specs/043).

Two modes over the same data and the same client work, so the difference between them is what serving
under the ACL costs end to end:

  plain  quack_serve, no authorization callback, clients naming the physical table
  acl    acl_quack_serve, clients holding a JWT and naming their virtual object

Each client is its own process, as in the e2e harness - the door is a socket, and a thread in the
runner would measure something else. Reads are point queries (cheap to execute, so the door and the
rewrite are what shows); writes are streamed bulk loads, which is spec 042's drain path.

The numbers are throughput, not latency percentiles: what an operator sizes a deployment with. A
per-statement figure for the rewrite itself, with no socket in the way, is test/bench/rewrite_cost.py.

Usage:  test/bench/door_throughput.py [--clients 4] [--reads 200] [--rows 20000]
"""

import argparse
import json
import pathlib
import re
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
BUILD = ROOT / "build" / "release"

TOKENS = {
    "acme": (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJpc3MiOiJodHRwczovL2lzc3Vlci50ZXN0L3MiLCJhdWQiOiJhcGk6Ly9hY2wtdGVzdCIsImV4cCI6NDEwMjQ0NDgwMCwic3ViIjoidS1hY21lIiwicm9sZXMiOlsiYW5hbHlzdCJdLCJ0aWQiOiJhY21lIn0."
        "vzPJbHXAXfczhZwQp183JaaBLlSRSipNsSqwxoIFfng"
    ),
    "globex": (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJpc3MiOiJodHRwczovL2lzc3Vlci50ZXN0L3MiLCJhdWQiOiJhcGk6Ly9hY2wtdGVzdCIsImV4cCI6NDEwMjQ0NDgwMCwic3ViIjoidS1nbG9iZXgiLCJyb2xlcyI6WyJhbmFseXN0Il0sInRpZCI6Imdsb2JleCJ9."
        "CitaHH8sw-ndoasm0iTvIRKq9XBJt7PDfm22IhSQZ78"
    ),
}
SERVER_TOKEN = "bench-server-token"


# What the grant says, so the cost of each part can be seen on its own rather than as one number.
# `writes` says whether a bulk load is even possible under that grant: a predicate with no column list
# has no publish order, and spec 042 refuses a write whose columns it cannot judge - a real property of
# the design, reported here rather than worked around.
POLICIES = {
    "none": ("", True),                                       # a plain rename: the floor
    "cols": ("    COLUMNS 'id,tenant,amount'", True),         # a column list, nothing computed
    "rls": ("    RLS 'tenant = acl_claim(''tenant'')'", False),  # a predicate alone: reads only
    "inject": ("    COLUMNS 'id,tenant=acl_claim(''tenant''),amount'", True),  # an assigned column
    "full": ("    RLS 'tenant = acl_claim(''tenant'')'\n"
             "    COLUMNS 'id,tenant=acl_claim(''tenant''),amount'", True),
}


def server_script(loads: str, mode: str, port: int, rows: int, policy: str = "full") -> str:
    data = f"""
{loads}
-- In the server's own default catalog, because that is where a client's `remote.main.orders` lands in
-- plain mode. Both modes therefore read the very same table, which is the point of comparing them.
CREATE TABLE orders AS
    SELECT i AS id, CASE WHEN i % 2 = 0 THEN 'acme' ELSE 'globex' END AS tenant,
           i % 997 AS amount
    FROM range({rows}) t(i);
"""
    if mode == "plain":
        # quack on its own: a server token and nothing else deciding anything.
        return data + f"SELECT * FROM quack_serve('quack:localhost:{port}', token := '{SERVER_TOKEN}');\n"
    if mode == "callback":
        # quack with an authorization callback that decides nothing: it hands back the statement it was
        # given. Whatever separates this from `plain` is what quack's callback mechanism costs - it runs
        # `SELECT <fn>(?, ?)` as a full query, per statement - and whatever separates `acl` from THIS is
        # ours. Without this row the two are indistinguishable and every conclusion is a guess.
        return data + f"""
CREATE MACRO acl_bench_passthru(connection_id, query) AS query;
SET GLOBAL quack_authorization_function = 'acl_bench_passthru';
SELECT * FROM quack_serve('quack:localhost:{port}', token := '{SERVER_TOKEN}');
"""
    if mode == "alias":
        return data + f"""
ATTACH ':memory:' AS store;
SELECT acl_use_db('store', 'acl', true);
SET GLOBAL acl_allow_anonymous_admin=true;
SELECT acl_define_issuer('https://issuer.test/s',
    '{{"keys":[{{"kty":"oct","k":"YWNsLXRlc3QtaHMyNTYtc2VjcmV0"}}]}}',
    'api://acl-test', 'HS256', 'roles', '{{"tid": "tenant"}}');
ACL ADMIN CREATE VIRTUAL CATALOG c;
-- a whole physical schema behind one alias, rather than an object per table
ACL ADMIN ADD SCHEMA memory.main AS c.raw;
ACL ADMIN CREATE ROLE analyst;
ACL ADMIN GRANT CATALOG c TO ROLE analyst WITH (select, insert) MAIN;
SET GLOBAL acl_allow_anonymous_admin=false;
SELECT acl_quack_serve('quack:localhost:{port}', '{SERVER_TOKEN}');
"""
    return data + f"""
ATTACH ':memory:' AS store;
SELECT acl_use_db('store', 'acl', true);
SET GLOBAL acl_allow_anonymous_admin=true;
SELECT acl_define_issuer('https://issuer.test/s',
    '{{"keys":[{{"kty":"oct","k":"YWNsLXRlc3QtaHMyNTYtc2VjcmV0"}}]}}',
    'api://acl-test', 'HS256', 'roles', '{{"tid": "tenant"}}');
ACL ADMIN CREATE VIRTUAL CATALOG c;
ACL ADMIN CREATE VIRTUAL TABLE c.orders AS memory.main.orders;
ACL ADMIN CREATE ROLE analyst;
ACL ADMIN GRANT CATALOG c TO ROLE analyst WITH (select, insert) MAIN;
ACL ADMIN GRANT TABLE c.orders TO ROLE analyst
    CAPS '{{"select": true, "insert": true}}'
{POLICIES[policy][0]};
SET GLOBAL acl_allow_anonymous_admin=false;
SELECT acl_quack_serve('quack:localhost:{port}', '{SERVER_TOKEN}');
"""


def client_script(loads: str, mode: str, port: int, tenant: str, reads: int, write_rows: int,
                  id_base: int, table_rows: int) -> str:
    token = SERVER_TOKEN if mode in ("plain", "callback") else TOKENS[tenant]
    # through a schema alias the object is reached under the alias's own path
    table = "remote.raw.orders" if mode == "alias" else "remote.main.orders"
    lines = [loads, f"ATTACH 'quack:localhost:{port}' AS remote (TYPE quack, TOKEN '{token}');"]
    # From here the CLI times every statement it runs, and run_mode sums those times. Spawning the
    # process, loading extensions and attaching the catalog therefore stay out of the measurement -
    # they are measured on their own, because for a served client the connect is a cost of its own.
    lines.append(".timer on")
    # Point reads: the execution is trivial, so what the numbers show is the door plus the rewrite.
    for k in range(reads):
        lines.append(f"SELECT amount FROM {table} WHERE id = {(k * 7919) % table_rows};")
    if write_rows:
        # the payload is built before the timer matters, so it is not part of the write measurement
        lines.insert(2, f"CREATE TABLE payload AS SELECT {id_base} + i AS id, 'x' AS tenant, i AS amount "
                        f"FROM range({write_rows}) t(i);")
        lines.append(f"INSERT INTO {table} SELECT * FROM payload;")
    return "\n".join(lines) + "\n"


def wait_ready(duckdb: str, loads: str, port: int, token: str, proc, timeout: float = 30.0) -> None:
    deadline = time.time() + timeout
    probe = f"{loads}\nSELECT * FROM quack_query('quack:localhost:{port}', 'SELECT 1', token := '{token}');"
    while time.time() < deadline:
        if proc.poll() is not None:
            raise SystemExit(f"the server exited before it was serving (code {proc.returncode})")
        done = subprocess.run([duckdb, "-unsigned"], input=probe, capture_output=True, text=True)
        if done.returncode == 0 and "Error" not in done.stdout:
            return
        time.sleep(0.3)
    proc.kill()
    out, _ = proc.communicate(timeout=5)
    sys.stderr.write("--- server output ---\n" + (out or "")[-3000:] + "\n")
    raise SystemExit(f"the door never came up on port {port}")


def run_mode(duckdb: str, loads: str, mode: str, port: int, clients: int, reads: int,
             write_rows: int, table_rows: int, policy: str = "full", repeats: int = 3) -> dict:
    server = subprocess.Popen(
        [duckdb, "-unsigned"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, text=True,
    )
    try:
        server.stdin.write(server_script(loads, mode, port, table_rows, policy))
        server.stdin.flush()
        probe_token = SERVER_TOKEN if mode in ("plain", "callback") else TOKENS["acme"]
        wait_ready(duckdb, loads, port, probe_token, server)

        timer_re = re.compile(r"Run Time \(s\): real ([0-9.]+)")

        def launch(phase_reads: int, phase_rows: int):
            """Returns (wall, summed in-client statement time)."""
            procs = []
            started = time.perf_counter()
            for i in range(clients):
                tenant = "acme" if i % 2 == 0 else "globex"
                script = client_script(loads, mode, port, tenant, phase_reads, phase_rows,
                                       1_000_000 * (i + 1), table_rows)
                procs.append(subprocess.Popen(
                    [duckdb, "-unsigned", "-noheader", "-list"], stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                ))
                procs[-1].stdin.write(script)
                procs[-1].stdin.close()
            in_client = 0.0
            for p in procs:
                out = p.stdout.read()
                p.wait()
                if p.returncode != 0 or "Error" in out:
                    sys.stderr.write(out[-3000:])
                    raise SystemExit(f"a {mode} client failed")
                in_client += sum(float(m) for m in timer_re.findall(out))
            return time.perf_counter() - started, in_client

        # A client is a process: spawning it, loading the extensions and ATTACHing the remote catalog
        # all land in the wall clock, and at a few hundred statements that dwarfs the statements. Measure
        # it with a client that does nothing and subtract, so what is left is the work.
        # Twice: the first connect pays whatever the server warms up on its first served statement,
        # and telling a one-off warm-up apart from a per-connection cost changes what the number means.
        cold_wall, _ = launch(0, 0)
        setup_wall, _ = launch(0, 0)
        # Best of N for the phases. A bulk load is one statement per client, so a single sample is at the
        # mercy of whatever else the machine was doing; the best run is the one least contaminated.
        read_wall, read_time = min((launch(reads, 0) for _ in range(repeats)), key=lambda r: r[1])
        writes_ok = mode in ("plain", "callback", "alias") or POLICIES[policy][1]
        # Writes are timed by the phase's wall clock, not by the client's own timer: a streamed insert
        # is sent by the client and *drained by a statement on the server*, so the client's timer stops
        # when the data is away rather than when it is written. Wall minus the connect measured just
        # above is the end-to-end figure, which is the one that means anything here.
        write_wall, write_time = (min((launch(0, write_rows) for _ in range(repeats)), key=lambda r: r[0])
                                  if writes_ok else (0.0, 0.0))
        # If a phase barely exceeds the setup it is measuring process spawning, not the door: say so
        # rather than dividing by a sliver and printing a confident number.
        # `read_time` and `write_time` are summed across clients, so dividing the work by them gives
        # per-client throughput; the wall clock is kept alongside to show what running them together won.
        return {
            "cold_connect_s": cold_wall,
            "connect_s": setup_wall,
            "read_wall_s": read_wall,
            "read_us": read_time / (clients * reads) * 1e6 if reads else 0.0,
            "reads_per_s": (clients * reads) / read_wall if read_wall else 0.0,
            "write_wall_s": write_wall,
            "write_s": write_time,
            # End to end, connect included. Subtracting the connect was tried and abandoned: at any
            # sane volume the phase is shorter than a connect, so the subtraction produced noise and
            # occasionally negatives. Every mode pays its own connect, so the comparison still holds -
            # it just says "what a client that connects and bulk-loads gets", which is the real question.
            "rows_per_s": (clients * write_rows / write_wall) if writes_ok and write_wall else 0.0,
            "writes_ok": writes_ok,
        }
    finally:
        server.kill()
        server.wait()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--clients", type=int, default=4, help="parallel client processes (default 4)")
    ap.add_argument("--reads", type=int, default=200, help="point reads per client (default 200)")
    ap.add_argument("--rows", type=int, default=20000, help="rows each client bulk-loads (default 20k)")
    ap.add_argument("--table-rows", type=int, default=100000, help="rows in the served table")
    ap.add_argument("--port", type=int, default=31800)
    ap.add_argument("--repeats", type=int, default=3, help="runs per phase, best wins (default 3)")
    ap.add_argument("--policies", default="none,cols,rls,inject,full",
                    help="which grants to measure in acl mode (default all four)")
    ap.add_argument("--json", help="also write the numbers here")
    args = ap.parse_args()

    duckdb = str(BUILD / "duckdb")
    acl_ext = BUILD / "extension" / "acl" / "acl.duckdb_extension"
    quack = sorted(BUILD.glob("repository/*/*/quack.duckdb_extension"))
    if not pathlib.Path(duckdb).exists() or not acl_ext.exists():
        print("SKIP: no build - run 'ACL_QUACK=1 GEN=ninja make' first")
        return 0
    if not quack:
        print("SKIP: quack is not built - rebuild with ACL_QUACK=1")
        return 0
    loads = f"LOAD '{acl_ext}'; LOAD '{quack[-1]}';"

    print(f"door throughput: {args.clients} clients, {args.reads} reads each, "
          f"{args.rows} rows each, table {args.table_rows} rows")
    print()
    print(f"{'mode':<8} {'cold':>7} {'connect':>9} {'reads/s':>10} {'µs/read':>9} "
          f"{'rows/s*':>12}")
    print("  (µs/read is in-client; rows/s* is end-to-end and includes the client's connect)")

    out = {}
    offset = 0
    for baseline in ("plain", "callback", "alias"):
        out[baseline] = run_mode(duckdb, loads, baseline, args.port + offset, args.clients,
                                 args.reads, args.rows, args.table_rows, repeats=args.repeats)
        offset += 1
        r = out[baseline]
        print(f"{baseline:<8} {r['cold_connect_s']:>6.2f}s {r['connect_s']:>8.2f}s "
              f"{r['reads_per_s']:>10.0f} {r['read_us']:>8.0f}µ {r['rows_per_s']:>12.0f}")
    for policy in args.policies.split(","):
        policy = policy.strip()
        if policy not in POLICIES:
            raise SystemExit(f"unknown policy {policy!r}; pick from {', '.join(POLICIES)}")
        offset += 1
        out[f"acl:{policy}"] = run_mode(duckdb, loads, "acl", args.port + offset, args.clients,
                                        args.reads, args.rows, args.table_rows, policy,
                                        repeats=args.repeats)
        r = out[f"acl:{policy}"]
        wrote = f"{r['rows_per_s']:>12.0f}" if r["writes_ok"] else f"{'n/a':>12}"
        print(f"{'acl/' + policy:<8} {r['cold_connect_s']:>6.2f}s {r['connect_s']:>8.2f}s "
              f"{r['reads_per_s']:>10.0f} {r['read_us']:>8.0f}µ {wrote}")

    base = out["plain"]
    if base["read_us"] and base["rows_per_s"]:
        print()
        # Measured inside the client, so process startup and the connect stay out of these; the connect
        # is its own column above precisely because it behaves differently from the statements.
        print("per-statement cost against plain quack (in-client time), and what a connect adds:")
        for key, r in out.items():
            if key == "plain":
                continue
            writes = (f"{base['rows_per_s']/r['rows_per_s']*100:>5.0f}%" if r["writes_ok"] and r["rows_per_s"]
                      else "  n/a")
            print(f"  {key:<12} reads {r['read_us']/base['read_us']*100:>5.0f}% of plain's time   "
                  f"writes {writes}   connect {r['connect_s']/base['connect_s']:>4.1f}x")

    if args.json:
        pathlib.Path(args.json).write_text(json.dumps(out, indent=2))
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
