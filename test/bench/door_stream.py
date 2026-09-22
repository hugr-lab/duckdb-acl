#!/usr/bin/env python3
"""Does the quack door stream? A large result through the embedded server, and what it costs the
server's memory while it goes out (spec 063).

The server serves a virtual view of N generated rows (an integer and its text, so the scan costs
something and nothing is stored); a client reads all of it through `quack_query` under a JWT. A
sampler reads the server process's resident set every 100 ms. Three reads:

  first  `... LIMIT 1` on the client: the time until the first batch is there (a stream answers at
         once; a materialized result answers when the whole result is built)
  fast   the whole result, consumed as fast as the client can - throughput (both columns are read:
         the quack client pushes its projection to the server, so a read of `i` alone would never
         build the text, and the transfer would be a fraction of the result)
  slow   the whole result, consumed by a client that is slower than the server (one thread, a hash
         per row): without backpressure the server builds the result ahead of the client, and its
         memory grows with the result; with it, the server waits and its memory stays flat

What decides "streams": the server's peak resident set above its baseline stays bounded as N grows,
in the slow read especially. The numbers are for comparing two builds of the same code on one
machine (`--artifacts` points at a directory holding `duckdb`, `acl.duckdb_extension` and
`quack.duckdb_extension`), not for sizing a deployment.

Usage:  test/bench/door_stream.py [--rows 300000000] [--slow-rows 50000000] [--artifacts DIR]
"""

import argparse
import json
import pathlib
import re
import subprocess
import sys
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]

TOKEN = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJpc3MiOiJodHRwczovL2lzc3Vlci50ZXN0L3MiLCJhdWQiOiJhcGk6Ly9hY2wtdGVzdCIsImV4cCI6NDEwMjQ0NDgwMCwic3ViIjoidS1hY21lIiwicm9sZXMiOlsiYW5hbHlzdCJdLCJ0aWQiOiJhY21lIn0."
    "vzPJbHXAXfczhZwQp183JaaBLlSRSipNsSqwxoIFfng"
)
SERVER_TOKEN = "bench-server-token"


def artifacts(directory: pathlib.Path) -> tuple:
    duckdb, acl, quack = directory / "duckdb", directory / "acl.duckdb_extension", directory / "quack.duckdb_extension"
    if not acl.exists():  # a build tree (build/release): the CLI at the top, the loadables below it
        acl = directory / "extension" / "acl" / "acl.duckdb_extension"
        quack = directory / "extension" / "quack" / "quack.duckdb_extension"
    for path in (duckdb, acl, quack):
        if not path.exists():
            raise SystemExit(f"missing {path}")
    return str(duckdb), f"LOAD '{acl}'; LOAD '{quack}';"


def server_script(loads: str, port: int, rows: int, slow_rows: int) -> str:
    return f"""
{loads}
ATTACH ':memory:' AS store;
SELECT acl_use_db('store', 'acl', true);
SET GLOBAL acl_allow_anonymous_admin=true;
SELECT acl_define_issuer('https://issuer.test/s',
    '{{"keys":[{{"kty":"oct","k":"YWNsLXRlc3QtaHMyNTYtc2VjcmV0"}}]}}',
    'api://acl-test', 'HS256', 'roles', '{{"tid": "tenant"}}');
ACL ADMIN CREATE VIRTUAL CATALOG c;
ACL ADMIN CREATE VIRTUAL VIEW c.big AS SELECT i, i::VARCHAR AS s FROM range({rows}) t(i);
ACL ADMIN CREATE VIRTUAL VIEW c.slow AS SELECT i, i::VARCHAR AS s FROM range({slow_rows}) t(i);
ACL ADMIN CREATE ROLE analyst;
ACL ADMIN GRANT CATALOG c TO ROLE analyst WITH (select) MAIN;
SET GLOBAL acl_allow_anonymous_admin=false;
SELECT acl_quack_serve('quack:localhost:{port}', '{SERVER_TOKEN}');
"""


def rss_kib(pid: int) -> int:
    out = subprocess.run(["ps", "-o", "rss=", "-p", str(pid)], capture_output=True, text=True).stdout.strip()
    return int(out) if out.isdigit() else 0


class Sampler:
    """The server's resident set every 100 ms while a read runs; the peak is what the read cost."""

    def __init__(self, pid: int):
        self.pid, self.peak, self.running = pid, 0, False

    def __enter__(self):
        self.peak, self.running = rss_kib(self.pid), True
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()
        return self

    def run(self):
        while self.running:
            self.peak = max(self.peak, rss_kib(self.pid))
            time.sleep(0.1)

    def __exit__(self, *exc):
        self.running = False
        self.thread.join()


def client(duckdb: str, loads: str, sql: str) -> tuple:
    script = f"{loads}\n.timer on\n{sql}\n"
    started = time.time()
    done = subprocess.run([duckdb, "-unsigned"], input=script, capture_output=True, text=True)
    wall = time.time() - started
    if done.returncode != 0 or "Error" in done.stdout or "Error" in done.stderr:
        raise SystemExit(f"the client failed:\n{done.stdout[-2000:]}\n{done.stderr[-2000:]}")
    runs = [float(m) for m in re.findall(r"Run Time \(s\): real ([0-9.]+)", done.stdout)]
    return (runs[-1] if runs else wall), done.stdout


def wait_ready(duckdb: str, loads: str, port: int, proc, timeout: float = 60.0) -> None:
    deadline = time.time() + timeout
    probe = f"{loads}\nSELECT * FROM quack_query('quack:localhost:{port}', 'SELECT 1', token := '{TOKEN}');"
    while time.time() < deadline:
        if proc.poll() is not None:
            raise SystemExit(f"the server exited before it was serving (code {proc.returncode})")
        done = subprocess.run([duckdb, "-unsigned"], input=probe, capture_output=True, text=True)
        if done.returncode == 0 and "Error" not in done.stdout:
            return
        time.sleep(0.3)
    raise SystemExit(f"the door never came up on port {port}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rows", type=int, default=300_000_000, help="rows of the fast read (default 300M)")
    ap.add_argument("--slow-rows", type=int, default=50_000_000, help="rows of the slow read (default 50M)")
    ap.add_argument("--artifacts", default=str(ROOT / "build" / "release"),
                    help="a build tree, or a directory with duckdb + acl/quack loadables")
    ap.add_argument("--label", default="build")
    ap.add_argument("--port", type=int, default=31900)
    ap.add_argument("--json", help="also write the numbers here")
    args = ap.parse_args()

    duckdb, loads = artifacts(pathlib.Path(args.artifacts))
    results = {"label": args.label, "rows": args.rows, "slow_rows": args.slow_rows}
    q = "SELECT {cols} FROM quack_query('quack:localhost:%d', '{src}', token := '%s')" % (args.port, TOKEN)
    reads = {
        "first": q.format(cols="*", src="SELECT * FROM big") + " LIMIT 1;",
        "fast": q.format(cols="count(*), sum(i), sum(length(s))", src="SELECT * FROM big") + ";",
        "slow": "SET threads = 1;\n" + q.format(cols="count(*), sum(length(md5(md5(s))))",
                                                src="SELECT * FROM slow") + ";",
    }
    for name, sql in reads.items():
        # a fresh server per read: a process's resident set does not shrink when a query's buffers
        # are freed, so a second read on the same server would carry the first one's peak
        server = subprocess.Popen([duckdb, "-unsigned"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, text=True)
        server.stdin.write(server_script(loads, args.port, args.rows, args.slow_rows))
        server.stdin.flush()
        try:
            wait_ready(duckdb, loads, args.port, server)
            time.sleep(1.0)
            baseline = rss_kib(server.pid)
            with Sampler(server.pid) as sampler:
                seconds, out = client(duckdb, loads, sql)
        finally:
            server.kill()
            server.communicate(timeout=10)
        rows = args.rows if name == "fast" else args.slow_rows if name == "slow" else 1
        if name != "first" and f"{rows}" not in out.replace(",", ""):
            raise SystemExit(f"the {name} read did not bring back {rows} rows:\n{out[-1500:]}")
        results[name] = {
            "seconds": round(seconds, 3),
            "rows_per_s": round(rows / seconds) if name != "first" else None,
            "baseline_mib": round(baseline / 1024),
            "peak_mib": round(sampler.peak / 1024),
            "above_baseline_mib": round((sampler.peak - baseline) / 1024),
        }
        print(f"{args.label:>10} {name:>5}: {seconds:8.3f} s  peak {sampler.peak / 1024:7.0f} MiB "
              f"(+{(sampler.peak - baseline) / 1024:6.0f} over a {baseline / 1024:.0f} MiB baseline)", flush=True)
    if args.json:
        pathlib.Path(args.json).write_text(json.dumps(results, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
