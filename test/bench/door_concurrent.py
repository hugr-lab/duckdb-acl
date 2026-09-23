#!/usr/bin/env python3
"""Many quack clients at once through the door: does the fetch window (spec 077) hold up when
clients compete for the server - its workers, its producers, its memory?

One server serves the same virtual views as door_stream.py; N clients start together, each a separate
duckdb process running one query through `quack_query` under a JWT, with its own quack log in memory
so it can count its FETCHes. Every client checks its answer. The kinds of client, assigned in turn:

  full   the whole result, as fast as the client reads (count, sums over both columns)
  first  `LIMIT 1` over the whole result: the early stop
  slow   the whole of a smaller result on one client thread, a hash per row
  sort   `LIMIT 10` over a sort of the whole result: a first batch that takes the server a while

What decides "holds up": every client answers, correctly, within the timeout; a failure is told
apart as hung, an error (with its text) or a WRONG answer; the FETCHes per client stay bounded; the
server's peak resident set above its baseline. The server's worker pool is one thread per connection up to
`acl_quack_server_max_connections` and a quack client opens one connection per FETCH in flight, so a
small pool (`--set acl_quack_server_max_connections=64`) makes the clients queue for workers.

Usage:  test/bench/door_concurrent.py [--clients 8] [--mix full,first,slow,sort] [--rows 50000000]
                                      [--slow-rows 5000000] [--set NAME=VALUE ...] [--timeout 180]
"""

import argparse
import pathlib
import re
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from door_stream import ROOT, TOKEN, artifacts, rss_kib, server_script, Sampler, wait_ready  # noqa: E402


def client_sql(loads: str, port: int, kind: str, read_ahead: int) -> str:
    q = "FROM quack_query('quack:localhost:%d', '{src}', token := '%s')" % (port, TOKEN)
    body = {
        "full": "SELECT 'answer', count(*), sum(i), sum(length(s)) " + q.format(src="SELECT * FROM big") + ";",
        "first": "SELECT 'answer', count(*) FROM (SELECT * " + q.format(src="SELECT * FROM big") + " LIMIT 1);",
        "slow": "SET threads = 1;\nSELECT 'answer', count(*), sum(length(md5(md5(s)))) "
        + q.format(src="SELECT * FROM slow") + ";",
        "sort": "SELECT 'answer', count(*), min(i) FROM (SELECT * "
        + q.format(src="SELECT i FROM big ORDER BY i DESC") + " LIMIT 10);",
    }[kind]
    ahead = f"SET quack_fetch_read_ahead = {read_ahead};\n" if read_ahead else ""
    return f"""{loads}
{ahead}CALL enable_logging(['Quack'], storage := 'memory');
.timer on
{body}
.timer off
SELECT 'fetches', count(*) FROM duckdb_logs WHERE message LIKE '%FETCH_REQUEST%' AND message LIKE '%''server'': ''http%';
"""


def expected(kind: str, rows: int, slow_rows: int):
    if kind == "full":
        return str(rows)
    if kind == "first":
        return "1"
    if kind == "slow":
        return str(slow_rows)
    return "10"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--clients", type=int, default=8)
    ap.add_argument("--mix", default="full,first,slow,sort", help="client kinds, assigned in turn")
    ap.add_argument("--rows", type=int, default=50_000_000)
    ap.add_argument("--slow-rows", type=int, default=5_000_000)
    ap.add_argument("--read-ahead", type=int, default=0, help="the clients' quack_fetch_read_ahead (0 = theirs)")
    ap.add_argument("--set", action="append", default=[], metavar="NAME=VALUE", help="a server setting")
    ap.add_argument("--timeout", type=int, default=180, help="seconds a client may take before it counts as hung")
    ap.add_argument("--artifacts", default=str(ROOT / "build" / "release"))
    ap.add_argument("--label", default="run")
    ap.add_argument("--port", type=int, default=31910)
    args = ap.parse_args()

    duckdb, loads = artifacts(pathlib.Path(args.artifacts))
    kinds = [k.strip() for k in args.mix.split(",") if k.strip()]
    server = subprocess.Popen([duckdb, "-unsigned"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, text=True)
    server.stdin.write(server_script(loads, args.port, args.rows, args.slow_rows, args.set))
    server.stdin.flush()
    results, failures = [], 0
    try:
        wait_ready(duckdb, loads, args.port, server)
        time.sleep(1.0)
        baseline = rss_kib(server.pid)
        with Sampler(server.pid) as sampler:
            started = time.time()
            procs = []
            work = pathlib.Path(tempfile.mkdtemp(prefix="door-concurrent-"))
            for n in range(args.clients):
                kind = kinds[n % len(kinds)]
                script, log = work / f"client{n}.sql", work / f"client{n}.out"
                script.write_text(client_sql(loads, args.port, kind, args.read_ahead))
                with open(script) as stdin, open(log, "w") as stdout:
                    # box mode: in -csv / -list the CLI prints no error raised while a result streams (a FETCH that
                    # fails), and the client would look like it answered nothing
                    p = subprocess.Popen([duckdb, "-unsigned"], stdin=stdin, stdout=stdout,
                                         stderr=subprocess.STDOUT)
                procs.append((n, kind, p, log))
            for n, kind, p, log in procs:
                left = max(1.0, args.timeout - (time.time() - started))
                try:
                    p.wait(timeout=left)
                    hung = False
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait()
                    hung = True
                out = re.sub(r"\x1b\[[0-9;]*m", "", log.read_text())
                run = re.findall(r"Run Time \(s\): real ([0-9.]+)", out)
                answer = re.search(r"│\s*answer\s*│\s*([0-9]+)", out)
                fetches = re.search(r"│\s*fetches\s*│\s*([0-9]+)", out)
                got = answer.group(1) if answer else None
                error = next((ln.strip() for ln in out.splitlines() if "Error" in ln), None)
                ok = not hung and got == expected(kind, args.rows, args.slow_rows) and error is None
                # a failure is one of three: the client hung, it got an error, or it got a WRONG answer
                outcome = "ok" if ok else "hung" if hung else "error" if error else "WRONG" if got else "no answer"
                failures += 0 if ok else 1
                results.append({
                    "client": n, "kind": kind, "ok": ok, "hung": hung, "outcome": outcome, "error": error,
                    "seconds": float(run[-1]) if run else None,
                    "fetches": int(fetches.group(1)) if fetches else None,
                    "detail": "" if ok else ([ln.strip()[:240] for ln in out.splitlines() if "Error" in ln][:2]
                                             or out.strip().splitlines()[-3:] or ["(no output)"]),
                })
            wall = time.time() - started
    finally:
        server.kill()
        server.communicate(timeout=10)

    print(f"== {args.label}: {args.clients} clients ({','.join(kinds)}), server {' '.join(args.set) or 'defaults'}")
    for kind in kinds:
        mine = [r for r in results if r["kind"] == kind]
        secs = [r["seconds"] for r in mine if r["seconds"] is not None]
        fetches = [r["fetches"] for r in mine if r["fetches"] is not None]
        bad = [r for r in mine if not r["ok"]]
        print(f"  {kind:>5} x{len(mine)}: time {min(secs, default=0):.2f}-{max(secs, default=0):.2f} s, "
              f"FETCHes {min(fetches, default=0)}-{max(fetches, default=0)}"
              + (f", FAILED {len(bad)}: " + ", ".join(sorted({r['outcome'] for r in bad})) if bad else ""))
        for r in bad:
            print(f"      client {r['client']} {r['outcome']} after {r['seconds']} s: {(r['error'] or ' | '.join(r['detail']))[:200]}")
    print(f"  wall {wall:.2f} s, server peak +{(sampler.peak - baseline) / 1024:.0f} MiB over "
          f"{baseline / 1024:.0f} MiB")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
