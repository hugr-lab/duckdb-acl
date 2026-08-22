#!/usr/bin/env python3
"""What the ACL costs per statement, with no socket in the way (specs/043).

The door's end-to-end numbers mix our work with quack's, the network's and the source's. This measures
only ours: the same physical query, executed by the same process, reached three ways --

  native   the physical table named directly, no prefix; the extension is loaded but does nothing
  role     ACL ROLE "analyst" <the virtual name>   - prefix scan, resolve, rewrite, per statement
  session  ACL SESSION '<handle>' <the virtual name> - what a served client actually sends

-- and against two kinds of object, because the rewrite's cost is not one number:

  rename    the grant is a plain name swap (RENAME form): the floor of what we charge
  policy    projection + a claim-baked RLS predicate (SUBQUERY form): what a real grant costs

Method: each mode runs N identical statements through one CLI process; the process's own startup is
measured separately with an empty script and subtracted. Crude on purpose - no timing hooks inside the
extension, nothing to keep in sync with the code - and the number it reports is the one an operator
would feel.

Usage:  test/bench/rewrite_cost.py [-n 2000] [--rows 100000] [--json out.json]
"""

import argparse
import json
import pathlib
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
BUILD = ROOT / "build" / "release"

# A verified HS256 token for the seeded issuer; the session mode opens a handle with it.
TOKEN = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJpc3MiOiJodHRwczovL2lzc3Vlci50ZXN0L3MiLCJhdWQiOiJhcGk6Ly9hY2wtdGVzdCIsImV4cCI6NDEwMjQ0NDgwMCwic3ViIjoidS1hY21lIiwicm9sZXMiOlsiYW5hbHlzdCJdLCJ0aWQiOiJhY21lIn0."
    "vzPJbHXAXfczhZwQp183JaaBLlSRSipNsSqwxoIFfng"
)


def data_sql(rows: int) -> str:
    """Just the physical data - the baseline that has never heard of the ACL."""
    return f"""
ATTACH ':memory:' AS phys;
CREATE TABLE phys.main.orders AS
    SELECT i AS id, 'acme' AS tenant, i % 997 AS amount, 'ssn-' || i AS ssn
    FROM range({rows}) t(i);
"""


def setup_sql(acl_ext: str, rows: int) -> str:
    """Physical data, and two objects over it: one a pure rename, one carrying a real policy."""
    return f"""
LOAD '{acl_ext}';
ATTACH ':memory:' AS phys;
CREATE TABLE phys.main.orders AS
    SELECT i AS id, 'acme' AS tenant, i % 997 AS amount, 'ssn-' || i AS ssn
    FROM range({rows}) t(i);
ATTACH ':memory:' AS store;
SELECT acl_use_db('store', 'acl', true);
SET GLOBAL acl_allow_anonymous_admin=true;
SELECT acl_define_issuer('https://issuer.test/s',
    '{{"keys":[{{"kty":"oct","k":"YWNsLXRlc3QtaHMyNTYtc2VjcmV0"}}]}}',
    'api://acl-test', 'HS256', 'roles', '{{"tid": "tenant"}}');
ACL ADMIN CREATE VIRTUAL CATALOG c;
ACL ADMIN CREATE VIRTUAL TABLE c.plain AS phys.main.orders;
ACL ADMIN CREATE VIRTUAL TABLE c.guarded AS phys.main.orders;
ACL ADMIN CREATE ROLE analyst;
ACL ADMIN GRANT CATALOG c TO ROLE analyst WITH (select, insert) MAIN;
-- the floor: nothing to project, nothing to filter, so the rewrite is a name swap
ACL ADMIN GRANT TABLE c.plain TO ROLE analyst CAPS '{{"select": true}}';
-- and a grant that actually says something: a hidden column, a mask, and a claim-baked predicate
ACL ADMIN GRANT TABLE c.guarded TO ROLE analyst
    CAPS '{{"select": true}}'
    RLS 'tenant = acl_claim(''tenant'')'
    COLUMNS 'id,amount,ssn=NULL';
SET GLOBAL acl_allow_anonymous_admin=false;
"""


# Each case is (name, native statement, virtual statement). The two must do the same physical work, so
# that the difference between them is ours and not the query's.
def cases(rows: int):
    mid = rows // 2
    return [
        (
            "point",
            f"SELECT amount FROM phys.main.orders WHERE id = {mid};",
            f"SELECT amount FROM plain WHERE id = {mid};",
            f"SELECT amount FROM guarded WHERE id = {mid};",
        ),
        (
            "scan",
            "SELECT count(*), sum(amount) FROM phys.main.orders;",
            "SELECT count(*), sum(amount) FROM plain;",
            "SELECT count(*), sum(amount) FROM guarded;",
        ),
        # Four references to the same object in one statement. Not a realistic query - a probe: the
        # resolver runs per reference, so this says whether our cost is paid once per statement or once
        # per name, which is the difference between "fine" and "fix the cache".
        (
            "4refs",
            " ".join(f"SELECT (SELECT amount FROM phys.main.orders WHERE id = {mid + k}) AS c{k},"
                     for k in range(0, 1)) +
            " ".join(f"(SELECT amount FROM phys.main.orders WHERE id = {mid + k})" +
                     ("," if k < 3 else ";") for k in range(1, 4)),
            " ".join(f"SELECT (SELECT amount FROM plain WHERE id = {mid + k}) AS c{k},"
                     for k in range(0, 1)) +
            " ".join(f"(SELECT amount FROM plain WHERE id = {mid + k})" +
                     ("," if k < 3 else ";") for k in range(1, 4)),
            " ".join(f"SELECT (SELECT amount FROM guarded WHERE id = {mid + k}) AS c{k},"
                     for k in range(0, 1)) +
            " ".join(f"(SELECT amount FROM guarded WHERE id = {mid + k})" +
                     ("," if k < 3 else ";") for k in range(1, 4)),
        ),
    ]


def run(duckdb: str, script: str) -> float:
    started = time.perf_counter()
    proc = subprocess.run(
        [duckdb, "-unsigned", "-noheader", "-list"],
        input=script,
        capture_output=True,
        text=True,
    )
    elapsed = time.perf_counter() - started
    if proc.returncode != 0:
        sys.stderr.write(proc.stdout[-4000:] + proc.stderr[-4000:])
        raise SystemExit(f"benchmark script failed (exit {proc.returncode})")
    # duckdb's CLI reports statement errors on stdout and still exits 0, so look for them
    if "Error:" in proc.stdout:
        sys.stderr.write(proc.stdout[-4000:])
        raise SystemExit("benchmark script reported an error")
    return elapsed


def measure(duckdb: str, setup: str, body: str, n: int, repeats: int) -> float:
    """Wall time of the body alone, in seconds, taking the best of `repeats` runs.

    The best rather than the mean: we are after the cost of the work, and every source of noise on a
    developer's machine only ever adds. The setup is run in both the measured and the baseline script,
    so it cancels.
    """
    full = min(run(duckdb, setup + body) for _ in range(repeats))
    bare = min(run(duckdb, setup) for _ in range(repeats))
    return max(full - bare, 0.0) / n


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-n", type=int, default=2000, help="statements per measurement (default 2000)")
    ap.add_argument("--rows", type=int, default=100000, help="rows in the physical table (default 100k)")
    ap.add_argument("--repeats", type=int, default=3, help="runs per measurement, best wins (default 3)")
    ap.add_argument("--json", help="also write the numbers here")
    args = ap.parse_args()

    duckdb = str(BUILD / "duckdb")
    acl_ext = str(BUILD / "extension" / "acl" / "acl.duckdb_extension")
    for path in (duckdb, acl_ext):
        if not pathlib.Path(path).exists():
            print(f"SKIP: {path} is missing - run 'GEN=ninja make' first")
            return 0

    setup = setup_sql(acl_ext, args.rows)

    print(f"acl rewrite cost: n={args.n} statements per measurement, {args.rows} rows, "
          f"best of {args.repeats}")
    print()
    print(f"{'case':<8} {'unloaded':>10} {'loaded':>10} {'toll':>8} "
          f"{'rename':>10} {'+cost':>9} {'policy':>10} {'+cost':>9}")

    data = data_sql(args.rows)
    results = {}
    for name, native_sql, plain_sql, guarded_sql in cases(args.rows):
        # What the same statement costs with the extension not loaded at all. The parser override sees
        # every statement, prefixed or not - it scans for our prefix and, since spec 042, for a call to
        # quack's stream scan - so this column is the toll we charge queries that are not ours.
        unloaded = measure(duckdb, data, (native_sql + "\n") * args.n, args.n, args.repeats)
        native = measure(duckdb, setup, (native_sql + "\n") * args.n, args.n, args.repeats)
        role_plain = measure(duckdb, setup, f'ACL ROLE "analyst" {plain_sql}\n' * args.n, args.n, args.repeats)
        role_guarded = measure(duckdb, setup, f'ACL ROLE "analyst" {guarded_sql}\n' * args.n, args.n, args.repeats)
        results[name] = {
            "unloaded_us": unloaded * 1e6,
            "native_us": native * 1e6,
            "rename_us": role_plain * 1e6,
            "policy_us": role_guarded * 1e6,
        }
        print(f"{name:<8} {unloaded*1e6:>9.1f}µ {native*1e6:>9.1f}µ {(native-unloaded)*1e6:>7.1f}µ "
              f"{role_plain*1e6:>9.1f}µ {(role_plain-native)*1e6:>8.1f}µ "
              f"{role_guarded*1e6:>9.1f}µ {(role_guarded-native)*1e6:>8.1f}µ")

    # The session prefix is NOT measured here. A handle lives in the DatabaseInstance that minted it
    # (spec 040), so one process cannot hand it to another - and every statement here runs in a fresh
    # CLI. What the session form adds over the role form is a map lookup; the door benchmark measures it
    # where sessions exist by construction.

    if args.json:
        pathlib.Path(args.json).write_text(json.dumps(results, indent=2))
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
