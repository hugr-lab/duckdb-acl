#!/usr/bin/env python3
"""Spec 119: what a principal's metadata listing costs when many sources sit under one virtual catalog.

The deployment it models (owner, 2026-10-11): 100-200 physical sources attached to a node, each with its own
schemas and 100-200 objects, and ONE virtual catalog built over them (a schema alias per source). Expanding one
node of a tool's tree - one schema's tables, one table's columns - should cost what that node holds, not what the
node's sources hold.

    python3 test/bench/metadata_scale.py [--sources 200] [--tables 150] [--columns 10] [--dir /tmp/acl_meta_scale]
                                          [--reps 5] [--unrelated 0]

The sources and the policy are generated once into --dir (re-run with --rebuild to regenerate). Each query runs
`reps` times warm in one CLI session as the principal; the median is printed with the row count. Numbers of a
run belong in specs/119-metadata-scale/spec.md.
"""
import argparse, os, re, statistics, subprocess, sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DUCK = os.path.join(REPO, "build", "release", "duckdb")


def run_sql(sql, cwd=REPO):
    return subprocess.run([DUCK, "-no-agent", "-unsigned"], input=sql, text=True, capture_output=True, cwd=cwd)


def generate(args):
    os.makedirs(args.dir, exist_ok=True)
    for i in range(args.sources):
        path = os.path.join(args.dir, f"src{i:03d}.duckdb")
        if os.path.exists(path) and not args.rebuild:
            continue
        if os.path.exists(path):
            os.remove(path)
        cols = ", ".join(f"c{j} INTEGER" for j in range(args.columns))
        body = "".join(f"CREATE TABLE s.main.t{t:03d}({cols});\n" for t in range(args.tables))
        out = run_sql(f"ATTACH '{path}' AS s;\n{body}")
        if out.returncode:
            sys.exit(out.stderr)
    for i in range(args.unrelated):
        path = os.path.join(args.dir, f"unrelated{i:03d}.duckdb")
        if not os.path.exists(path):
            cols = ", ".join(f"c{j} INTEGER" for j in range(args.columns))
            body = "".join(f"CREATE TABLE u.main.t{t:04d}({cols});\n" for t in range(1000))
            out = run_sql(f"ATTACH '{path}' AS u;\n{body}")
            if out.returncode:
                sys.exit(out.stderr)
    policy = os.path.join(args.dir, "policy.duckdb")
    if os.path.exists(policy) and not args.rebuild:
        return
    for p in (policy, policy + ".wal"):
        if os.path.exists(p):
            os.remove(p)
    sql = attaches(args) + f"ATTACH '{policy}' AS store;\nSELECT acl_use_db('store', 'acl', true);\n"
    sql += "SET GLOBAL acl_allow_anonymous_admin=true;\nACL ADMIN CREATE VIRTUAL CATALOG c;\n"
    sql += "".join(f"ACL ADMIN CREATE VIRTUAL SCHEMA c.v{i:03d} AS src{i:03d}.main;\n" for i in range(args.sources))
    sql += "ACL ADMIN CREATE ROLE r;\nACL ADMIN GRANT CATALOG c TO ROLE r MAIN;\n"
    out = run_sql(sql)
    if out.returncode:
        sys.exit(out.stderr)


def attaches(args):
    sql = "SET GLOBAL acl_jwks_locations = 'test/idp/';\n"
    sql += "".join(f"ATTACH '{os.path.join(args.dir, f'src{i:03d}.duckdb')}' AS src{i:03d} (READ_ONLY);\n"
                   for i in range(args.sources))
    sql += "".join(f"ATTACH '{os.path.join(args.dir, f'unrelated{i:03d}.duckdb')}' AS unrelated{i:03d} (READ_ONLY);\n"
                   for i in range(args.unrelated))
    return sql


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sources", type=int, default=200)
    ap.add_argument("--tables", type=int, default=150)
    ap.add_argument("--columns", type=int, default=10)
    ap.add_argument("--unrelated", type=int, default=0)
    ap.add_argument("--dir", default="/tmp/acl_meta_scale")
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--rebuild", action="store_true")
    args = ap.parse_args()
    generate(args)
    mid = f"v{args.sources // 2:03d}"
    queries = {
        "tables of one schema": f"SELECT * FROM information_schema.tables WHERE table_catalog = 'c' AND table_schema = '{mid}'",
        "columns of one table": f"SELECT * FROM information_schema.columns WHERE table_catalog = 'c' AND table_schema = '{mid}' AND table_name = 't010'",
        "columns of one schema": f"SELECT * FROM information_schema.columns WHERE table_catalog = 'c' AND table_schema = '{mid}'",
        "schemas of the catalog": "SELECT * FROM duckdb_schemas() WHERE database_name = 'c'",
        "GetTables, as the RPC writes it": f"SELECT table_catalog AS catalog_name, table_schema AS db_schema_name, table_name, table_type FROM information_schema.tables WHERE table_catalog = 'c' AND table_schema LIKE '{mid}' ESCAPE '\\' ORDER BY 1, 2, 3",
        "every table, unbounded": "SELECT * FROM information_schema.tables",
    }
    head = attaches(args) + f"ATTACH '{os.path.join(args.dir, 'policy.duckdb')}' AS store (READ_ONLY);\n"
    head += "SELECT acl_use_db('store', 'acl');\nSET GLOBAL acl_metadata_max_rows = 0;\n.timer on\n.mode csv\n"
    print(f"{args.sources} sources x {args.tables} tables x {args.columns} columns, {args.unrelated} unrelated")
    for name, q in queries.items():
        body = "".join(f"ACL ROLE \"r\" SELECT count(*) AS n FROM ({q});\n" for _ in range(args.reps + 1))
        out = run_sql(head + body)
        times = [float(t) for t in re.findall(r"Run Time \(s\): real ([0-9.]+)", out.stdout)][-(args.reps + 1):]
        rows = re.findall(r"^(\d+)$", out.stdout, re.M)
        if out.returncode or len(times) < 2:
            print(f"  {name:32s} ERROR {out.stderr.strip()[:200]}")
            continue
        print(f"  {name:32s} {statistics.median(times[1:]):7.3f} s  (first {times[0]:.3f})  rows {rows[-1] if rows else '?'}")


if __name__ == "__main__":
    main()
