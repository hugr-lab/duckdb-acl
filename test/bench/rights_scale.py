#!/usr/bin/env python3
"""Spec 120.2: what platform.exposures / platform.effective_rights cost on a large declared policy.

Exposures reads every stored body of the policy (view SQL, templates, computed columns, RLS, grant masks) and
decides each reader for each role of its catalog; effective_rights decides each object of a catalog for one role
and reads the role's columns listing once. The worst case for both is a DECLARED catalog (a relation per physical
table, views over them, object grants), not a schema alias per source.

    python3 test/bench/rights_scale.py [--sources 20] [--tables 150] [--views 500] [--roles 10] [--grants 50]
                                       [--dir /tmp/acl_rights_scale] [--reps 3] [--rebuild]

The sources and the policy are generated once into --dir. Each query runs `reps` times in one CLI session as an
admin holding `policy`; the median is printed with the row count. Numbers of a run belong in
specs/120-maintenance/spec.md.
"""
import argparse, os, re, statistics, subprocess, sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DUCK = os.path.join(REPO, "build", "release", "duckdb")


def run_sql(sql):
    return subprocess.run([DUCK, "-no-agent", "-unsigned"], input=sql, text=True, capture_output=True, cwd=REPO)


def attaches(args):
    sql = "SET GLOBAL acl_jwks_locations = 'test/idp/';\n"
    sql += "".join(f"ATTACH '{os.path.join(args.dir, f'src{i:03d}.duckdb')}' AS src{i:03d} (READ_ONLY);\n"
                   for i in range(args.sources))
    return sql


def generate(args):
    os.makedirs(args.dir, exist_ok=True)
    for i in range(args.sources):
        path = os.path.join(args.dir, f"src{i:03d}.duckdb")
        if os.path.exists(path) and not args.rebuild:
            continue
        if os.path.exists(path):
            os.remove(path)
        body = "".join(f"CREATE TABLE s.main.t{t:03d}(id INTEGER, tenant VARCHAR, amount INTEGER);\n"
                       for t in range(args.tables))
        out = run_sql(f"ATTACH '{path}' AS s;\n{body}")
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
    for i in range(args.sources):
        # an expansion: a declared relation per physical table
        sql += f"ACL ADMIN CREATE VIRTUAL SCHEMA c.v{i:03d} FROM src{i:03d}.main;\n"
    for v in range(args.views):
        i, t = v % args.sources, v % args.tables
        u = (t + 1) % args.tables
        sql += (f"ACL ADMIN CREATE VIRTUAL VIEW c.w{v:04d} AS 'SELECT a.id, b.amount FROM src{i:03d}.main.t{t:03d} a "
                f"JOIN src{i:03d}.main.t{u:03d} b ON a.id = b.id WHERE a.amount > (SELECT avg(amount) FROM "
                f"src{i:03d}.main.t{t:03d})';\n")
    for r in range(args.roles):
        sql += f"ACL ADMIN CREATE ROLE r{r:02d};\n"
        sql += f"ACL ADMIN GRANT CATALOG c TO ROLE r{r:02d} MAIN RLS (tenant = 'x{r}');\n"
        for g in range(args.grants):
            i, t = (r * args.grants + g) % args.sources, (r + g) % args.tables
            sql += (f"ACL ADMIN GRANT TABLE c.v{i:03d}.t{t:03d} TO ROLE r{r:02d} CAPS '{{\"select\": true}}' "
                    f"COLUMNS (id, amount = 0);\n")
    sql += "ACL ADMIN CREATE ROLE pol;\nACL ADMIN GRANT ADMIN policy TO ROLE pol;\n"
    out = run_sql(sql)
    if out.returncode:
        sys.exit(out.stderr[-2000:])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sources", type=int, default=20)
    ap.add_argument("--tables", type=int, default=150)
    ap.add_argument("--views", type=int, default=500)
    ap.add_argument("--roles", type=int, default=10)
    ap.add_argument("--grants", type=int, default=50)
    ap.add_argument("--dir", default="/tmp/acl_rights_scale")
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--rebuild", action="store_true")
    args = ap.parse_args()
    generate(args)
    queries = [
        ("exposures: one table", "SELECT count(*) FROM platform.exposures('src000', 'main', 't000')"),
        ("exposures: one source", "SELECT count(*) FROM platform.exposures('src000')"),
        ("effective_rights: one object", "SELECT count(*) FROM platform.effective_rights('r00', 'c', 'v000.t000')"),
        ("effective_rights: the catalog", "SELECT count(*) FROM platform.effective_rights('r00', 'c')"),
    ]
    policy = os.path.join(args.dir, "policy.duckdb")
    base = attaches(args) + f"ATTACH '{policy}' AS store;\nSELECT acl_use_db('store', 'acl');\n.timer on\n"
    objects = args.sources * args.tables
    print(f"policy: {objects} relations, {args.views} views, {args.roles} roles x {args.grants} object grants")
    for label, query in queries:
        sql = base + "".join(f'ACL ROLE "pol" {query};\n' for _ in range(args.reps))
        out = run_sql(sql)
        times = [float(m) for m in re.findall(r"Run Time \(s\): real ([0-9.]+)", out.stdout)][-args.reps:]
        rows = re.findall(r"│\s+(\d+)\s+│", out.stdout)
        if out.returncode or not times:
            print(f"{label}: FAILED {out.stderr[-500:]}")
            continue
        print(f"{label}: {statistics.median(times):.3f} s (rows {rows[-1] if rows else '?'})")


if __name__ == "__main__":
    main()
