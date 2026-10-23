#!/usr/bin/env python3
"""Spec 147: what a big virtual catalog costs - its writes, its memory, its queries and listings, with many roles.

The deployment it models (owner, 2026-10-23): ONE virtual catalog of 10,000 tables, 10,000 views and 10,000 table
functions spread over schemas, a policy of 1,000 roles (each a catalog grant with a row filter and a column list,
plus object grants), and principals holding 1, 10 or 100 of those roles.

    python3 test/bench/catalog_scale.py [--tables 10000] [--views 10000] [--functions 10000] [--schemas 100]
                                        [--columns 10] [--roles 1000] [--object-grants 10] [--principal-roles 1,10,100]
                                        [--chunk 1000] [--reps 5] [--dir /tmp/acl_catalog_scale] [--rebuild]

Method (crude on purpose, as test/bench/rewrite_cost.py): every measured step is its own CLI process; a process that
only opens the sources and the policy is measured the same way and subtracted, so a number is what the step costs on
an open node. The policy is written in chunks of --chunk statements (a process each), so a write's cost is seen as the
catalog grows. Memory is the process's maximum RSS (`/usr/bin/time`) and duckdb_memory() at its end. Numbers of a run
belong in specs/147-catalog-scale/spec.md.
"""
import argparse, json, os, platform, re, shutil, signal, statistics, subprocess, sys, time

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DUCK = os.path.join(REPO, "build", "release", "duckdb")
TIME = ["/usr/bin/time", "-l"] if platform.system() == "Darwin" else ["/usr/bin/time", "-v"]


def run(sql, timeout=None):
    """One CLI process; answers (wall seconds, max RSS bytes, stdout, stderr lines with an error); a process past
    `timeout` seconds answers wall = None."""
    env = dict(os.environ)
    env.pop("AI_AGENT", None)
    env.pop("CLAUDECODE", None)
    started = time.monotonic()
    # its own session: past the timeout the whole group goes - killing /usr/bin/time alone leaves duckdb running,
    # holding the files' locks and a core
    proc = subprocess.Popen(TIME + [DUCK, "-no-agent", "-unsigned", "-csv"], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=REPO, env=env,
                            start_new_session=True)
    try:
        stdout, stderr = proc.communicate(sql, timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.communicate()
        return None, 0, "", []
    out = subprocess.CompletedProcess(proc.args, proc.returncode, stdout, stderr)
    wall = time.monotonic() - started
    rss = 0
    m = re.search(r"(\d+)\s+maximum resident set size", out.stderr)  # macOS: bytes
    if m:
        rss = int(m.group(1))
    m = re.search(r"Maximum resident set size \(kbytes\): (\d+)", out.stderr)  # Linux: KiB
    if m:
        rss = int(m.group(1)) * 1024
    errors = [line for line in out.stderr.splitlines() if "Error" in line or "error" in line.split(":")[0]]
    return wall, rss, out.stdout, errors


def mib(n):
    return f"{n / 1048576:.0f} MiB"


class Bench:
    def __init__(self, args):
        self.a = args
        self.phys = os.path.join(args.dir, "phys.duckdb")
        self.policy = os.path.join(args.dir, "policy.duckdb")

    def table(self, i):
        return f"s{i % self.a.schemas:03d}.t{i:05d}"

    def head(self, store_ro=True, phys_ro=True):
        return (f"SET GLOBAL acl_jwks_locations = 'test/idp/';\n"
                f"ATTACH '{self.phys}' AS phys{' (READ_ONLY)' if phys_ro else ''};\n"
                f"ATTACH '{self.policy}' AS store{' (READ_ONLY)' if store_ro else ''};\n"
                "SELECT acl_use_db('store', 'acl');\nSET GLOBAL acl_allow_anonymous_admin = true;\n"
                "SET GLOBAL acl_metadata_max_rows = 0;\n")

    def startup(self, store_ro=True, phys_ro=True):
        walls = [run(self.head(store_ro, phys_ro) + "SELECT 1;\n")[0] for _ in range(3)]
        return statistics.median(walls)

    # -- the catalog ------------------------------------------------------------------------------------------------
    def build(self):
        a = self.a
        if os.path.exists(self.policy) and not a.rebuild:
            return
        shutil.rmtree(a.dir, ignore_errors=True)
        os.makedirs(a.dir)
        cols = ", ".join(f"c{j} INTEGER" for j in range(a.columns))
        vals = ", ".join(f"({r}, " + ", ".join(str(r * j) for j in range(1, a.columns)) + f", {r % 10})"
                         for r in range(20))
        sql = f"ATTACH '{self.phys}' AS phys;\n"
        for i in range(a.tables):
            sql += f"CREATE TABLE phys.main.t{i:05d}({cols}, tenant INTEGER);\n"
            sql += f"INSERT INTO phys.main.t{i:05d} VALUES {vals};\n"
        wall, _, _, errors = run(sql)
        if errors:
            sys.exit("phys: " + "; ".join(errors[:3]))
        print(f"sources: {a.tables} physical tables of {a.columns + 1} columns, 20 rows each ({wall:.1f} s)")
        wall, _, _, errors = run(f"ATTACH '{self.policy}' AS store;\nSELECT acl_use_db('store', 'acl', true);\n"
                                 "SET GLOBAL acl_allow_anonymous_admin = true;\n"
                                 "SET GLOBAL acl_jwks_locations = 'test/idp/';\n"
                                 "SELECT acl_define_issuer('test/idp/rs', '{\"url\": \"test/idp/rs\", \"client\": "
                                 "{\"audiences\": [\"api://acl-test\"], \"roles_from\": [\"roles\"]}}');\n"
                                 "ACL ADMIN CREATE VIRTUAL CATALOG c;\n")
        if errors:
            sys.exit("policy: " + "; ".join(errors[:3]))
        grant = lambda j: (f"ACL ADMIN GRANT CATALOG c TO ROLE r{j:04d} WITH (select, insert, update, delete) MAIN "
                           f"RLS (tenant = {j % 10}) COLUMNS (c0, c1, c2, tenant);")
        # the catalog grants first: one with a row filter probes it against every relation of the catalog (spec 027),
        # which is measured at full size below on a sample rather than paid a thousand times
        kinds = [
            ("role", a.roles, lambda j: f"ACL ADMIN CREATE ROLE r{j:04d};"),
            ("catalog grant", a.roles, grant),
            ("table", a.tables, lambda i: f"ACL ADMIN CREATE VIRTUAL TABLE c.{self.table(i)} AS phys.main.t{i:05d};"),
            ("view", a.views, lambda i: f"ACL ADMIN CREATE VIRTUAL VIEW c.s{i % a.schemas:03d}.v{i:05d} AS SELECT * "
                                        f"FROM phys.main.t{i % a.tables:05d} WHERE c0 >= 0;"),
            ("function", a.functions,
             lambda i: f"ACL ADMIN ADD TABLE FUNCTION c.s{i % a.schemas:03d}.f{i:05d} MACRO 'SELECT * FROM "
                       f"phys.main.t{i % a.tables:05d} WHERE c0 >= acl_arg(1)';"),
            ("object grant", a.roles * a.object_grants,
             lambda k: f"ACL ADMIN GRANT TABLE c.{self.table((k * 7919) % a.tables)} TO ROLE "
                       f"r{k // a.object_grants:04d} COLUMNS (c0, c1, tenant);"),
        ]
        base = self.startup(store_ro=False)
        print(f"policy writes (per statement, a process of {a.chunk} each, its {base:.2f} s startup subtracted):")
        report = {}
        for kind, count, stmt in kinds:
            per = []
            for start in range(0, count, a.chunk):
                n = min(a.chunk, count - start)
                body = "".join(stmt(i) + "\n" for i in range(start, start + n))
                wall, rss, _, errors = run(self.head(store_ro=False) + body)
                if errors:
                    sys.exit(f"{kind} at {start}: " + "; ".join(errors[:3]))
                per.append(((wall - base) * 1000 / n, rss))
            first, last = per[0][0], per[-1][0]
            report[kind] = per
            print(f"  {kind:14s} {count:6d}: {first:6.1f} ms first chunk, {last:6.1f} ms last, "
                  f"{statistics.mean(p[0] for p in per):6.1f} ms mean; max RSS {mib(max(p[1] for p in per))}")
        sample = min(5, a.roles)
        wall, _, _, errors = run(self.head(store_ro=False) + "".join(grant(j) + "\n" for j in range(sample)))
        print(f"  catalog grant with RLS at full size ({sample} rewritten): {(wall - base) * 1000 / sample:8.1f} ms")
        size = os.path.getsize(self.policy)
        print(f"policy catalog file: {mib(size)}")

    # -- a principal --------------------------------------------------------------------------------------------------
    def token(self, k):
        payload = {"iss": "test/idp/rs", "aud": "api://acl-test", "exp": 4102444800, "sub": f"bench{k}",
                   "roles": [f"r{j:04d}" for j in range(k)]}
        return subprocess.check_output(["python3", os.path.join(REPO, "test/scripts/idp_fixtures.py"), "mint",
                                        json.dumps(payload), "rs"], cwd=REPO).decode().strip()

    def timed(self, prefix, statements, reps, phys_ro=True):
        """The first run of `statements` and the median of `reps` more, in one process (.timer)."""
        body = ".timer on\n" + "".join(f"{prefix} {s}\n" for s in statements for _ in range(reps + 1))
        wall, rss, out, errors = run(self.head(phys_ro=phys_ro) + body)
        times = [float(t) for t in re.findall(r"Run Time \(s\): real ([0-9.]+)", out)]
        result = {}
        for n, s in enumerate(statements):
            own = times[n * (reps + 1):(n + 1) * (reps + 1)]
            result[s] = (own[0] if own else float("nan"), statistics.median(own[1:]) if len(own) > 1 else float("nan"))
        return result, rss, errors

    def principal(self, k):
        a = self.a
        tok = self.token(k)
        prefix = f"ACL TOKEN '{tok}'"
        print(f"\nprincipal with {k} role(s):")
        base_wall, base_rss, _, errors = run(self.head() + f"{prefix} SELECT 1;\n")
        if errors:
            print("  ERROR", errors[:2])
            return
        print(f"  open + first statement: {base_wall:.2f} s, max RSS {mib(base_rss)}")
        reads = [f"SELECT count(*) FROM {self.table(1)};", f"SELECT count(*) FROM s001.v00001;",
                 f"SELECT count(*) FROM s001.f00001(0);",
                 f"SELECT count(*) FROM {self.table(2)} a JOIN {self.table(3)} b USING (c0);"]
        res, rss, errors = self.timed(prefix, reads, a.reps)
        for s, (first, warm) in res.items():
            print(f"  {s[:60]:60s} first {first * 1000:7.1f} ms, warm {warm * 1000:6.1f} ms")
        if errors:
            print("  errors:", errors[:2])
        writes = [f"INSERT INTO {self.table(4)} (c0, c1, c2, tenant) VALUES (100, 1, 2, 0);",
                  f"UPDATE {self.table(4)} SET c1 = c1 + 1 WHERE c0 = 100;",
                  f"DELETE FROM {self.table(4)} WHERE c0 = 100;"]
        res, rss, errors = self.timed(prefix, writes, a.reps, phys_ro=False)
        for s, (first, warm) in res.items():
            print(f"  {s[:60]:60s} first {first * 1000:7.1f} ms, warm {warm * 1000:6.1f} ms")
        if errors:
            print("  errors:", errors[:2])
        # the resolver's cache filled: many distinct objects, once each - and the same reads with no ACL, for what the
        # engine's own buffers hold of them
        n = min(2000, a.tables)
        body = "".join(f"{prefix} SELECT count(*) FROM {self.table(i)};\n" for i in range(n))
        wall, rss, _, errors = run(self.head() + body)
        native_wall, native_rss, _, _ = run(self.head() + "".join(f"SELECT count(*) FROM phys.main.t{i:05d};\n"
                                                                 for i in range(n)))
        print(f"  {n} distinct tables, one statement each: {(wall - base_wall) * 1000 / n:6.2f} ms a statement, "
              f"max RSS {mib(rss)} (native: {(native_wall - base_wall) * 1000 / n:5.2f} ms, {mib(native_rss)})" +
              (f" errors {errors[:1]}" if errors else ""))
        listings = ["SELECT count(*) FROM information_schema.tables;",
                    f"SELECT count(*) FROM information_schema.columns WHERE table_schema = 's001' AND "
                    f"table_name = 't00001';",
                    "SELECT count(*) FROM information_schema.columns WHERE table_schema = 's001';",
                    "SELECT count(*) FROM information_schema.columns;",
                    "SELECT count(*) FROM duckdb_tables();",
                    "SELECT count(*) FROM duckdb_functions() WHERE function_type = 'table_macro' OR "
                    "function_type = 'table';",
                    "SELECT count(*) FROM (SHOW ALL TABLES);"]
        for q in listings:
            body = ".timer on\n" + f"{prefix} {q}\n" * 2
            wall, rss, out, errors = run(self.head() + body, timeout=a.listing_timeout)
            if wall is None:
                print(f"  {q[:60]:60s} over {a.listing_timeout} s")
                continue
            times = [float(t) * 1000 for t in re.findall(r"Run Time \(s\): real ([0-9.]+)", out)]
            rows = re.findall(r"^(\d+)$", out, re.M)
            print(f"  {q[:60]:60s} first {times[0] if times else float('nan'):8.1f} ms, warm "
                  f"{times[1] if len(times) > 1 else float('nan'):8.1f} ms, rows {rows[-1] if rows else '?'}, "
                  f"max RSS {mib(rss)}" + (f" errors {errors[:1]}" if errors else ""))
        mem_sql = (f"{prefix} SELECT count(*) FROM {self.table(1)};\n"
                   "SELECT tag, memory_usage_bytes FROM duckdb_memory() WHERE memory_usage_bytes > 0 "
                   "ORDER BY 2 DESC;\n")
        _, _, out, _ = run(self.head() + mem_sql)
        mem = [line for line in out.splitlines() if re.match(r"^[A-Z_]+,\d+$", line)]
        if mem:
            print("  duckdb_memory(): " + ", ".join(f"{t.split(',')[0]} {mib(int(t.split(',')[1]))}" for t in mem))

    def after_write(self, k):
        """A policy write empties the resolver's caches: what the next statement pays."""
        tok = self.token(k)
        prefix = f"ACL TOKEN '{tok}'"
        body = (".timer on\n" + f"{prefix} SELECT count(*) FROM {self.table(1)};\n"
                f"{prefix} SELECT count(*) FROM {self.table(1)};\n"
                "ACL ADMIN GRANT TABLE c.s002.t00002 TO ROLE r0999 COLUMNS (c0, tenant);\n"
                f"{prefix} SELECT count(*) FROM {self.table(1)};\n"
                f"{prefix} SELECT count(*) FROM {self.table(1)};\n")
        _, _, out, errors = run(self.head(store_ro=False) + body)
        times = [float(t) * 1000 for t in re.findall(r"Run Time \(s\): real ([0-9.]+)", out)]
        if len(times) >= 5:
            print(f"  a policy write ({times[2]:.1f} ms) at full size, then the next statement {times[3]:.1f} ms "
                  f"(warm before {times[1]:.1f} ms, after {times[4]:.1f} ms)")
        if errors:
            print("  errors:", errors[:2])


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--tables", type=int, default=10000)
    p.add_argument("--views", type=int, default=10000)
    p.add_argument("--functions", type=int, default=10000)
    p.add_argument("--schemas", type=int, default=100)
    p.add_argument("--columns", type=int, default=10)
    p.add_argument("--roles", type=int, default=1000)
    p.add_argument("--object-grants", type=int, default=10)
    p.add_argument("--principal-roles", default="1,10,100")
    p.add_argument("--chunk", type=int, default=1000)
    p.add_argument("--reps", type=int, default=5)
    p.add_argument("--dir", default="/tmp/acl_catalog_scale")
    p.add_argument("--rebuild", action="store_true")
    p.add_argument("--skip-build", action="store_true")
    p.add_argument("--listing-timeout", type=int, default=300)
    a = p.parse_args()
    b = Bench(a)
    if not a.skip_build:
        b.build()
    print(f"\nstartup (open the sources and the policy, SELECT 1): {b.startup():.2f} s")
    for k in [int(x) for x in a.principal_roles.split(",")]:
        b.principal(min(k, a.roles))
        b.after_write(min(k, a.roles))


main()
