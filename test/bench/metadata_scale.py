#!/usr/bin/env python3
"""Spec 119: what a principal's metadata listing costs when many sources sit under one virtual catalog.

The deployment it models (owner, 2026-10-11): 100-200 physical sources attached to a node, each with its own
schemas and 100-200 objects, and ONE virtual catalog built over them (a schema alias per source). Expanding one
node of a tool's tree - one schema's tables, one table's columns - should cost what that node holds, not what the
node's sources hold.

    python3 test/bench/metadata_scale.py [--sources 200] [--tables 150] [--columns 10] [--dir /tmp/acl_meta_scale]
                                          [--reps 5] [--unrelated 0] [--sources-in duckdb|postgres|mssql]
                                          [--policy-in duckdb|postgres]

--sources-in postgres|mssql (spec 121): the sources are schemas `aclb_s<NNN>` of ONE database behind the scanner
(ACL_PG_DSN / ACL_MSSQL_DSN, as `make test-integration` composes them), attached once as `ext`, each a virtual
schema - so what a listing costs through a scanner's catalog reads. --policy-in postgres keeps the policy catalog
in that postgres (schema `aclb_policy`).

The sources and the policy are generated once into --dir (re-run with --rebuild to regenerate). Each query runs
`reps` times warm in one CLI session as the principal; the median is printed with the row count. Numbers of a
run belong in specs/119-metadata-scale/spec.md.
"""
import argparse, os, re, statistics, subprocess, sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DUCK = os.path.join(REPO, "build", "release", "duckdb")


def run_sql(sql, cwd=REPO):
    return subprocess.run([DUCK, "-no-agent", "-unsigned"], input=sql, text=True, capture_output=True, cwd=cwd)


def ext_attach(args):
    if args.sources_in == "postgres":
        return f"ATTACH '{os.environ['ACL_PG_DSN']}' AS ext (TYPE postgres);\n"
    if args.sources_in == "mssql":
        ext = os.environ.get("ACL_MSSQL_EXT")
        load = f"LOAD '{ext}';\n" if ext else ""
        return load + f"ATTACH '{os.environ['ACL_MSSQL_DSN']}' AS ext (TYPE mssql);\n"
    return ""


def policy_attach(args, path):
    if args.policy_in == "postgres":
        return (f"ATTACH '{os.environ['ACL_PG_DSN']}' AS store (TYPE postgres);\n",
                "SELECT acl_use_db('store', 'aclb_policy'")
    return f"ATTACH '{path}' AS store;\n", "SELECT acl_use_db('store', 'acl'"


def generate_external(args):
    """The sources as schemas of one external database; a marker table says what was built."""
    marker = f"aclb_meta_{args.sources}_{args.tables}_{args.columns}"
    exec_fn = "postgres_execute" if args.sources_in == "postgres" else "mssql_exec"
    probe = run_sql(ext_attach(args) + f"SELECT count(*) FROM ext.aclb_s000.{marker};\n")
    if probe.returncode == 0 and not args.rebuild:
        return
    cols = ", ".join(f"c{j} INTEGER" for j in range(args.columns))
    for i in range(args.sources):
        schema = f"aclb_s{i:03d}"
        if args.sources_in == "postgres":
            ddl = f"DROP SCHEMA IF EXISTS {schema} CASCADE; CREATE SCHEMA {schema}; "
        else:
            drops = "".join(f"IF OBJECT_ID(''{schema}.t{t:03d}'') IS NOT NULL DROP TABLE {schema}.t{t:03d}; "
                            for t in range(args.tables))
            ddl = (f"IF SCHEMA_ID(''{schema}'') IS NULL EXEC(''CREATE SCHEMA {schema}''); " + drops)
        ddl += "".join(f"CREATE TABLE {schema}.t{t:03d}({cols}); " for t in range(args.tables))
        if i == 0:
            ddl += f"CREATE TABLE {schema}.{marker}(x INTEGER); "
        if args.sources_in == "postgres":
            # postgres_execute runs one command: the schema's DDL as one anonymous block
            ddl = "DO $b$ BEGIN " + ddl.replace("DROP SCHEMA IF EXISTS", "EXECUTE ''DROP SCHEMA IF EXISTS", 1)
            ddl = ddl.replace(" CASCADE; ", " CASCADE''; ", 1) + "END $b$"
            out = run_sql(ext_attach(args) + f"CALL {exec_fn}('ext', '{ddl}');\n")
        else:
            out = run_sql(ext_attach(args) + f"SELECT {exec_fn}('ext', '{ddl}');\n")
        if out.returncode:
            sys.exit(out.stderr[:600])


def generate(args):
    os.makedirs(args.dir, exist_ok=True)
    if args.sources_in != "duckdb":
        generate_external(args)
    for i in range(args.sources if args.sources_in == "duckdb" else 0):
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
    policy = policy_path(args)
    if args.policy_in == "duckdb":
        if os.path.exists(policy) and not args.rebuild:
            return
        for p in (policy, policy + ".wal"):
            if os.path.exists(p):
                os.remove(p)
    else:
        out = run_sql(f"ATTACH '{os.environ['ACL_PG_DSN']}' AS pg (TYPE postgres);\n"
                      "CALL postgres_execute('pg', 'DROP SCHEMA IF EXISTS aclb_policy CASCADE');\n")
        if out.returncode:
            sys.exit(out.stderr)
    attach, use = policy_attach(args, policy)
    sql = attaches(args) + attach + use + ", true);\n"
    sql += "SET GLOBAL acl_allow_anonymous_admin=true;\nACL ADMIN CREATE VIRTUAL CATALOG c;\n"
    source = (lambda i: f"src{i:03d}.main") if args.sources_in == "duckdb" else (lambda i: f"ext.aclb_s{i:03d}")
    sql += "".join(f"ACL ADMIN CREATE VIRTUAL SCHEMA c.v{i:03d} AS {source(i)};\n" for i in range(args.sources))
    sql += "ACL ADMIN CREATE ROLE r;\nACL ADMIN GRANT CATALOG c TO ROLE r MAIN;\n"
    out = run_sql(sql)
    if out.returncode:
        sys.exit(out.stderr)


def policy_path(args):
    tag = "" if args.sources_in == "duckdb" else f"_{args.sources_in}_{args.sources}_{args.tables}"
    return os.path.join(args.dir, f"policy{tag}.duckdb")


def attaches(args):
    sql = "SET GLOBAL acl_jwks_locations = 'test/idp/';\n" + ext_attach(args)
    sql += "".join(f"ATTACH '{os.path.join(args.dir, f'src{i:03d}.duckdb')}' AS src{i:03d} (READ_ONLY);\n"
                   for i in range(args.sources if args.sources_in == "duckdb" else 0))
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
    ap.add_argument("--sources-in", choices=["duckdb", "postgres", "mssql"], default="duckdb")
    ap.add_argument("--policy-in", choices=["duckdb", "postgres"], default="duckdb")
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
        # what the JDBC driver (acl-clients spec 006) sends as a tool's tree expands, one level each (spec 121)
        "jdbc getSchemas (catalog)": "SELECT catalog_name, schema_name FROM information_schema.schemata WHERE catalog_name = 'c' AND schema_name LIKE '%' ESCAPE '\\' ORDER BY catalog_name, schema_name",
        "jdbc getTables (schema)": f"SELECT database_name, schema_name, table_name AS object_name, comment, temporary, false AS is_view FROM duckdb_tables() WHERE database_name = 'c' AND schema_name LIKE '{mid}' ESCAPE '\\' AND table_name LIKE '%' ESCAPE '\\' UNION ALL SELECT database_name, schema_name, view_name AS object_name, comment, temporary, true AS is_view FROM duckdb_views() WHERE database_name = 'c' AND schema_name LIKE '{mid}' ESCAPE '\\' AND view_name LIKE '%' ESCAPE '\\' ORDER BY is_view, temporary, database_name, schema_name, object_name",
        "jdbc getColumns (table)": f"SELECT database_name, schema_name, table_name, column_name, column_index, comment, column_default, is_nullable, data_type, is_generated FROM duckdb_columns() WHERE database_name = 'c' AND schema_name LIKE '{mid}' ESCAPE '\\' AND table_name LIKE 't010' ESCAPE '\\' AND column_name LIKE '%' ESCAPE '\\' ORDER BY database_name, schema_name, table_name, column_index",
        "jdbc getPrimaryKeys (table)": f"SELECT vcat, object, key_sequence, \"column\" FROM acl_keys() WHERE kind = 'relation' AND vcat = 'c' AND object = '{mid}.t010' ORDER BY vcat, object, \"column\"",
        "jdbc getImportedKeys (table)": f"SELECT r.vcat, r.name, r.from_object, r.to_object, r.from_column_list, r.to_column_list, k.object AS key_object FROM acl_references() r LEFT JOIN (SELECT DISTINCT vcat, object FROM acl_keys() WHERE kind = 'relation') k ON k.vcat = r.vcat AND k.object = r.to_object WHERE r.to_kind = 'relation' AND r.expression IS NULL AND r.vcat = 'c' AND r.from_object = '{mid}.t010' ORDER BY r.vcat, r.name",
        "jdbc getFunctions (schema)": f"SELECT database_name, schema_name, function_name, function_type, comment, description, parameter_types FROM duckdb_functions() WHERE database_name = 'c' AND schema_name LIKE '{mid}' ESCAPE '\\' AND function_name LIKE '%' ESCAPE '\\' ORDER BY database_name, schema_name, function_name",
    }
    attach, use = policy_attach(args, policy_path(args))
    if args.policy_in == "duckdb":
        attach = attach.replace(" AS store;", " AS store (READ_ONLY);")
    head = attaches(args) + attach + use + ");\nSET GLOBAL acl_metadata_max_rows = 0;\n.timer on\n.mode csv\n"
    print(f"{args.sources} sources x {args.tables} tables x {args.columns} columns, {args.unrelated} unrelated, "
          f"sources in {args.sources_in}, policy in {args.policy_in}")
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
