#!/usr/bin/env python3
"""Fail on the two ways a name comparison in generated SQL stops agreeing with the C++ side (spec 116).

1. `lower(` in SQL text. SQL's lower() folds Unicode; StringUtil::Lower / CIEquals and duckdb's own
   catalog fold ASCII. Two folds give two answers to "is this the same name": a hidden column that a
   grant's projection kept ("Äx" read as "äx"), an alias tail cut in the wrong place. A name or a key in
   SQL is folded with KeyFoldSql (translate A-Z) - an occurrence that is NOT a name comparison is listed
   in ALLOWED with its reason.
2. A C++ size or length concatenated into SQL text (`substr(col, 1, " + std::to_string(x.size()) ...`).
   C++ counts bytes, SQL's substr / left / right count characters: a prefix over a non-ASCII name stops
   matching (a REVOKE that kept a subtree). A prefix in SQL is KeyPrefixSql, measured in SQL.

Comments are skipped; the check is textual, run over src/ by the lint job.
"""
import glob
import re
import sys

# (file, a fragment of the line) -> why `lower(` is right there
ALLOWED = {
    ("src/acl_cluster.cpp", 'lower(\\"name\\") = lower('): "cluster items (extensions, sources): both sides in SQL",
    ("src/acl_cluster.cpp", 'lower(\\"name\\"), lower(\\"depends_on\\")'): "cluster deps: both read back folded in SQL",
    ("src/acl_cluster.cpp", 'lower(d.\\"name\\") = lower(i.\\"name\\")'): "cluster deps: both sides in SQL",
    ("src/acl_cluster.cpp", "lower(name) = lower("): "duckdb_settings names: both sides folded in SQL",
}

LOWER = re.compile(r"(?<![A-Za-z_.:])lower\(")
SQL_CUT = re.compile(r"\b(substr|left|right)\(")
CPP_SIZE = re.compile(r"to_string\([^;]*\.(size|length)\(\)")

bad = []
for path in sorted(glob.glob("src/**/*.cpp", recursive=True) + glob.glob("src/**/*.hpp", recursive=True)):
    if path.startswith("src/quack_embed/") or path.endswith("acl_schema_sql.hpp") or "acl_function_seed" in path:
        continue  # generated or vendored
    previous = ""
    for number, line in enumerate(open(path, encoding="utf-8"), 1):
        code = line.split("//", 1)[0]
        window, previous = previous + code, code
        if CPP_SIZE.search(code) and SQL_CUT.search("".join(re.findall(r'"((?:[^"\\]|\\.)*)"', window))):
            bad.append(f"{path}:{number}: a C++ size in SQL text next to substr/left/right - use KeyPrefixSql")
        if '"' not in code:
            continue  # SQL text is a literal
        literals = "".join(re.findall(r'"((?:[^"\\]|\\.)*)"', code))
        if LOWER.search(literals) and not any(path == f and frag in code for (f, frag) in ALLOWED):
            bad.append(f"{path}:{number}: lower( in SQL text - fold a name with KeyFoldSql (spec 116)")

if bad:
    print("\n".join(bad))
    sys.exit(1)
print("sql fold: no lower( on a name, no C++ byte count in SQL text")
