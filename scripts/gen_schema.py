#!/usr/bin/env python3
"""Render schema/policy_schema.sql into what else needs it (spec 034).

The .sql file is the source of truth. This writes:

  src/acl_schema_sql.hpp           every statement the extension runs, placeholders intact - beside
                                   its one consumer (acl_policy_catalog.cpp), not in include/: a
                                   generated DDL is not the module's API
  schema/acl_schema.sql            the schema as it stands, names resolved - apply this to a fresh
                                   database and the extension will use what it finds
  src/acl_function_seed.hpp        the shipped function categories (spec 072) as C++ data, for the
                                   in-memory store; the schema seeds the same rows
and refreshes the seed region of a migration step that carries one (schema/migrations/v14.sql).
The migration steps (schema/migrations/v<n>.sql) are written by hand alongside a schema change; this
script never generates them. schema/migrations/README.md holds the contract, and `make schema-check`
proves a migrated catalog has the shape of a fresh one.

Both come from one file, so a hand-applied schema and the extension's own cannot drift apart.

Only the duckdb dialect is rendered. Translating to another one is left to whoever applies it, or
to a later step through a real translator (sqlglot and friends) - the schema is plain SQL, and a
hand-rolled per-dialect renderer is a second thing to keep correct for no gain. Where a target
genuinely differs the source file says so: `ACL_KEY_TEXT` marks the columns that carry an index,
which SQL Server needs bounded (spec 033).

Run `make schema` after editing the source; `make schema-check` fails when the outputs are stale.
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SOURCE = os.path.join(ROOT, "schema", "policy_schema.sql")
HEADER = os.path.join(ROOT, "src", "acl_schema_sql.hpp")
APPLIABLE = os.path.join(ROOT, "schema", "acl_schema.sql")


def read_statements(path):
    """The source file as (section, comments, sql) triples, in order.

    A `;` at end of line ends a statement; `-- @section <name>` starts a section. `schema` is the
    tables as they are now, `migrations` only what an older catalog is missing - which is why a
    hand-applied schema needs the first section and none of the second.
    """
    statements = []
    comments = []
    buffer = ""
    section = "schema"
    seen_sql = False
    for line in open(path):
        stripped = line.strip()
        if not stripped:
            # a blank line ends the file's own header block; comments before the first statement
            # describe the file, not the statement that happens to follow
            if not seen_sql:
                comments = []
            continue
        if stripped.startswith("-- @section "):
            section = stripped[len("-- @section ") :].strip()
            comments = []
            continue
        if stripped.startswith("-- @seed "):
            # a marker the seed statements are generated in place of (spec 072)
            statements.append((section, comments, "@seed " + stripped[len("-- @seed ") :].strip()))
            comments = []
            seen_sql = True
            continue
        if stripped.startswith("--"):
            if not buffer:
                comments.append(stripped[2:].strip())
            continue
        seen_sql = True
        buffer += (" " if buffer else "") + stripped
        if buffer.endswith(";"):
            statements.append((section, comments, buffer[:-1]))
            comments = []
            buffer = ""
    if buffer:
        raise SystemExit("gen_schema: unterminated statement: " + buffer[:60])
    return statements


SEED_DIR = os.path.join(ROOT, "schema", "function_categories")
SEED_CHUNK = 150  # rows per INSERT: a C++ string literal stays well under MSVC's 16 KB per piece


def sql_literal(text):
    return "'" + text.replace("'", "''") + "'"


def read_seed():
    """The shipped function categories (spec 072) as (categories, members, auto) from
    schema/function_categories/: categories.txt is `name<TAB>auto|grant<TAB>comment`, <name>.txt one
    member per line as `[database.schema.]name [TABLE]` (default system.main, default kind scalar)."""
    categories = []
    members = []
    auto = []
    for line in open(os.path.join(SEED_DIR, "categories.txt")):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) != 3 or parts[1] not in ("auto", "grant"):
            raise SystemExit("gen_schema: bad categories.txt line: " + line)
        name, mode, comment = parts
        categories.append((name, comment))
        if mode == "auto":
            auto.append(name)
        seen = set()
        for member in open(os.path.join(SEED_DIR, name + ".txt")):
            member = member.strip()
            if not member or member.startswith("#"):
                continue
            # a name with spaces (an operator such as IS DISTINCT FROM) is written double-quoted
            quoted = re.match(r'^"([^"]+)"(\s+TABLE)?$', member, re.IGNORECASE)
            if quoted:
                words = [quoted.group(1)] + (["TABLE"] if quoted.group(2) else [])
            else:
                words = member.split()
            kind = "scalar"
            if len(words) == 2 and words[1].upper() == "TABLE":
                kind = "table"
            elif len(words) != 1:
                raise SystemExit("gen_schema: bad member in %s.txt: %s" % (name, member))
            path = words[0].split(".") if not quoted else [words[0]]
            if len(path) == 1:
                database, schema, fname = "system", "main", path[0]
            elif len(path) == 3:
                database, schema, fname = path
            else:
                raise SystemExit("gen_schema: a member is bare or database.schema.name: " + member)
            key = (database, schema, fname.lower(), kind)
            if key in seen:
                raise SystemExit("gen_schema: %s.txt lists %s twice" % (name, member))
            seen.add(key)
            members.append((name,) + key)
    return categories, members, auto


def seed_statements():
    """The seed as statements, placeholders intact: guarded by the `function_seed` stamp in meta so a
    re-run of the schema over a seeded catalog inserts nothing (what the operator removed stays
    removed), and stamped last."""
    categories, members, auto = read_seed()
    guard = " WHERE NOT EXISTS (SELECT 1 FROM <meta> WHERE \"key\" = 'function_seed')"
    out = []

    def insert(table, columns, rows):
        for start in range(0, len(rows), SEED_CHUNK):
            values = ", ".join("(" + ", ".join(cells) + ")" for cells in rows[start : start + SEED_CHUNK])
            out.append(
                "INSERT INTO <%s> SELECT * FROM (VALUES %s) AS v(%s)%s"
                % (table, values, ", ".join('"%s"' % c for c in columns), guard)
            )

    insert("function_categories", ("category", "comment", "builtin"),
           [(sql_literal(n), sql_literal(c), "true") for n, c in categories])
    insert("function_category_members", ("category", "database", "schema", "name", "kind"),
           [tuple(sql_literal(x) for x in m) for m in members])
    insert("function_grants", ("role", "category", "database", "schema", "name", "kind", "allowed"),
           [("''", sql_literal(n), "''", "''", "''", "''", "true") for n in auto])
    out.append("INSERT INTO <meta> SELECT 'function_seed', '1'" + guard)
    return out


def expand_seed(statements):
    """Replace the `@seed` marker with the generated statements, keeping its section and comments."""
    expanded = []
    for section, comments, sql in statements:
        if sql.startswith("@seed "):
            if sql != "@seed function_categories":
                raise SystemExit("gen_schema: unknown seed marker: " + sql)
            for index, generated in enumerate(seed_statements()):
                expanded.append((section, comments if index == 0 else [], generated))
            continue
        expanded.append((section, comments, sql))
    return expanded


def schema_version(statements):
    """The version the schema stamps into `meta` - the one statement that says what this shape is."""
    for _, _, sql in statements:
        found = re.search(r"'schema_version', '(\d+)'", sql)
        if found:
            return int(found.group(1))
    raise SystemExit("gen_schema: the schema does not stamp a schema_version")


def cpp_literal(text):
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def write_header(statements):
    out = [
        "// Generated by scripts/gen_schema.py from schema/policy_schema.sql - do not edit.",
        "// Edit the .sql file and run `make schema` (spec 034).",
        "",
        "#pragma once",
        "",
        "namespace duckdb {",
        "namespace acl {",
        "",
        "//! The managed schema, in the order it must be applied. `<schema>` and `<table>` are",
        "//! substituted with the qualified names of the catalog being initialised, and ACL_KEY_TEXT",
        "//! with the key-column type that catalog's kind needs (spec 033).",
        # A DDL statement is one string and does not wrap: reflowing it would only make the
        # generated file disagree with the .sql it came from, so the formatter is told to
        # leave the table alone rather than the column limit relaxed for the whole file.
        "// clang-format off",
        "static const char *const ACL_SCHEMA_SQL[] = {",
    ]
    for _, _, sql in statements:
        out.append("    " + cpp_literal(sql) + ",")
    version = schema_version(statements)
    out += [
        "};",
        "// clang-format on",
        "",
        "//! The version this schema is. A catalog carries its own in `meta`, and a build refuses one",
        "//! that does not match: the migration contract rests on the two being comparable (spec 034).",
        "static constexpr int ACL_SCHEMA_VERSION = %d;" % version,]
    out += [
        "",
        "} // namespace acl",
        "} // namespace duckdb",
        "",
    ]
    open(HEADER, "w").write("\n".join(out))


def resolve_names(sql):
    """`<schema>` and `<table>` as a hand-applied file spells them: the schema `acl` of whatever
    database the file is run against."""
    return re.sub(r"<([a-z_]+)>", lambda m: "acl" if m.group(1) == "schema" else 'acl."%s"' % m.group(1), sql)


def write_appliable(statements):
    lines = [
        "-- duckdb-acl policy schema (spec 006), generated from schema/policy_schema.sql.",
        "-- Do not edit: run `make schema` after changing the source (spec 034).",
        "--",
        "-- duckdb dialect, ready to run as it stands: it creates the schema `acl` in the database you",
        "-- run it against, which is what `acl_use_db('<db>', 'acl', true)` would have created. Pass the",
        "-- same schema name to acl_use_db afterwards, with init disabled, and the extension will use it.",
        "--",
        "-- It is the schema as it stands - the migrations the extension also carries are for catalogs",
        "-- an older version created, and a schema applied from here needs none of them.",
        "--",
        "-- For another engine, translate it - the SQL is plain, and a translator (sqlglot and friends)",
        "-- handles it. Two things a target may need changing:",
        "--   * a key column (VARCHAR below, ACL_KEY_TEXT in the source) is indexed, so SQL Server needs",
        "--     it bounded - NVARCHAR(255) rather than NVARCHAR(MAX), which cannot carry an index;",
        "--   * `IF NOT EXISTS` on CREATE TABLE / ADD COLUMN is not universal - T-SQL guards instead.",
        "",
    ]
    for section, comments, sql in statements:
        for comment in comments:
            lines.append("-- " + comment)
        lines.append(resolve_names(sql).replace("ACL_KEY_TEXT", "VARCHAR") + ";")
        lines.append("")
    open(APPLIABLE, "w").write("\n".join(lines))


MIGRATIONS = os.path.join(ROOT, "schema", "migrations")
SEED_HEADER = os.path.join(ROOT, "src", "acl_function_seed.hpp")


def write_seed_header():
    """The seed as C++ data (spec 072): what the in-memory store starts from, and what a function-driver
    source without the category slots falls back to - the same rows the schema seeds."""
    categories, members, auto = read_seed()
    auto_set = set(auto)
    out = [
        "// Generated by scripts/gen_schema.py from schema/function_categories/ - do not edit.",
        "// Edit the category files and run `make schema` (spec 072).",
        "",
        "#pragma once",
        "",
        "namespace duckdb {",
        "namespace acl {",
        "",
        "//! One shipped category: its name, comment, and whether every role holds it from the start",
        "struct FunctionSeedCategory {",
        "\tconst char *name;",
        "\tconst char *comment;",
        "\tbool auto_granted;",
        "};",
        "",
        "//! One shipped member: category, then the key (database, schema, name, kind)",
        "struct FunctionSeedMember {",
        "\tconst char *category;",
        "\tconst char *database;",
        "\tconst char *schema;",
        "\tconst char *name;",
        "\tconst char *kind;",
        "};",
        "",
        "// clang-format off",
        "static const FunctionSeedCategory ACL_FUNCTION_SEED_CATEGORIES[] = {",
    ]
    for name, comment in categories:
        out.append("    {%s, %s, %s}," % (cpp_literal(name), cpp_literal(comment), "true" if name in auto_set else "false"))
    out += ["};", "", "static const FunctionSeedMember ACL_FUNCTION_SEED_MEMBERS[] = {"]
    for category, database, schema, fname, kind in members:
        out.append("    {%s, %s, %s, %s, %s}," % tuple(cpp_literal(x) for x in (category, database, schema, fname, kind)))
    out += ["};", "// clang-format on", "", "} // namespace acl", "} // namespace duckdb", ""]
    open(SEED_HEADER, "w").write("\n".join(out))


def refresh_migration_seed(statements):
    """A migration step that carries the seed marks the region `-- @seed-begin` ... `-- @seed-end`;
    the region is rewritten with the current seed, names resolved, so the step a v13 catalog takes
    and a fresh v14 catalog end up with the same rows (spec 072)."""
    for name in sorted(os.listdir(MIGRATIONS)):
        path = os.path.join(MIGRATIONS, name)
        if not name.endswith(".sql"):
            continue
        text = open(path).read()
        begin = text.find("-- @seed-begin\n")
        end = text.find("-- @seed-end")
        if begin < 0 or end < 0:
            continue
        body = "\n".join(resolve_names(sql).replace("ACL_KEY_TEXT", "VARCHAR") + ";" for sql in seed_statements())
        open(path, "w").write(text[: begin + len("-- @seed-begin\n")] + body + "\n" + text[end:])


def main():
    statements = expand_seed(read_statements(SOURCE))
    write_header(statements)
    write_appliable(statements)
    refresh_migration_seed(statements)
    write_seed_header()
    print("gen_schema: %d statements -> acl_schema_sql.hpp + acl_schema.sql (+ acl_function_seed.hpp)" % len(statements))


if __name__ == "__main__":
    sys.exit(main())
