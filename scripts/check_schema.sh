#!/usr/bin/env bash
# Two things about the generated schema (spec 034):
#   1. the outputs are current - regenerate into a scratch copy and diff
#   2. the hand-applied file actually works - apply schema/acl_schema.sql to an empty database, point
#      the extension at it with init disabled, and use it. If the two ever diverge this is what says so.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

echo "schema-check: outputs current?"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
for f in src/include/acl_schema_sql.hpp schema/acl_schema.sql; do
    cp "$f" "$tmp/$(basename "$f").before"
done
python3 scripts/gen_schema.py >/dev/null
stale=0
for f in src/include/acl_schema_sql.hpp schema/acl_schema.sql; do
    if ! diff -q "$tmp/$(basename "$f").before" "$f" >/dev/null; then
        echo "  STALE: $f - run 'make schema' and commit the result" >&2
        stale=1
    fi
done
test "$stale" -eq 0 || exit 1
echo "  ok"

duckdb=build/release/duckdb
if [ ! -x "$duckdb" ]; then
    echo "schema-check: no $duckdb - build first to check the applied schema" >&2
    exit 1
fi

echo "schema-check: does a hand-applied schema work?"
db="$tmp/applied.db"
"$duckdb" "$db" -c ".read schema/acl_schema.sql" >/dev/null
# init disabled: the extension must be content with what the file created. Fed from a file rather
# than -c: the CLI parses a whole -c string at once, so the ACL grammar would be read before the
# setting that enables it has run.
cat > "$tmp/use.sql" <<SQL
ATTACH '$db' AS store;
ATTACH ':memory:' AS phys;
CREATE TABLE phys.main.t(id INT, tenant VARCHAR);
INSERT INTO phys.main.t VALUES (1, 'acme'), (2, 'globex');
SELECT acl_use_db('store', 'acl', false);
SET GLOBAL acl_allow_anonymous_admin=true;
ACL ADMIN CREATE VIRTUAL CATALOG c;
ACL ADMIN CREATE VIRTUAL TABLE c.t AS phys.main.t;
ACL ADMIN CREATE ROLE r CLAIMS (tenant = 'acme');
ACL ADMIN GRANT CATALOG c TO ROLE r MAIN;
ACL ADMIN GRANT TABLE c.t TO ROLE r WITH (select) RLS (tenant = acl_claim('tenant'));
ACL ROLE "r" SELECT CASE WHEN count(*) = 1 THEN 'schema-applied-ok' ELSE 'WRONG ROW COUNT: ' || count(*) END AS result FROM t;
SQL
"$duckdb" -f "$tmp/use.sql" | tee "$tmp/out" | tail -6
grep -q "schema-applied-ok" "$tmp/out" || { echo "  the applied schema did not serve a policy" >&2; exit 1; }
echo "  ok"

# 3. the migration contract (schema/migrations/README.md): a catalog created from the schema file the
#    `main` branch ships, taken forward by every v<n>.sql above its version, must have the same tables
#    and columns - in the same order, with the same types - as one created fresh from the current file.
#    Before a merge origin/main is version n-1 and this exercises the new step; after it, both are n
#    and there is nothing to migrate, which is reported rather than faked.
echo "schema-check: does a catalog migrated from main's schema match a fresh one?"
if ! git rev-parse --verify -q origin/main >/dev/null 2>&1; then
    git fetch -q --depth 1 origin main 2>/dev/null || true
fi
if ! git show origin/main:schema/acl_schema.sql > "$tmp/prev.sql" 2>/dev/null; then
    echo "  skip: origin/main is not available here" >&2
else
    version_of() { grep -oE "'schema_version', '[0-9]+'" "$1" | grep -oE "[0-9]+" | head -1; }
    prev_version="$(version_of "$tmp/prev.sql")"
    cur_version="$(version_of schema/acl_schema.sql)"
    if [ -z "$prev_version" ] || [ -z "$cur_version" ]; then
        echo "  a schema file does not stamp a schema_version" >&2; exit 1
    fi
    if [ "$prev_version" -ge "$cur_version" ]; then
        echo "  (origin/main is at $prev_version, this tree at $cur_version - nothing to migrate)"
    else
        "$duckdb" "$tmp/migrated.db" -c ".read $tmp/prev.sql" >/dev/null
        for v in $(seq "$((prev_version + 1))" "$cur_version"); do
            step="schema/migrations/v$v.sql"
            [ -f "$step" ] || { echo "  missing migration step $step" >&2; exit 1; }
            "$duckdb" "$tmp/migrated.db" -c ".read $step" >/dev/null
        done
        "$duckdb" "$tmp/fresh.db" -c ".read schema/acl_schema.sql" >/dev/null
        shape="SELECT table_name, ordinal_position, column_name, data_type FROM information_schema.columns WHERE table_schema = 'acl' ORDER BY 1, 2"
        stamp="SELECT value FROM acl.meta WHERE key = 'schema_version'"
        "$duckdb" -csv -noheader "$tmp/migrated.db" -c "$shape" > "$tmp/migrated.shape"
        "$duckdb" -csv -noheader "$tmp/fresh.db" -c "$shape" > "$tmp/fresh.shape"
        if ! diff -u "$tmp/fresh.shape" "$tmp/migrated.shape"; then
            echo "  a catalog migrated $prev_version -> $cur_version differs from a fresh $cur_version (above: - fresh, + migrated)" >&2
            exit 1
        fi
        migrated_stamp="$("$duckdb" -csv -noheader "$tmp/migrated.db" -c "$stamp")"
        [ "$migrated_stamp" = "$cur_version" ] || { echo "  the migrated catalog is stamped $migrated_stamp, not $cur_version" >&2; exit 1; }
        echo "  ok ($prev_version -> $cur_version: $(wc -l < "$tmp/fresh.shape" | tr -d ' ') columns match)"
    fi
fi
