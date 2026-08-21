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
