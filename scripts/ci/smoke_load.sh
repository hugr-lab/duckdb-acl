#!/usr/bin/env bash
# The artifact must LOAD, not only compile (release plan 3.3): symbol visibility, a runtime
# dependency that resolved on the build machine only, an init that throws - all pass a build and fail
# the first user. So the built file is copied out of the tree and loaded by the CLI from a different
# working directory, as an operator would, and asked for a few of its own functions.
#
#   scripts/ci/smoke_load.sh [<extension file>] [<duckdb binary>]
set -euo pipefail
ext="${1:-build/release/extension/acl/acl.duckdb_extension}"
duckdb="${2:-build/release/duckdb}"
[ -f "$ext" ] || { echo "smoke_load: no extension at $ext" >&2; exit 1; }
[ -x "$duckdb" ] || { echo "smoke_load: no duckdb CLI at $duckdb" >&2; exit 1; }
ext_abs="$(cd "$(dirname "$ext")" && pwd)/$(basename "$ext")"
duckdb_abs="$(cd "$(dirname "$duckdb")" && pwd)/$(basename "$duckdb")"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
cp "$ext_abs" "$tmp/acl.duckdb_extension"
cd "$tmp"

out="$("$duckdb_abs" -unsigned -csv -noheader -c "
LOAD '$tmp/acl.duckdb_extension';
SELECT acl_drain_status();
SELECT count(*) FROM duckdb_functions() WHERE function_name LIKE 'acl_%';
SELECT current_setting('allow_parser_override_extension');
" 2>&1)" || { echo "smoke_load: the artifact did not load:" >&2; echo "$out" >&2; exit 1; }

status="$(sed -n '1p' <<<"$out")"
functions="$(sed -n '2p' <<<"$out")"
override="$(sed -n '3p' <<<"$out")"
[ "$status" = "serving" ] || { echo "smoke_load: acl_drain_status answered '$status'" >&2; echo "$out" >&2; exit 1; }
[ "${functions:-0}" -ge 60 ] || { echo "smoke_load: only $functions acl_* functions registered" >&2; exit 1; }
[ "$override" = "STRICT" ] || { echo "smoke_load: the override is '$override', not STRICT after LOAD" >&2; exit 1; }
echo "smoke_load: ok ($functions acl_* functions, override STRICT, size $(wc -c < "$ext_abs" | tr -d ' ') bytes)"
