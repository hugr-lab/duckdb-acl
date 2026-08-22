#!/usr/bin/env bash
# Does the built extension link anything from outside its own vcpkg tree? (specs/045)
#
# The ACL_FLIGHT build pulls Arrow, gRPC and their dependencies, and several of those are resolved by
# Arrow's own CMake modules rather than ours - FindOpenSSLAlt.cmake on macOS literally shells out to
# `brew`. So "we told CMake where to look" is not evidence; this is. Run after an ACL_FLIGHT=1 build.
#
# Allowed: the OS itself. Everything else - a homebrew dylib, a /usr/local library, anything the
# machine happened to carry - is a build that would behave differently on the next machine.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ARTIFACT="${1:-$ROOT/build/release/extension/acl/acl.duckdb_extension}"

[ -f "$ARTIFACT" ] || { echo "SKIP: no artifact at $ARTIFACT"; exit 0; }

case "$(uname -s)" in
Darwin) LINKED="$(otool -L "$ARTIFACT" | tail -n +2 | awk '{print $1}')" ;;
Linux)  LINKED="$(objdump -p "$ARTIFACT" | awk '/NEEDED/ {print $2}')" ;;
*)      echo "SKIP: no way to read link dependencies on $(uname -s)"; exit 0 ;;
esac

# The OS, and the artifact's own id. Anything else has to come from the vcpkg tree, which means it is
# linked statically and does not appear here at all.
STRAYS="$(echo "$LINKED" | grep -vE '^(/usr/lib/|/System/Library/|@rpath/acl\.duckdb_extension$|lib(c|m|dl|pthread|rt|stdc\+\+|gcc_s|resolv)\.so)' || true)"

if [ -n "$STRAYS" ]; then
	echo "FAIL: the extension links libraries from outside its vcpkg tree:" >&2
	echo "$STRAYS" | sed 's/^/  /' >&2
	echo "" >&2
	echo "Each of these was resolved from the machine rather than from the build, so this artifact" >&2
	echo "would differ on another machine - and on a machine without them it would not load at all." >&2
	exit 1
fi

echo "PASS: the extension links only the OS ($(echo "$LINKED" | wc -l | tr -d ' ') entries checked)"
