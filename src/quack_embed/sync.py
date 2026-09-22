#!/usr/bin/env python3
"""Regenerate the acl-owned rename copies of quack server TUs (spec 063).

The embedded quack server (third_party/quack, pinned) reads a handful of `quack_*`
extension settings and drains client streams through a `scan_data_from_quack_client`
table function. For a clean co-load with a standalone quack (Strategy B, spec 063)
everything acl registers is `acl_quack_*`-named — so the embedded server must READ the
acl_-prefixed names. These few TUs carry those literals; this script copies them from
the submodule and rewrites ONLY those exact literals, leaving all logic untouched.

Run after bumping the `third_party/quack` submodule:  python3 src/quack_embed/sync.py
It overwrites src/quack_embed/<file> and fails loudly if an expected literal is gone
(upstream moved it — re-audit the read sites before trusting the rename).

duckdb carries patches for quack (`.github/patches/extensions/quack/`), applied to the loadable
client through APPLY_PATCHES; the embedded server is the same commit and must build against the
same duckdb, so the copies are taken from a scratch copy of the submodule's `src` with those
patches applied first — the two never diverge, and a patch that stops applying fails the sync.
PATCHES below are the embed's own: two calls around quack's statement driver - spec 074's profile
arming before the statement, spec 069's audit hook after it. (From 2026-09-17 to 2026-09-22 the
driver itself was ours, while duckdb ended a failing delegated query twice - #25887, fixed in #25978.)

The http server (acl_quack_http_server.cpp) is NOT generated here: it carries real
logic changes (TLS, /.well-known, public bind, registry) and is hand-maintained.
"""
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
SUB = ROOT / "third_party" / "quack" / "src"
OUT = ROOT / "src" / "quack_embed"
DUCKDB_PATCHES = ROOT / "duckdb" / ".github" / "patches" / "extensions" / "quack"

# Exact literal renames applied to every generated file. Setting names and the drain
# function name only — never a blanket quack_ -> acl_quack_ (that would corrupt error
# messages, wire tags and class-name strings).
RENAMES = {
    '"quack_authentication_function"': '"acl_quack_authentication_function"',
    '"quack_authorization_function"': '"acl_quack_authorization_function"',
    '"quack_prepare_inline_rows"': '"acl_quack_prepare_inline_rows"',
    '"quack_debug_emit_delay_ms"': '"acl_quack_debug_emit_delay_ms"',
    '"quack_target_batch_bytes"': '"acl_quack_target_batch_bytes"',
    '"quack_rebalance_buffer_bytes"': '"acl_quack_rebalance_buffer_bytes"',
    '"quack_fetch_producer_buffer_bytes"': '"acl_quack_fetch_producer_buffer_bytes"',
    '"quack_enable_reconnects"': '"acl_quack_enable_reconnects"',
    '"quack_cache_max_rows"': '"acl_quack_cache_max_rows"',
    '"quack_result_ttl"': '"acl_quack_result_ttl"',
    # bare token (unquoted): the drain name appears inside an "INSERT ... FROM <name>(%s)"
    # format string, in the function registration, and in error text — rename all, consistently.
    'scan_data_from_quack_client': 'acl_quack_scan_data',
}

# Exact-text patches applied after the renames: acl's own hooks into the server's logic, each
# guarded like a rename - an anchor that is gone fails the sync, so an upstream change of the
# patched site is re-audited rather than silently dropped. Keep these few and small.
PATCHES = {
    "quack_server.cpp": [
        (
            '#include "duckdb/main/client_config.hpp"\n',
            '#include "duckdb/main/client_config.hpp"\n'
            '#include "acl_quack_embed.hpp"\n',
        ),
        # The driver is quack's own: MakeQuackFetchCollector, delegated through get_result_collector,
        # carries the first result into the stream from the executor's own sink - parallel, and a full
        # buffer parks the producing TASK (backpressure without a thread held; the stream's capacity is
        # acl_quack_fetch_producer_buffer_bytes, at most a quarter of the memory limit). From duckdb
        # #25477 to #25978 (2026-09-17..22) a delegated submission that failed ended its query twice
        # (our #25887) and the driver was ours; since the fix it is quack's again, measured by
        # test/bench/door_stream.py (spec 063). What stays ours is two calls around the statement:
        # spec 074's profile arming before it (the profiler starts at plan), spec 069's audit hook
        # after it - the outcome of every statement the server drives, a client's streamed-insert
        # drain among them (an INSERT is not claimed by the collector: its count comes back through
        # the default sink, buffered since #25978).
        (
            "\t\tunique_ptr<QueryResult> result;\n"
            "\t\ttry {\n"
            "\t\t\tresult = connection.duckdb_connection->Query(sql);\n"
            "\t\t} catch (...) {\n"
            "\t\t\t// leave no collector hook on the connection's config\n"
            "\t\t\tconfig.get_result_collector = nullptr;\n"
            "\t\t\tthrow;\n"
            "\t\t}\n"
            "\t\tconfig.get_result_collector = nullptr;\n"
            "\t\tif (result->HasError()) {\n",
            "\t\t// acl (spec 074): whether this statement is profiled is decided before it runs\n"
            "\t\tacl::AclQuackStatementStarting(*connection.duckdb_connection, connection.session_id);\n"
            "\t\tunique_ptr<QueryResult> result;\n"
            "\t\ttry {\n"
            "\t\t\tresult = connection.duckdb_connection->Query(sql);\n"
            "\t\t} catch (...) {\n"
            "\t\t\t// leave no collector hook on the connection's config\n"
            "\t\t\tconfig.get_result_collector = nullptr;\n"
            "\t\t\tthrow;\n"
            "\t\t}\n"
            "\t\tconfig.get_result_collector = nullptr;\n"
            "\t\t// acl (spec 069): the outcome of every statement the server drives\n"
            "\t\tacl::AclQuackStatementCompleted(*connection.duckdb_connection, connection.session_id, sql, *result);\n"
            "\t\tif (result->HasError()) {\n",
        ),
    ],
}

# file -> the subset of RENAMES that MUST appear in it (guard against silent drift)
FILES = {
    "quack_server.cpp": [
        '"quack_authentication_function"', '"quack_authorization_function"',
        '"quack_prepare_inline_rows"', '"quack_fetch_producer_buffer_bytes"',
        'scan_data_from_quack_client',
    ],
    "quack_result_cache.cpp": [
        '"quack_enable_reconnects"', '"quack_cache_max_rows"', '"quack_result_ttl"',
    ],
    "quack_fetch_collector.cpp": ['"quack_debug_emit_delay_ms"'],
    "quack_rebalancer_sink.cpp": ['"quack_target_batch_bytes"', '"quack_rebalance_buffer_bytes"'],
    "quack_scan_from_client.cpp": ['"scan_data_from_quack_client"'],
}

BANNER = (
    "//===----------------------------------------------------------------------===//\n"
    "// GENERATED by src/quack_embed/sync.py from third_party/quack — DO NOT EDIT.\n"
    "// acl-owned rename copy (spec 063): the embedded quack server reads acl_quack_*\n"
    "// settings and drains through acl_quack_scan_data so a standalone quack can be\n"
    "// co-loaded without a registration clash. Regenerate after a submodule bump.\n"
    "//===----------------------------------------------------------------------===//\n"
)


def patched_source() -> pathlib.Path:
    """A scratch copy of the submodule's `src` with duckdb's quack patches applied (the caller removes it)."""
    patches = sorted(DUCKDB_PATCHES.glob("*.patch"))
    if not patches:
        # a copy made without them would compile against the wrong duckdb and pass the sync
        sys.exit(f"SYNC FAILED: no quack patches under {DUCKDB_PATCHES} - is the duckdb submodule checked out?")
    scratch = pathlib.Path(tempfile.mkdtemp(prefix="acl-quack-sync-"))
    shutil.copytree(SUB, scratch / "src")
    applied = 0
    for patch in patches:
        # the scratch holds quack's `src` only: a patch that touches nothing under it (a test of
        # quack's own, 0003 of 2026-09-22) is not ours to apply - skipped, and said so. A patch that
        # touches `src` and something else is applied to the part we carry, and must apply cleanly.
        targets = re.findall(r"^\+\+\+ b/(\S+)", patch.read_text(), flags=re.M)
        if targets and not any(t.startswith("src/") for t in targets):
            print(f"skipped {patch.relative_to(ROOT)} (touches only {', '.join(targets)})")
            continue
        subprocess.run(["patch", "-p1", "-s", "-N", "-d", str(scratch), "-i", str(patch)], check=True)
        print(f"applied {patch.relative_to(ROOT)}")
        applied += 1
    if applied == 0:
        sys.exit(f"SYNC FAILED: none of the patches under {DUCKDB_PATCHES} touches quack's src")
    return scratch / "src"


def main():
    failures = []
    source = patched_source()
    for name, required in FILES.items():
        src = source / name
        if not src.exists():
            failures.append(f"{name}: source missing at {src}")
            continue
        text = src.read_text()
        for lit in required:
            if lit not in text:
                failures.append(f"{name}: expected literal {lit} not found (upstream moved it?)")
        out = text
        for a, b in RENAMES.items():
            out = out.replace(a, b)
        for anchor, patched in PATCHES.get(name, []):
            if out.count(anchor) != 1:
                failures.append(f"{name}: patch anchor {anchor!r} found {out.count(anchor)} times, expected 1")
                continue
            out = out.replace(anchor, patched)
        dest = OUT / ("acl_embed_" + name[len("quack_"):] if name.startswith("quack_") else name)
        dest.write_text(BANNER + out)
        # quack is formatted with its own duckdb pin's .clang-format, which differs from ours just
        # enough that a few files fail the CI check. Normalise to OUR pinned clang-format (11.0.1) so
        # the generated files stay clean on every regeneration.
        if shutil.which("clang-format"):
            subprocess.run(["clang-format", "-i", str(dest)], check=True)
        print(f"generated {dest.relative_to(ROOT)}")
    shutil.rmtree(source.parent, ignore_errors=True)
    if failures:
        print("\nSYNC FAILED:", file=sys.stderr)
        for f in failures:
            print("  -", f, file=sys.stderr)
        sys.exit(1)
    print("ok")


if __name__ == "__main__":
    main()
