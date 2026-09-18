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
PATCHES below are the embed's own: the statement driver (no delegated collector - duckdb #25477
ends a failing delegated query twice) with spec 069's audit hook inside it.

The http server (acl_quack_http_server.cpp) is NOT generated here: it carries real
logic changes (TLS, /.well-known, public bind, registry) and is hand-maintained.
"""
import pathlib
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
            '#include "duckdb/common/enums/result_eagerness.hpp"\n'
            '#include "duckdb/main/query_result_stream.hpp"\n'
            '#include "acl_quack_embed.hpp"\n',
        ),
        # duckdb #25477 (the unified QueryResult, our pin since 2026-09-17) and the delegated collector:
        # a submission that delegates its collector (get_result_collector set) and then FAILS ends the
        # query twice in duckdb - FailQueryInternal inside CompleteDelegatedInternal, then the "query
        # failed: abort now" branch of SubmitStatementInternal, whose own comment admits the query may
        # already be gone - a null dereference, an INTERNAL error, and with it the whole database
        # invalidated by nothing more than a principal's refused INSERT. quack's own pin of duckdb
        # predates the change and duckdb's CI does not run quack's tests, so the embed drives the
        # statement itself: submitted, its result drained through a QueryResultStream (a bounded
        # buffer, chunks released as they go out - the collector's memory profile, on the driver
        # thread); a text of several statements (the parser's implicit PIVOT) cannot be submitted and
        # runs through Query(), materialized. spec 069's audit hook rides the same site: the outcome
        # of every statement the server drives, the drain of a client's streamed insert among them.
        # The double end is reported upstream as duckdb #25887 (2026-09-18).
        (
            "\t\t// MakeQuackFetchCollector sends the FIRST statement that returns a result into the stream.\n"
            "\t\t// Every other statement keeps the default collector.\n"
            "\t\tauto &config = ClientConfig::GetConfig(context);\n"
            "\t\tconfig.get_result_collector = [stream](ClientContext &ctx, PreparedStatementData &data) {\n"
            "\t\t\treturn MakeQuackFetchCollector(ctx, data, stream);\n"
            "\t\t};\n"
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
            "\t\t// acl (duckdb #25477): no collector hook - a delegated submission that fails ends its query\n"
            "\t\t// twice in duckdb (INTERNAL, the database invalidated). The statement is submitted and its\n"
            "\t\t// result drained here through a QueryResultStream; several statements at once (the\n"
            "\t\t// parser's implicit PIVOT) cannot be submitted and run through Query(), materialized.\n"
            "\t\tunique_ptr<QueryResult> result = connection.duckdb_connection->Submit(sql);\n"
            "\t\tif (result->HasError() && result->GetError().find(\"multiple statements\") != string::npos) {\n"
            "\t\t\tresult = connection.duckdb_connection->Query(sql);\n"
            "\t\t}\n"
            "\t\tif (!result->HasError() && result->GetStatementProperties().return_type == StatementReturnType::QUERY_RESULT &&\n"
            "\t\t    result->GetStatementProperties().result_eagerness != ResultEagerness::FORCED && result->HasBufferedData()) {\n"
            "\t\t\t// the stream carries this statement: its shape is known at submission, its chunks go\n"
            "\t\t\t// out in batches of about the target size as duckdb produces them\n"
            "\t\t\tvector<string> result_names;\n"
            "\t\t\tfor (auto &col_name : result->GetNames()) {\n"
            "\t\t\t\tresult_names.push_back(col_name.GetIdentifierName());\n"
            "\t\t\t}\n"
            "\t\t\tauto types = result->GetTypes();\n"
            "\t\t\tQueryResultStream reader(std::move(result));\n"
            "\t\t\tstream->SignalBound(types, std::move(result_names));\n"
            "\t\t\tauto target_bytes = MaxValue<idx_t>(\n"
            "\t\t\t    1, QuackGetUBigintSetting(context, \"acl_quack_target_batch_bytes\", QUACK_TARGET_BATCH_BYTES_DEFAULT));\n"
            "\t\t\tunique_ptr<QuackChunkPayloadWriter> writer;\n"
            "\t\t\tidx_t batch_index = 1;\n"
            "\t\t\tidx_t rows = 0;\n"
            "\t\t\tidx_t last_size = 0;\n"
            "\t\t\tauto flush = [&]() {\n"
            "\t\t\t\tif (!writer) {\n"
            "\t\t\t\t\treturn;\n"
            "\t\t\t\t}\n"
            "\t\t\t\tauto sealed = writer->Seal();\n"
            "\t\t\t\tQuackFetchPayload entry;\n"
            "\t\t\t\tentry.payload = std::move(sealed.payload);\n"
            "\t\t\t\tentry.payload_size = sealed.payload_size;\n"
            "\t\t\t\tentry.chunk_count = sealed.chunk_count;\n"
            "\t\t\t\tentry.rows = rows;\n"
            "\t\t\t\tlast_size = entry.payload_size;\n"
            "\t\t\t\tauto bytes = entry.payload_size;\n"
            "\t\t\t\tstream->buffer.PushBatch(batch_index++, std::move(entry), bytes);\n"
            "\t\t\t\twriter.reset();\n"
            "\t\t\t\trows = 0;\n"
            "\t\t\t};\n"
            "\t\t\twhile (auto chunk = reader.Fetch()) {\n"
            "\t\t\t\tif (chunk->size() == 0) {\n"
            "\t\t\t\t\tcontinue;\n"
            "\t\t\t\t}\n"
            "\t\t\t\tif (!writer) {\n"
            "\t\t\t\t\twriter = make_uniq<QuackChunkPayloadWriter>(last_size);\n"
            "\t\t\t\t}\n"
            "\t\t\t\twriter->AppendChunk(*chunk);\n"
            "\t\t\t\trows += chunk->size();\n"
            "\t\t\t\tif (writer->AllocatedBytes() >= target_bytes) {\n"
            "\t\t\t\t\tflush();\n"
            "\t\t\t\t}\n"
            "\t\t\t}\n"
            "\t\t\tif (reader.HasError()) {\n"
            "\t\t\t\tresult = make_uniq<QueryResult>(reader.GetErrorObject());\n"
            "\t\t\t} else {\n"
            "\t\t\t\tflush();\n"
            "\t\t\t\tstream->announced_total = batch_index - 1;\n"
            "\t\t\t\t// a stand-in for the handle the stream consumed: successful, empty, bound already\n"
            "\t\t\t\tresult = make_uniq<QueryResult>(StatementType::SELECT_STATEMENT, StatementProperties(), vector<Identifier>(),\n"
            "\t\t\t\t                                make_uniq<ColumnDataCollection>(Allocator::DefaultAllocator()),\n"
            "\t\t\t\t                                context.GetClientProperties());\n"
            "\t\t\t}\n"
            "\t\t}\n"
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
    for patch in patches:
        subprocess.run(["patch", "-p1", "-s", "-N", "-d", str(scratch), "-i", str(patch)], check=True)
        print(f"applied {patch.relative_to(ROOT)}")
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
