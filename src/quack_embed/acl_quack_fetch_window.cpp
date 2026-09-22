//===----------------------------------------------------------------------===//
// acl_quack_fetch_window.cpp — the embedded door's fetch window (spec 077)
//
// The plan is header-only (acl_quack_fetch_window.hpp, tested on its own); this is what ties it to
// quack's server: a window per result stream, found by the FETCH handler (a sync.py patch of the
// generated server), and the empty batch it answers with.
//===----------------------------------------------------------------------===//

#include "acl_quack_fetch_window.hpp"

#include "duckdb/common/serializer/binary_serializer.hpp"
#include "duckdb/common/serializer/memory_stream.hpp"
#include "duckdb/common/types/data_chunk.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/client_context_state.hpp"

#include "quack_fetch_collector.hpp"
#include "quack_message.hpp"
#include "quack_rebalancer_sink.hpp"

namespace duckdb {
namespace acl {

namespace {

//! The windows of one server connection's streams. A connection runs one statement at a time, but a
//! superseded stream's FETCH can still be in its handler, so a stream is found by identity, never by
//! "the current one"; a window goes when its stream does.
class AclQuackFetchWindows : public ClientContextState {
public:
	shared_ptr<AclQuackFetchWindow> For(const shared_ptr<QuackResultStream> &stream, idx_t start, idx_t max) {
		lock_guard<mutex> guard(lock);
		shared_ptr<AclQuackFetchWindow> found;
		for (auto entry = windows.begin(); entry != windows.end();) {
			auto held = entry->first.lock();
			if (!held) {
				entry = windows.erase(entry);
				continue;
			}
			if (held.get() == stream.get()) {
				found = entry->second;
			}
			++entry;
		}
		if (!found) {
			found = make_shared_ptr<AclQuackFetchWindow>(start, max);
			windows.emplace_back(weak_ptr<QuackResultStream>(stream), found);
		}
		return found;
	}

private:
	mutex lock;
	vector<std::pair<weak_ptr<QuackResultStream>, shared_ptr<AclQuackFetchWindow>>> windows;
};

//! quack's wire options (QuackWireSerializationOptions in quack_message.cpp, file-static there): the
//! empty batch is a chunk blob like any other. sync.py fails if quack's definition changes.
SerializationOptions WireOptions() {
	SerializationOptions options;
	options.storage_compatibility = StorageCompatibility::FromIndex(StorageVersion::V2_0_0);
	return options;
}

} // namespace

shared_ptr<AclQuackFetchWindow>
AclQuackFetchWindowFor(ClientContext &context, const shared_ptr<QuackResultStream> &stream, DatabaseInstance &db) {
	auto start = QuackGetUBigintSetting(db, "acl_quack_fetch_window", ACL_QUACK_FETCH_WINDOW_DEFAULT);
	auto max = QuackGetUBigintSetting(db, "acl_quack_fetch_window_max", ACL_QUACK_FETCH_WINDOW_MAX_DEFAULT);
	// the types are written when the statement binds (under the stream's bind lock, which Bound()
	// takes); a stream that is not bound yet - a drain waiting for the client's data - or has no
	// columns answers one count, and gets no window
	if (!stream->Bound() || stream->types.empty()) {
		start = 0;
	}
	auto windows = context.registered_state->GetOrCreate<AclQuackFetchWindows>("acl_quack_fetch_windows");
	return windows->For(stream, start, max);
}

shared_ptr<MemoryStream> AclQuackEmptyBatch(AclQuackFetchWindow &window, const QuackResultStream &stream,
                                            idx_t client_index, idx_t &body_start) {
	if (window.empty_blob.empty()) {
		// QuackChunkPayloadWriter::AppendChunk wants rows, so the one chunk is written the way it writes one
		DataChunk chunk;
		chunk.Initialize(Allocator::DefaultAllocator(), stream.types, 1);
		MemoryStream blob;
		BinarySerializer serializer(blob, WireOptions());
		serializer.Begin();
		chunk.Serialize(serializer);
		serializer.End();
		window.empty_blob.assign(blob.GetData(), blob.GetData() + blob.GetPosition());
	}
	auto payload = make_shared_ptr<MemoryStream>(Allocator::DefaultAllocator(),
	                                             QUACK_PAYLOAD_HEADER_BYTES + window.empty_blob.size());
	payload->SetPosition(QUACK_PAYLOAD_HEADER_BYTES);
	payload->WriteData(window.empty_blob.data(), window.empty_blob.size());
	FetchResponseMessage header_message;
	header_message.SetChunkCount(1);
	header_message.SetBatchIndex(client_index);
	body_start = QuackPrependHeader(*payload, header_message);
	return payload;
}

} // namespace acl
} // namespace duckdb
