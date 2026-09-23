//===----------------------------------------------------------------------===//
// acl_quack_fetch_window.hpp — the embedded door's fetch window (spec 077)
//
// A quack client keeps `quack_fetch_read_ahead` FETCHes in flight (0 = its async threads, 64 on a
// 16-core machine) and, when it stops early, waits for every one of them before it cancels - so one
// `LIMIT 1` costs the server that many full batches. The protocol has no way for a server to say
// "fewer" (duckdb-quack #277), so the window answers within it: at most the window's indices above
// the client's ack carry rows; a FETCH beyond that is answered at once with an EMPTY batch - one
// chunk of zero rows, which the client's scan skips - and the produced batches move to the indices
// after it. The client holds an answered FETCH's slot until its scan consumes it, so the empty
// answers cost a round trip per slot the consumer passes, never a loop.
//
// The window starts at `acl_quack_fetch_window` and doubles each time the client acknowledges a
// window's worth of batches with rows, up to `acl_quack_fetch_window_max` (0 = no cap): an early
// stop costs the start, while a long read reaches the client's own parallelism in a few windows
// (its scan decodes one batch per thread, so batches in flight, not bytes, set its speed).
//
// The plan is decided in index order, whatever order the FETCHes arrive in: a FETCH for index k
// decides every index up to k (all of them requested - the client asks densely), so the produced
// batch an index gets never depends on arrival, and the result keeps its order. The total the
// terminal answer announces counts the empty batches, and once one is announced no index is made
// empty, so the client's own check (every batch received) still holds.
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb/common/constants.hpp"
#include "duckdb/common/helper.hpp"
#include "duckdb/common/shared_ptr.hpp"
#include "duckdb/common/vector.hpp"

#include <map>

namespace duckdb {

class ClientContext;
class DatabaseInstance;
class MemoryStream;
struct QuackResultStream;

namespace acl {

//! The window a stream starts with: batches with rows a quack client may have above its ack
//! (0 = no window at all: quack's behaviour).
static constexpr idx_t ACL_QUACK_FETCH_WINDOW_DEFAULT = 8;
//! The most the window grows to (0 = no cap: as far as the client reads ahead).
static constexpr idx_t ACL_QUACK_FETCH_WINDOW_MAX_DEFAULT = 0;

//! Which answer each FETCH index gets. Indices are dense and count PREPARE's inline batches too (the
//! FETCH handler's `dense_index`). Not thread-safe: the caller holds the stream's serve_lock.
class AclFetchWindowPlan {
public:
	//! `start` 0 = no window; `max` 0 = no cap.
	AclFetchWindowPlan(idx_t start, idx_t max_p)
	    : width(max_p ? MinValue<idx_t>(start, max_p) : start), max(max_p), next_growth(width) {
	}

	enum class Kind : uint8_t {
		BATCH,  //! answered by the produced batch `source`
		EMPTY,  //! answered by an empty batch
		GONE,   //! decided and acknowledged long ago: no correct client asks for it again
		TOO_FAR //! further above the ack than any client reads ahead: refused, nothing decided
	};

	//! How far above its ack a FETCH may name an index. A quack client asks at most its read-ahead
	//! ahead (its async threads by default, one HTTP connection each); the plan decides every index
	//! up to the one named, so this bounds what one request can make it do.
	static constexpr idx_t MAX_AHEAD = 65536;
	struct Answer {
		Kind kind;
		idx_t source;
	};

	//! The answer for `index`. `ack`: the request's ack (dense); `first`: the batches PREPARE answered
	//! inline (a FETCH names first + 1 or later).
	Answer Decide(idx_t index, idx_t ack, idx_t first) {
		if (width == 0) {
			return Answer {Kind::BATCH, index};
		}
		if (decided < first) {
			decided = first;
		}
		if (ack > acked) {
			acked = ack;
			for (auto it = answers.begin(); it != answers.end() && it->first <= acked;) {
				if (it->second != EMPTY_MARK) {
					open_batches--;
					acked_batches++;
				}
				it = answers.erase(it);
			}
			// the client keeps reading: a window's worth acknowledged doubles it, up to the cap
			while (acked_batches >= next_growth && width < MAX_AHEAD && (max == 0 || width < max)) {
				width = max ? MinValue<idx_t>(width * 2, max) : width * 2;
				next_growth += width;
			}
		}
		if (index > MaxValue<idx_t>(acked, first) + MAX_AHEAD) {
			return Answer {Kind::TOO_FAR, 0};
		}
		while (decided < index) {
			auto next = decided + 1;
			if (!closed && open_batches >= width) {
				answers.emplace(next, EMPTY_MARK);
				empties++;
			} else {
				// the produced batches keep their order: each goes to the next index that carries rows
				answers.emplace(next, next - empties);
				open_batches++;
			}
			decided = next;
		}
		auto entry = answers.find(index);
		if (entry == answers.end()) {
			return Answer {Kind::GONE, 0};
		}
		if (entry->second == EMPTY_MARK) {
			return Answer {Kind::EMPTY, 0};
		}
		return Answer {Kind::BATCH, entry->second};
	}

	//! A terminal answer is being sent: its total counts EmptyBatches(), so no index is made empty
	//! after this (the rest of the produced batches go to the next indices, then the terminal again).
	void Close() {
		closed = true;
	}

	//! The empty batches decided so far. The client-visible total is the produced count plus these.
	idx_t EmptyBatches() const {
		return empties;
	}

	//! The window now.
	idx_t Width() const {
		return width;
	}

private:
	static constexpr idx_t EMPTY_MARK = DConstants::INVALID_INDEX;

	idx_t width;
	idx_t max;
	//! The acknowledged batches with rows at which the window doubles next.
	idx_t next_growth;
	idx_t acked_batches = 0;
	//! 1..decided have their answer.
	idx_t decided = 0;
	//! The highest ack seen: the client holds 1..acked and never asks for them again.
	idx_t acked = 0;
	idx_t empties = 0;
	bool closed = false;
	//! Indices above the ack that carry rows.
	idx_t open_batches = 0;
	//! The answers above the ack: the produced batch, or EMPTY_MARK.
	std::map<idx_t, idx_t> answers;
};

//! One stream's window: the plan, and the empty batch it answers with. Both are guarded by the
//! stream's serve_lock.
struct AclQuackFetchWindow {
	AclQuackFetchWindow(idx_t start, idx_t max) : plan(start, max) {
	}

	AclFetchWindowPlan plan;
	//! The wire form of one zero-row chunk of the stream's types, made at the first empty answer.
	vector<data_t> empty_blob;
};

//! The window of `stream` on a server connection (`context` is the session's). The stream's first
//! FETCH makes it, with the `acl_quack_fetch_window[_max]` in force then; it lives as long as the
//! stream. The seam where a profile per role or token (resource groups) would decide them.
shared_ptr<AclQuackFetchWindow>
AclQuackFetchWindowFor(ClientContext &context, const shared_ptr<QuackResultStream> &stream, DatabaseInstance &db);

//! A FETCH_RESPONSE payload of one zero-row chunk for the client's index `client_index`, its header
//! written the way the server writes a produced batch's; `body_start` is where the wire body starts.
shared_ptr<MemoryStream> AclQuackEmptyBatch(AclQuackFetchWindow &window, const QuackResultStream &stream,
                                            idx_t client_index, idx_t &body_start);

} // namespace acl
} // namespace duckdb
