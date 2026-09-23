//===----------------------------------------------------------------------===//
// acl_quack_fetch_window.hpp — the embedded door's fetch window (spec 077)
//
// A quack client keeps `quack_fetch_read_ahead` FETCHes in flight (0 = its async threads, 64 on a
// 16-core machine) and, when it stops early, waits for every one of them before it cancels - so one
// `LIMIT 1` costs the server that many full batches. The protocol has no way for a server to say
// "fewer" (duckdb-quack #277), so the window answers within it: at most the window's indices above
// the client's ack carry rows; a FETCH beyond that is answered at once with an EMPTY batch - one
// chunk of zero rows, which the client's scan skips - and the produced batches move to the indices
// after it.
//
// An empty answer is HELD while a batch with rows below it is not yet acknowledged. The client's scan
// threads each claim their own index: a thread holding an empty index would consume it, free its slot
// and ask again - and with the ack stuck below the batch still on its way, every new index is empty
// too, so the client would spin FETCHes for as long as that batch takes (a sort before its first
// batch: seconds; past MAX_AHEAD the query fails). Two holds, neither waiting on the client alone:
//   - PRODUCTION: a batch with rows below is not yet answered (being produced). Released by the
//     server's own progress - the batch is answered when it exists.
//   - ACKNOWLEDGEMENT: the batches below are answered but not acknowledged (in transit, or the
//     client stopped). Released by the ack a reading client sends as soon as it consumes the batch,
//     or after a time: a client that stopped early sends no more FETCHes and waits for these answers
//     before it cancels, so the hold must end by itself. The time starts at ACK_HOLD_MS and doubles
//     (to ACK_HOLD_MAX_MS) each time a hold runs out with the ack still stuck - a client starved of
//     CPU, receiving slowly - and the next ack that moves resets it.
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
#include <set>

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
	//! How long an empty answer waits for the acknowledgement of the batches below it, at first ...
	static constexpr uint64_t ACK_HOLD_MS = 20;
	//! ... and at most, after holds ran out with the ack stuck.
	static constexpr uint64_t ACK_HOLD_MAX_MS = 500;

	enum class Hold : uint8_t {
		NONE,           //! answer it now
		PRODUCTION,     //! a batch with rows below is still being produced
		ACKNOWLEDGEMENT //! the batches below are answered, not yet acknowledged
	};
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
			ack_hold_ms = ACK_HOLD_MS; // the client is receiving: holds are short again
			for (auto it = answers.begin(); it != answers.end() && it->first <= acked;) {
				if (it->second != EMPTY_MARK) {
					open_real.erase(it->first);
					acked_batches++;
					unanswered.erase(it->first);
				}
				held_since.erase(it->first);
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
			if (!closed && open_real.size() >= width) {
				answers.emplace(next, EMPTY_MARK);
				empties++;
			} else {
				// the produced batches keep their order: each goes to the next index that carries rows
				answers.emplace(next, next - empties);
				open_real.insert(next);
				unanswered.insert(next);
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

	//! The index carrying rows has been answered: its batch served, or the terminal sent.
	void Answered(idx_t index) {
		unanswered.erase(index);
	}

	//! Whether an EMPTY index may be answered now (`now_ms` on any monotonic clock).
	Hold EmptyHold(idx_t index, uint64_t now_ms) {
		if (open_real.empty() || *open_real.begin() > index) {
			held_since.erase(index);
			return Hold::NONE; // every batch with rows below it is acknowledged
		}
		if (!unanswered.empty() && *unanswered.begin() < index) {
			return Hold::PRODUCTION;
		}
		// the hold's length is fixed when it starts, so the indices held together are released together
		auto held = held_since.emplace(index, std::make_pair(now_ms, ack_hold_ms)).first->second;
		if (now_ms >= held.first + held.second) {
			held_since.erase(index);
			// it ran out with the ack stuck: the next holds wait longer
			ack_hold_ms = MinValue<uint64_t>(held.second * 2, ACK_HOLD_MAX_MS);
			return Hold::NONE;
		}
		return Hold::ACKNOWLEDGEMENT;
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
	std::set<idx_t> open_real;
	//! The answers above the ack: the produced batch, or EMPTY_MARK.
	std::map<idx_t, idx_t> answers;
	//! Indices carrying rows that are decided and not yet answered.
	std::set<idx_t> unanswered;
	//! When an EMPTY index was first held for an acknowledgement, and for how long.
	std::map<idx_t, std::pair<uint64_t, uint64_t>> held_since;
	uint64_t ack_hold_ms = ACK_HOLD_MS;
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

//! Whether the EMPTY `dense_index` of `stream` may be answered now: the plan's EmptyHold on the steady
//! clock, held after the producer is done too (the batches below may still be in transit), where a
//! PRODUCTION hold becomes a poll (ACKNOWLEDGEMENT) since a finished buffer wakes nobody. Under the
//! stream's serve_lock.
AclFetchWindowPlan::Hold AclQuackEmptyHold(AclQuackFetchWindow &window, QuackResultStream &stream, idx_t dense_index);

//! A FETCH_RESPONSE payload of one zero-row chunk for the client's index `client_index`, its header
//! written the way the server writes a produced batch's; `body_start` is where the wire body starts.
shared_ptr<MemoryStream> AclQuackEmptyBatch(AclQuackFetchWindow &window, const QuackResultStream &stream,
                                            idx_t client_index, idx_t &body_start);

} // namespace acl
} // namespace duckdb
