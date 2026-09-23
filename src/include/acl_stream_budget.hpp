//===----------------------------------------------------------------------===//
// acl_stream_budget.hpp — the node's budget for the memory its streams hold (spec 080)
//
// A quack statement's stream buffers what it produces until the client fetches it - the producer
// buffer, the batches in flight, the producer threads' fragments - in memory duckdb's buffer manager
// does not govern. Nothing bounded the sum: a node full of clients could run out of memory for all
// of them at once. The budget reserves a stream's worst case while its producer runs, admits in
// arrival order, and makes a statement that finds it full WAIT - a sticky session's next statement
// waits on its node for capacity - up to a timeout, then fail with the reason.
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb/common/common.hpp"
#include "duckdb/common/mutex.hpp"

#include <chrono>
#include <condition_variable>
#include <functional>

namespace duckdb {
namespace acl {

class StreamBudget {
public:
	//! Wait, in arrival order, until `bytes` fit under `budget` (0 = no budget) or `timeout` passes.
	//! A stream that alone exceeds the budget is admitted once nothing else is reserved - it must
	//! run eventually. `interrupted` is polled while waiting (the client went away). True when
	//! reserved; false on the timeout (counted as refused). Throws nothing of its own.
	bool Acquire(idx_t bytes, idx_t budget, std::chrono::milliseconds timeout, const std::function<bool()> &interrupted,
	             bool &was_interrupted);
	void Release(idx_t bytes);

	struct Snapshot {
		idx_t reserved = 0;
		idx_t producing = 0;
		idx_t queued = 0;
		int64_t refused = 0;
	};
	Snapshot Now() const;

private:
	mutable mutex lock;
	std::condition_variable cv;
	idx_t reserved = 0;
	idx_t producing = 0;
	idx_t queued = 0;
	int64_t refused = 0;
	uint64_t next_ticket = 0;
	uint64_t serving = 0;
	//! Tickets that gave up behind the head: passed over when their turn comes
	vector<uint64_t> abandoned;
	void SkipAbandoned();
};

// header-only, so the invariant test compiles it on its own (test/cpp/test_acl_stream_budget.cpp)
inline bool StreamBudget::Acquire(idx_t bytes, idx_t budget, std::chrono::milliseconds timeout,
                                  const std::function<bool()> &interrupted, bool &was_interrupted) {
	was_interrupted = false;
	std::unique_lock<std::mutex> guard(lock);
	auto ticket = next_ticket++;
	queued++;
	auto deadline = std::chrono::steady_clock::now() + timeout;
	auto fits = [&]() {
		return serving == ticket && (budget == 0 || reserved == 0 || reserved + bytes <= budget);
	};
	while (!fits()) {
		if (interrupted && interrupted()) {
			was_interrupted = true;
			break;
		}
		if (std::chrono::steady_clock::now() >= deadline) {
			break;
		}
		cv.wait_for(guard, std::chrono::milliseconds(100));
	}
	queued--;
	if (!fits()) {
		// leaving the line: if this was its head, the next ticket is served now
		if (serving == ticket) {
			serving++;
		} else {
			// a ticket behind the head gives up: mark it so the head skips over it when it gets there.
			// Tickets are served in order, so an abandoned one is simply passed: remember it.
			abandoned.push_back(ticket);
		}
		SkipAbandoned();
		if (!was_interrupted) {
			refused++;
		}
		cv.notify_all();
		return false;
	}
	serving++;
	SkipAbandoned();
	reserved += bytes;
	producing++;
	cv.notify_all();
	return true;
}

inline void StreamBudget::SkipAbandoned() {
	for (bool moved = true; moved;) {
		moved = false;
		for (auto it = abandoned.begin(); it != abandoned.end(); ++it) {
			if (*it == serving) {
				serving++;
				abandoned.erase(it);
				moved = true;
				break;
			}
		}
	}
}

inline void StreamBudget::Release(idx_t bytes) {
	{
		lock_guard<mutex> guard(lock);
		reserved = reserved >= bytes ? reserved - bytes : 0;
		if (producing > 0) {
			producing--;
		}
	}
	cv.notify_all();
}

inline StreamBudget::Snapshot StreamBudget::Now() const {
	lock_guard<mutex> guard(lock);
	Snapshot now;
	now.reserved = reserved;
	now.producing = producing;
	now.queued = queued;
	now.refused = refused;
	return now;
}

} // namespace acl
} // namespace duckdb
