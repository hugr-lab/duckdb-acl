//===----------------------------------------------------------------------===//
// acl_stream_budget.hpp — the node's budget for the memory its streams hold (spec 080)
//
// A quack statement's stream buffers what it produces until the client fetches it - the producer
// buffer, the batches in flight, the producer threads' fragments - in memory duckdb's buffer manager
// does not govern. Nothing bounded the sum: a node full of clients could run out of memory for all
// of them at once. The budget reserves a stream's worst case while its producer runs, admits by
// priority then arrival (spec 085), and makes a statement that finds it full WAIT - a sticky session's next statement
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
	//! Wait until `bytes` fit under `budget` (0 = no budget) or `timeout` passes. The line is ordered by
	//! priority, then arrival (spec 085: a resource group's `queue_priority`); a waiting statement gains
	//! one level per `age_step` it has waited, so no priority starves another past the timeout. A
	//! stream that alone exceeds the budget is admitted once nothing else is reserved - it must run
	//! eventually. `interrupted` is polled while waiting (the client went away). True when reserved;
	//! false on the timeout (counted as refused). Throws nothing of its own.
	bool Acquire(idx_t bytes, idx_t budget, std::chrono::milliseconds timeout, const std::function<bool()> &interrupted,
	             bool &was_interrupted, int64_t priority = 0);
	void Release(idx_t bytes);

	struct Snapshot {
		idx_t reserved = 0;
		idx_t producing = 0;
		idx_t queued = 0;
		int64_t refused = 0;
	};
	Snapshot Now() const;

	//! How long a waiting statement takes to gain one priority level (spec 085); a test shortens it
	std::chrono::milliseconds age_step {5000};

private:
	struct Waiter {
		uint64_t ticket;
		int64_t priority;
		std::chrono::steady_clock::time_point arrived;
	};
	mutable mutex lock;
	std::condition_variable cv;
	idx_t reserved = 0;
	idx_t producing = 0;
	int64_t refused = 0;
	uint64_t next_ticket = 0;
	vector<Waiter> waiting;
	//! The ticket served next: the highest priority after aging, the earliest arrival among equals
	uint64_t HeadLocked(std::chrono::steady_clock::time_point now) const;
	void LeaveLocked(uint64_t ticket);
};

// header-only, so the invariant test compiles it on its own (test/cpp/test_acl_stream_budget.cpp)
inline uint64_t StreamBudget::HeadLocked(std::chrono::steady_clock::time_point now) const {
	uint64_t head = 0;
	int64_t best = 0;
	bool any = false;
	for (auto &waiter : waiting) {
		auto waited = std::chrono::duration_cast<std::chrono::milliseconds>(now - waiter.arrived).count();
		auto step = age_step.count() > 0 ? age_step.count() : 1;
		auto effective = waiter.priority + waited / step;
		if (!any || effective > best || (effective == best && waiter.ticket < head)) {
			head = waiter.ticket;
			best = effective;
			any = true;
		}
	}
	return head;
}

inline void StreamBudget::LeaveLocked(uint64_t ticket) {
	for (auto it = waiting.begin(); it != waiting.end(); ++it) {
		if (it->ticket == ticket) {
			waiting.erase(it);
			return;
		}
	}
}

inline bool StreamBudget::Acquire(idx_t bytes, idx_t budget, std::chrono::milliseconds timeout,
                                  const std::function<bool()> &interrupted, bool &was_interrupted, int64_t priority) {
	was_interrupted = false;
	std::unique_lock<std::mutex> guard(lock);
	auto ticket = next_ticket++;
	auto arrived = std::chrono::steady_clock::now();
	waiting.push_back(Waiter {ticket, priority, arrived});
	auto deadline = arrived + timeout;
	auto fits = [&]() {
		return HeadLocked(std::chrono::steady_clock::now()) == ticket &&
		       (budget == 0 || reserved == 0 || reserved + bytes <= budget);
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
	if (!fits()) {
		// leaving the line: whoever is its head now is served next
		LeaveLocked(ticket);
		if (!was_interrupted) {
			refused++;
		}
		cv.notify_all();
		return false;
	}
	LeaveLocked(ticket);
	reserved += bytes;
	producing++;
	cv.notify_all();
	return true;
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
	now.queued = waiting.size();
	now.refused = refused;
	return now;
}

} // namespace acl
} // namespace duckdb
