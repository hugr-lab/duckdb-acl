// The embedded door's fetch window (spec 077): the plan that decides which FETCH index carries a
// produced batch and which is answered with an empty one. A quack client is simulated the way
// quack_fetch_ahead.cpp behaves - it asks densely, carries the contiguous prefix it received as its
// ack, holds a slot until its scan consumes the batch (a terminal answer frees it at once) and, on
// an early stop, waits for every FETCH in flight - while the server answers the requests, and the
// network delivers the answers, in a random order. What must hold whatever the order:
//
//   - the client reads every produced batch, once, in order, and its own check (the batches it
//     received against the total the terminal answer announced) passes;
//   - batches with rows in flight never exceed the window; an early stop costs at most the window it
//     starts with, a stop later at most the window then (the cap, for a fixed one);
//   - the window grows while the client reads: a long read stops paying empty round trips;
//   - the plan of the first burst does not depend on the order its FETCHes arrive in;
//   - a window of 0 is quack's behaviour (every index is its own batch).

#include "acl_test_util.hpp"

#include "acl_quack_fetch_window.hpp"

#include <algorithm>
#include <random>
#include <set>
#include <vector>

using namespace duckdb;
using namespace duckdb::acl;
using namespace acl_test;

namespace {

using Kind = AclFetchWindowPlan::Kind;

struct Outcome {
	std::vector<idx_t> consumed; // the produced batches the scan read, in its order
	idx_t pushed = 0;            // batches (with rows or empty) the client received
	idx_t expected_total = 0;    // what the terminal answer announced (0 = none)
	bool totals_agree = true;    // every terminal answer announced the same total
	bool within_window = true;   // answers with rows in flight never exceeded the window
	idx_t rows_after_stop = 0;   // answers with rows the client received after its scan stopped
	idx_t fetches = 0;
};

//! One stream: `first` batches went inline with PREPARE, `total` produced batches in all (dense).
//! The window starts at `start` and grows to `max` (0 = no cap). `stop_after`: the scan stops after
//! this many batches with rows (0 = reads to the end).
Outcome Run(idx_t depth, idx_t start, idx_t max, idx_t first, idx_t total, idx_t stop_after, uint32_t seed) {
	AclFetchWindowPlan plan(start, max);
	std::mt19937 rng(seed);
	Outcome out;

	// client
	idx_t next_request = 1, outstanding = 0, consume_at = 1;
	bool no_more = false, stopped = false;
	std::map<idx_t, idx_t> received; // client index -> produced batch (dense), or INVALID for empty
	std::set<idx_t> have;
	auto contiguous = [&]() {
		idx_t c = 0;
		while (have.count(c + 1)) {
			c++;
		}
		return c;
	};
	// the wire
	struct Request {
		idx_t index, ack;
	};
	struct Response {
		idx_t index;
		bool terminal;
		idx_t source; // INVALID = empty
		idx_t total;
	};
	std::vector<Request> requests;
	std::vector<Response> responses;

	auto rows_in_flight = [&]() {
		idx_t n = 0;
		for (auto &r : responses) {
			n += (!r.terminal && r.source != DConstants::INVALID_INDEX) ? 1 : 0;
		}
		return n;
	};

	auto top_up = [&]() {
		while (!no_more && !stopped && outstanding < depth) {
			requests.push_back(Request {next_request++, contiguous()});
			outstanding++;
			out.fetches++;
		}
	};
	for (idx_t step = 0; step < 10000000; step++) {
		top_up();
		// the scan consumes what is there, in index order, and each batch it frees is asked for again
		while (!stopped && received.count(consume_at)) {
			auto source = received[consume_at];
			received.erase(consume_at);
			outstanding--;
			consume_at++;
			if (source != DConstants::INVALID_INDEX) {
				out.consumed.push_back(source);
				if (stop_after && out.consumed.size() == stop_after) {
					stopped = true; // the LIMIT is met: no new FETCH; the ones in flight are waited for
				}
			}
		}
		top_up();
		if (requests.empty() && responses.empty()) {
			break;
		}
		// the server handles a request, or the network delivers an answer - in no particular order
		bool serve = !requests.empty() && (responses.empty() || rng() % 2 == 0);
		if (serve) {
			auto pick = rng() % requests.size();
			auto request = requests[pick];
			requests.erase(requests.begin() + static_cast<std::ptrdiff_t>(pick));
			auto answer = plan.Decide(request.index + first, request.ack + first, first);
			if (answer.kind == Kind::GONE || answer.kind == Kind::TOO_FAR) {
				Check(false, "a requested index is decided");
				return out;
			}
			Response response {request.index, false, DConstants::INVALID_INDEX, 0};
			if (answer.kind == Kind::BATCH) {
				if (answer.source > total) {
					plan.Close();
					response.terminal = true;
					response.total = total - first + plan.EmptyBatches();
				} else {
					response.source = answer.source;
				}
			}
			responses.push_back(response);
			if (start > 0 && rows_in_flight() > plan.Width()) {
				out.within_window = false;
			}
		} else {
			auto pick = rng() % responses.size();
			auto response = responses[pick];
			responses.erase(responses.begin() + static_cast<std::ptrdiff_t>(pick));
			if (response.terminal) {
				no_more = true;
				if (out.expected_total && out.expected_total != response.total) {
					out.totals_agree = false;
				}
				out.expected_total = response.total;
				outstanding--; // nothing entered the buffer: the slot is free at once
			} else {
				received[response.index] = response.source;
				have.insert(response.index);
				out.pushed++;
				if (stopped && response.source != DConstants::INVALID_INDEX) {
					out.rows_after_stop++;
				}
			}
		}
	}
	return out;
}

bool ReadsEverythingInOrder(const Outcome &out, idx_t first, idx_t total) {
	if (out.consumed.size() != total - first) {
		return false;
	}
	for (idx_t i = 0; i < out.consumed.size(); i++) {
		if (out.consumed[i] != first + 1 + i) {
			return false;
		}
	}
	return true;
}

} // namespace

int main() {
	return RunMain("the quack door's fetch window (spec 077)", [] {
		Scenario("every batch arrives once, in order, and the client's own count holds", [] {
			struct Shape {
				idx_t depth, start, max, first, total;
			};
			for (auto shape : std::vector<Shape> {{64, 8, 0, 0, 500},
			                                      {64, 8, 8, 0, 500},
			                                      {16, 2, 2, 3, 200},
			                                      {16, 2, 0, 3, 200},
			                                      {64, 8, 0, 1, 5},
			                                      {8, 8, 0, 0, 100},
			                                      {4, 16, 0, 0, 50},
			                                      {64, 1, 4, 2, 300},
			                                      {64, 0, 0, 2, 300},
			                                      {16, 2, 0, 0, 0},
			                                      {16, 2, 2, 4, 4}}) {
				for (uint32_t seed = 1; seed <= 40; seed++) {
					auto out = Run(shape.depth, shape.start, shape.max, shape.first, shape.total, 0, seed);
					auto what = "depth " + std::to_string(shape.depth) + ", window " + std::to_string(shape.start) +
					            ".." + std::to_string(shape.max) + ", " + std::to_string(shape.total) +
					            " batches, seed " + std::to_string(seed);
					if (!Check(ReadsEverythingInOrder(out, shape.first, shape.total), what + ": the rows, in order") ||
					    !Check(out.pushed == out.expected_total, what + ": received = announced total") ||
					    !Check(out.totals_agree, what + ": every terminal announces the same total") ||
					    !Check(out.within_window, what + ": rows in flight within the window")) {
						return;
					}
				}
			}
		});

		Scenario("an early stop costs at most the window", [] {
			for (uint32_t seed = 1; seed <= 40; seed++) {
				// LIMIT 1 over a big result: the window it starts with, ramp or not
				auto first = Run(64, 8, 0, 0, 100000, 1, seed);
				Check(first.consumed.size() == 1 && first.consumed[0] == 1, "LIMIT 1 reads the first batch");
				if (!Check(first.rows_after_stop <= 8, "LIMIT 1: at most the start arrives after the stop (" +
				                                           std::to_string(first.rows_after_stop) + ")")) {
					return;
				}
				// a fixed window (start = max) bounds a stop anywhere in the stream
				auto mid = Run(64, 8, 8, 0, 100000, 500, seed);
				if (!Check(mid.rows_after_stop <= 8, "a fixed window: a stop mid-stream costs at most it (" +
				                                         std::to_string(mid.rows_after_stop) + ")")) {
					return;
				}
				// a growing one bounds it by its cap
				auto capped = Run(64, 8, 16, 0, 100000, 500, seed);
				if (!Check(capped.rows_after_stop <= 16, "a window grown to its cap of 16: at most the cap (" +
				                                             std::to_string(capped.rows_after_stop) + ")")) {
					return;
				}
			}
			// without a window the same stop pulls the client's whole read-ahead
			auto quack = Run(64, 0, 0, 0, 100000, 1, 7);
			Check(quack.rows_after_stop > 8,
			      "window 0: the read-ahead arrives after the stop (" + std::to_string(quack.rows_after_stop) + ")");
		});

		Scenario("the window grows while the client reads", [] {
			// a fixed window of 2 against a read-ahead of 16: most answers are empty, all the way
			auto fixed = Run(16, 2, 2, 0, 2000, 0, 3);
			Check(fixed.fetches > 4 * 2000, "fixed window 2: about read-ahead / window FETCHes per batch (" +
			                                    std::to_string(fixed.fetches) + ")");
			// starting at 2 with no cap it outgrows the read-ahead in a few windows
			auto grown = Run(16, 2, 0, 0, 2000, 0, 3);
			Check(grown.fetches < 2000 + 200,
			      "growing window: the empty answers stop (" + std::to_string(grown.fetches) + " FETCHes)");
			AclFetchWindowPlan plan(2, 8);
			for (idx_t i = 1; i <= 40; i++) {
				plan.Decide(i, i - 1, 0);
			}
			Check(plan.Width() == 8, "the window stops at its cap (" + std::to_string(plan.Width()) + ")");
		});

		Scenario("the first burst's plan does not depend on arrival order", [] {
			std::vector<idx_t> order;
			for (idx_t i = 1; i <= 64; i++) {
				order.push_back(i);
			}
			std::vector<Kind> in_order;
			{
				AclFetchWindowPlan plan(8, 8);
				for (auto index : order) {
					in_order.push_back(plan.Decide(index, 0, 0).kind);
				}
			}
			std::mt19937 rng(11);
			for (int round = 0; round < 20; round++) {
				std::shuffle(order.begin(), order.end(), rng);
				AclFetchWindowPlan plan(8, 8);
				std::vector<Kind> kinds(64);
				std::vector<idx_t> sources(64);
				for (auto index : order) {
					auto answer = plan.Decide(index, 0, 0);
					kinds[index - 1] = answer.kind;
					sources[index - 1] = answer.source;
				}
				if (!Check(kinds == in_order, "shuffled burst: the same answers")) {
					return;
				}
				bool leading = true;
				for (idx_t i = 0; i < 8; i++) {
					leading = leading && kinds[i] == Kind::BATCH && sources[i] == i + 1;
				}
				if (!Check(leading, "the window's first 8 carry batches 1..8")) {
					return;
				}
			}
			Check(in_order[8] == Kind::EMPTY && in_order[63] == Kind::EMPTY, "past the window: empty");
		});

		Scenario("an acknowledged index is GONE, one too far ahead is refused, window 0 is quack's", [] {
			AclFetchWindowPlan plan(2, 2);
			plan.Decide(3, 0, 0);
			Check(plan.Decide(4, 3, 0).kind != Kind::GONE, "above the ack: decided");
			Check(plan.Decide(2, 3, 0).kind == Kind::GONE, "at or below the ack: GONE");
			// one request cannot make the plan decide a billion indices
			Check(plan.Decide(1000000000, 3, 0).kind == Kind::TOO_FAR, "far past the ack: refused");
			Check(plan.Decide(5, 3, 0).kind != Kind::TOO_FAR && plan.EmptyBatches() < 10,
			      "a refused request decided nothing");
			Check(plan.Decide(3 + AclFetchWindowPlan::MAX_AHEAD, 3, 0).kind != Kind::TOO_FAR,
			      "the read-ahead limit itself is allowed");
			AclFetchWindowPlan none(0, 0);
			bool identity = true;
			for (idx_t i = 1; i <= 100; i++) {
				auto answer = none.Decide(i, 0, 0);
				identity = identity && answer.kind == Kind::BATCH && answer.source == i;
			}
			Check(identity && none.EmptyBatches() == 0, "window 0: index i is batch i, never empty");
		});
	});
}
