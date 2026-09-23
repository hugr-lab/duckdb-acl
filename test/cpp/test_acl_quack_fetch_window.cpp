// The embedded door's fetch window (spec 077): the plan that decides which FETCH index carries a
// produced batch and which is answered with an empty one. A quack client is simulated the way
// quack_fetch_ahead.cpp and quack_scan.cpp behave - it asks densely, carries the contiguous prefix it
// received as its ack, holds a slot until a scan thread consumes the batch (a terminal answer frees it
// at once), its scan threads each claim their own index, and on an early stop it waits for every FETCH
// in flight - while the producer makes batches at its own pace, the server answers what it can, and
// the network delivers, in a random order. What must hold whatever the order:
//
//   - the client reads every produced batch, once, in order, and its own check (the batches it
//     received against the total the terminal answer announced) passes;
//   - batches with rows in flight never exceed the window; an early stop costs at most the window it
//     starts with, a stop later at most the window then (the cap, for a fixed one);
//   - the window grows while the client reads: a long read stops paying empty round trips;
//   - a slow producer, a slow network and a parallel scan do not spin: an empty answer waits while a
//     batch with rows below it is being produced, then for its acknowledgement, a bounded time
//     (without that hold the client loops on empty FETCHes);
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
constexpr idx_t NONE = DConstants::INVALID_INDEX;

struct Sim {
	idx_t depth = 64;        // the client's read-ahead
	idx_t start = 8;         // acl_quack_fetch_window
	idx_t max = 0;           // acl_quack_fetch_window_max
	idx_t first = 0;         // batches PREPARE answered inline
	idx_t total = 500;       // produced batches in all (dense)
	idx_t stop_after = 0;    // the scan stops after this many batches with rows (0 = reads to the end)
	idx_t threads = 1;       // scan threads, each with its own claimed index
	idx_t produce_every = 0; // steps per produced batch (0 = everything is produced at once)
	bool hold = true;        // the server holds an empty answer below an unacknowledged batch with rows
	idx_t shed_every = 0;    // the server drops every Nth request it takes (a full worker pool), and
	idx_t retry_after = 300; // the client sends it again this many steps later
	uint32_t seed = 1;
};

struct Outcome {
	std::vector<std::pair<idx_t, idx_t>> consumed; // (client index, produced batch) of every batch with rows
	idx_t pushed = 0;                              // batches (with rows or empty) the client received
	idx_t expected_total = 0;                      // what the terminal answer announced (0 = none)
	bool totals_agree = true;                      // every terminal answer announced the same total
	bool within_window = true;                     // answers with rows in flight never exceeded the window
	bool refused = false;                          // the plan refused a request (GONE / TOO_FAR)
	idx_t rows_after_stop = 0;                     // answers with rows the client received after its stop
	idx_t fetches = 0;
};

Outcome Run(const Sim &sim) {
	AclFetchWindowPlan plan(sim.start, sim.max);
	std::mt19937 rng(sim.seed);
	Outcome out;
	idx_t produced = sim.produce_every ? sim.first : sim.total;

	// client
	idx_t next_request = 1, outstanding = 0, next_claim = 1;
	bool no_more = false, stopped = false;
	std::map<idx_t, idx_t> received; // client index -> produced batch (dense), or NONE for empty
	std::set<idx_t> have;
	std::vector<idx_t> claims(sim.threads, NONE);
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
		idx_t ready_at = 0; // a shed request comes back at this step
	};
	struct Response {
		idx_t index;
		bool terminal;
		idx_t source; // NONE = empty
		idx_t total;
	};
	std::vector<Request> requests;
	std::vector<Response> responses;

	auto rows_in_flight = [&]() {
		idx_t n = 0;
		for (auto &r : responses) {
			n += (!r.terminal && r.source != NONE) ? 1 : 0;
		}
		return n;
	};
	auto top_up = [&]() {
		while (!no_more && !stopped && outstanding < sim.depth) {
			requests.push_back(Request {next_request++, contiguous(), 0});
			outstanding++;
			out.fetches++;
		}
	};
	// each scan thread consumes its claimed index when it is there, then claims the next
	auto consume = [&]() {
		bool progressed = true;
		while (progressed && !stopped) {
			progressed = false;
			for (auto &claim : claims) {
				if (stopped) {
					break;
				}
				if (claim == NONE) {
					claim = next_claim++;
				}
				auto entry = received.find(claim);
				if (entry == received.end()) {
					continue;
				}
				auto source = entry->second;
				received.erase(entry);
				outstanding--;
				if (source != NONE) {
					out.consumed.emplace_back(claim, source);
					if (sim.stop_after && out.consumed.size() == sim.stop_after) {
						stopped = true; // the LIMIT is met: no new FETCH; the ones in flight are waited for
					}
				}
				claim = NONE;
				progressed = true;
			}
		}
	};

	idx_t taken = 0;
	for (idx_t step = 0; step < 4000000; step++) {
		if (sim.produce_every && step % sim.produce_every == 0 && produced < sim.total) {
			produced++;
		}
		bool producer_done = produced == sim.total;
		top_up();
		consume();
		top_up();
		if (requests.empty() && responses.empty()) {
			break;
		}
		// the server answers a request it can answer, or the network delivers - in no particular order
		bool served = false;
		if (!requests.empty() && (responses.empty() || rng() % 2 == 0)) {
			auto offset = rng() % requests.size();
			for (idx_t n = 0; n < requests.size() && !served; n++) {
				auto pick = (offset + n) % requests.size();
				auto request = requests[pick];
				if (request.ready_at > step) {
					continue; // shed: the client has not sent it again yet
				}
				if (sim.shed_every && ++taken % sim.shed_every == 0) {
					requests[pick].ready_at = step + sim.retry_after; // dropped before the handler saw it
					served = true;
					break;
				}
				auto dense = request.index + sim.first;
				auto answer = plan.Decide(dense, request.ack + sim.first, sim.first);
				if (answer.kind == Kind::GONE || answer.kind == Kind::TOO_FAR) {
					out.refused = true;
					return out;
				}
				Response response {request.index, false, NONE, 0};
				if (answer.kind == Kind::EMPTY) {
					// the server's hold, with the step count for its clock (ACK_HOLD_MS steps)
					if (sim.hold && !producer_done && plan.EmptyHold(dense, step) != AclFetchWindowPlan::Hold::NONE) {
						continue; // held until the batches below are produced, then acknowledged or waited on
					}
				} else if (answer.source > sim.total) {
					if (!producer_done) {
						continue; // the terminal waits for the end of the stream
					}
					plan.Answered(dense);
					plan.Close();
					response.terminal = true;
					response.total = sim.total - sim.first + plan.EmptyBatches();
				} else {
					if (answer.source > produced) {
						continue; // not produced yet: the FETCH waits in its handler
					}
					plan.Answered(dense);
					response.source = answer.source;
				}
				requests.erase(requests.begin() + static_cast<std::ptrdiff_t>(pick));
				responses.push_back(response);
				served = true;
				if (sim.start > 0 && rows_in_flight() > plan.Width()) {
					out.within_window = false;
				}
			}
		}
		if (!served && !responses.empty()) {
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
				if (stopped && response.source != NONE) {
					out.rows_after_stop++;
				}
			}
		}
	}
	return out;
}

bool ReadsEverythingInOrder(Outcome out, idx_t first, idx_t total) {
	if (out.consumed.size() != total - first) {
		return false;
	}
	// the client's output is ordered by batch index: sorted so, the produced batches must be 1..total
	std::sort(out.consumed.begin(), out.consumed.end());
	for (idx_t i = 0; i < out.consumed.size(); i++) {
		if (out.consumed[i].second != first + 1 + i) {
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
			for (auto shape : std::vector<Shape> {{64, 8, 0, 0, 300},
			                                      {64, 8, 8, 0, 300},
			                                      {16, 2, 2, 3, 200},
			                                      {16, 2, 0, 3, 200},
			                                      {64, 8, 0, 1, 5},
			                                      {8, 8, 0, 0, 100},
			                                      {4, 16, 0, 0, 50},
			                                      {64, 1, 4, 2, 200},
			                                      {64, 0, 0, 2, 200},
			                                      {16, 2, 0, 0, 0},
			                                      {16, 2, 2, 4, 4}}) {
				// one scan thread or sixteen; everything produced at once, or a batch every few steps
				for (idx_t threads : {1, 16}) {
					for (idx_t pace : {0, 3}) {
						for (uint32_t seed = 1; seed <= 12; seed++) {
							Sim sim;
							sim.depth = shape.depth, sim.start = shape.start, sim.max = shape.max;
							sim.first = shape.first, sim.total = shape.total, sim.threads = threads;
							sim.produce_every = pace, sim.seed = seed;
							auto out = Run(sim);
							auto what = "depth " + std::to_string(shape.depth) + ", window " +
							            std::to_string(shape.start) + ".." + std::to_string(shape.max) + ", " +
							            std::to_string(shape.total) + " batches, " + std::to_string(threads) +
							            " threads, pace " + std::to_string(pace) + ", seed " + std::to_string(seed);
							if (!Check(!out.refused, what + ": every request is decided") ||
							    !Check(ReadsEverythingInOrder(out, shape.first, shape.total),
							           what + ": the rows, in order") ||
							    !Check(out.pushed == out.expected_total, what + ": received = announced total") ||
							    !Check(out.totals_agree, what + ": every terminal announces the same total") ||
							    !Check(out.within_window, what + ": rows in flight within the window")) {
								return;
							}
						}
					}
				}
			}
		});

		Scenario("an early stop costs at most the window", [] {
			for (uint32_t seed = 1; seed <= 20; seed++) {
				for (idx_t threads : {1, 16}) {
					Sim sim;
					sim.total = 100000, sim.threads = threads, sim.seed = seed;
					// LIMIT 1 over a big result: the window it starts with, ramp or not
					sim.stop_after = 1;
					auto first = Run(sim);
					if (!Check(first.consumed.size() == 1 && first.rows_after_stop <= 8,
					           "LIMIT 1: at most the start arrives after the stop (" +
					               std::to_string(first.rows_after_stop) + ", " + std::to_string(threads) +
					               " threads)")) {
						return;
					}
					// a fixed window (start = max) bounds a stop anywhere in the stream
					sim.stop_after = 500, sim.max = 8;
					auto mid = Run(sim);
					if (!Check(mid.rows_after_stop <= 8, "a fixed window: a stop mid-stream costs at most it (" +
					                                         std::to_string(mid.rows_after_stop) + ")")) {
						return;
					}
					// a growing one bounds it by its cap
					sim.max = 16;
					auto capped = Run(sim);
					if (!Check(capped.rows_after_stop <= 16, "a window grown to its cap of 16: at most the cap (" +
					                                             std::to_string(capped.rows_after_stop) + ")")) {
						return;
					}
				}
			}
			// without a window the same stop pulls the client's whole read-ahead
			Sim quack;
			quack.start = 0, quack.total = 100000, quack.stop_after = 1, quack.seed = 7;
			auto pulled = Run(quack);
			Check(pulled.rows_after_stop > 8,
			      "window 0: the read-ahead arrives after the stop (" + std::to_string(pulled.rows_after_stop) + ")");
		});

		Scenario("the window grows while the client reads", [] {
			// a fixed window of 2 against a read-ahead of 16: most answers are empty, all the way
			Sim fixed;
			fixed.depth = 16, fixed.start = 2, fixed.max = 2, fixed.total = 2000, fixed.seed = 3;
			auto fixed_out = Run(fixed);
			Check(fixed_out.fetches > 4 * 2000, "fixed window 2: about read-ahead / window FETCHes per batch (" +
			                                        std::to_string(fixed_out.fetches) + ")");
			// starting at 2 with no cap it outgrows the read-ahead in a few windows
			auto grown = fixed;
			grown.max = 0;
			auto grown_out = Run(grown);
			Check(grown_out.fetches < 2000 + 200,
			      "growing window: the empty answers stop (" + std::to_string(grown_out.fetches) + " FETCHes)");
			AclFetchWindowPlan plan(2, 8);
			for (idx_t i = 1; i <= 40; i++) {
				plan.Decide(i, i - 1, 0);
				plan.Answered(i);
			}
			Check(plan.Width() == 8, "the window stops at its cap (" + std::to_string(plan.Width()) + ")");
		});

		Scenario("a slow producer and a parallel scan do not spin on empty answers", [] {
			// sixteen scan threads, a batch produced every 200 steps (a round trip is two): while a batch
			// with rows is being made, the threads holding empty indices would consume them and ask again,
			// the ack stuck below it - a real producer is slower still (a sort before its first batch)
			for (idx_t max : {2, 0}) {
				Sim sim;
				sim.depth = 16, sim.start = 2, sim.max = max, sim.total = 100, sim.threads = 16;
				sim.produce_every = 200, sim.seed = 5;
				auto held = Run(sim);
				auto label = std::string(max ? "a fixed window of 2" : "a growing window from 2");
				Check(!held.refused && ReadsEverythingInOrder(held, 0, 100),
				      label + ": every batch, in order, nothing refused");
				Check(held.fetches <= 100 * 16, label + ": FETCHes stay near read-ahead / window per batch (" +
				                                    std::to_string(held.fetches) + ")");
				// the same client against a server that answers empties at once
				sim.hold = false;
				auto spun = Run(sim);
				Check(spun.refused || spun.fetches > 5 * held.fetches,
				      label + ", without the hold: the client spins (" + std::to_string(spun.fetches) + " FETCHes" +
				          (spun.refused ? ", refused past MAX_AHEAD" : "") + ")");
			}
		});

		Scenario("a batch whose FETCH never arrived holds the empties above it on a timer, not forever", [] {
			// at the connection cap a FETCH can be shed before any handler sees it: an empty answer
			// waiting on that batch's production would wait for a FETCH that may never come
			AclFetchWindowPlan plan(2, 2);
			Check(plan.Decide(3, 0, 0).kind == Kind::EMPTY, "3 is past the window");
			Check(plan.EmptyHold(3, 1000) == AclFetchWindowPlan::Hold::ACKNOWLEDGEMENT,
			      "1 and 2 were never requested here: a timed hold");
			Check(plan.EmptyHold(3, 1000 + AclFetchWindowPlan::ACK_HOLD_MS) == AclFetchWindowPlan::Hold::NONE,
			      "...that runs out");
			plan.Decide(1, 0, 0);
			plan.Decide(2, 0, 0);
			Check(plan.Decide(4, 0, 0).kind == Kind::EMPTY, "4 is past the window too");
			Check(plan.EmptyHold(4, 5000) == AclFetchWindowPlan::Hold::PRODUCTION,
			      "1 and 2 are requested and not produced: the producer's hold, no timer");
			plan.Answered(1);
			plan.Answered(2);
			Check(plan.EmptyHold(4, 5000) == AclFetchWindowPlan::Hold::ACKNOWLEDGEMENT,
			      "answered, not acknowledged: the timed hold again");
			// and a whole stream with a server that sheds one request in seven, the client re-sending
			for (idx_t threads : {1, 16}) {
				for (uint32_t seed = 1; seed <= 8; seed++) {
					Sim sim;
					sim.depth = 16, sim.start = 2, sim.total = 150, sim.threads = threads, sim.produce_every = 5;
					sim.shed_every = 7, sim.seed = seed;
					auto out = Run(sim);
					if (!Check(!out.refused && ReadsEverythingInOrder(out, 0, 150) && out.pushed == out.expected_total,
					           "a shedding server: every batch, in order, the count holds (" + std::to_string(threads) +
					               " threads, seed " + std::to_string(seed) + ")")) {
						return;
					}
				}
			}
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
