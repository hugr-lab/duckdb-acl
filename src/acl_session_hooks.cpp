//===----------------------------------------------------------------------===//
// acl_session_hooks.cpp — acl's side of the acl_connection contract (spec 078)
//===----------------------------------------------------------------------===//

#include "acl_session_hooks.hpp"

#include <chrono>

namespace duckdb {
namespace acl {

namespace {

int64_t ElapsedMs(std::chrono::steady_clock::time_point since) {
	return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - since).count();
}

} // namespace

void SessionNotifier::Attach(shared_ptr<AclSessionHooks> hooks_p) {
	hooks = std::move(hooks_p);
}

void SessionNotifier::BeginOpen(const string &session_id) {
	if (!hooks) {
		return;
	}
	lock_guard<mutex> guard(lock);
	opening.insert(session_id);
}

void SessionNotifier::Opened(const SessionOpenInfo &info, const string &access_token) {
	if (!hooks) {
		return;
	}
	for (auto &observer : hooks->Observers()) {
		auto started = std::chrono::steady_clock::now();
		try {
			observer->OnSessionOpen(info, access_token);
		} catch (...) {
			// an observer never fails an open: counted, and the session opens (spec 078)
			failures++;
		}
		if (ElapsedMs(started) > SLOW_CALL_MS) {
			slow++;
		}
	}
	{
		lock_guard<mutex> guard(lock);
		opening.erase(info.session_id);
		auto waiting = deferred.find(info.session_id);
		if (waiting != deferred.end()) {
			closes.emplace_back(waiting->first, waiting->second);
			deferred.erase(waiting);
		}
	}
	Flush();
}

void SessionNotifier::QueueClose(const string &session_id, const string &reason) {
	if (!hooks) {
		return;
	}
	lock_guard<mutex> guard(lock);
	if (opening.count(session_id)) {
		deferred[session_id] = reason; // its open is being delivered: the close follows it
		return;
	}
	closes.emplace_back(session_id, reason);
}

void SessionNotifier::Flush() {
	if (!hooks) {
		return;
	}
	std::deque<std::pair<string, string>> due;
	{
		lock_guard<mutex> guard(lock);
		due.swap(closes);
	}
	if (due.empty()) {
		return;
	}
	auto observers = hooks->Observers();
	for (auto &close : due) {
		for (auto &observer : observers) {
			auto started = std::chrono::steady_clock::now();
			try {
				observer->OnSessionClose(close.first, close.second);
			} catch (...) {
				failures++;
			}
			if (ElapsedMs(started) > SLOW_CALL_MS) {
				slow++;
			}
		}
	}
}

int64_t SessionNotifier::ObserverCount() const {
	if (refused) {
		return -1;
	}
	return hooks ? NumericCast<int64_t>(hooks->Observers().size()) : 0;
}

bool PublishStatementSession(ClientContext &context, AclSessionView view) {
	string why;
	auto state = AclConnection::Reach(context, why);
	if (!state) {
		return false;
	}
	state->Publish(std::move(view));
	return true;
}

void WithdrawStatementSession(ClientContext &context) {
	auto state = context.registered_state->Get<AclConnection>(AclConnection::StateKey());
	if (!state || state->contract_magic != AclConnectionContract::MAGIC ||
	    state->contract_version != AclConnectionContract::VERSION) {
		return; // never published here, or not ours to touch
	}
	state->Withdraw();
}

} // namespace acl
} // namespace duckdb
