//===----------------------------------------------------------------------===//
// acl_session_hooks.hpp — acl's side of the acl_connection contract (spec 078)
//
// duckdb-ext-common's contracts/acl_connection.hpp is what another extension compiles against: the
// per-connection AclConnection and the AclSessionHooks registry of session observers. This is how
// acl fills them: SessionNotifier delivers the opens and the closes of the store's sessions to the
// observers - never under the store's lock (an observer may call back into acl), a session's close
// never before its open (a close that arrives while its open is being delivered waits for it), each
// exactly once - and the two calls that put a statement's session on its connection and take it off.
//===----------------------------------------------------------------------===//

#pragma once

#include "acl_connection.hpp"

#include "duckdb/common/mutex.hpp"

#include <atomic>
#include <deque>
#include <unordered_map>
#include <unordered_set>

namespace duckdb {
namespace acl {

class SessionNotifier {
public:
	//! An observer call slower than this is counted (the client's connect waits on an open)
	static constexpr int64_t SLOW_CALL_MS = 100;

	//! At load: the instance's registry, or null when the one there speaks another contract version
	void Attach(shared_ptr<AclSessionHooks> hooks_p);

	//! Under the store's lock, right before the session is inserted: from here its close waits for
	//! its open to be delivered. A no-op while nobody observes.
	void BeginOpen(const string &session_id);
	//! Outside the store's lock, before the handle is returned: every observer's OnSessionOpen, the
	//! token by reference for the call only; then any close that came meanwhile.
	void Opened(const SessionOpenInfo &info, const string &access_token);
	//! Under the store's lock, wherever a session record is removed: queued for Flush().
	void QueueClose(const string &session_id, const string &reason);
	//! Outside the store's lock: every queued close, to every observer.
	void Flush();

	//! For the gauges: observer calls that threw, and that took longer than SLOW_CALL_MS
	int64_t Failures() const {
		return failures.load();
	}
	int64_t Slow() const {
		return slow.load();
	}
	//! The observers registered now; -1 when the instance's registry speaks another contract
	int64_t ObserverCount() const;

private:
	shared_ptr<AclSessionHooks> hooks;
	bool refused = false;
	mutex lock;
	std::unordered_set<string> opening;
	std::unordered_map<string, string> deferred;
	std::deque<std::pair<string, string>> closes;
	std::atomic<int64_t> failures {0};
	std::atomic<int64_t> slow {0};

public:
	//! Set by Attach when the registry was refused (reported by the caller once)
	void MarkRefused() {
		refused = true;
	}
};

//! A statement under a session is about to run on `context`: its session goes on the connection
//! (AclConnection::Publish). False when the connection state could not be reached (another contract).
bool PublishStatementSession(ClientContext &context, AclSessionView view);
//! The statement ended (or the next one runs under no session): the session comes off.
void WithdrawStatementSession(ClientContext &context);

} // namespace acl
} // namespace duckdb
