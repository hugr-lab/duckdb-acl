//===----------------------------------------------------------------------===//
// acl_audit_pipeline.hpp — the base's side of the audit (spec 069): acl's own, never a consumer's
//
// What drains the registry of acl_audit.hpp: the bounded queue, the audit
// thread that hands every event to every sink and then to the ring and the
// JSON-lines file, the counters derived from the events, the levels. Held by
// the PolicyStore and the doors; an extended extension never sees it (it
// could not resolve a symbol of acl's anyway - RTLD_LOCAL).
//===----------------------------------------------------------------------===//

#pragma once

#include "acl_audit.hpp"

#include "duckdb/common/file_system.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <thread>

namespace duckdb {
class ExtensionLoader;

namespace acl {

class AuditPipeline {
public:
	explicit AuditPipeline(shared_ptr<AuditHooks> hooks);
	~AuditPipeline();

	//! Bind to the instance whose settings drive the pipeline (level, queue, ring, file, node id).
	void Attach(DatabaseInstance &db);
	AuditHooks &Hooks() {
		return *hooks;
	}
	//! The instance level, read from `acl_audit_level` on every call: a SET takes effect on the next
	//! statement.
	AuditLevel InstanceLevel();
	//! Whether an event at `level` is recorded for a session at `session_level` (`-1` = inherit).
	bool Records(AuditLevel level, int8_t session_level);
	//! Ask the registered policy for a session's level; false = no opinion (a policy that throws has
	//! none, and never refuses a session).
	bool LevelForSession(const Principal &principal, const string &door, AuditLevel &out);
	//! Enqueue. Fills node, seq and ts; drops and counts when the queue is full. Never blocks.
	void Emit(AuditEvent event);
	//! The events of the ring, oldest first.
	vector<AuditEvent> Ring();
	int64_t Dropped() const;
	//! Wait until every event enqueued so far has been handled (tests; shutdown), then flush the sinks
	//! and sync the file. Bounded: false when the thread did not drain in time (a sink is stuck).
	bool Flush(int64_t timeout_ms = 30000);
	//! End the thread: the backlog gets a bounded while to reach the sinks, the rest is dropped and
	//! counted, the file is synced and closed. Idempotent; safe from the audit thread itself (the
	//! instance's teardown may run on whichever thread held its last reference - then it detaches).
	void Stop();

private:
	void Run();
	void Handle(const AuditEvent &event);
	void Count(const AuditEvent &event);
	void WriteFile(const AuditEvent &event);
	//! On the emitting thread: (re)open the file sink when the path changed or a write failed. The
	//! worker only ever writes to a handle opened here, so it never touches the instance.
	void OpenFileIfNeeded(const string &path);
	void SyncFile();
	string Setting(const char *name, const string &fallback);
	int64_t SettingInt(const char *name, int64_t fallback);

	shared_ptr<AuditHooks> hooks;
	weak_ptr<DatabaseInstance> db;
	std::atomic<int64_t> seq {0};
	std::atomic<int64_t> dropped {0};
	string node;

	std::mutex queue_lock;
	std::condition_variable queue_cv;
	std::condition_variable drained_cv;
	std::deque<AuditEvent> queue;
	int64_t handled = 0;
	int64_t enqueued = 0;
	bool stopping = false;
	bool abandon = false; // Stop() gave up on the backlog: the worker drops what is left, counted
	std::thread worker;

	//! The denial rate limit (spec 069): per source - a session, else a principal, else a door - at
	//! most `acl_audit_denials_per_second` denials are RECORDED per second; the rest are counted (the
	//! counters stay exact) and reported as dropped where=rate_limit. One principal's flood of cheap
	//! refusals cannot push everybody else's records out of the ring, the queue or a sink.
	bool AdmitDenial(const AuditEvent &event, int64_t per_second);
	std::mutex rate_lock;
	unordered_map<string, std::pair<int64_t, int64_t>> denial_buckets; // source -> (second, count)

	// the settings the worker uses, read on the emitting thread (inside the instance) per event
	std::atomic<int64_t> ring_cap {10000};
	std::mutex ring_lock;
	std::deque<AuditEvent> ring;

	// the file sink: opened by path on the emitting thread, written by the worker
	std::mutex file_lock;
	string file_path;
	unique_ptr<FileHandle> file;
	std::chrono::steady_clock::time_point last_open_attempt;
};

//! JSON-lines rendering of one event, the base file sink's line: every field, no claim values.
string AuditEventJson(const AuditEvent &event);

//! What a refusal's text may carry onto an event, by code (spec 069): a `parse` refusal echoes the
//! statement's own text ("at or near ..."), so it is replaced by a fixed sentence; a `principal`
//! refusal may echo a claim of an UNVERIFIED token (its issuer, its algorithm), so every quoted
//! value is blanked; every other code is our own text, which names virtual objects and nothing else.
string AuditReasonText(const string &reason_code, const string &text);

//! Register the audit surface: `acl_audit_events()`, `acl_metrics()`, `acl_audit_dropped()`,
//! `acl_audit_flush()`, `acl_session_audit_level()`, and the gauges the store owns.
void RegisterAclAudit(ExtensionLoader &loader, shared_ptr<PolicyStore> store, shared_ptr<AuditPipeline> pipeline);

} // namespace acl
} // namespace duckdb
