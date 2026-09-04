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
	//! Wait until every event enqueued so far has been handled (tests; shutdown).
	void Flush();
	void Stop();

private:
	void Run();
	void Handle(const AuditEvent &event);
	void Count(const AuditEvent &event);
	void WriteFile(const AuditEvent &event);
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
	std::thread worker;

	std::mutex ring_lock;
	std::deque<AuditEvent> ring;

	// the file sink: opened by path, reopened when the setting changes
	std::mutex file_lock;
	string file_path;
	unique_ptr<FileHandle> file;
};

//! JSON-lines rendering of one event, the base file sink's line: every field, no claim values.
string AuditEventJson(const AuditEvent &event);

//! Register the audit surface: `acl_audit_events()`, `acl_metrics()`, `acl_audit_dropped()`,
//! `acl_audit_flush()`, `acl_session_audit_level()`, and the gauges the store owns.
void RegisterAclAudit(ExtensionLoader &loader, shared_ptr<PolicyStore> store, shared_ptr<AuditPipeline> pipeline);

} // namespace acl
} // namespace duckdb
