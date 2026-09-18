//===----------------------------------------------------------------------===//
// acl_audit.hpp — the audit and observability contract (spec 069)
//
// The ONE header an extension built on the base compiles against: the event,
// the levels, a sink, a session policy, the counters and gauges, and the hook
// registry every extension reaches through duckdb's object cache:
//
//   auto hooks = db.GetObjectCache().GetOrCreate<AuditHooks>(AuditHooks::ObjectType());
//
// GetOrCreate on both sides makes the load order irrelevant - whoever comes
// first creates it, acl adopts it when it loads - and the registry is per
// DatabaseInstance, so two instances in one process never share sinks.
//
// EVERYTHING here is header-only, deliberately: a loadable extension is
// dlopen'd RTLD_LOCAL, so an extension compiled against this header can never
// resolve a symbol of acl's - it calls what it compiled, on the object it got
// from the cache (the cache resolves the type by name, not by RTTI). The
// pipeline behind the registry - the queue, the audit thread, the ring, the
// file - is acl's own (acl_audit_pipeline.hpp) and is never called from outside.
//
// The flip side of header-only: BOTH extensions carry their own compiled copy
// of these types, and two copies built from different revisions of this header
// would read one object through two layouts. So the registry is stamped with
// AuditHooks::CONTRACT_VERSION by whoever creates it, at a fixed offset (the
// first member), and AuditHooks::Reach() is how both sides get it: a registry
// stamped with another version is refused - the base keeps a private one and
// says so in a gauge, the extension refuses to attach and says so in its
// status - never dereferenced. Bump the version on ANY change to what this
// header lays out: AuditEvent, AuditObject, AuditLevel, Principal, the
// interfaces, AuditCounters, AuditGauges, AuditHooks.
//
// Delivery is decoupled from the decision: the emitting seam composes the
// event and pushes it onto one bounded queue; the audit thread pops and hands
// each event to every sink in turn, then to the base's own ring and file. A
// slow sink costs dropped events (counted), never latency on a statement; a
// sink that throws is counted and skipped for that event. Nothing a consumer
// does can slow or stop a decision.
//===----------------------------------------------------------------------===//

#pragma once

#include "acl_policy.hpp"

#include "duckdb/storage/object_cache.hpp"

#include <algorithm>
#include <functional>
#include <map>
#include <mutex>

namespace duckdb {
namespace acl {

//! Ordered: a level records every event at or below itself.
enum class AuditLevel : uint8_t { OFF = 0, DENIED = 1, DECISIONS = 2, ALL = 3 };

//! spec 074: whether a node profiles what it executes - nothing, statements the caller's trace
//! context marks as sampled, or every statement.
enum class ProfileLevel : uint8_t { OFF = 0, SAMPLED = 1, ALL = 2 };

inline const char *ProfileLevelName(ProfileLevel level) {
	switch (level) {
	case ProfileLevel::OFF:
		return "off";
	case ProfileLevel::SAMPLED:
		return "sampled";
	default:
		return "all";
	}
}

//! Parses `off` / `sampled` / `all` (case-insensitive, trimmed); false on anything else.
inline bool ParseProfileLevel(const string &text, ProfileLevel &out) {
	string lowered;
	for (auto c : text) {
		if (c != ' ' && c != '\t' && c != '\n' && c != '\r') {
			lowered += static_cast<char>((c >= 'A' && c <= 'Z') ? c + ('a' - 'A') : c);
		}
	}
	if (lowered == "off") {
		out = ProfileLevel::OFF;
	} else if (lowered == "sampled") {
		out = ProfileLevel::SAMPLED;
	} else if (lowered == "all") {
		out = ProfileLevel::ALL;
	} else {
		return false;
	}
	return true;
}

inline const char *AuditLevelName(AuditLevel level) {
	switch (level) {
	case AuditLevel::OFF:
		return "off";
	case AuditLevel::DENIED:
		return "denied";
	case AuditLevel::DECISIONS:
		return "decisions";
	default:
		return "all";
	}
}

//! Parses `off` / `denied` / `decisions` / `all` (case-insensitive, trimmed); false on anything else.
inline bool ParseAuditLevel(const string &text, AuditLevel &out) {
	string lowered;
	for (auto c : text) {
		if (c != ' ' && c != '\t' && c != '\n' && c != '\r') {
			lowered += static_cast<char>((c >= 'A' && c <= 'Z') ? c + ('a' - 'A') : c);
		}
	}
	if (lowered == "off") {
		out = AuditLevel::OFF;
	} else if (lowered == "denied") {
		out = AuditLevel::DENIED;
	} else if (lowered == "decisions") {
		out = AuditLevel::DECISIONS;
	} else if (lowered == "all") {
		out = AuditLevel::ALL;
	} else {
		return false;
	}
	return true;
}

//! One virtual object a decision touched, with the capability judged for it.
struct AuditObject {
	string name;
	string capability;
};

//! spec 074: one source of an executed statement - an attached database the rewrite resolved a
//! scan to, or a file format - rolled up over its scans. Numbers only: a source's name is the
//! attached catalog's, a kind is the scanner's; the pushdown is counted, never quoted.
struct AuditSource {
	string source;     // the attached database (`pg`, `lake`, `memory`); empty for a file scan
	string kind;       // the scanner: table_scan, postgres_scan, ducklake_scan, read_parquet, ...
	int64_t scans = 0; // scan operators; for a file format, the files read
	int64_t rows = 0;  // rows the scans returned
	int64_t rows_scanned = 0;
	int64_t timing_us = 0; // cumulative thread time of the scans - may exceed the statement's wall time
	int64_t bytes = 0;     // intermediate bytes the scans produced
	int64_t filters = 0;   // conjuncts pushed to the scans, summed
	int64_t projections = 0;
	bool dynamic_filters = false; // a join filter reached at least one of the scans
};

//! spec 074: one operator of the executed plan, in preorder; `parent` is -1 at the root.
struct AuditPlanNode {
	int64_t id = 0;
	int64_t parent = -1;
	int64_t depth = 0;
	string type;   // duckdb's operator type (TABLE_SCAN, HASH_JOIN, ...)
	string kind;   // for a scan: as AuditSource::kind; else empty
	string source; // for a scan: as AuditSource::source; else empty
	int64_t rows = 0;
	int64_t rows_scanned = 0;
	int64_t timing_us = 0; // cumulative thread time
	int64_t bytes = 0;
	int64_t peak_memory_observed = 0; // the node's buffer-pool peak seen while this operator ran
	int64_t filters = 0;
	int64_t projections = 0;
	bool dynamic_filters = false;
};

//! One decision, or one lifecycle occurrence. Never the statement text, parameters, rows or
//! physical names; claim values are here in memory (`principal.claims`) for a sink to filter, and
//! never written by a base sink.
struct AuditEvent {
	int64_t ts_us = 0;
	int64_t seq = 0;
	string node;
	AuditLevel level = AuditLevel::DECISIONS; // the lowest level that includes this event
	string door;                              // flight / quack / gateway / admin / session
	string session;                           // the ops id, never the handle; empty off a session
	Principal principal;
	string kind;      // statement / admin / session / ingest / door / policy / keys / profile
	string statement; // the statement class, or MANAGEMENT / NATIVE; empty for lifecycle kinds
	vector<AuditObject> objects;
	bool allowed = true;
	string reason_code; // denied: one of the bounded taxonomy (spec 069)
	string reason;      // denied: our refusal text, prefix included
	string correlation_id;
	string traceparent;
	int64_t rewrite_us = -1;  // decisions: the decision's own cost
	int64_t rows = -1;        // ingest: rows written by the completed drain
	int64_t duration_us = -1; // session close: how long it lived
	string detail;            // policy / keys / session: reloaded, source_error, refreshed, refresh_failed,
	                          // client, idle, expired, killed, door_stopped
	//! spec 074, kind `profile`: the execution of a decided statement, emitted when it ends. Every
	//! number is duckdb's own measure (see the spec for what each one is and is not); the tree and
	//! the rollup carry names of attached catalogs and operator types, never text of the statement.
	int64_t decision_seq = -1; // the statement event whose execution this is; -1 = unlinked
	bool error = false;        // the execution failed; `detail` carries the error's class
	int64_t exec_us = -1;      // wall time, the statement's begin to its end
	int64_t cpu_us = -1;       // thread time summed over operators
	int64_t rows_scanned = -1;
	int64_t rows_out = -1;
	int64_t bytes_read = -1;
	int64_t bytes_written = -1;
	int64_t peak_memory = -1;      // the buffer pool's peak during the statement
	int64_t memory_allocated = -1; // bytes the statement allocated in total
	int64_t blocked_us = -1;       // thread time spent blocked
	bool truncated = false;        // `plan` was cut at its limit; `sources` is rolled up over the whole tree
	vector<AuditSource> sources;
	vector<AuditPlanNode> plan;
	//! False when the effective level did not record this event: it is then counted (metrics are a
	//! state of the node, whatever the level) and never handed to a sink, the ring or the file - so a
	//! sink only ever sees `true`.
	bool recorded = true;
};

//! A consumer of events. Called on the audit thread, in `seq` order, never on the decision path.
struct AuditSink {
	virtual ~AuditSink() = default;
	virtual void OnEvent(const AuditEvent &event) = 0;
	//! Called when the level or a setting changes, and at shutdown.
	virtual void Flush() {
	}
};

//! Decides a session's level when it opens: the extended extension's "per role, per user, per
//! door" rule. `false` means "no opinion" - the instance's level applies.
struct SessionPolicy {
	virtual ~SessionPolicy() = default;
	virtual bool LevelFor(const Principal &principal, const string &door, AuditLevel &out) = 0;
	//! spec 074: the profile level of a session (the same "per role, per user, per door" rule);
	//! `false` = no opinion, the instance's `acl_profile_level` applies. Not pure: an extension that
	//! has no rule for it keeps attaching.
	virtual bool ProfileFor(const Principal &principal, const string &door, ProfileLevel &out) {
		(void)principal;
		(void)door;
		(void)out;
		return false;
	}
};

//! One metric row, as a scrape wants it.
struct AuditMetric {
	string name;
	string kind; // counter / gauge
	vector<std::pair<string, string>> attributes;
	int64_t value = 0;
	string unit;
	string description;
};

inline string AuditAttributesKey(const vector<std::pair<string, string>> &attributes) {
	string key;
	for (auto &attribute : attributes) {
		key += attribute.first + "=" + attribute.second + "\x1f";
	}
	return key;
}

//! The counters the base keeps, derived from the events on the audit thread (so a level of `off`
//! still counts - metrics are a state of the node, not audit) plus the pipeline's own. Attributes
//! only from bounded sets; nothing per role, object or subject (those are an extension's, from the
//! events). Header-only so a consumer reads them without a symbol of acl's.
class AuditCounters {
public:
	//! Add to the counter for this (name, attribute tuple); a new tuple appears on first use.
	void Add(const string &name, const vector<std::pair<string, string>> &attributes, int64_t delta = 1) {
		auto key = name + "\x1f" + AuditAttributesKey(attributes);
		std::lock_guard<std::mutex> guard(lock);
		auto entry = values.find(key);
		if (entry == values.end()) {
			values[key] = delta;
			keys[key] = {name, attributes};
		} else {
			entry->second += delta;
		}
	}
	int64_t Get(const string &name, const vector<std::pair<string, string>> &attributes) const {
		auto key = name + "\x1f" + AuditAttributesKey(attributes);
		std::lock_guard<std::mutex> guard(lock);
		auto entry = values.find(key);
		return entry == values.end() ? 0 : entry->second;
	}
	vector<AuditMetric> Snapshot() const {
		std::lock_guard<std::mutex> guard(lock);
		vector<AuditMetric> out;
		for (auto &entry : values) {
			auto &named = keys.at(entry.first);
			AuditMetric metric;
			metric.name = named.first;
			metric.kind = "counter";
			metric.attributes = named.second;
			metric.value = entry.second;
			metric.unit = "1";
			out.push_back(std::move(metric));
		}
		return out;
	}

private:
	mutable std::mutex lock;
	std::map<string, int64_t> values;
	std::map<string, std::pair<string, vector<std::pair<string, string>>>> keys;
};

//! The gauges: states, read at snapshot time through the function the owner of the state
//! registered. The store registers live sessions, drain, policy version and staleness, JWKS age;
//! the pipeline registers its own fills.
class AuditGauges {
public:
	using Reader = std::function<int64_t()>;
	using DynamicReader = std::function<vector<std::pair<vector<std::pair<string, string>>, int64_t>>()>;

	void Register(const string &name, const vector<std::pair<string, string>> &attributes, const string &unit,
	              const string &description, Reader reader) {
		std::lock_guard<std::mutex> guard(lock);
		entries.push_back(Entry {name, attributes, unit, description, std::move(reader)});
	}
	//! For a name whose attribute tuples change over time (the JWKS ages, one row per issuer).
	void RegisterDynamic(const string &name, const string &unit, const string &description, DynamicReader reader) {
		std::lock_guard<std::mutex> guard(lock);
		dynamics.push_back(Dynamic {name, unit, description, std::move(reader)});
	}
	//! Drop every gauge of this name: an owner whose state is going away takes its readers with it,
	//! so a later snapshot never calls into freed memory.
	void Remove(const string &name) {
		std::lock_guard<std::mutex> guard(lock);
		for (auto it = entries.begin(); it != entries.end();) {
			it = it->name == name ? entries.erase(it) : it + 1;
		}
		for (auto it = dynamics.begin(); it != dynamics.end();) {
			it = it->name == name ? dynamics.erase(it) : it + 1;
		}
	}
	vector<AuditMetric> Snapshot() const {
		vector<Entry> fixed;
		vector<Dynamic> dynamic;
		{
			std::lock_guard<std::mutex> guard(lock);
			fixed = entries;
			dynamic = dynamics;
		}
		vector<AuditMetric> out;
		for (auto &entry : fixed) {
			AuditMetric metric;
			metric.name = entry.name;
			metric.kind = "gauge";
			metric.attributes = entry.attributes;
			metric.value = entry.reader();
			metric.unit = entry.unit;
			metric.description = entry.description;
			out.push_back(std::move(metric));
		}
		for (auto &entry : dynamic) {
			for (auto &row : entry.reader()) {
				AuditMetric metric;
				metric.name = entry.name;
				metric.kind = "gauge";
				metric.attributes = row.first;
				metric.value = row.second;
				metric.unit = entry.unit;
				metric.description = entry.description;
				out.push_back(std::move(metric));
			}
		}
		return out;
	}

private:
	struct Entry {
		string name;
		vector<std::pair<string, string>> attributes;
		string unit;
		string description;
		Reader reader;
	};
	struct Dynamic {
		string name;
		string unit;
		string description;
		DynamicReader reader;
	};
	mutable std::mutex lock;
	vector<Entry> entries;
	vector<Dynamic> dynamics;
};

//! The registry: per DatabaseInstance, reached as the header comment shows. What a consumer
//! registers and reads; what the base's pipeline drains. Header-only.
class AuditHooks : public ObjectCacheEntry {
public:
	//! The layout contract of this header (see the header comment): bumped on any change to what
	//! an extension compiles from here. Written by whoever creates the registry, as the first two
	//! members so the other side reads them at the same offset whatever else moved: a magic that
	//! says "stamped at all" (a registry created by a build from before the stamp has other bytes
	//! here), then the version.
	static constexpr int32_t CONTRACT_MAGIC = 0x41434C41; // "ACLA"
	static constexpr int32_t CONTRACT_VERSION = 2;        // 2: spec 074 - the profile event, ProfileFor
	int32_t contract_magic = CONTRACT_MAGIC;
	int32_t contract_version = CONTRACT_VERSION;

	static string ObjectType() {
		return "acl_audit_hooks";
	}
	string GetObjectType() override {
		return ObjectType();
	}
	//! The registry of an instance, from either extension in either load order (C2) - created here
	//! when absent, and checked: null with `why` when the object under the key was stamped with
	//! another contract version (the two extensions were built from different revisions of this
	//! header) or is not a registry at all. The caller must not use such a registry.
	static shared_ptr<AuditHooks> Reach(ObjectCache &cache, string &why) {
		auto hooks = cache.GetOrCreate<AuditHooks>(ObjectType());
		if (!hooks) {
			why = "the object cache holds something else under '" + ObjectType() + "'";
			return nullptr;
		}
		if (hooks->contract_magic != CONTRACT_MAGIC) {
			why = "the audit registry carries no contract stamp - created by an extension built from an acl_audit.hpp "
			      "older than the stamp; this build speaks contract version " +
			      std::to_string(CONTRACT_VERSION);
			return nullptr;
		}
		if (hooks->contract_version != CONTRACT_VERSION) {
			why = "the audit registry is stamped with contract version " + std::to_string(hooks->contract_version) +
			      ", this build speaks " + std::to_string(CONTRACT_VERSION) +
			      " - acl and its extension were built from different revisions of acl_audit.hpp";
			return nullptr;
		}
		why.clear();
		return hooks;
	}
	//! What a refused registry was stamped with, for a gauge attribute: its version, or 0 for none
	static int32_t StampOf(ObjectCache &cache) {
		auto hooks = cache.GetOrCreate<AuditHooks>(ObjectType());
		return hooks && hooks->contract_magic == CONTRACT_MAGIC ? hooks->contract_version : 0;
	}
	//! Never evicted: a sink registration must outlive any cache pressure.
	optional_idx GetEstimatedCacheMemory() const override {
		return optional_idx();
	}

	void AddSink(shared_ptr<AuditSink> sink) {
		std::lock_guard<std::mutex> guard(lock);
		sinks.push_back(std::move(sink));
	}
	void RemoveSink(const shared_ptr<AuditSink> &sink) {
		std::lock_guard<std::mutex> guard(lock);
		for (auto it = sinks.begin(); it != sinks.end(); ++it) {
			if (*it == sink) {
				sinks.erase(it);
				return;
			}
		}
	}
	void SetSessionPolicy(shared_ptr<SessionPolicy> policy_p) {
		std::lock_guard<std::mutex> guard(lock);
		policy = std::move(policy_p);
	}
	//! The sinks as they are now (a copy: a sink may be removed while the audit thread runs).
	vector<shared_ptr<AuditSink>> Sinks() const {
		std::lock_guard<std::mutex> guard(lock);
		return sinks;
	}
	shared_ptr<SessionPolicy> Policy() const {
		std::lock_guard<std::mutex> guard(lock);
		return policy;
	}
	AuditCounters &Counters() {
		return counters;
	}
	const AuditCounters &Counters() const {
		return counters;
	}
	AuditGauges &Gauges() {
		return gauges;
	}

private:
	mutable std::mutex lock;
	vector<shared_ptr<AuditSink>> sinks;
	shared_ptr<SessionPolicy> policy;
	AuditCounters counters;
	AuditGauges gauges;
};

//! Every counter and gauge in the Prometheus text exposition format - what `GET /metrics` on the
//! embedded listener serves, and what a consumer may render for itself. Metric names have their
//! dots turned to underscores; attributes become labels.
inline string RenderPrometheus(AuditHooks &hooks) {
	auto quote = [](const string &value) {
		string out = "\"";
		for (auto c : value) {
			if (c == '"' || c == '\\') {
				out += '\\';
			}
			if (c == '\n') {
				out += "\\n";
				continue;
			}
			out += c;
		}
		return out + "\"";
	};
	auto underscored = [](string name) {
		std::replace(name.begin(), name.end(), '.', '_');
		return name;
	};
	string out;
	string last;
	auto render = [&](const AuditMetric &metric) {
		auto name = underscored(metric.name);
		if (metric.name != last) {
			last = metric.name;
			if (!metric.description.empty()) {
				out += "# HELP " + name + " " + metric.description + "\n";
			}
			out += "# TYPE " + name + " " + metric.kind + "\n";
		}
		string labels;
		for (auto &attribute : metric.attributes) {
			if (!labels.empty()) {
				labels += ",";
			}
			labels += attribute.first + "=" + quote(attribute.second);
		}
		out += name + (labels.empty() ? "" : "{" + labels + "}") + " " + std::to_string(metric.value) + "\n";
	};
	auto by_name = [](const AuditMetric &a, const AuditMetric &b) {
		return a.name == b.name ? AuditAttributesKey(a.attributes) < AuditAttributesKey(b.attributes) : a.name < b.name;
	};
	auto counters = hooks.Counters().Snapshot();
	std::sort(counters.begin(), counters.end(), by_name);
	for (auto &metric : counters) {
		render(metric);
	}
	auto gauges = hooks.Gauges().Snapshot();
	std::sort(gauges.begin(), gauges.end(), by_name);
	for (auto &metric : gauges) {
		render(metric);
	}
	return out;
}

} // namespace acl
} // namespace duckdb
