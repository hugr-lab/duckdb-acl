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
	string kind;      // statement / admin / session / ingest / door / policy / keys
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
	static string ObjectType() {
		return "acl_audit_hooks";
	}
	string GetObjectType() override {
		return ObjectType();
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
