//===----------------------------------------------------------------------===//
// acl_node_load.cpp — what a node reports about its load (spec 079)
//===----------------------------------------------------------------------===//

#include "acl_node_load.hpp"

#include "acl_door_common.hpp"
#include "acl_node_label.hpp"
#include "acl_rewriter.hpp"

#include "duckdb/main/config.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/extension/extension_loader.hpp"

#ifdef ACL_QUACK_EMBED_ENABLED
#include "acl_quack_embed.hpp"
#include "acl_quack_server.hpp"
#endif

namespace duckdb {
namespace acl {

namespace {

idx_t SettingOf(DatabaseInstance &db, const char *name, idx_t fallback) {
	Value value;
	if (!DBConfig::GetConfig(db).TryGetCurrentSetting(name, value) || value.IsNull()) {
		return fallback;
	}
	return value.GetValue<idx_t>();
}

void AclNodeLoadFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &db = DatabaseInstance::GetDatabase(state.GetContext());
	result.Reference(Value(NodeLoadJson(db, StoreOf(state))), count_t(args.size()));
}

} // namespace

bool NodeLoadServed(DatabaseInstance &db) {
	Value on;
	return DBConfig::GetConfig(db).TryGetCurrentSetting("acl_metrics_endpoint", on) && !on.IsNull() &&
	       on.GetValue<bool>();
}

string NodeLabel(DatabaseInstance &db) {
	Value label;
	if (!DBConfig::GetConfig(db).TryGetCurrentSetting("acl_node_label", label) || label.IsNull()) {
		return string();
	}
	auto text = label.ToString();
	return ValidNodeLabel(text) ? text : string(); // the setting's validator holds it; a name never carries less
}

namespace {

//! spec 097: the operator's explicit opt-out - the pull surfaces answer without a token
bool ObserveOpen(DatabaseInstance &db) {
	Value open;
	return DBConfig::GetConfig(db).TryGetCurrentSetting("acl_observe_unauthenticated", open) && !open.IsNull() &&
	       open.GetValue<bool>();
}

} // namespace

ObserveVerdict ObserveAuthorize(DatabaseInstance &db, PolicyStore &store, const string &authorization, const char *door,
                                const char *surface) {
	auto detail = string("observe_") + surface;
	auto refuse = [&](ObserveVerdict verdict, const string &code, const string &reason, const Principal *who) {
		try {
			store.AuditDoor(door, detail, false, code, reason, string(), who);
		} catch (...) { // NOLINT: the refusal stands whatever the audit does
		}
		return verdict;
	};
	// the decision cannot be made - the node's policy or keys - is 503, never the caller's 401
	auto unavailable = [&](const string &code, const string &reason, const Principal *who) {
		return refuse(ObserveVerdict::UNAVAILABLE, code, reason, who);
	};
	try {
		if (!NodeLoadServed(db)) {
			return ObserveVerdict::OFF;
		}
		if (ObserveOpen(db)) {
			store.AuditDoor(door, detail, true, "", "");
			return ObserveVerdict::ALLOWED;
		}
		// `Bearer <token>`, the scheme case-insensitive (RFC 6750); anything else is no token
		string token;
		auto trimmed = authorization;
		StringUtil::Trim(trimmed);
		if (trimmed.size() > 7 && StringUtil::CIEquals(trimmed.substr(0, 7), "bearer ")) {
			token = trimmed.substr(7);
			StringUtil::Trim(token);
		}
		if (token.empty()) {
			return refuse(ObserveVerdict::UNAUTHENTICATED, "principal", "acl: the load report needs a bearer token",
			              nullptr);
		}
		TakeDenyReason(); // a note nobody audited must not name this refusal
		try {
			// the identity model first, as SessionOpen reads it: a source that fails here is the node's
			store.Identity();
		} catch (std::exception &ex) {
			TakeDenyReason();
			return unavailable("source_error", ErrorData(ex).RawMessage(), nullptr);
		}
		Principal principal;
		try {
			if (!store.VerifyPrincipal(true, token, principal)) {
				return refuse(ObserveVerdict::UNAUTHENTICATED, "principal", "acl: the bearer token did not verify",
				              nullptr);
			}
		} catch (std::exception &ex) {
			// the keys' source failing, or a policy the node cannot apply (a refused key location, an
			// ambiguous client), is not the caller's fault: 503, and the audit says which
			auto code = TakeDenyReason();
			auto message = ErrorData(ex).RawMessage();
			if (code == "source_error" || code == "policy_error") {
				return unavailable(code, message, nullptr);
			}
			// a token the policy refuses always says so (`acl_rewrite: token rejected: ...`); anything
			// else without a note is the node's - a catalog read that failed between freshness checks
			if (code.empty() && !StringUtil::StartsWith(message, "acl_rewrite: token rejected")) {
				return unavailable("source_error", message, nullptr);
			}
			return refuse(ObserveVerdict::UNAUTHENTICATED, code.empty() ? "principal" : code, message, nullptr);
		}
		PolicyStore::AdminRights rights;
		try {
			// cached per principal until the next policy version - a poll costs one signature check
			rights = store.AdminRightsOf(principal);
		} catch (std::exception &ex) {
			TakeDenyReason(); // EnsureFresh's note: this thread serves the next request too
			return unavailable("source_error", ErrorData(ex).RawMessage(), &principal);
		}
		if (!rights.observe) {
			return refuse(ObserveVerdict::FORBIDDEN, "capability",
			              "acl: reading the load report needs the observe scope (GRANT ADMIN observe)", &principal);
		}
		store.AuditDoor(door, detail, true, "", "", string(), &principal);
		return ObserveVerdict::ALLOWED;
	} catch (std::exception &ex) {
		TakeDenyReason();
		return unavailable("source_error", ErrorData(ex).RawMessage(), nullptr);
	} catch (...) { // NOLINT: never into the HTTP or gRPC handler
		return ObserveVerdict::UNAVAILABLE;
	}
}

string NodeLoadJson(DatabaseInstance &db, PolicyStore &store, const string &besides) {
	auto draining = store.Draining();
	auto live = store.SessionCount();
	// the session left out: its door and the group it is charged to, so every count agrees
	string besides_door, besides_group;
	bool left_out = false;
	if (!besides.empty()) {
		for (auto &session : store.SessionList()) {
			if (session.id == besides) {
				besides_door = session.door;
				besides_group = session.charged_group;
				left_out = true;
				break;
			}
		}
	}
	if (left_out && live > 0) {
		live--;
	}
	auto max_sessions = SettingOf(db, "acl_max_sessions", 1000);
	// spec 096: the node's resource group and the profile version it targets / has applied. Read from
	// the policy, so guarded: the report answers callers that are not authenticated, and a source that
	// does not answer reads as "unknown", never as its own text
	auto group = store.NodeGroup();
	bool group_known = group.empty();
	bool group_default = false;
	auto label = NodeLabel(db); // spec 134: the name the node's sessions carry, for a front to match
	string target = "null";
	auto now = std::chrono::steady_clock::now();
	uint64_t writes = store.CatalogLocalWrites();
	bool cached = false;
	{
		lock_guard<mutex> guard(store.lock);
		auto &policy = store.node_load_policy;
		if (policy.valid && policy.group == group && policy.writes == writes &&
		    now - policy.at < std::chrono::seconds(2)) {
			group_known = policy.group_known;
			group_default = policy.group_default;
			target = policy.target;
			cached = true;
		}
	}
	if (!cached) {
		// a catalog this build may not read (spec 094) admits nobody: neither known nor targeted
		try {
			group_known = store.node_traits.node_group_known ? store.node_traits.node_group_known() : true;
		} catch (std::exception &) {
			group_known = false;
		}
		try {
			group_default = group_known && store.NodeGroupDefault();
		} catch (std::exception &) {
		}
		try {
			if (store.node_traits.config_target) { // spec 126: an open node has no profile to target
				target = std::to_string(store.node_traits.config_target());
			}
		} catch (std::exception &) {
		}
		lock_guard<mutex> guard(store.lock);
		store.node_load_policy = {now, group, group_known, group_default, target, writes, true};
	}
	auto applied = store.cluster_applied.load();
	bool session_room = !draining && group_known && (max_sessions == 0 || live < max_sessions);

	string by_door;
	for (auto &door : store.SessionCountsByDoor()) {
		auto count = door.second;
		if (left_out && door.first == besides_door && count > 0) {
			count--;
		}
		by_door += (by_door.empty() ? "" : ",") + JsonQuote(door.first) + ":" + std::to_string(count);
	}
	// spec 085: sessions per resource group that caps them - what an orchestrator routes a tenant by
	string groups;
	for (auto &group : store.SessionCountsByGroup()) {
		auto count = group.second.first;
		if (left_out && group.first == besides_group && count > 0) {
			count--;
		}
		groups += (groups.empty() ? "" : ",") + JsonQuote(group.first) + ":{\"live\":" + std::to_string(count) +
		          ",\"max\":" + std::to_string(group.second.second) + "}";
	}

	string quack = "null";
	bool quack_room = false;
	string streams = "null";
	bool stream_room = true;
#ifdef ACL_QUACK_EMBED_ENABLED
	{
		auto per_client = SettingOf(db, "acl_quack_client_depth", ACL_QUACK_CLIENT_DEPTH_DEFAULT);
		auto slots = SettingOf(db, "acl_quack_server_max_connections", 1024);
		auto seats = per_client == 0 ? slots : MaxValue<idx_t>(1, slots / per_client);
		string doors;
		for (auto &door : AclQuackDoorLoads(db)) {
			auto left = door.seated >= seats ? 0 : seats - door.seated;
			quack_room = quack_room || left > 0;
			doors += string(doors.empty() ? "" : ",") + "{\"uri\":" + JsonQuote(door.uri) +
			         ",\"seated\":" + std::to_string(door.seated) + ",\"seats_left\":" + std::to_string(left) + "}";
		}
		quack = "{\"slots\":" + std::to_string(slots) + ",\"per_client\":" + std::to_string(per_client) +
		        ",\"seats\":" + std::to_string(seats) + ",\"doors\":[" + doors + "]}";
		// spec 080: the stream budget - what producing quack statements reserve, and who waits for room
		auto budget = AclNodeStreamBudget(db);
		auto reserve = AclQuackStreamReserve(db);
		auto now = store.stream_budget.Now();
		stream_room = now.queued == 0 && (now.reserved == 0 || now.reserved + reserve <= budget);
		streams = "{\"budget_bytes\":" + std::to_string(budget) + ",\"reserve_bytes\":" + std::to_string(reserve) +
		          ",\"reserved_bytes\":" + std::to_string(now.reserved) +
		          ",\"producing\":" + std::to_string(now.producing) + ",\"queued\":" + std::to_string(now.queued) +
		          ",\"refused\":" + std::to_string(now.refused) + "}";
	}
#endif
	// spec 140: the served doors' certificates - when each expires, when its pair was taken, and the class
	// of a renewal it refused (a door that re-reads its files says watched)
	string certificates;
	for (auto &certificate : store.DoorCertificates()) {
		certificates +=
		    string(certificates.empty() ? "" : ",") + "{\"door\":" + JsonQuote(certificate.door) +
		    ",\"watched\":" + (certificate.watched ? "true" : "false") +
		    ",\"not_after\":" + (certificate.not_after.empty() ? string("null") : JsonQuote(certificate.not_after)) +
		    ",\"refreshed_at\":" + std::to_string(certificate.refreshed_at) +
		    ",\"error\":" + (certificate.error.empty() ? string("null") : JsonQuote(certificate.error)) + "}";
	}
	return "{\"draining\":" + string(draining ? "true" : "false") +
	       ",\"observe\":" + (ObserveOpen(db) ? "\"open\"" : "\"token\"") +
	       ",\"group\":" + (group.empty() ? string("null") : JsonQuote(group)) +
	       ",\"group_known\":" + (group_known ? "true" : "false") +
	       ",\"group_default\":" + (group_default ? "true" : "false") +
	       ",\"label\":" + (label.empty() ? string("null") : JsonQuote(label)) + ",\"config\":{\"target\":" + target +
	       ",\"applied\":" + (applied < 0 ? string("null") : std::to_string(applied)) + "}" +
	       ",\"sessions\":{\"live\":" + std::to_string(live) + ",\"max\":" + std::to_string(max_sessions) +
	       ",\"by_door\":{" + by_door + "},\"by_group\":{" + groups + "}},\"quack\":" + quack +
	       ",\"streams\":" + streams + ",\"certificates\":[" + certificates + "]" +
	       ",\"admit\":{\"new_session\":" + (session_room ? "true" : "false") +
	       ",\"new_quack_client\":" + (session_room && quack_room ? "true" : "false") +
	       ",\"new_stream\":" + (stream_room ? "true" : "false") + "}}";
}

void RegisterAclNodeLoad(ExtensionLoader &loader, shared_ptr<PolicyStore> store) {
	ScalarFunction function(Identifier("acl_node_load"), {}, LogicalType::VARCHAR, AclNodeLoadFunc);
	MarkAclScalar(function, store);
	loader.RegisterFunction(function);
}

} // namespace acl
} // namespace duckdb
