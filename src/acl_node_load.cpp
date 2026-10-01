//===----------------------------------------------------------------------===//
// acl_node_load.cpp — what a node reports about its load (spec 079)
//===----------------------------------------------------------------------===//

#include "acl_node_load.hpp"

#include "acl_door_common.hpp"

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

string NodeLoadJson(DatabaseInstance &db, PolicyStore &store) {
	auto draining = store.Draining();
	auto live = store.SessionCount();
	auto max_sessions = SettingOf(db, "acl_max_sessions", 1000);
	// spec 096: the node's resource group and the profile version it targets / has applied. Read from
	// the policy, so guarded: the report answers callers that are not authenticated, and a source that
	// does not answer reads as "unknown", never as its own text
	auto group = store.NodeGroup();
	bool group_known = group.empty();
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
			target = policy.target;
			cached = true;
		}
	}
	if (!cached) {
		// a catalog this build may not read (spec 094) admits nobody: neither known nor targeted
		try {
			group_known = store.NodeGroupKnown();
		} catch (std::exception &) {
			group_known = false;
		}
		try {
			target = std::to_string(store.ClusterVersion());
		} catch (std::exception &) {
		}
		lock_guard<mutex> guard(store.lock);
		store.node_load_policy = {now, group, group_known, target, writes, true};
	}
	auto applied = store.cluster_applied.load();
	bool session_room = !draining && group_known && (max_sessions == 0 || live < max_sessions);

	string by_door;
	for (auto &door : store.SessionCountsByDoor()) {
		by_door += (by_door.empty() ? "" : ",") + JsonQuote(door.first) + ":" + std::to_string(door.second);
	}
	// spec 085: sessions per resource group that caps them - what an orchestrator routes a tenant by
	string groups;
	for (auto &group : store.SessionCountsByGroup()) {
		groups += (groups.empty() ? "" : ",") + JsonQuote(group.first) +
		          ":{\"live\":" + std::to_string(group.second.first) +
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
	return "{\"draining\":" + string(draining ? "true" : "false") +
	       ",\"group\":" + (group.empty() ? string("null") : JsonQuote(group)) +
	       ",\"group_known\":" + (group_known ? "true" : "false") + ",\"config\":{\"target\":" + target +
	       ",\"applied\":" + (applied < 0 ? string("null") : std::to_string(applied)) + "}" +
	       ",\"sessions\":{\"live\":" + std::to_string(live) + ",\"max\":" + std::to_string(max_sessions) +
	       ",\"by_door\":{" + by_door + "},\"by_group\":{" + groups + "}},\"quack\":" + quack +
	       ",\"streams\":" + streams + ",\"admit\":{\"new_session\":" + (session_room ? "true" : "false") +
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
