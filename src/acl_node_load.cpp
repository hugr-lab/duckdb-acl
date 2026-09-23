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
	bool session_room = !draining && (max_sessions == 0 || live < max_sessions);

	string by_door;
	for (auto &door : store.SessionCountsByDoor()) {
		by_door += (by_door.empty() ? "" : ",") + JsonQuote(door.first) + ":" + std::to_string(door.second);
	}

	string quack = "null";
	bool quack_room = false;
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
	}
#endif
	return "{\"draining\":" + string(draining ? "true" : "false") + ",\"sessions\":{\"live\":" + std::to_string(live) +
	       ",\"max\":" + std::to_string(max_sessions) + ",\"by_door\":{" + by_door + "}},\"quack\":" + quack +
	       ",\"admit\":{\"new_session\":" + (session_room ? "true" : "false") +
	       ",\"new_quack_client\":" + (session_room && quack_room ? "true" : "false") + "}}";
}

void RegisterAclNodeLoad(ExtensionLoader &loader, shared_ptr<PolicyStore> store) {
	ScalarFunction function(Identifier("acl_node_load"), {}, LogicalType::VARCHAR, AclNodeLoadFunc);
	MarkAclScalar(function, store);
	loader.RegisterFunction(function);
}

} // namespace acl
} // namespace duckdb
