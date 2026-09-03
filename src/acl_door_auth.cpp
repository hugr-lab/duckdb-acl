//===----------------------------------------------------------------------===//
// acl_door_auth.cpp — the auth-discovery document (spec 064), shared by the doors
//===----------------------------------------------------------------------===//

#include "acl_door_auth.hpp"
#include "acl_door_common.hpp"

#include "duckdb/common/string_util.hpp"

#include <chrono>
#include <mutex>
#include <unordered_map>

namespace duckdb {
namespace acl {

namespace {

std::mutex discovery_cache_lock;
std::unordered_map<string, std::pair<oidc::Endpoints, std::chrono::steady_clock::time_point>> discovery_cache;

} // namespace

oidc::Endpoints DiscoverEndpointsCached(const string &issuer) {
	auto now = std::chrono::steady_clock::now();
	{
		std::lock_guard<std::mutex> guard(discovery_cache_lock);
		auto entry = discovery_cache.find(issuer);
		if (entry != discovery_cache.end()) {
			auto ttl = std::chrono::seconds(entry->second.first.Ok() ? 300 : 30);
			if (now - entry->second.second < ttl) {
				return entry->second.first;
			}
		}
	}
	auto ep = oidc::Discover(issuer);
	std::lock_guard<std::mutex> guard(discovery_cache_lock);
	discovery_cache[issuer] = {ep, now};
	return ep;
}

string DoorAuthJson(PolicyStore &store) {
	string json = "{\"issuers\":[";
	auto issuers = store.ListIssuers();
	for (idx_t i = 0; i < issuers.size(); i++) {
		if (i > 0) {
			json += ",";
		}
		json += "{\"issuer\":" + JsonQuote(issuers[i]);
		IssuerConfig config;
		if (store.LookupIssuer(issuers[i], config) && !config.client_id.empty()) {
			json += ",\"client_id\":" + JsonQuote(config.client_id);
		}
		auto ep = DiscoverEndpointsCached(issuers[i]);
		if (ep.Ok()) {
			json += ",\"token_endpoint\":" + JsonQuote(ep.token_endpoint);
			if (!ep.device_authorization_endpoint.empty()) {
				json += ",\"device_authorization_endpoint\":" + JsonQuote(ep.device_authorization_endpoint);
			}
		}
		json += "}";
	}
	json += "]}";
	return json;
}

} // namespace acl
} // namespace duckdb
