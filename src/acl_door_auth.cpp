//===----------------------------------------------------------------------===//
// acl_door_auth.cpp — the auth-discovery document (spec 064), shared by the doors
//===----------------------------------------------------------------------===//

#include "duckdb/common/error_data.hpp"
#include "duckdb/common/string_util.hpp"
#include "acl_door_auth.hpp"
#include "acl_door_common.hpp"

#include <chrono>
#include <mutex>
#include <unordered_map>

namespace duckdb {
namespace acl {

namespace {

// process-wide on purpose: a discovery document is the issuer's public metadata, the same for every
// database instance in the process, and fetching it once per instance would only multiply the round
// trips - nothing per-principal or per-instance lives here
std::mutex discovery_cache_lock; // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
std::unordered_map<string, std::pair<oidc::Endpoints, std::chrono::steady_clock::time_point>>
    discovery_cache; // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

} // namespace

oidc::Endpoints DiscoverEndpointsCached(PolicyStore &store, const string &issuer) {
	// spec 071: the node fetches from the network only where the operator allowed - the issuer's
	// discovery document is a fetch like a key document, judged by the same list (and not cached:
	// the list may change)
	// judged as what is fetched - the discovery document's URL, not the bare issuer - so a prefix
	// that names the realm with its trailing slash admits it, exactly as it admits the realm's keys
	auto document = issuer + (StringUtil::EndsWith(issuer, "/") ? "" : "/") + ".well-known/openid-configuration";
	string why;
	if (!store.JwksLocationAllowed(document, why)) {
		oidc::Endpoints refused;
		refused.issuer = issuer;
		refused.error = "the issuer's discovery is not read from here: " + why;
		return refused;
	}
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

//! The document itself; the guard below is what every caller gets. Spec 095: each issuer the node
//! can resolve now, by name and URL, its endpoints, and the clients a driver can run a flow as - a
//! client id is public; a client secret is never here.
static string DoorAuthDocument(PolicyStore &store) {
	string json = "{\"issuers\":[";
	idx_t written = 0;
	for (auto &issuer : store.DoorIssuers()) {
		if (written++ > 0) {
			json += ",";
		}
		json += "{\"name\":" + JsonQuote(issuer.name) + ",\"issuer\":" + JsonQuote(issuer.url);
		auto ep = DiscoverEndpointsCached(store, issuer.url);
		if (ep.Ok()) {
			json += ",\"token_endpoint\":" + JsonQuote(ep.token_endpoint);
			if (!ep.device_authorization_endpoint.empty()) {
				json += ",\"device_authorization_endpoint\":" + JsonQuote(ep.device_authorization_endpoint);
			}
			if (!ep.authorization_endpoint.empty()) {
				json += ",\"authorization_endpoint\":" + JsonQuote(ep.authorization_endpoint);
			}
		}
		json += ",\"clients\":[";
		idx_t listed = 0;
		for (auto &client : issuer.clients) {
			vector<string> flows;
			for (auto &flow : client.flows) {
				if (IsDriverFlow(flow)) {
					flows.push_back(JsonQuote(flow));
				}
			}
			if (flows.empty() || client.client_id.empty()) {
				continue; // nothing a driver can run as: not advertised
			}
			json += string(listed++ ? "," : "") + "{\"name\":" + JsonQuote(client.name) +
			        ",\"client_id\":" + JsonQuote(client.client_id) + ",\"flows\":[" + StringUtil::Join(flows, ",") +
			        "]}";
		}
		json += "]}";
	}
	json += "]}";
	return json;
}

string DoorAuthJson(PolicyStore &store, const char *door) {
	try {
		// cached for a few seconds within one policy version: the callers are unauthenticated, and a
		// document that names secret-held URLs and client ids is a read of the secrets service
		store.Identity(); // the freshness check first, so the version below is the source's, not a stale one
		auto version = store.PolicyVersion();
		auto now = std::chrono::steady_clock::now();
		{
			lock_guard<mutex> guard(store.lock);
			auto &cached = store.door_document;
			if (cached.policy_version == version && now - cached.at < std::chrono::seconds(10)) {
				return cached.document;
			}
		}
		auto document = DoorAuthDocument(store);
		lock_guard<mutex> guard(store.lock);
		store.door_document = {version, now, document};
		return document;
	} catch (std::exception &ex) {
		// the one place both doors build it, so the guard belongs here rather than at each call
		store.AuditDoor(door, "discovery", false, "source_error", ErrorData(ex).RawMessage());
		return "{\"issuers\":[]}";
	}
}

} // namespace acl
} // namespace duckdb
