// The OIDC client core (spec 060) against a fake IdP served in-process by the bundled httplib:
// discovery (with the RFC 8414 issuer check), client_credentials, password, refresh, the device
// flow's pending->granted poll, and the cache's refresh margin. No network, no sleeps beyond the
// poll's own zero-interval path. Build + run via `GEN=ninja make test-cpp`.

#include "acl_oidc.hpp"

#include "httplib.hpp"

#include <atomic>
#include <chrono>
#include <functional>
#include <iostream>
#include <string>
#include <thread>

using namespace duckdb::acl::oidc;

namespace {

int failures = 0;

bool Check(bool ok, const std::string &what) {
	std::cout << (ok ? "  ok:   " : "  FAIL: ") << what << std::endl;
	if (!ok) {
		failures++;
	}
	return ok;
}

void Scenario(const std::string &name, const std::function<void()> &body) {
	std::cout << name << std::endl;
	try {
		body();
	} catch (std::exception &ex) {
		Check(false, name + " aborted: " + std::string(ex.what()));
	}
}

//! The fake IdP: enough of an issuer for every flow the core speaks. Runs on a loopback port the
//! OS picks; `pending_polls` device polls answer authorization_pending before the grant.
struct FakeIdp {
	duckdb_httplib::Server server;
	std::thread thread;
	int port = 0;
	std::atomic<int> pending_polls {0};
	std::atomic<int> device_polls_seen {0};

	std::string Issuer() const {
		return "http://127.0.0.1:" + std::to_string(port);
	}

	void Start() {
		server.Get("/.well-known/openid-configuration",
		           [this](const duckdb_httplib::Request &, duckdb_httplib::Response &res) {
			           res.set_content("{\"issuer\":\"" + Issuer() + "\",\"token_endpoint\":\"" + Issuer() +
			                               "/token\",\"device_authorization_endpoint\":\"" + Issuer() + "/device\"}",
			                           "application/json");
		           });
		// a LYING document: served at /realms/other, speaking for the root issuer - discovery asked
		// about /realms/other must refuse it on the issuer check, not on a 404
		server.Get("/realms/other/.well-known/openid-configuration", [this](const duckdb_httplib::Request &,
		                                                                    duckdb_httplib::Response &res) {
			res.set_content("{\"issuer\":\"" + Issuer() + "\",\"token_endpoint\":\"" + Issuer() + "/token\"}",
			                "application/json");
		});
		// a canonical trailing slash: the advertised issuer ends in '/', the asked-for one does not
		server.Get("/slashy/.well-known/openid-configuration", [this](const duckdb_httplib::Request &,
		                                                              duckdb_httplib::Response &res) {
			res.set_content("{\"issuer\":\"" + Issuer() + "/slashy/\",\"token_endpoint\":\"" + Issuer() + "/token\"}",
			                "application/json");
		});
		server.Post("/device", [this](const duckdb_httplib::Request &, duckdb_httplib::Response &res) {
			res.set_content("{\"device_code\":\"dc-1\",\"user_code\":\"WDJB-MJHT\",\"verification_uri\":\"" + Issuer() +
			                    "/activate\",\"interval\":0,\"expires_in\":60}",
			                "application/json");
		});
		server.Post("/token", [this](const duckdb_httplib::Request &req, duckdb_httplib::Response &res) {
			auto grant = req.get_param_value("grant_type");
			auto deny = [&](const std::string &code, const std::string &description) {
				res.status = 400;
				res.set_content("{\"error\":\"" + code + "\",\"error_description\":\"" + description + "\"}",
				                "application/json");
			};
			if (grant == "client_credentials") {
				if (req.get_param_value("client_id") == "svc" && req.get_param_value("client_secret") == "s3cr3t") {
					res.set_content("{\"access_token\":\"cc-token\",\"expires_in\":120}", "application/json");
				} else {
					deny("invalid_client", "bad client secret");
				}
				return;
			}
			if (grant == "password") {
				if (req.get_param_value("username") == "analyst" && req.get_param_value("password") == "pw") {
					res.set_content("{\"access_token\":\"pw-token\",\"refresh_token\":\"rt-1\",\"expires_in\":60}",
					                "application/json");
				} else {
					deny("invalid_grant", "wrong credentials");
				}
				return;
			}
			if (grant == "refresh_token") {
				if (req.get_param_value("refresh_token") == "rt-1") {
					res.set_content("{\"access_token\":\"pw-token-2\",\"expires_in\":60}", "application/json");
				} else {
					deny("invalid_grant", "unknown refresh token");
				}
				return;
			}
			if (grant == "urn:ietf:params:oauth:grant-type:device_code") {
				device_polls_seen++;
				if (req.get_param_value("device_code") != "dc-1") {
					deny("access_denied", "unknown device code");
				} else if (pending_polls.fetch_sub(1) > 0) {
					deny("authorization_pending", "the user has not approved yet");
				} else {
					res.set_content("{\"access_token\":\"device-token\",\"expires_in\":90}", "application/json");
				}
				return;
			}
			deny("unsupported_grant_type", grant);
		});
		port = server.bind_to_any_port("127.0.0.1");
		thread = std::thread([this] { server.listen_after_bind(); });
		server.wait_until_ready();
	}

	void Stop() {
		server.stop();
		if (thread.joinable()) {
			thread.join();
		}
	}
};

} // namespace

int main() {
	std::cout << "=== the OIDC client core against a fake IdP (spec 060) ===" << std::endl;
	FakeIdp idp;
	idp.Start();

	Endpoints ep;
	Scenario("discovery finds the endpoints and checks the issuer", [&] {
		ep = Discover(idp.Issuer());
		Check(ep.Ok(), "discovery succeeds: " + ep.error);
		Check(ep.token_endpoint == idp.Issuer() + "/token", "token endpoint discovered");
		Check(!ep.device_authorization_endpoint.empty(), "device endpoint discovered");
		auto mismatch = Discover(idp.Issuer() + "/realms/other");
		Check(!mismatch.Ok() && mismatch.error.find("issuer mismatch") != std::string::npos,
		      "a document speaking for another issuer is refused ON THE ISSUER CHECK: " + mismatch.error);
		auto slashy = Discover(idp.Issuer() + "/slashy");
		Check(slashy.Ok(),
		      "a canonical trailing slash in the advertised issuer is normalised, not refused: " + slashy.error);
	});

	Scenario("client_credentials - the machine identity flow", [&] {
		auto granted = ClientCredentials(ep, "svc", "s3cr3t");
		Check(granted.Ok() && granted.access_token == "cc-token", "the right secret earns a token");
		Check(granted.expires_at > 0, "the expiry travelled");
		auto denied = ClientCredentials(ep, "svc", "wrong");
		Check(!denied.Ok() && denied.error_code == "invalid_client",
		      "a wrong secret is the protocol's own refusal: " + denied.error);
	});

	Scenario("password grant and its refresh", [&] {
		auto granted = PasswordGrant(ep, "cli", "", "analyst", "pw");
		Check(granted.Ok() && granted.access_token == "pw-token", "user/password earns a token");
		Check(granted.refresh_token == "rt-1", "with a refresh token");
		auto renewed = RefreshGrant(ep, "cli", "", granted.refresh_token);
		Check(renewed.Ok() && renewed.access_token == "pw-token-2", "the refresh renews silently");
		auto denied = PasswordGrant(ep, "cli", "", "analyst", "nope");
		Check(!denied.Ok() && denied.error_code == "invalid_grant", "wrong credentials refused");
	});

	Scenario("device flow - begin, pending, granted", [&] {
		auto begun = DeviceBegin(ep, "cli");
		Check(begun.Ok() && begun.user_code == "WDJB-MJHT", "the user gets a code to type");
		idp.pending_polls = 2;
		auto deadline =
		    std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
		        .count() +
		    30;
		auto granted = DevicePoll(ep, "cli", begun.device_code, /*interval*/ 0, deadline);
		Check(granted.Ok() && granted.access_token == "device-token",
		      "the poll rides out authorization_pending: " + granted.error);
		Check(idp.device_polls_seen >= 3, "at least two pendings were actually answered before the grant");
		auto denied = DevicePoll(ep, "cli", "dc-bogus", 0, deadline);
		Check(!denied.Ok() && denied.error_code == "access_denied", "an unknown device code is refused");
	});

	Scenario("the cache serves only tokens with margin left", [&] {
		auto &cache = TokenCache::Instance();
		TokenSet fresh;
		fresh.access_token = "cached";
		fresh.expires_at =
		    std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
		        .count() +
		    600;
		cache.Set(&idp, "kc", fresh);
		Check(cache.Get(&idp, "kc").access_token == "cached", "a fresh token is served");
		Check(cache.Get(&idp, "kc", /*margin*/ 700).access_token.empty(),
		      "inside the margin it is not served (and the stale row is dropped)");
		Check(cache.Get(&idp, "kc").access_token.empty(), "the stale read erased it");
		cache.Set(&idp, "kc", fresh);
		cache.Invalidate(&idp, "kc");
		Check(cache.Get(&idp, "kc").access_token.empty(), "invalidate removes it");
	});

	idp.Stop();
	std::cout << (failures == 0 ? "PASS" : "FAIL") << " test_acl_oidc" << std::endl;
	return failures == 0 ? 0 : 1;
}
