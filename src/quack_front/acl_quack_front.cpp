//===----------------------------------------------------------------------===//
// acl_quack_front.cpp — the quack door's front listener (spec 062). See header.
//
// One more TU that compiles duckdb's bundled httplib (the single-TU discipline
// of specs 060/061): with ACL_OIDC_TLS it carries CPPHTTPLIB_OPENSSL_SUPPORT
// and the SSLServer; without it the front is cleartext-only and says so.
//===----------------------------------------------------------------------===//

#ifdef ACL_OIDC_TLS
#define CPPHTTPLIB_OPENSSL_SUPPORT
#endif
#include "httplib.hpp"

#include "acl_quack_front.hpp"

#include "duckdb/main/database.hpp"

#include <map>
#include <memory>
#include <mutex>
#include <thread>

#ifdef ACL_OIDC_TLS
namespace hl = duckdb_httplib_openssl;
#else
namespace hl = duckdb_httplib;
#endif

namespace duckdb {
namespace acl {

namespace {

struct Front {
	std::unique_ptr<hl::Server> server;
	std::thread listener;
	int internal_port = 0;
	weak_ptr<DatabaseInstance> owner;
#ifdef ACL_OIDC_TLS
	X509 *cert = nullptr;
	EVP_PKEY *key = nullptr;
#endif

	~Front() {
		if (server) {
			server->stop();
		}
		if (listener.joinable()) {
			listener.join();
		}
#ifdef ACL_OIDC_TLS
		if (cert) {
			X509_free(cert);
		}
		if (key) {
			EVP_PKEY_free(key);
		}
#endif
	}
};

std::mutex fronts_lock;
std::map<std::string, std::unique_ptr<Front>> fronts;

std::string Key(const std::string &host, int port) {
	return host + ":" + std::to_string(port);
}

//! Streamed pass-through to the loopback quack: the method, path, body and
//! content type travel; quack's protocol is POST bodies, so this is the whole
//! of it. The proxy client is per-request — quack's own server closes
//! connections on its schedule, and a stale kept-alive socket would turn into
//! spurious refusals.
void Proxy(int internal_port, const hl::Request &request, hl::Response &response) {
	hl::Client upstream("127.0.0.1", internal_port);
	upstream.set_connection_timeout(10);
	upstream.set_read_timeout(600); // a drain of a large SEND_DATA body is legitimate work
	auto content_type = request.get_header_value("Content-Type");
	hl::Result answer;
	if (request.method == "POST") {
		answer = upstream.Post(request.path, request.body,
		                       content_type.empty() ? "application/octet-stream" : content_type.c_str());
	} else if (request.method == "GET") {
		answer = upstream.Get(request.path);
	} else {
		response.status = 405;
		return;
	}
	if (!answer) {
		response.status = 502;
		response.set_content("quack front: upstream unreachable", "text/plain");
		return;
	}
	response.status = answer->status;
	auto answer_type = answer->get_header_value("Content-Type");
	response.set_content(answer->body, answer_type.empty() ? "application/octet-stream" : answer_type.c_str());
}

} // namespace

int FreeLoopbackPort() {
	hl::Server probe;
	auto port = probe.bind_to_any_port("127.0.0.1");
	probe.stop();
	return port;
}

std::string StartQuackFront(const QuackFrontConfig &config) {
	auto front = std::make_unique<Front>();
	if (!config.cert_pem.empty() || !config.key_pem.empty()) {
#ifdef ACL_OIDC_TLS
		if (config.cert_pem.empty() || config.key_pem.empty()) {
			return "quack front: TLS needs both a certificate and a key";
		}
		auto *cert_bio = BIO_new_mem_buf(config.cert_pem.data(), int(config.cert_pem.size()));
		front->cert = PEM_read_bio_X509(cert_bio, nullptr, nullptr, nullptr);
		BIO_free(cert_bio);
		auto *key_bio = BIO_new_mem_buf(config.key_pem.data(), int(config.key_pem.size()));
		front->key = PEM_read_bio_PrivateKey(key_bio, nullptr, nullptr, nullptr);
		BIO_free(key_bio);
		if (!front->cert || !front->key) {
			return "quack front: the certificate or key did not parse as PEM";
		}
		auto tls = std::make_unique<hl::SSLServer>(front->cert, front->key);
		if (!tls->is_valid()) {
			return "quack front: the TLS context refused the certificate/key pair";
		}
		front->server = std::move(tls);
#else
		return "quack front: TLS needs a build that carries OpenSSL (the flight build) - "
		       "this build can front cleartext only";
#endif
	} else {
		front->server = std::make_unique<hl::Server>();
	}

	auto wellknown = config.wellknown;
	front->server->Get("/.well-known/quack-auth", [wellknown](const hl::Request &, hl::Response &response) {
		// metadata only, unauthenticated by design: the same class of fact OIDC discovery itself
		// publishes - where to authenticate, nothing about who may. Composed per request, so the
		// document tracks the policy live.
		response.set_content(wellknown ? wellknown() : "{\"issuers\":[]}", "application/json");
	});
	auto internal_port = config.internal_port;
	front->server->Post(".*", [internal_port](const hl::Request &request, hl::Response &response) {
		Proxy(internal_port, request, response);
	});
	front->server->Get(".*", [internal_port](const hl::Request &request, hl::Response &response) {
		Proxy(internal_port, request, response);
	});

	if (!front->server->bind_to_port(config.host.c_str(), config.port)) {
		return "quack front: could not bind " + Key(config.host, config.port);
	}
	auto *server = front->server.get();
	front->listener = std::thread([server] { server->listen_after_bind(); });
	front->server->wait_until_ready();

	front->internal_port = config.internal_port;
	front->owner = config.owner;
	std::lock_guard<std::mutex> guard(fronts_lock);
	auto key = Key(config.host, config.port);
	auto existing = fronts.find(key);
	if (existing != fronts.end()) {
		// a front whose serving instance is gone is a leak, not a live door - reclaim it and take
		// its place rather than refuse the address forever (the review's finding)
		if (!existing->second->owner.expired()) {
			return "quack front: " + key + " is already served";
		}
		fronts.erase(existing); // ~Front stops and joins the zombie listener
	}
	fronts[key] = std::move(front);
	return "";
}

bool StopQuackFront(const std::string &host, int port, int &internal_port_out) {
	std::unique_ptr<Front> gone;
	{
		std::lock_guard<std::mutex> guard(fronts_lock);
		auto entry = fronts.find(Key(host, port));
		if (entry == fronts.end()) {
			return false;
		}
		gone = std::move(entry->second);
		fronts.erase(entry);
	}
	internal_port_out = gone->internal_port;
	return true; // ~Front stops and joins outside the lock
}

} // namespace acl
} // namespace duckdb
