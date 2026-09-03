//===----------------------------------------------------------------------===//
// acl_quack_http_server.cpp — the embedded quack door's listener (spec 063)
//
// AclQuackServer is a sibling of quack's HttpQuackServer: it derives the same
// QuackServer base (so the protocol — HandleMessage and the whole connection
// lifecycle — is quack's own, unchanged), but owns the httplib listener so it can
// (1) bind the PUBLIC address directly, (2) terminate TLS here, and (3) answer the
// unauthenticated GET /.well-known/quack-auth. The loopback proxy of spec 062 is
// gone: a remote client's request lands on this one listener.
//
// The ElasticThreadPool and the POST /quack plumbing are copied verbatim from
// quack_http_server.cpp @ f28823d (re-sync on a submodule bump); only the TLS
// branch, the discovery route, and the acl_quack_* settings are acl's.
//
// This TU is force-included with acl_quack_httplib_ns.hpp (CMake) so quack's
// hardcoded `duckdb_httplib::` names resolve onto the OpenSSL namespace when TLS
// is compiled in.
//===----------------------------------------------------------------------===//

#include "duckdb/common/serializer/memory_stream.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/main/database.hpp"

#include "quack_server.hpp"
#include "quack_message.hpp"
#include "quack_uri.hpp"

#include "acl_quack_server.hpp"

#include "httplib.hpp"

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
#include "mbedtls_wrapper.hpp"
#include <openssl/rand.h>
#include <type_traits>
#endif

#include <condition_variable>
#include <deque>
#include <map>
#include <mutex>
#include <thread>
#include <unordered_set>

namespace duckdb {
namespace acl {
namespace {

//! Verbatim from quack_http_server.cpp: httplib hands each accepted socket to the task queue as one
//! task spanning the connection's whole keep-alive lifetime, so a fixed pool deadlocks once idle
//! connections pin every worker. This pool grows a thread per connection up to `max_threads` and
//! sheds at the cap (clients retry). In acl's anonymous namespace so a co-loaded quack never clashes.
class ElasticThreadPool final : public duckdb_httplib::TaskQueue {
public:
	explicit ElasticThreadPool(idx_t max_threads_p) : max_threads(max_threads_p) {
	}

	~ElasticThreadPool() override {
		shutdown();
	}

	bool enqueue(std::function<void()> fn) override {
		std::unique_lock<std::mutex> guard(lock);
		JoinFinishedWorkers(guard);
		if (shutting_down) {
			return false;
		}
		if (idle_workers > jobs.size()) {
			jobs.push_back(std::move(fn));
			cv.notify_one();
			return true;
		}
		if (live_workers >= max_threads) {
			return false;
		}
		jobs.push_back(std::move(fn));
		try {
			workers.emplace_back(&ElasticThreadPool::WorkerLoop, this);
		} catch (...) {
			jobs.pop_back();
			return false;
		}
		live_workers++;
		return true;
	}

	void shutdown() override {
		std::unique_lock<std::mutex> guard(lock);
		if (!shutting_down) {
			shutting_down = true;
			cv.notify_all();
		}
		done_cv.wait(guard, [&] { return live_workers == 0; });
		JoinFinishedWorkers(guard);
	}

private:
	void WorkerLoop() {
		std::unique_lock<std::mutex> guard(lock);
		for (;;) {
			idle_workers++;
			bool has_work = cv.wait_for(guard, std::chrono::milliseconds(IDLE_WORKER_TIMEOUT_MS),
			                            [&] { return !jobs.empty() || shutting_down; });
			idle_workers--;
			if (!jobs.empty()) {
				auto fn = std::move(jobs.front());
				jobs.pop_front();
				guard.unlock();
				fn();
				guard.lock();
				continue;
			}
			if (shutting_down || !has_work) {
				break;
			}
		}
		live_workers--;
		finished_workers.insert(std::this_thread::get_id());
		if (shutting_down && live_workers == 0) {
			done_cv.notify_all();
		}
	}

	void JoinFinishedWorkers(std::unique_lock<std::mutex> &guard) {
		if (finished_workers.empty()) {
			return;
		}
		std::vector<std::thread> to_join;
		for (auto it = workers.begin(); it != workers.end();) {
			if (finished_workers.count(it->get_id())) {
				finished_workers.erase(it->get_id());
				to_join.push_back(std::move(*it));
				it = workers.erase(it);
			} else {
				++it;
			}
		}
		guard.unlock();
		for (auto &thread : to_join) {
			thread.join();
		}
		guard.lock();
	}

	static constexpr uint64_t IDLE_WORKER_TIMEOUT_MS = 30000;

	const idx_t max_threads;
	std::mutex lock;
	std::condition_variable cv;
	std::condition_variable done_cv;
	std::deque<std::function<void()>> jobs;
	std::vector<std::thread> workers;
	std::unordered_set<std::thread::id> finished_workers;
	idx_t live_workers = 0;
	idx_t idle_workers = 0;
	bool shutting_down = false;
};

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
//! The door mints session ids and server tokens from a CSPRNG. duckdb's default crypto module is
//! read-only (it refuses to hand out an RNG unless httpfs is loaded), and its bundled mbedtls RNG is a
//! non-crypto PRNG (RandomEngine) gated behind `force_mbedtls_unsafe` — unfit for auth tokens. We
//! already link OpenSSL for Arrow Flight, so the door's RNG comes from OpenSSL's `RAND_bytes`. The
//! rest of the EncryptionUtil surface (Hash/Hmac) is inherited from duckdb's mbedtls factory, which is
//! correct and ungated; the door never encrypts through the util, so the cipher path stays the base's.
struct AclDoorRandomState : public EncryptionState {
	explicit AclDoorRandomState(unique_ptr<EncryptionStateMetadata> metadata) : EncryptionState(std::move(metadata)) {
	}
	void GenerateRandomData(data_ptr_t data, idx_t len) override {
		if (RAND_bytes(data, NumericCast<int>(len)) != 1) {
			throw InternalException("OpenSSL RAND_bytes failed");
		}
	}
};

struct AclDoorCryptoUtil : public duckdb_mbedtls::MbedTlsWrapper::AESStateMBEDTLSFactory {
	shared_ptr<EncryptionState> CreateEncryptionState(unique_ptr<EncryptionStateMetadata> metadata) const override {
		return make_shared_ptr<AclDoorRandomState>(std::move(metadata));
	}
};

std::mutex g_crypto_lock;

//! duckdb main's httplib (>=0.53) dropped SSLServer(X509*, EVP_PKEY*) for SSLServer(PemMemory); our
//! older pinned duckdb still has the X509 pair. We build against the pin locally and against duckdb
//! main at the distribution stage, so detect which constructor the header carries.
template <typename S, typename = void>
struct HasPemMemoryCtor : std::false_type {};
template <typename S>
struct HasPemMemoryCtor<S, std::void_t<typename S::PemMemory>> : std::true_type {};

//! Build an SSLServer from inline PEM across both httplib generations. Modern: inline PEM straight in
//! (nothing to own). Legacy: parse PEM into an X509/EVP_PKEY pair the caller then owns (cert_out/
//! key_out), returning null if it does not parse. A template so `if constexpr` discards - rather than
//! compiles - the branch whose constructor this header lacks.
template <typename S = duckdb_httplib::SSLServer>
std::unique_ptr<S> MakeTlsServer(const string &cert_pem, const string &key_pem, X509 *&cert_out, EVP_PKEY *&key_out) {
	if constexpr (HasPemMemoryCtor<S>::value) {
		typename S::PemMemory pem {};
		pem.cert_pem = cert_pem.c_str();
		pem.cert_pem_len = cert_pem.size();
		pem.key_pem = key_pem.c_str();
		pem.key_pem_len = key_pem.size();
		return make_uniq<S>(pem);
	} else {
		auto *cert_bio = BIO_new_mem_buf(cert_pem.data(), int(cert_pem.size()));
		cert_out = PEM_read_bio_X509(cert_bio, nullptr, nullptr, nullptr);
		BIO_free(cert_bio);
		auto *key_bio = BIO_new_mem_buf(key_pem.data(), int(key_pem.size()));
		key_out = PEM_read_bio_PrivateKey(key_bio, nullptr, nullptr, nullptr);
		BIO_free(key_bio);
		if (!cert_out || !key_out) {
			return nullptr;
		}
		return make_uniq<S>(cert_out, key_out);
	}
}

//! Give the instance a real crypto module for the server's RNG if it has none — WITHOUT loading httpfs
//! or the unsafe mbedtls flag. Only-if-empty, so a loaded httpfs (its own OpenSSL util) always wins,
//! and only at serve time, so a non-serving instance keeps duckdb's default crypto posture. The lock
//! keeps two concurrent serves from racing on the shared_ptr assignment.
void EnsureDoorCryptoModule(ClientContext &context) {
	auto &config = DBConfig::GetConfig(*context.db);
	std::lock_guard<std::mutex> guard(g_crypto_lock);
	if (!config.encryption_util) {
		config.encryption_util = make_shared_ptr<AclDoorCryptoUtil>();
	}
}
#endif

enum class AclServerState { WAITING_TO_START, RUNNING, CLOSED };

//! The acl-owned listener. Same base as HttpQuackServer, same POST /quack protocol; the difference is
//! the public bind, the TLS branch and the discovery route.
class AclQuackServer : public QuackServer {
public:
	AclQuackServer(ClientContext &context, const QuackUri &uri_p, const string &token_p, const string &cert_pem,
	               const string &key_pem, std::function<string()> wellknown, std::function<bool()> draining,
	               bool discovery);
	~AclQuackServer() override;

	void StopAccepting() override;
	void Close() override;

	//! True once the DatabaseInstance that served this listener is gone. A server left in the registry
	//! by an instance destroyed without acl_quack_stop is a leak, not a live door - a later serve of
	//! the same address reclaims it rather than refusing forever (spec 062 review, kept in 063).
	bool OwnerExpired() const {
		return db_ptr.expired();
	}
	//! Whether this database instance opened the server: the registry is per process, and a stop or
	//! a "last door" count from another instance would act on the wrong sessions (the 2026-09-03
	//! review).
	bool OwnedBy(const DatabaseInstance &db) const {
		auto owner = db_ptr.lock();
		return owner.get() == &db;
	}

private:
	static void ListenThread(AclQuackServer *self);

	std::unique_ptr<duckdb_httplib::Server> server;
	std::mutex state_lock;
	AclServerState server_state = AclServerState::WAITING_TO_START;
	std::function<string()> wellknown;
	std::function<bool()> draining;
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
	X509 *tls_cert = nullptr;
	EVP_PKEY *tls_key = nullptr;
#endif
};

AclQuackServer::AclQuackServer(ClientContext &context, const QuackUri &uri_p, const string &token_p,
                               const string &cert_pem, const string &key_pem, std::function<string()> wellknown_p,
                               std::function<bool()> draining_p, bool discovery)
    : QuackServer(context, uri_p, token_p), wellknown(std::move(wellknown_p)), draining(std::move(draining_p)) {
	if (!cert_pem.empty() || !key_pem.empty()) {
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
		if (cert_pem.empty() || key_pem.empty()) {
			throw IOException("acl_quack_serve: TLS needs both a certificate and a key");
		}
		auto tls = MakeTlsServer(cert_pem, key_pem, tls_cert, tls_key);
		if (!tls) {
			throw IOException("acl_quack_serve: the certificate or key did not parse as PEM");
		}
		if (!tls->is_valid()) {
			throw IOException("acl_quack_serve: the TLS context refused the certificate/key pair");
		}
		server = std::move(tls);
#else
		throw IOException("acl_quack_serve: TLS needs a build that carries OpenSSL (the flight build) - "
		                  "this build serves cleartext only");
#endif
	} else {
		server = make_uniq<duckdb_httplib::Server>();
	}

	auto &db_config = DBConfig::GetConfig(*context.db);
	Value max_connections_val = Value::UBIGINT(1024);
	db_config.TryGetCurrentSetting("acl_quack_server_max_connections", max_connections_val);
	auto max_connections = MaxValue<idx_t>(1, max_connections_val.GetValue<idx_t>());
	Value keep_alive_timeout_val = Value::UBIGINT(300);
	db_config.TryGetCurrentSetting("acl_quack_server_keep_alive_timeout", keep_alive_timeout_val);
	auto keep_alive_timeout = MaxValue<idx_t>(1, keep_alive_timeout_val.GetValue<idx_t>());

	server->new_task_queue = [max_connections] {
		return new ElasticThreadPool(max_connections);
	};
	server->set_keep_alive_max_count(1 << 20);
	server->set_keep_alive_timeout(NumericCast<time_t>(keep_alive_timeout));
	server->set_tcp_nodelay(true);

	server->Get("/", [](const duckdb_httplib::Request &, duckdb_httplib::Response &res) {
		res.set_content("This is a DuckDB Quack RPC endpoint. Use ATTACH 'quack:...' to connect here.\n", "text/plain");
	});

	// Unauthenticated discovery, by design: the same class of fact OIDC discovery itself publishes -
	// where to authenticate, nothing about who may. Composed per request, so it tracks policy live.
	// `mode := 'plain'` leaves it off entirely - a bare quack server.
	if (discovery) {
		auto wk = wellknown;
		auto dr = draining;
		server->Get("/.well-known/quack-auth",
		            [wk, dr](const duckdb_httplib::Request &, duckdb_httplib::Response &res) {
			            // A draining node (spec 066) answers 503 here BEFORE the document: this route is what a
			            // load balancer's health check watches, and new connections are refused anyway.
			            if (dr && dr()) {
				            res.status = 503;
				            res.set_content("draining", "text/plain");
				            return;
			            }
			            res.set_content(wk ? wk() : "{\"issuers\":[]}", "application/json");
		            });
	}

	server->Options("/quack", [](const duckdb_httplib::Request &, duckdb_httplib::Response &res) {
		res.set_header("Access-Control-Allow-Origin", "*");
		res.set_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
		res.set_header("Access-Control-Allow-Headers", "*");
		res.status = 204;
	});

	server->Post("/quack", [&](const duckdb_httplib::Request &, duckdb_httplib::Response &res,
	                           const duckdb_httplib::ContentReader &content_reader) {
		res.set_header("Access-Control-Allow-Origin", "*");
		MemoryStream stream;
		content_reader([&](const char *data, size_t data_length) {
			stream.WriteData((data_ptr_t)data, data_length);
			return true;
		});
		auto response = HandleMessage(stream);
		auto raw = response->RawPayload();
		if (raw) {
			auto data = const_char_ptr_cast(raw->GetData());
			auto size = raw->GetPosition();
			shared_ptr<QuackMessage> owned(std::move(response));
			res.set_content_provider(size, "application/vnd.duckdb",
			                         [owned, data](size_t offset, size_t length, duckdb_httplib::DataSink &sink) {
				                         sink.write(data + offset, length);
				                         return true;
			                         });
		} else {
			response->ToMemoryStream(stream);
			res.set_content((const char *)stream.GetData(), stream.GetPosition(), "application/vnd.duckdb");
		}
	});

	if (!server->is_valid()) {
		throw IOException("acl_quack_serve: failed to instantiate the server at %s", uri_p.Http());
	}

	bool success;
	if (uri_p.Port() == 0) {
		int actual_port = server->bind_to_any_port(uri_p.Host());
		success = actual_port >= 0;
		if (success) {
			uri = QuackUri(uri_p, NumericCast<uint16_t>(actual_port));
		}
	} else {
		success = server->bind_to_port(uri_p.Host(), uri_p.Port());
	}
	if (!success) {
		throw IOException("acl_quack_serve: failed to bind %s (address in use, permission denied, or invalid "
		                  "host/port)",
		                  uri_p.Http());
	}

	server_state = AclServerState::WAITING_TO_START;
	listen_threads.emplace_back(ListenThread, this);
}

void AclQuackServer::ListenThread(AclQuackServer *self) {
	D_ASSERT(self->server);
	{
		std::lock_guard<std::mutex> guard(self->state_lock);
		if (self->server_state != AclServerState::WAITING_TO_START) {
			return;
		}
		self->server_state = AclServerState::RUNNING;
	}
	try {
		self->server->listen_after_bind();
	} catch (...) {
		self->server_state = AclServerState::CLOSED;
	}
}

void AclQuackServer::StopAccepting() {
	std::lock_guard<std::mutex> guard(state_lock);
	if (server_state == AclServerState::RUNNING) {
		server->wait_until_ready();
		server->stop();
		server->decommission();
	}
	server_state = AclServerState::CLOSED;
}

void AclQuackServer::Close() {
	StopAccepting();
	for (auto &thread : listen_threads) {
		if (thread.joinable()) {
			thread.join();
		}
	}
}

AclQuackServer::~AclQuackServer() {
	try {
		AclQuackServer::Close();
	} catch (std::exception &) {
	}
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
	if (tls_cert) {
		X509_free(tls_cert);
	}
	if (tls_key) {
		EVP_PKEY_free(tls_key);
	}
#endif
}

//! Process-wide registry of embedded servers, keyed by canonical uri (host:port). Mirrors quack's own
//! per-instance map, but acl's door is one-per-process by uri and the ops surface stays tiny.
std::mutex g_servers_lock;
std::map<string, unique_ptr<AclQuackServer>> g_servers;

} // namespace

string StartAclQuackServer(ClientContext &context, const AclQuackServeConfig &cfg, string &actual_uri_out) {
	try {
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
		// The server's token/session RNG needs a crypto module; give it OpenSSL's before it starts, so a
		// plain flight build serves with neither `LOAD httpfs` nor `force_mbedtls_unsafe`.
		EnsureDoorCryptoModule(context);
#endif
		// The server always listens without SSL at the socket level UNLESS we hand it cert/key; the
		// QuackUri's own ssl flag is about how a CLIENT dials, so build it cleartext here.
		QuackUri listen_uri(cfg.uri, /* ssl */ false);

		// Reclaim a leaked server of a dead instance BEFORE we bind, so its port is actually freed - a
		// live zombie still holding the port would otherwise fail our bind before we ever got here
		// (don't rely on SO_REUSEPORT). Keyed by the requested uri; an auto-port :0 serve never
		// collides, so it needs no reclaim. A live server on this address is refused, untouched.
		{
			unique_ptr<AclQuackServer> zombie;
			{
				std::lock_guard<std::mutex> guard(g_servers_lock);
				auto existing = g_servers.find(listen_uri.CanonicalUri());
				if (existing != g_servers.end()) {
					if (!existing->second->OwnerExpired()) {
						return "a server is already listening on " + listen_uri.CanonicalUri();
					}
					zombie = std::move(existing->second);
					g_servers.erase(existing);
				}
			}
			if (zombie) {
				zombie->StopAccepting(); // free the listening socket now
				zombie.reset();          // join the listener outside the lock
			}
		}

		auto server = make_uniq<AclQuackServer>(context, listen_uri, cfg.token, cfg.cert_pem, cfg.key_pem,
		                                        cfg.wellknown, cfg.draining, cfg.discovery);
		auto key = server->ListenUri().CanonicalUri();
		actual_uri_out = server->ListenUri().Uri();
		std::lock_guard<std::mutex> guard(g_servers_lock);
		if (g_servers.find(key) != g_servers.end()) {
			// another serve took this address between our reclaim and our bind
			return "a server is already listening on " + key;
		}
		g_servers.emplace(key, std::move(server));
		return "";
	} catch (IOException &) {
		// a bind or PEM failure is the environment's, not the policy's: it keeps its IO class all the
		// way to the caller (the error contract, docs/security.md section 8)
		throw;
	} catch (std::exception &ex) {
		string message = ex.what();
		// The server's token/session RNG needs a writable crypto module; without one the raw mbedtls
		// message is opaque. Point at the fix acl deployments already use (httpfs is loaded for JWKS).
		if (message.find("crypto module") != string::npos || message.find("force_mbedtls_unsafe") != string::npos) {
			return "the server needs a writable crypto module for its token/session RNG - "
			       "`LOAD httpfs` (the usual choice, also used for JWKS) or `SET force_mbedtls_unsafe='true'` "
			       "before serving. (" +
			       message + ")";
		}
		return message;
	}
}

bool StopAclQuackServer(const DatabaseInstance &caller, const string &uri) {
	unique_ptr<AclQuackServer> gone;
	{
		std::lock_guard<std::mutex> guard(g_servers_lock);
		QuackUri parsed(uri, false);
		auto it = g_servers.find(parsed.CanonicalUri());
		if (it == g_servers.end()) {
			return false;
		}
		if (!it->second->OwnedBy(caller)) {
			throw BinderException("acl_quack_stop: the server on %s belongs to another database instance", uri);
		}
		gone = std::move(it->second);
		g_servers.erase(it);
	}
	// Stop accepting (frees the port), then tear down fully and SYNCHRONOUSLY - joining the listener
	// and the worker pool here rather than on a detached thread. The detach saved the caller a moment
	// on a busy server, but a detached teardown racing process exit is exactly what left a joinable
	// std::thread to be destroyed under us on Linux ("terminate called without an active exception").
	gone->StopAccepting();
	gone.reset();
	return true;
}

idx_t AclQuackServerCount(const DatabaseInstance &db) {
	std::lock_guard<std::mutex> guard(g_servers_lock);
	idx_t count = 0;
	for (auto &entry : g_servers) {
		if (entry.second->OwnedBy(db)) {
			count++;
		}
	}
	return count;
}

} // namespace acl
} // namespace duckdb
