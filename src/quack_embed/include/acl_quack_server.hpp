//===----------------------------------------------------------------------===//
// acl_quack_server.hpp — the embedded server's own API (spec 063), for the module's units only
//
// What acl_quack_door.cpp composes and drives, and acl_quack_http_server.cpp
// provides: the serve configuration, start, stop and the per-instance count.
// The extension's seam is acl_quack_embed.hpp (the two registrations); nothing
// outside src/quack_embed/ reaches the server directly.
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb/common/constants.hpp"
#include "duckdb/common/string.hpp"

#include <functional>

namespace duckdb {

class ClientContext;
class DatabaseInstance;

namespace acl {

struct AclQuackServeConfig {
	//! The public listen uri, e.g. "quack:0.0.0.0:8815" (the acl_quack_serve argument, verbatim).
	string uri;
	//! The server token every connection presents; validated by acl_quack_authenticate.
	string token;
	//! Both empty = cleartext listener; both set = TLS terminated here (inline PEM). A build without
	//! OpenSSL (no flight) refuses TLS by name.
	string cert_pem;
	string key_pem;
	//! Composes the /.well-known/quack-auth document PER REQUEST, so an issuer added or dropped after
	//! the serve is advertised immediately. The callback must own everything it touches.
	std::function<string()> wellknown;
	//! Answers whether the node is draining (spec 066), read per discovery request: while true,
	//! /.well-known/quack-auth answers 503 `draining` - the health-check shape a load balancer or an
	//! ops probe already watches. Unset = never draining.
	std::function<bool()> draining;
	//! Renders the Prometheus text of acl_metrics() PER REQUEST for GET /metrics (spec 069), or ""
	//! while `acl_metrics_endpoint` is off - the route then answers 404, like one that is not there.
	//! Unset = no route at all.
	std::function<string()> metrics;
	//! Default (true): advertise /.well-known/quack-auth so an acl-aware client discovers the issuers.
	//! `mode := 'plain'` sets false - a bare quack server (no discovery route), for a stock client or
	//! when TLS is terminated by a reverse proxy upstream. Still acl-gated; still cleartext-only here.
	bool discovery = true;
};

//! Start the embedded server on `cfg.uri`. Returns "" on success (with `actual_uri_out` set to the
//! bound uri, port filled in when the request named :0), otherwise the reason (address in use, TLS on
//! a non-OpenSSL build, unparseable PEM, ...). One server per canonical uri.
string StartAclQuackServer(ClientContext &context, const AclQuackServeConfig &cfg, string &actual_uri_out);

//! Stop the embedded server for this uri; false when none is registered. Frees the port synchronously.
//! Refuses (throws) a server another database instance opened: the registry is per process, and
//! the sessions the caller would close afterwards are its own, not the door's.
bool StopAclQuackServer(const DatabaseInstance &caller, const string &uri);

//! Number of embedded servers THIS database instance has open (the "last door" judgement of
//! acl_quack_stop): another instance's servers must not keep this one's fence armed.
idx_t AclQuackServerCount(const DatabaseInstance &db);

} // namespace acl
} // namespace duckdb
