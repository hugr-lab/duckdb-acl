//===----------------------------------------------------------------------===//
// acl_quack_embed.hpp — the embedded quack door (spec 063, design/016 A2)
//
// quack's server, compiled INTO acl rather than reached through a loopback proxy
// (the spec-062 front this replaces). The protocol machinery is quack's own,
// unchanged (third_party/quack); only the listener is acl-owned (AclQuackServer):
// it binds the PUBLIC address, terminates TLS itself, and answers the
// unauthenticated `/.well-known/quack-auth` discovery document. Everything acl
// registers here is `acl_quack_*`-named, so a standalone quack loaded alongside
// never collides (spec 063, Strategy B).
//
// Deliberately narrow surface: acl_admin_functions.cpp composes the config and
// calls Start/Stop; the server object graph and httplib stay behind this header.
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb/common/constants.hpp"
#include "duckdb/common/string.hpp"

#include <functional>

namespace duckdb {

class ClientContext;
class ExtensionLoader;

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
bool StopAclQuackServer(const string &uri);

//! Number of embedded servers currently registered on this process (the door's ops surface).
idx_t AclQuackServerCount();

//! Register the embedded door's SQL surface: the acl_quack_* server settings the embedded graph reads,
//! and the acl_quack_scan_data drain table function. Auth/authz scalars (acl_quack_authenticate/
//! acl_quack_authorize) are registered by acl_admin_functions.cpp. Called once at extension load.
void RegisterAclQuackEmbed(ExtensionLoader &loader);

} // namespace acl
} // namespace duckdb
