//===----------------------------------------------------------------------===//
// acl_quack_front.hpp — the quack door's front listener (spec 062, design/016 A2)
//
// quack's own listener is plain HTTP by construction and stays on loopback; this
// front owns the PUBLIC address instead: it terminates TLS (where the build
// carries OpenSSL — the flight build's vcpkg tree), answers the unauthenticated
// `GET /.well-known/quack-auth` discovery document itself, and streams every
// other request to the loopback quack. Zero quack changes — and the quack
// client already speaks https to non-local hosts by default, so a TLS front is
// exactly what a remote client expects. Deliberately store-free and
// duckdb-free: the caller composes the discovery JSON; this TU is httplib+std.
//===----------------------------------------------------------------------===//

#pragma once

#include <functional>
#include <string>

namespace duckdb {
namespace acl {

struct QuackFrontConfig {
	std::string host;      // the public bind (from the acl_quack_serve uri)
	int port = 0;          // the public port
	int internal_port = 0; // where the real quack listens, loopback only
	std::string cert_pem;  // both empty = cleartext front; both set = TLS
	std::string key_pem;
	//! Composes the discovery document PER REQUEST, so an issuer added or dropped after the serve
	//! is advertised immediately - a frozen document would lie (caught by the front's own test).
	//! The callback must own everything it touches (capture shared ownership of the store).
	std::function<std::string()> wellknown;
};

//! Start the front; "" on success, otherwise the reason (already-bound, TLS on a
//! build without OpenSSL, unparseable PEM, ...). One front per host:port.
std::string StartQuackFront(const QuackFrontConfig &config);

//! Stop the front for this public host:port; false when none is registered.
//! On success `internal_port_out` names the loopback quack behind it, so the
//! caller can stop that too.
bool StopQuackFront(const std::string &host, int port, int &internal_port_out);

//! A free loopback port for the internal quack listener (bind :0, release).
int FreeLoopbackPort();

} // namespace acl
} // namespace duckdb
