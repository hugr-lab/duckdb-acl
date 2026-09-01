//===----------------------------------------------------------------------===//
// acl_quack_httplib_ns.hpp — namespace bridge for the embedded quack server (spec 063)
//
// quack's server hardcodes the `duckdb_httplib::Server` type. duckdb's bundled
// httplib renames its namespace to `duckdb_httplib_openssl` whenever
// CPPHTTPLIB_OPENSSL_SUPPORT is defined (its ODR-avoidance against the core's
// non-TLS copy). We compile the embedded server with OpenSSL so the door can
// terminate TLS itself; this force-included shim aliases the name quack expects
// back onto the OpenSSL namespace, so quack's sources compile UNCHANGED and the
// listener can reach `duckdb_httplib::SSLServer`. In a non-TLS build the macro is
// undefined, no alias is made, and quack uses the real `duckdb_httplib` — so this
// header is a no-op there. Force-included via -include on the embed graph only.
//===----------------------------------------------------------------------===//
#pragma once

#include "httplib.hpp"

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
// The embedded quack TUs never pull the core's non-TLS httplib, so `duckdb_httplib`
// is a free name here and this alias cannot clash with a real namespace of that name.
namespace duckdb_httplib = duckdb_httplib_openssl;
#endif
