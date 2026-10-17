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
// undefined and the alias runs the other way: quack's headers name
// `duckdb_httplib_openssl` since e7a9be3, which then means the core's httplib (spec 133).
// Force-included via -include on the embed graph only.
//===----------------------------------------------------------------------===//
#pragma once

// windows.h, reached through httplib here, spills wingdi.h's macros over ordinary identifiers:
// PASSTHROUGH (a GDI escape code) collided with AdminScope::PASSTHROUGH in acl_policy.hpp once this
// shim preceded it in every embed TU (the 4.3 move; MSVC: "missing '}' before 'constant'"), and
// ERROR waits to do the same. Nothing in the embed draws, so the GDI half is left out.
#if defined(_WIN32) && !defined(NOGDI)
#define NOGDI
#endif

#include "httplib.hpp"

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
// The embedded quack TUs never pull the core's non-TLS httplib, so `duckdb_httplib`
// is a free name here and this alias cannot clash with a real namespace of that name.
namespace duckdb_httplib = duckdb_httplib_openssl;
#else
// Since quack e7a9be3 (spec 133) its headers name `duckdb_httplib_openssl` themselves (the server's member,
// the pinned client's): in a build without TLS that name is free, and it means the core's httplib.
namespace duckdb_httplib_openssl = duckdb_httplib;
#endif
