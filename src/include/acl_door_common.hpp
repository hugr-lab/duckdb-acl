//===----------------------------------------------------------------------===//
// acl_door_common.hpp — what both doors do the same way, written once
//
// The Flight door and the quack door each grew a PEM reader, a JSON escaper and
// the serve preconditions of their own, and the copies had started to disagree
// (the 2026-09-03 review): one escaper emitted control bytes raw, one door refused
// a cleartext non-local bind and the other did not. A door is a place where a
// disagreement is a hole, so the shared parts live here, compiled into every build.
//===----------------------------------------------------------------------===//
#pragma once

#include "acl_policy.hpp"

#include "duckdb/common/types/data_chunk.hpp"
#include "duckdb/execution/expression_executor_state.hpp"

namespace duckdb {
namespace acl {

//! The store an acl_* scalar belongs to, reached through the function's own info (AclScalarInfo), so
//! nothing here is a process global (spec 041). The shared form is for a callback that may outlive
//! the call - the quack door's live discovery document (specs 062/063). Once three copies: the admin
//! functions, the Flight door and the quack door each had their own.
PolicyStore &StoreOf(ExpressionState &state);
shared_ptr<PolicyStore> SharedStoreOf(ExpressionState &state);

//! The argument readers every acl_* scalar uses. `fn` and `what` name the function and the argument
//! in the refusal of a NULL; an optional argument past the last column answers its fallback.
string RequiredArg(DataChunk &args, idx_t col, idx_t row, const char *fn, const char *what);
string OptionalArg(DataChunk &args, idx_t col, idx_t row, const string &fallback);
string Trimmed(string value);

//! A JSON string literal, quotes included: `"` and `\` escaped, every control byte below 0x20 as
//! `\u00XX`. Anything that reaches a JSON document from a token - a subject, a role, a claim - goes
//! through this, or a client parsing `acl_sessions()` breaks on the first odd byte.
string JsonQuote(const string &value);

//! A certificate or key argument: inline PEM if it opens with the armor, otherwise a path/URI read
//! through duckdb's own filesystem (the spec 023/053 pattern - a local file works out of the box,
//! an operator's secret manager or object store rides httpfs). `fn` names the calling function in
//! a refusal; `what` is "certificate" or "private key". A non-PEM document is refused here rather
//! than reaching the TLS stack as a cryptic init error.
string ReadPemArg(ClientContext &context, const string &arg, const char *what, const char *fn);

//! The host part of a listen uri as either door writes it: `quack:host:port`, `grpc://host:port`,
//! `grpc+tls://host:port` or a bare `host:port`; a bracketed IPv6 literal keeps its brackets.
string ListenHost(const string &uri);

//! What no door may serve past (specs 041/053, one rule for both): a policy source is configured,
//! anonymous admin is off, the parser override is STRICT - and, unless TLS terminates here or the
//! caller opted into a cleartext server explicitly (`cleartext_ok`: quack's `plain` mode, for a
//! TLS-terminating proxy upstream), the bind is loopback only, because a cleartext door must not
//! leave the machine. `fn` names the calling function in the refusal.
void RefuseUnlessServable(ClientContext &context, PolicyStore &store, const char *fn, const string &host, bool has_tls,
                          bool cleartext_ok);

} // namespace acl
} // namespace duckdb
