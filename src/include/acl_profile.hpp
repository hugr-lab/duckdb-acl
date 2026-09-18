//===----------------------------------------------------------------------===//
// acl_profile.hpp - spec 074: the execution profile
//
// duckdb's QueryProfiler is per connection and its tree dies with the query. This module registers
// a ClientContextState on every connection of the instance (ExtensionCallback::OnConnectionOpened)
// whose QueryEnd - called by duckdb after profiler->EndQuery(), for a statement, a stream's end and
// each execution of a prepared statement - walks the tree once and emits one `profile` event through
// the audit pipeline (spec 069): the statement's own wall time, thread time, rows, bytes, memory, a
// rollup per source and the plan, preorder. Numbers and names of attached catalogs and operator
// types; never the statement's text, a literal, a path or a claim value.
//
// Profiling is decided BEFORE a statement (the profiler starts at parse), per connection: a door
// sets it around what it runs; the gateway path gets it from the connection's next statement on.
//===----------------------------------------------------------------------===//
#pragma once

#include "acl_audit.hpp"

namespace duckdb {
class ClientContext;
class ExtensionLoader;

namespace acl {
class AuditPipeline;
class PolicyStore;

//! What the override knows at decision time and the profile needs at execution time: the seq of
//! the statement event, the batch's shared identity (door, session, principal, trace ids), the
//! statement's class and objects, and the physical names its relations resolved to.
struct ProfileNote {
	int64_t decision_seq = -1;
	//! StatementTextHash of the text the executing statement carries (`SQLStatement::query`, what
	//! duckdb reports as the current query while it runs - the same for a PREPARE and each of its
	//! executions): the note is taken by the execution whose text it is, and by nothing else.
	uint64_t text_hash = 0;
	AuditEvent proto;
	string statement;
	vector<AuditObject> objects;
	vector<string> physical;
};

//! The hash a note and an execution are matched by; never the text.
uint64_t StatementTextHash(const string &text);

//! The override, on its thread, per decided statement of a batch: parse and execution are one
//! Query() on one thread, so a queue on the thread meets the batch's first execution, which takes
//! it whole onto the connection - a nested query on another connection of the thread finds it empty.
void PushProfileNote(ProfileNote note);
//! The override, before a new batch: a note nobody executed (a refusal ended the batch) must not
//! name the next statement.
void ClearProfileNotes();
//! The override, on a parse it decided nothing about (no prefix): the statement that follows on
//! this thread is nobody's, and ends the note its connection kept for re-executions.
void PushProfileBoundary();
//! A door whose Prepare and execution are different calls (Flight): the note the Prepare left on
//! this connection (a PREPARE's tree is its own, so the note survives it), taken into the
//! reservation - and given back to the connection right before an execution, which takes it when
//! its text is the prepared one. `false` when the Prepare left none.
bool TakeConnectionProfileNote(ClientContext &context, ProfileNote &out);
void SetConnectionProfileNote(ClientContext &context, ProfileNote note);

//! A door, before a statement on a connection it owns: decides from the level (the instance's, or
//! the registered policy's for this principal and door) and the caller's trace context whether the
//! statement is profiled, and sets the connection's profiler accordingly - never over a client's
//! own `enable_profiling`, in either direction.
void ProfileConnectionFor(ClientContext &context, const shared_ptr<AuditPipeline> &pipeline, const Principal &principal,
                          const string &door, const string &traceparent);

//! The sampled flag of a W3C traceparent (`00-<trace>-<span>-<flags>`): flags & 1. False when the
//! text is not one.
bool TraceSampled(const string &traceparent);

void RegisterAclProfile(ExtensionLoader &loader, const shared_ptr<PolicyStore> &store);

} // namespace acl
} // namespace duckdb
