//===----------------------------------------------------------------------===//
// acl_quack_door.cpp — the quack door's SQL surface (specs 041/063), beside the server it drives
//
// Four scalars, registered here and nowhere else: acl_quack_serve / acl_quack_stop
// open and close the embedded server, acl_quack_authenticate / acl_quack_authorize
// are the callbacks the server calls per connection and per statement. All four
// are thin over the session contract of spec 040 (PolicyStore::Session*), which
// is what makes serving under the ACL two wrappers rather than a second gate.
// The Flight door is the same shape in src/flight/ (release plan 4.3).
//===----------------------------------------------------------------------===//

#include "acl_quack_embed.hpp"

#include "acl_door_auth.hpp"
#include "acl_door_common.hpp"
#include "acl_quack_server.hpp"

#include "duckdb/common/exception/binder_exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/extension/extension_loader.hpp"

namespace duckdb {
namespace acl {
namespace {

//! acl_quack_serve(uri, token[, cert, key][, mode]): the safe way to open the quack door (spec 041).
//! It starts the embedded server (spec 063) - but only from an instance a client cannot step out of,
//! and it says which condition is missing rather than serving something half-configured. Everything
//! it sets could be set by hand; the point of the function is that it is all of it or none.
void AclQuackServeFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &context = state.GetContext();
	result.SetVectorType(VectorType::FLAT_VECTOR);
	for (idx_t row = 0; row < args.size(); row++) {
		auto uri = RequiredArg(args, 0, row, "acl_quack_serve", "listen uri");
		auto token = args.ColumnCount() > 1 ? OptionalArg(args, 1, row, "") : string();
		auto &store = StoreOf(state);
		if (token.empty()) {
			throw BinderException("acl_quack_serve: pass a server token explicitly. It is not what admits a "
			                      "client - their JWT is - but a default-configured quack accepts whatever a "
			                      "caller sends, and this is the outer fence around that");
		}
		// Argument shapes (mode defaults to 'embedded'):
		//   (uri, token)                     embedded, discovery on, cleartext
		//   (uri, token, mode)               mode ∈ {embedded, plain}
		//   (uri, token, cert, key)          embedded + TLS
		//   (uri, token, cert, key, mode)    embedded + TLS + mode
		auto cols = args.ColumnCount();
		string cert_arg, key_arg, mode;
		if (cols == 3) {
			mode = Trimmed(OptionalArg(args, 2, row, ""));
		} else if (cols >= 4) {
			cert_arg = OptionalArg(args, 2, row, "");
			key_arg = OptionalArg(args, 3, row, "");
			if (cols >= 5) {
				mode = Trimmed(OptionalArg(args, 4, row, ""));
			}
		}
		if (cert_arg.empty() != key_arg.empty()) {
			throw BinderException("acl_quack_serve: TLS needs both the certificate and the key");
		}
		if (!mode.empty() && !StringUtil::CIEquals(mode, "embedded") && !StringUtil::CIEquals(mode, "plain")) {
			throw BinderException("acl_quack_serve: unknown mode \"%s\" (expected 'embedded' or 'plain')", mode);
		}
		bool plain = StringUtil::CIEquals(mode, "plain");
		if (plain && (!cert_arg.empty() || !key_arg.empty())) {
			throw BinderException("acl_quack_serve: 'plain' mode is a cleartext server - terminate TLS upstream, "
			                      "or drop the mode to serve TLS here");
		}
		// The preconditions both doors share (acl_door_common), checked before quack is touched at
		// all so the refusal names the thing to fix. `plain` is the explicit cleartext opt-in - a
		// proxy terminates TLS upstream - so it, like a certificate, lifts the loopback-only rule;
		// the default embedded cleartext door binds only localhost, exactly as the Flight door does.
		RefuseUnlessServable(context, store, "acl_quack_serve", ListenHost(uri), !cert_arg.empty(), plain);
		// spec 063: quack's own server, compiled into acl. It binds the public address itself,
		// terminates TLS where asked, and answers /.well-known/quack-auth - no loopback front, no
		// heartbeat headroom tax. It reads acl_quack_* settings (defaulted to acl_quack_authenticate /
		// acl_quack_authorize), so there is nothing to SET and quack need not be loaded at all.
		// 'plain' drops the discovery route for a bare, still-acl-gated quack server (TLS upstream).
		AclQuackServeConfig cfg;
		cfg.uri = uri;
		cfg.token = token;
		cfg.discovery = !plain;
		cfg.cert_pem = cert_arg.empty() ? string() : ReadPemArg(context, cert_arg, "certificate", "acl_quack_serve");
		cfg.key_pem = key_arg.empty() ? string() : ReadPemArg(context, key_arg, "private key", "acl_quack_serve");
		auto shared_store = SharedStoreOf(state);
		// per request, so the discovery document tracks an issuer added or dropped after the serve;
		// the document is spec 064's - the same one the Flight door answers to `discover-auth`
		cfg.wellknown = [shared_store] {
			return DoorAuthJson(*shared_store);
		};
		// spec 066: while draining, the discovery route answers 503 - the LB's take-me-out signal
		cfg.draining = [shared_store] {
			return shared_store->Draining();
		};
		string actual_uri;
		auto error = StartAclQuackServer(context, cfg, actual_uri);
		if (!error.empty()) {
			throw BinderException("acl_quack_serve: %s", error);
		}
		// From here the fence on unprefixed statements applies: a drained stream is now ours to judge
		// (spec 043). Set after the listener is up, so a refused serve leaves nothing behind.
		store.SetDoorOpen(true);
		result.SetValue(row, Value(actual_uri));
	}
}

//! acl_quack_stop(uri): close the door, and the sessions it served with it (spec 041). Stopping the
//! listener leaves every session bound to a connection that will never come back, and nothing else
//! can tell that they are gone - a door is the only thing that knows it closed.
//!
//! quack does not tell a callback which server a connection arrived at, so sessions cannot be
//! attributed to one. They are therefore swept only when no quack server is left in the instance:
//! with two doors open, stopping one says what it did rather than guessing whose sessions to drop.
void AclQuackStopFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &context = state.GetContext();
	result.SetVectorType(VectorType::FLAT_VECTOR);
	for (idx_t row = 0; row < args.size(); row++) {
		auto uri = RequiredArg(args, 0, row, "acl_quack_stop", "listen uri");
		auto stopped = StopAclQuackServer(*context.db, uri);
		string note = stopped ? ("Stopped listening on " + uri) : ("No server found listening on " + uri);
		if (!stopped) {
			// nothing of ours closed, so there is nothing to sweep: a stop of a uri nobody serves must
			// not end the sessions of the doors that ARE open (found writing docs/serving.md)
			result.SetValue(row, Value(note));
			continue;
		}
		// The embedded registry knows exactly how many doors THIS instance has left, so the last-door
		// judgement is exact (no guessing which door's sessions to drop) - and another instance's
		// doors do not keep this instance's fence armed.
		bool last_door = AclQuackServerCount(*context.db) == 0;
		if (!last_door) {
			result.SetValue(row, Value(note + " (another quack server is still open, so its sessions stay)"));
			continue;
		}
		auto &store = StoreOf(state);
		// The last door is closed, so the fence on unprefixed statements lifts with it: a drained
		// stream is once again nobody's business but quack's own (spec 043).
		store.SetDoorOpen(false);
		auto closed = store.SessionCloseAll();
		result.SetValue(row, Value(note + " (" + std::to_string(closed) + " session(s) closed)"));
	}
}

//! acl_quack_authenticate(session_id, client_token, server_token): the server's authentication
//! callback (spec 041). The client's token is a JWT we verify for ourselves, so quack's own shared
//! token is not what admits anyone - it stays the operator's outer fence, and this decides the
//! principal. Binding is by quack's `session_id`, which is the `connection_id` every later message
//! carries.
void AclQuackAuthenticateFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	result.SetVectorType(VectorType::FLAT_VECTOR);
	for (idx_t row = 0; row < args.size(); row++) {
		auto session_id = RequiredArg(args, 0, row, "acl_quack_authenticate", "session id");
		auto token = RequiredArg(args, 1, row, "acl_quack_authenticate", "client token");
		auto &store = StoreOf(state);
		auto handle = store.SessionOpen(token);
		if (handle.empty()) {
			result.SetValue(row, Value::BOOLEAN(false));
			continue;
		}
		store.SessionBind(session_id, handle);
		result.SetValue(row, Value::BOOLEAN(true));
	}
}

//! acl_quack_authorize(connection_id, query): the server's authorization callback (spec 041). A
//! VARCHAR return replaces the SQL quack executes, so returning the prefixed statement is the whole
//! of serving under the ACL; NULL is a refusal, which is what an unknown or expired session gets.
//!
//! One statement arrives here that quack does *not* execute: before a stream starts it asks about the
//! write with `INSERT INTO <schema>.<table> VALUES (NULL)` and reads only whether the answer is NULL.
//! It gets the same treatment as everything else - prefixed, not special-cased - for two reasons. The
//! write itself is judged where the server generates it (spec 042), so refusing here would refuse
//! every bulk load; and a prefixed answer is the safe one to hand back for a statement we are told is
//! never run, because if quack ever does run it, it runs through the ACL rather than around it.
void AclQuackAuthorizeFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	result.SetVectorType(VectorType::FLAT_VECTOR);
	for (idx_t row = 0; row < args.size(); row++) {
		auto connection_id = RequiredArg(args, 0, row, "acl_quack_authorize", "connection id");
		auto sql = RequiredArg(args, 1, row, "acl_quack_authorize", "query");
		auto &store = StoreOf(state);
		string handle;
		if (!store.SessionHandleFor(connection_id, handle)) {
			result.SetValue(row, Value());
			continue;
		}
		// SessionSql is the one place the prefix is composed, so every door spells it the same way
		auto prefixed = store.SessionSql(handle, sql);
		result.SetValue(row, prefixed.empty() ? Value() : Value(prefixed));
	}
}

} // namespace

void RegisterAclQuackDoor(ExtensionLoader &loader, shared_ptr<PolicyStore> store) {
	const LogicalType &v = LogicalType::VARCHAR;
	auto register_text = [&](const string &name, vector<vector<LogicalType>> signatures, const scalar_function_t &fn) {
		ScalarFunctionSet set((Identifier(name)));
		for (auto &arguments : signatures) {
			ScalarFunction function(Identifier(name), std::move(arguments), v, fn);
			MarkAclScalar(function, store);
			set.AddFunction(function);
		}
		loader.RegisterFunction(set);
	};
	// spec 062/063: (uri, token[, mode]) serves in the clear; (uri, token, cert, key[, mode]) serves TLS
	register_text("acl_quack_serve", {{v, v}, {v, v, v}, {v, v, v, v}, {v, v, v, v, v}}, AclQuackServeFunc);
	register_text("acl_quack_stop", {{v}}, AclQuackStopFunc);
	register_text("acl_quack_authorize", {{v, v}}, AclQuackAuthorizeFunc);
	ScalarFunction authenticate(Identifier("acl_quack_authenticate"), {v, v, v}, LogicalType::BOOLEAN,
	                            AclQuackAuthenticateFunc);
	MarkAclScalar(authenticate, store);
	loader.RegisterFunction(authenticate);
}

} // namespace acl
} // namespace duckdb
