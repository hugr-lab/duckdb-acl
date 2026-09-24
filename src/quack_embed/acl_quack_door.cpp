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
#include "duckdb/storage/buffer_manager.hpp"
#include "quack_fetch_collector.hpp"
#include "quack_rebalancer_sink.hpp"
#include "acl_quack_fetch_window.hpp"
#include "acl_node_load.hpp"

#include "acl_audit_pipeline.hpp"
#include "acl_parser_override.hpp"
#include "acl_profile.hpp"
#include "acl_door_auth.hpp"
#include "acl_door_common.hpp"
#include "acl_quack_server.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/main/connection.hpp"
#include "duckdb/main/query_result.hpp"

#include "duckdb/common/error_data.hpp"
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
			return DoorAuthJson(*shared_store, "quack");
		};
		// spec 066: while draining, the discovery route answers 503 - the LB's take-me-out signal
		cfg.draining = [shared_store] {
			return shared_store->Draining();
		};
		// spec 069: GET /metrics, read per request - the operator's SET GLOBAL acl_metrics_endpoint
		// after the serve counts, and "" (404) while it is off
		weak_ptr<DatabaseInstance> weak_db = context.db;
		cfg.metrics = [shared_store, weak_db]() -> string {
			auto db = weak_db.lock();
			if (!db || !shared_store->audit) {
				return string();
			}
			Value on;
			if (!DBConfig::GetConfig(*db).TryGetCurrentSetting("acl_metrics_endpoint", on) || on.IsNull() ||
			    !on.GetValue<bool>()) {
				return string();
			}
			return RenderPrometheus(shared_store->audit->Hooks());
		};
		cfg.node_load = [shared_store, weak_db]() -> string {
			auto db = weak_db.lock();
			if (!db || !NodeLoadServed(*db)) {
				return string();
			}
			return NodeLoadJson(*db, *shared_store);
		};
		string actual_uri;
		// a bind or PEM failure inside is an IOException that carries this function's prefix and passes
		// through untouched (the error contract, website/docs/security.md section 8); what comes back as text is
		// a refused state - an occupied uri, a missing crypto module - and stays a binder error
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
			// not end the sessions of the doors that ARE open (found writing website/docs/serving.md)
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
	auto &store = StoreOf(state);
	for (idx_t row = 0; row < args.size(); row++) {
		// Since quack f4328c5 the server hands a failed callback's error text back over the wire, so
		// an exception here would tell a client that has not authenticated yet what our policy source
		// said - a DSN, a catalog name. Fail closed and keep the reason where it belongs: the audit
		// (spec 069 - the door refuses, it does not learn why; the same rule SessionOpen follows for
		// a JWKS document it cannot read).
		try {
			auto session_id = RequiredArg(args, 0, row, "acl_quack_authenticate", "session id");
			auto token = RequiredArg(args, 1, row, "acl_quack_authenticate", "client token");
			// spec 085: a re-authentication replaces the connection's session, so a group at its
			// max_sessions does not refuse the connection its own token refresh
			string replacing;
			store.SessionHandleFor(session_id, replacing);
			auto handle = store.SessionOpen(token, "quack", replacing);
			if (handle.empty()) {
				result.SetValue(row, Value::BOOLEAN(false));
				continue;
			}
			store.SessionBind(session_id, handle);
			result.SetValue(row, Value::BOOLEAN(true));
		} catch (std::exception &ex) {
			store.AuditDoor("quack", "authenticate", false, "policy_error", ErrorData(ex).RawMessage());
			result.SetValue(row, Value::BOOLEAN(false));
		}
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
	auto &store = StoreOf(state);
	for (idx_t row = 0; row < args.size(); row++) {
		// NULL is the refusal this callback speaks, and it is also what an exception has to become:
		// the server would otherwise put our error text in front of the client (see the note in
		// acl_quack_authenticate)
		try {
			auto connection_id = RequiredArg(args, 0, row, "acl_quack_authorize", "connection id");
			auto sql = RequiredArg(args, 1, row, "acl_quack_authorize", "query");
			string handle;
			if (!store.SessionHandleFor(connection_id, handle)) {
				result.SetValue(row, Value());
				continue;
			}
			// SessionSql is the one place the prefix is composed, so every door spells it the same way;
			// the trace is whatever the client SET on its connection (spec 069)
			string correlation_id, traceparent;
			TraceFromContext(state.GetContext(), correlation_id, traceparent);
			auto prefixed = store.SessionSql(handle, sql, correlation_id, traceparent);
			result.SetValue(row, prefixed.empty() ? Value() : Value(prefixed));
		} catch (std::exception &ex) {
			store.AuditDoor("quack", "authorize", false, "policy_error", ErrorData(ex).RawMessage());
			result.SetValue(row, Value());
		}
	}
}

} // namespace

namespace {

idx_t SettingOr(DatabaseInstance &db, const char *name, idx_t fallback) {
	Value value;
	if (!DBConfig::GetConfig(db).TryGetCurrentSetting(name, value) || value.IsNull()) {
		return fallback;
	}
	return value.GetValue<idx_t>();
}

} // namespace

shared_ptr<const ResourceLimits> AclQuackLimitsOf(ClientContext &context) {
	auto state = context.registered_state->Get<AclQuackSessionLimits>(AclQuackSessionLimits::KEY);
	if (!state) {
		return nullptr;
	}
	return state->Get();
}

idx_t AclQuackStreamReserve(DatabaseInstance &db, const ResourceLimits *limits) {
	auto fixed = SettingOr(db, "acl_quack_stream_reserve_bytes", 0);
	if (fixed > 0) {
		return fixed;
	}
	// what the server lets one stream hold: its producer buffer (as the server caps it: at most a
	// quarter of the operator memory limit), and the batches in flight - the window's cap, or the
	// client's whole read-ahead when the window grows without one
	auto producer = SettingOr(db, "acl_quack_fetch_producer_buffer_bytes", QUACK_FETCH_PRODUCER_BUFFER_BYTES_DEFAULT);
	auto memory_cap = BufferManager::GetBufferManager(db).GetOperatorMemoryLimit() / 4;
	if (producer > 0 && memory_cap > 0) {
		producer = MinValue<idx_t>(producer, memory_cap);
	}
	auto window = limits && limits->window_max.IsValid()
	                  ? limits->window_max.GetIndex()
	                  : SettingOr(db, "acl_quack_fetch_window_max", ACL_QUACK_FETCH_WINDOW_MAX_DEFAULT);
	if (window == 0) {
		window = SettingOr(db, "acl_quack_client_depth", ACL_QUACK_CLIENT_DEPTH_DEFAULT);
	}
	if (window == 0) {
		window = ACL_QUACK_CLIENT_DEPTH_DEFAULT;
	}
	auto batch = limits && limits->batch_bytes.IsValid()
	                 ? limits->batch_bytes.GetIndex()
	                 : SettingOr(db, "acl_quack_target_batch_bytes", 8ULL * 1024ULL * 1024ULL);
	return producer + window * batch;
}

idx_t AclNodeStreamBudget(DatabaseInstance &db) {
	auto budget = SettingOr(db, "acl_node_stream_budget", 0);
	if (budget > 0) {
		return budget;
	}
	return BufferManager::GetBufferManager(db).GetOperatorMemoryLimit() / 2;
}

AclQuackStreamSlot::AclQuackStreamSlot(Connection &connection) {
	auto &db = *connection.context->db;
	store = PolicyStore::Of(db);
	if (!store) {
		return;
	}
	auto &context = *connection.context;
	auto limits = AclQuackLimitsOf(context);
	auto want = AclQuackStreamReserve(db, limits.get());
	auto budget = AclNodeStreamBudget(db);
	auto timeout = std::chrono::seconds(SettingOr(db, "acl_stream_queue_timeout", 25));
	bool interrupted = false;
	// spec 085: the session's group's priority orders the line (aging keeps a low one from starving)
	auto priority = limits ? limits->queue_priority : 0;
	if (!store->stream_budget.Acquire(
	        want, budget, timeout, [&context]() { return context.IsInterrupted(); }, interrupted, priority)) {
		if (interrupted) {
			throw InterruptException();
		}
		auto now = store->stream_budget.Now();
		throw InvalidInputException("acl: node at capacity - the stream memory budget stayed full for %llu s (%s of %s "
		                            "reserved by %llu producing statements, %s wanted); try again or another node",
		                            NumericCast<idx_t>(timeout.count()),
		                            StringUtil::BytesToHumanReadableString(now.reserved),
		                            StringUtil::BytesToHumanReadableString(budget), now.producing,
		                            StringUtil::BytesToHumanReadableString(want));
	}
	bytes = want;
}

AclQuackStreamSlot::~AclQuackStreamSlot() {
	if (store && bytes > 0) {
		store->stream_budget.Release(bytes);
	}
}

AclQuackSeatClaim::AclQuackSeatClaim(DatabaseInstance &db_p, idx_t seated, string &refusal) : db(db_p) {
	auto store = PolicyStore::Of(db);
	if (!store) {
		granted = true; // no acl state to account against: quack's own pool is the bound
		return;
	}
	lock_guard<mutex> guard(store->quack_seat_lock);
	granted = AclQuackAdmit(db, seated + store->quack_seats_claimed, refusal);
	if (granted) {
		store->quack_seats_claimed++;
		counted = true;
	}
}

AclQuackSeatClaim::~AclQuackSeatClaim() {
	if (!counted) {
		return;
	}
	try {
		if (auto store = PolicyStore::Of(db)) {
			lock_guard<mutex> guard(store->quack_seat_lock);
			if (store->quack_seats_claimed > 0) {
				store->quack_seats_claimed--;
			}
		}
	} catch (...) {
	}
}

bool AclQuackAdmit(DatabaseInstance &db, idx_t seated, string &refusal) {
	try {
		auto &config = DBConfig::GetConfig(db);
		auto read = [&](const char *name, idx_t fallback) {
			Value value;
			if (!config.TryGetCurrentSetting(name, value) || value.IsNull()) {
				return fallback;
			}
			return value.GetValue<idx_t>();
		};
		auto per_client = read("acl_quack_client_depth", ACL_QUACK_CLIENT_DEPTH_DEFAULT);
		if (per_client == 0) {
			return true; // no seat accounting: quack's own pool is the only bound
		}
		auto slots = read("acl_quack_server_max_connections", 1024);
		auto seats = MaxValue<idx_t>(1, slots / per_client);
		if (seated < seats) {
			return true;
		}
		refusal = StringUtil::Format("acl: node at capacity - %llu of %llu quack clients seated "
		                             "(acl_quack_server_max_connections %llu / acl_quack_client_depth %llu); "
		                             "try another node",
		                             seated, seats, slots, per_client);
		if (auto store = PolicyStore::Of(db)) {
			store->AuditSessionRefused("quack", "at_capacity", refusal);
		}
		return false;
	} catch (...) {
		return true; // accounting that fails never refuses a client: the pool still bounds the node
	}
}

void AclQuackConnectionGone(DatabaseInstance &db, const string &connection_id, const char *how) {
	try {
		if (auto store = PolicyStore::Of(db)) {
			store->SessionEndBound(connection_id, how);
		}
	} catch (...) {
		// the idle timeout still ends it
	}
}

namespace {

//! spec 085: the session's limits onto the server connection its statement runs on - the connection
//! is the door's (a client cannot SET on it: spec 068), so its session-scoped batch setting is ours
//! to set, and to clear for a session whose groups name none
void ApplySessionLimits(ClientContext &context, const ResourceLimits &limits) {
	context.registered_state->GetOrCreate<AclQuackSessionLimits>(AclQuackSessionLimits::KEY)->Set(limits);
	optional_ptr<const ConfigurationOption> option;
	auto index = DBConfig::GetConfig(context).TryGetSettingIndex(Identifier("acl_quack_target_batch_bytes"), option);
	if (!index.IsValid()) {
		return;
	}
	auto &settings = ClientConfig::GetConfig(context).user_settings;
	if (limits.batch_bytes.IsValid()) {
		settings.SetUserSetting(index.GetIndex(), Value::UBIGINT(limits.batch_bytes.GetIndex()));
	} else {
		settings.ClearSetting(index.GetIndex());
	}
}

} // namespace

void AclQuackStatementStarting(Connection &connection, const string &connection_id) {
	try {
		auto store = PolicyStore::Of(*connection.context->db);
		string handle;
		PolicyStore::SessionRef ref;
		if (!store || !store->SessionHandleFor(connection_id, handle) || !store->SessionRefOf(handle, ref)) {
			return;
		}
		ProfileConnectionFor(*connection.context, store->audit, ref.principal, ref.door, ref.traceparent,
		                     ref.profile_override);
		ApplySessionLimits(*connection.context, ref.limits);
	} catch (...) {
		// a profile is never worth the statement
	}
}

void AclQuackStatementCompleted(Connection &connection, const string &connection_id, const string &sql,
                                QueryResult &result) {
	// the connection id is what acl_quack_authenticate bound to a session; a drain on a connection
	// nobody bound was refused at parse and has nothing to complete
	auto store = PolicyStore::Of(*connection.context->db);
	string handle;
	if (!store || !store->SessionHandleFor(connection_id, handle)) {
		return;
	}
	// what makes the statement a drain is the note the rewriter left on the session when it exempted
	// the call on the AST (spec 042) - never this text, which a client could dress up with a literal
	// or an alias to have an ordinary statement recorded as a load. The note names the stream, and
	// the statement that completed must carry it.
	auto stream = store->TakeSessionDrain(handle);
	if (stream.empty() || sql.find(stream) == string::npos) {
		return; // an ordinary statement: its decision is the override's event
	}
	if (result.HasError()) {
		store->AuditIngest(handle, -1, result.GetError());
		return;
	}
	// an INSERT answers one count row through the default collector, complete by the time the server
	// hands it here (Query is blocking); RowCount/GetValue read the retained rows without moving the
	// cursor the server's own Fetch loop uses next
	int64_t rows = -1;
	if (result.RowCount() == 1 && result.ColumnCount() == 1) {
		auto count = result.GetValue(0, 0);
		if (!count.IsNull() && count.type().id() == LogicalTypeId::BIGINT) {
			rows = count.GetValue<int64_t>();
		}
	}
	store->AuditIngest(handle, rows, string());
}

void RegisterAclQuackDoor(ExtensionLoader &loader, shared_ptr<PolicyStore> store) {
	// the door's state gauge (spec 069): listeners of this instance serving right now. Through the
	// registry in the object cache, which exists before the pipeline is attached.
	{
		auto &db = loader.GetDatabaseInstance();
		auto hooks = store->hooks; // the instance's registry, or the private one (AuditHooks::Reach)
		weak_ptr<DatabaseInstance> weak_db = db.shared_from_this();
		hooks->Gauges().Register("acl.door.state", {{"door", "quack"}}, "{door}", "listeners serving right now",
		                         [weak_db]() -> int64_t {
			                         auto locked = weak_db.lock();
			                         return locked ? int64_t(AclQuackServerCount(*locked)) : 0;
		                         });
	}
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
