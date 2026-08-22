//===----------------------------------------------------------------------===//
// The Arrow Flight SQL door (spec 045).
//
// A door decides nothing. It turns a token into a session handle once, puts `ACL SESSION '<handle>'`
// in front of every statement after that, and lets the rewriter do the rest - the same shape spec 041
// established for quack, on the protocol the ADBC and JDBC drivers speak.
//
// Two seams of `FlightSqlServerBase` carry the whole thing: GetFlightInfoStatement is where a client's
// SQL arrives, and DoGetStatement is where its rows go out.
//===----------------------------------------------------------------------===//

#include "acl_flight_door.hpp"

#include "duckdb/common/arrow/arrow_converter.hpp"
#include "duckdb/common/exception/binder_exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/planner/expression/bound_function_expression.hpp"
#include <thread>

#include <arrow/c/bridge.h>
#include <arrow/flight/server.h>
#include <arrow/flight/sql/server.h>
#include <arrow/record_batch.h>
#include <arrow/status.h>
#include <arrow/table.h>
#include <mutex>
#include <random>
#include <unordered_map>

namespace duckdb {
namespace acl {

namespace {

//! The store this call belongs to, reached the way the admin functions reach it (spec 041): through
//! the function's own info, so nothing here is a process global.
shared_ptr<PolicyStore> StoreShared(ExpressionState &state) {
	return state.expr.Cast<BoundFunctionExpression>().Function().GetExtraFunctionInfo().Cast<AclScalarInfo>().store;
}

PolicyStore &StoreOf(ExpressionState &state) {
	return *StoreShared(state);
}

namespace flight = arrow::flight;
namespace flightsql = arrow::flight::sql;

//! The header a client's JWT arrives in. `authorization: Bearer <jwt>` is what every Flight SQL driver
//! sends when it is given a token, so this is the driver's setting rather than our invention.
constexpr const char *AUTH_HEADER = "authorization";
constexpr const char *BEARER = "bearer ";

//! An opaque, unguessable id - for tickets, for the same reason spec 040 mints one for a session: a
//! Flight ticket is handed to the client, so nothing in it may be a credential of ours.
string MintId() {
	static const char *HEX = "0123456789abcdef";
	std::random_device source;
	string out;
	out.reserve(32);
	for (idx_t i = 0; i < 4; i++) {
		auto word = static_cast<uint64_t>(source()) | (static_cast<uint64_t>(source()) << 32);
		for (idx_t nibble = 0; nibble < 8; nibble++) {
			out.push_back(HEX[(word >> (nibble * 4)) & 0xF]);
		}
	}
	return out;
}

arrow::Status StatusFromDuck(const string &what, const string &error) {
	return arrow::Status::Invalid(what + ": " + error);
}

//! Everything one served instance needs: the database the statements run against, the store that
//! resolves sessions, and the statements whose tickets are outstanding.
struct FlightDoorState {
	explicit FlightDoorState(DatabaseInstance &db_p, shared_ptr<PolicyStore> store_p)
	    : db(db_p), store(std::move(store_p)) {
	}

	DatabaseInstance &db;
	shared_ptr<PolicyStore> store;

	std::mutex lock;
	//! ticket id -> the already-prefixed statement it stands for. The prefixed text never leaves the
	//! server: what the client holds is the id.
	std::unordered_map<string, string> tickets;
	//! Flight peer -> session handle. A Flight call carries its peer identity, and the handshake is
	//! what binds a verified token to it - the same job quack's connection_id does (spec 041).
	std::unordered_map<string, string> sessions;

	void Bind(const string &peer, const string &handle) {
		std::lock_guard<std::mutex> guard(lock);
		auto previous = sessions.find(peer);
		if (previous != sessions.end() && previous->second != handle) {
			store->SessionClose(previous->second); // as SessionBind does: end what this replaces
		}
		sessions[peer] = handle;
	}

	bool HandleFor(const string &peer, string &out) {
		std::lock_guard<std::mutex> guard(lock);
		auto entry = sessions.find(peer);
		if (entry == sessions.end()) {
			return false;
		}
		out = entry->second;
		return true;
	}

	string PutTicket(const string &prefixed) {
		auto id = MintId();
		std::lock_guard<std::mutex> guard(lock);
		tickets[id] = prefixed;
		return id;
	}

	bool TakeTicket(const string &id, string &out) {
		std::lock_guard<std::mutex> guard(lock);
		auto entry = tickets.find(id);
		if (entry == tickets.end()) {
			return false;
		}
		out = entry->second;
		tickets.erase(entry); // one ticket, one fetch: a replayed ticket is not a second read
		return true;
	}
};

//! The token a call carries, or "" - read from the headers on every call rather than only at a
//! handshake, because a Flight client is free to open a fresh connection per call and several drivers
//! do exactly that.
string TokenFromHeaders(const flight::ServerCallContext &context) {
	for (const auto &header : context.incoming_headers()) {
		if (!StringUtil::CIEquals(string(header.first), AUTH_HEADER)) {
			continue;
		}
		string value(header.second);
		if (value.size() > strlen(BEARER) && StringUtil::CIEquals(value.substr(0, strlen(BEARER)), BEARER)) {
			return value.substr(strlen(BEARER));
		}
		return value;
	}
	return string();
}

class AclFlightSqlServer : public flightsql::FlightSqlServerBase {
public:
	explicit AclFlightSqlServer(shared_ptr<FlightDoorState> state_p) : state(std::move(state_p)) {
	}

	//! Where a client's SQL arrives. Nothing about the policy is decided here: the statement is
	//! prefixed with the caller's session and handed on, exactly as quack's authorization callback
	//! does. A caller without a live session is refused, and refused is the default.
	arrow::Result<std::unique_ptr<flight::FlightInfo>>
	GetFlightInfoStatement(const flight::ServerCallContext &context, const flightsql::StatementQuery &command,
	                       const flight::FlightDescriptor &descriptor) override {
		string handle;
		ARROW_ASSIGN_OR_RAISE(handle, SessionFor(context));

		auto prefixed = state->store->SessionSql(handle, command.query);
		if (prefixed.empty()) {
			return arrow::Status::Invalid("acl: this session is no longer usable - reconnect");
		}

		// The schema has to be known before the rows are fetched, so the statement is prepared once
		// here. Preparing also means a statement the ACL refuses fails now, with the client still
		// waiting on GetFlightInfo, rather than half way through a stream.
		Connection con(state->db);
		auto prepared = con.Prepare(prefixed);
		if (prepared->HasError()) {
			return StatusFromDuck("acl", prepared->GetError());
		}
		std::shared_ptr<arrow::Schema> schema;
		ARROW_ASSIGN_OR_RAISE(schema, SchemaOf(*prepared));

		auto ticket_id = state->PutTicket(prefixed);
		ARROW_ASSIGN_OR_RAISE(auto ticket, flightsql::CreateStatementQueryTicket(ticket_id));
		std::vector<flight::FlightEndpoint> endpoints {
		    flight::FlightEndpoint {flight::Ticket {std::move(ticket)}, {}, std::nullopt, {}}};
		ARROW_ASSIGN_OR_RAISE(auto info, flight::FlightInfo::Make(*schema, descriptor, endpoints, -1, -1, false));
		return std::make_unique<flight::FlightInfo>(std::move(info));
	}

	//! Where the rows go out. The statement behind this ticket was prefixed when the ticket was made,
	//! so the ACL has already had its say; what is left is running it and handing over Arrow.
	arrow::Result<std::unique_ptr<flight::FlightDataStream>>
	DoGetStatement(const flight::ServerCallContext &context, const flightsql::StatementQueryTicket &command) override {
		string prefixed;
		if (!state->TakeTicket(string(command.statement_handle), prefixed)) {
			return arrow::Status::KeyError("acl: unknown or already fetched ticket");
		}
		Connection con(state->db);
		auto result = con.Query(prefixed);
		if (result->HasError()) {
			return StatusFromDuck("acl", result->GetError());
		}
		std::shared_ptr<arrow::Schema> schema;
		ARROW_ASSIGN_OR_RAISE(schema, SchemaFor(result->GetTypes(), result->GetNames()));

		std::vector<std::shared_ptr<arrow::RecordBatch>> batches;
		auto properties = con.context->GetClientProperties();
		while (true) {
			auto chunk = result->Fetch();
			if (!chunk || chunk->size() == 0) {
				break;
			}
			ArrowArray array;
			ArrowConverter::ToArrowArray(*chunk, &array, properties, {});
			ARROW_ASSIGN_OR_RAISE(auto batch, arrow::ImportRecordBatch(&array, schema));
			batches.push_back(std::move(batch));
		}
		ARROW_ASSIGN_OR_RAISE(auto reader, arrow::RecordBatchReader::Make(std::move(batches), schema));
		return std::make_unique<flight::RecordBatchStream>(std::move(reader));
	}

private:
	//! The caller's session: their token verified once, then remembered against the Flight peer. A
	//! token that does not verify is refused here and learns nothing more (spec 040).
	arrow::Result<string> SessionFor(const flight::ServerCallContext &context) {
		auto peer = context.peer_identity().empty() ? context.peer() : context.peer_identity();
		auto token = TokenFromHeaders(context);
		if (!token.empty()) {
			auto handle = state->store->SessionOpen(token);
			if (handle.empty()) {
				return arrow::Status::UnknownError("acl: authentication failed");
			}
			state->Bind(peer, handle);
			return handle;
		}
		string handle;
		if (!state->HandleFor(peer, handle)) {
			return arrow::Status::UnknownError("acl: authentication failed");
		}
		return handle;
	}

	arrow::Result<std::shared_ptr<arrow::Schema>> SchemaOf(PreparedStatement &prepared) {
		return SchemaFor(prepared.GetTypes(), prepared.GetNames());
	}

	//! duckdb names columns with `Identifier`; the Arrow converter takes plain strings, so the one
	//! conversion happens here rather than at both call sites.
	arrow::Result<std::shared_ptr<arrow::Schema>> SchemaFor(const vector<LogicalType> &types,
	                                                        const vector<Identifier> &names) {
		vector<string> plain;
		plain.reserve(names.size());
		for (auto &name : names) {
			plain.push_back(name.GetIdentifierName());
		}
		Connection con(state->db);
		auto properties = con.context->GetClientProperties();
		ArrowSchema schema;
		ArrowConverter::ToArrowSchema(&schema, types, plain, properties);
		return arrow::ImportSchema(&schema);
	}

	shared_ptr<FlightDoorState> state;
};

//! A door that is listening: the server, the thread serving it, and the state its calls share.
struct ServedDoor {
	std::unique_ptr<AclFlightSqlServer> server;
	std::thread thread;
	shared_ptr<FlightDoorState> state;
};

//! One server per listen uri, per process. Kept here rather than in the store: the store is policy,
//! and a listening socket is not.
struct ServedDoors {
	std::mutex lock;
	std::unordered_map<string, ServedDoor> doors;

	static ServedDoors &Get() {
		static ServedDoors doors;
		return doors;
	}
};

//! `grpc://host:port`, or a bare `host:port` for convenience. Returned by value because everything
//! after this point needs the host to decide whether serving it in the clear is acceptable.
arrow::Result<flight::Location> ParseListenUri(const string &uri, string &host_out) {
	auto text = StringUtil::Contains(uri, "://") ? uri : "grpc://" + uri;
	ARROW_ASSIGN_OR_RAISE(auto location, flight::Location::Parse(text));
	// Read back from the parsed form rather than from what was passed in: `Location` normalises, and
	// the host is what decides below whether serving this address in the clear is acceptable.
	auto normalised = location.ToString();
	auto host_start = normalised.find("://");
	host_start = host_start == string::npos ? 0 : host_start + 3;
	auto host_end = normalised.find(':', host_start);
	host_out = normalised.substr(host_start, host_end == string::npos ? string::npos : host_end - host_start);
	return location;
}

//! The four things spec 041 refuses to serve past, restated for this door. Each is checked before the
//! socket is touched, so the refusal names the thing to fix.
void RefuseUnlessServable(ClientContext &context, PolicyStore &store, const string &host) {
	if (!store.CatalogEnabled()) {
		throw BinderException("acl_flight_serve: no policy source is configured - a served instance "
		                      "resolves every statement against one, so `acl_use_db` comes first");
	}
	if (store.CatalogAnonymousAdminAllowed()) {
		throw BinderException("acl_flight_serve: `acl_allow_anonymous_admin` is on, so a served client "
		                      "could administer the ACL with a bare `ACL ADMIN` - turn it off first");
	}
	Value override_setting;
	if (context.TryGetCurrentSetting("allow_parser_override_extension", override_setting) &&
	    !StringUtil::CIEquals(override_setting.ToString(), "strict")) {
		throw BinderException("acl_flight_serve: the parser override is \"%s\", not STRICT - a served "
		                      "statement that failed to parse as ACL would fall through to plain SQL",
		                      override_setting.ToString());
	}
	// TLS is this door's own job (spec 045) and is not implemented yet, so the only address it will
	// serve is one that cannot leave the machine. Refusing is the honest form of "not yet".
	if (host != "localhost" && host != "127.0.0.1" && host != "::1") {
		throw BinderException("acl_flight_serve: this door serves in the clear so far, so it binds only "
		                      "localhost - TLS is a follow-up, and until it lands a non-local address "
		                      "would be handing out data unencrypted (spec 045)");
	}
}

//! acl_flight_serve(uri): start the Flight SQL door in this process.
void AclFlightServeFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &context = state.GetContext();
	result.SetVectorType(VectorType::FLAT_VECTOR);
	for (idx_t row = 0; row < args.size(); row++) {
		auto uri = FlatVector::GetData<string_t>(args.data[0])[row].GetString();
		auto &store = StoreOf(state);

		string host;
		auto location = ParseListenUri(uri, host);
		if (!location.ok()) {
			throw BinderException("acl_flight_serve: %s", location.status().ToString());
		}
		RefuseUnlessServable(context, store, host);

		auto &doors = ServedDoors::Get();
		std::lock_guard<std::mutex> guard(doors.lock);
		if (doors.doors.count(uri) > 0) {
			throw BinderException("acl_flight_serve: a door is already listening on %s", uri);
		}

		ServedDoor door;
		door.state = make_shared_ptr<FlightDoorState>(*context.db, StoreShared(state));
		door.server = std::make_unique<AclFlightSqlServer>(door.state);
		flight::FlightServerOptions options(*location);
		auto init = door.server->Init(options);
		if (!init.ok()) {
			throw BinderException("acl_flight_serve: %s", init.ToString());
		}
		// Serve() blocks for the life of the door, so it gets a thread of its own; Shutdown() is what
		// ends it, and acl_flight_stop is the only thing that calls that.
		auto *serving = door.server.get();
		door.thread = std::thread([serving]() { (void)serving->Serve(); });
		doors.doors.emplace(uri, std::move(door));

		result.SetValue(row, Value(uri));
	}
}

//! acl_flight_stop(uri): close it, and end the sessions it served - a door is the only thing that
//! knows it closed (spec 041's reasoning, unchanged here).
void AclFlightStopFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	result.SetVectorType(VectorType::FLAT_VECTOR);
	for (idx_t row = 0; row < args.size(); row++) {
		auto uri = FlatVector::GetData<string_t>(args.data[0])[row].GetString();
		auto &doors = ServedDoors::Get();
		ServedDoor door;
		{
			std::lock_guard<std::mutex> guard(doors.lock);
			auto entry = doors.doors.find(uri);
			if (entry == doors.doors.end()) {
				throw BinderException("acl_flight_stop: no door of ours is listening on %s", uri);
			}
			door = std::move(entry->second);
			doors.doors.erase(entry);
		}
		auto shutdown = door.server->Shutdown();
		if (door.thread.joinable()) {
			door.thread.join();
		}
		auto closed = StoreOf(state).SessionCloseAll();
		result.SetValue(row, Value(uri + " (" + std::to_string(closed) + " session(s) closed)" +
		                           (shutdown.ok() ? "" : " [" + shutdown.ToString() + "]")));
	}
}

} // namespace

void RegisterAclFlightDoor(ExtensionLoader &loader, shared_ptr<PolicyStore> store) {
	auto v = LogicalType::VARCHAR;
	auto register_door = [&](const string &name, scalar_function_t fn) {
		ScalarFunction function(Identifier(name), {v}, v, fn);
		function.SetExtraFunctionInfo(make_shared_ptr<AclScalarInfo>(store));
		function.SetFallible();
		loader.RegisterFunction(function);
	};
	register_door("acl_flight_serve", AclFlightServeFunc);
	register_door("acl_flight_stop", AclFlightStopFunc);
}

} // namespace acl
} // namespace duckdb
