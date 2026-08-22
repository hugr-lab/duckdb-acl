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

//! One server per listen uri, per instance. Kept here rather than in the store: the store is policy,
//! and a listening socket is not.
struct ServedDoors {
	std::mutex lock;
	std::unordered_map<string, std::unique_ptr<flight::FlightServerBase>> servers;

	static ServedDoors &Get() {
		static ServedDoors doors;
		return doors;
	}
};

} // namespace

void RegisterAclFlightDoor(ExtensionLoader &loader, shared_ptr<PolicyStore> store) {
	(void)loader;
	(void)store;
	// Registration of acl_flight_serve / acl_flight_stop lands in the next commit; this file exists
	// first so that the build integration - which is the risky half - is proven on its own.
}

} // namespace acl
} // namespace duckdb
