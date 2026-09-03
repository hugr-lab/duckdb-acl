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

#include "acl_flight_catalog.hpp"
#include "duckdb/common/error_data.hpp"

#include <algorithm>
#include <chrono>
#include <arrow/util/config.h>

#include "duckdb/common/arrow/arrow_converter.hpp"
#include "duckdb/common/arrow/arrow_wrapper.hpp"
#include "duckdb/function/table/arrow.hpp"
#include "duckdb/common/exception/binder_exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/types/blob.hpp"
#include "acl_door_auth.hpp"
#include "acl_door_common.hpp"
#include "acl_oidc.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/planner/expression/bound_function_expression.hpp"
#include <thread>

#include <arrow/c/bridge.h>
#include <arrow/flight/server.h>
#include <arrow/flight/middleware.h>
#include <arrow/flight/server_auth.h>
#include <arrow/flight/server_middleware.h>
#include <arrow/flight/sql/server.h>
#include <arrow/record_batch.h>
#include <arrow/status.h>
#include <arrow/table.h>
#include <mutex>
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
	return MintRandomHex(16); // the store's minter, with its deterministic-device guard (spec 040)
}

arrow::Status StatusFromDuck(const string &what, const string &error) {
	return arrow::Status::Invalid(what + ": " + error);
}

//! The exec-context seam (spec 050), held for exactly the Prepare that needs it: the rewriter reads
//! this context to resolve session temp names authoritatively. Set inside the connection's exec
//! lock, on the calling thread - the parse inside Prepare runs synchronously on it, and it is
//! cleared before the lock is released, so no other thread ever observes a value.
struct TempScanScope {
	explicit TempScanScope(ClientContext *context) {
		SetTempScanContext(context);
	}
	~TempScanScope() {
		SetTempScanContext(nullptr);
	}
};

//! Everything one served instance needs: the database the statements run against, the store that
//! resolves sessions, and the statements whose tickets are outstanding.
struct FlightDoorState {
	explicit FlightDoorState(DatabaseInstance &db_p, shared_ptr<PolicyStore> store_p)
	    : db(db_p), store(std::move(store_p)) {
	}

	DatabaseInstance &db;
	shared_ptr<PolicyStore> store;

	std::mutex lock;

	//! The session's connection (spec 050): a session IS a duckdb connection, held for as long as
	//! the session lives, so what a connection owns - temp tables, in time a transaction - survives
	//! across the session's RPCs and is visible to nobody else's. ~7KB idle, measured; destroying
	//! the entry reclaims all of it natively.
	struct SessionConn {
		unique_ptr<Connection> con;
		//! One execution at a time per connection: neither a Connection nor a PreparedStatement is
		//! a concurrent object, and every reservation of a session now shares this one.
		std::mutex exec;
		//! The open transaction's id (spec 055), or "" for none. A session's connection holds at most
		//! one transaction - BeginTransaction opens it, EndTransaction ends it, and destroying the
		//! connection (session end) rolls it back natively. Guarded by `exec`, like the connection.
		string txn_id;
	};
	std::unordered_map<string, shared_ptr<SessionConn>> session_conns;
	int64_t last_conn_sweep = 0;

	//! The reservation (design 010 §10.3, applied to one instance): a statement PARSED, REWRITTEN
	//! AND BOUND exactly once, held on its session's own connection, redeemable only by the
	//! principal that made it. The ticket the client carries is an opaque id and nothing more - it
	//! is not an authority (the owner check is), and it carries no data (the store does).
	//!
	//! This replaces two earlier shapes at once. The spec-045 ticket held the client's *text* and
	//! recomposed under whoever fetched - the price was parsing and resolving twice, and the reason
	//! ("a stolen ticket answers the thief's own slice") became obsolete the day spec 047 introduced
	//! the stronger rule: a stolen handle earns nothing. The spec-047 prepared record held text too,
	//! and re-prepared per execution - same price, same obsolete reason. One record now serves both:
	//! a statement ticket is a single-use reservation, a prepared handle a reusable one with
	//! parameters.
	//!
	//! What is knowingly accepted: the record holds the statement as rewritten under the owner's
	//! rights at creation - a policy change between creation and redemption is not re-read. The
	//! window is TTL-bounded and identical to what any prepared statement anywhere accepts.
	struct Reservation {
		//! The session's connection, shared: the map entry may go (a transient session's does at
		//! scope end), but a pending ticket keeps the connection alive for exactly its own
		//! redemption - the shared_ptr is what bridges GetFlightInfo to DoGet.
		shared_ptr<SessionConn> conn;
		unique_ptr<PreparedStatement> stmt;
		string owner; // the creating principal's fingerprint (roles + claims)
		int64_t last_used = 0;
		bool single_use = false;
		vector<vector<Value>> parameter_rows;
	};
	std::unordered_map<string, shared_ptr<Reservation>> reservations;
	//! Refuse a new reservation rather than evict somebody's old one: an evicted one is a mid-flight
	//! failure, a refused create is a clean retry. (The old ticket map cleared itself wholesale at
	//! the cap - that was eviction by another name, and it goes with it.)
	static constexpr idx_t MAX_RESERVATIONS = 4096;
	//! Bound parameters are for parameters; bulk data is spec 049's ingest. Enforced while the
	//! stream is read, not after it sits in RAM.
	static constexpr idx_t MAX_PARAM_ROWS = 65536;

	static int64_t NowSeconds() {
		return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
		    .count();
	}

	//! Drop records nobody used for the session idle timeout - clients that crash close nothing,
	//! and a client whose token expired *cannot* close. spec 044's rule; an in-flight execution is
	//! safe because the map holds shared_ptrs. Caller holds the lock.
	void SweepReservationsLocked(int64_t idle_seconds) {
		if (idle_seconds <= 0) {
			return;
		}
		auto now = NowSeconds();
		for (auto it = reservations.begin(); it != reservations.end();) {
			if (now - it->second->last_used > idle_seconds) {
				it = reservations.erase(it);
			} else {
				++it;
			}
		}
	}

	string PutReservation(shared_ptr<Reservation> reservation, int64_t idle_seconds) {
		auto id = MintId();
		std::lock_guard<std::mutex> guard(lock);
		if (reservations.size() >= MAX_RESERVATIONS) {
			SweepReservationsLocked(idle_seconds);
		}
		if (reservations.size() >= MAX_RESERVATIONS) {
			return string();
		}
		reservation->last_used = NowSeconds();
		reservations[id] = std::move(reservation);
		return id;
	}

	//! Owner-checked: not yours reads exactly like not there - no oracle.
	shared_ptr<Reservation> FindReservation(const string &id, const string &owner) {
		std::lock_guard<std::mutex> guard(lock);
		auto entry = reservations.find(id);
		if (entry == reservations.end() || entry->second->owner != owner) {
			return nullptr;
		}
		entry->second->last_used = NowSeconds();
		return entry->second;
	}

	//! Find and erase in one motion: a single-use ticket is redeemed, not looked at. The returned
	//! shared_ptr keeps the record alive for exactly this execution.
	shared_ptr<Reservation> TakeReservation(const string &id, const string &owner) {
		std::lock_guard<std::mutex> guard(lock);
		auto entry = reservations.find(id);
		if (entry == reservations.end() || entry->second->owner != owner) {
			return nullptr;
		}
		auto out = std::move(entry->second);
		reservations.erase(entry);
		return out;
	}

	//! Idempotent, and silent about other people's reservations - the same no-oracle rule.
	void CloseReservation(const string &id, const string &owner) {
		std::lock_guard<std::mutex> guard(lock);
		auto entry = reservations.find(id);
		if (entry != reservations.end() && entry->second->owner == owner) {
			reservations.erase(entry);
		}
	}

	//! The session's connection, made on first use. Every execution path of a session goes through
	//! here, which is the whole point: what one statement of a session leaves on the connection, the
	//! next statement of the same session finds, and nobody else can.
	shared_ptr<SessionConn> ConnFor(const string &handle) {
		std::lock_guard<std::mutex> guard(lock);
		auto now = NowSeconds();
		if (now - last_conn_sweep >= 60) {
			last_conn_sweep = now;
			// sweep abandoned reservations on the same clock, not only under cap pressure (spec 055
			// review): a reservation holds a shared_ptr to its SessionConn, so a lingering one pins
			// the connection - and now an open transaction with its write locks - past session end.
			// This bounds an abandoned transaction to the idle timeout rather than the reservation cap.
			SweepReservationsLocked(store->SessionIdleTimeout());
			SweepConnsLocked();
		}
		auto &entry = session_conns[handle];
		if (!entry) {
			entry = make_shared_ptr<SessionConn>();
			entry->con = make_uniq<Connection>(db);
		}
		return entry;
	}

	//! Drop a session's connection entry. A reservation still holding the shared_ptr keeps the
	//! connection alive for its own pending redemption; nobody new can reach it.
	void DropConn(const string &handle) {
		std::lock_guard<std::mutex> guard(lock);
		session_conns.erase(handle);
	}

	//! Connections whose session is gone (swept, expired, admin-killed) go with it - and ONE clock
	//! rules both: the session's own liveness. The connection deliberately has no idle clock of its
	//! own, because the metadata RPCs keep a session warm without executing on its connection, and a
	//! second clock diverging there dropped temp tables under a live session (the PR review's
	//! finding). SessionAlive bumps nothing - an observer must not keep the observed alive. Caller
	//! holds the lock.
	void SweepConnsLocked() {
		for (auto it = session_conns.begin(); it != session_conns.end();) {
			if (!store->SessionAlive(it->first)) {
				it = session_conns.erase(it);
			} else {
				++it;
			}
		}
	}

	//! What the door's stop does: the server is down and its threads joined, so nothing is mid-use.
	void CloseAllConns() {
		std::lock_guard<std::mutex> guard(lock);
		session_conns.clear();
	}
};

//! Who a principal *is*, for owning door state across calls: the sorted roles and claims. Two tokens
//! of the same principal (a reconnect, a refresh) fingerprint alike; two principals never do.
string PrincipalFingerprint(const Principal &principal) {
	auto roles = principal.roles;
	std::sort(roles.begin(), roles.end());
	vector<string> claims;
	for (auto &entry : principal.claims) {
		claims.push_back(entry.first + "\x1e" + entry.second);
	}
	std::sort(claims.begin(), claims.end());
	string out;
	out += principal.subject + "\x1d"; // identity within the issuer (spec 050 F5), before roles/claims
	for (auto &role : roles) {
		out += role + "\x1f";
	}
	out += "\x1f";
	for (auto &claim : claims) {
		out += claim + "\x1f";
	}
	return out;
}

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

//! The session cookie (spec 050): the client's connection identity, in a cookie we own so a session
//! spans the connection's RPCs. Our own middleware rather than Arrow's ServerSessionMiddleware,
//! whose session store is never evicted (the M1 review's F2) - here the id lives in the ACL's own
//! session_bindings, swept with the sessions (spec 044), so nothing accumulates.
constexpr const char *SESSION_COOKIE = "acl_flight_session_id";
constexpr const char *COOKIE_MIDDLEWARE_KEY = "acl-cookie";

//! A CSPRNG cookie id (F4): every nibble from random_device, not a seeded PRNG - the cookie selects a
//! session that owns client resources, so it is a bearer credential and gets bearer-grade bytes.
string MintCookieId() {
	return MintRandomHex(16); // bearer-grade bytes from the one guarded minter (spec 040)
}

//! The session cookie a request carries, parsed by NAME from the Cookie header (F1: never a substring
//! of the value). Empty when the client sent none.
string CookieFromHeaders(const flight::ServerCallContext &context) {
	for (const auto &header : context.incoming_headers()) {
		if (!StringUtil::CIEquals(string(header.first), "cookie")) {
			continue;
		}
		string cookies(header.second);
		idx_t pos = 0;
		while (pos < cookies.size()) {
			auto semi = cookies.find(';', pos);
			auto piece = cookies.substr(pos, semi == string::npos ? string::npos : semi - pos);
			auto eq = piece.find('=');
			if (eq != string::npos) {
				string name = piece.substr(0, eq);
				StringUtil::Trim(name);
				if (name == SESSION_COOKIE) {
					string value = piece.substr(eq + 1);
					StringUtil::Trim(value);
					return value;
				}
			}
			if (semi == string::npos) {
				break;
			}
			pos = semi + 1;
		}
	}
	return string();
}

//! Carries the connection's cookie id for one call and, when it was minted this call, emits it.
class CookieMiddleware : public flight::ServerMiddleware {
public:
	CookieMiddleware(string id_p, bool fresh_p) : id(std::move(id_p)), fresh(fresh_p) {
	}
	string name() const override {
		return COOKIE_MIDDLEWARE_KEY;
	}
	void SendingHeaders(flight::AddCallHeaders *outgoing) override {
		if (fresh && outgoing) {
			outgoing->AddHeader("set-cookie",
			                    string(SESSION_COOKIE) + "=" + id + "; HttpOnly; Path=/; SameSite=Strict");
		}
	}
	void CallCompleted(const arrow::Status &) override {
	}
	string id;
	bool fresh; // minted this call (client sent none) -> set-cookie, and this call is transient
};

class CookieMiddlewareFactory : public flight::ServerMiddlewareFactory {
public:
	arrow::Status StartCall(const flight::CallInfo &, const flight::ServerCallContext &context,
	                        std::shared_ptr<flight::ServerMiddleware> *middleware) override {
		auto incoming = CookieFromHeaders(context);
		bool fresh = incoming.empty();
		*middleware = std::make_shared<CookieMiddleware>(fresh ? MintCookieId() : incoming, fresh);
		return arrow::Status::OK();
	}
};

//! --- spec 064: auth discovery + the password handshake --------------------------------------------
//! The two things a client without a token needs from the door: WHERE to authenticate (B2) and, for a
//! vanilla Username/Password client, the door running the OAuth password grant for it (B3). The IdP
//! is the gate for B3 - the node carries no flow toggle of its own; an IdP that refuses ROPC refuses
//! this handshake, and that refusal is surfaced as the answer.

//! The door's auth handler: what the Handshake RPC does. A payload-less handshake stays the no-op
//! success of spec 058 (the per-call Bearer header is the real gate, and IsValid refuses nobody);
//! the payload `discover-auth` answers the discovery document - the Handshake is the protocol's own
//! unauthenticated pre-auth exchange, and FlightSqlServerBase seals DoAction against custom actions.
class AclDoorAuthHandler : public flight::ServerAuthHandler {
public:
	explicit AclDoorAuthHandler(shared_ptr<FlightDoorState> state_p) : state(std::move(state_p)) {
	}
	arrow::Status Authenticate(const flight::ServerCallContext &, flight::ServerAuthSender *outgoing,
	                           flight::ServerAuthReader *incoming) override {
		string payload;
		if (!incoming->Read(&payload).ok()) {
			payload.clear(); // a client that sent nothing is the JDBC/ADBC path: connect, nothing more
		}
		if (payload == "discover-auth") {
			return outgoing->Write(DoorAuthJson(*state->store));
		}
		return arrow::Status::OK();
	}
	arrow::Status IsValid(const flight::ServerCallContext &, const std::string &, std::string *peer_identity) override {
		peer_identity->clear();
		return arrow::Status::OK();
	}

private:
	shared_ptr<FlightDoorState> state;
};

//! `authorization: Basic <base64 user:password>` on the Handshake, or false. Anywhere else the
//! header is ignored: the exchange runs once per connection, where the drivers send it.
bool BasicFromHeaders(const flight::ServerCallContext &context, string &user, string &password) {
	for (const auto &header : context.incoming_headers()) {
		if (!StringUtil::CIEquals(string(header.first), AUTH_HEADER)) {
			continue;
		}
		string value(header.second);
		constexpr const char *BASIC = "Basic ";
		if (value.size() <= strlen(BASIC) || !StringUtil::CIEquals(value.substr(0, strlen(BASIC)), BASIC)) {
			return false;
		}
		auto encoded = value.substr(strlen(BASIC));
		string decoded;
		try {
			string_t blob(encoded.c_str(), NumericCast<uint32_t>(encoded.size()));
			auto size = Blob::FromBase64Size(blob);
			decoded.resize(size);
			Blob::FromBase64(blob, reinterpret_cast<data_ptr_t>(&decoded[0]), size);
		} catch (std::exception &) {
			return false; // not base64 is not an error to act on, it is simply not BasicAuth
		}
		auto colon = decoded.find(':');
		if (colon == string::npos) {
			return false;
		}
		user = decoded.substr(0, colon);
		password = decoded.substr(colon + 1);
		return true;
	}
	return false;
}

//! Carries the bearer the handshake earned back to the client, in the response header the Flight
//! drivers (JDBC, ADBC, pyarrow's authenticate_basic_token) read it from.
class PasswordHandshakeMiddleware : public flight::ServerMiddleware {
public:
	explicit PasswordHandshakeMiddleware(string bearer_p) : bearer(std::move(bearer_p)) {
	}
	void SendingHeaders(flight::AddCallHeaders *outgoing_headers) override {
		outgoing_headers->AddHeader("authorization", "Bearer " + bearer);
	}
	void CallCompleted(const arrow::Status &) override {
	}
	std::string name() const override {
		return "PasswordHandshakeMiddleware";
	}

private:
	string bearer;
};

//! B3: a BasicAuth Handshake becomes the OAuth password grant, run by the node against the issuer's
//! own token endpoint, as the client_id the admin put on the issuer. The token the IdP answers is
//! verified offline exactly like any Bearer - the node trusts its own verification, never the
//! password - and handed back as the connection's bearer, so every later call takes the normal path.
//! The password crosses this function once and is neither logged nor stored.
class PasswordHandshakeFactory : public flight::ServerMiddlewareFactory {
public:
	PasswordHandshakeFactory(shared_ptr<FlightDoorState> state_p, bool has_tls_p)
	    : state(std::move(state_p)), has_tls(has_tls_p) {
	}
	arrow::Status StartCall(const flight::CallInfo &info, const flight::ServerCallContext &context,
	                        std::shared_ptr<flight::ServerMiddleware> *middleware) override {
		if (info.method != flight::FlightMethod::Handshake) {
			return arrow::Status::OK();
		}
		string user, password;
		if (!BasicFromHeaders(context, user, password)) {
			return arrow::Status::OK();
		}
		// a draining node refuses before running the grant (spec 066): the handshake exists only to
		// seat a new client, and minting an IdP token for one the node will refuse is waste and noise
		if (state->store->Draining()) {
			return flight::MakeFlightError(flight::FlightStatusCode::Unavailable,
			                               "acl: node is draining - not accepting new sessions");
		}
		// a cleartext door refuses before anything reads the password: the one thing worse than the
		// node seeing a password is the wire carrying it readable
		if (!has_tls) {
			return flight::MakeFlightError(flight::FlightStatusCode::Unauthenticated,
			                               "acl: the password handshake needs a TLS door "
			                               "(acl_flight_serve with a certificate) - refused over cleartext");
		}
		string refusal = "acl: no issuer here carries a CLIENT ID, so the door cannot run the "
		                 "password grant - authenticate with a bearer token instead";
		for (auto &issuer : state->store->ListIssuers()) {
			IssuerConfig config;
			if (!state->store->LookupIssuer(issuer, config) || config.client_id.empty()) {
				continue; // an issuer with no client_id cannot do ROPC and is skipped (spec 064)
			}
			auto ep = DiscoverEndpointsCached(issuer);
			if (!ep.Ok()) {
				refusal = "acl: OIDC discovery against " + issuer + " failed: " + ep.error;
				continue;
			}
			auto tokens = oidc::PasswordGrant(ep, config.client_id, config.client_secret, user, password);
			if (!tokens.Ok()) {
				// the IdP's own refusal IS the gate: unsupported_grant_type means ROPC is off there
				refusal = "acl: the IdP at " + issuer + " refused the password grant: " + tokens.error;
				continue;
			}
			Principal principal;
			bool verified = false;
			try {
				verified = state->store->VerifyPrincipal(true, tokens.access_token, principal);
			} catch (std::exception &) {
				verified = false;
			}
			if (!verified) {
				refusal = "acl: the token the IdP at " + issuer +
				          " answered does not verify against "
				          "this door's issuers";
				continue;
			}
			*middleware = std::make_shared<PasswordHandshakeMiddleware>(tokens.access_token);
			return arrow::Status::OK();
		}
		return flight::MakeFlightError(flight::FlightStatusCode::Unauthenticated, refusal);
	}

private:
	shared_ptr<FlightDoorState> state;
	bool has_tls;
};

class AclFlightSqlServer : public flightsql::FlightSqlServerBase {
public:
	explicit AclFlightSqlServer(shared_ptr<FlightDoorState> state_p) : state(std::move(state_p)) {
		// SqlInfo (spec 047): the base class answers GetSqlInfo from this registry - and answers
		// NOT_FOUND from an empty one, which a driver refuses outright while tolerating a server that
		// lacks the RPC entirely. So the registry is filled, with values chosen to be true rather
		// than flattering; a wrong answer here once panicked the Go driver (design/012).
		using Info = flightsql::SqlInfoOptions;
		RegisterSqlInfo(Info::FLIGHT_SQL_SERVER_NAME, string("duckdb-acl"));
#ifdef EXT_VERSION_ACL
		RegisterSqlInfo(Info::FLIGHT_SQL_SERVER_VERSION, string(EXT_VERSION_ACL));
#else
		RegisterSqlInfo(Info::FLIGHT_SQL_SERVER_VERSION, string("dev"));
#endif
		RegisterSqlInfo(Info::FLIGHT_SQL_SERVER_ARROW_VERSION, string(ARROW_VERSION_STRING));
		RegisterSqlInfo(Info::FLIGHT_SQL_SERVER_READ_ONLY, false);
		RegisterSqlInfo(Info::FLIGHT_SQL_SERVER_SQL, true);
		RegisterSqlInfo(Info::FLIGHT_SQL_SERVER_SUBSTRAIT, false);
		// spec 055: transactions live on the session's held connection - BEGIN/COMMIT/ROLLBACK across
		// RPCs, which is what a driver with autocommit off asks for. Savepoints are a follow-up.
		RegisterSqlInfo(Info::FLIGHT_SQL_SERVER_TRANSACTION,
		                int32_t(Info::SqlSupportedTransaction::SQL_SUPPORTED_TRANSACTION_TRANSACTION));
		RegisterSqlInfo(Info::FLIGHT_SQL_SERVER_CANCEL, false);
		// specs 049/051: DoPutCommandStatementIngest below - append, create or replace under the ACL
		RegisterSqlInfo(Info::FLIGHT_SQL_SERVER_BULK_INGESTION, true);
	}

	//! A statement's transaction_id, checked against the session's open transaction (spec 055). Empty
	//! is autocommit and always fine; a non-empty id must be the one BeginTransaction handed this
	//! session - a foreign or stale id is refused rather than silently run outside its transaction.
	//! The caller holds `conn->exec`, so the transaction it names cannot be ended underneath the check.
	static arrow::Status ValidateTxnLocked(const FlightDoorState::SessionConn &conn, const string &txn_id) {
		if (!txn_id.empty() && conn.txn_id != txn_id) {
			return arrow::Status::KeyError("acl: unknown transaction - it belongs to no open transaction of "
			                               "this session (begin one, or omit the id for autocommit)");
		}
		return arrow::Status::OK();
	}

	//! Begin a transaction on the session's own connection (spec 055): it spans the session's RPCs
	//! because the connection does, and it is rolled back natively if the session ends first. Needs a
	//! connection-long (cookie) session - a per-call one has nowhere to hold it.
	arrow::Result<flightsql::ActionBeginTransactionResult>
	BeginTransaction(const flight::ServerCallContext &context,
	                 const flightsql::ActionBeginTransactionRequest &) override {
		return UnderSession(context,
		                    [&](const string &handle) -> arrow::Result<flightsql::ActionBeginTransactionResult> {
			                    if (!ClientSentCookie(context)) {
				                    return arrow::Status::Invalid(
				                        "acl: a transaction needs a connection-long session - echo the door's "
				                        "session cookie (a client has one from its second call on)");
			                    }
			                    auto conn = state->ConnFor(handle);
			                    std::lock_guard<std::mutex> execution(conn->exec);
			                    if (!conn->txn_id.empty()) {
				                    return arrow::Status::Invalid(
				                        "acl: a transaction is already open on this session - commit or roll it "
				                        "back first (savepoints are a follow-up)");
			                    }
			                    auto begun = conn->con->Query("BEGIN TRANSACTION");
			                    if (begun->HasError()) {
				                    return StatusFromDuck("acl", begun->GetError());
			                    }
			                    conn->txn_id = MintId();
			                    flightsql::ActionBeginTransactionResult result;
			                    result.transaction_id = conn->txn_id;
			                    return result;
		                    });
	}

	//! Commit or roll back the session's transaction (spec 055). The id must be the session's own; the
	//! record is cleared whichever way duckdb's own COMMIT/ROLLBACK goes, so a failed commit does not
	//! strand the session in a transaction it can no longer name.
	arrow::Status EndTransaction(const flight::ServerCallContext &context,
	                             const flightsql::ActionEndTransactionRequest &request) override {
		auto ended = UnderSession(context, [&](const string &handle) -> arrow::Result<bool> {
			auto conn = state->ConnFor(handle);
			std::lock_guard<std::mutex> execution(conn->exec);
			if (conn->txn_id.empty() || conn->txn_id != request.transaction_id) {
				return arrow::Status::KeyError("acl: unknown transaction");
			}
			const char *verb =
			    request.action == flightsql::ActionEndTransactionRequest::kCommit ? "COMMIT" : "ROLLBACK";
			auto done = conn->con->Query(verb);
			conn->txn_id.clear();
			if (done->HasError()) {
				return StatusFromDuck("acl", done->GetError());
			}
			return true;
		});
		return ended.status();
	}

	//! Where a client's SQL arrives. Nothing about the policy is decided here: the statement is
	//! prefixed with the caller's session and handed on, exactly as quack's authorization callback
	//! does. A caller without a live session is refused, and refused is the default.
	arrow::Result<std::unique_ptr<flight::FlightInfo>>
	GetFlightInfoStatement(const flight::ServerCallContext &context, const flightsql::StatementQuery &command,
	                       const flight::FlightDescriptor &descriptor) override {
		return UnderSession(context, [&](const string &handle) -> arrow::Result<std::unique_ptr<flight::FlightInfo>> {
			ARROW_ASSIGN_OR_RAISE(auto owner, OwnerOf(handle));
			auto prefixed = state->store->SessionSql(handle, command.query);
			if (prefixed.empty()) {
				return arrow::Status::Invalid("acl: this session is no longer usable - reconnect");
			}
			// Parsed, rewritten and bound ONCE, right here, while the session of this very call is
			// alive - and kept. A refusal surfaces now, with the client still on GetFlightInfo; the
			// schema comes from the same binder that will produce the rows; and DoGet has nothing
			// left to do but execute.
			auto reservation = make_shared_ptr<FlightDoorState::Reservation>();
			reservation->conn = state->ConnFor(handle);
			{
				std::lock_guard<std::mutex> execution(reservation->conn->exec);
				ARROW_RETURN_NOT_OK(ValidateTxnLocked(*reservation->conn, command.transaction_id));
				TempScanScope temp_scan(reservation->conn->con->context.get());
				reservation->stmt = reservation->conn->con->Prepare(prefixed);
			}
			if (reservation->stmt->HasError()) {
				return StatusFromDuck("acl", reservation->stmt->GetError());
			}
			std::shared_ptr<arrow::Schema> schema;
			ARROW_ASSIGN_OR_RAISE(schema, SchemaOf(*reservation->stmt));
			reservation->owner = owner;
			reservation->single_use = true;
			auto ticket_id = state->PutReservation(std::move(reservation), state->store->SessionIdleTimeout());
			if (ticket_id.empty()) {
				return arrow::Status::Invalid("acl: too many open tickets - fetch or retry later");
			}
			ARROW_ASSIGN_OR_RAISE(auto ticket, flightsql::CreateStatementQueryTicket(ticket_id));
			std::vector<flight::FlightEndpoint> endpoints {
			    flight::FlightEndpoint {flight::Ticket {std::move(ticket)}, {}, std::nullopt, {}}};
			ARROW_ASSIGN_OR_RAISE(auto info, flight::FlightInfo::Make(*schema, descriptor, endpoints, -1, -1, false));
			return std::make_unique<flight::FlightInfo>(std::move(info));
		});
	}

	//! Where the rows go out. The statement behind this ticket was prefixed when the ticket was made,
	//! so the ACL has already had its say; what is left is running it and handing over Arrow.
	arrow::Result<std::unique_ptr<flight::FlightDataStream>>
	DoGetStatement(const flight::ServerCallContext &context, const flightsql::StatementQueryTicket &command) override {
		// The ticket is an id; the statement behind it is already parsed, rewritten and bound under
		// its owner. What DoGet does is verify the caller IS that owner - a stolen ticket earns
		// nothing, spec 047's rule - and execute. No second parse, no second resolution.
		return UnderSession(context,
		                    [&](const string &caller) -> arrow::Result<std::unique_ptr<flight::FlightDataStream>> {
			                    ARROW_ASSIGN_OR_RAISE(auto owner, OwnerOf(caller));
			                    auto reservation = state->TakeReservation(string(command.statement_handle), owner);
			                    if (!reservation) {
				                    return arrow::Status::KeyError("acl: unknown or already fetched ticket");
			                    }
			                    std::lock_guard<std::mutex> execution(reservation->conn->exec);
			                    vector<Value> values;
			                    auto result = reservation->stmt->Execute(values, false);
			                    if (result->HasError()) {
				                    return StatusFromDuck("acl", result->GetError());
			                    }
			                    return StreamRows(*reservation->conn->con, *result);
		                    });
	}

	//! Text DML via DoPut - the path JDBC's executeUpdate speaks (spec 048). The statement path's
	//! twin: same session, same composition, same rewriter, same verbatim refusals; the count comes
	//! back as the protocol wants. Multi-statement strings keep duckdb's own refusal at Prepare.
	arrow::Result<int64_t> DoPutCommandStatementUpdate(const flight::ServerCallContext &context,
	                                                   const flightsql::StatementUpdate &command) override {
		return UnderSession(context, [&](const string &handle) -> arrow::Result<int64_t> {
			auto prefixed = state->store->SessionSql(handle, command.query);
			if (prefixed.empty()) {
				return arrow::Status::Invalid("acl: this session is no longer usable - reconnect");
			}
			auto conn = state->ConnFor(handle);
			std::lock_guard<std::mutex> execution(conn->exec);
			ARROW_RETURN_NOT_OK(ValidateTxnLocked(*conn, command.transaction_id));
			TempScanScope temp_scan(conn->con->context.get());
			auto stmt = conn->con->Prepare(prefixed);
			if (stmt->HasError()) {
				return StatusFromDuck("acl", stmt->GetError());
			}
			vector<Value> values;
			auto result = stmt->Execute(values, false);
			if (result->HasError()) {
				return StatusFromDuck("acl", result->GetError());
			}
			int64_t total = 0;
			auto chunk = result->Fetch();
			if (chunk && chunk->size() > 0 && chunk->ColumnCount() == 1) {
				auto count = chunk->GetValue(0, 0);
				if (!count.IsNull() && count.type().id() == LogicalTypeId::BIGINT) {
					total = count.GetValue<int64_t>();
				}
			}
			return total;
		});
	}

	//! --- bulk ingestion (spec 049) ---------------------------------------------------------------

	//! The client's Flight stream as a C ArrowArrayStream: get_next pulls the reader directly, so a
	//! load never sits in server RAM whole, and the row cap refuses *while reading*. The state lives
	//! on the DoPut frame, which outlives the one statement that scans it - release is a no-op.
	struct IngestStreamState {
		flight::FlightMessageReader *reader = nullptr;
		std::shared_ptr<arrow::Schema> schema;
		int64_t cap = 0;
		int64_t rows = 0;
		std::string error;
	};
	static int IngestGetSchema(struct ArrowArrayStream *stream, struct ArrowSchema *out) {
		auto &ingest = *reinterpret_cast<IngestStreamState *>(stream->private_data);
		auto status = arrow::ExportSchema(*ingest.schema, out);
		if (!status.ok()) {
			ingest.error = status.ToString();
			return EINVAL;
		}
		return 0;
	}
	static int IngestGetNext(struct ArrowArrayStream *stream, struct ArrowArray *out) {
		auto &ingest = *reinterpret_cast<IngestStreamState *>(stream->private_data);
		auto chunk = ingest.reader->Next();
		if (!chunk.ok()) {
			ingest.error = chunk.status().ToString();
			return EINVAL;
		}
		if (!chunk->data) {
			out->release = nullptr; // end of stream
			return 0;
		}
		ingest.rows += chunk->data->num_rows();
		if (ingest.cap > 0 && ingest.rows > ingest.cap) {
			ingest.error = "acl: the ingest exceeds acl_max_ingest_rows (" + std::to_string(ingest.cap) + ")";
			return EINVAL;
		}
		auto status = arrow::ExportRecordBatch(*chunk->data, out);
		if (!status.ok()) {
			ingest.error = status.ToString();
			return EINVAL;
		}
		return 0;
	}
	static const char *IngestLastError(struct ArrowArrayStream *stream) {
		auto &ingest = *reinterpret_cast<IngestStreamState *>(stream->private_data);
		return ingest.error.empty() ? nullptr : ingest.error.c_str();
	}
	static void IngestRelease(struct ArrowArrayStream *stream) {
		stream->release = nullptr; // owned by the DoPut frame
	}
	//! The two adapters arrow_scan wants (the ParamRowsFrom pattern): produce moves the C stream into
	//! duckdb's wrapper, get-schema asks the stream itself.
	static unique_ptr<ArrowArrayStreamWrapper> IngestStreamProduce(uintptr_t stream_ptr, ArrowStreamParameters &) {
		auto source = reinterpret_cast<ArrowArrayStream *>(stream_ptr);
		auto wrapper = make_uniq<ArrowArrayStreamWrapper>();
		wrapper->arrow_array_stream = *source;
		source->release = nullptr;
		return wrapper;
	}
	static void IngestStreamGetSchema(ArrowArrayStream *stream, ArrowSchema &schema) {
		stream->get_schema(stream, &schema);
	}

	//! Flight SQL bulk ingestion (spec 049): the client streams batches at a named table, the server
	//! composes `INSERT INTO <target>(<the stream's own column names>) SELECT ... FROM arrow_scan(...)`
	//! under the ACL INGEST prefix - a prefix only this code composes - and the rewriter enforces it
	//! as any other INSERT: caps, the grant's predicate where the row is written, injections. One
	//! statement, atomic on duckdb's own terms: a refusal anywhere stores nothing.
	arrow::Result<int64_t> DoPutCommandStatementIngest(const flight::ServerCallContext &context,
	                                                   const flightsql::StatementIngest &command,
	                                                   flight::FlightMessageReader *reader) override {
		return UnderSession(context, [&](const string &handle) -> arrow::Result<int64_t> {
			if (command.transaction_id.has_value() && !command.transaction_id->empty()) {
				// ingest runs the load in a transaction it owns (the row-count cross-check must decide
				// before commit, spec 049); joining a client's transaction would hand it the rollback
				return arrow::Status::Invalid(
				    "acl: bulk ingest runs in its own transaction - do not run it inside one");
			}
			using NotExist = flightsql::TableDefinitionOptionsTableNotExistOption;
			using Exists = flightsql::TableDefinitionOptionsTableExistsOption;
			auto not_exist = command.table_definition_options.if_not_exist;
			auto if_exists = command.table_definition_options.if_exists;
			bool create_form = false;
			bool replace_form = false;
			if (command.temporary) {
				// spec 050, completing spec 049 milestone 2: the staging target is a native temp
				// table on the session's own connection - which only exists for a connection-long
				// (cookie) session. The composed CREATE goes through the same rewriter gate as a
				// client's own: the temp capability, the anti-shadow rule, and the arrow_scan
				// exemption only the ACL INGEST prefix carries.
				if (!ClientSentCookie(context)) {
					return arrow::Status::Invalid(
					    "acl: a temporary ingest target lives in the session, and this call carries "
					    "none - a client that echoes the door's session cookie has one from its "
					    "second call on");
				}
				if ((command.catalog.has_value() && !command.catalog->empty() &&
				     !StringUtil::CIEquals(*command.catalog, "temp")) ||
				    (command.schema.has_value() && !command.schema->empty() &&
				     !StringUtil::CIEquals(*command.schema, "main") &&
				     !StringUtil::CIEquals(*command.schema, "temp"))) {
					return arrow::Status::Invalid(
					    "acl: a temporary target has no catalog or schema of its own - name the table alone");
				}
				if (not_exist == NotExist::kCreate && if_exists == Exists::kAppend) {
					return arrow::Status::Invalid("acl: mode create_append is ambiguous for a temporary target - "
					                              "ingest with mode create, replace or append");
				}
				replace_form = if_exists == Exists::kReplace;
				create_form = replace_form || not_exist == NotExist::kCreate;
				// mode append falls through: the INSERT below aims at the session's temp catalog,
				// and a target that was never created is the bind's own honest error
			} else {
				// spec 051: create and replace land in a physical home through the same rewriter
				// gate as a CREATE the principal typed - because the composed statement is one; the
				// create capability prices CREATE, and drop prices the REPLACE. Only the two-faced
				// mode keeps a refusal of its own.
				if (not_exist == NotExist::kCreate && if_exists == Exists::kAppend) {
					return arrow::Status::Invalid(
					    "acl: mode create_append is ambiguous - ingest with mode create, replace or append");
				}
				replace_form = if_exists == Exists::kReplace;
				create_form = replace_form || not_exist == NotExist::kCreate;
				if (!create_form && if_exists == Exists::kFail) {
					return arrow::Status::AlreadyExists("acl: if_exists = FAIL asks to fail when the target exists, "
					                                    "and an append target here always exists");
				}
			}
			ARROW_ASSIGN_OR_RAISE(auto schema, reader->GetSchema());
			if (schema->num_fields() == 0) {
				return arrow::Status::Invalid("acl: the ingest stream declares no columns");
			}
			// the client's own field names, quoted: the rewriter and duckdb check them by name and
			// width, so a stream that does not match the writable set is an error, never a shifted row
			auto quote = [](const string &name) {
				return "\"" + StringUtil::Replace(name, "\"", "\"\"") + "\"";
			};
			string target;
			if (command.catalog.has_value() && !command.catalog->empty()) {
				target += quote(*command.catalog) + ".";
			}
			if (command.schema.has_value() && !command.schema->empty()) {
				target += quote(*command.schema) + ".";
			}
			target += quote(command.table);
			string columns;
			for (int i = 0; i < schema->num_fields(); i++) {
				columns += (i ? ", " : "") + quote(schema->field(i)->name());
			}
			IngestStreamState ingest;
			ingest.reader = reader;
			ingest.schema = schema;
			ingest.cap = state->store->MaxIngestRows();
			ArrowArrayStream stream;
			stream.get_schema = IngestGetSchema;
			stream.get_next = IngestGetNext;
			stream.get_last_error = IngestLastError;
			stream.release = IngestRelease;
			stream.private_data = &ingest;
			// the three pointers travel as the door's own bound parameters - POINTER has no literal
			// form in SQL text, and this statement carries no parameters of anybody else's, so the
			// golden rule stands: the rewriter adds none, and no user numbering exists to shift
			string sql;
			if (create_form) {
				// one composition for both homes: the session's temp catalog (spec 050) or the
				// granted physical schema the rewriter resolves (spec 051)
				sql = string("CREATE ") + (replace_form ? "OR REPLACE " : "") +
				      (command.temporary ? "TEMP TABLE " + quote(command.table) : "TABLE " + target) +
				      " AS SELECT * FROM arrow_scan($1, $2, $3)";
			} else {
				if (command.temporary) {
					// append into the session's own staging table, never anywhere else
					target = "temp.main." + quote(command.table);
				}
				sql = "INSERT INTO " + target + " (" + columns + ") SELECT " + columns + " FROM arrow_scan($1, $2, $3)";
			}
			auto prefixed = "ACL INGEST '" + StringUtil::Replace(handle, "'", "''") + "' " + sql;
			auto conn = state->ConnFor(handle);
			std::lock_guard<std::mutex> execution(conn->exec);
			TempScanScope temp_scan(conn->con->context.get());
			auto &con = *conn->con;
			auto stmt = con.Prepare(prefixed);
			if (stmt->HasError()) {
				return StatusFromDuck("acl", stmt->GetError());
			}
			vector<Value> values {Value::POINTER(reinterpret_cast<uintptr_t>(&stream)),
			                      Value::POINTER(reinterpret_cast<uintptr_t>(&IngestStreamProduce)),
			                      Value::POINTER(reinterpret_cast<uintptr_t>(&IngestStreamGetSchema))};
			// the row cross-check has to decide BEFORE the write commits, or a false mismatch reports
			// failure on data that already landed and a retry double-loads (the review's finding). So
			// the load runs in a transaction this call OWNS. A held connection means a client's own
			// SQL `BEGIN` really does span RPCs now (as it always has on quack) - and joining such a
			// transaction would hand the rollback decision to the client, whose COMMIT would keep a
			// partial load. Refusing to load inside a transaction we would not own keeps "one batch,
			// one outcome" structural rather than conditional (the PR review's finding).
			if (con.HasActiveTransaction()) {
				return arrow::Status::Invalid(
				    "acl: ingest inside an open transaction is not supported - commit or roll back first");
			}
			auto begun = con.Query("BEGIN TRANSACTION");
			if (begun->HasError()) {
				return StatusFromDuck("acl", begun->GetError());
			}
			auto fail = [&](arrow::Status status) -> arrow::Status {
				con.Query("ROLLBACK");
				return status;
			};
			auto result = stmt->Execute(values, false);
			if (result->HasError()) {
				return fail(StatusFromDuck("acl", result->GetError()));
			}
			int64_t total = 0;
			auto chunk = result->Fetch();
			if (chunk && chunk->size() > 0 && chunk->ColumnCount() == 1) {
				auto count = chunk->GetValue(0, 0);
				if (!count.IsNull() && count.type().id() == LogicalTypeId::BIGINT) {
					total = count.GetValue<int64_t>();
				}
			}
			if (!ingest.error.empty()) {
				return fail(arrow::Status::Invalid(ingest.error));
			}
			// the GizmoSQL lesson: a partial load must be an error, never a silent success - and now it
			// is caught before commit, so nothing of a mismatched load is stored
			if (total != ingest.rows) {
				return fail(arrow::Status::Invalid("acl: the target took " + std::to_string(total) + " rows of the " +
				                                   std::to_string(ingest.rows) + " the stream delivered"));
			}
			auto committed = con.Query("COMMIT");
			if (committed->HasError()) {
				return StatusFromDuck("acl", committed->GetError());
			}
			return total;
		});
	}

	//! --- prepared statements (spec 047) ----------------------------------------------------------
	//!
	//! The ticket rule, applied to a handle: the record holds the client's own SQL, every call
	//! re-verifies the token, and execution composes under whoever calls - a stolen handle earns its
	//! holder exactly what their own token earns them. The client's parameters are the only
	//! parameters in the composed statement (the rewriter adds none - the golden rule), so the bound
	//! values map onto it one to one.

	arrow::Result<flightsql::ActionCreatePreparedStatementResult>
	CreatePreparedStatement(const flight::ServerCallContext &context,
	                        const flightsql::ActionCreatePreparedStatementRequest &request) override {
		return UnderSession(
		    context, [&](const string &handle) -> arrow::Result<flightsql::ActionCreatePreparedStatementResult> {
			    ARROW_ASSIGN_OR_RAISE(auto owner, OwnerOf(handle));
			    auto prefixed = state->store->SessionSql(handle, request.query);
			    if (prefixed.empty()) {
				    return arrow::Status::Invalid("acl: this session is no longer usable - reconnect");
			    }
			    auto reservation = make_shared_ptr<FlightDoorState::Reservation>();
			    reservation->conn = state->ConnFor(handle);
			    {
				    std::lock_guard<std::mutex> execution(reservation->conn->exec);
				    ARROW_RETURN_NOT_OK(ValidateTxnLocked(*reservation->conn, request.transaction_id));
				    TempScanScope temp_scan(reservation->conn->con->context.get());
				    reservation->stmt = reservation->conn->con->Prepare(prefixed);
			    }
			    if (reservation->stmt->HasError()) {
				    return StatusFromDuck("acl", reservation->stmt->GetError());
			    }
			    flightsql::ActionCreatePreparedStatementResult result;
			    ARROW_RETURN_NOT_OK(
			        SchemasFromStatement(*reservation->stmt, nullptr, result.dataset_schema, result.parameter_schema));
			    reservation->owner = owner;
			    auto id = state->PutReservation(std::move(reservation), state->store->SessionIdleTimeout());
			    if (id.empty()) {
				    return arrow::Status::Invalid("acl: too many open prepared statements - close some");
			    }
			    result.prepared_statement_handle = std::move(id);
			    return result;
		    });
	}

	arrow::Status ClosePreparedStatement(const flight::ServerCallContext &context,
	                                     const flightsql::ActionClosePreparedStatementRequest &request) override {
		auto closed = UnderSession(context, [&](const string &handle) -> arrow::Result<bool> {
			ARROW_ASSIGN_OR_RAISE(auto owner, OwnerOf(handle));
			state->CloseReservation(request.prepared_statement_handle, owner);
			return true;
		});
		return closed.status();
	}

	arrow::Status DoPutPreparedStatementQuery(const flight::ServerCallContext &context,
	                                          const flightsql::PreparedStatementQuery &command,
	                                          flight::FlightMessageReader *reader,
	                                          flight::FlightMetadataWriter *writer) override {
		auto bound = UnderSession(context, [&](const string &handle) -> arrow::Result<bool> {
			ARROW_ASSIGN_OR_RAISE(auto owner, OwnerOf(handle));
			ARROW_ASSIGN_OR_RAISE(auto rows, ParamRowsFrom(state->db, *reader, FlightDoorState::MAX_PARAM_ROWS));
			auto reservation = state->FindReservation(command.prepared_statement_handle, owner);
			if (!reservation) {
				return arrow::Status::KeyError("acl: unknown prepared statement");
			}
			std::lock_guard<std::mutex> execution(reservation->conn->exec);
			reservation->parameter_rows = std::move(rows);
			return true;
		});
		return bound.status();
	}

	arrow::Result<std::unique_ptr<flight::FlightInfo>>
	GetFlightInfoPreparedStatement(const flight::ServerCallContext &context,
	                               const flightsql::PreparedStatementQuery &command,
	                               const flight::FlightDescriptor &descriptor) override {
		return UnderSession(context, [&](const string &handle) -> arrow::Result<std::unique_ptr<flight::FlightInfo>> {
			ARROW_ASSIGN_OR_RAISE(auto owner, OwnerOf(handle));
			auto reservation = state->FindReservation(command.prepared_statement_handle, owner);
			if (!reservation) {
				return arrow::Status::KeyError("acl: unknown prepared statement");
			}
			std::shared_ptr<arrow::Schema> dataset_schema;
			std::shared_ptr<arrow::Schema> parameter_schema;
			{
				std::lock_guard<std::mutex> execution(reservation->conn->exec);
				auto bound = reservation->parameter_rows.empty() ? nullptr : &reservation->parameter_rows.front();
				ARROW_RETURN_NOT_OK(SchemasFromStatement(*reservation->stmt, bound, dataset_schema, parameter_schema));
			}
			// the ticket is the protocol's own command, which carries the handle - nothing is
			// remembered between the two calls that is not already in the reservation
			std::vector<flight::FlightEndpoint> endpoints {
			    flight::FlightEndpoint {flight::Ticket {descriptor.cmd}, {}, std::nullopt, {}}};
			ARROW_ASSIGN_OR_RAISE(auto info,
			                      flight::FlightInfo::Make(*dataset_schema, descriptor, endpoints, -1, -1, false));
			return std::make_unique<flight::FlightInfo>(std::move(info));
		});
	}

	arrow::Result<std::unique_ptr<flight::FlightDataStream>>
	DoGetPreparedStatement(const flight::ServerCallContext &context,
	                       const flightsql::PreparedStatementQuery &command) override {
		return UnderSession(
		    context, [&](const string &caller) -> arrow::Result<std::unique_ptr<flight::FlightDataStream>> {
			    ARROW_ASSIGN_OR_RAISE(auto owner, OwnerOf(caller));
			    auto reservation = state->FindReservation(command.prepared_statement_handle, owner);
			    if (!reservation) {
				    return arrow::Status::KeyError("acl: unknown prepared statement");
			    }
			    std::lock_guard<std::mutex> execution(reservation->conn->exec);
			    if (reservation->parameter_rows.size() > 1) {
				    // answering from the first row alone is a silently wrong result; batches are
				    // the update path's business
				    return arrow::Status::Invalid("acl: a query executes one parameter row - " +
				                                  std::to_string(reservation->parameter_rows.size()) + " are bound");
			    }
			    vector<Value> values;
			    if (!reservation->parameter_rows.empty()) {
				    values = reservation->parameter_rows.front();
			    }
			    auto result = reservation->stmt->Execute(values, false);
			    if (result->HasError()) {
				    return StatusFromDuck("acl", result->GetError());
			    }
			    return StreamRows(*reservation->conn->con, *result);
		    });
	}

	arrow::Result<int64_t> DoPutPreparedStatementUpdate(const flight::ServerCallContext &context,
	                                                    const flightsql::PreparedStatementUpdate &command,
	                                                    flight::FlightMessageReader *reader) override {
		return UnderSession(context, [&](const string &caller) -> arrow::Result<int64_t> {
			ARROW_ASSIGN_OR_RAISE(auto owner, OwnerOf(caller));
			auto reservation = state->FindReservation(command.prepared_statement_handle, owner);
			if (!reservation) {
				return arrow::Status::KeyError("acl: unknown prepared statement");
			}
			ARROW_ASSIGN_OR_RAISE(auto rows, ParamRowsFrom(state->db, *reader, FlightDoorState::MAX_PARAM_ROWS));
			std::lock_guard<std::mutex> execution(reservation->conn->exec);
			// executemany semantics, DBAPI's: once per parameter row. Zero rows with declared
			// parameters is zero executions - not one; only a parameterless statement runs once.
			if (rows.empty()) {
				if (reservation->stmt->GetParameterCount() > 0) {
					return int64_t(0);
				}
				rows.push_back({});
			}
			// One batch, one outcome (the review's lesson): a mid-batch refusal rolls the whole
			// batch back, so a retry cannot duplicate rows. When the client already holds an explicit
			// transaction (spec 055), the batch joins it rather than nesting a second BEGIN - the
			// client owns the commit then, and a mid-batch failure surfaces without us rolling back
			// work that is now the client's to keep or discard.
			auto &con = *reservation->conn->con;
			bool owns_txn = !con.HasActiveTransaction();
			if (owns_txn) {
				auto begun = con.Query("BEGIN TRANSACTION");
				if (begun->HasError()) {
					return StatusFromDuck("acl", begun->GetError());
				}
			}
			int64_t total = 0;
			for (auto &row : rows) {
				auto result = reservation->stmt->Execute(row, false);
				if (result->HasError()) {
					if (owns_txn) {
						con.Query("ROLLBACK");
					}
					return StatusFromDuck("acl", result->GetError());
				}
				auto chunk = result->Fetch();
				if (chunk && chunk->size() > 0 && chunk->ColumnCount() == 1) {
					auto count = chunk->GetValue(0, 0);
					// only a DML's count column is a count; anything else must not be force-cast
					if (!count.IsNull() && count.type().id() == LogicalTypeId::BIGINT) {
						total += count.GetValue<int64_t>();
					}
				}
			}
			if (owns_txn) {
				auto committed = con.Query("COMMIT");
				if (committed->HasError()) {
					return StatusFromDuck("acl", committed->GetError());
				}
			}
			return total;
		});
	}

	//! The caller's fingerprint, from the live session this call already opened.
	arrow::Result<string> OwnerOf(const string &session_handle) {
		Principal principal;
		string reason;
		if (!state->store->SessionPrincipal(session_handle, principal, reason)) {
			return arrow::Status::UnknownError("acl: authentication failed");
		}
		return PrincipalFingerprint(principal);
	}

	//! Prepare under the caller and hand back both schemas the protocol wants: the result's, and the
	//! parameters' - the latter from duckdb's own binder, ordered by parameter position, so the
	//! client binds exactly what the composed statement will accept.
	//! Both schemas the protocol wants, from an already-prepared statement: the result's (a
	//! parameter-riding UNKNOWN resolved by *planning* with the bound row when one exists - planning
	//! executes nothing) and the parameters', from duckdb's own binder, ordered by position.
	arrow::Status SchemasFromStatement(PreparedStatement &stmt, const vector<Value> *bound_row,
	                                   std::shared_ptr<arrow::Schema> &dataset_schema,
	                                   std::shared_ptr<arrow::Schema> &parameter_schema) {
		bool unresolved = false;
		for (auto &type : stmt.GetTypes()) {
			if (type.id() == LogicalTypeId::UNKNOWN) {
				unresolved = true;
			}
		}
		if (unresolved && bound_row) {
			vector<Value> values = *bound_row;
			auto pending = stmt.PendingQuery(values, false);
			if (!pending->HasError()) {
				ARROW_ASSIGN_OR_RAISE(dataset_schema, SchemaFor(pending->GetTypes(), pending->GetNames()));
			} else {
				ARROW_ASSIGN_OR_RAISE(dataset_schema, SchemaOf(stmt));
			}
		} else {
			ARROW_ASSIGN_OR_RAISE(dataset_schema, SchemaOf(stmt));
		}

		vector<std::pair<idx_t, std::pair<string, LogicalType>>> ordered;
		for (auto &entry : stmt.GetNamedParameterMap()) {
			LogicalType type = LogicalType::UNKNOWN;
			stmt.TryGetParameterType(entry.first, type);
			ordered.emplace_back(entry.second, std::make_pair(entry.first.GetIdentifierName(), type));
		}
		std::sort(ordered.begin(), ordered.end(), [](const auto &a, const auto &b) { return a.first < b.first; });
		vector<LogicalType> types;
		vector<Identifier> names;
		for (auto &entry : ordered) {
			names.emplace_back(entry.second.first);
			// an unresolved parameter type binds as anything; VARCHAR is the honest wire default
			types.push_back(entry.second.second.id() == LogicalTypeId::UNKNOWN ? LogicalType::VARCHAR
			                                                                   : entry.second.second);
		}
		ARROW_ASSIGN_OR_RAISE(parameter_schema, SchemaFor(types, names));
		return arrow::Status::OK();
	}

	//! A finished result as one Flight stream - the tail every data-returning RPC shares. (The
	//! statement path predates it and still carries its own copy; folding that is cleanup, not now.)
	arrow::Result<std::unique_ptr<flight::FlightDataStream>> StreamRows(Connection &con, QueryResult &result) {
		std::shared_ptr<arrow::Schema> schema;
		ARROW_ASSIGN_OR_RAISE(schema, SchemaFor(result.GetTypes(), result.GetNames()));

		std::vector<std::shared_ptr<arrow::RecordBatch>> batches;
		auto properties = con.context->GetClientProperties();
		while (true) {
			auto chunk = result.Fetch();
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

	//! --- the catalog RPCs (spec 046) -------------------------------------------------------------
	//!
	//! Every one of them is a statement the principal could have written. The door composes SQL over
	//! the surfaces spec 035 already replaces, runs it through the same session prefix, and reshapes
	//! the rows into the schema the protocol fixes. It holds a mapping, not a policy - so no bug here
	//! can widen what a role sees, because there is no path from here to the physical catalog.

	arrow::Result<std::unique_ptr<flight::FlightInfo>>
	GetFlightInfoCatalogs(const flight::ServerCallContext &context,
	                      const flight::FlightDescriptor &descriptor) override {
		return CatalogInfo(context, flightsql::SqlSchema::GetCatalogsSchema(), descriptor);
	}

	arrow::Result<std::unique_ptr<flight::FlightDataStream>>
	DoGetCatalogs(const flight::ServerCallContext &context) override {
		return CatalogStream(context, flightsql::SqlSchema::GetCatalogsSchema(),
		                     BuildCatalogListing(CatalogListing::CATALOGS, CatalogFilter()));
	}

	arrow::Result<std::unique_ptr<flight::FlightInfo>>
	GetFlightInfoSchemas(const flight::ServerCallContext &context, const flightsql::GetDbSchemas &command,
	                     const flight::FlightDescriptor &descriptor) override {
		return CatalogInfo(context, flightsql::SqlSchema::GetDbSchemasSchema(), descriptor);
	}

	arrow::Result<std::unique_ptr<flight::FlightDataStream>>
	DoGetDbSchemas(const flight::ServerCallContext &context, const flightsql::GetDbSchemas &command) override {
		return CatalogStream(context, flightsql::SqlSchema::GetDbSchemasSchema(),
		                     BuildCatalogListing(CatalogListing::DB_SCHEMAS, FilterFrom(command)));
	}

	arrow::Result<std::unique_ptr<flight::FlightInfo>>
	GetFlightInfoTables(const flight::ServerCallContext &context, const flightsql::GetTables &command,
	                    const flight::FlightDescriptor &descriptor) override {
		return CatalogInfo(context,
		                   command.include_schema ? flightsql::SqlSchema::GetTablesSchemaWithIncludedSchema()
		                                          : flightsql::SqlSchema::GetTablesSchema(),
		                   descriptor);
	}

	arrow::Result<std::unique_ptr<flight::FlightDataStream>> DoGetTables(const flight::ServerCallContext &context,
	                                                                     const flightsql::GetTables &command) override {
		auto filter = FilterFrom(command);
		if (!command.include_schema) {
			return CatalogStream(context, flightsql::SqlSchema::GetTablesSchema(),
			                     BuildCatalogListing(CatalogListing::TABLES, filter));
		}
		// With schemas: two statements, not one per table. The second is the columns listing under the
		// same filters, which describes what the role actually reads - so a hidden column is absent
		// from the schema a client is promised, and a masked one carries the mask's type (spec 026).
		auto schema = flightsql::SqlSchema::GetTablesSchemaWithIncludedSchema();
		return CatalogStream(
		    context, schema, [&](const string &handle) -> arrow::Result<std::shared_ptr<arrow::RecordBatch>> {
			    // on the session's own connection (spec 050): a listing composed here goes through
			    // the same rewriter with the executing context set, so the session's temp tables
			    // appear in GetTables exactly as they do in SHOW TABLES
			    auto conn = state->ConnFor(handle);
			    std::lock_guard<std::mutex> execution(conn->exec);
			    TempScanScope temp_scan(conn->con->context.get());
			    ARROW_ASSIGN_OR_RAISE(auto tables,
			                          RunCatalogQuery(*state->store, *conn->con, handle,
			                                          BuildCatalogListing(CatalogListing::TABLES, filter)));
			    ARROW_ASSIGN_OR_RAISE(auto columns,
			                          RunCatalogQuery(*state->store, *conn->con, handle,
			                                          BuildCatalogListing(CatalogListing::COLUMNS, filter)));
			    Connection con(state->db);
			    ARROW_ASSIGN_OR_RAISE(auto serialized, SchemasFor(*con.context, *tables, *columns));
			    return BatchFrom(schema, *tables, &serialized);
		    });
	}

	arrow::Result<std::unique_ptr<flight::FlightInfo>>
	GetFlightInfoTableTypes(const flight::ServerCallContext &context,
	                        const flight::FlightDescriptor &descriptor) override {
		return CatalogInfo(context, flightsql::SqlSchema::GetTableTypesSchema(), descriptor);
	}

	arrow::Result<std::unique_ptr<flight::FlightDataStream>>
	DoGetTableTypes(const flight::ServerCallContext &context) override {
		return CatalogStream(context, flightsql::SqlSchema::GetTableTypesSchema(),
		                     BuildCatalogListing(CatalogListing::TABLE_TYPES, CatalogFilter()));
	}

	arrow::Result<std::unique_ptr<flight::FlightInfo>>
	GetFlightInfoPrimaryKeys(const flight::ServerCallContext &context, const flightsql::GetPrimaryKeys &command,
	                         const flight::FlightDescriptor &descriptor) override {
		return CatalogInfo(context, flightsql::SqlSchema::GetPrimaryKeysSchema(), descriptor);
	}

	arrow::Result<std::unique_ptr<flight::FlightDataStream>>
	DoGetPrimaryKeys(const flight::ServerCallContext &context, const flightsql::GetPrimaryKeys &command) override {
		// spec 048: the *declared* key, from the same acl_keys() surface a principal reads - still
		// never a physical fact (spec 035's rule stands; the declaration is the virtual object's own)
		return CatalogStream(context, flightsql::SqlSchema::GetPrimaryKeysSchema(),
		                     BuildPrimaryKeyListing(TableRefFrom(command.table_ref)));
	}

	arrow::Result<std::unique_ptr<flight::FlightInfo>>
	GetFlightInfoImportedKeys(const flight::ServerCallContext &context, const flightsql::GetImportedKeys &command,
	                          const flight::FlightDescriptor &descriptor) override {
		return CatalogInfo(context, flightsql::SqlSchema::GetImportedKeysSchema(), descriptor);
	}

	arrow::Result<std::unique_ptr<flight::FlightDataStream>>
	DoGetImportedKeys(const flight::ServerCallContext &context, const flightsql::GetImportedKeys &command) override {
		return CatalogStream(context, flightsql::SqlSchema::GetImportedKeysSchema(),
		                     BuildKeyListing(KeyListing::IMPORTED, TableRefFrom(command.table_ref), CatalogTableRef()));
	}

	arrow::Result<std::unique_ptr<flight::FlightInfo>>
	GetFlightInfoExportedKeys(const flight::ServerCallContext &context, const flightsql::GetExportedKeys &command,
	                          const flight::FlightDescriptor &descriptor) override {
		return CatalogInfo(context, flightsql::SqlSchema::GetExportedKeysSchema(), descriptor);
	}

	arrow::Result<std::unique_ptr<flight::FlightDataStream>>
	DoGetExportedKeys(const flight::ServerCallContext &context, const flightsql::GetExportedKeys &command) override {
		return CatalogStream(context, flightsql::SqlSchema::GetExportedKeysSchema(),
		                     BuildKeyListing(KeyListing::EXPORTED, TableRefFrom(command.table_ref), CatalogTableRef()));
	}

	arrow::Result<std::unique_ptr<flight::FlightInfo>>
	GetFlightInfoCrossReference(const flight::ServerCallContext &context, const flightsql::GetCrossReference &command,
	                            const flight::FlightDescriptor &descriptor) override {
		return CatalogInfo(context, flightsql::SqlSchema::GetCrossReferenceSchema(), descriptor);
	}

	arrow::Result<std::unique_ptr<flight::FlightDataStream>>
	DoGetCrossReference(const flight::ServerCallContext &context,
	                    const flightsql::GetCrossReference &command) override {
		return CatalogStream(
		    context, flightsql::SqlSchema::GetCrossReferenceSchema(),
		    BuildKeyListing(KeyListing::CROSS, TableRefFrom(command.pk_table_ref), TableRefFrom(command.fk_table_ref)));
	}

private:
	//! A catalog answer needs no SQL to describe itself: its schema is a protocol constant. So this
	//! authenticates - nobody lists anything without a live token - and leaves the work to `DoGet`.
	//!
	//! The endpoint carries **no location**, and that is a decision rather than an omission. Flight's
	//! own words are that an empty location list means the ticket "can only be redeemed on the current
	//! service where the ticket was generated", which is right for a listing: every ready node answers
	//! it identically, so redirecting one would buy a round trip and change nothing. The ticket is the
	//! command itself - it names no session and grants nothing - so nothing is remembered between the
	//! two calls and no ticket registry is touched.
	arrow::Result<std::unique_ptr<flight::FlightInfo>> CatalogInfo(const flight::ServerCallContext &context,
	                                                               const std::shared_ptr<arrow::Schema> &schema,
	                                                               const flight::FlightDescriptor &descriptor) {
		return UnderSession(context, [&](const string &) -> arrow::Result<std::unique_ptr<flight::FlightInfo>> {
			std::vector<flight::FlightEndpoint> endpoints {
			    flight::FlightEndpoint {flight::Ticket {descriptor.cmd}, {}, std::nullopt, {}}};
			ARROW_ASSIGN_OR_RAISE(auto info, flight::FlightInfo::Make(*schema, descriptor, endpoints, -1, -1, false));
			return std::make_unique<flight::FlightInfo>(std::move(info));
		});
	}

	//! A catalog answer: whatever `produce` builds under the caller's session, as one stream in the
	//! protocol's schema. The two-statement `include_schema` path and the one-statement everything
	//! else share this skeleton rather than each carrying a copy of the open-run-close discipline.
	template <class Produce>
	arrow::Result<std::unique_ptr<flight::FlightDataStream>> CatalogStream(const flight::ServerCallContext &context,
	                                                                       const std::shared_ptr<arrow::Schema> &schema,
	                                                                       Produce produce) {
		return UnderSession(context,
		                    [&](const string &handle) -> arrow::Result<std::unique_ptr<flight::FlightDataStream>> {
			                    ARROW_ASSIGN_OR_RAISE(std::shared_ptr<arrow::RecordBatch> batch, produce(handle));
			                    return StreamOf(schema, std::move(batch));
		                    });
	}

	//! One statement, under the caller's own session, shaped into the protocol's schema.
	arrow::Result<std::unique_ptr<flight::FlightDataStream>> CatalogStream(const flight::ServerCallContext &context,
	                                                                       const std::shared_ptr<arrow::Schema> &schema,
	                                                                       const CatalogQuery &query) {
		return CatalogStream(
		    context, schema, [&](const string &handle) -> arrow::Result<std::shared_ptr<arrow::RecordBatch>> {
			    auto conn = state->ConnFor(handle);
			    std::lock_guard<std::mutex> execution(conn->exec);
			    TempScanScope temp_scan(conn->con->context.get());
			    ARROW_ASSIGN_OR_RAISE(auto rows, RunCatalogQuery(*state->store, *conn->con, handle, query));
			    return BatchFrom(schema, *rows, nullptr);
		    });
	}

	static arrow::Result<std::unique_ptr<flight::FlightDataStream>>
	StreamOf(const std::shared_ptr<arrow::Schema> &schema, std::shared_ptr<arrow::RecordBatch> batch) {
		std::vector<std::shared_ptr<arrow::RecordBatch>> batches {std::move(batch)};
		ARROW_ASSIGN_OR_RAISE(auto reader, arrow::RecordBatchReader::Make(std::move(batches), schema));
		return std::make_unique<flight::RecordBatchStream>(std::move(reader));
	}

	//! A session that closes itself, whichever way the call leaves. Sessions here are opened and closed
	//! inside one RPC (see SessionFor); the one way to leak one was a C++ exception between the two,
	//! and this is what makes that impossible rather than merely unlikely.
	struct SessionScope {
		SessionScope(FlightDoorState &state_p, string handle_p) : state(state_p), handle(std::move(handle_p)) {
		}
		~SessionScope() {
			state.store->SessionClose(handle);
			// a transient session's connection goes with it; a pending ticket's shared_ptr is what
			// bridges its GetFlightInfo to its DoGet
			state.DropConn(handle);
		}
		FlightDoorState &state;
		string handle;
	};

	//! The boundary every RPC crosses: authenticate, run `body` under the session, close the session,
	//! and let no C++ exception out.
	//!
	//! The last clause is the reason this exists. duckdb reports through exceptions and gRPC's handler
	//! catches everything into one message - "Unexpected error in RPC handling" - which tells a client
	//! nothing and used to skip SessionClose on the way past. Two of the throws are not even ours to
	//! avoid: SessionOpen resolves an issuer's keys before it verifies anything, and a JWKS document
	//! that cannot be read throws from under SessionFor; the Arrow converters throw on a type they do
	//! not carry. Every RPC now runs inside one try, so what escapes is a Status that names itself, and
	//! the session is closed by the scope's destructor either way. This is the same boundary the
	//! statement RPCs of spec 045 needed and did not have.
	template <class Body>
	auto UnderSession(const flight::ServerCallContext &context, Body body) -> decltype(body(string())) {
		try {
			string handle;
			bool transient = false;
			ARROW_ASSIGN_OR_RAISE(handle, SessionFor(context, transient));
			if (!transient) {
				// a connection-long session (spec 050): the sweeper, exp, CloseSession or the door's
				// stop end it - an RPC boundary does not
				return body(handle);
			}
			SessionScope scope(*state, handle);
			return body(handle);
		} catch (std::exception &ex) {
			// duckdb's what() is a JSON envelope; ErrorData gives the message a person wrote
			return StatusFromDuck("acl", ErrorData(ex).Message());
		}
	}

	//! The connection's cookie id, from our own middleware (empty if unavailable).
	string CookieOf(const flight::ServerCallContext &context) {
		auto *raw = context.GetMiddleware(COOKIE_MIDDLEWARE_KEY);
		return raw ? static_cast<CookieMiddleware *>(raw)->id : string();
	}
	//! Did the client actually send the cookie back - the difference between a connection-long session
	//! and a per-call one. A freshly minted cookie (client sent none) is transient.
	bool ClientSentCookie(const flight::ServerCallContext &context) {
		auto *raw = context.GetMiddleware(COOKIE_MIDDLEWARE_KEY);
		return raw && !static_cast<CookieMiddleware *>(raw)->fresh;
	}
	//! Verify a token without opening a session and without learning why a bad one is bad.
	//! ignore_exp: spec 059's 'connect' binding - re-verifying the bearer of an EXISTING session
	//! tolerates a past exp (the session was established with a fresh one); signature, issuer,
	//! audience, nbf and roles are still enforced, so the token remains the cryptographic proof of
	//! identity F9 asks for - only its staleness is forgiven, and only against a live session of the
	//! same fingerprint. Establishment (SessionOpen) never ignores exp, under either binding.
	bool VerifyQuietly(const string &token, Principal &out, bool ignore_exp = false) {
		try {
			return state->store->VerifyPrincipal(true, token, out, ignore_exp);
		} catch (std::exception &) {
			return false;
		}
	}

	//! The caller's session (spec 050): the client's connection, identified by the cookie our
	//! middleware set. A call that returns the cookie reuses the connection's session - which is what
	//! lets a session own resources across calls - and only a session of the SAME principal; a call
	//! without the cookie gets a per-call session, closed on the way out (the cookie-less degradation:
	//! single-call RPCs still work, a session resource honestly refuses on the next call). The token
	//! is the authority of every call, verified BEFORE the session's idle clock is touched (F9); an
	//! unverifiable token falls through to the honest refusal it always earned, cookie or not.
	arrow::Result<string> SessionFor(const flight::ServerCallContext &context, bool &transient) {
		auto token = TokenFromHeaders(context);
		if (token.empty()) {
			return arrow::Status::UnknownError("acl: authentication failed");
		}
		auto cookie = CookieOf(context);
		transient = !ClientSentCookie(context);
		if (!transient) {
			string handle;
			if (state->store->SessionHandleFor(cookie, handle)) {
				Principal caller;
				// under 'connect' the existing session's bearer may be stale; everything else about
				// it must still verify, and the fingerprint match below still gates (spec 059)
				if (!VerifyQuietly(token, caller, !state->store->SessionExpEveryUse())) {
					return arrow::Status::UnknownError("acl: authentication failed");
				}
				Principal current;
				string reason;
				if (state->store->SessionPrincipal(handle, current, reason)) {
					if (PrincipalFingerprint(caller) == PrincipalFingerprint(current)) {
						return handle; // the connection's own live session, same principal
					}
					// Re-authenticating as somebody else is a SWAP: close this session, open
					// another. A draining node refuses the swap BEFORE the close (spec 066):
					// drain never ends a session, and the close without the open would be
					// exactly that - the old principal keeps working until it leaves by itself.
					if (state->store->Draining()) {
						return flight::MakeFlightError(flight::FlightStatusCode::Unavailable,
						                               "acl: node is draining - not accepting new sessions");
					}
					state->store->SessionClose(handle); // re-authenticated as somebody else
					state->DropConn(handle);            // and the old principal's connection with it
				}
			}
		}
		// Whoever reaches this point is new: no live session of their own resolved above. A draining
		// node seats nobody new (spec 066), and says WHY - a load balancer and a driver both treat
		// UNAVAILABLE as "go elsewhere", where a generic auth failure would read as bad credentials.
		if (state->store->Draining()) {
			return flight::MakeFlightError(flight::FlightStatusCode::Unavailable,
			                               "acl: node is draining - not accepting new sessions");
		}
		auto handle = state->store->SessionOpen(token);
		if (handle.empty()) {
			// what refuses a token in the prefix refuses it here, and says no more (spec 040)
			return arrow::Status::UnknownError("acl: authentication failed");
		}
		if (!transient) {
			state->store->SessionBind(cookie, handle);
		}
		return handle;
	}

	//! Client-local settings over the protocol (spec 068): what a driver sets with session options
	//! (ADBC's `adbc.flight.sql.session.option.<name>`) lands as SQL SET on the session's own
	//! connection, through the same allowlist the SQL gate applies - so the two paths can never
	//! disagree. A per-call session has no connection to keep a setting on, so it is refused like
	//! any other session resource (spec 050).
	arrow::Result<flight::SetSessionOptionsResult>
	SetSessionOptions(const flight::ServerCallContext &context,
	                  const flight::SetSessionOptionsRequest &request) override {
		return UnderSession(context, [&](const string &handle) -> arrow::Result<flight::SetSessionOptionsResult> {
			if (!ClientSentCookie(context)) {
				return arrow::Status::Invalid("acl: a session option needs a connection-long session - echo the "
				                              "door's session cookie (a client has one from its second call on)");
			}
			auto conn = state->ConnFor(handle);
			std::lock_guard<std::mutex> execution(conn->exec);
			flight::SetSessionOptionsResult result;
			for (auto &option : request.session_options) {
				if (!ClientSettingAllowed(option.first)) {
					result.errors[option.first] = {flight::SetSessionOptionErrorValue::kInvalidName};
					continue;
				}
				auto *text = std::get_if<std::string>(&option.second);
				bool erase = std::holds_alternative<std::monostate>(option.second);
				if (!text && !erase) {
					result.errors[option.first] = {flight::SetSessionOptionErrorValue::kInvalidValue};
					continue;
				}
				auto sql = erase ? "RESET \"" + option.first + "\""
				                 : "SET \"" + option.first + "\" = '" + StringUtil::Replace(*text, "'", "''") + "'";
				auto applied = conn->con->Query(sql);
				if (applied->HasError()) {
					result.errors[option.first] = {flight::SetSessionOptionErrorValue::kInvalidValue};
				}
			}
			return result;
		});
	}

	//! The listed settings as this session currently renders them. Read through current_setting on
	//! the session's own connection - the door's, never the principal's (the function gate denies a
	//! principal current_setting, spec 052).
	arrow::Result<flight::GetSessionOptionsResult>
	GetSessionOptions(const flight::ServerCallContext &context, const flight::GetSessionOptionsRequest &) override {
		return UnderSession(context, [&](const string &handle) -> arrow::Result<flight::GetSessionOptionsResult> {
			flight::GetSessionOptionsResult result;
			if (!ClientSentCookie(context)) {
				return result; // a per-call session holds nothing
			}
			auto conn = state->ConnFor(handle);
			std::lock_guard<std::mutex> execution(conn->exec);
			for (const char *name : {"TimeZone", "Calendar"}) {
				auto value = conn->con->Query(string("SELECT current_setting('") + name + "')");
				if (!value->HasError() && value->RowCount() == 1 && !value->GetValue(0, 0).IsNull()) {
					result.session_options[name] = value->GetValue(0, 0).ToString();
				}
			}
			return result;
		});
	}

	//! The driver's own end-of-connection signal (spec 050): closes our session when the token speaks
	//! for it - a stolen cookie alone ends nothing. Idempotent.
	arrow::Result<flight::CloseSessionResult> CloseSession(const flight::ServerCallContext &context,
	                                                       const flight::CloseSessionRequest &) override {
		try {
			auto token = TokenFromHeaders(context);
			auto cookie = CookieOf(context);
			if (!token.empty() && !cookie.empty()) {
				string handle;
				if (state->store->SessionHandleFor(cookie, handle)) {
					Principal current, caller;
					string reason;
					if (state->store->SessionPrincipal(handle, current, reason) &&
					    VerifyQuietly(token, caller, !state->store->SessionExpEveryUse()) &&
					    PrincipalFingerprint(caller) == PrincipalFingerprint(current)) {
						state->store->SessionClose(handle); // also drops the cookie binding
						state->DropConn(handle);
					}
				}
			}
			return flight::CloseSessionResult {flight::CloseSessionStatus::kClosed};
		} catch (std::exception &ex) {
			return StatusFromDuck("acl", ErrorData(ex).Message());
		}
	}

	arrow::Result<std::shared_ptr<arrow::Schema>> SchemaOf(PreparedStatement &prepared) {
		return SchemaFor(prepared.GetTypes(), prepared.GetNames());
	}

	//! duckdb names columns with `Identifier`; the Arrow converter takes plain strings, so the one
	//! conversion happens here rather than at both call sites.
	arrow::Result<std::shared_ptr<arrow::Schema>> SchemaFor(const vector<LogicalType> &types_p,
	                                                        const vector<Identifier> &names) {
		// A type the binder could not resolve at prepare - a parameter, or a DML whose injected
		// write-check rides on one (spec 024) - arrives here as UNKNOWN, which Arrow cannot spell.
		// The promise degrades to VARCHAR, the wire default; what a fetch actually streams is built
		// from the *executed* result, which is always concretely typed. Found by a real driver
		// preparing an INSERT under an RLS grant: the result column of the rewritten statement was
		// UNKNOWN and the promised-schema conversion threw.
		vector<LogicalType> types = types_p;
		for (auto &type : types) {
			if (type.id() == LogicalTypeId::UNKNOWN) {
				type = LogicalType::VARCHAR;
			}
		}
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
	//! The database instance that opened it. The registry is per process and keyed by uri, so
	//! without this another instance could stop this door - and close ITS OWN sessions for the
	//! privilege (the 2026-09-03 review); and an instance that closed without acl_flight_stop left
	//! a door nobody could reclaim. The quack door has held the same since spec 063.
	weak_ptr<DatabaseInstance> owner;
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
arrow::Result<flight::Location> ParseListenUri(const string &uri, string &host_out, int &port_out) {
	auto text = StringUtil::Contains(uri, "://") ? uri : "grpc://" + uri;
	ARROW_ASSIGN_OR_RAISE(auto location, flight::Location::Parse(text));
	// Read back from the parsed form rather than from what was passed in: `Location` normalises, and
	// the host is what decides below whether serving this address in the clear is acceptable.
	auto normalised = location.ToString();
	auto host_start = normalised.find("://");
	host_start = host_start == string::npos ? 0 : host_start + 3;
	// A bracketed IPv6 literal (`[::1]:port`) carries colons inside the host, so the port is the
	// colon AFTER the closing bracket - splitting on the first colon would take one from inside the
	// address (the review's finding, which the `any address` promise now invites).
	size_t host_end;
	if (host_start < normalised.size() && normalised[host_start] == '[') {
		auto close = normalised.find(']', host_start);
		host_out = normalised.substr(host_start, close == string::npos ? string::npos : close - host_start + 1);
		host_end = (close != string::npos) ? normalised.find(':', close) : string::npos;
	} else {
		host_end = normalised.find(':', host_start);
		host_out = normalised.substr(host_start, host_end == string::npos ? string::npos : host_end - host_start);
	}
	port_out = host_end == string::npos ? 0 : std::atoi(normalised.c_str() + host_end + 1);
	return location;
}

//! acl_flight_serve(uri): start the Flight SQL door in this process.
void AclFlightServeFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &context = state.GetContext();
	result.SetVectorType(VectorType::FLAT_VECTOR);
	for (idx_t row = 0; row < args.size(); row++) {
		if (FlatVector::IsNull(args.data[0], row)) {
			throw BinderException("acl_flight_serve: the listen uri is required");
		}
		auto uri = FlatVector::GetData<string_t>(args.data[0])[row].GetString();
		auto &store = StoreOf(state);

		// spec 053: a cert+key turn the door to TLS - read as inline PEM or through duckdb's own
		// filesystem (a path, or an object-store URI over httpfs). Both or neither: a key without a
		// cert cannot serve, and saying so beats a cryptic gRPC init error.
		bool has_cert = args.ColumnCount() > 1 && !FlatVector::IsNull(args.data[1], row);
		bool has_key = args.ColumnCount() > 2 && !FlatVector::IsNull(args.data[2], row);
		if (has_cert != has_key) {
			throw BinderException("acl_flight_serve: TLS needs both a certificate and a key - "
			                      "acl_flight_serve(uri, cert, key)");
		}
		bool has_tls = has_cert && has_key;

		string host;
		int port = 0;
		auto location = ParseListenUri(uri, host, port);
		if (!location.ok()) {
			throw BinderException("acl_flight_serve: %s", location.status().ToString());
		}
		// the preconditions both doors share (acl_door_common): a cleartext Flight door has no
		// explicit cleartext mode, so without a certificate it is loopback-only, full stop
		RefuseUnlessServable(context, store, "acl_flight_serve", host, has_tls, false);
		if (has_tls) {
			// build the location as grpc+tls whatever scheme was written: the certificate is the
			// intent, and a plain grpc:// location would start a cleartext listener beside the certs
			auto tls_location = flight::Location::ForGrpcTls(host, port);
			if (!tls_location.ok()) {
				throw BinderException("acl_flight_serve: %s", tls_location.status().ToString());
			}
			location = tls_location;
		}

		auto &doors = ServedDoors::Get();
		// Reclaim a door left behind by an instance that closed without acl_flight_stop, BEFORE
		// binding, so its port is actually free; a live instance's door on this uri is refused,
		// untouched. The teardown runs outside the registry lock, as the quack door's does.
		{
			ServedDoor zombie;
			bool reclaim = false;
			{
				std::lock_guard<std::mutex> guard(doors.lock);
				auto entry = doors.doors.find(uri);
				if (entry != doors.doors.end()) {
					if (!entry->second.owner.expired()) {
						throw BinderException("acl_flight_serve: a door is already listening on %s", uri);
					}
					zombie = std::move(entry->second);
					doors.doors.erase(entry);
					reclaim = true;
				}
			}
			if (reclaim) {
				(void)zombie.server->Shutdown();
				if (zombie.thread.joinable()) {
					zombie.thread.join();
				}
			}
		}
		std::lock_guard<std::mutex> guard(doors.lock);
		if (doors.doors.count(uri) > 0) {
			throw BinderException("acl_flight_serve: a door is already listening on %s", uri);
		}

		ServedDoor door;
		door.owner = context.db;
		door.state = make_shared_ptr<FlightDoorState>(*context.db, SharedStoreOf(state));
		door.server = std::make_unique<AclFlightSqlServer>(door.state);
		flight::FlightServerOptions options(*location);
		// spec 058: the Arrow Flight SQL JDBC driver (DBeaver) opens a connection by calling the
		// Handshake RPC, and a server with no auth_handler answers it "This service does not have an
		// authentication mechanism enabled" - so the driver cannot even connect, though pyarrow and
		// ADBC, which never handshake, work. The door's handler keeps that a no-op success (the real
		// gate is the per-call `authorization: Bearer` header every RPC still carries), and spec 064
		// adds the two pre-auth answers: the `discover-auth` payload reads the discovery document,
		// and a BasicAuth handshake runs the IdP-gated password grant (the middleware below).
		options.auth_handler = std::make_shared<AclDoorAuthHandler>(door.state);
		if (has_tls) {
			auto cert = ReadPemArg(context, FlatVector::GetData<string_t>(args.data[1])[row].GetString(), "certificate",
			                       "acl_flight_serve");
			auto key = ReadPemArg(context, FlatVector::GetData<string_t>(args.data[2])[row].GetString(), "key",
			                      "acl_flight_serve");
			options.tls_certificates.push_back(flight::CertKeyPair {std::move(cert), std::move(key)});
		}
		// spec 050: the cookie identifies a client connection, which is what lets a session persist
		std::shared_ptr<flight::ServerMiddlewareFactory> cookie_factory = std::make_shared<CookieMiddlewareFactory>();
		options.middleware.emplace_back(string(COOKIE_MIDDLEWARE_KEY), std::move(cookie_factory));
		// spec 064: a BasicAuth Handshake becomes the IdP-gated password grant; TLS-only by refusal
		options.middleware.emplace_back(string("acl-password-handshake"),
		                                std::make_shared<PasswordHandshakeFactory>(door.state, has_tls));
		auto init = door.server->Init(options);
		if (!init.ok()) {
			// Init binds the listen address (and loads the TLS material): what fails here is the
			// environment - a port in use, an address that is not ours - not the policy, so it is an
			// IO error (the error contract, docs/security.md section 8)
			throw IOException("acl_flight_serve: %s", init.ToString());
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
			// another instance's door is not ours to stop: the sessions closed below would be
			// THIS instance's, and the door that died would be theirs
			if (entry->second.owner.lock().get() != state.GetContext().db.get()) {
				throw BinderException("acl_flight_stop: the door on %s belongs to another database instance", uri);
			}
			door = std::move(entry->second);
			doors.doors.erase(entry);
		}
		auto shutdown = door.server->Shutdown();
		if (door.thread.joinable()) {
			door.thread.join();
		}
		door.state->CloseAllConns();
		auto closed = StoreOf(state).SessionCloseAll();
		result.SetValue(row, Value(uri + " (" + std::to_string(closed) + " session(s) closed)" +
		                           (shutdown.ok() ? "" : " [" + shutdown.ToString() + "]")));
	}
}

} // namespace

void RegisterAclFlightDoor(ExtensionLoader &loader, shared_ptr<PolicyStore> store) {
	auto v = LogicalType::VARCHAR;
	auto register_door = [&](const string &name, vector<vector<LogicalType>> signatures, const scalar_function_t &fn,
	                         bool special_nulls) {
		ScalarFunctionSet set((Identifier(name)));
		for (auto &arguments : signatures) {
			ScalarFunction function(Identifier(name), std::move(arguments), v, fn);
			MarkAclScalar(function, store);
			// the serve body must run even when a cert/key argument is NULL, or duckdb's default null
			// propagation returns NULL without ever reaching the cert-without-key guard - a served
			// door that silently does not start (the review's finding)
			if (special_nulls) {
				function.SetNullHandling(FunctionNullHandling::SPECIAL_HANDLING);
			}
			set.AddFunction(function);
		}
		loader.RegisterFunction(set);
	};
	// spec 053: acl_flight_serve(uri) serves in the clear on localhost; (uri, cert, key) serves TLS
	// and may bind any address.
	register_door("acl_flight_serve", {{v}, {v, v, v}}, AclFlightServeFunc, true);
	register_door("acl_flight_stop", {{v}}, AclFlightStopFunc, false);
}

} // namespace acl
} // namespace duckdb
