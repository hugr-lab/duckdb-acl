//===----------------------------------------------------------------------===//
// acl_quack_embed.hpp — the embedded quack door (spec 063, design/016 A2)
//
// quack's server, compiled INTO acl rather than reached through a loopback proxy
// (the spec-062 front this replaces). The protocol machinery is quack's own,
// unchanged (third_party/quack); only the listener is acl-owned (AclQuackServer):
// it binds the PUBLIC address, terminates TLS itself, and answers the
// unauthenticated `/.well-known/quack-auth` discovery document. Everything acl
// registers here is `acl_quack_*`-named, so a standalone quack loaded alongside
// never collides (spec 063, Strategy B).
//
// This is the module's one seam, mirroring src/flight/: two registrations, called
// once at extension load. The server object graph, httplib and the serve/stop API
// (acl_quack_server.hpp) stay inside src/quack_embed/.
//===----------------------------------------------------------------------===//

#pragma once

#include "acl_policy.hpp"

namespace duckdb {

class ExtensionLoader;
class Connection;
class DatabaseInstance;
class QueryResult;

namespace acl {

//! spec 079: the workers a quack client reserves by default - its default read-ahead (64 on 16 cores)
static constexpr idx_t ACL_QUACK_CLIENT_DEPTH_DEFAULT = 64;

//! Register the embedded server's SQL surface: the acl_quack_* server settings the embedded graph
//! reads, and the acl_quack_scan_data drain table function.
void RegisterAclQuackEmbed(ExtensionLoader &loader);

//! Register the door itself (spec 041/063): acl_quack_serve / acl_quack_stop, and the two callbacks
//! the server calls - acl_quack_authenticate per connection, acl_quack_authorize per statement.
void RegisterAclQuackDoor(ExtensionLoader &loader, shared_ptr<PolicyStore> store);

//! A statement the server drove for a client completed: called from the generated server TU (a
//! sync.py patch, see there) with the outcome, on the server's statement thread. What the audit
//! wants from it is the drain of a client's streamed insert - since quack f4328c5 a statement the
//! CLIENT composes (`INSERT ... SELECT * FROM scan_data_from_quack_client(...)`) and the server runs
//! like any other - recorded as the session's ingest with its rows, or why it failed (spec 069).
//! Any other statement is ignored here (its decision was audited by the override). Never throws.
void AclQuackStatementCompleted(Connection &connection, const string &connection_id, const string &sql,
                                QueryResult &result);
//! The server's statement driver, before it submits a statement on a connection (spec 074): decides
//! from the level and the session's trace whether the execution is profiled, and sets the
//! connection's profiler so. A connection nobody bound is left alone. Never throws.
void AclQuackStatementStarting(Connection &connection, const string &connection_id);
//! The server's connect, before authentication opens a session (spec 079): true when the door has
//! a seat for one more client - `seated` quack clients each reserving `acl_quack_client_depth` of
//! the `acl_quack_server_max_connections` workers. False with the reason to answer, audited as a
//! `session refused` with `at_capacity`. Never throws.
bool AclQuackAdmit(DatabaseInstance &db, idx_t seated, string &refusal);

//! A seat held for a client while it authenticates (spec 079): admission counts the clients seated
//! AND the ones between the check and their connection's creation, so a burst of connects cannot all
//! pass the check at once. Held for the connect handler's scope - released when the connection is
//! created or refused, an exception included.
//! spec 080: a statement's place in the node's stream budget, for as long as it produces - taken in
//! the server's statement driver before Query() (waiting in arrival order up to
//! `acl_stream_queue_timeout`), released when production ends. Throws the refusal when the wait
//! runs out, and an interrupt when the client went away meanwhile; the driver turns either into the
//! stream's error, which the client's PREPARE answers.
class AclQuackStreamSlot {
public:
	explicit AclQuackStreamSlot(Connection &connection);
	~AclQuackStreamSlot();
	AclQuackStreamSlot(const AclQuackStreamSlot &) = delete;
	AclQuackStreamSlot &operator=(const AclQuackStreamSlot &) = delete;

private:
	shared_ptr<PolicyStore> store;
	idx_t bytes = 0;
};

//! spec 085: the resource limits of the session a door connection's statement runs under - put on the
//! server connection by AclQuackStatementStarting, read by the stream slot and the fetch window of
//! that statement. A connection nobody bound carries none (the node's settings apply).
class AclQuackSessionLimits : public ClientContextState {
public:
	static constexpr const char *KEY = "acl_quack_session_limits";
	//! Swapped whole under the lock: a FETCH of the previous statement's stream may read while the
	//! next statement puts its session's limits here
	void Set(ResourceLimits limits_p) {
		auto next = make_shared_ptr<const ResourceLimits>(std::move(limits_p));
		lock_guard<mutex> guard(lock);
		limits = std::move(next);
	}
	shared_ptr<const ResourceLimits> Get() const {
		lock_guard<mutex> guard(lock);
		return limits;
	}

private:
	mutable mutex lock;
	shared_ptr<const ResourceLimits> limits;
};
//! The limits on `context`'s connection now, or null
shared_ptr<const ResourceLimits> AclQuackLimitsOf(ClientContext &context);

//! spec 080: what one quack stream reserves, and the node's budget, as the settings say now; spec 085:
//! a session's group may name the window cap and the batch the reservation is priced by
idx_t AclQuackStreamReserve(DatabaseInstance &db, const ResourceLimits *limits = nullptr);
idx_t AclNodeStreamBudget(DatabaseInstance &db);

class AclQuackSeatClaim {
public:
	AclQuackSeatClaim(DatabaseInstance &db, idx_t seated, string &refusal);
	~AclQuackSeatClaim();
	AclQuackSeatClaim(const AclQuackSeatClaim &) = delete;
	AclQuackSeatClaim &operator=(const AclQuackSeatClaim &) = delete;
	bool Granted() const {
		return granted;
	}

private:
	DatabaseInstance &db;
	bool granted = false;
	bool counted = false;
};
//! The server dropped a client connection (spec 079): its DISCONNECT (`how` = client) or a heartbeat
//! lease that ran out (`idle`). The acl session bound to it ends now. Never throws.
void AclQuackConnectionGone(DatabaseInstance &db, const string &connection_id, const char *how);

} // namespace acl
} // namespace duckdb
