//===----------------------------------------------------------------------===//
//                         DuckDB ACL
//
// acl_session_state.hpp
//
// Spec 135: what a session holds, carried in the cookie a door sets - the portable context (its USE, the
// client-local settings it SET) and why it cannot move (pinned: an open transaction, a temp table, the
// view-as mode). A node that does not know a session restores the context of one that is not pinned and
// refuses the first call of one that is, once. The codec is pure (no store, no connection): the door
// computes the state and judges every restored item through the client's own paths.
//===----------------------------------------------------------------------===//

#pragma once

#include <string>
#include <utility>
#include <vector>

namespace duckdb {
namespace acl {

//! the cookie's name, beside acl_flight_session_id and acl_node
constexpr const char *SESSION_STATE_COOKIE = "acl_session_state";
//! the encoded value's bound: a larger state is pinned "context", never written partly
constexpr std::size_t SESSION_STATE_MAX_BYTES = 3072;
//! the decoder reads no more than this, whatever arrives
constexpr std::size_t SESSION_STATE_MAX_INPUT = 4096;

//! What a session holds. Empty = nothing worth a cookie.
struct SessionState {
	//! spec 114's USE, canonical keys (spec 116); empty = none
	std::string use_catalog;
	std::string use_schema;
	//! the client-local settings the client SET (spec 068's allowlist), in the order they are written
	std::vector<std::pair<std::string, std::string>> settings;
	//! why it cannot move: "transaction", "temp", "view_as", or "context" (a state past the bound, or an
	//! entry this build does not know)
	std::vector<std::string> pinned;

	bool Empty() const {
		return use_catalog.empty() && use_schema.empty() && settings.empty() && pinned.empty();
	}
	bool Pinned() const {
		return !pinned.empty();
	}
	bool operator==(const SessionState &other) const {
		return use_catalog == other.use_catalog && use_schema == other.use_schema && settings == other.settings &&
		       pinned == other.pinned;
	}
};

//! The cookie's value: base64url (no padding) of {"v":1, "use":{...}, "set":{...}, "pinned":[...]}. An
//! empty state encodes as "". A state whose encoding passes SESSION_STATE_MAX_BYTES becomes
//! {"v":1,"pinned":["context"]}: a move then errors honestly instead of carrying part of it.
std::string EncodeSessionState(const SessionState &state);

enum class SessionStateRead {
	ABSENT,    // no value: nothing to restore, nothing to refuse
	OK,        // read whole
	UNREADABLE // malformed, oversized, an unknown version, a wrong type: refused once, never read partly
};

//! Read a cookie value. On UNREADABLE `out` is left empty.
SessionStateRead DecodeSessionState(const std::string &value, SessionState &out);

//! The Set-Cookie header value for an encoded state; "" clears the cookie (Max-Age=0). The attributes are
//! the session cookie's own.
std::string SessionStateSetCookie(const std::string &encoded);

//! What a refusal names: "open transaction", "temp tables", "view-as mode", "session context"
std::string SessionStateLost(const std::vector<std::string> &pinned);

} // namespace acl
} // namespace duckdb
