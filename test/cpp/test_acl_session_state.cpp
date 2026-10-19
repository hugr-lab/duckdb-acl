// The session-state cookie's codec (spec 135), with no store and no door: a state round-trips, the bound turns a
// large one into a pin, and anything that is not exactly what this build writes reads as UNREADABLE - never partly.
// src/acl_session_state.cpp is compiled into this test. Build + run via `GEN=ninja make test-cpp`.

#include "acl_test_util.hpp"

#include "acl_session_state.hpp"

using namespace acl_test;
using duckdb::acl::DecodeSessionState;
using duckdb::acl::EncodeSessionState;
using duckdb::acl::PORTABLE_SETTINGS;
using duckdb::acl::PortableSetting;
using duckdb::acl::SESSION_STATE_MAX_BYTES;
using duckdb::acl::SessionState;
using duckdb::acl::SessionStateLost;
using duckdb::acl::SessionStateRead;
using duckdb::acl::SessionStateSetCookie;

namespace {

std::string B64Url(const std::string &json) {
	// the encoder's own output for a state is the reference; raw inputs are spelled here by hand
	static const char *alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
	std::string out;
	unsigned buffer = 0;
	int bits = 0;
	for (unsigned char c : json) {
		buffer = buffer << 8 | c;
		bits += 8;
		while (bits >= 6) {
			bits -= 6;
			out += alphabet[buffer >> bits & 63];
		}
	}
	if (bits > 0) {
		out += alphabet[buffer << (6 - bits) & 63];
	}
	return out;
}

SessionStateRead Read(const std::string &value, SessionState &out) {
	return DecodeSessionState(value, out);
}

void RoundTrip() {
	SessionState empty;
	Check(EncodeSessionState(empty).empty(), "an empty state encodes as no value");
	SessionState read;
	Check(Read("", read) == SessionStateRead::ABSENT, "no value reads as absent");

	SessionState state;
	state.principal = "0123456789abcdef";
	state.use_catalog = "sales";
	state.use_schema = "\"eu.west\"";
	state.settings = {{"TimeZone", "Europe/Berlin"}, {"acl_correlation_id", "req \"1\"\n\\x"}};
	auto value = EncodeSessionState(state);
	Check(!value.empty() && value.find_first_of("=+/;, ") == std::string::npos,
	      "the value is base64url without padding: a cookie carries it as is");
	Check(Read(value, read) == SessionStateRead::OK && read == state, "use and settings round-trip, escapes included");
	Check(!read.Pinned(), "a state with nothing pinned moves");

	state.pinned = {"transaction", "temp"};
	Check(Read(EncodeSessionState(state), read) == SessionStateRead::OK && read == state && read.Pinned(),
	      "the pins round-trip");
	Check(SessionStateLost(read.pinned) == "its open transaction, its temp tables", "a refusal names what was lost");
}

void Bound() {
	SessionState big;
	big.principal = "0123456789abcdef";
	big.settings = {{"acl_traceparent", std::string(SESSION_STATE_MAX_BYTES, 'x')}};
	big.pinned = {"transaction", "view_as"};
	auto value = EncodeSessionState(big);
	SessionState read;
	Check(value.size() <= SESSION_STATE_MAX_BYTES, "a state past the bound is never written whole");
	Check(Read(value, read) == SessionStateRead::OK &&
	          read.pinned == std::vector<std::string> {"transaction", "view_as", "context"} && read.settings.empty() &&
	          read.principal == big.principal,
	      "past the bound the state keeps its principal and its pins, adds 'context', and carries nothing partly");
	// one setting short of the bound is carried whole
	SessionState fits;
	fits.principal = big.principal;
	fits.settings = {{"acl_traceparent", std::string(600, 'y')}};
	Check(Read(EncodeSessionState(fits), read) == SessionStateRead::OK && read == fits,
	      "a state within the bound whole");
	// a VALID state past the input bound is not read: the bound is checked before anything else
	std::string huge = "{\"v\":1,\"p\":\"x\",\"set\":{\"TimeZone\":\"" + std::string(4000, 'z') + "\"}}";
	Check(Read(B64Url(huge), read) == SessionStateRead::UNREADABLE, "a valid state past 4096 bytes is not read");
}

void Malformed() {
	SessionState read;
	auto unreadable = [&](const std::string &value, const std::string &what) {
		bool refused = Read(value, read) == SessionStateRead::UNREADABLE && read.Empty();
		Check(refused, what + " reads as unreadable, with nothing taken from it");
	};
	unreadable(B64Url("{\"v\":1}"), "no principal");
	unreadable(B64Url("{\"v\":1,\"p\":\"\"}"), "an empty principal");
	unreadable(B64Url("{\"v\":1,\"p\":\"t\",\"set\":{\"search_path\":\"x\"}}"),
	           "a setting outside the client-local list (search_path)");
	unreadable(B64Url("{\"v\":1,\"p\":\"t\",\"set\":{\"TimeZone\":\"UTC\",\"timezone\":\"UTC\"}}"),
	           "a setting twice (a restore runs one statement per item: bounded by the list)");
	unreadable(B64Url("{\"v\":1,\"p\":\"t\",\"set\":{\"TimeZone\":\"UTC\\u0000x\"}}"), "a NUL inside a value");
	unreadable("not*base64", "a character outside base64url");
	unreadable("eyJ2Ijox=", "padding");
	unreadable("A", "a length base64 cannot end on");
	unreadable(B64Url("[1,2]"), "JSON that is no object");
	unreadable(B64Url("{\"v\":1"), "truncated JSON");
	unreadable(B64Url("{\"use\":{\"catalog\":\"c\"}}"), "no version");
	unreadable(B64Url("{\"v\":2}"), "a version this build does not know");
	unreadable(B64Url("{\"v\":\"1\"}"), "a version of the wrong type");
	unreadable(B64Url("{\"v\":1,\"use\":\"c.s\"}"), "use not an object");
	unreadable(B64Url("{\"v\":1,\"use\":{\"catalog\":1}}"), "a use part not a string");
	unreadable(B64Url("{\"v\":1,\"use\":{\"database\":\"c\"}}"), "a use part this build does not write");
	unreadable(B64Url("{\"v\":1,\"set\":{\"TimeZone\":3}}"), "a setting's value not a string");
	unreadable(B64Url("{\"v\":1,\"pinned\":\"transaction\"}"), "pinned not an array");
	unreadable(B64Url("{\"v\":1,\"pinned\":[1]}"), "a pin not a string");
	unreadable(B64Url("{\"v\":1,\"p\":\"t\",\"handle\":\"x\"}"), "a key this build does not write");

	Check(Read(B64Url("{\"v\":1,\"p\":\"t\",\"pinned\":[\"lock\"]}"), read) == SessionStateRead::OK &&
	          read.pinned == std::vector<std::string> {"context"},
	      "a pin this build does not know still pins, as 'context'");
	Check(Read(B64Url("{\"v\":1,\"p\":\"t\"}"), read) == SessionStateRead::OK && read.Empty(),
	      "a principal alone is an empty state");
	Check(Read(B64Url("{\"v\":1,\"p\":\"t\",\"set\":{\"timezone\":\"UTC\"}}"), read) == SessionStateRead::OK &&
	          read.settings.size() == 1 && read.settings[0].first == "TimeZone",
	      "a listed setting in any case reads in the list's spelling");
}

void OneList() {
	// what a moved session carries is exactly what a client may SET: ClientSettingAllowed reads this list
	Check(sizeof(PORTABLE_SETTINGS) / sizeof(PORTABLE_SETTINGS[0]) == 8, "eight client-local settings");
	for (auto name : {"TimeZone", "calendar", "ACL_METADATA_MAX_ROWS", "acl_correlation_id", "acl_traceparent",
	                  "acl_lineage_parent", "acl_lineage_root_parent", "acl_lineage_job"}) {
		Check(PortableSetting(name) != nullptr, std::string(name) + " is on the list");
	}
	for (auto name : {"search_path", "schema", "acl_use_schema", "threads", "memory_limit", "TimeZoneX", ""}) {
		Check(PortableSetting(name) == nullptr, "'" + std::string(name) + "' is not");
	}
}

void Cookie() {
	Check(SessionStateSetCookie("abc") == "acl_session_state=abc; HttpOnly; Path=/; SameSite=Strict",
	      "the cookie carries the session cookie's attributes");
	Check(SessionStateSetCookie("") == "acl_session_state=; Max-Age=0; HttpOnly; Path=/; SameSite=Strict",
	      "an empty state clears the cookie");
}

} // namespace

int main() {
	return RunMain("the session-state cookie (spec 135)", [&] {
		Scenario("round trip", RoundTrip);
		Scenario("bound", Bound);
		Scenario("malformed", Malformed);
		Scenario("one list", OneList);
		Scenario("cookie", Cookie);
	});
}
