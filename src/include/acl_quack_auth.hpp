//===----------------------------------------------------------------------===//
// acl_quack_auth.hpp - a door's own auth-discovery document (spec 062/064), over the OIDC core
//
// `GET <base>/.well-known/quack-auth` names the issuers a node trusts, so a client needs no IdP
// configuration beyond the door's address. The door's, not the IdP's - so it stayed here when the
// OIDC core moved to duckdb-ext-common (spec 076); it uses the module's HttpGet and nothing else.
//===----------------------------------------------------------------------===//

#pragma once

#include "oidc_core.hpp"

#include <string>
#include <vector>

namespace duckdb {
namespace acl {
namespace oidc {

struct DoorAuth {
	std::vector<std::string> issuers;
	std::string error;

	bool Ok() const {
		return error.empty();
	}
};

DoorAuth FetchQuackAuth(const std::string &base_url, int timeout_seconds = 10);
//! The parser behind it, over a response already received: a pure function of the bytes a door
//! answered, which is what the fuzz target (test/fuzz/fuzz_quack_auth_parse.cpp) feeds it.
DoorAuth ParseQuackAuthDocument(const HttpResult &response);

} // namespace oidc
} // namespace acl
} // namespace duckdb
