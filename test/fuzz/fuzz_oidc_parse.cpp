// libFuzzer target for the OIDC core's parsers (release plan 3.6): the bytes an IdP or a door
// answers are the pre-authentication network input of the node, so they are the right thing to fuzz.
// The module is duckdb-free by design (spec 060), which is what makes this a small standalone
// binary: acl_oidc.cpp + the bundled yyjson + this file, under -fsanitize=fuzzer,address,undefined.
//
// The first byte picks the parser and the HTTP status shape; the rest is the body. The parsers
// promise to refuse or bound every value and never to crash on a malformed document - that promise,
// not any particular output, is what a run asserts.
//
// Build + run: `make fuzz-oidc` (clang only; FUZZ_SECONDS bounds the run, corpus in test/fuzz/corpus).

#include "acl_oidc.hpp"

#include <cstddef>
#include <cstdint>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if (size == 0) {
		return 0;
	}
	using namespace duckdb::acl::oidc;
	HttpResult response;
	auto selector = data[0];
	response.status = (selector & 0x80) ? 400 : 200; // an error status exercises the error branches
	response.body.assign(reinterpret_cast<const char *>(data + 1), size - 1);
	switch (selector & 0x03) {
	case 0:
		(void)ParseTokenResponse(response);
		break;
	case 1:
		(void)ParseDiscoveryDocument("https://issuer.test", response);
		break;
	case 2:
		(void)ParseQuackAuthDocument(response);
		break;
	default:
		(void)ParseDeviceAuthorization(response);
		break;
	}
	return 0;
}
