// libFuzzer target for the door's auth-discovery parser (release plan 3.6): the bytes a door answers
// are a client's pre-authentication network input. The OIDC core's own parsers are fuzzed where the
// core lives now (duckdb-ext-common, spec 002); this is the one parser that stayed here (spec 076).
//
// Build + run: `make fuzz-oidc` (clang only; FUZZ_SECONDS bounds the run, corpus in test/fuzz/corpus).

#include "acl_quack_auth.hpp"

#include <cstddef>
#include <cstdint>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if (size == 0) {
		return 0;
	}
	using namespace duckdb::acl::oidc;
	HttpResult response;
	response.status = (data[0] & 0x80) ? 400 : 200; // an error status exercises the error branch
	response.body.assign(reinterpret_cast<const char *>(data + 1), size - 1);
	(void)ParseQuackAuthDocument(response);
	return 0;
}
