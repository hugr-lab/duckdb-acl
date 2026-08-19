PROJ_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

# Configuration of extension
EXT_NAME=acl
EXT_CONFIG=${PROJ_DIR}extension_config.cmake

# Include the Makefile from extension-ci-tools
include extension-ci-tools/makefiles/duckdb_extension.Makefile

# --- Standalone C++ invariant tests (specs/002-cpp-invariant-tests) ---------
# Style of hugr-lab/mssql-extension: each test/cpp/test_*.cpp is its own program, compiled directly
# against the already-built release archives. The archives are named explicitly - in particular the
# GENERATED extension loader must be linked (never globbed next to the dummy one, which defines the
# same RegisterLinkedExtensions symbol), so the linked-extension registry works in the test binaries
# and `LOAD acl` resolves to the statically linked extension. Uses the release build, so run with the
# same generator as the main build (GEN=ninja make test-cpp).

TEST_CPP_SOURCES := $(wildcard test/cpp/test_*.cpp)
TEST_CPP_BINS := $(patsubst test/cpp/%.cpp,build/test/%,$(TEST_CPP_SOURCES))

# match the release archives (-O2 -DNDEBUG), so D_ASSERT is compiled out of the test TUs too
TEST_CPP_FLAGS := -std=c++17 -O2 -DNDEBUG -pthread
TEST_CPP_INCLUDES := -I duckdb/src/include -I duckdb/third_party/fmt/include

# per-extension archives live one level below build/release/extension; the loader archives at its
# root are excluded by the pattern, and the generated loader is added first explicitly
TEST_CPP_LIBS = build/release/extension/libduckdb_generated_extension_loader.a \
    $(wildcard build/release/extension/*/lib*_extension.a) \
    build/release/src/libduckdb_static.a

ifeq ($(shell uname -s),Linux)
TEST_CPP_LINK = -Wl,--start-group $(TEST_CPP_LIBS) -Wl,--end-group -ldl -lrt
else
TEST_CPP_LINK = $(TEST_CPP_LIBS)
endif

build/test/%: test/cpp/%.cpp test/cpp/acl_test_util.hpp \
		build/release/src/libduckdb_static.a build/release/extension/acl/libacl_extension.a
	@mkdir -p build/test
	$(CXX) $(TEST_CPP_FLAGS) $(TEST_CPP_INCLUDES) $< $(TEST_CPP_LINK) -o $@

.PHONY: test-cpp test-cpp-run
test-cpp: release
	@$(MAKE) --no-print-directory test-cpp-run

test-cpp-run: $(TEST_CPP_BINS)
	@test -n "$(TEST_CPP_BINS)" || { echo "test-cpp: no test/cpp/test_*.cpp sources found" >&2; exit 1; }
	@fail=0; \
	for b in $(TEST_CPP_BINS); do \
		if $$b >$$b.out 2>&1; then echo "  PASS $$(basename $$b)"; \
		else echo "  FAIL $$(basename $$b)"; cat $$b.out; fail=1; fi; \
	done; \
	exit $$fail

# CI runs `make test_release` (extension-ci-tools); chain the C++ tests into it on the platforms
# that can build and run them (not Windows, not wasm cross-builds)
ifneq ($(OS),Windows_NT)
ifeq ($(findstring wasm,$(DUCKDB_PLATFORM)),)
test_release: test-cpp
endif
endif
