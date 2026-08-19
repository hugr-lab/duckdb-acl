PROJ_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

# Configuration of extension
EXT_NAME=acl
EXT_CONFIG=${PROJ_DIR}extension_config.cmake

# Include the Makefile from extension-ci-tools
include extension-ci-tools/makefiles/duckdb_extension.Makefile

# --- Standalone C++ invariant tests (specs/002-cpp-invariant-tests) ---------
# Style of hugr-lab/mssql-extension: each test/cpp/*.cpp is its own program, compiled
# directly against the already-built static libs. Uses the release build, so run with
# the same generator as the main build (GEN=ninja make test-cpp).

TEST_CPP_SOURCES := \
    test/cpp/test_acl_params_passthrough.cpp \
    test/cpp/test_acl_instance_isolation.cpp

TEST_CPP_FLAGS := -std=c++17 -pthread
TEST_CPP_INCLUDES := -I duckdb/src/include -I duckdb/third_party/fmt/include
ifeq ($(shell uname -s),Linux)
TEST_CPP_PLATFORM_LIBS := -ldl -lrt
endif

.PHONY: test-cpp
test-cpp: release
	@mkdir -p build/test
	@fail=0; \
	libs="build/release/extension/acl/libacl_extension.a build/release/src/libduckdb_static.a \
	      $$(find build/release/extension build/release/third_party -name '*.a' 2>/dev/null | grep -v libacl_extension | tr '\n' ' ') \
	      build/release/src/libduckdb_static.a"; \
	for f in $(TEST_CPP_SOURCES); do \
		n=$$(basename $$f .cpp); \
		$(CXX) $(TEST_CPP_FLAGS) $(TEST_CPP_INCLUDES) $$f $$libs $(TEST_CPP_PLATFORM_LIBS) \
		    -o build/test/$$n 2>build/test/$$n.log || { echo "  BUILD FAIL $$n (see build/test/$$n.log)"; fail=1; continue; }; \
		if build/test/$$n >build/test/$$n.out 2>&1; then echo "  PASS $$n"; \
		else echo "  FAIL $$n"; tail -20 build/test/$$n.out; fail=1; fi; \
	done; \
	exit $$fail
