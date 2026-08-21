PROJ_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

# Configuration of extension
EXT_NAME=acl
EXT_CONFIG=${PROJ_DIR}extension_config.cmake

# Local integration-test environment config (specs/005); see .env.example
-include .env

# Integration builds (ACL_INTEGRATION=1) add the source scanners. Their build dependencies come from
# vcpkg, like every duckdb extension: the merged-manifest step collects the vcpkg.json of each loaded
# extension (libpq/openssl from duckdb-postgres, roaring from ducklake, ...), so nothing is listed
# here by hand. Bootstrap once with `make vcpkg-setup`, or point VCPKG_TOOLCHAIN_PATH at an existing
# vcpkg checkout.
ifdef ACL_INTEGRATION
USE_MERGED_VCPKG_MANIFEST := 1
VCPKG_TOOLCHAIN_PATH ?= $(PROJ_DIR)vcpkg/scripts/buildsystems/vcpkg.cmake
GOALS := $(if $(MAKECMDGOALS),$(MAKECMDGOALS),all)
ifeq ($(wildcard $(VCPKG_TOOLCHAIN_PATH)),)
ifneq ($(filter-out vcpkg-setup docker-up docker-down docker-status,$(GOALS)),)
$(error ACL_INTEGRATION build needs vcpkg: run 'make vcpkg-setup' first, or set VCPKG_TOOLCHAIN_PATH)
endif
endif
endif

# Include the Makefile from extension-ci-tools
include extension-ci-tools/makefiles/duckdb_extension.Makefile

# --- Standalone C++ invariant tests (specs/002-cpp-invariant-tests) ---------
# Style of hugr-lab/mssql-extension: each test/cpp/test_*.cpp is its own program built from the
# already-compiled release tree. Uses the release build, so run with the same generator as the main
# build (GEN=ninja make test-cpp).

TEST_CPP_SOURCES := $(wildcard test/cpp/test_*.cpp)
TEST_CPP_BINS := $(patsubst test/cpp/%.cpp,build/test/%,$(TEST_CPP_SOURCES))

# match the release archives (-O2 -DNDEBUG), so D_ASSERT is compiled out of the test TUs too
TEST_CPP_FLAGS := -std=c++17 -O2 -DNDEBUG -pthread
TEST_CPP_INCLUDES := -I duckdb/src/include -I duckdb/third_party/fmt/include

# Link against the shared libduckdb, exactly like duckdb's own unittest: it already carries the
# statically linked extensions (acl, core_functions, ... and the scanners of an integration build)
# together with their resolved third-party dependencies, so the link line never has to track them.
ifeq ($(shell uname -s),Darwin)
TEST_CPP_DUCKDB_LIB := build/release/src/libduckdb.dylib
else
TEST_CPP_DUCKDB_LIB := build/release/src/libduckdb.so
endif
TEST_CPP_LINK = -L build/release/src -lduckdb -Wl,-rpath,$(abspath build/release/src)

build/test/%: test/cpp/%.cpp test/cpp/acl_test_util.hpp $(TEST_CPP_DUCKDB_LIB)
	@mkdir -p build/test
	$(CXX) $(TEST_CPP_FLAGS) $(TEST_CPP_INCLUDES) $< $(TEST_CPP_LINK) -o $@

# Deliberately NOT depending on `release`: in the distribution CI the build runs inside a docker
# container and the tests on the host, so re-triggering cmake against the container-made cache fails
# on the path change. Guard on the built library instead (mssql-extension does the same).
.PHONY: test-cpp test-cpp-run
test-cpp:
	@test -f $(TEST_CPP_DUCKDB_LIB) || { \
		echo "test-cpp: $(TEST_CPP_DUCKDB_LIB) missing - run 'GEN=ninja make' first" >&2; exit 1; }
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

# --- Integration environment (specs/005-integration-env) --------------------
# Real databases in docker (postgres, mysql, sqlserver) + DuckLake on the postgres catalog.
# Copy .env.example to .env first. Scenarios live in test/sql/integration/ and skip themselves
# when their scanner or DSN is absent (require / require-env).

ACL_PG_HOST ?= localhost
ACL_PG_PORT ?= 6432
ACL_PG_USER ?= acl
ACL_PG_PASS ?= aclpass
ACL_PG_DB ?= acltest
ACL_DUCKLAKE_CATALOG_DB ?= ducklake_catalog
ACL_MYSQL_HOST ?= localhost
ACL_MYSQL_PORT ?= 6433
ACL_MYSQL_USER ?= acl
ACL_MYSQL_PASS ?= aclpass
ACL_MYSQL_DB ?= acltest
ACL_MSSQL_HOST ?= localhost
ACL_MSSQL_PORT ?= 6434
ACL_MSSQL_USER ?= sa
ACL_MSSQL_PASS ?= TestPassword1
ACL_MSSQL_DB ?= acltest

# -p matches the `name:` in the compose file: belt and braces, so no invocation can pick up the
# directory-derived project name and adopt an unrelated project's containers (spec 033)
DOCKER_COMPOSE := docker compose -p duckdb-acl -f docker/docker-compose.yml

.PHONY: docker-up docker-down docker-status test-integration
# --wait would treat the one-shot sqlserver-init container as a failure; wait on the servers, then
# run the init separately (it only starts once sqlserver is healthy anyway)
docker-up:
	$(DOCKER_COMPOSE) up -d --wait postgres mysql sqlserver
	$(DOCKER_COMPOSE) up -d sqlserver-init

docker-down:
	$(DOCKER_COMPOSE) down

docker-status:
	$(DOCKER_COMPOSE) ps

# Runs the integration scenarios against the docker databases. Needs an integration build first:
#   ACL_INTEGRATION=1 GEN=ninja make
test-integration:
	@test -x build/release/test/unittest || { \
		echo "test-integration: no unittest binary - run 'ACL_INTEGRATION=1 GEN=ninja make' first" >&2; exit 1; }
	ACL_PG_DSN="dbname=$(ACL_PG_DB) user=$(ACL_PG_USER) password=$(ACL_PG_PASS) host=$(ACL_PG_HOST) port=$(ACL_PG_PORT)" \
	ACL_DUCKLAKE_DSN="ducklake:postgres:dbname=$(ACL_DUCKLAKE_CATALOG_DB) user=$(ACL_PG_USER) password=$(ACL_PG_PASS) host=$(ACL_PG_HOST) port=$(ACL_PG_PORT)" \
	ACL_MYSQL_DSN="host=$(ACL_MYSQL_HOST) port=$(ACL_MYSQL_PORT) user=$(ACL_MYSQL_USER) passwd=$(ACL_MYSQL_PASS) db=$(ACL_MYSQL_DB)" \
	ACL_MSSQL_DSN="Server=$(ACL_MSSQL_HOST),$(ACL_MSSQL_PORT);Database=$(ACL_MSSQL_DB);User Id=$(ACL_MSSQL_USER);Password=$(ACL_MSSQL_PASS)" \
	build/release/test/unittest "test/sql/integration/*"

# --- The managed policy schema (spec 034) ---------------------------------
# schema/policy_schema.sql is the source of truth; everything else is rendered from it, so what an
# operator applies by hand and what the extension creates are the same statements.
.PHONY: schema schema-check
schema:
	python3 scripts/gen_schema.py

schema-check:
	./scripts/check_schema.sh

# Bootstrap a local vcpkg checkout for integration builds (the standard duckdb-extension dependency
# manager; dependencies themselves come from the merged manifests of the loaded extensions)
.PHONY: vcpkg-setup
vcpkg-setup:
	@test -d vcpkg || git clone https://github.com/microsoft/vcpkg.git vcpkg
	./vcpkg/bootstrap-vcpkg.sh -disableMetrics
