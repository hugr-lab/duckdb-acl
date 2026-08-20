#define DUCKDB_EXTENSION_MAIN

#include "acl_extension.hpp"

#include "acl_admin_functions.hpp"
#include "acl_parser_override.hpp"
#include "acl_policy.hpp"
#include "duckdb/common/helper.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/main/extension/extension_loader.hpp"

// Role/token-scoped access control via a `parser_override` that rewrites the query AST before bind
// (see specs/001-parser-override-ast-rewrite/spec.md).
//
// A trusted gateway prepends `ACL ROLE "<role>"` / `ACL TOKEN '<token>'` / `ACL ADMIN` to every query.
// The parser override (acl_parser_override.cpp, enabled with
// `SET allow_parser_override_extension='fallback'`) recognizes that prefix, verifies the principal
// offline, re-parses the remainder with the native parser, and rewrites the parsed AST in place
// (acl_rewriter.cpp). The resolver (acl_policy.cpp) picks one of two replacement forms per relation:
//   * RENAME - swap a virtual name for its physical target in place (full path a.b.c -> pdb.psch.pobj);
//     it stays a real table, so it is writable (INSERT/UPDATE/DELETE flow through). Used when the whole
//     physical object is exposed as-is;
//   * SUBQUERY - wrap a SELECT: allowed columns (masks / computed columns), an RLS predicate whose claim
//     values are baked in as constants, or a view's/vfunc's full defining SQL. Read-only by construction
//     (you cannot write through a subquery), so masked/RLS/view relations reject DML;
//   * a virtual table function -> either a RENAME-alias of a physical/system table function (retarget
//     the call in place, keep args) or a SUBQUERY-macro whose template substitutes the call arguments
//     via acl_arg(n) markers (claims/RLS via acl_claim), read-only;
//   * a virtual scalar function -> a RENAME-alias of a physical/system scalar, or an expression macro
//     whose template substitutes the call arguments via acl_arg(n) (claims via acl_claim);
//   * every other function (scalar or table) -> routed through one resolver seam, which decides
//     allow/deny; the stub denies only source readers and rights-bypass functions (ST_Read/read_csv/
//     postgres_query/query/getvariable/...) and passes the rest (pure transforms like ST_AsGeoJSON),
//     refused at parse time before any bind - production plugs the role-aware ACL callback in here;
//   * an unknown name -> hard denial (never left for the binder to resolve against the real catalog);
//   * a DML target -> capability check + resolve-in-place to the physical name; reads additionally
//     require the 'select' capability (spec 003).
// Service statements (CALL/PRAGMA/DDL) never reach the DML/SELECT rewrite and are denied by the
// statement gate, so pragma-form passthroughs (e.g. postgres_execute as a pragma) are refused too.
// The rewritten statements flow through the normal bind->optimize->execute path, so DML/DDL/CTAS work
// as ordinary top-level statements. The admin functions (acl_admin_functions.cpp) are in-process stubs;
// in production they are the read-only policy loaders described by the contract (offline token verify +
// bounded LRU policy cache).

namespace duckdb {
namespace {

void LoadInternal(ExtensionLoader &loader) {
	auto &db = loader.GetDatabaseInstance();
	auto &config = DBConfig::GetConfig(db);

	// bounded staleness of the catalog-backed policy (spec 006): the policy_version is re-read at
	// most once per this many milliseconds; 0 = check on every batch
	// all three are read through DatabaseInstance (the parser override has no client context), so they
	// are registered GLOBAL: a session-scoped SET would report success and change nothing
	config.AddExtensionOption("acl_version_check_interval",
	                          "acl: milliseconds between policy_version checks of the policy catalog",
	                          LogicalType::BIGINT, Value::BIGINT(1000), nullptr, SetScope::GLOBAL);
	config.AddExtensionOption("acl_allow_anonymous_admin",
	                          "acl: allow a bare `ACL ADMIN` (no principal) once a policy source is "
	                          "enabled - the gateway's own escape hatch (spec 009)",
	                          LogicalType::BOOLEAN, Value::BOOLEAN(false), nullptr, SetScope::GLOBAL);
	config.AddExtensionOption("acl_jwt_clock_skew", "acl: allowed clock skew in seconds for JWT exp/nbf checks",
	                          LogicalType::BIGINT, Value::BIGINT(60));

	// one policy store per database instance, shared by the parser override and the admin functions
	auto store = make_shared_ptr<acl::PolicyStore>();
	acl::RegisterAclParser(config, store);
	acl::RegisterAclAdminFunctions(loader, std::move(store));
}

} // namespace

void AclExtension::Load(ExtensionLoader &loader) {
	LoadInternal(loader);
}
std::string AclExtension::Name() {
	return "acl";
}
std::string AclExtension::Version() const {
#ifdef EXT_VERSION_ACL
	return EXT_VERSION_ACL;
#else
	return "";
#endif
}

} // namespace duckdb

extern "C" {
DUCKDB_CPP_EXTENSION_ENTRY(acl, loader) {
	duckdb::LoadInternal(loader);
}
}
