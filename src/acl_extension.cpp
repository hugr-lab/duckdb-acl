#define DUCKDB_EXTENSION_MAIN

#include "acl_extension.hpp"
#ifdef ACL_QUACK_EMBED_ENABLED
#include "acl_quack_embed.hpp"
#endif
#include "acl_oidc_secret.hpp"

#ifdef ACL_FLIGHT_ENABLED
#include "acl_flight_door.hpp"
#endif

#include "duckdb/common/string_util.hpp"
#include "duckdb/main/settings.hpp"

#include "acl_admin_functions.hpp"
#include "acl_introspection.hpp"
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
	                          LogicalType::BIGINT, Value::BIGINT(60), nullptr, SetScope::GLOBAL);
	config.AddExtensionOption("acl_jwks_refresh_interval",
	                          "acl: seconds a fetched JWKS is used before it is read again (spec 023)",
	                          LogicalType::BIGINT, Value::BIGINT(300), nullptr, SetScope::GLOBAL);
	config.AddExtensionOption(
	    "acl_session_idle_timeout",
	    "acl: seconds a session may go unused before it is dead, whatever its "
	    "token's exp says; 0 disables the rule (spec 044) - refused while "
	    "acl_session_token_binding='connect', where idle is the only automatic reaper (spec 059)",
	    LogicalType::BIGINT, Value::BIGINT(900),
	    [](ClientContext &context, SetScope, Value &parameter) {
		    if (!parameter.IsNull() && parameter.GetValue<int64_t>() == 0) {
			    Value binding;
			    auto have = context.TryGetCurrentSetting("acl_session_token_binding", binding);
			    auto value = have && !binding.IsNull() ? StringUtil::Lower(binding.ToString()) : string("connect");
			    if (value == "connect") {
				    throw InvalidInputException(
				        "acl_session_idle_timeout=0 would leave no automatic session reaper under "
				        "acl_session_token_binding='connect' - set the binding to 'every_use' first (spec 059)");
			    }
		    }
	    },
	    SetScope::GLOBAL);
	config.AddExtensionOption(
	    "acl_session_token_binding",
	    "acl: when the token's exp is judged - 'connect' (default) gates only session establishment, "
	    "so a session opened with a fresh token keeps working until idle/close/kill; 'every_use' "
	    "re-judges exp on every use (spec 059)",
	    LogicalType::VARCHAR, Value("connect"),
	    [](ClientContext &context, SetScope scope, Value &parameter) {
		    if (scope != SetScope::GLOBAL) {
			    // a session-scoped value would validate, show in current_setting() and be ignored by
			    // the judgment, which reads the global - refuse the false comfort outright
			    throw InvalidInputException("acl_session_token_binding is global - use SET GLOBAL");
		    }
		    auto value = StringUtil::Lower(parameter.ToString());
		    if (value != "connect" && value != "every_use") {
			    throw InvalidInputException("acl_session_token_binding accepts 'connect' or 'every_use', not '%s'",
			                                parameter.ToString());
		    }
		    if (value == "connect") {
			    // under 'connect' the idle rule is the ONLY automatic reaper; with it disabled every
			    // abandoned session would pin acl_max_sessions forever (spec 059)
			    Value idle;
			    if (context.TryGetCurrentSetting("acl_session_idle_timeout", idle) && !idle.IsNull() &&
			        idle.GetValue<int64_t>() == 0) {
				    throw InvalidInputException("acl_session_token_binding='connect' needs a live idle reaper: "
				                                "set acl_session_idle_timeout > 0 first (it is currently 0/disabled)");
			    }
		    }
	    },
	    SetScope::GLOBAL);
	config.AddExtensionOption("acl_max_sessions",
	                          "acl: how many sessions may live at once; at the cap a new one is refused "
	                          "rather than an old one evicted, and 0 means unlimited (spec 044). Each "
	                          "session holds a duckdb connection (spec 050), so this bounds held "
	                          "connections too - 1000 is a deliberately conservative default",
	                          LogicalType::BIGINT, Value::BIGINT(1000), nullptr, SetScope::GLOBAL);
	config.AddExtensionOption("acl_max_ingest_rows",
	                          "acl: maximum rows one Flight ingest may stream (0 = unlimited, spec 049)",
	                          LogicalType::BIGINT, Value::BIGINT(0), nullptr, SetScope::GLOBAL);
	config.AddExtensionOption("acl_jwks_max_stale",
	                          "acl: seconds a JWKS that can no longer be read may still be used; past "
	                          "that a token is refused rather than verified against keys of unknown age",
	                          LogicalType::BIGINT, Value::BIGINT(3600), nullptr, SetScope::GLOBAL);

	// Enforcement lives entirely behind the parser override, and duckdb skips every override while
	// `allow_parser_override_extension` is at its default - so loading acl without it leaves the
	// extension inert: policy can still be configured through the acl_* functions, but no `ACL …`
	// statement parses. Turn it on here (duckpgq does the same), and pick STRICT: for us the two
	// modes are identical - a denial is thrown, never returned - while a co-loaded extension that
	// does use the error channel keeps its own parse errors under STRICT and loses them under
	// FALLBACK. An explicit value set before load is left alone.
	Value current;
	if (!db.TryGetCurrentSetting("allow_parser_override_extension", current) || current.IsNull() ||
	    StringUtil::CIEquals(current.ToString(), "DEFAULT")) {
		Settings::Set<AllowParserOverrideExtensionSetting>(db, SetScope::GLOBAL, Value("STRICT"));
	}

	// one policy store per database instance, shared by the parser override and the admin functions
	auto store = make_shared_ptr<acl::PolicyStore>();
	acl::RegisterQuackOidcProvider(loader); // spec 061: CREATE SECRET (TYPE quack, PROVIDER oidc, ...)
	acl::RegisterAclParser(config, store);
	acl::RegisterAclIntrospection(loader, store);
#ifdef ACL_QUACK_EMBED_ENABLED
	// The embedded quack door (spec 063): the acl_quack_* server settings and the acl_quack_scan_data
	// drain the server INSERTs through, then the door itself - serve/stop and the two callbacks the
	// server calls (src/quack_embed/acl_quack_door.cpp, the shape of the Flight door below). Present in
	// every non-WASM build unless ACL_NO_QUACK_EMBED; without it there is no acl_quack_* function at all.
	acl::RegisterAclQuackEmbed(loader);
	acl::RegisterAclQuackDoor(loader, store);
#endif
#ifdef ACL_FLIGHT_ENABLED
	// The Flight SQL door (spec 045), present only in an ACL_FLIGHT=1 build. Registered here so the
	// seam is real rather than declared: if Arrow ever fails to link, it fails at build time and not
	// the first time somebody opens a door.
	acl::RegisterAclFlightDoor(loader, store);
#endif
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
