//===----------------------------------------------------------------------===//
// acl_platform.cpp — the `platform` catalog (spec 117)
//
// The registry of its views and functions, the one authorizer of administration, the compilation of
// a top-level `platform.<op>(…)` call into the acl_* call it is, the SQL of each view (rows scoped to
// the caller), its share of the principal's listings, and the node-state table functions and typed
// conversions the views read through.
//===----------------------------------------------------------------------===//

#include "acl_platform.hpp"

#include "acl_connection.hpp"
#include "acl_door_common.hpp"
#include "acl_name_path.hpp"
#include "acl_node_load.hpp"
#include "acl_policy_catalog.hpp"
#include "acl_rewriter.hpp"

#include "duckdb/common/exception/binder_exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/types/timestamp.hpp"
#include "duckdb/execution/expression_executor_state.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/parser/expression/constant_expression.hpp"
#include "duckdb/parser/expression/function_expression.hpp"
#include "duckdb/parser/expression/parameter_expression.hpp"
#include "duckdb/parser/expression/star_expression.hpp"
#include "duckdb/parser/parsed_expression_iterator.hpp"
#include "duckdb/parser/query_node/select_node.hpp"
#include "duckdb/parser/statement/call_statement.hpp"
#include "duckdb/parser/statement/select_statement.hpp"
#include "duckdb/parser/tableref/emptytableref.hpp"
#include "duckdb/parser/tableref/table_function_ref.hpp"
#include "yyjson.hpp"

#include <cstdlib>
#include <unordered_map>

namespace duckdb {
namespace acl {

using acl_detail::Lit;

bool IsPlatformCatalog(const string &name) {
	if (name.empty()) {
		return false;
	}
	return NamePath::KeyEquals(name, PLATFORM_CATALOG) || StringUtil::CIEquals(name, PLATFORM_CATALOG);
}

namespace {

//===--------------------------------------------------------------------===//
// The registry
//===--------------------------------------------------------------------===//

// the column types the views carry, by short name
constexpr const char *V = "VARCHAR";
constexpr const char *B = "BOOLEAN";
constexpr const char *I = "BIGINT";
constexpr const char *TS = "TIMESTAMP";
constexpr const char *LV = "VARCHAR[]";
constexpr const char *CAPS = "CAPS";
constexpr const char *MAPV = "MAP";
constexpr const char *MAPI = "MAPI";
constexpr const char *CONDITIONS = "CONDITIONS";
constexpr const char *ATTRIBUTES = "ATTRIBUTES";
constexpr const char *GROUPS = "GROUPS";
//! what an ACL CLUSTER call answers (spec 093), as the listings spell its type
constexpr const char *CLUSTER_ANSWER = "STRUCT(version BIGINT, class VARCHAR, applied_here BOOLEAN, note VARCHAR)";

const char *const CAPABILITIES[] = {"select", "insert", "update",  "delete",  "merge", "create",
                                    "drop",   "temp",   "explain", "secrets", "manage"};

LogicalType CapsType() {
	child_list_t<LogicalType> children;
	for (auto capability : CAPABILITIES) {
		children.emplace_back(capability, LogicalType::BOOLEAN);
	}
	return LogicalType::STRUCT(std::move(children));
}

LogicalType ConditionsType() {
	child_list_t<LogicalType> children {{"path", LogicalType::VARCHAR},
	                                    {"op", LogicalType::VARCHAR},
	                                    {"values", LogicalType::LIST(LogicalType::VARCHAR)}};
	return LogicalType::LIST(LogicalType::STRUCT(std::move(children)));
}

LogicalType AttributesType() {
	child_list_t<LogicalType> children {{"name", LogicalType::VARCHAR},
	                                    {"paths", LogicalType::LIST(LogicalType::VARCHAR)},
	                                    {"constant", LogicalType::VARCHAR}};
	return LogicalType::LIST(LogicalType::STRUCT(std::move(children)));
}

LogicalType GroupsType() {
	child_list_t<LogicalType> children {{"live", LogicalType::BIGINT}, {"max", LogicalType::BIGINT}};
	return LogicalType::MAP(LogicalType::VARCHAR, LogicalType::STRUCT(std::move(children)));
}

LogicalType TypeOf(const string &code) {
	if (code == V) {
		return LogicalType::VARCHAR;
	}
	if (code == B) {
		return LogicalType::BOOLEAN;
	}
	if (code == I) {
		return LogicalType::BIGINT;
	}
	if (code == TS) {
		return LogicalType::TIMESTAMP;
	}
	if (code == LV) {
		return LogicalType::LIST(LogicalType::VARCHAR);
	}
	if (code == CAPS) {
		return CapsType();
	}
	if (code == MAPV) {
		return LogicalType::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR);
	}
	if (code == MAPI) {
		return LogicalType::MAP(LogicalType::VARCHAR, LogicalType::BIGINT);
	}
	if (code == CONDITIONS) {
		return ConditionsType();
	}
	if (code == ATTRIBUTES) {
		return AttributesType();
	}
	if (code == GROUPS) {
		return GroupsType();
	}
	throw InternalException("acl platform: unknown column type %s", code);
}

//! the type as SQL spells it (what a cast and a listing write)
string TypeText(const string &code) {
	return TypeOf(code).ToString();
}

using PV = PlatformViewClass;

vector<PlatformView> BuildViews() {
	return {
	    // the policy - a catalog admin reads its catalogs' rows
	    {"catalogs", PV::CATALOG, {{"catalog", V}, {"comment", V}}, "the virtual catalogs"},
	    {"relations",
	     PV::CATALOG,
	     {{"catalog", V},
	      {"name", V},
	      {"form", V},
	      {"phys", V},
	      {"view_sql", V},
	      {"rls", V},
	      {"rls_checked", B},
	      {"origin", V},
	      {"comment", V},
	      {"alias_types", V},
	      {"enum_types", V}},
	     "the virtual tables and views of each catalog"},
	    {"relation_columns",
	     PV::CATALOG,
	     {{"catalog", V}, {"relation", V}, {"pos", I}, {"name", V}, {"expr", V}, {"nullable", B}},
	     "the declared column lists of the relations"},
	    {"schemas",
	     PV::CATALOG,
	     {{"catalog", V}, {"path", V}, {"phys_path", V}, {"origin", V}, {"comment", V}},
	     "the virtual schemas (aliases and expansions)"},
	    {"functions",
	     PV::CATALOG,
	     {{"catalog", V},
	      {"name", V},
	      {"kind", V},
	      {"form", V},
	      {"target", V},
	      {"template", V},
	      {"params", LV},
	      {"comment", V}},
	     "the virtual table and scalar functions"},
	    {"function_columns",
	     PV::CATALOG,
	     {{"catalog", V},
	      {"function", V},
	      {"kind", V},
	      {"pos", I},
	      {"name", V},
	      {"type", V},
	      {"comment", V},
	      {"nullable", B}},
	     "the result columns of the virtual functions"},
	    {"references",
	     PV::CATALOG,
	     {{"catalog", V},
	      {"name", V},
	      {"from_object", V},
	      {"to_object", V},
	      {"to_kind", V},
	      {"expression", V},
	      {"cardinality", V},
	      {"optional", B},
	      {"join_method", V},
	      {"comment", V}},
	     "the declared join paths (spec 022)"},
	    {"reference_columns",
	     PV::CATALOG,
	     {{"catalog", V}, {"reference", V}, {"pos", I}, {"side", V}, {"column", V}, {"param", V}},
	     "the columns each reference pairs"},
	    {"keys",
	     PV::CATALOG,
	     {{"catalog", V}, {"object", V}, {"kind", V}, {"pos", I}, {"column", V}},
	     "the declared keys (spec 048)"},
	    {"roles", PV::ROLES, {{"role", V}, {"comment", V}}, "the roles"},
	    {"role_claims", PV::POLICY, {{"role", V}, {"claim", V}, {"value", V}}, "the default claims of each role"},
	    {"grants",
	     PV::CATALOG,
	     {{"role", V}, {"catalog", V}, {"is_main", B}, {"caps", CAPS}, {"rls", V}, {"rls_checked", B}, {"columns", LV}},
	     "the catalog grants; caps NULL = unstated (every data capability)"},
	    {"schema_grants",
	     PV::CATALOG,
	     {{"role", V},
	      {"catalog", V},
	      {"schema_path", V},
	      {"caps", CAPS},
	      {"inherited", B},
	      {"into", V},
	      {"virtual_only", B},
	      {"comment", V}},
	     "the schema grants (spec 015)"},
	    {"object_grants",
	     PV::CATALOG,
	     {{"role", V}, {"catalog", V}, {"object", V}, {"caps", CAPS}, {"rls", V}, {"rls_checked", B}, {"columns", LV}},
	     "the object grants; caps NULL = inherited from the catalog grant"},
	    {"grant_columns",
	     PV::CATALOG,
	     {{"role", V}, {"catalog", V}, {"object", V}, {"pos", I}, {"name", V}, {"type", V}},
	     "what each grant's projection produces (spec 026)"},
	    {"admins", PV::POLICY, {{"role", V}, {"scope", V}, {"catalog", V}}, "the administration bundles of each role"},
	    {"platform_grants",
	     PV::POLICY,
	     {{"role", V}, {"object", V}, {"kind", V}, {"allowed", B}},
	     "the point grants on the platform catalog's objects"},
	    {"issuers",
	     PV::POLICY,
	     {{"name", V}, {"url", V}, {"secret_service", V}, {"secret", V}},
	     "the token issuers (a secret by its name, never its content)"},
	    {"clients",
	     PV::POLICY,
	     {{"name", V},
	      {"issuer", V},
	      {"audiences", LV},
	      {"azp", LV},
	      {"requires", CONDITIONS},
	      {"roles_from", LV},
	      {"roles_constant", LV},
	      {"unmapped", V},
	      {"attributes", ATTRIBUTES},
	      {"subject", LV},
	      {"token_type", V},
	      {"client_id", V},
	      {"flows", LV},
	      {"secret_service", V},
	      {"secret", V},
	      {"implicit", B}},
	     "the clients of each issuer (spec 095)"},
	    {"role_mappings",
	     PV::POLICY,
	     {{"scope_kind", V}, {"scope_name", V}, {"source", V}, {"external_value", V}, {"role", V}},
	     "the role mappings (spec 095)"},
	    {"jwks_cache",
	     PV::POLICY,
	     {{"issuer", V},
	      {"location", V},
	      {"allowed", B},
	      {"fetched_at", TS},
	      {"age_seconds", I},
	      {"last_tried_at", TS},
	      {"error", V},
	      {"keys", I},
	      {"kids", LV}},
	     "what the node trusts right now: one row per key location (spec 071)"},
	    {"function_categories",
	     PV::POLICY,
	     {{"category", V}, {"comment", V}, {"builtin", B}},
	     "the function categories (spec 072)"},
	    {"function_category_members",
	     PV::POLICY,
	     {{"category", V}, {"database", V}, {"schema", V}, {"name", V}, {"kind", V}},
	     "the members of each category"},
	    {"function_grants",
	     PV::POLICY,
	     {{"role", V}, {"category", V}, {"database", V}, {"schema", V}, {"name", V}, {"kind", V}, {"allowed", B}},
	     "the grants and denies of categories and functions"},
	    {"function_status",
	     PV::POLICY,
	     {{"database", V},
	      {"schema", V},
	      {"name", V},
	      {"kind", V},
	      {"function_type", V},
	      {"categories", LV},
	      {"status", V},
	      {"present", B}},
	     "every function of the node beside its categories: never / categorized / uncategorized"},
	    {"resource_groups",
	     PV::POLICY,
	     {{"group", V},
	      {"window_start", I},
	      {"window_max", I},
	      {"batch_bytes", I},
	      {"max_result_rows", I},
	      {"queue_priority", I},
	      {"max_sessions", I},
	      {"comment", V},
	      {"is_default", B}},
	     "the resource groups (spec 085)"},
	    {"role_resource_groups", PV::POLICY, {{"role", V}, {"group", V}}, "which role is in which resource group"},
	    {"cluster_items",
	     PV::POLICY,
	     {{"scope", V},
	      {"kind", V},
	      {"name", V},
	      {"spec", MAPV},
	      {"class", V},
	      {"version", I},
	      {"depends_on", LV},
	      {"comment", V}},
	     "the cluster profile as written (spec 093)"},
	    {"cluster_effective",
	     PV::POLICY,
	     {{"scope", V},
	      {"kind", V},
	      {"name", V},
	      {"spec", MAPV},
	      {"class", V},
	      {"version", I},
	      {"depends_on", LV},
	      {"comment", V}},
	     "what of the cluster profile applies to this node (spec 096)"},
	    {"catalog_schema",
	     PV::POLICY,
	     {{"build", I}, {"build_min_reader", I}, {"catalog", I}, {"min_reader", I}, {"mode", V}},
	     "this build's schema version and window, the catalog's, and the mode (spec 094)"},
	    // the node - the observe bundle
	    {"sessions",
	     PV::NODE,
	     {{"id", V},
	      {"subject", V},
	      {"roles", LV},
	      {"door", V},
	      {"idle_seconds", I},
	      {"expires_at", TS},
	      {"audit_level", V},
	      {"audit_level_source", V},
	      {"profile_level", V},
	      {"profile_source", V},
	      {"groups", LV},
	      {"charged_group", V}},
	     "the live sessions of this node (never a handle)"},
	    {"node_load",
	     PV::NODE,
	     {{"draining", B},
	      {"observe", V},
	      {"group", V},
	      {"group_known", B},
	      {"config_target", I},
	      {"config_applied", I},
	      {"sessions_live", I},
	      {"sessions_max", I},
	      {"sessions_by_door", MAPI},
	      {"sessions_by_group", GROUPS},
	      {"admit_new_session", B},
	      {"admit_new_quack_client", B},
	      {"admit_new_stream", B}},
	     "the node's load report (spec 079), one row"},
	    {"node_doors",
	     PV::NODE,
	     {{"door", V}, {"uri", V}, {"seats", I}, {"seated", I}, {"seats_left", I}},
	     "the quack doors serving and their seats (spec 079)"},
	    {"node_streams",
	     PV::NODE,
	     {{"budget_bytes", I},
	      {"reserve_bytes", I},
	      {"reserved_bytes", I},
	      {"producing", I},
	      {"queued", I},
	      {"refused", I}},
	     "the stream budget of the quack doors (spec 080)"},
	    {"drain", PV::NODE, {{"draining", B}, {"sessions", I}}, "whether the node drains (spec 066)"},
	    {"lineage_status",
	     PV::NODE,
	     {{"status", V}, {"sending", B}, {"level", V}, {"namespace", V}},
	     "why lineage is or is not sent (spec 112)"},
	};
}

// parameter shorthands
PlatformParam A(const char *name, const char *type = V, const char *fallback = "") {
	return PlatformParam {name, true, type, fallback};
}
PlatformParam P(const char *name, const char *type = V, const char *fallback = "") {
	return PlatformParam {name, false, type, fallback};
}
using PR = PlatformRight;

vector<PlatformFunction> BuildFunctions() {
	auto catalog = A("catalog");
	auto name = A("name");
	auto mode = P("mode");
	auto comment = P("comment");
	auto role = A("role");
	return {
	    // the catalogs and their content: the policy bundle, or the manage capability on that catalog
	    {"create_catalog",
	     "acl_create_catalog",
	     {catalog, comment, mode},
	     {1, 2, 3},
	     0,
	     PR::CATALOG,
	     false,
	     B,
	     "create a virtual catalog"},
	    {"alter_catalog",
	     "acl_alter_catalog",
	     {catalog, comment},
	     {2},
	     0,
	     PR::CATALOG,
	     false,
	     B,
	     "change a catalog's comment"},
	    {"add_relation",
	     "acl_add_relation",
	     {catalog, name, A("phys"), P("columns"), P("rls"), comment, mode, P("primary_key")},
	     {5, 6, 7, 8},
	     0,
	     PR::CATALOG,
	     false,
	     B,
	     "a virtual table over a physical one (CREATE VIRTUAL TABLE)"},
	    {"add_view",
	     "acl_add_view",
	     {catalog, name, P("sql"), P("returns"), comment, mode, P("primary_key")},
	     {3, 4, 5, 6, 7},
	     0,
	     PR::CATALOG,
	     false,
	     B,
	     "a virtual view (CREATE VIRTUAL VIEW)"},
	    {"add_schema_alias",
	     "acl_add_schema_alias",
	     {catalog, A("path"), A("phys_path"), comment, mode},
	     {3, 4, 5},
	     0,
	     PR::CATALOG,
	     false,
	     B,
	     "a physical schema under a virtual path"},
	    {"expand_schema",
	     "acl_expand_schema",
	     {catalog, A("path"), A("phys_path"), comment, mode},
	     {3, 4, 5},
	     0,
	     PR::CATALOG,
	     false,
	     B,
	     "one virtual record per object of a physical schema (spec 014)"},
	    {"refresh_schema_objects",
	     "acl_refresh_schema_objects",
	     {catalog, A("path"), P("prune", B)},
	     {2, 3},
	     0,
	     PR::CATALOG,
	     false,
	     I,
	     "re-read an expansion's source"},
	    {"add_table_function",
	     "acl_add_table_function",
	     {catalog, name, P("definition"), P("params"), P("returns"), comment, mode, P("primary_key")},
	     {3, 5, 6, 7, 8},
	     0,
	     PR::CATALOG,
	     false,
	     B,
	     "a virtual table function (a macro)"},
	    {"add_table_function_alias",
	     "acl_add_table_function_alias",
	     {catalog, name, A("target"), P("params"), P("returns"), comment, mode},
	     {3, 6, 7},
	     0,
	     PR::CATALOG,
	     false,
	     B,
	     "a virtual table function over an engine one"},
	    {"add_scalar",
	     "acl_add_scalar",
	     {catalog, name, P("definition"), P("params"), P("returns"), comment, mode},
	     {3, 5, 6, 7},
	     0,
	     PR::CATALOG,
	     false,
	     B,
	     "a virtual scalar function (a macro)"},
	    {"add_scalar_alias",
	     "acl_add_scalar_alias",
	     {catalog, name, A("target"), P("params"), P("returns"), comment, mode},
	     {3, 6, 7},
	     0,
	     PR::CATALOG,
	     false,
	     B,
	     "a virtual scalar function over an engine one"},
	    {"drop_relation",
	     "acl_drop_relation",
	     {catalog, name, mode},
	     {2, 3},
	     0,
	     PR::CATALOG,
	     false,
	     B,
	     "drop a virtual table or view"},
	    {"alter_relation",
	     "acl_alter_relation",
	     {catalog, name, A("property"), P("value")},
	     {4},
	     0,
	     PR::CATALOG,
	     false,
	     B,
	     "change one property of a relation: phys | columns | rls | view"},
	    {"alter_schema_alias",
	     "acl_alter_schema_alias",
	     {catalog, A("path"), A("phys_path")},
	     {3},
	     0,
	     PR::CATALOG,
	     false,
	     B,
	     "retarget a schema alias"},
	    {"alter_function",
	     "acl_alter_function",
	     {catalog, name, A("kind"), A("form"), P("definition")},
	     {5},
	     0,
	     PR::CATALOG,
	     false,
	     B,
	     "redefine a virtual function"},
	    {"drop_schema_alias",
	     "acl_drop_schema_alias",
	     {catalog, A("path"), mode, P("cascade", B)},
	     {2, 3, 4},
	     0,
	     PR::CATALOG,
	     false,
	     B,
	     "drop a schema alias"},
	    {"drop_function",
	     "acl_drop_function",
	     {catalog, name, A("kind"), mode},
	     {3, 4},
	     0,
	     PR::CATALOG,
	     false,
	     B,
	     "drop a virtual function"},
	    {"comment",
	     "acl_comment",
	     {catalog, name, A("kind", V, "relation"), A("column_name"), P("comment")},
	     {5},
	     0,
	     PR::CATALOG,
	     false,
	     B,
	     "document an object or one of its columns"},
	    {"refresh_schema",
	     "acl_refresh_schema",
	     {catalog, name},
	     {1, 2},
	     0,
	     PR::CATALOG,
	     false,
	     I,
	     "re-derive the stored schema of query-defined objects"},
	    {"repair_relation",
	     "acl_repair_relation",
	     {catalog, name, A("action"), P("spec")},
	     {3, 4},
	     0,
	     PR::CATALOG,
	     false,
	     I,
	     "mend a declared column list (spec 039)"},
	    {"set_key",
	     "acl_set_key",
	     {catalog, name, A("kind"), P("primary_key")},
	     {3, 4},
	     0,
	     PR::CATALOG,
	     false,
	     B,
	     "the declared primary key of an object (spec 048)"},
	    {"add_reference",
	     "acl_add_reference",
	     {catalog, name, A("from_object"), A("to_object"), P("to_kind"), P("arguments"), P("pairs"), P("expression"),
	      P("cardinality"), P("optional"), P("join_method"), comment, mode},
	     {4, 5, 6, 7, 8, 9, 10, 11, 12, 13},
	     0,
	     PR::CATALOG,
	     false,
	     B,
	     "declare a join path (spec 022)"},
	    {"drop_reference",
	     "acl_drop_reference",
	     {catalog, name, mode},
	     {2, 3},
	     0,
	     PR::CATALOG,
	     false,
	     B,
	     "drop a declared join path"},
	    {"rematerialize_schema_caps",
	     "acl_rematerialize_schema_caps",
	     {catalog, A("path")},
	     {1, 2},
	     0,
	     PR::CATALOG,
	     false,
	     B,
	     "rebuild a subtree's inherited grants (spec 015)"},
	    // handing out access: the policy bundle (spec 009 - managing a catalog does not include it)
	    {"grant_catalog",
	     "acl_grant_catalog",
	     {role, catalog, P("caps"), P("main", B), P("rls"), P("columns")},
	     {3, 4, 6},
	     1,
	     PR::HANDS_OUT,
	     false,
	     B,
	     "grant a catalog to a role"},
	    {"revoke_catalog",
	     "acl_revoke_catalog",
	     {role, catalog},
	     {2},
	     1,
	     PR::HANDS_OUT,
	     false,
	     B,
	     "revoke a catalog grant"},
	    {"grant_object",
	     "acl_grant_object",
	     {role, catalog, name, P("caps"), P("rls"), P("columns")},
	     {4, 6},
	     1,
	     PR::HANDS_OUT,
	     false,
	     B,
	     "grant one object of a catalog, with its own policy (spec 011)"},
	    {"grant_schema",
	     "acl_grant_schema",
	     {role, catalog, A("path"), P("caps"), comment, A("into_schema"), P("virtual_only", B)},
	     {4, 5, 7},
	     1,
	     PR::HANDS_OUT,
	     false,
	     B,
	     "grant a schema of a catalog (spec 015)"},
	    {"revoke_schema",
	     "acl_revoke_schema",
	     {role, catalog, A("path")},
	     {3},
	     1,
	     PR::HANDS_OUT,
	     false,
	     B,
	     "revoke a schema grant"},
	    {"alter_grant",
	     "acl_alter_grant",
	     {role, catalog, A("property"), P("value")},
	     {4},
	     1,
	     PR::HANDS_OUT,
	     false,
	     B,
	     "change a catalog grant: caps | main"},
	    {"drop_catalog",
	     "acl_drop_catalog",
	     {catalog, P("cascade", B), mode},
	     {1, 2, 3},
	     0,
	     PR::HANDS_OUT,
	     false,
	     B,
	     "drop a catalog (taking it away from everyone who holds it)"},
	    // the rest of the policy: not catalog-specific, the policy bundle
	    {"create_role",
	     "acl_define_role",
	     {role, P("claims"), mode},
	     {2, 3},
	     -1,
	     PR::POLICY,
	     false,
	     B,
	     "create a role (its default claims as name=value csv)"},
	    {"alter_role",
	     "acl_alter_role",
	     {role, P("claims")},
	     {2},
	     -1,
	     PR::POLICY,
	     false,
	     B,
	     "change a role's default claims"},
	    {"drop_role", "acl_drop_role", {role, mode}, {1, 2}, -1, PR::POLICY, false, B, "drop a role"},
	    {"define_issuer",
	     "acl_define_issuer",
	     {name, P("spec"), P("mode", V, "replace")},
	     {1, 2, 3},
	     -1,
	     PR::POLICY,
	     false,
	     B,
	     "an issuer (spec 095): {url, secret, service}"},
	    {"alter_issuer", "acl_alter_issuer", {name, P("spec")}, {2}, -1, PR::POLICY, false, B, "change an issuer"},
	    {"drop_issuer", "acl_drop_issuer", {name, mode}, {1, 2}, -1, PR::POLICY, false, B, "drop an issuer"},
	    {"define_client",
	     "acl_define_client",
	     {name, A("issuer"), P("spec"), P("mode", V, "replace")},
	     {2, 3, 4},
	     -1,
	     PR::POLICY,
	     false,
	     B,
	     "a client of an issuer (spec 095)"},
	    {"alter_client", "acl_alter_client", {name, P("spec")}, {2}, -1, PR::POLICY, false, B, "change a client"},
	    {"drop_client", "acl_drop_client", {name, mode}, {1, 2}, -1, PR::POLICY, false, B, "drop a client"},
	    {"map_role",
	     "acl_map_role",
	     {A("scope_kind"), A("scope_name"), A("source"), A("external_value"), role},
	     {5},
	     -1,
	     PR::POLICY,
	     false,
	     B,
	     "map a claim value to a role, for one client or issuer (spec 095)"},
	    {"drop_role_mapping",
	     "acl_drop_role_mapping",
	     {A("scope_kind"), A("scope_name"), A("source"), A("external_value"), role},
	     {5},
	     -1,
	     PR::POLICY,
	     false,
	     B,
	     "drop a role mapping"},
	    {"create_function_category",
	     "acl_create_function_category",
	     {A("category"), comment},
	     {1, 2},
	     -1,
	     PR::POLICY,
	     false,
	     B,
	     "create a function category (spec 072)"},
	    {"drop_function_category",
	     "acl_drop_function_category",
	     {A("category"), mode},
	     {1, 2},
	     -1,
	     PR::POLICY,
	     false,
	     B,
	     "drop a function category"},
	    {"function_category_add",
	     "acl_function_category_add",
	     {A("category"), A("members", LV)},
	     {2},
	     -1,
	     PR::POLICY,
	     false,
	     B,
	     "add members to a category"},
	    {"function_category_remove",
	     "acl_function_category_remove",
	     {A("category"), A("members", LV)},
	     {2},
	     -1,
	     PR::POLICY,
	     false,
	     B,
	     "remove members from a category"},
	    {"grant_function_category",
	     "acl_grant_function_category",
	     {role, A("category"), P("allowed", V, "true")},
	     {2, 3},
	     -1,
	     PR::POLICY,
	     false,
	     B,
	     "grant (or deny) a category to a role ('' = every role)"},
	    {"revoke_function_category",
	     "acl_revoke_function_category",
	     {role, A("category")},
	     {2},
	     -1,
	     PR::POLICY,
	     false,
	     B,
	     "revoke a category grant"},
	    {"grant_function",
	     "acl_grant_function",
	     {role, A("function"), P("allowed", V, "true")},
	     {2, 3},
	     -1,
	     PR::POLICY,
	     false,
	     B,
	     "grant (or deny) a function by name"},
	    {"revoke_function",
	     "acl_revoke_function",
	     {role, A("function")},
	     {2},
	     -1,
	     PR::POLICY,
	     false,
	     B,
	     "revoke a function grant"},
	    {"session_profile",
	     "acl_session_profile",
	     {A("session"), P("level")},
	     {2},
	     -1,
	     PR::POLICY,
	     false,
	     B,
	     "the operator's profile level on a session (spec 074)"},
	    {"create_resource_group",
	     "acl_create_resource_group",
	     {A("group_name"), P("limits", V, "{}"), comment, P("is_default")},
	     {2, 3, 4},
	     -1,
	     PR::POLICY,
	     false,
	     B,
	     "create a resource group (spec 085)"},
	    {"alter_resource_group",
	     "acl_alter_resource_group",
	     {A("group_name"), A("property"), P("value")},
	     {3},
	     -1,
	     PR::POLICY,
	     false,
	     B,
	     "change a resource group: default"},
	    {"drop_resource_group",
	     "acl_drop_resource_group",
	     {A("group_name"), mode},
	     {1, 2},
	     -1,
	     PR::POLICY,
	     false,
	     B,
	     "drop a resource group"},
	    {"grant_resource_group",
	     "acl_grant_resource_group",
	     {role, A("group_name")},
	     {2},
	     -1,
	     PR::POLICY,
	     false,
	     B,
	     "put a role in a resource group"},
	    {"revoke_resource_group",
	     "acl_revoke_resource_group",
	     {role, A("group_name")},
	     {2},
	     -1,
	     PR::POLICY,
	     false,
	     B,
	     "take a role out of a resource group"},
	    // privilege: passthrough alone - the admin scopes and the grants on `platform`
	    {"grant_admin",
	     "acl_grant_admin",
	     {role, A("scope")},
	     {2},
	     -1,
	     PR::ESCALATES,
	     false,
	     B,
	     "grant a bundle: observe | policy | passthrough (manage: policy + observe)"},
	    {"revoke_admin",
	     "acl_revoke_admin",
	     {role, A("scope")},
	     {1, 2},
	     -1,
	     PR::ESCALATES,
	     false,
	     B,
	     "revoke a bundle, or (no scope) every administration of the role"},
	    {"grant_platform",
	     "acl_grant_platform",
	     {role, A("kind"), A("object"), P("allowed", V, "true")},
	     {3, 4},
	     -1,
	     PR::ESCALATES,
	     false,
	     B,
	     "a point grant (or deny) on one view or function of platform"},
	    {"revoke_platform",
	     "acl_revoke_platform",
	     {role, A("kind"), A("object")},
	     {3},
	     -1,
	     PR::ESCALATES,
	     false,
	     B,
	     "revoke a point grant on platform"},
	    // the cluster profile (spec 093): the node's infrastructure, passthrough's until spec 118
	    {"cluster_extension",
	     "acl_cluster_extension",
	     {A("verb"), A("scope"), A("name"), P("version"), A("repository"), comment},
	     {6},
	     -1,
	     PR::INFRASTRUCTURE,
	     false,
	     CLUSTER_ANSWER,
	     "install / update / remove an extension of the profile"},
	    {"cluster_attach",
	     "acl_cluster_attach",
	     {A("scope"), A("alias"), A("path"), A("type"), A("secret"), P("options"), A("depends_on"), comment,
	      P("lineage")},
	     {8, 9},
	     -1,
	     PR::INFRASTRUCTURE,
	     false,
	     CLUSTER_ANSWER,
	     "attach a source in the profile"},
	    {"cluster_detach",
	     "acl_cluster_detach",
	     {A("scope"), A("alias"), P("cascade"), P("force")},
	     {4},
	     -1,
	     PR::INFRASTRUCTURE,
	     false,
	     CLUSTER_ANSWER,
	     "detach a source of the profile"},
	    {"cluster_setting",
	     "acl_cluster_setting",
	     {A("verb"), A("scope"), A("name"), P("value")},
	     {4},
	     -1,
	     PR::INFRASTRUCTURE,
	     false,
	     CLUSTER_ANSWER,
	     "set / reset a setting of the profile"},
	    // read: table functions in FROM
	    {"check_catalog",
	     "acl_check_catalog",
	     {catalog},
	     {0, 1},
	     0,
	     PR::CATALOG,
	     true,
	     "TABLE",
	     "probe a catalog's stored facts against the source (spec 039)"},
	    {"console_info",
	     "",
	     {},
	     {0},
	     -1,
	     PR::OPEN,
	     true,
	     "TABLE",
	     "the build, the contracts, the schema window, what this node has and what the caller holds"},
	};
}

const vector<PlatformView> &Views() {
	static const vector<PlatformView> views = BuildViews();
	return views;
}

const vector<PlatformFunction> &Functions() {
	static const vector<PlatformFunction> functions = BuildFunctions();
	return functions;
}

} // namespace

const vector<PlatformView> &PlatformViews() {
	return Views();
}

const vector<PlatformFunction> &PlatformFunctions() {
	return Functions();
}

optional_ptr<const PlatformView> FindPlatformView(const string &name) {
	for (auto &view : Views()) {
		if (StringUtil::CIEquals(view.name, name)) {
			return &view;
		}
	}
	return nullptr;
}

optional_ptr<const PlatformFunction> FindPlatformFunction(const string &name) {
	for (auto &function : Functions()) {
		if (StringUtil::CIEquals(function.name, name)) {
			return &function;
		}
	}
	return nullptr;
}

optional_ptr<const PlatformFunction> PlatformFunctionByTarget(const string &target) {
	for (auto &function : Functions()) {
		if (*function.target && StringUtil::CIEquals(function.target, target)) {
			return &function;
		}
	}
	return nullptr;
}

bool PlatformObjectName(const vector<string> &parts, string &leaf) {
	if (parts.size() == 2 && IsPlatformCatalog(parts[0])) {
		leaf = parts[1];
		return true;
	}
	if (parts.size() == 3 && IsPlatformCatalog(parts[0]) && StringUtil::CIEquals(parts[1], "main")) {
		leaf = parts[2];
		return true;
	}
	return false;
}

bool IsPlatformFunctionName(const vector<string> &parts) {
	string leaf;
	return PlatformObjectName(parts, leaf) && FindPlatformFunction(leaf);
}

//===--------------------------------------------------------------------===//
// Rights
//===--------------------------------------------------------------------===//

int PolicyStore::AdminRights::PlatformGrant(const string &kind, const string &object) const {
	auto entry = platform.find(StringUtil::Lower(kind) + ":" + StringUtil::Lower(object));
	if (entry == platform.end()) {
		return -1;
	}
	return entry->second ? 1 : 0;
}

bool PolicyStore::AdminRights::MayAdminister() const {
	if (passthrough || unrestricted_manage || !catalogs.empty()) {
		return true;
	}
	for (auto &grant : platform) {
		if (grant.second && StringUtil::StartsWith(grant.first, "function:")) {
			auto function = FindPlatformFunction(grant.first.substr(9));
			if (function && !function->table) {
				return true;
			}
		}
	}
	return false;
}

bool PolicyStore::AdminRights::Privileged() const {
	return passthrough || unrestricted_manage || observe || unknown_scope || !catalogs.empty() || !platform.empty();
}

vector<string> PolicyStore::AdminRights::Bundles() const {
	vector<string> out;
	if (observe) {
		out.emplace_back("observe");
	}
	if (unrestricted_manage) {
		out.emplace_back("policy");
	}
	if (passthrough) {
		out.emplace_back("passthrough");
	}
	return out;
}

bool PlatformAccess::ReadsView(const PlatformView &view, bool &rows_scoped) const {
	rows_scoped = false;
	if (!rights) {
		return false;
	}
	if (rights->passthrough) {
		return true;
	}
	auto point = rights->PlatformGrant("view", view.name);
	if (point == 0) {
		return false; // a deny wins over every bundle but the break-glass
	}
	if (point == 1) {
		return true; // granted by name: the view whole
	}
	switch (view.view_class) {
	case PlatformViewClass::NODE:
		return rights->observe;
	case PlatformViewClass::POLICY:
		return rights->unrestricted_manage;
	case PlatformViewClass::CATALOG:
	case PlatformViewClass::ROLES:
		if (rights->unrestricted_manage) {
			return true;
		}
		if (!rights->catalogs.empty()) {
			rows_scoped = true;
			return true;
		}
		return false;
	}
	return false;
}

bool PlatformAccess::CallsFunction(const PlatformFunction &function) const {
	if (!rights) {
		return false;
	}
	if (function.right == PlatformRight::OPEN) {
		return Any();
	}
	if (rights->passthrough) {
		return true;
	}
	auto point = rights->PlatformGrant("function", function.name);
	if (point == 0) {
		return false;
	}
	switch (function.right) {
	case PlatformRight::ESCALATES:
	case PlatformRight::INFRASTRUCTURE:
		return false; // passthrough's alone - a point grant never reaches them
	default:
		break;
	}
	if (point == 1) {
		return true;
	}
	switch (function.right) {
	case PlatformRight::CATALOG:
		return rights->unrestricted_manage || !rights->catalogs.empty();
	case PlatformRight::POLICY:
	case PlatformRight::HANDS_OUT:
		return rights->unrestricted_manage;
	default:
		return false;
	}
}

bool PlatformAccess::Any() const {
	if (!rights) {
		return false;
	}
	if (rights->passthrough || rights->unrestricted_manage || rights->observe || !rights->catalogs.empty()) {
		return true;
	}
	for (auto &grant : rights->platform) {
		if (grant.second) {
			return true;
		}
	}
	return false;
}

//===--------------------------------------------------------------------===//
// The one authorizer
//===--------------------------------------------------------------------===//

namespace {

//! The call a compiled management statement makes: `SELECT acl_<fn>(…)` or `SELECT * FROM acl_<fn>(…)`
FunctionExpression &CompiledCall(SQLStatement &statement) {
	if (statement.type != StatementType::SELECT_STATEMENT) {
		throw BinderException("acl admin: a management statement compiles to one call");
	}
	auto &node = *statement.Cast<SelectStatement>().node;
	if (node.type != QueryNodeType::SELECT_NODE) {
		throw BinderException("acl admin: a management statement compiles to one call");
	}
	auto &select = node.Cast<SelectNode>();
	if (select.from_table && select.from_table->type == TableReferenceType::TABLE_FUNCTION) {
		return select.from_table->Cast<TableFunctionRef>().function->Cast<FunctionExpression>();
	}
	if (select.select_list.size() != 1 || select.select_list[0]->GetExpressionClass() != ExpressionClass::FUNCTION) {
		throw BinderException("acl admin: a management statement compiles to one call");
	}
	return select.select_list[0]->Cast<FunctionExpression>();
}

//! A constant argument's text, or "" when the argument is absent or NULL. A parameter where one is
//! judged is refused: what it will hold is not known before the call runs.
string ConstantArgument(FunctionExpression &call, idx_t index, const char *function) {
	auto &arguments = call.GetArguments();
	if (index >= arguments.size()) {
		return string();
	}
	auto &argument = arguments[index].GetExpression();
	if (argument.GetExpressionClass() != ExpressionClass::CONSTANT) {
		throw BinderException("acl admin: platform.%s: the argument that carries authorization must be a constant, "
		                      "not a parameter - it is judged before the call runs",
		                      function);
	}
	auto value = argument.Cast<ConstantExpression>().GetLiteral().ToValue();
	return value.IsNull() ? string() : value.ToString();
}

} // namespace

void AuthorizeAdminCall(SQLStatement &statement, const PolicyStore::AdminRights &rights) {
	auto &call = CompiledCall(statement);
	auto name = StringUtil::Lower(call.FunctionName().GetIdentifierName());
	auto function = PlatformFunctionByTarget(name);
	if (!function) {
		// a management call this table does not know: refuse rather than treat it as unscoped
		throw BinderException("acl admin: cannot authorize the management call \"%s\"", name);
	}
	string vcat;
	if (function->catalog_arg >= 0) {
		vcat = ConstantArgument(call, NumericCast<idx_t>(function->catalog_arg), function->name);
		if (IsPlatformCatalog(vcat)) {
			// spec 117: the system catalog is synthesized - no management call may name it as a catalog
			throw BinderException("acl admin: \"%s\" is the reserved system catalog of administration - no "
			                      "virtual catalog takes that name",
			                      vcat);
		}
	}
	if (rights.passthrough) {
		return;
	}
	auto point = rights.PlatformGrant("function", function->name);
	if (point == 0) {
		throw BinderException("acl admin: platform.%s is denied to the principal", function->name);
	}
	switch (function->right) {
	case PlatformRight::ESCALATES:
		if (name == "acl_grant_platform" || name == "acl_revoke_platform") {
			throw BinderException("acl admin: grants on the platform catalog require a passthrough scope - a "
			                      "grantor that can grant everything is everything");
		}
		throw BinderException("acl admin: granting admin scopes requires a passthrough scope");
	case PlatformRight::INFRASTRUCTURE:
		throw BinderException("acl admin: ACL CLUSTER changes the cluster's infrastructure (extensions, sources, "
		                      "settings) and requires a passthrough scope - manage administers the ACL, not the "
		                      "nodes");
	case PlatformRight::OPEN:
		return;
	default:
		break;
	}
	if (point == 1) {
		return; // granted by name
	}
	if (function->right == PlatformRight::HANDS_OUT) {
		if (!rights.unrestricted_manage) {
			throw BinderException("acl admin: granting access to a catalog requires an unrestricted manage "
			                      "scope - managing a catalog does not include handing it out");
		}
		return;
	}
	if (rights.unrestricted_manage) {
		return;
	}
	if (function->right == PlatformRight::POLICY || vcat.empty()) {
		// a call without the catalog argument (acl_check_catalog() over every catalog) stays unscoped
		throw BinderException(
		    "acl admin: this statement is not catalog-specific and needs an unrestricted manage scope");
	}
	// case-insensitive (spec 116): a write lands on the catalog as the policy spells it
	// (PolicyStore::SpellCatalog), and the policy holds one spelling per catalog name
	for (auto &catalog : rights.catalogs) {
		if (NamePath::KeyEquals(catalog, vcat) || StringUtil::CIEquals(catalog, vcat)) {
			return;
		}
	}
	throw BinderException("acl admin: no manage scope for catalog \"%s\"", vcat);
}

void AuthorizeMgmt(vector<unique_ptr<SQLStatement>> &statements, const PolicyStore::AdminRights &rights) {
	for (auto &statement : statements) {
		AuthorizeAdminCall(*statement, rights);
	}
}

//===--------------------------------------------------------------------===//
// A top-level platform.<op>(…) call
//===--------------------------------------------------------------------===//

namespace {

vector<string> PartsOf(const QualifiedName &name) {
	vector<string> parts;
	for (auto &part : name.Path()) {
		if (!part.empty()) {
			parts.push_back(part.GetIdentifierName());
		}
	}
	return parts;
}

//! The platform function a call names, or nullptr
optional_ptr<const PlatformFunction> PlatformCallOf(const ParsedExpression &expr) {
	if (expr.GetExpressionClass() != ExpressionClass::FUNCTION) {
		return nullptr;
	}
	string leaf;
	if (!PlatformObjectName(PartsOf(expr.Cast<FunctionExpression>().GetQualifiedName()), leaf)) {
		return nullptr;
	}
	return FindPlatformFunction(leaf);
}

//! Fold an argument written as a constant - a literal, a list literal of them, a struct literal - into its
//! value; false for anything else (a parameter is answered by the caller)
bool FoldConstant(const ParsedExpression &expr, Value &out) {
	if (expr.GetExpressionClass() == ExpressionClass::CONSTANT) {
		out = expr.Cast<ConstantExpression>().GetLiteral().ToValue();
		return true;
	}
	if (expr.GetExpressionClass() != ExpressionClass::FUNCTION) {
		return false;
	}
	auto &function = expr.Cast<FunctionExpression>();
	auto name = StringUtil::Lower(function.FunctionName().GetIdentifierName());
	if (name != "list_value" && name != "array_value") {
		return false;
	}
	vector<Value> items;
	for (auto &argument : function.GetArguments()) {
		if (argument.HasName()) {
			return false;
		}
		Value item;
		if (!FoldConstant(argument.GetExpression(), item)) {
			return false;
		}
		items.push_back(item.IsNull() ? Value(LogicalType::VARCHAR) : Value(item.ToString()));
	}
	out = Value::LIST(LogicalType::VARCHAR, std::move(items));
	return true;
}

//! A capability list (`['select', 'insert']`) as the caps JSON the target takes
string CapsJson(const Value &value) {
	vector<string> entries;
	for (auto &item : ListValue::GetChildren(value)) {
		if (item.IsNull()) {
			continue;
		}
		auto capability = StringUtil::Lower(item.ToString());
		StringUtil::Trim(capability);
		entries.push_back(JsonQuote(capability) + ": true");
	}
	return "{" + StringUtil::Join(entries, ", ") + "}";
}

//! The argument as the target signature takes it
unique_ptr<ParsedExpression> TypedArgument(const PlatformFunction &function, const PlatformParam &param,
                                           unique_ptr<ParsedExpression> expr) {
	if (expr->GetExpressionClass() == ExpressionClass::PARAMETER) {
		if (param.authz) {
			throw BinderException("acl admin: platform.%s: \"%s\" carries authorization and must be a constant, not "
			                      "a parameter - it is judged before the call runs",
			                      function.name, param.name);
		}
		return expr;
	}
	Value value;
	if (!FoldConstant(*expr, value)) {
		throw BinderException("acl admin: platform.%s: \"%s\" takes a constant%s - a management call reads no "
		                      "data",
		                      function.name, param.name, param.authz ? "" : " or a parameter");
	}
	auto type = string(param.type);
	if (value.type().id() == LogicalTypeId::LIST) {
		if (type == LV) {
			return ConstantExpression::FromValue(value);
		}
		auto name = string(param.name);
		if (name == "caps") {
			return ConstantExpression::FromValue(Value(CapsJson(value)));
		}
		// a list where the target takes text: the csv the grammar writes (columns, claims, members)
		vector<string> items;
		for (auto &item : ListValue::GetChildren(value)) {
			if (!item.IsNull()) {
				items.push_back(item.ToString());
			}
		}
		return ConstantExpression::FromValue(Value(StringUtil::Join(items, ", ")));
	}
	if (value.IsNull()) {
		// an explicit NULL is the argument left out: the target's fallback (a NULL would make the call NULL)
		if (type == B) {
			return ConstantExpression::FromValue(Value::BOOLEAN(false));
		}
		if (type == LV) {
			return ConstantExpression::FromValue(Value::LIST(LogicalType::VARCHAR, {}));
		}
		return ConstantExpression::FromValue(Value(param.fallback));
	}
	if (type == B) {
		if (value.type().id() == LogicalTypeId::BOOLEAN) {
			return ConstantExpression::FromValue(value);
		}
		auto text = StringUtil::Lower(value.ToString());
		if (text != "true" && text != "false") {
			throw BinderException("acl admin: platform.%s: \"%s\" is true or false", function.name, param.name);
		}
		return ConstantExpression::FromValue(Value::BOOLEAN(text == "true"));
	}
	if (type == LV) {
		return ConstantExpression::FromValue(Value(value.ToString()));
	}
	// text: a boolean written for an `allowed` / `is_default` flag is its word
	if (value.type().id() == LogicalTypeId::BOOLEAN) {
		return ConstantExpression::FromValue(Value(BooleanValue::Get(value) ? "true" : "false"));
	}
	return ConstantExpression::FromValue(Value(value.ToString()));
}

//! The call's arguments put in the target's places: named ones by name, gaps filled with NULL up to the
//! smallest signature that takes them
vector<unique_ptr<ParsedExpression>> PlaceArguments(const PlatformFunction &function, FunctionExpression &call) {
	vector<unique_ptr<ParsedExpression>> slots(function.params.size());
	idx_t positional = 0;
	bool named_seen = false;
	for (auto &argument : call.GetArgumentsMutable()) {
		idx_t index;
		if (argument.HasName()) {
			named_seen = true;
			auto written = argument.GetName().GetIdentifierName();
			index = DConstants::INVALID_INDEX;
			for (idx_t i = 0; i < function.params.size(); i++) {
				if (StringUtil::CIEquals(function.params[i].name, written)) {
					index = i;
				}
			}
			if (index == DConstants::INVALID_INDEX) {
				vector<string> names;
				for (auto &param : function.params) {
					names.emplace_back(param.name);
				}
				throw BinderException("acl admin: platform.%s takes no argument \"%s\" (it takes: %s)", function.name,
				                      written, StringUtil::Join(names, ", "));
			}
		} else {
			if (named_seen) {
				throw BinderException("acl admin: platform.%s: a positional argument after a named one", function.name);
			}
			index = positional++;
			if (index >= function.params.size()) {
				throw BinderException("acl admin: platform.%s takes at most %llu arguments", function.name,
				                      function.params.size());
			}
		}
		if (slots[index]) {
			throw BinderException("acl admin: platform.%s: \"%s\" is given twice", function.name,
			                      function.params[index].name);
		}
		slots[index] = TypedArgument(function, function.params[index], std::move(argument.GetExpressionMutable()));
	}
	idx_t needed = 0;
	for (idx_t i = 0; i < slots.size(); i++) {
		if (slots[i]) {
			needed = i + 1;
		}
	}
	idx_t arity = DConstants::INVALID_INDEX;
	for (auto candidate : function.arities) {
		if (candidate >= needed) {
			arity = candidate;
			break;
		}
	}
	if (arity == DConstants::INVALID_INDEX) {
		throw BinderException("acl admin: platform.%s takes at most %llu arguments", function.name,
		                      function.arities.back());
	}
	vector<unique_ptr<ParsedExpression>> out;
	for (idx_t i = 0; i < arity; i++) {
		if (slots[i]) {
			out.push_back(std::move(slots[i]));
		} else {
			// a gap before an argument given (or below the smallest signature): the target's own fallback
			auto &param = function.params[i];
			auto type = string(param.type);
			if (type == B) {
				out.push_back(ConstantExpression::FromValue(Value::BOOLEAN(false)));
			} else if (type == LV) {
				out.push_back(ConstantExpression::FromValue(Value::LIST(LogicalType::VARCHAR, {})));
			} else {
				out.push_back(ConstantExpression::FromValue(Value(param.fallback)));
			}
		}
	}
	return out;
}

//! The bare top-level shape: one item, no FROM, nothing that would make the call per row or conditional
bool TopLevelSelect(SelectStatement &statement, FunctionExpression *&call) {
	if (!statement.node || statement.node->type != QueryNodeType::SELECT_NODE) {
		return false;
	}
	auto &node = statement.node->Cast<SelectNode>();
	if (node.select_list.size() != 1 || !PlatformCallOf(*node.select_list[0])) {
		return false;
	}
	bool bare = (!node.from_table || node.from_table->type == TableReferenceType::EMPTY_FROM) && !node.where_clause &&
	            !node.having && !node.qualify && !node.sample && node.groups.group_expressions.empty() &&
	            node.groups.grouping_sets.empty() && node.modifiers.empty() && node.cte_map.map.empty();
	if (!bare) {
		return false;
	}
	call = &node.select_list[0]->Cast<FunctionExpression>();
	return true;
}

unique_ptr<SQLStatement> CompiledStatement(const PlatformFunction &function, FunctionExpression &call) {
	if (call.Distinct() || call.Filter() || (call.OrderBy() && !call.OrderBy()->orders.empty())) {
		throw BinderException("acl admin: platform.%s is a management call - no DISTINCT, FILTER or ORDER BY",
		                      function.name);
	}
	auto arguments = PlaceArguments(function, call);
	auto node = make_uniq<SelectNode>();
	if (function.table) {
		node->select_list.push_back(make_uniq<StarExpression>());
		auto ref = make_uniq<TableFunctionRef>();
		ref->function = make_uniq<FunctionExpression>(Identifier(function.target), std::move(arguments));
		node->from_table = std::move(ref);
	} else {
		auto target = make_uniq<FunctionExpression>(Identifier(function.target), std::move(arguments));
		target->SetAlias(Identifier(function.name));
		node->select_list.push_back(std::move(target));
		node->from_table = make_uniq<EmptyTableRef>();
	}
	auto statement = make_uniq<SelectStatement>();
	statement->node = std::move(node);
	return std::move(statement);
}

} // namespace

bool CompilePlatformCall(SQLStatement &statement, unique_ptr<SQLStatement> &compiled) {
	FunctionExpression *call = nullptr;
	if (statement.type == StatementType::SELECT_STATEMENT) {
		if (!TopLevelSelect(statement.Cast<SelectStatement>(), call)) {
			return false;
		}
	} else if (statement.type == StatementType::CALL_STATEMENT) {
		auto &function = statement.Cast<CallStatement>().function;
		if (!function || !PlatformCallOf(*function)) {
			return false;
		}
		call = &function->Cast<FunctionExpression>();
	} else {
		return false;
	}
	auto leaf = call->FunctionName().GetIdentifierName();
	auto function = FindPlatformFunction(leaf);
	if (function->table) {
		if (statement.type == StatementType::SELECT_STATEMENT) {
			throw BinderException("acl admin: platform.%s is a table function - SELECT * FROM platform.%s(…)",
			                      function->name, function->name);
		}
		return false; // CALL of a read function: the rewriter answers it like `SELECT * FROM platform.f(…)`
	}
	compiled = CompiledStatement(*function, *call);
	return true;
}

bool IsPlatformCallStatement(SQLStatement &statement) {
	unique_ptr<SQLStatement> ignored;
	try {
		return CompilePlatformCall(statement, ignored);
	} catch (std::exception &) {
		return true; // a platform call written wrongly is still one
	}
}

//===--------------------------------------------------------------------===//
// The views
//===--------------------------------------------------------------------===//

namespace {

//! The rows of the principal's catalogs only: `vcat` IN its catalogs, compared as names compare
string InCatalogs(const string &column, const std::set<string> &catalogs) {
	vector<string> folded;
	for (auto &catalog : catalogs) {
		folded.push_back(KeyFoldSql(Lit(catalog)));
	}
	if (folded.empty()) {
		return "false";
	}
	return KeyFoldSql(column) + " IN (" + StringUtil::Join(folded, ", ") + ")";
}

string Ident(const string &name) {
	return "\"" + StringUtil::Replace(name, "\"", "\"\"") + "\"";
}

//! `SELECT CAST("c" AS T) AS "c", …` over the body - the view's declared shape, whatever the source says
string Typed(const PlatformView &view, const string &body) {
	vector<string> items;
	for (auto &column : view.columns) {
		items.push_back("CAST(" + Ident(column.name) + " AS " + TypeText(column.type) + ") AS " + Ident(column.name));
	}
	return "SELECT " + StringUtil::Join(items, ", ") + " FROM (" + body + ") __platform_" + view.name;
}

//! The body of a view read from the policy catalog's tables; empty when the view does not read them
string TableBody(acl_detail::CatalogBackend &catalog, const string &view, bool scoped, const std::set<string> &cats) {
	auto table = [&](const char *name) {
		return catalog.Tbl(name);
	};
	auto where = [&](const string &column) {
		return scoped ? " WHERE " + InCatalogs(column, cats) : string();
	};
	if (view == "catalogs") {
		return "SELECT \"vcat\" AS \"catalog\", \"comment\" FROM " + table("catalogs") + where("\"vcat\"");
	}
	if (view == "relations") {
		return "SELECT \"vcat\" AS \"catalog\", \"vname\" AS \"name\", \"form\", \"phys\", \"view_sql\", \"rls\","
		       " \"rls_checked\", \"origin\", \"comment\", \"alias_types\", \"enum_types\" FROM " +
		       table("relations") + where("\"vcat\"");
	}
	if (view == "relation_columns") {
		return "SELECT \"vcat\" AS \"catalog\", \"vname\" AS \"relation\", \"pos\", \"name\", \"expr\", \"nullable\" "
		       "FROM " +
		       table("relation_columns") + where("\"vcat\"");
	}
	if (view == "schemas") {
		return "SELECT \"vcat\" AS \"catalog\", \"path\", \"phys_path\", \"origin\", \"comment\" FROM " +
		       table("schemas") + where("\"vcat\"");
	}
	if (view == "functions") {
		return "SELECT \"vcat\" AS \"catalog\", \"vname\" AS \"name\", \"kind\", \"form\", \"target\", \"template\","
		       " acl_platform_list(\"params\") AS \"params\", \"comment\" FROM " +
		       table("functions") + where("\"vcat\"");
	}
	if (view == "function_columns") {
		return "SELECT \"vcat\" AS \"catalog\", \"vname\" AS \"function\", \"kind\", \"pos\", \"name\", \"type\","
		       " \"comment\", \"nullable\" FROM " +
		       table("object_columns") + " WHERE \"kind\" <> 'relation'" +
		       (scoped ? " AND " + InCatalogs("\"vcat\"", cats) : string());
	}
	if (view == "references") {
		return "SELECT \"vcat\" AS \"catalog\", \"name\", \"from_vname\" AS \"from_object\", \"to_vname\" AS "
		       "\"to_object\", \"to_kind\", \"expr\" AS \"expression\", \"cardinality\", \"optional\", "
		       "\"join_method\", \"comment\" FROM " +
		       table("references") + where("\"vcat\"");
	}
	if (view == "reference_columns") {
		return "SELECT \"vcat\" AS \"catalog\", \"name\" AS \"reference\", \"pos\", \"side\", \"column\", \"param\" "
		       "FROM " +
		       table("reference_columns") + where("\"vcat\"");
	}
	if (view == "keys") {
		return "SELECT \"vcat\" AS \"catalog\", \"vname\" AS \"object\", \"kind\", \"pos\", \"column\" FROM " +
		       table("keys") + where("\"vcat\"");
	}
	if (view == "roles") {
		if (scoped) {
			// a catalog admin sees the NAMES of the roles holding its catalogs, nothing about them
			return "SELECT DISTINCT \"role\", NULL AS \"comment\" FROM " + table("role_catalogs") + where("\"vcat\"");
		}
		return "SELECT \"role\", \"comment\" FROM " + table("roles");
	}
	if (view == "role_claims") {
		return "SELECT \"role\", \"claim\", \"value\" FROM " + table("role_claims");
	}
	if (view == "grants") {
		return "SELECT \"role\", \"vcat\" AS \"catalog\", \"is_main\", acl_platform_caps(\"caps\") AS \"caps\", "
		       "\"rls\", \"rls_checked\", acl_platform_list(\"columns\") AS \"columns\" FROM " +
		       table("role_catalogs") + where("\"vcat\"");
	}
	if (view == "schema_grants") {
		return "SELECT \"role\", \"vcat\" AS \"catalog\", \"schema_path\", acl_platform_caps(\"caps\") AS \"caps\", "
		       "\"inherited\", \"into\", \"virtual_only\", \"comment\" FROM " +
		       table("role_schemas") + where("\"vcat\"");
	}
	if (view == "object_grants") {
		return "SELECT \"role\", \"vcat\" AS \"catalog\", \"vname\" AS \"object\", acl_platform_caps(\"caps\") AS "
		       "\"caps\", \"rls\", \"rls_checked\", acl_platform_list(\"columns\") AS \"columns\" FROM " +
		       table("role_object_caps") + where("\"vcat\"");
	}
	if (view == "grant_columns") {
		return "SELECT \"role\", \"vcat\" AS \"catalog\", \"vname\" AS \"object\", \"pos\", \"name\", \"type\" FROM " +
		       table("grant_columns") + where("\"vcat\"");
	}
	if (view == "admins") {
		return "SELECT \"role\", \"scope\", nullif(\"vcat\", '') AS \"catalog\" FROM " + table("admins");
	}
	if (view == "platform_grants") {
		return "SELECT \"role\", \"object\", \"kind\", \"allowed\" FROM " + table("platform_grants");
	}
	if (view == "issuers") {
		return "SELECT \"name\", \"url\", \"secret_service\", \"secret\" FROM " + table("issuers");
	}
	if (view == "clients") {
		return "SELECT \"name\", \"issuer\", acl_platform_list(\"audiences\") AS \"audiences\", "
		       "acl_platform_list(\"azp\") AS \"azp\", acl_platform_conditions(\"requires\") AS \"requires\", "
		       "acl_platform_list(\"roles_from\") AS \"roles_from\", acl_platform_list(\"roles_constant\") AS "
		       "\"roles_constant\", \"unmapped\", acl_platform_attributes(\"attributes\") AS \"attributes\", "
		       "acl_platform_list(\"subject\") AS \"subject\", \"token_type\", \"client_id\", "
		       "acl_platform_list(\"flows\") AS \"flows\", \"secret_service\", \"secret\", \"implicit\" FROM " +
		       table("clients");
	}
	if (view == "role_mappings") {
		return "SELECT \"scope_kind\", \"scope_name\", \"source\", \"external_value\", \"role\" FROM " +
		       table("role_mappings");
	}
	if (view == "resource_groups") {
		return "SELECT \"group\", \"window_start\", \"window_max\", \"batch_bytes\", \"max_result_rows\", "
		       "\"queue_priority\", \"max_sessions\", \"comment\", \"is_default\" FROM " +
		       table("resource_groups");
	}
	if (view == "role_resource_groups") {
		return "SELECT \"role\", \"group\" FROM " + table("role_resource_groups");
	}
	return string();
}

//! The body of a view read through a function (any mode of the store); empty when it is not one
string FunctionBody(const string &view) {
	if (view == "jwks_cache") {
		return "SELECT * FROM acl_jwks_cache()";
	}
	if (view == "function_categories" || view == "function_category_members" || view == "function_grants") {
		return "SELECT * FROM acl_" + view + "()";
	}
	if (view == "function_status") {
		return "SELECT \"database\", \"schema\", \"name\", \"kind\", \"function_type\", \"categories\", \"status\","
		       " \"present\" FROM acl_function_status()";
	}
	if (view == "cluster_items" || view == "cluster_effective") {
		return "SELECT \"scope\", \"kind\", \"name\", acl_platform_map(\"spec\") AS \"spec\", \"class\", \"version\","
		       " \"depends_on\", \"comment\" FROM acl_" +
		       view + "()";
	}
	if (view == "catalog_schema") {
		return "SELECT s.build AS \"build\", s.build_min_reader AS \"build_min_reader\", s.catalog AS \"catalog\","
		       " s.min_reader AS \"min_reader\", s.mode AS \"mode\" FROM (SELECT acl_catalog_schema() AS s)";
	}
	if (view == "sessions" || view == "node_load" || view == "node_doors" || view == "node_streams") {
		return "SELECT * FROM acl_platform_" + view + "()";
	}
	if (view == "drain") {
		return "SELECT acl_drain_status() = 'draining' AS \"draining\", acl_session_count() AS \"sessions\"";
	}
	if (view == "lineage_status") {
		return "SELECT acl_lineage_status() AS \"status\", acl_lineage_status() = 'on' AS \"sending\","
		       " current_setting('acl_lineage_level') AS \"level\", current_setting('acl_lineage_namespace') AS "
		       "\"namespace\"";
	}
	return string();
}

} // namespace

bool PlatformViewSql(PolicyStore &store, const PolicyStore::AdminRights &rights, const string &name, string &sql) {
	auto view = FindPlatformView(name);
	if (!view) {
		return false;
	}
	PlatformAccess access;
	access.rights = &rights;
	bool scoped = false;
	if (!access.ReadsView(*view, scoped)) {
		return false;
	}
	auto body = FunctionBody(view->name);
	if (body.empty()) {
		if (!store.catalog || store.catalog->FunctionMode()) {
			NoteDenyReason(Reason::UNAVAILABLE);
			throw BinderException("acl_rewrite: platform.%s needs a policy catalog - this policy source cannot "
			                      "enumerate it (acl_use_db)",
			                      view->name);
		}
		body = TableBody(*store.catalog, view->name, scoped, rights.catalogs);
	}
	sql = Typed(*view, body);
	return true;
}

bool PlatformReadFunctionSql(PolicyStore &store, const Principal &principal, const PolicyStore::AdminRights &rights,
                             const string &name, const vector<Value> &arguments, string &sql) {
	auto function = FindPlatformFunction(name);
	if (!function || !function->table) {
		return false;
	}
	PlatformAccess access;
	access.rights = &rights;
	if (!access.CallsFunction(*function)) {
		return false;
	}
	if (function->right == PlatformRight::OPEN) {
		// console_info(): what a console reads to show only what works
		if (!arguments.empty()) {
			throw BinderException("acl_rewrite: platform.console_info takes no arguments");
		}
		string build;
#ifdef EXT_VERSION_ACL
		build = EXT_VERSION_ACL;
#endif
		auto list = [](const vector<string> &items) {
			vector<string> quoted;
			for (auto &item : items) {
				quoted.push_back(Lit(item));
			}
			return "[" + StringUtil::Join(quoted, ", ") + "]::VARCHAR[]";
		};
		vector<string> views, functions, catalogs(rights.catalogs.begin(), rights.catalogs.end());
		for (auto &view : Views()) {
			views.emplace_back(view.name);
		}
		for (auto &each : Functions()) {
			functions.emplace_back(each.name);
		}
		auto bundles = rights.Bundles();
		vector<string> readable, callable;
		for (auto &view : Views()) {
			bool scoped;
			if (access.ReadsView(view, scoped)) {
				readable.emplace_back(view.name);
			}
		}
		for (auto &each : Functions()) {
			if (access.CallsFunction(each)) {
				callable.emplace_back(each.name);
			}
		}
		sql = "SELECT " + Lit(build.empty() ? string("dev") : build) + " AS \"build\", " +
		      std::to_string(AuditHooks::CONTRACT_VERSION) + "::BIGINT AS \"audit_contract\", " +
		      std::to_string(AclConnectionContract::VERSION) +
		      "::BIGINT AS \"connection_contract\", s.build AS \"schema_build\", s.build_min_reader AS "
		      "\"schema_build_min_reader\", s.catalog AS \"schema_catalog\", s.min_reader AS \"schema_min_reader\", "
		      "s.mode AS \"schema_mode\", " +
		      list(views) + " AS \"views\", " + list(functions) + " AS \"functions\", " + list(readable) +
		      " AS \"my_views\", " + list(callable) + " AS \"my_functions\", " + list(bundles) + " AS \"bundles\", " +
		      list(catalogs) + " AS \"admin_catalogs\" FROM (SELECT acl_catalog_schema() AS s)";
		return true;
	}
	// check_catalog([vcat]): the authorizer judges it like the grammar's CHECK VIRTUAL CATALOG
	if (arguments.size() > 1) {
		throw BinderException("acl_rewrite: platform.%s takes at most one argument: the catalog", function->name);
	}
	vector<unique_ptr<ParsedExpression>> children;
	for (auto &argument : arguments) {
		children.push_back(ConstantExpression::FromValue(argument));
	}
	auto node = make_uniq<SelectNode>();
	node->select_list.push_back(make_uniq<StarExpression>());
	auto ref = make_uniq<TableFunctionRef>();
	ref->function = make_uniq<FunctionExpression>(Identifier(function->target), std::move(children));
	node->from_table = std::move(ref);
	SelectStatement statement;
	statement.node = std::move(node);
	AuthorizeAdminCall(statement, rights);
	sql = statement.ToString();
	return true;
}

//===--------------------------------------------------------------------===//
// The listings' share
//===--------------------------------------------------------------------===//

void PlatformListingCtes(const PolicyStore::AdminRights &rights, string &objects, string &columns) {
	objects.clear();
	columns.clear();
	PlatformAccess access;
	access.rights = &rights;
	if (!access.Any()) {
		return;
	}
	vector<string> object_rows, column_rows;
	for (auto &view : Views()) {
		bool scoped;
		if (!access.ReadsView(view, scoped)) {
			continue;
		}
		object_rows.push_back("(" + Lit(view.name) + ", " + Lit(view.comment) + ")");
		for (idx_t i = 0; i < view.columns.size(); i++) {
			column_rows.push_back("(" + Lit(view.name) + ", " + std::to_string(i + 1) + ", " +
			                      Lit(view.columns[i].name) + ", " + Lit(TypeText(view.columns[i].type)) + ")");
		}
	}
	if (object_rows.empty()) {
		// a principal holding only functions: the catalog is there (its schema `main` holds them)
		objects = "SELECT NULL::VARCHAR AS vname, NULL::VARCHAR AS comment WHERE false";
		columns = "SELECT NULL::VARCHAR AS vname, NULL::BIGINT AS pos, NULL::VARCHAR AS name, NULL::VARCHAR AS type "
		          "WHERE false";
		return;
	}
	objects = "SELECT * FROM (VALUES " + StringUtil::Join(object_rows, ", ") + ") AS p(vname, comment)";
	columns = "SELECT * FROM (VALUES " + StringUtil::Join(column_rows, ", ") + ") AS p(vname, pos, name, type)";
}

vector<PlatformFunctionRow> PlatformFunctionRows(const PolicyStore::AdminRights &rights) {
	vector<PlatformFunctionRow> out;
	PlatformAccess access;
	access.rights = &rights;
	for (auto &function : Functions()) {
		if (!access.CallsFunction(function)) {
			continue;
		}
		PlatformFunctionRow row;
		row.name = function.name;
		row.kind = function.table ? "table" : "scalar";
		row.returns = function.returns;
		for (auto &param : function.params) {
			row.parameters.emplace_back(param.name);
			row.parameter_types.push_back(TypeText(param.type));
		}
		row.comment = function.comment;
		out.push_back(std::move(row));
	}
	return out;
}

//===--------------------------------------------------------------------===//
// The node's state and the typed conversions
//===--------------------------------------------------------------------===//

namespace {

struct PlatformInfo : TableFunctionInfo {
	PlatformInfo(shared_ptr<PolicyStore> store_p, string view_p) : store(std::move(store_p)), view(std::move(view_p)) {
	}
	shared_ptr<PolicyStore> store;
	string view;
};

struct PlatformBindData : TableFunctionData {
	shared_ptr<PolicyStore> store;
	string view;
};

struct PlatformRowsState : GlobalTableFunctionState {
	vector<vector<Value>> rows;
	idx_t next = 0;
};

using JsonVal = duckdb_yyjson::yyjson_val;

Value JsonBigint(JsonVal *value) {
	if (!value || !duckdb_yyjson::yyjson_is_num(value)) {
		return Value(LogicalType::BIGINT);
	}
	if (duckdb_yyjson::yyjson_is_int(value)) {
		return Value::BIGINT(duckdb_yyjson::yyjson_get_sint(value));
	}
	return Value::BIGINT(static_cast<int64_t>(duckdb_yyjson::yyjson_get_num(value)));
}

Value JsonBool(JsonVal *value) {
	if (!value || !duckdb_yyjson::yyjson_is_bool(value)) {
		return Value(LogicalType::BOOLEAN);
	}
	return Value::BOOLEAN(duckdb_yyjson::yyjson_get_bool(value));
}

Value JsonText(JsonVal *value) {
	if (!value || !duckdb_yyjson::yyjson_is_str(value)) {
		return Value(LogicalType::VARCHAR);
	}
	return Value(duckdb_yyjson::yyjson_get_str(value));
}

JsonVal *Field(JsonVal *object, const char *name) {
	return object && duckdb_yyjson::yyjson_is_obj(object) ? duckdb_yyjson::yyjson_obj_get(object, name) : nullptr;
}

//! What a JSON value says, as text: a string itself, anything else its JSON
string JsonValueText(JsonVal *value) {
	if (duckdb_yyjson::yyjson_is_str(value)) {
		return duckdb_yyjson::yyjson_get_str(value);
	}
	size_t size = 0;
	auto text = duckdb_yyjson::yyjson_val_write(value, 0, &size);
	if (!text) {
		return string();
	}
	string out(text, size);
	free(text); // NOLINT: yyjson's allocation
	return out;
}

vector<Value> JsonStrings(JsonVal *value) {
	vector<Value> out;
	if (!value || !duckdb_yyjson::yyjson_is_arr(value)) {
		return out;
	}
	duckdb_yyjson::yyjson_arr_iter iter;
	duckdb_yyjson::yyjson_arr_iter_init(value, &iter);
	while (auto item = duckdb_yyjson::yyjson_arr_iter_next(&iter)) {
		out.emplace_back(JsonValueText(item));
	}
	return out;
}

struct JsonDocument {
	explicit JsonDocument(const string &text) {
		doc = duckdb_yyjson::yyjson_read(text.c_str(), text.size(), 0);
	}
	~JsonDocument() {
		if (doc) {
			duckdb_yyjson::yyjson_doc_free(doc);
		}
	}
	JsonDocument(const JsonDocument &) = delete;
	JsonDocument &operator=(const JsonDocument &) = delete;
	JsonVal *Root() const {
		return doc ? duckdb_yyjson::yyjson_doc_get_root(doc) : nullptr;
	}
	duckdb_yyjson::yyjson_doc *doc = nullptr;
};

vector<vector<Value>> NodeRows(ClientContext &context, PolicyStore &store, const string &view) {
	vector<vector<Value>> rows;
	if (view == "sessions") {
		for (auto &session : store.SessionList()) {
			vector<Value> roles, groups;
			for (auto &role : session.roles) {
				roles.emplace_back(role);
			}
			for (auto &group : session.groups) {
				groups.emplace_back(group);
			}
			auto text = [](const string &value) {
				return value.empty() ? Value(LogicalType::VARCHAR) : Value(value);
			};
			rows.push_back({Value(session.id), text(session.subject), Value::LIST(LogicalType::VARCHAR, roles),
			                text(session.door), Value::BIGINT(session.idle_seconds),
			                session.expires_at > 0 ? Value::TIMESTAMP(Timestamp::FromEpochSeconds(session.expires_at))
			                                       : Value(LogicalType::TIMESTAMP),
			                text(session.level), text(session.level_source), text(session.profile_level),
			                text(session.profile_source), Value::LIST(LogicalType::VARCHAR, groups),
			                text(session.charged_group)});
		}
		return rows;
	}
	auto &db = DatabaseInstance::GetDatabase(context);
	JsonDocument doc(NodeLoadJson(db, store));
	auto root = doc.Root();
	if (!root) {
		throw BinderException("acl: the load report is not a document");
	}
	if (view == "node_load") {
		auto sessions = Field(root, "sessions");
		vector<Value> door_keys, door_values, group_keys, group_values;
		auto by_door = Field(sessions, "by_door");
		if (by_door && duckdb_yyjson::yyjson_is_obj(by_door)) {
			duckdb_yyjson::yyjson_obj_iter iter;
			duckdb_yyjson::yyjson_obj_iter_init(by_door, &iter);
			while (auto key = duckdb_yyjson::yyjson_obj_iter_next(&iter)) {
				door_keys.emplace_back(duckdb_yyjson::yyjson_get_str(key));
				door_values.push_back(JsonBigint(duckdb_yyjson::yyjson_obj_iter_get_val(key)));
			}
		}
		auto by_group = Field(sessions, "by_group");
		if (by_group && duckdb_yyjson::yyjson_is_obj(by_group)) {
			duckdb_yyjson::yyjson_obj_iter iter;
			duckdb_yyjson::yyjson_obj_iter_init(by_group, &iter);
			while (auto key = duckdb_yyjson::yyjson_obj_iter_next(&iter)) {
				auto entry = duckdb_yyjson::yyjson_obj_iter_get_val(key);
				group_keys.emplace_back(duckdb_yyjson::yyjson_get_str(key));
				child_list_t<Value> pair {{"live", JsonBigint(Field(entry, "live"))},
				                          {"max", JsonBigint(Field(entry, "max"))}};
				group_values.push_back(Value::STRUCT(std::move(pair)));
			}
		}
		auto group_type = MapType::ValueType(GroupsType());
		auto config = Field(root, "config");
		auto admit = Field(root, "admit");
		rows.push_back({JsonBool(Field(root, "draining")), JsonText(Field(root, "observe")),
		                JsonText(Field(root, "group")), JsonBool(Field(root, "group_known")),
		                JsonBigint(Field(config, "target")), JsonBigint(Field(config, "applied")),
		                JsonBigint(Field(sessions, "live")), JsonBigint(Field(sessions, "max")),
		                Value::MAP(LogicalType::VARCHAR, LogicalType::BIGINT, door_keys, door_values),
		                Value::MAP(LogicalType::VARCHAR, group_type, group_keys, group_values),
		                JsonBool(Field(admit, "new_session")), JsonBool(Field(admit, "new_quack_client")),
		                JsonBool(Field(admit, "new_stream"))});
		return rows;
	}
	if (view == "node_doors") {
		auto quack = Field(root, "quack");
		auto doors = Field(quack, "doors");
		if (doors && duckdb_yyjson::yyjson_is_arr(doors)) {
			duckdb_yyjson::yyjson_arr_iter iter;
			duckdb_yyjson::yyjson_arr_iter_init(doors, &iter);
			while (auto door = duckdb_yyjson::yyjson_arr_iter_next(&iter)) {
				rows.push_back({Value("quack"), JsonText(Field(door, "uri")), JsonBigint(Field(quack, "seats")),
				                JsonBigint(Field(door, "seated")), JsonBigint(Field(door, "seats_left"))});
			}
		}
		return rows;
	}
	// node_streams
	auto streams = Field(root, "streams");
	if (streams && duckdb_yyjson::yyjson_is_obj(streams)) {
		rows.push_back({JsonBigint(Field(streams, "budget_bytes")), JsonBigint(Field(streams, "reserve_bytes")),
		                JsonBigint(Field(streams, "reserved_bytes")), JsonBigint(Field(streams, "producing")),
		                JsonBigint(Field(streams, "queued")), JsonBigint(Field(streams, "refused"))});
	}
	return rows;
}

unique_ptr<FunctionData> NodeBind(ClientContext &, TableFunctionBindInput &input, vector<LogicalType> &return_types,
                                  vector<Identifier> &names) {
	auto bind = make_uniq<PlatformBindData>();
	auto &info = input.info->Cast<PlatformInfo>();
	bind->store = info.store;
	bind->view = info.view;
	auto view = FindPlatformView(bind->view);
	if (!view) {
		throw InternalException("acl platform: no view behind acl_platform_%s", bind->view);
	}
	for (auto &column : view->columns) {
		names.push_back(Identifier(column.name));
		return_types.push_back(TypeOf(column.type));
	}
	return std::move(bind);
}

unique_ptr<GlobalTableFunctionState> NodeInit(ClientContext &context, TableFunctionInitInput &input) {
	auto &bind = input.bind_data->Cast<PlatformBindData>();
	auto state = make_uniq<PlatformRowsState>();
	state->rows = NodeRows(context, *bind.store, bind.view);
	return std::move(state);
}

void NodeScan(ClientContext &, TableFunctionInput &data, DataChunk &output) {
	auto &state = data.global_state->Cast<PlatformRowsState>();
	idx_t count = 0;
	while (state.next < state.rows.size() && count < STANDARD_VECTOR_SIZE) {
		auto &row = state.rows[state.next++];
		for (idx_t col = 0; col < row.size() && col < output.ColumnCount(); col++) {
			output.data[col].SetValue(count, row[col]);
		}
		count++;
	}
	output.SetChildCardinality(count);
}

//! acl_platform_caps(caps_json) -> STRUCT of every capability; NULL when the caps are unstated
void CapsFunc(DataChunk &args, ExpressionState &, Vector &result) {
	for (idx_t row = 0; row < args.size(); row++) {
		auto value = args.GetValue(0, row);
		auto text = value.IsNull() ? string() : value.ToString();
		StringUtil::Trim(text);
		if (text.empty()) {
			result.SetValue(row, Value(CapsType()));
			continue;
		}
		auto caps = acl_detail::ParseCaps(text);
		child_list_t<Value> children;
		for (auto capability : CAPABILITIES) {
			children.emplace_back(capability, Value::BOOLEAN(caps.count(capability) > 0));
		}
		result.SetValue(row, Value::STRUCT(std::move(children)));
	}
}

//! acl_platform_list(text) -> VARCHAR[]: a JSON array, or a top-level csv (a column list, a parameter list)
void ListFunc(DataChunk &args, ExpressionState &, Vector &result) {
	for (idx_t row = 0; row < args.size(); row++) {
		auto value = args.GetValue(0, row);
		if (value.IsNull()) {
			result.SetValue(row, Value(LogicalType::LIST(LogicalType::VARCHAR)));
			continue;
		}
		auto text = value.ToString();
		StringUtil::Trim(text);
		vector<Value> items;
		if (!text.empty() && text[0] == '[') {
			JsonDocument doc(text);
			items = JsonStrings(doc.Root());
		} else if (!text.empty()) {
			for (auto &part : SplitTopLevel(text, ',')) {
				if (!part.empty()) {
					items.emplace_back(part);
				}
			}
		}
		result.SetValue(row, Value::LIST(LogicalType::VARCHAR, std::move(items)));
	}
}

//! acl_platform_map(json_object) -> MAP(VARCHAR, VARCHAR): a string value as itself, anything else as JSON
void MapFunc(DataChunk &args, ExpressionState &, Vector &result) {
	for (idx_t row = 0; row < args.size(); row++) {
		auto value = args.GetValue(0, row);
		vector<Value> keys, values;
		if (!value.IsNull()) {
			JsonDocument doc(value.ToString());
			auto root = doc.Root();
			if (root && duckdb_yyjson::yyjson_is_obj(root)) {
				duckdb_yyjson::yyjson_obj_iter iter;
				duckdb_yyjson::yyjson_obj_iter_init(root, &iter);
				while (auto key = duckdb_yyjson::yyjson_obj_iter_next(&iter)) {
					keys.emplace_back(duckdb_yyjson::yyjson_get_str(key));
					values.emplace_back(JsonValueText(duckdb_yyjson::yyjson_obj_iter_get_val(key)));
				}
			}
		}
		if (value.IsNull()) {
			result.SetValue(row, Value(LogicalType::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR)));
			continue;
		}
		result.SetValue(row, Value::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR, keys, values));
	}
}

//! acl_platform_conditions(json) -> LIST(STRUCT(path, op, values)): a client's REQUIRE (spec 095)
void ConditionsFunc(DataChunk &args, ExpressionState &, Vector &result) {
	auto item_type = ListType::GetChildType(ConditionsType());
	for (idx_t row = 0; row < args.size(); row++) {
		auto value = args.GetValue(0, row);
		vector<Value> items;
		if (!value.IsNull()) {
			JsonDocument doc(value.ToString());
			auto root = doc.Root();
			if (root && duckdb_yyjson::yyjson_is_arr(root)) {
				duckdb_yyjson::yyjson_arr_iter iter;
				duckdb_yyjson::yyjson_arr_iter_init(root, &iter);
				while (auto item = duckdb_yyjson::yyjson_arr_iter_next(&iter)) {
					child_list_t<Value> children {
					    {"path", JsonText(Field(item, "path"))},
					    {"op", JsonText(Field(item, "op"))},
					    {"values", Value::LIST(LogicalType::VARCHAR, JsonStrings(Field(item, "values")))}};
					items.push_back(Value::STRUCT(std::move(children)));
				}
			}
		}
		result.SetValue(row, Value::LIST(item_type, std::move(items)));
	}
}

//! acl_platform_attributes(json) -> LIST(STRUCT(name, paths, constant)): a client's ATTRIBUTES (spec 095)
void AttributesFunc(DataChunk &args, ExpressionState &, Vector &result) {
	auto item_type = ListType::GetChildType(AttributesType());
	for (idx_t row = 0; row < args.size(); row++) {
		auto value = args.GetValue(0, row);
		vector<Value> items;
		if (!value.IsNull()) {
			JsonDocument doc(value.ToString());
			auto root = doc.Root();
			if (root && duckdb_yyjson::yyjson_is_arr(root)) {
				duckdb_yyjson::yyjson_arr_iter iter;
				duckdb_yyjson::yyjson_arr_iter_init(root, &iter);
				while (auto item = duckdb_yyjson::yyjson_arr_iter_next(&iter)) {
					child_list_t<Value> children {
					    {"name", JsonText(Field(item, "name"))},
					    {"paths", Value::LIST(LogicalType::VARCHAR, JsonStrings(Field(item, "paths")))},
					    {"constant", JsonText(Field(item, "constant"))}};
					items.push_back(Value::STRUCT(std::move(children)));
				}
			}
		}
		result.SetValue(row, Value::LIST(item_type, std::move(items)));
	}
}

} // namespace

void RegisterAclPlatform(ExtensionLoader &loader, const shared_ptr<PolicyStore> &store) {
	for (auto view : {"sessions", "node_load", "node_doors", "node_streams"}) {
		auto name = string("acl_platform_") + view;
		TableFunction function(Identifier(name), {}, NodeScan, NodeBind, NodeInit);
		function.function_info = make_shared_ptr<PlatformInfo>(store, view);
		loader.RegisterFunction(function);
	}
	auto scalar = [&](const char *name, const LogicalType &returns, const scalar_function_t &fn) {
		ScalarFunction function(Identifier(name), {LogicalType::VARCHAR}, returns, fn);
		MarkAclScalar(function, store);
		loader.RegisterFunction(function);
	};
	scalar("acl_platform_caps", CapsType(), CapsFunc);
	scalar("acl_platform_list", LogicalType::LIST(LogicalType::VARCHAR), ListFunc);
	scalar("acl_platform_map", LogicalType::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR), MapFunc);
	scalar("acl_platform_conditions", ConditionsType(), ConditionsFunc);
	scalar("acl_platform_attributes", AttributesType(), AttributesFunc);
}

} // namespace acl
} // namespace duckdb
