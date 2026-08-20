// Per-principal policy state (specs/001): the policy shape, the per-instance PolicyStore with its
// resolver methods and template cache, and the info carriers that attach the store to DuckDB's parser
// extension and to the admin functions. In production the resolver methods become the read-only,
// role-aware ACL callbacks behind this same seam.

#pragma once

#include "duckdb/common/case_insensitive_map.hpp"
#include "duckdb/common/mutex.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/parser/parser_extension.hpp"
#include "duckdb/parser/qualified_name.hpp"
#include "duckdb/parser/query_node.hpp"
#include "duckdb/parser/statement/select_statement.hpp"

#include <functional>
#include <list>
#include <unordered_map>

namespace duckdb {
class DatabaseInstance;

namespace acl {

struct Principal {
	vector<string> roles; // multi-role since spec 006 (union semantics); single-element until spec 007
	case_insensitive_map_t<string> claims;
};

//! Policy for one virtual relation (table or view) under one role. The resolver picks the replacement
//! form: RENAME (subquery_form=false) swaps the name in place for a physical object - it stays a real
//! table, so it is writable; SUBQUERY (subquery_form=true) wraps a SELECT - projection with computed
//! columns / masks, an RLS predicate, or a full view SQL - and is read-only by construction (you cannot
//! write through a subquery). Claim values are baked in for either RLS or view/computed SQL.
struct TablePolicy {
	bool subquery_form = true;   // true: wrap a SELECT (read-only); false: rename in place (writable)
	string phys;                 // physical relation reference, e.g. "phys.main.orders_physical"
	vector<string> projection;   // SQL select items (SUBQUERY), e.g. {"id", "NULL AS ssn", "amount*2 AS total"}
	string rls;                  // predicate template (SUBQUERY); may contain acl_claim('<name>'); empty = none
	string query;                // full SELECT template for a view (SUBQUERY; replaces phys/projection/rls)
	case_insensitive_set_t caps; // {"select","insert","update","delete","merge"}
};

//! Whether a function reference is a scalar/aggregate (expression position) or a table function (FROM)
enum class FunctionKind : uint8_t { SCALAR, TABLE };

//! One issuer's offline JWT verification config (spec 007): a row of acl.issuers, or the in-memory
//! issuer map. Keys are data, never fetched: the gateway/admin rotates them.
struct IssuerConfig {
	string issuer;
	string keys_json;            // JWKS ({"keys":[...]}: RSA n/e, EC P-256 x/y, oct k) or a PEM public key
	vector<string> audiences;    // allowlist; the token's aud (string or array) must intersect
	case_insensitive_set_t algs; // allowlist of {RS256, ES256, HS256}; anything else (incl. none) is refused
	string role_claim;           // dot path to the roles claim ("roles", "realm_access.roles", "groups")
	string claim_map;            // JSON: {"<jwt dot path>": "<acl_claim name>"}
};

//! Which functions are gated is a policy question, not the rewriter's: every function reference is
//! routed through the resolver, which decides. Most functions - the vast majority extensions add -
//! are pure transforms (e.g. ST_AsGeoJSON) and pass; only functions that read external data or route
//! queries past the ACL are denied (source readers like ST_Read/read_csv, cross-source scanners and
//! SQL passthrough like postgres_query/mssql_scan/query, session/secret access like getvariable). This
//! default denylist is a stub for the future role-aware ACL callback, which may classify differently
//! (and, for table functions it does not recognize, should lean to default-deny).
case_insensitive_set_t DefaultDeniedFunctions();

//! A small bounded LRU of parsed template prototypes. On a hit it returns a fresh Copy() of the
//! prototype (so the caller may bake markers into the copy); on a miss it parses via `parse`, caches the
//! prototype, and copies. Keyed by the exact template text, so a re-registered policy is a new key.
template <class T>
struct TemplateCache {
	static constexpr idx_t CAPACITY = 256;
	mutex lock;
	std::unordered_map<string, unique_ptr<T>> entries;
	std::list<string> recency; // front = least recently used
	std::unordered_map<string, std::list<string>::iterator> positions;

	unique_ptr<T> GetCopy(const string &key, const std::function<unique_ptr<T>()> &parse) {
		lock_guard<mutex> guard(lock);
		auto entry = entries.find(key);
		if (entry == entries.end()) {
			auto prototype = parse(); // may throw on a malformed template; nothing is cached then
			if (entries.size() >= CAPACITY && !recency.empty()) {
				auto victim = recency.front();
				entries.erase(victim);
				positions.erase(victim);
				recency.pop_front();
			}
			recency.push_back(key);
			positions[key] = std::prev(recency.end());
			entry = entries.emplace(key, std::move(prototype)).first;
		} else {
			recency.erase(positions[key]);
			recency.push_back(key);
			positions[key] = std::prev(recency.end());
		}
		return entry->second->Copy();
	}
};

namespace acl_detail {
struct CatalogBackend; // catalog-DB policy backend (spec 006), defined in acl_policy_catalog.cpp
} // namespace acl_detail

//! Per-database policy store: the seam the rewriter and the admin functions talk to. Two backends:
//! the in-memory maps below (default; dev/tests) and, once acl_use_db() ran, the catalog backend
//! (spec 006) reading policy from an ATTACHed database in standard duckdb dialect. Owned by
//! AclParserInfo (reached from the parser override) and shared with the admin setup functions via
//! ScalarFunctionInfo - no process-global state, so DB instances stay isolated.
struct PolicyStore {
	mutex lock;
	// role -> virtual name -> policy (tables and views share one namespace)
	case_insensitive_map_t<case_insensitive_map_t<TablePolicy>> tables;
	// role -> virtual table-function name -> policy (a separate namespace from relations)
	case_insensitive_map_t<case_insensitive_map_t<TablePolicy>> table_functions;
	// role -> virtual scalar-function name -> policy (subquery_form=true: expr macro; false: alias)
	case_insensitive_map_t<case_insensitive_map_t<TablePolicy>> scalar_functions;
	// token -> principal (the dev stub; a JWT-shaped token takes the real verification path instead)
	case_insensitive_map_t<Principal> tokens;
	// issuer registry + external->role mappings (spec 007), memory-mode counterparts of the catalog
	case_insensitive_map_t<IssuerConfig> issuers;
	case_insensitive_map_t<case_insensitive_map_t<vector<string>>> role_mappings; // issuer -> external -> roles
	// role -> default claims (used by the ROLE form, which carries no token)
	case_insensitive_map_t<case_insensitive_map_t<string>> role_claims;
	// gateway-wide function denylist (readers / rights-bypass); everything else passes
	case_insensitive_set_t denied_functions = DefaultDeniedFunctions();
	// parsed rewrite-template prototypes, so a template is parsed once and only copied per request
	TemplateCache<QueryNode> select_cache;      // relation / table-function subquery templates
	TemplateCache<ParsedExpression> expr_cache; // scalar macro templates
	// catalog backend (spec 006); present after acl_use_db()
	unique_ptr<acl_detail::CatalogBackend> catalog;

	// ctor/dtor out of line: the inline-defaulted versions would need ~CatalogBackend, incomplete here
	PolicyStore();
	~PolicyStore();

	//! Switch to the catalog backend: read policy from schema `schema` of the ATTACHed database
	//! `db_name` (standard duckdb dialect only). init=true creates/migrates the managed schema first.
	void EnableCatalog(DatabaseInstance &db, const string &db_name, const string &schema, bool init);
	bool CatalogEnabled() const {
		return catalog != nullptr;
	}

	// catalog admin operations (spec 006); each throws unless the catalog backend is enabled.
	// columns are (name, expr) pairs with an empty expr for a plain projected column.
	void CatalogCreate(const string &vcat, const string &comment);
	void CatalogAddRelation(const string &vcat, const string &vname, const string &form, const string &phys,
	                        const string &view_sql, const string &rls,
	                        const vector<std::pair<string, string>> &columns);
	void CatalogAddSchemaAlias(const string &vcat, const string &alias_path, const string &phys_path);
	void CatalogAddFunction(const string &vcat, const string &vname, const string &kind, const string &form,
	                        const string &target, const string &template_sql);
	void CatalogGrant(const string &role, const string &vcat, const string &caps_json, bool is_main);
	void CatalogRevoke(const string &role, const string &vcat);
	void CatalogDropRelation(const string &vcat, const string &vname);
	void CatalogDefineRole(const string &role, const case_insensitive_map_t<string> &claims);
	//! remove=true deletes the gate row (fall back to the default denylist); otherwise upserts it
	void CatalogSetFunctionGate(const string &name, bool allowed, bool remove);
	void CatalogDefineIssuer(const IssuerConfig &config);
	void CatalogMapRole(const string &issuer, const string &source, const string &external_value, const string &role);
	//! per-object caps override (the compatibility wrappers carry per-object caps, spec 006)
	void CatalogSetObjectCaps(const string &role, const string &vcat, const string &vname, const string &caps_json);
	//! ensure a role->catalog grant row exists without clobbering an existing one
	void CatalogEnsureGrant(const string &role, const string &vcat, bool is_main);

	//! Instantiate a SELECT template: a fresh SelectStatement whose node is a copy of the cached
	//! prototype (parsed once). The caller bakes markers into the copy.
	unique_ptr<SelectStatement> InstantiateSelect(const string &sql, const ParserOptions &options);
	//! Instantiate an expression template: a fresh copy of the cached parsed prototype.
	unique_ptr<ParsedExpression> InstantiateExpr(const string &expr, const ParserOptions &options);

	//! Verify a principal offline. A JWT-shaped token goes through real signature verification against
	//! the issuer registry (spec 007, throws with a specific reason on failure); a non-JWT token is a
	//! dev-stub lookup in the in-memory map; the ROLE form trusts the gateway.
	bool VerifyPrincipal(bool is_token, const string &value, Principal &out);

	//! Register an issuer / map an external role value (memory mode; catalog mode via the Catalog* ops)
	void DefineIssuer(IssuerConfig config);
	void MapRole(const string &issuer, const string &source, const string &external_value, const string &role);

	bool ResolveTable(const Principal &principal, const string &vname, TablePolicy &out);
	bool ResolveTableFunction(const Principal &principal, const string &vname, TablePolicy &out);
	bool ResolveScalarFunction(const Principal &principal, const string &vname, TablePolicy &out);

	//! The resolver seam every non-virtual function flows through. Catalog backend: function_gate rows
	//! (per-role, then global) decide first; otherwise the built-in denylist passes everything except
	//! source readers / rights-bypass functions (matching the last name component, so a qualified alias
	//! db.schema.read_csv cannot slip past).
	bool FunctionAllowed(const Principal &principal, const QualifiedName &name);

private:
	bool Resolve(const case_insensitive_map_t<case_insensitive_map_t<TablePolicy>> &space, const Principal &principal,
	             const string &vname, TablePolicy &out);

	//! The real JWT path of VerifyPrincipal (spec 007): issuer lookup -> acl_token verification ->
	//! role mapping -> claims; throws on any failure. Defined in acl_policy.cpp.
	void VerifyJwtPrincipal(const string &token, const string &issuer, Principal &out);
	bool LookupIssuer(const string &issuer, IssuerConfig &out);
	//! acl_jwt_clock_skew setting (seconds); the memory mode uses the 60s default (no db handle)
	int64_t JwtClockSkew();
	//! Map raw role-claim values through role_mappings; unmapped values pass only if the role exists
	vector<string> MapExternalRoles(const string &issuer, const vector<string> &raw_roles);

	// catalog-backend bridges, defined in acl_policy_catalog.cpp (the backend type stays private there)
	bool CatalogResolveTable(const Principal &principal, const string &vname, TablePolicy &out);
	bool CatalogResolveFunction(const Principal &principal, const string &vname, bool table_kind, TablePolicy &out);
	//! returns true when a gate row decides; `allowed` then carries the verdict
	bool CatalogFunctionGate(const Principal &principal, const QualifiedName &name, bool &allowed);
	void CatalogLoadRoleClaims(Principal &principal);
	bool CatalogLookupIssuer(const string &issuer, IssuerConfig &out);
	//! (external_value -> mapped roles) for the given values; also flags which candidates exist as roles
	void CatalogMapExternalRoles(const string &issuer, const vector<string> &values,
	                             case_insensitive_map_t<vector<string>> &mapped, case_insensitive_set_t &known_roles);
};

//! Carried on the parser extension (parser_info); the override reads the store from it.
struct AclParserInfo : ParserExtensionInfo {
	explicit AclParserInfo(shared_ptr<PolicyStore> store_p) : store(std::move(store_p)) {
	}
	shared_ptr<PolicyStore> store;
};

//! Carried on each admin setup scalar function (function_info); reaches the same store at execution.
struct AclScalarInfo : ScalarFunctionInfo {
	explicit AclScalarInfo(shared_ptr<PolicyStore> store_p) : store(std::move(store_p)) {
	}
	shared_ptr<PolicyStore> store;
};

} // namespace acl
} // namespace duckdb
