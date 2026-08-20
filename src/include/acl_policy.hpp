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
namespace acl {

struct Principal {
	string role;
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

//! Per-database policy store: virtual relations/functions, principals, and the function denylist, plus
//! the resolver methods over them. Owned by AclParserInfo (reached from the parser override) and shared
//! with the admin setup functions via ScalarFunctionInfo - no process-global state, so DB instances
//! stay isolated. In production the resolver methods become the read-only, role-aware ACL callbacks.
struct PolicyStore {
	mutex lock;
	// role -> virtual name -> policy (tables and views share one namespace)
	case_insensitive_map_t<case_insensitive_map_t<TablePolicy>> tables;
	// role -> virtual table-function name -> policy (a separate namespace from relations)
	case_insensitive_map_t<case_insensitive_map_t<TablePolicy>> table_functions;
	// role -> virtual scalar-function name -> policy (subquery_form=true: expr macro; false: alias)
	case_insensitive_map_t<case_insensitive_map_t<TablePolicy>> scalar_functions;
	// token -> principal
	case_insensitive_map_t<Principal> tokens;
	// role -> default claims (used by the ROLE form, which carries no token)
	case_insensitive_map_t<case_insensitive_map_t<string>> role_claims;
	// gateway-wide function denylist (readers / rights-bypass); everything else passes
	case_insensitive_set_t denied_functions = DefaultDeniedFunctions();
	// parsed rewrite-template prototypes, so a template is parsed once and only copied per request
	TemplateCache<QueryNode> select_cache;      // relation / table-function subquery templates
	TemplateCache<ParsedExpression> expr_cache; // scalar macro templates

	//! Instantiate a SELECT template: a fresh SelectStatement whose node is a copy of the cached
	//! prototype (parsed once). The caller bakes markers into the copy.
	unique_ptr<SelectStatement> InstantiateSelect(const string &sql, const ParserOptions &options);
	//! Instantiate an expression template: a fresh copy of the cached parsed prototype.
	unique_ptr<ParsedExpression> InstantiateExpr(const string &expr, const ParserOptions &options);

	//! Verify a principal offline. In production this checks a token signature; here it is a store hit.
	bool VerifyPrincipal(bool is_token, const string &value, Principal &out);

	bool ResolveTable(const Principal &principal, const string &vname, TablePolicy &out);
	bool ResolveTableFunction(const Principal &principal, const string &vname, TablePolicy &out);
	bool ResolveScalarFunction(const Principal &principal, const string &vname, TablePolicy &out);

	//! The resolver seam every non-virtual function flows through: it passes unless its bare name is on
	//! the denylist (matching the last component so a qualified alias db.schema.read_csv cannot slip past).
	//! A production, role-aware callback would also receive the principal and FunctionKind.
	bool FunctionAllowed(const QualifiedName &name);

private:
	bool Resolve(const case_insensitive_map_t<case_insensitive_map_t<TablePolicy>> &space, const Principal &principal,
	             const string &vname, TablePolicy &out);
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
