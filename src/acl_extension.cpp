#define DUCKDB_EXTENSION_MAIN

#include "acl_extension.hpp"
#include "duckdb.hpp"
#include "duckdb/common/case_insensitive_map.hpp"
#include "duckdb/common/helper.hpp"
#include "duckdb/common/mutex.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/parser/expression/constant_expression.hpp"
#include "duckdb/parser/expression/function_expression.hpp"
#include "duckdb/parser/expression/subquery_expression.hpp"
#include "duckdb/parser/parsed_expression_iterator.hpp"
#include "duckdb/execution/expression_executor_state.hpp"
#include "duckdb/parser/parser.hpp"
#include "duckdb/parser/parser_extension.hpp"
#include "duckdb/planner/expression/bound_function_expression.hpp"
#include "duckdb/parser/query_node/cte_node.hpp"
#include "duckdb/parser/query_node/delete_query_node.hpp"
#include "duckdb/parser/query_node/insert_query_node.hpp"
#include "duckdb/parser/query_node/merge_query_node.hpp"
#include "duckdb/parser/query_node/recursive_cte_node.hpp"
#include "duckdb/parser/query_node/select_node.hpp"
#include "duckdb/parser/query_node/set_operation_node.hpp"
#include "duckdb/parser/query_node/update_query_node.hpp"
#include "duckdb/parser/statement/delete_statement.hpp"
#include "duckdb/parser/statement/explain_statement.hpp"
#include "duckdb/parser/statement/insert_statement.hpp"
#include "duckdb/parser/statement/merge_into_statement.hpp"
#include "duckdb/parser/statement/select_statement.hpp"
#include "duckdb/parser/statement/update_statement.hpp"
#include "duckdb/parser/tableref/basetableref.hpp"
#include "duckdb/parser/tableref/joinref.hpp"
#include "duckdb/parser/tableref/subqueryref.hpp"
#include "duckdb/parser/tableref/table_function_ref.hpp"

#include <functional>
#include <list>
#include <unordered_map>

// PoC skeleton for the "parser_override + AST-rewrite" ACL model (see specs/001-parser-override-ast-rewrite/spec.md).
//
// A trusted gateway prepends `ACL ROLE "<role>"` / `ACL TOKEN '<token>'` / `ACL ADMIN` to every query.
// The parser_override below (enabled with `SET allow_parser_override_extension='fallback'`) recognizes
// that prefix, verifies the principal offline, re-parses the remainder with the native parser, and
// rewrites the parsed AST in place. The resolver picks one of two replacement forms per relation:
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
//   * every other function (scalar or table) -> routed through one resolver seam, which decides allow/deny;
//     the stub denies only source readers and rights-bypass functions (ST_Read/read_csv/postgres_query/
//     query/getvariable/...) and passes the rest (pure transforms like ST_AsGeoJSON), refused at parse
//     time before any bind - production plugs the role-aware ACL callback in here;
//   * an unknown name -> hard denial (never left for the binder to resolve against the real catalog);
//   * a DML target -> capability check + resolve-in-place to the physical name.
// Service statements (CALL/PRAGMA/DDL) never reach the DML/SELECT rewrite and are denied by the
// statement gate, so pragma-form passthroughs (e.g. postgres_execute as a pragma) are refused too.
// The rewritten statements flow through the normal bind->optimize->execute path, so DML/DDL/CTAS work
// as ordinary top-level statements. Resolvers here are in-process stubs; in production they are the
// read-only policy loaders described by the contract (offline token verify + bounded LRU policy cache).

namespace duckdb {
namespace {

//===--------------------------------------------------------------------===//
// Principal + policy registries (stub resolvers)
//===--------------------------------------------------------------------===//

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

//! Which functions are gated is a policy question, not the rewriter's: every function reference is
//! routed through the resolver, which decides. Most functions - the vast majority extensions add -
//! are pure transforms (e.g. ST_AsGeoJSON) and pass; only functions that read external data or route
//! queries past the ACL are denied (source readers like ST_Read/read_csv, cross-source scanners and
//! SQL passthrough like postgres_query/mssql_scan/query, session/secret access like getvariable). This
//! default denylist is a stub for the future role-aware ACL callback, which may classify differently
//! (and, for table functions it does not recognize, should lean to default-deny).
case_insensitive_set_t DefaultDeniedFunctions() {
	return {// file / blob readers
	        "read_csv", "read_csv_auto", "read_parquet", "parquet_scan", "read_json", "read_json_auto",
	        "read_json_objects", "read_ndjson", "read_ndjson_objects", "read_text", "read_blob", "sniff_csv", "glob",
	        // spatial readers
	        "st_read", "st_readosm", "st_read_meta",
	        // external-source scanners / SQL passthrough (bypass the gateway's ACL)
	        "postgres_query", "postgres_scan", "postgres_scan_pushdown", "postgres_execute", "mysql_query",
	        "mysql_scan", "mysql_execute", "mssql_query", "mssql_scan", "mssql_execute", "sqlite_scan", "sqlite_query",
	        "iceberg_scan", "iceberg_metadata", "delta_scan", "query", "query_table",
	        // session / secret state
	        "getvariable", "which_secret", "current_setting", "current_query"};
}

//! Whether a function reference is a scalar/aggregate (expression position) or a table function (FROM)
enum class FunctionKind : uint8_t { SCALAR, TABLE };

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
	unique_ptr<SelectStatement> InstantiateSelect(const string &sql, const ParserOptions &options) {
		auto node = select_cache.GetCopy(sql, [&]() -> unique_ptr<QueryNode> {
			Parser parser(options);
			parser.ParseQuery(sql);
			if (parser.statements.size() != 1 || parser.statements[0]->type != StatementType::SELECT_STATEMENT) {
				throw BinderException("acl_rewrite: rewrite template is not a single SELECT");
			}
			return std::move(parser.statements[0]->Cast<SelectStatement>().node);
		});
		auto statement = make_uniq<SelectStatement>();
		statement->node = std::move(node);
		return statement;
	}

	//! Instantiate an expression template: a fresh copy of the cached parsed prototype.
	unique_ptr<ParsedExpression> InstantiateExpr(const string &expr, const ParserOptions &options) {
		return expr_cache.GetCopy(expr, [&]() -> unique_ptr<ParsedExpression> {
			auto expressions = Parser::ParseExpressionList(expr, options);
			if (expressions.size() != 1) {
				throw BinderException("acl_rewrite: scalar template must be a single expression");
			}
			return std::move(expressions[0]);
		});
	}

	//! Verify a principal offline. In production this checks a token signature; here it is a store hit.
	bool VerifyPrincipal(bool is_token, const string &value, Principal &out) {
		lock_guard<mutex> guard(lock);
		if (is_token) {
			auto entry = tokens.find(value);
			if (entry == tokens.end()) {
				return false;
			}
			out = entry->second;
			return true;
		}
		out.role = value;
		auto claims = role_claims.find(value);
		if (claims != role_claims.end()) {
			out.claims = claims->second;
		}
		return true;
	}

	bool ResolveTable(const Principal &principal, const string &vname, TablePolicy &out) {
		return Resolve(tables, principal, vname, out);
	}
	bool ResolveTableFunction(const Principal &principal, const string &vname, TablePolicy &out) {
		return Resolve(table_functions, principal, vname, out);
	}
	bool ResolveScalarFunction(const Principal &principal, const string &vname, TablePolicy &out) {
		return Resolve(scalar_functions, principal, vname, out);
	}

	//! The resolver seam every non-virtual function flows through: it passes unless its bare name is on
	//! the denylist (matching the last component so a qualified alias db.schema.read_csv cannot slip past).
	//! A production, role-aware callback would also receive the principal and FunctionKind.
	bool FunctionAllowed(const QualifiedName &name) {
		lock_guard<mutex> guard(lock);
		return denied_functions.count(name.Name().GetIdentifierName()) == 0;
	}

private:
	bool Resolve(const case_insensitive_map_t<case_insensitive_map_t<TablePolicy>> &space, const Principal &principal,
	             const string &vname, TablePolicy &out) {
		lock_guard<mutex> guard(lock);
		auto role_entry = space.find(principal.role);
		if (role_entry == space.end()) {
			return false;
		}
		auto entry = role_entry->second.find(vname);
		if (entry == role_entry->second.end()) {
			return false;
		}
		out = entry->second;
		return true;
	}
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

//! Retrieve the policy store attached to the currently-executing admin setup function
PolicyStore &StoreOf(ExpressionState &state) {
	return *state.expr.Cast<BoundFunctionExpression>().Function().GetExtraFunctionInfo().Cast<AclScalarInfo>().store;
}

string Trimmed(string value) {
	StringUtil::Trim(value);
	return value;
}

vector<string> SplitCsv(const string &csv) {
	vector<string> out;
	for (auto &part : StringUtil::Split(csv, ',')) {
		auto trimmed = Trimmed(part);
		if (!trimmed.empty()) {
			out.push_back(trimmed);
		}
	}
	return out;
}

case_insensitive_map_t<string> ParseClaims(const string &csv) {
	case_insensitive_map_t<string> claims;
	for (auto &item : SplitCsv(csv)) {
		auto pos = item.find('=');
		if (pos == string::npos) {
			continue;
		}
		claims[Trimmed(item.substr(0, pos))] = Trimmed(item.substr(pos + 1));
	}
	return claims;
}

//===--------------------------------------------------------------------===//
// AST rewriter
//===--------------------------------------------------------------------===//

[[noreturn]] void Deny(const string &what) {
	throw BinderException("acl_rewrite: %s", what);
}

//! The lookup key for a virtual relation is its full written path (schema.subschema.table), not just
//! the last component, so a nested virtual namespace resolves to its own physical target.
string VirtualKey(const QualifiedName &name) {
	vector<string> parts;
	for (auto &part : name.Path()) {
		if (!part.empty()) {
			parts.push_back(part.GetIdentifierName());
		}
	}
	return StringUtil::Join(parts, ".");
}

//! Build a QualifiedName from a dotted physical name of any depth: the last component is the name, the
//! preceding ones are the (possibly nested) catalog/schema path. Preserves depth beyond [catalog,
//! schema, name] for DuckDB's nested-schema support (do not collapse to three components).
QualifiedName ParsePhysName(const string &phys) {
	auto parts = StringUtil::Split(phys, '.');
	if (parts.empty()) {
		return QualifiedName(Identifier(phys));
	}
	vector<Identifier> path;
	for (auto &part : parts) {
		path.push_back(Identifier(part));
	}
	auto name = std::move(path.back());
	path.pop_back();
	return QualifiedName(std::move(path), std::move(name));
}

//! Rewrites a parsed statement tree for one principal: virtual names -> safe subqueries, claims baked.
class AclRewriter {
public:
	AclRewriter(const Principal &principal, const ParserOptions &options, PolicyStore &store)
	    : principal(principal), store(store) {
		// re-parse rewrite templates with the native parser, never re-entering this override
		template_options = options;
		template_options.parser_override_setting = AllowParserOverride::DEFAULT_OVERRIDE;
	}

	void RewriteStatement(SQLStatement &stmt) {
		switch (stmt.type) {
		case StatementType::SELECT_STATEMENT:
			RewriteQueryNode(*stmt.Cast<SelectStatement>().node);
			break;
		case StatementType::INSERT_STATEMENT:
			RewriteQueryNode(*stmt.Cast<InsertStatement>().node);
			break;
		case StatementType::UPDATE_STATEMENT:
			RewriteQueryNode(*stmt.Cast<UpdateStatement>().node);
			break;
		case StatementType::DELETE_STATEMENT:
			RewriteQueryNode(*stmt.Cast<DeleteStatement>().node);
			break;
		case StatementType::MERGE_INTO_STATEMENT:
			RewriteQueryNode(*stmt.Cast<MergeIntoStatement>().node);
			break;
		case StatementType::EXPLAIN_STATEMENT:
			RewriteStatement(*stmt.Cast<ExplainStatement>().stmt);
			break;
		default:
			Deny("statement type " + StatementTypeToString(stmt.type) + " is not permitted under ACL");
		}
	}

private:
	//===------------------------------------------------------------------===//
	// Query nodes
	//===------------------------------------------------------------------===//
	void RewriteQueryNode(QueryNode &node) {
		// CTE names shadow catalog objects within this node and its descendants (scoped)
		auto saved_scope = cte_scope;
		for (auto &entry : node.cte_map.map) {
			cte_scope.insert(entry.first.GetIdentifierName());
		}
		for (auto &entry : node.cte_map.map) {
			if (entry.second->query_node) {
				RewriteQueryNode(*entry.second->query_node);
			}
		}
		ParsedExpressionIterator::EnumerateQueryNodeModifiers(
		    node, [&](unique_ptr<ParsedExpression> &child) { RewriteExpr(child); });

		switch (node.type) {
		case QueryNodeType::SELECT_NODE:
			RewriteSelectNode(node.Cast<SelectNode>());
			break;
		case QueryNodeType::SET_OPERATION_NODE:
			for (auto &child : node.Cast<SetOperationNode>().children) {
				RewriteQueryNode(*child);
			}
			break;
		case QueryNodeType::CTE_NODE: {
			auto &cte = node.Cast<CTENode>();
			if (cte.query) {
				RewriteQueryNode(*cte.query);
			}
			if (cte.child) {
				RewriteQueryNode(*cte.child);
			}
			break;
		}
		case QueryNodeType::RECURSIVE_CTE_NODE: {
			auto &rcte = node.Cast<RecursiveCTENode>();
			cte_scope.insert(rcte.ctename.GetIdentifierName());
			if (rcte.left) {
				RewriteQueryNode(*rcte.left);
			}
			if (rcte.right) {
				RewriteQueryNode(*rcte.right);
			}
			break;
		}
		case QueryNodeType::INSERT_QUERY_NODE:
			RewriteInsertNode(node.Cast<InsertQueryNode>());
			break;
		case QueryNodeType::UPDATE_QUERY_NODE:
			RewriteUpdateNode(node.Cast<UpdateQueryNode>());
			break;
		case QueryNodeType::DELETE_QUERY_NODE:
			RewriteDeleteNode(node.Cast<DeleteQueryNode>());
			break;
		case QueryNodeType::MERGE_QUERY_NODE:
			RewriteMergeNode(node.Cast<MergeQueryNode>());
			break;
		default:
			Deny("query node type is not permitted under ACL");
		}
		cte_scope = saved_scope;
	}

	void RewriteSelectNode(SelectNode &node) {
		RewriteTableRef(node.from_table);
		for (auto &item : node.select_list) {
			RewriteExpr(item);
		}
		RewriteExpr(node.where_clause);
		RewriteExpr(node.having);
		RewriteExpr(node.qualify);
		for (auto &group : node.groups.group_expressions) {
			RewriteExpr(group);
		}
	}

	void RewriteInsertNode(InsertQueryNode &node) {
		ResolveDmlTarget(node.table_ref, node.qualified_name, "insert");
		if (node.select_statement && node.select_statement->node) {
			RewriteQueryNode(*node.select_statement->node);
		}
		for (auto &item : node.returning_list) {
			RewriteExpr(item);
		}
	}

	void RewriteUpdateNode(UpdateQueryNode &node) {
		ResolveDmlTarget(node.table, "update");
		RewriteTableRef(node.from_table);
		if (node.set_info) {
			for (auto &expr : node.set_info->expressions) {
				RewriteExpr(expr);
			}
			RewriteExpr(node.set_info->condition);
		}
		for (auto &item : node.returning_list) {
			RewriteExpr(item);
		}
	}

	void RewriteDeleteNode(DeleteQueryNode &node) {
		ResolveDmlTarget(node.table, "delete");
		for (auto &using_ref : node.using_clauses) {
			RewriteTableRef(using_ref);
		}
		RewriteExpr(node.condition);
		for (auto &item : node.returning_list) {
			RewriteExpr(item);
		}
	}

	void RewriteMergeNode(MergeQueryNode &node) {
		ResolveDmlTarget(node.target, "merge");
		RewriteTableRef(node.source);
		RewriteExpr(node.join_condition);
		for (auto &action_set : node.actions) {
			for (auto &action : action_set.second) {
				RewriteExpr(action->condition);
				if (action->update_info) {
					for (auto &expr : action->update_info->expressions) {
						RewriteExpr(expr);
					}
					RewriteExpr(action->update_info->condition);
				}
				for (auto &expr : action->expressions) {
					RewriteExpr(expr);
				}
			}
		}
		for (auto &item : node.returning_list) {
			RewriteExpr(item);
		}
	}

	//===------------------------------------------------------------------===//
	// Table refs
	//===------------------------------------------------------------------===//
	void RewriteTableRef(unique_ptr<TableRef> &ref) {
		if (!ref) {
			return;
		}
		switch (ref->type) {
		case TableReferenceType::BASE_TABLE: {
			auto &base = ref->Cast<BaseTableRef>();
			if (IsCteName(base)) {
				return; // a CTE reference, not a catalog object
			}
			auto key = VirtualKey(base.GetQualifiedName());
			TablePolicy policy;
			if (!store.ResolveTable(principal, key, policy)) {
				Deny("no access to object \"" + key + "\"");
			}
			if (policy.subquery_form) {
				ref = BuildTableSubquery(base.Table().GetIdentifierName(), policy, base);
			} else {
				// RENAME: swap the name for its physical target in place; it stays a real (writable) table.
				// Keep the virtual name as an alias so qualified references (vname.col) still resolve.
				auto virtual_name = base.Table();
				base.SetQualifiedName(ParsePhysName(policy.phys));
				if (base.alias.empty()) {
					base.alias = virtual_name;
				}
			}
			break;
		}
		case TableReferenceType::SUBQUERY: {
			auto &sub = ref->Cast<SubqueryRef>();
			if (sub.subquery && sub.subquery->node) {
				RewriteQueryNode(*sub.subquery->node);
			}
			break;
		}
		case TableReferenceType::JOIN: {
			auto &join = ref->Cast<JoinRef>();
			RewriteTableRef(join.left);
			RewriteTableRef(join.right);
			RewriteExpr(join.condition);
			break;
		}
		case TableReferenceType::TABLE_FUNCTION:
			RewriteTableFunction(ref);
			break;
		case TableReferenceType::EMPTY_FROM:
		case TableReferenceType::EXPRESSION_LIST:
			break;
		default:
			Deny("table reference form is not permitted under ACL");
		}
	}

	//! A FROM-position table function. If it is a virtual table function for this role, expand it
	//! (RENAME-alias or SUBQUERY-macro with argument substitution); otherwise route it through the
	//! resolver seam (default-deny readers). Arguments are rewritten first so nested virtual names resolve.
	void RewriteTableFunction(unique_ptr<TableRef> &ref) {
		auto &tf = ref->Cast<TableFunctionRef>();
		if (!tf.function || tf.function->GetExpressionClass() != ExpressionClass::FUNCTION) {
			Deny("unsupported table function form");
		}
		auto &function = tf.function->Cast<FunctionExpression>();
		auto vname = function.FunctionName().GetIdentifierName();

		TablePolicy policy;
		if (store.ResolveTableFunction(principal, vname, policy)) {
			RewriteFunctionArgs(function); // resolve virtual names inside the call arguments first
			if (policy.subquery_form) {
				ref = BuildFunctionSubquery(vname, policy, function, tf);
			} else {
				// RENAME-alias: retarget the call to a physical/system function, keep the arguments
				function.SetQualifiedName(ParsePhysName(policy.phys));
			}
			return;
		}
		// not a virtual table function: gate by name, then rewrite arguments and any subquery argument
		if (!store.FunctionAllowed(function.GetQualifiedName())) {
			Deny("table function \"" + vname + "\" is not allowed");
		}
		RewriteFunctionArgs(function);
		if (tf.subquery && tf.subquery->node) {
			RewriteQueryNode(*tf.subquery->node);
		}
	}

	//! Rewrite each argument expression of a function call (without re-gating the function itself)
	void RewriteFunctionArgs(FunctionExpression &function) {
		for (auto &arg : function.GetArgumentsMutable()) {
			RewriteExpr(arg.GetExpressionMutable());
		}
	}

	//! Expand a virtual table function `vfunc(args)` into `(SELECT ... ) AS vfunc`: the template's
	//! acl_arg(n) markers are replaced by the call arguments' AST, claims are baked, result is read-only.
	unique_ptr<TableRef> BuildFunctionSubquery(const string &vname, const TablePolicy &policy,
	                                           FunctionExpression &function, TableFunctionRef &tf) {
		if (policy.query.empty()) {
			Deny("virtual table function \"" + vname + "\" has no template");
		}
		auto select_stmt = store.InstantiateSelect(policy.query, template_options);
		vector<unique_ptr<ParsedExpression>> args;
		for (auto &arg : function.GetArgumentsMutable()) {
			args.push_back(std::move(arg.GetExpressionMutable()));
		}
		BakeMarkersInNode(*select_stmt->node, &args);

		Identifier alias = tf.alias.empty() ? Identifier(vname) : tf.alias;
		auto sub = make_uniq<SubqueryRef>(std::move(select_stmt), alias);
		sub->column_name_alias = std::move(tf.column_name_alias);
		return std::move(sub);
	}

	bool IsCteName(BaseTableRef &base) {
		auto &name = base.GetQualifiedName();
		if (!name.Catalog().empty() || !name.Schema().empty()) {
			return false; // a qualified name never refers to a CTE
		}
		return cte_scope.count(base.Table().GetIdentifierName()) > 0;
	}

	//! Replace a virtual relation with a subquery: a view uses its full `query`, a table is assembled
	//! as `(SELECT <projection> FROM <phys> [WHERE <rls>]) AS <alias>`. Claim values are baked in.
	unique_ptr<TableRef> BuildTableSubquery(const string &vname, const TablePolicy &policy, BaseTableRef &original) {
		string sql;
		if (!policy.query.empty()) {
			sql = policy.query; // a view: its SQL is the definition
		} else {
			if (policy.projection.empty()) {
				Deny("object \"" + vname + "\" exposes no readable columns");
			}
			sql = "SELECT " + StringUtil::Join(policy.projection, ", ") + " FROM " + policy.phys;
			if (!policy.rls.empty()) {
				sql += " WHERE " + policy.rls;
			}
		}
		auto select_stmt = store.InstantiateSelect(sql, template_options);
		BakeMarkersInNode(*select_stmt->node, nullptr);

		Identifier alias = original.alias.empty() ? Identifier(vname) : original.alias;
		auto sub = make_uniq<SubqueryRef>(std::move(select_stmt), alias);
		sub->column_name_alias = std::move(original.column_name_alias);
		sub->sample = std::move(original.sample);
		return std::move(sub);
	}

	//! Resolve a DML target in place (name -> physical), enforcing the required capability
	void ResolveDmlTarget(unique_ptr<TableRef> &target, const string &capability) {
		if (!target || target->type != TableReferenceType::BASE_TABLE) {
			return;
		}
		auto &base = target->Cast<BaseTableRef>();
		QualifiedName ignored;
		ResolveDmlTarget(target, base.GetQualifiedNameMutable(), capability);
	}

	void ResolveDmlTarget(unique_ptr<TableRef> &target_ref, QualifiedName &target_name, const string &capability) {
		string key;
		if (target_ref && target_ref->type == TableReferenceType::BASE_TABLE) {
			key = VirtualKey(target_ref->Cast<BaseTableRef>().GetQualifiedName());
		} else {
			key = VirtualKey(target_name);
		}
		TablePolicy policy;
		if (!store.ResolveTable(principal, key, policy)) {
			Deny("no access to object \"" + key + "\"");
		}
		// only RENAME relations are writable; a SUBQUERY relation (view / masked / RLS) is read-only
		if (policy.subquery_form) {
			Deny(capability + " into read-only relation \"" + key + "\" is not allowed");
		}
		if (!policy.caps.count(capability)) {
			Deny(capability + " on \"" + key + "\" is not allowed");
		}
		auto phys = ParsePhysName(policy.phys);
		if (target_ref && target_ref->type == TableReferenceType::BASE_TABLE) {
			target_ref->Cast<BaseTableRef>().SetQualifiedName(phys);
		}
		target_name = phys;
	}

	//===------------------------------------------------------------------===//
	// Expressions + claim baking
	//===------------------------------------------------------------------===//
	void RewriteExpr(unique_ptr<ParsedExpression> &expr) {
		if (!expr) {
			return;
		}
		if (expr->GetExpressionClass() == ExpressionClass::SUBQUERY) {
			auto &subquery = expr->Cast<SubqueryExpression>();
			if (subquery.SubqueryMutable() && subquery.SubqueryMutable()->node) {
				RewriteQueryNode(*subquery.SubqueryMutable()->node);
			}
		}
		if (expr->GetExpressionClass() == ExpressionClass::FUNCTION) {
			auto &function = expr->Cast<FunctionExpression>();
			auto name = function.FunctionName().GetIdentifierName();
			// a virtual scalar function for this role: expand it (expr-macro) or retarget it (alias)
			TablePolicy spolicy;
			if (store.ResolveScalarFunction(principal, name, spolicy)) {
				RewriteFunctionArgs(function); // resolve virtual names inside the arguments first
				if (spolicy.subquery_form) {
					expr = BuildScalarExpr(name, spolicy, function);
				} else {
					function.SetQualifiedName(ParsePhysName(spolicy.phys));
				}
				return; // handled: do not re-gate or re-recurse
			}
			// otherwise route it through the resolver seam (default-allow, deny readers)
			if (!store.FunctionAllowed(function.GetQualifiedName())) {
				Deny("function \"" + name + "\" is not allowed");
			}
		}
		ParsedExpressionIterator::EnumerateChildren(*expr,
		                                            [&](unique_ptr<ParsedExpression> &child) { RewriteExpr(child); });
	}

	//! Expand a virtual scalar function `vfunc(args)` into its template expression, substituting the
	//! call arguments via acl_arg(n) markers and baking claims via acl_claim.
	unique_ptr<ParsedExpression> BuildScalarExpr(const string &vname, const TablePolicy &policy,
	                                             FunctionExpression &function) {
		if (policy.query.empty()) {
			Deny("virtual scalar function \"" + vname + "\" has no template");
		}
		auto replacement = store.InstantiateExpr(policy.query, template_options);
		vector<unique_ptr<ParsedExpression>> args;
		for (auto &arg : function.GetArgumentsMutable()) {
			args.push_back(std::move(arg.GetExpressionMutable()));
		}
		BakeMarkers(replacement, &args);
		return replacement;
	}

	//! Replace template markers in a node's expressions: acl_claim('<name>') -> baked constant, and (for
	//! a table-function macro) acl_arg(<n>) -> the n-th call argument's AST. `args` is null for relations.
	void BakeMarkersInNode(QueryNode &node, const vector<unique_ptr<ParsedExpression>> *args) {
		if (node.type != QueryNodeType::SELECT_NODE) {
			return; // rewrite templates are always plain SELECTs
		}
		auto &select = node.Cast<SelectNode>();
		for (auto &item : select.select_list) {
			BakeMarkers(item, args);
		}
		BakeMarkers(select.where_clause, args);
		BakeMarkers(select.having, args);
		BakeMarkers(select.qualify, args);
	}

	void BakeMarkers(unique_ptr<ParsedExpression> &expr, const vector<unique_ptr<ParsedExpression>> *args) {
		if (!expr) {
			return;
		}
		if (expr->GetExpressionClass() == ExpressionClass::FUNCTION) {
			auto &function = expr->Cast<FunctionExpression>();
			auto marker = StringUtil::Lower(function.FunctionName().GetIdentifierName());
			if (marker == "acl_claim") {
				expr = make_uniq<ConstantExpression>(ClaimValue(function));
				return; // replaced whole node; nothing below to recurse into
			}
			if (marker == "acl_arg") {
				expr = ArgExpression(function, args);
				return;
			}
		}
		ParsedExpressionIterator::EnumerateChildren(
		    *expr, [&](unique_ptr<ParsedExpression> &child) { BakeMarkers(child, args); });
	}

	//! Resolve acl_arg(<n>) to a copy of the n-th (1-based) table-function call argument
	unique_ptr<ParsedExpression> ArgExpression(FunctionExpression &function,
	                                           const vector<unique_ptr<ParsedExpression>> *args) {
		if (!args) {
			Deny("acl_arg() is only valid inside a table-function template");
		}
		auto &call_args = function.GetArguments();
		if (call_args.size() != 1 || call_args[0].GetExpression().GetExpressionClass() != ExpressionClass::CONSTANT) {
			Deny("acl_arg() expects a single constant position");
		}
		int64_t position = call_args[0].GetExpression().Cast<ConstantExpression>().GetValue().GetValue<int64_t>();
		if (position < 1 || static_cast<idx_t>(position) > args->size() || !(*args)[position - 1]) {
			Deny("acl_arg(" + std::to_string(position) + ") has no matching call argument");
		}
		return (*args)[position - 1]->Copy();
	}

	Value ClaimValue(FunctionExpression &function) {
		auto &args = function.GetArguments();
		if (args.size() != 1 || args[0].GetExpression().GetExpressionClass() != ExpressionClass::CONSTANT) {
			Deny("acl_claim() expects a single constant claim name");
		}
		auto claim_name = args[0].GetExpression().Cast<ConstantExpression>().GetValue().ToString();
		auto entry = principal.claims.find(claim_name);
		if (entry == principal.claims.end()) {
			return Value(LogicalType::VARCHAR); // absent claim -> NULL (fail closed)
		}
		return Value(entry->second);
	}

private:
	const Principal &principal;
	PolicyStore &store;
	ParserOptions template_options;
	case_insensitive_set_t cte_scope;
};

//===--------------------------------------------------------------------===//
// Prefix parsing + parser_override entry point
//===--------------------------------------------------------------------===//

struct AclPrefix {
	enum class Kind { NONE, ROLE, TOKEN, ADMIN };
	Kind kind = Kind::NONE;
	string value;
	string rest;
};

bool IsWordChar(char c) {
	return StringUtil::CharacterIsAlpha(c) || StringUtil::CharacterIsDigit(c) || c == '_';
}

string ReadWord(const string &query, idx_t &pos) {
	auto start = pos;
	while (pos < query.size() && IsWordChar(query[pos])) {
		pos++;
	}
	return query.substr(start, pos - start);
}

void SkipWhitespace(const string &query, idx_t &pos) {
	while (pos < query.size() && StringUtil::CharacterIsSpace(query[pos])) {
		pos++;
	}
}

//! Read a single-quoted or double-quoted literal, honoring the doubled-quote escape
string ReadQuoted(const string &query, idx_t &pos) {
	char quote = query[pos++];
	string value;
	while (pos < query.size()) {
		if (query[pos] == quote) {
			if (pos + 1 < query.size() && query[pos + 1] == quote) {
				value += quote;
				pos += 2;
				continue;
			}
			pos++;
			return value;
		}
		value += query[pos++];
	}
	throw ParserException("acl_rewrite: unterminated quoted value after ACL prefix");
}

AclPrefix ParseAclPrefix(const string &query) {
	AclPrefix prefix;
	idx_t pos = 0;
	SkipWhitespace(query, pos);
	auto keyword = ReadWord(query, pos);
	if (!StringUtil::CIEquals(keyword, "acl")) {
		return prefix; // not our syntax
	}
	SkipWhitespace(query, pos);
	auto mode = ReadWord(query, pos);
	if (StringUtil::CIEquals(mode, "admin")) {
		prefix.kind = AclPrefix::Kind::ADMIN;
		prefix.rest = query.substr(pos);
		return prefix;
	}
	bool is_role = StringUtil::CIEquals(mode, "role");
	bool is_token = StringUtil::CIEquals(mode, "token");
	if (!is_role && !is_token) {
		return prefix; // "ACL <unknown>" -> leave for the native parser (NONE)
	}
	SkipWhitespace(query, pos);
	if (pos >= query.size() || (query[pos] != '\'' && query[pos] != '"')) {
		throw ParserException("acl_rewrite: ACL %s requires a quoted value", mode);
	}
	prefix.kind = is_role ? AclPrefix::Kind::ROLE : AclPrefix::Kind::TOKEN;
	prefix.value = ReadQuoted(query, pos);
	prefix.rest = query.substr(pos);
	return prefix;
}

ParserOverrideResult AclParserOverride(ParserExtensionInfo *info, const string &query, ParserOptions &options) {
	auto prefix = ParseAclPrefix(query);
	if (prefix.kind == AclPrefix::Kind::NONE) {
		return ParserOverrideResult(); // fall through to the native parser
	}

	// re-parse the remainder with the native parser (never re-entering this override)
	ParserOptions inner = options;
	inner.parser_override_setting = AllowParserOverride::DEFAULT_OVERRIDE;
	Parser parser(inner);
	parser.ParseQuery(prefix.rest);

	if (prefix.kind == AclPrefix::Kind::ADMIN) {
		return ParserOverrideResult(std::move(parser.statements)); // passthrough, no rewrite
	}

	auto &store = *info->Cast<AclParserInfo>().store;
	Principal principal;
	bool is_token = prefix.kind == AclPrefix::Kind::TOKEN;
	if (!store.VerifyPrincipal(is_token, prefix.value, principal)) {
		throw BinderException("acl_rewrite: %s verification failed", is_token ? "token" : "role");
	}

	AclRewriter rewriter(principal, options, store);
	for (auto &stmt : parser.statements) {
		rewriter.RewriteStatement(*stmt);
	}
	return ParserOverrideResult(std::move(parser.statements));
}

//===--------------------------------------------------------------------===//
// Admin setup functions (register stub policy)
//===--------------------------------------------------------------------===//

//! acl_grant_table(role, vname, phys, cols_csv, rls, caps_csv): register a virtual-table policy.
//! cols_csv items are `name` or `name=expr` (expr masks/renames as `expr AS name`); denied columns
//! are simply omitted. caps_csv is a comma list of {select,insert,update,delete,merge}.
void AclGrantTableFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t row = 0; row < args.size(); row++) {
		auto role = args.GetValue(0, row);
		auto vname = args.GetValue(1, row);
		auto phys = args.GetValue(2, row);
		if (role.IsNull() || vname.IsNull() || phys.IsNull()) {
			throw InvalidInputException("acl_grant_table: role, name and phys must not be NULL");
		}
		TablePolicy policy;
		policy.phys = phys.ToString();
		auto cols = args.GetValue(3, row);
		for (auto &item : SplitCsv(cols.IsNull() ? string() : cols.ToString())) {
			auto pos = item.find('=');
			if (pos == string::npos) {
				policy.projection.push_back(item);
			} else {
				auto name = Trimmed(item.substr(0, pos));
				auto expr = Trimmed(item.substr(pos + 1));
				policy.projection.push_back(expr + " AS " + name);
			}
		}
		auto rls = args.GetValue(4, row);
		policy.rls = rls.IsNull() ? string() : rls.ToString();
		// no projection and no RLS: expose the physical table as-is via RENAME (writable); otherwise a
		// read-only SUBQUERY (masking / computed columns / RLS need a wrapping subquery)
		policy.subquery_form = !policy.projection.empty() || !policy.rls.empty();
		auto caps = args.GetValue(5, row);
		auto cap_list = SplitCsv(caps.IsNull() ? string("select") : caps.ToString());
		if (cap_list.empty()) {
			cap_list.push_back("select");
		}
		for (auto &cap : cap_list) {
			policy.caps.insert(StringUtil::Lower(cap));
		}
		auto &store = StoreOf(state);
		lock_guard<mutex> guard(store.lock);
		store.tables[role.ToString()][vname.ToString()] = std::move(policy);
	}
	result.Reference(Value::BOOLEAN(true), count_t(args.size()));
}

//! acl_grant_view(role, vname, select_sql): map a virtual name to a view (its SQL is the definition).
//! The SQL may contain acl_claim('<name>') markers; they are baked to constants at rewrite time.
void AclGrantViewFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t row = 0; row < args.size(); row++) {
		auto role = args.GetValue(0, row);
		auto vname = args.GetValue(1, row);
		auto sql = args.GetValue(2, row);
		if (role.IsNull() || vname.IsNull() || sql.IsNull()) {
			throw InvalidInputException("acl_grant_view: role, name and SQL must not be NULL");
		}
		TablePolicy policy;
		policy.subquery_form = true; // a view is always a read-only SUBQUERY
		policy.query = sql.ToString();
		policy.caps.insert("select");
		auto &store = StoreOf(state);
		lock_guard<mutex> guard(store.lock);
		store.tables[role.ToString()][vname.ToString()] = std::move(policy);
	}
	result.Reference(Value::BOOLEAN(true), count_t(args.size()));
}

//! acl_grant_table_function(role, vname, sql_template): a virtual table function whose SQL is expanded
//! as a read-only subquery. The template refers to call arguments as acl_arg(1), acl_arg(2), ... and
//! may carry RLS via acl_claim('<name>').
void AclGrantTableFunctionFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t row = 0; row < args.size(); row++) {
		auto role = args.GetValue(0, row);
		auto vname = args.GetValue(1, row);
		auto sql = args.GetValue(2, row);
		if (role.IsNull() || vname.IsNull() || sql.IsNull()) {
			throw InvalidInputException("acl_grant_table_function: role, name and SQL must not be NULL");
		}
		TablePolicy policy;
		policy.subquery_form = true;
		policy.query = sql.ToString();
		policy.caps.insert("select");
		auto &store = StoreOf(state);
		lock_guard<mutex> guard(store.lock);
		store.table_functions[role.ToString()][vname.ToString()] = std::move(policy);
	}
	result.Reference(Value::BOOLEAN(true), count_t(args.size()));
}

//! acl_grant_table_function_alias(role, vname, phys_function): a virtual table function that is just an
//! alias of a physical/system table function; the call is retargeted in place, arguments kept as-is.
void AclGrantTableFunctionAliasFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t row = 0; row < args.size(); row++) {
		auto role = args.GetValue(0, row);
		auto vname = args.GetValue(1, row);
		auto phys = args.GetValue(2, row);
		if (role.IsNull() || vname.IsNull() || phys.IsNull()) {
			throw InvalidInputException("acl_grant_table_function_alias: role, name and phys must not be NULL");
		}
		TablePolicy policy;
		policy.subquery_form = false;
		policy.phys = phys.ToString();
		auto &store = StoreOf(state);
		lock_guard<mutex> guard(store.lock);
		store.table_functions[role.ToString()][vname.ToString()] = std::move(policy);
	}
	result.Reference(Value::BOOLEAN(true), count_t(args.size()));
}

//! acl_grant_scalar(role, vname, expr_template): a virtual scalar function replaced by an expression.
//! The template refers to call arguments as acl_arg(1), acl_arg(2), ... and may use acl_claim('<name>').
void AclGrantScalarFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t row = 0; row < args.size(); row++) {
		auto role = args.GetValue(0, row);
		auto vname = args.GetValue(1, row);
		auto expr = args.GetValue(2, row);
		if (role.IsNull() || vname.IsNull() || expr.IsNull()) {
			throw InvalidInputException("acl_grant_scalar: role, name and expression must not be NULL");
		}
		TablePolicy policy;
		policy.subquery_form = true;
		policy.query = expr.ToString();
		auto &store = StoreOf(state);
		lock_guard<mutex> guard(store.lock);
		store.scalar_functions[role.ToString()][vname.ToString()] = std::move(policy);
	}
	result.Reference(Value::BOOLEAN(true), count_t(args.size()));
}

//! acl_grant_scalar_alias(role, vname, phys_function): a virtual scalar function that is just an alias
//! of a physical/system scalar function; the call is retargeted in place, arguments kept as-is.
void AclGrantScalarAliasFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t row = 0; row < args.size(); row++) {
		auto role = args.GetValue(0, row);
		auto vname = args.GetValue(1, row);
		auto phys = args.GetValue(2, row);
		if (role.IsNull() || vname.IsNull() || phys.IsNull()) {
			throw InvalidInputException("acl_grant_scalar_alias: role, name and phys must not be NULL");
		}
		TablePolicy policy;
		policy.subquery_form = false;
		policy.phys = phys.ToString();
		auto &store = StoreOf(state);
		lock_guard<mutex> guard(store.lock);
		store.scalar_functions[role.ToString()][vname.ToString()] = std::move(policy);
	}
	result.Reference(Value::BOOLEAN(true), count_t(args.size()));
}

//! acl_deny_function(fname): add a function (scalar or table) to the gateway-wide denylist
void AclDenyFunctionFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t row = 0; row < args.size(); row++) {
		auto fname = args.GetValue(0, row);
		if (fname.IsNull()) {
			throw InvalidInputException("acl_deny_function: name must not be NULL");
		}
		auto &store = StoreOf(state);
		lock_guard<mutex> guard(store.lock);
		store.denied_functions.insert(fname.ToString());
	}
	result.Reference(Value::BOOLEAN(true), count_t(args.size()));
}

//! acl_allow_function(fname): remove a function from the denylist (e.g. to un-deny a default)
void AclAllowFunctionFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t row = 0; row < args.size(); row++) {
		auto fname = args.GetValue(0, row);
		if (fname.IsNull()) {
			throw InvalidInputException("acl_allow_function: name must not be NULL");
		}
		auto &store = StoreOf(state);
		lock_guard<mutex> guard(store.lock);
		store.denied_functions.erase(fname.ToString());
	}
	result.Reference(Value::BOOLEAN(true), count_t(args.size()));
}

//! acl_define_token(token, role, claims_csv): bind a token to a principal (role + claims)
void AclDefineTokenFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t row = 0; row < args.size(); row++) {
		auto token = args.GetValue(0, row);
		auto role = args.GetValue(1, row);
		if (token.IsNull() || role.IsNull()) {
			throw InvalidInputException("acl_define_token: token and role must not be NULL");
		}
		Principal principal;
		principal.role = role.ToString();
		auto claims = args.GetValue(2, row);
		principal.claims = ParseClaims(claims.IsNull() ? string() : claims.ToString());
		auto &store = StoreOf(state);
		lock_guard<mutex> guard(store.lock);
		store.tokens[token.ToString()] = std::move(principal);
	}
	result.Reference(Value::BOOLEAN(true), count_t(args.size()));
}

//! acl_define_role(role, claims_csv): default claims carried by the bare ROLE form
void AclDefineRoleFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t row = 0; row < args.size(); row++) {
		auto role = args.GetValue(0, row);
		if (role.IsNull()) {
			throw InvalidInputException("acl_define_role: role must not be NULL");
		}
		auto claims = args.GetValue(1, row);
		auto &store = StoreOf(state);
		lock_guard<mutex> guard(store.lock);
		store.role_claims[role.ToString()] = ParseClaims(claims.IsNull() ? string() : claims.ToString());
	}
	result.Reference(Value::BOOLEAN(true), count_t(args.size()));
}

void LoadInternal(ExtensionLoader &loader) {
	auto &db = loader.GetDatabaseInstance();
	auto &config = DBConfig::GetConfig(db);

	// one policy store per database instance, shared by the parser override and the admin functions
	auto store = make_shared_ptr<PolicyStore>();

	ParserExtension extension;
	extension.parser_override = AclParserOverride;
	extension.parser_info = make_shared_ptr<AclParserInfo>(store);
	ParserExtension::Register(config, extension);

	// register an admin setup function, attaching the shared store via its function_info
	auto register_admin = [&](const string &name, vector<LogicalType> arguments, scalar_function_t fn) {
		ScalarFunction function(Identifier(name), std::move(arguments), LogicalType::BOOLEAN, fn);
		function.SetExtraFunctionInfo(make_shared_ptr<AclScalarInfo>(store));
		loader.RegisterFunction(function);
	};

	const LogicalType &v = LogicalType::VARCHAR;
	register_admin("acl_grant_table", {v, v, v, v, v, v}, AclGrantTableFunc);
	register_admin("acl_grant_view", {v, v, v}, AclGrantViewFunc);
	register_admin("acl_grant_table_function", {v, v, v}, AclGrantTableFunctionFunc);
	register_admin("acl_grant_table_function_alias", {v, v, v}, AclGrantTableFunctionAliasFunc);
	register_admin("acl_grant_scalar", {v, v, v}, AclGrantScalarFunc);
	register_admin("acl_grant_scalar_alias", {v, v, v}, AclGrantScalarAliasFunc);
	register_admin("acl_deny_function", {v}, AclDenyFunctionFunc);
	register_admin("acl_allow_function", {v}, AclAllowFunctionFunc);
	register_admin("acl_define_token", {v, v, v}, AclDefineTokenFunc);
	register_admin("acl_define_role", {v, v}, AclDefineRoleFunc);
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
