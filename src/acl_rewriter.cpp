#include "acl_rewriter.hpp"

#include "duckdb/common/exception/binder_exception.hpp"
#include "duckdb/common/helper.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/parser/expression/constant_expression.hpp"
#include "duckdb/parser/expression/function_expression.hpp"
#include "duckdb/parser/expression/subquery_expression.hpp"
#include "duckdb/parser/parsed_expression_iterator.hpp"
#include "duckdb/parser/parser.hpp"
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

namespace duckdb {
namespace acl {
namespace {

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
			// the read path needs the 'select' capability, just like DML paths need theirs (spec 003):
			// a write-only grant (e.g. an audit/ingest table) must not leak reads through either form
			if (!policy.caps.count("select")) {
				Deny("select on \"" + key + "\" is not allowed");
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
		if (!store.FunctionAllowed(principal, function.GetQualifiedName())) {
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
			if (!store.FunctionAllowed(principal, function.GetQualifiedName())) {
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

} // namespace

namespace {

//! Replace acl_claim('…') / acl_arg(n) with NULL constants so the template binds without a
//! principal. An acl_arg NULL is TYPED from the declared signature when there is one: an untyped
//! NULL binds to the wrong type whenever the result depends on the argument.
void BakeNullMarkers(unique_ptr<ParsedExpression> &expr, const vector<string> &param_types,
                     const ParserOptions &options) {
	if (!expr) {
		return;
	}
	if (expr->GetExpressionClass() == ExpressionClass::FUNCTION) {
		auto &function = expr->Cast<FunctionExpression>();
		auto marker = StringUtil::Lower(function.FunctionName().GetIdentifierName());
		if (marker == "acl_claim" || marker == "acl_arg") {
			string type;
			if (marker == "acl_arg") {
				auto &args = function.GetArguments();
				if (args.size() == 1 && args[0].GetExpression().GetExpressionClass() == ExpressionClass::CONSTANT) {
					auto position = args[0].GetExpression().Cast<ConstantExpression>().GetValue().GetValue<int64_t>();
					if (position >= 1 && static_cast<idx_t>(position) <= param_types.size()) {
						type = param_types[NumericCast<idx_t>(position - 1)];
					}
				}
			}
			if (type.empty()) {
				expr = make_uniq<ConstantExpression>(Value(LogicalType::VARCHAR));
			} else {
				// parse the cast rather than resolving the type name by hand (no context needed here)
				auto casted = Parser::ParseExpressionList("CAST(NULL AS " + type + ")", options);
				expr = std::move(casted[0]);
			}
			return;
		}
	}
	ParsedExpressionIterator::EnumerateChildren(
	    *expr, [&](unique_ptr<ParsedExpression> &child) { BakeNullMarkers(child, param_types, options); });
}

void BakeNullMarkersInNode(QueryNode &node, const vector<string> &param_types, const ParserOptions &options) {
	if (node.type != QueryNodeType::SELECT_NODE) {
		return;
	}
	auto &select = node.Cast<SelectNode>();
	for (auto &item : select.select_list) {
		BakeNullMarkers(item, param_types, options);
	}
	BakeNullMarkers(select.where_clause, param_types, options);
	BakeNullMarkers(select.having, param_types, options);
	BakeNullMarkers(select.qualify, param_types, options);
}

} // namespace

string BakeTemplateForProbe(const string &sql, const ParserOptions &options, bool expression,
                            const vector<string> &param_types) {
	ParserOptions inner = options;
	inner.parser_override_setting = AllowParserOverride::DEFAULT_OVERRIDE;
	if (expression) {
		auto expressions = Parser::ParseExpressionList(sql, inner);
		if (expressions.size() != 1) {
			throw BinderException("acl_rewrite: scalar template must be a single expression");
		}
		BakeNullMarkers(expressions[0], param_types, inner);
		return expressions[0]->ToString();
	}
	Parser parser(inner);
	parser.ParseQuery(sql);
	if (parser.statements.size() != 1 || parser.statements[0]->type != StatementType::SELECT_STATEMENT) {
		throw BinderException("acl_rewrite: rewrite template is not a single SELECT");
	}
	auto &statement = parser.statements[0]->Cast<SelectStatement>();
	BakeNullMarkersInNode(*statement.node, param_types, inner);
	return statement.node->ToString();
}

void RewriteStatements(vector<unique_ptr<SQLStatement>> &statements, const Principal &principal,
                       const ParserOptions &options, PolicyStore &store) {
	AclRewriter rewriter(principal, options, store);
	for (auto &stmt : statements) {
		rewriter.RewriteStatement(*stmt);
	}
}

} // namespace acl
} // namespace duckdb
