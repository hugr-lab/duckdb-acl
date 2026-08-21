#include "acl_rewriter.hpp"

#include "duckdb/common/exception/binder_exception.hpp"
#include "duckdb/common/helper.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/parser/expression/case_expression.hpp"
#include "duckdb/parser/expression/columnref_expression.hpp"
#include "duckdb/parser/expression/conjunction_expression.hpp"
#include "duckdb/parser/expression/constant_expression.hpp"
#include "duckdb/parser/expression/function_expression.hpp"
#include "duckdb/parser/expression/star_expression.hpp"
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
#include "duckdb/parser/parsed_data/create_info.hpp"
#include "duckdb/parser/parsed_data/create_table_info.hpp"
#include "duckdb/parser/parsed_data/create_view_info.hpp"
#include "duckdb/parser/parsed_data/drop_info.hpp"
#include "duckdb/parser/statement/create_statement.hpp"
#include "duckdb/parser/statement/delete_statement.hpp"
#include "duckdb/parser/statement/drop_statement.hpp"
#include "duckdb/parser/statement/pragma_statement.hpp"
#include "duckdb/parser/statement/explain_statement.hpp"
#include "duckdb/parser/statement/insert_statement.hpp"
#include "duckdb/parser/statement/merge_into_statement.hpp"
#include "duckdb/parser/statement/select_statement.hpp"
#include "duckdb/parser/statement/update_statement.hpp"
#include "duckdb/parser/tableref/basetableref.hpp"
#include "duckdb/parser/tableref/emptytableref.hpp"
#include "duckdb/parser/tableref/joinref.hpp"
#include "duckdb/parser/tableref/showref.hpp"
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
		case StatementType::EXPLAIN_STATEMENT: {
			auto &explain = stmt.Cast<ExplainStatement>();
			RewriteStatement(*explain.stmt);
			if (replacement) {
				// the inner statement became a different one (a PRAGMA answered as a SELECT, spec 031):
				// the EXPLAIN keeps its place and explains what the principal actually runs
				explain.stmt = std::move(replacement);
			}
			break;
		}
		case StatementType::CREATE_STATEMENT:
			RewriteCreateStatement(stmt.Cast<CreateStatement>());
			break;
		case StatementType::DROP_STATEMENT:
			RewriteDropStatement(stmt.Cast<DropStatement>());
			break;
		case StatementType::PRAGMA_STATEMENT:
			RewritePragmaStatement(stmt.Cast<PragmaStatement>());
			break;
		case StatementType::TRANSACTION_STATEMENT:
			// BEGIN / COMMIT / ROLLBACK name no object and carry no expression, so there is nothing to
			// rewrite and nothing to gate: they are session control, not access. A client driver cannot
			// work without them - a quack client sends one before it reads anything - and refusing them
			// left a served connection unable to load its own catalog (spec 041).
			break;
		default:
			Deny("statement type " + StatementTypeToString(stmt.type) + " is not permitted under ACL");
		}
	}

	//! A PRAGMA that asks what is here is the question SHOW asks in an older spelling, and it is what a
	//! client sends before anything else (spec 031). The two that name the catalog are answered from the
	//! principal's own; every other PRAGMA stays denied, because a PRAGMA is otherwise a setting.
	void RewritePragmaStatement(PragmaStatement &stmt) {
		auto name = StringUtil::Lower(stmt.info->name.GetIdentifierName());
		string sql;
		if (name == "table_info") {
			if (stmt.info->parameters.size() != 1) {
				Deny("PRAGMA table_info needs exactly one table name");
			}
			// answered through DESCRIBE rather than through the column listing, so it goes down the
			// read path: a name the principal has no access to is refused, not answered with no rows
			sql = "SELECT CAST(row_number() OVER () - 1 AS INTEGER) AS cid, column_name AS name,"
			      " column_type AS type, \"null\" = 'NO' AS notnull, \"default\" AS dflt_value,"
			      " coalesce(key = 'PRI', false) AS pk FROM (DESCRIBE (SELECT * FROM " +
			      PragmaTargetName(*stmt.info->parameters[0]) + "))";
		} else if (name == "show_tables") {
			sql = "SELECT * FROM (SHOW TABLES)";
		} else {
			Deny("PRAGMA \"" + name + "\" is not permitted under ACL");
		}
		auto select_stmt = store.InstantiateSelect(sql, template_options);
		RewriteQueryNode(*select_stmt->node); // the DESCRIBE / SHOW inside is the principal's own
		replacement = std::move(select_stmt);
	}

	//! The table a `PRAGMA table_info(...)` names, requoted part by part so it splices into generated
	//! SQL as the name the principal wrote - `'vs.inner'` is a schema and a table, not one identifier.
	static string PragmaTargetName(const ParsedExpression &parameter) {
		string written;
		if (parameter.GetExpressionClass() == ExpressionClass::CONSTANT) {
			auto &value = parameter.Cast<ConstantExpression>().GetValue();
			if (!value.IsNull()) {
				written = value.ToString();
			}
		} else if (parameter.GetExpressionClass() == ExpressionClass::COLUMN_REF) {
			vector<string> parts;
			for (auto &part : parameter.Cast<ColumnRefExpression>().ColumnNames()) {
				parts.push_back(part.GetIdentifierName());
			}
			written = StringUtil::Join(parts, ".");
		}
		if (written.empty()) {
			throw BinderException("acl_rewrite: PRAGMA table_info needs a table name");
		}
		vector<string> quoted;
		for (auto &part : StringUtil::Split(written, '.')) {
			quoted.push_back("\"" + StringUtil::Replace(part, "\"", "\"\"") + "\"");
		}
		return StringUtil::Join(quoted, ".");
	}

	//! Statements the rewrite appends after the one being rewritten - the catalog record of an object
	//! a principal's DDL creates or drops. They run only if the DDL before them succeeded, so a failed
	//! CREATE never leaves a record behind (spec 016).
	vector<unique_ptr<SQLStatement>> follow_ups;
	//! Set when a statement is answered by a different one entirely - a PRAGMA rewritten into the
	//! SELECT that answers it (spec 031). The caller puts this in its place, so an enclosing EXPLAIN
	//! keeps explaining the statement the principal actually runs.
	unique_ptr<SQLStatement> replacement;
	//! Set when the statement itself must not run: VIRTUAL ONLY registers what exists, it never creates
	bool drop_statement = false;

private:
	//===------------------------------------------------------------------===//
	// DDL through the ACL (spec 016)
	//===------------------------------------------------------------------===//

	//! `SELECT acl_…(args)` as a statement of the batch. Built here, never written by a principal:
	//! every acl_* name is denied in a principal's own query (spec 009).
	unique_ptr<SQLStatement> AclCall(const string &function, vector<Value> arguments) {
		vector<unique_ptr<ParsedExpression>> children;
		for (auto &argument : arguments) {
			children.push_back(make_uniq<ConstantExpression>(std::move(argument)));
		}
		auto select = make_uniq<SelectNode>();
		select->select_list.push_back(make_uniq<FunctionExpression>(Identifier(function), std::move(children)));
		select->from_table = make_uniq<EmptyTableRef>();
		auto statement = make_uniq<SelectStatement>();
		statement->node = std::move(select);
		return std::move(statement);
	}

	void RewriteCreateStatement(CreateStatement &stmt) {
		if (!stmt.info) {
			Deny("unsupported CREATE form");
		}
		auto &info = *stmt.info;
		if (info.type == CatalogType::VIEW_ENTRY) {
			RewriteCreateView(stmt);
			return;
		}
		if (info.type != CatalogType::TABLE_ENTRY) {
			Deny("only tables and views can be created through the ACL");
		}
		if (info.temporary) {
			Deny("temporary objects are not available through the ACL yet");
		}
		// CREATE TABLE ... AS SELECT reads before it writes, and that read is a read like any other:
		// without this a role holding `create` could copy any physical table into its own schema
		auto &table_info = info.Cast<CreateTableInfo>();
		if (table_info.query && table_info.query->node) {
			RewriteQueryNode(*table_info.query->node);
		}
		auto key = VirtualKey(info.GetQualifiedName());
		DdlTarget target;
		if (!store.ResolveDdlTarget(principal, key, "create", target)) {
			Deny("no schema of the catalog allows creating \"" + key + "\"");
		}
		auto name = info.GetQualifiedName().Name();
		auto phys = target.phys_schema + "." + name.GetIdentifierName();
		if (target.virtual_only) {
			// the role registers what exists; it never materialises. The CREATE itself is dropped
			// from the batch, so nothing physical happens.
			drop_statement = true;
			follow_ups.push_back(
			    AclCall("acl_register_existing", {Value(target.vcat), Value(key), Value(phys), Value(target.origin)}));
			return;
		}
		info.SetQualifiedName(ParsePhysName(phys));
		if (target.needs_record) {
			// an expansion shows only its own records, so the new object needs one - written after
			// the CREATE, so a failure leaves nothing behind
			follow_ups.push_back(
			    AclCall("acl_register_created", {Value(target.vcat), Value(key), Value(phys), Value(target.origin)}));
		}
	}

	//! `CREATE VIEW v AS <query>` saves the query, in the virtual names it was written in. Nothing
	//! physical is made: the body is a record, and every read resolves it through the reader (spec 018).
	void RewriteCreateView(CreateStatement &stmt) {
		auto &info = stmt.info->Cast<CreateViewInfo>();
		if (info.temporary) {
			Deny("temporary objects are not available through the ACL yet");
		}
		if (!info.query) {
			Deny("a view needs a query");
		}
		auto key = VirtualKey(info.GetQualifiedName());
		DdlTarget target;
		if (!store.ResolveDdlTarget(principal, key, "create", target)) {
			Deny("no schema of the catalog allows creating \"" + key + "\"");
		}
		// The body is resolved here, with its author's rights: a view is an object of the virtual
		// catalog in its own right, and reading it is decided by the grant on the view - not by grants
		// on what it happens to read. Claims stay markers, so a reader in another tenant still sees
		// their own rows rather than the author's (spec 018).
		keep_claim_markers = true;
		RewriteQueryNode(*info.query->node);
		keep_claim_markers = false;
		auto body = info.query->ToString();
		drop_statement = true;
		follow_ups.push_back(AclCall("acl_register_view", {Value(target.vcat), Value(key), Value(body)}));
	}

	void RewriteDropStatement(DropStatement &stmt) {
		if (!stmt.info) {
			Deny("unsupported DROP form");
		}
		auto &info = *stmt.info;
		if (info.type != CatalogType::TABLE_ENTRY && info.type != CatalogType::VIEW_ENTRY) {
			Deny("only tables and views can be dropped through the ACL");
		}
		auto key = VirtualKey(info.GetQualifiedName());
		DdlTarget target;
		if (!store.ResolveDdlTarget(principal, key, "drop", target)) {
			Deny("no schema of the catalog allows dropping \"" + key + "\"");
		}
		TablePolicy existing;
		if (store.ResolveTable(principal, key, existing) && !existing.query.empty()) {
			// a view has no physical object behind it: the record is the whole of it
			drop_statement = true;
			follow_ups.push_back(AclCall("acl_drop_relation", {Value(target.vcat), Value(key), Value("skip")}));
			return;
		}
		if (target.virtual_only) {
			Deny("\"" + key + "\" is granted VIRTUAL ONLY, so its physical object is not this role's to drop");
		}
		auto name = info.GetQualifiedName().Name();
		info.SetQualifiedName(ParsePhysName(target.phys_schema + "." + name.GetIdentifierName()));
		if (target.needs_record) {
			// the record goes with the object it described; 'skip' because a name may have none
			follow_ups.push_back(AclCall("acl_drop_relation", {Value(target.vcat), Value(key), Value("skip")}));
		}
	}

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
		auto policy = ResolveDmlTarget(node.table_ref, node.qualified_name, "insert");
		auto vname = dml_target_name;
		// the written column names are the virtual ones: map them back onto the physical table
		for (auto &column : node.columns) {
			column = MapWrittenColumn(policy, column, vname);
		}
		if (node.select_statement && node.select_statement->node) {
			RewriteQueryNode(*node.select_statement->node);
		}
		ApplyInsertPolicy(node, policy, vname);
		ApplyInsertCheck(node, policy, vname);
		ApplyConflictPolicy(node, policy, vname);
		for (auto &item : node.returning_list) {
			RewriteExpr(item);
			MapColumnRefs(item, policy, vname); // RETURNING names the target's own columns
			// An INSERT target binds under its table name - DuckDB ignores an alias here, with or
			// without the ACL - so a qualifier the principal wrote is mapped rather than aliased.
			MapTargetQualifier(item, vname, node.qualified_name.Name().GetIdentifierName());
		}
		RequireReadableReturning(node.returning_list, policy, vname);
	}

	//! `ON CONFLICT … DO UPDATE` is an update wearing an insert's clothes, and it was going through
	//! untouched: its SET list decides what an existing row becomes, and the row it lands on may belong
	//! to someone else entirely. It carries the same policy as any other update (specs 011, 024).
	void ApplyConflictPolicy(InsertQueryNode &node, const TablePolicy &policy, const string &vname) {
		if (!node.on_conflict_info) {
			return;
		}
		auto &conflict = *node.on_conflict_info;
		RewriteExpr(conflict.condition);
		MapColumnRefs(conflict.condition, policy, vname);
		if (!conflict.set_info) {
			return;
		}
		for (auto &column : conflict.set_info->columns) {
			column = MapWrittenColumn(policy, column, vname);
			RequireWritableColumn(policy, column, vname);
		}
		for (auto &expr : conflict.set_info->expressions) {
			RewriteExpr(expr);
			MapColumnRefs(expr, policy, vname);
		}
		ApplySetInjections(*conflict.set_info, policy, vname);
		RewriteExpr(conflict.set_info->condition);
		MapColumnRefs(conflict.set_info->condition, policy, vname);
		// which rows it may update at all, and what they may become
		AndPolicyPredicate(conflict.set_info->condition, policy);
		ApplyUpdateCheck(*conflict.set_info, policy, vname, Identifier());
	}

	//! `RETURNING vname.col` -> `RETURNING <physical table>.col`: only for INSERT, where the target is
	//! bound by name. The other verbs keep the virtual name as an alias instead (ResolveDmlTarget).
	void MapTargetQualifier(unique_ptr<ParsedExpression> &expr, const string &vname, const string &phys_table) {
		if (!expr) {
			return;
		}
		if (expr->GetExpressionClass() == ExpressionClass::COLUMN_REF) {
			auto &names = expr->Cast<ColumnRefExpression>().ColumnNamesMutable();
			if (names.size() >= 2) {
				auto &qualifier = names[names.size() - 2];
				auto last = SplitTopLevel(vname, '.').back();
				if (StringUtil::CIEquals(qualifier.GetIdentifierName(), last)) {
					qualifier = Identifier(phys_table);
				}
			}
			return;
		}
		ParsedExpressionIterator::EnumerateChildren(
		    *expr, [&](unique_ptr<ParsedExpression> &child) { MapTargetQualifier(child, vname, phys_table); });
	}

	void RewriteUpdateNode(UpdateQueryNode &node) {
		auto policy = ResolveDmlTarget(node.table, "update");
		auto vname = dml_target_name;
		RewriteTableRef(node.from_table);
		if (node.set_info) {
			for (auto &column : node.set_info->columns) {
				column = MapWrittenColumn(policy, column, vname);
				RequireWritableColumn(policy, column, vname);
			}
			for (auto &expr : node.set_info->expressions) {
				RewriteExpr(expr);
				MapColumnRefs(expr, policy, vname);
			}
			// a grant's value column is assigned, not suggested: overriding the SET keeps the row
			// inside the principal's slice, and the predicate keeps the statement there too
			for (idx_t i = 0; i < node.set_info->columns.size() && i < node.set_info->expressions.size(); i++) {
				for (auto &injection : policy.injections) {
					if (StringUtil::CIEquals(injection.first, node.set_info->columns[i].GetIdentifierName())) {
						node.set_info->expressions[i] = InjectedValue(injection, vname);
						break;
					}
				}
			}
			ApplyUpdateCheck(*node.set_info, policy, vname, node.from_table ? TargetAliasOf(node.table) : Identifier());
			RewriteExpr(node.set_info->condition);
			MapColumnRefs(node.set_info->condition, policy, vname,
			              node.from_table ? TargetAliasOf(node.table) : Identifier());
			if (node.from_table) {
				AndInto(node.set_info->condition, TargetPredicate(policy, TargetAliasOf(node.table), vname));
			} else {
				AndPolicyPredicate(node.set_info->condition, policy);
			}
		}
		for (auto &item : node.returning_list) {
			RewriteExpr(item);
			MapColumnRefs(item, policy, vname);
		}
		RequireReadableReturning(node.returning_list, policy, vname);
	}

	void RewriteDeleteNode(DeleteQueryNode &node) {
		auto policy = ResolveDmlTarget(node.table, "delete");
		auto vname = dml_target_name;
		for (auto &using_ref : node.using_clauses) {
			RewriteTableRef(using_ref);
		}
		RewriteExpr(node.condition);
		MapColumnRefs(node.condition, policy, vname,
		              node.using_clauses.empty() ? Identifier() : TargetAliasOf(node.table));
		if (!node.using_clauses.empty()) {
			AndInto(node.condition, TargetPredicate(policy, TargetAliasOf(node.table), vname));
		} else {
			AndPolicyPredicate(node.condition, policy);
		}
		for (auto &item : node.returning_list) {
			RewriteExpr(item);
			MapColumnRefs(item, policy, vname);
		}
		RequireReadableReturning(node.returning_list, policy, vname);
	}

	void RewriteMergeNode(MergeQueryNode &node) {
		auto policy = ResolveDmlTarget(node.target, "merge");
		auto vname = dml_target_name;
		auto alias = TargetAliasOf(node.target);
		RewriteTableRef(node.source);
		RewriteExpr(node.join_condition);
		MapColumnRefs(node.join_condition, policy, vname, alias);
		// The predicate joins the target rather than filters the result: a row outside the grant is
		// never matched, so no WHEN MATCHED branch can reach it.
		AndInto(node.join_condition, TargetPredicate(policy, alias, vname));
		for (auto &action_set : node.actions) {
			for (auto &action : action_set.second) {
				RewriteExpr(action->condition);
				MapColumnRefs(action->condition, policy, vname, alias);
				if (action_set.first == MergeActionCondition::WHEN_NOT_MATCHED_BY_SOURCE) {
					// ... but "not matched" now includes every row the predicate excluded, and this
					// branch acts on exactly those, so it needs the predicate of its own.
					AndInto(action->condition, TargetPredicate(policy, alias, vname));
				}
				if (action->update_info) {
					for (auto &column : action->update_info->columns) {
						column = MapWrittenColumn(policy, column, vname);
						RequireWritableColumn(policy, column, vname);
					}
					for (auto &expr : action->update_info->expressions) {
						RewriteExpr(expr);
						MapColumnRefs(expr, policy, vname, alias);
					}
					ApplySetInjections(*action->update_info, policy, vname);
					ApplyUpdateCheck(*action->update_info, policy, vname, alias);
					RewriteExpr(action->update_info->condition);
					MapColumnRefs(action->update_info->condition, policy, vname, alias);
				}
				for (auto &expr : action->expressions) {
					RewriteExpr(expr);
					MapColumnRefs(expr, policy, vname, alias);
				}
				if (action->action_type == MergeActionType::MERGE_INSERT) {
					ApplyMergeInsertPolicy(*action, policy, vname);
					ApplyMergeInsertCheck(*action, policy, vname);
				}
			}
		}
		for (auto &item : node.returning_list) {
			RewriteExpr(item);
			MapColumnRefs(item, policy, vname, alias);
		}
		RequireReadableReturning(node.returning_list, policy, vname);
	}

	//! A grant's value column is assigned, not suggested - the same rule the UPDATE path applies
	void ApplySetInjections(UpdateSetInfo &set_info, const TablePolicy &policy, const string &vname) {
		for (idx_t i = 0; i < set_info.columns.size() && i < set_info.expressions.size(); i++) {
			for (auto &injection : policy.injections) {
				if (StringUtil::CIEquals(injection.first, set_info.columns[i].GetIdentifierName())) {
					set_info.expressions[i] = InjectedValue(injection, vname);
					break;
				}
			}
		}
	}

	//! A merge's INSERT branch writes a new row, so it carries the grant's column policy exactly as a
	//! plain INSERT does: only granted columns, and every injected value assigned rather than supplied.
	void ApplyMergeInsertPolicy(MergeIntoAction &action, const TablePolicy &policy, const string &vname) {
		if (policy.write_columns.empty() && policy.injections.empty()) {
			return;
		}
		if (action.default_values || action.insert_columns.empty() ||
		    action.column_order == InsertColumnOrder::INSERT_BY_NAME) {
			// without an explicit column list we do not know which physical columns are written
			Deny("the insert branch of a merge into \"" + vname + "\" must name its columns");
		}
		for (auto &column : action.insert_columns) {
			column = MapWrittenColumn(policy, column, vname);
			RequireWritableColumn(policy, column, vname);
		}
		if (policy.injections.empty()) {
			return;
		}
		vector<Identifier> columns;
		vector<unique_ptr<ParsedExpression>> items;
		for (idx_t i = 0; i < action.insert_columns.size() && i < action.expressions.size(); i++) {
			bool injected = false;
			for (auto &injection : policy.injections) {
				if (StringUtil::CIEquals(injection.first, action.insert_columns[i].GetIdentifierName())) {
					injected = true; // the supplied value is dropped: the grant assigns this column
					break;
				}
			}
			if (!injected) {
				columns.push_back(action.insert_columns[i]);
				items.push_back(std::move(action.expressions[i]));
			}
		}
		for (auto &injection : policy.injections) {
			columns.push_back(Identifier(injection.first));
			items.push_back(InjectedValue(injection, vname));
		}
		action.insert_columns = std::move(columns);
		action.expressions = std::move(items);
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
			if (auto surface = MetadataSurfaceOf(key)) {
				// `FROM information_schema.tables` / `FROM duckdb_tables` - the view forms
				auto alias = base.alias.empty() ? base.Table() : base.alias;
				ref = BuildMetadataSubquery(surface, alias);
				return;
			}
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
			} else if (!policy.renames.empty()) {
				// Renamed but still writable: reads go through `SELECT * RENAME (...)`, which renames BY
				// NAME - a column added to the physical table can never shift an alias onto another
				// column. Writes keep the real table and map the names back (ResolveDmlTarget).
				ref = BuildRenamedSubquery(base.Table().GetIdentifierName(), policy, base);
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
		case TableReferenceType::SHOW_REF:
			RewriteShowRef(ref);
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
			// a call returns rows, so it is a read like any relation (spec 012). The check comes
			// before the template is expanded: a denied call never reaches bind.
			if (!policy.caps.count("select")) {
				Deny("select on table function \"" + vname + "\" is not allowed");
			}
			RewriteFunctionArgs(function); // resolve virtual names inside the call arguments first
			Identifier alias = tf.alias.empty() ? Identifier(vname) : tf.alias;
			if (policy.subquery_form) {
				ref = BuildFunctionSubquery(vname, policy, function, tf);
			} else {
				// RENAME-alias: retarget the call to a physical/system function, keep the arguments
				function.SetQualifiedName(ParsePhysName(policy.phys));
			}
			// a grant narrows what the function returns, whichever form it took (spec 011)
			WrapWithGrantPolicy(ref, policy, alias);
			return;
		}
		if (auto surface = MetadataSurfaceOf(vname)) {
			// `FROM duckdb_tables()` - the function form of the same catalog. None of these take
			// arguments, and quietly dropping one would answer a question nobody asked.
			if (!function.GetArguments().empty()) {
				Deny("\"" + vname + "\" takes no arguments");
			}
			ref = BuildMetadataSubquery(surface, tf.alias.empty() ? Identifier(vname) : tf.alias);
			return;
		}
		if (StringUtil::CIEquals(vname, "acl_references")) {
			// spec 022: the principal's own view of the declared join paths. Substituted here, before
			// the function gate, exactly as the metadata surfaces are - so it needs no hole in the gate.
			ref = BuildReferencesSubquery(function, tf.alias.empty() ? Identifier(vname) : tf.alias);
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

	//! `DESCRIBE` / `SUMMARIZE` / `SHOW TABLES` (spec 025). These are what a client sends before it
	//! sends anything else, so refusing them left every ordinary tool talking to a wall.
	void RewriteShowRef(unique_ptr<TableRef> &ref) {
		auto &show = ref->Cast<ShowRef>();
		if (show.query) {
			// DESCRIBE (SELECT …) - the query is the principal's, and it is rewritten like any other
			RewriteQueryNode(*show.query);
			return;
		}
		if (show.show_type == ShowType::DESCRIBE || show.show_type == ShowType::SUMMARY) {
			// `DESCRIBE <name>` becomes `DESCRIBE (SELECT * FROM <name>)`: the same shape to the caller,
			// and the answer comes from the read path, so it describes what the principal can read
			// rather than what the physical table has.
			auto select = make_uniq<SelectNode>();
			select->select_list.push_back(make_uniq<StarExpression>());
			auto base = make_uniq<BaseTableRef>();
			base->SetQualifiedName(show.qualified_name);
			select->from_table = std::move(base);
			show.query = std::move(select);
			show.qualified_name = QualifiedName();
			RewriteQueryNode(*show.query);
			return;
		}
		// SHOW_UNQUALIFIED carries *what* to show in the name duckdb's transform put there - "tables",
		// "databases", "schemas", "variables", or __show_tables_expanded for SHOW ALL TABLES. Every one
		// of them used to be answered with the table listing, in the shape SHOW TABLES has: a client
		// asking which databases it had got back a list of tables (spec 031).
		auto asked = ShowTarget(show);
		if (asked == "variables") {
			// Session variables are not the principal's: only `ACL NATIVE` sets one, and `getvariable`
			// is denied for the same reason. Answering empty would claim the principal has none, when
			// the truth is that the ones which exist are none of its business (spec 031).
			Deny("SHOW VARIABLES is not available under ACL: session variables are not part of a "
			     "principal's catalog");
		}
		if (asked == "databases" || asked == "schemas" || asked == "__show_tables_expanded" ||
		    (asked == "tables" && show.show_type != ShowType::SHOW_FROM)) {
			auto surface = asked == "databases"                ? "show_databases"
			               : asked == "schemas"                ? "show_schemas"
			               : asked == "__show_tables_expanded" ? "show_tables_expanded"
			                                                   : "show_tables";
			string listing;
			if (!store.MetadataListing(principal, surface, listing)) {
				Deny("metadata is not available: this policy source cannot enumerate " + asked);
			}
			ref = SubqueryOf(listing);
			return;
		}
		// SHOW TABLES [FROM <schema>] - the principal's own catalog in the shape SHOW TABLES has
		string sql;
		if (!store.MetadataListing(principal, "tables", sql)) {
			Deny("metadata is not available: this policy source cannot enumerate tables");
		}
		string filter;
		if (show.show_type == ShowType::SHOW_FROM) {
			auto path = show.qualified_name.Path();
			vector<string> parts;
			for (auto &part : path) {
				if (!part.empty()) {
					parts.push_back(part.GetIdentifierName());
				}
			}
			auto name = show.qualified_name.Name().GetIdentifierName();
			if (!name.empty()) {
				parts.push_back(name);
			}
			if (parts.empty()) {
				Deny("SHOW TABLES FROM needs a schema");
			}
			filter = " WHERE table_schema = " + SqlLiteral(parts.back());
			if (parts.size() > 1) {
				filter += " AND table_catalog = " + SqlLiteral(parts[parts.size() - 2]);
			}
		} else {
			// bare SHOW TABLES is the current schema, which for a principal is the default one
			filter = " WHERE table_schema = 'main'";
		}
		sql = "SELECT table_name AS name FROM (" + sql + ")" + filter + " ORDER BY 1";
		ref = SubqueryOf(sql);
	}

	//! What a SHOW_UNQUALIFIED asks for. duckdb's transform stores the word quoted ("\"databases\"")
	//! for the four it knows, and the bare marker __show_tables_expanded for SHOW ALL TABLES.
	static string ShowTarget(const ShowRef &show) {
		auto name = StringUtil::Lower(show.qualified_name.Name().GetIdentifierName());
		if (name.size() >= 2 && name.front() == '"' && name.back() == '"') {
			name = name.substr(1, name.size() - 2);
		}
		return name;
	}

	//! Wrap generated listing SQL as the subquery that replaces a metadata table reference
	unique_ptr<TableRef> SubqueryOf(const string &sql) {
		auto select_stmt = store.InstantiateSelect(sql, template_options);
		return make_uniq<SubqueryRef>(std::move(select_stmt), Identifier("__acl_show"));
	}

	//! A single-quoted SQL literal of a name we splice into generated SQL
	static string SqlLiteral(const string &text) {
		return "'" + StringUtil::Replace(text, "'", "''") + "'";
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

	//! `(SELECT <columns> FROM (<what the function expanded to>) [WHERE <predicate>]) AS <alias>` -
	//! the grant's policy over a table function's result. The shape is parsed as a template over a
	//! placeholder relation, so the column items and the predicate go through the normal parser (and
	//! the normal claim baking); the placeholder is then swapped for the real reference.
	//! The call the grant's wrapper is written around appears in it as `"__acl_inner"`. A narrowing
	//! wrapper nests (spec 038), so the placeholder is not always the outer FROM - find it wherever it
	//! is and put the real call there.
	static bool PlaceInner(unique_ptr<TableRef> &node, unique_ptr<TableRef> &call) {
		if (!node) {
			return false;
		}
		if (node->type == TableReferenceType::BASE_TABLE &&
		    StringUtil::CIEquals(node->Cast<BaseTableRef>().Table().GetIdentifierName(), "__acl_inner")) {
			node = std::move(call);
			return true;
		}
		if (node->type == TableReferenceType::SUBQUERY) {
			auto &sub = node->Cast<SubqueryRef>();
			if (sub.subquery && sub.subquery->node && sub.subquery->node->type == QueryNodeType::SELECT_NODE) {
				return PlaceInner(sub.subquery->node->Cast<SelectNode>().from_table, call);
			}
		}
		return false;
	}

	void WrapWithGrantPolicy(unique_ptr<TableRef> &ref, const TablePolicy &policy, const Identifier &alias) {
		if (policy.rls.empty() && policy.projection.empty() && policy.wrap_sql.empty()) {
			return;
		}
		string sql = policy.wrap_sql;
		if (sql.empty()) {
			string items = policy.projection.empty() ? "*" : StringUtil::Join(policy.projection, ", ");
			sql = "SELECT " + items + " FROM \"__acl_inner\"" + (policy.rls.empty() ? "" : " WHERE " + policy.rls);
		}
		auto select_stmt = store.InstantiateSelect(sql, template_options);
		BakeMarkersInNode(*select_stmt->node, nullptr); // acl_arg belongs to the call, not to the policy
		auto &select = select_stmt->node->Cast<SelectNode>();
		ref->alias = Identifier();
		if (!PlaceInner(select.from_table, ref)) {
			Deny("the grant's projection could not be applied to \"" + alias.GetIdentifierName() + "\"");
		}
		ref = make_uniq<SubqueryRef>(std::move(select_stmt), alias);
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
			if (policy.projection.empty() && policy.rls.empty()) {
				Deny("object \"" + vname + "\" exposes no readable columns");
			}
			// no projection means the grant narrowed only the rows (spec 011): every column is read,
			// renamed by name if the object renames any
			string items = "*";
			if (!policy.projection.empty()) {
				items = StringUtil::Join(policy.projection, ", ");
			} else if (!policy.renames.empty()) {
				items = "* RENAME (" + StringUtil::Join(RenameItems(policy), ", ") + ")";
			}
			sql = "SELECT " + items + " FROM " + policy.phys;
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

	//! `(SELECT * RENAME (phys AS virt, …) FROM <phys>) AS <alias>` - the read shape of a renamed but
	//! writable relation
	unique_ptr<TableRef> BuildRenamedSubquery(const string &vname, const TablePolicy &policy, BaseTableRef &original) {
		auto sql = "SELECT * RENAME (" + StringUtil::Join(RenameItems(policy), ", ") + ") FROM " + policy.phys;
		auto select_stmt = store.InstantiateSelect(sql, template_options);
		Identifier alias = original.alias.empty() ? Identifier(vname) : original.alias;
		auto sub = make_uniq<SubqueryRef>(std::move(select_stmt), alias);
		sub->column_name_alias = std::move(original.column_name_alias);
		sub->sample = std::move(original.sample);
		return std::move(sub);
	}

	//! Replace a metadata surface with the principal's own catalog in the same shape
	unique_ptr<TableRef> BuildMetadataSubquery(const char *surface, const Identifier &alias) {
		string sql;
		if (!store.MetadataListing(principal, surface, sql)) {
			Deny(string("metadata is not available: this policy source cannot enumerate ") + surface);
		}
		auto select_stmt = store.InstantiateSelect(sql, template_options);
		return make_uniq<SubqueryRef>(std::move(select_stmt), alias);
	}

	//! `FROM acl_references()` / `acl_references('orders')`: the references whose both ends this
	//! principal can see, optionally narrowed to the ones touching one object.
	unique_ptr<TableRef> BuildReferencesSubquery(FunctionExpression &function, const Identifier &alias) {
		auto &arguments = function.GetArguments();
		if (arguments.size() > 1) {
			Deny("acl_references takes at most one argument: the object to list references for");
		}
		string object;
		if (arguments.size() == 1) {
			auto &argument = arguments[0].GetExpression();
			if (argument.GetExpressionClass() != ExpressionClass::CONSTANT) {
				// the filter is spliced into generated SQL, so it has to be known now - and the golden
				// rule forbids adding a parameter of our own to carry it
				Deny("acl_references needs a constant object name");
			}
			object = argument.Cast<ConstantExpression>().GetValue().ToString();
		}
		string sql;
		if (!store.MetadataListing(principal, "references", sql)) {
			Deny("references are not available: this policy source cannot enumerate them");
		}
		if (!object.empty()) {
			auto quoted = "'" + StringUtil::Replace(object, "'", "''") + "'";
			sql = "SELECT * FROM (" + sql + ") WHERE from_object = " + quoted + " OR to_object = " + quoted;
		}
		auto select_stmt = store.InstantiateSelect(sql, template_options);
		return make_uniq<SubqueryRef>(std::move(select_stmt), alias);
	}

	//! `phys AS virt` items of a relation's rename list
	static vector<string> RenameItems(const TablePolicy &policy) {
		vector<string> items;
		for (auto &rename : policy.renames) {
			items.push_back(rename.second + " AS " + rename.first);
		}
		return items;
	}

	//! Map a written column name onto the physical one. A physical name that the policy renamed away
	//! is refused: the virtual relation does not have that column any more.
	Identifier MapWrittenColumn(const TablePolicy &policy, const Identifier &written, const string &vname) {
		auto name = written.GetIdentifierName();
		for (auto &rename : policy.renames) {
			if (StringUtil::CIEquals(rename.first, name)) {
				return Identifier(rename.second);
			}
		}
		for (auto &rename : policy.renames) {
			if (StringUtil::CIEquals(rename.second, name)) {
				Deny("\"" + vname + "\" has no column \"" + name + "\"");
			}
		}
		return written;
	}

	//! Rewrite column references of the DML target's own scope (SET values, WHERE, RETURNING)
	void MapColumnRefs(unique_ptr<ParsedExpression> &expr, const TablePolicy &policy, const string &vname,
	                   const Identifier &target_alias = Identifier()) {
		if (!expr) {
			return;
		}
		if (expr->GetExpressionClass() == ExpressionClass::COLUMN_REF) {
			auto &column_ref = expr->Cast<ColumnRefExpression>();
			auto &names = column_ref.ColumnNamesMutable();
			if (names.empty()) {
				return;
			}
			if (!target_alias.empty() && names.size() >= 2 &&
			    !StringUtil::CIEquals(names[names.size() - 2].GetIdentifierName(), target_alias.GetIdentifierName())) {
				return; // qualified by another relation in scope: not the target's column
			}
			names.back() = MapWrittenColumn(policy, names.back(), vname);
			return;
		}
		ParsedExpressionIterator::EnumerateChildren(
		    *expr, [&](unique_ptr<ParsedExpression> &child) { MapColumnRefs(child, policy, vname, target_alias); });
	}

	//! A grant's value column is an assignment, so it may only be built from claims and constants: an
	//! expression that reads the row is a mask, and a mask cannot be written through (spec 011).
	void RequireValueExpression(const ParsedExpression &expr, const string &column, const string &vname) {
		if (expr.GetExpressionClass() == ExpressionClass::COLUMN_REF) {
			Deny("column \"" + column + "\" of \"" + vname + "\" is computed from the row, so it cannot be written");
		}
		ParsedExpressionIterator::EnumerateChildren(
		    expr, [&](const ParsedExpression &child) { RequireValueExpression(child, column, vname); });
	}

	//! The baked value a grant assigns to one column
	unique_ptr<ParsedExpression> InjectedValue(const std::pair<string, string> &injection, const string &vname) {
		auto value = store.InstantiateExpr(injection.second, template_options);
		BakeMarkers(value, nullptr);
		RequireValueExpression(*value, injection.first, vname);
		return value;
	}

	//! Refuse a write to a column the grant does not list: silently dropping it would write a row the
	//! principal did not ask for.
	void RequireWritableColumn(const TablePolicy &policy, const Identifier &column, const string &vname) {
		if (policy.write_columns.empty() || policy.write_columns.count(column.GetIdentifierName())) {
			return;
		}
		Deny("column \"" + column.GetIdentifierName() + "\" of \"" + vname + "\" is not writable");
	}

	//! AND the policy's (already composed) predicate into a statement's WHERE, so an UPDATE/DELETE
	//! only reaches rows the principal can see. The predicate names physical columns, so it is added
	//! after the user's own condition has been mapped.
	void AndPolicyPredicate(unique_ptr<ParsedExpression> &condition, const TablePolicy &policy) {
		if (policy.rls.empty()) {
			return;
		}
		auto predicate = store.InstantiateExpr(policy.rls, template_options);
		BakeMarkers(predicate, nullptr);
		if (!condition) {
			condition = std::move(predicate);
			return;
		}
		condition = make_uniq<ConjunctionExpression>(ExpressionType::CONJUNCTION_AND, std::move(condition),
		                                             std::move(predicate));
	}

	//! Whether a grant narrows what may be written at all
	static bool HasWritePolicy(const TablePolicy &policy) {
		return !policy.injections.empty() || !policy.write_columns.empty() || !policy.rls.empty();
	}

	//! spec 024: a grant's predicate confines what is written, not only what may be reached. Without
	//! this an INSERT lands a row outside the principal's own slice - one it cannot read back - and an
	//! UPDATE moves its own row out of it.
	void ApplyInsertCheck(InsertQueryNode &node, const TablePolicy &policy, const string &vname) {
		auto predicate = WritePredicate(policy);
		if (!predicate) {
			return;
		}
		if (node.columns.empty() || node.default_values || !node.select_statement) {
			Deny("insert into \"" + vname +
			     "\" must name its columns: the grant's predicate decides which rows "
			     "may be written, and an unnamed column has no value to judge");
		}
		// a predicate reading a column the row does not carry cannot be evaluated at all
		vector<string> read;
		CollectColumnNames(*predicate, read);
		for (auto &name : read) {
			bool written = false;
			for (auto &column : node.columns) {
				if (StringUtil::CIEquals(column.GetIdentifierName(), name)) {
					written = true;
					break;
				}
			}
			if (!written) {
				Deny("insert into \"" + vname + "\" must supply \"" + name +
				     "\": the grant's predicate reads it "
				     "to decide whether the row may be "
				     "written");
			}
		}
		vector<unique_ptr<ParsedExpression>> items;
		for (idx_t i = 0; i < node.columns.size(); i++) {
			unique_ptr<ParsedExpression> item = make_uniq<ColumnRefExpression>(node.columns[i]);
			if (i == 0) {
				item = GuardedValue(std::move(item), std::move(predicate), vname);
			}
			items.push_back(std::move(item));
		}
		auto source = make_uniq<SubqueryRef>(std::move(node.select_statement), Identifier("__acl_check"));
		source->column_name_alias = node.columns;
		auto select = make_uniq<SelectNode>();
		select->from_table = std::move(source);
		select->select_list = std::move(items);
		auto statement = make_uniq<SelectStatement>();
		statement->node = std::move(select);
		node.select_statement = std::move(statement);
	}

	//! spec 024: the insert branch of a merge writes a new row, so the grant's predicate judges it like
	//! any other insert
	void ApplyMergeInsertCheck(MergeIntoAction &action, const TablePolicy &policy, const string &vname) {
		auto predicate = WritePredicate(policy);
		if (!predicate) {
			return;
		}
		if (action.default_values || action.insert_columns.empty() || action.expressions.empty()) {
			Deny("the insert branch of a merge into \"" + vname +
			     "\" must name its columns: the grant's predicate "
			     "decides which rows may be written");
		}
		vector<string> read;
		CollectColumnNames(*predicate, read);
		for (auto &name : read) {
			bool written = false;
			for (auto &column : action.insert_columns) {
				if (StringUtil::CIEquals(column.GetIdentifierName(), name)) {
					written = true;
					break;
				}
			}
			if (!written) {
				Deny("the insert branch of a merge into \"" + vname + "\" must supply \"" + name +
				     "\": the grant's predicate reads it to decide whether the row may be written");
			}
		}
		// the predicate names the row's columns; here they are the values about to be inserted
		UpdateSetInfo as_row;
		for (idx_t i = 0; i < action.insert_columns.size() && i < action.expressions.size(); i++) {
			as_row.columns.push_back(action.insert_columns[i]);
			as_row.expressions.push_back(action.expressions[i]->Copy());
		}
		SubstituteSetValues(predicate, as_row);
		action.expressions[0] = GuardedValue(std::move(action.expressions[0]), std::move(predicate), vname);
	}

	//! The row an UPDATE leaves behind: a column it sets takes the new value, every other keeps its own.
	//! Substituting the SET list into the grant's predicate is what turns "which rows may be touched"
	//! into "what they may become" (spec 024).
	static void SubstituteSetValues(unique_ptr<ParsedExpression> &expr, const UpdateSetInfo &set_info) {
		if (!expr) {
			return;
		}
		if (expr->GetExpressionClass() == ExpressionClass::COLUMN_REF) {
			auto &parts = expr->Cast<ColumnRefExpression>().ColumnNames();
			if (parts.empty()) {
				return;
			}
			auto name = parts.back().GetIdentifierName();
			for (idx_t i = 0; i < set_info.columns.size() && i < set_info.expressions.size(); i++) {
				if (StringUtil::CIEquals(set_info.columns[i].GetIdentifierName(), name)) {
					expr = set_info.expressions[i]->Copy();
					return;
				}
			}
			return;
		}
		ParsedExpressionIterator::EnumerateChildren(
		    *expr, [&](unique_ptr<ParsedExpression> &child) { SubstituteSetValues(child, set_info); });
	}

	//! spec 024: the row an UPDATE writes must satisfy the grant, not merely the row it started from
	void ApplyUpdateCheck(UpdateSetInfo &set_info, const TablePolicy &policy, const string &vname,
	                      const Identifier &target_alias) {
		auto predicate = WritePredicate(policy);
		if (!predicate || set_info.columns.empty() || set_info.expressions.empty()) {
			return;
		}
		// A SET that touches nothing the predicate reads leaves the answer where it was: the new row
		// satisfies the grant exactly when the old one did, and the predicate on the WHERE (or the ON)
		// already guaranteed that. Skipping the guard there is not only cheaper - a merge with a
		// WHEN NOT MATCHED BY SOURCE branch evaluates this expression for rows the branch never
		// touches, and a guard would fire on them.
		vector<string> read;
		CollectColumnNames(*predicate, read);
		bool touches = false;
		for (auto &name : read) {
			for (auto &column : set_info.columns) {
				if (StringUtil::CIEquals(column.GetIdentifierName(), name)) {
					touches = true;
					break;
				}
			}
		}
		if (!touches) {
			return;
		}
		// the predicate's own names are the target's, so they are bound to it before the SET list is
		// folded in - otherwise a same-named column on the other relation captures them (spec 020)
		if (!target_alias.empty()) {
			QualifyWithTarget(predicate, target_alias);
		}
		SubstituteSetValues(predicate, set_info);
		set_info.expressions[0] = GuardedValue(std::move(set_info.expressions[0]), std::move(predicate), vname);
	}

	//! Every column name an expression reads, whatever it is qualified by. Used to decide whether a row
	//! about to be written can be judged by the grant's predicate at all (spec 024).
	static void CollectColumnNames(const ParsedExpression &expr, vector<string> &names) {
		if (expr.GetExpressionClass() == ExpressionClass::COLUMN_REF) {
			auto &parts = expr.Cast<ColumnRefExpression>().ColumnNames();
			if (!parts.empty()) {
				names.push_back(parts.back().GetIdentifierName());
			}
			return;
		}
		ParsedExpressionIterator::EnumerateChildren(
		    expr, [&](const ParsedExpression &child) { CollectColumnNames(child, names); });
	}

	//! `CASE WHEN <predicate> THEN <value> ELSE error('…') END` - the row that does not satisfy the
	//! grant is refused where it would be written, rather than landing outside the principal's slice.
	//! DuckDB evaluates a CASE per row, so the error fires only for the rows that violate it.
	unique_ptr<ParsedExpression> GuardedValue(unique_ptr<ParsedExpression> value,
	                                          unique_ptr<ParsedExpression> predicate, const string &vname) {
		vector<unique_ptr<ParsedExpression>> message;
		message.push_back(make_uniq<ConstantExpression>(
		    Value("acl_rewrite: the row does not satisfy the grant on \"" + vname + "\", so it cannot be written")));
		auto raise = make_uniq<FunctionExpression>(Identifier("error"), std::move(message));
		auto guard = make_uniq<CaseExpression>();
		CaseCheck check;
		check.when_expr = std::move(predicate);
		check.then_expr = std::move(value);
		guard->CaseChecksMutable().push_back(std::move(check));
		guard->ElseMutable() = std::move(raise);
		return std::move(guard);
	}

	//! The grant's predicate, baked, or nullptr when the grant has none
	unique_ptr<ParsedExpression> WritePredicate(const TablePolicy &policy) {
		if (policy.rls.empty()) {
			return nullptr;
		}
		auto predicate = store.InstantiateExpr(policy.rls, template_options);
		BakeMarkers(predicate, nullptr);
		return predicate;
	}

	//! Apply the grant's write policy to an INSERT: the written columns must be granted, and every
	//! injected value is assigned - added when absent, overriding what the user supplied - by
	//! projecting the source through a subquery. The row therefore belongs to the principal by
	//! construction, without a separate WITH CHECK.
	void ApplyInsertPolicy(InsertQueryNode &node, const TablePolicy &policy, const string &vname) {
		// only a column policy has something to check an INSERT against: a predicate alone does not
		// confine what is written (that is what a value column is for), so it does not restrict here
		if (policy.write_columns.empty()) {
			return;
		}
		if (node.columns.empty() || node.default_values || node.column_order == InsertColumnOrder::INSERT_BY_NAME) {
			// without an explicit column list we do not know which physical columns are written, so
			// there is nothing to check the grant against
			Deny("insert into \"" + vname + "\" must name its columns");
		}
		if (node.on_conflict_info) {
			Deny("insert into \"" + vname + "\" cannot use ON CONFLICT under a column policy");
		}
		if (!node.select_statement) {
			Deny("insert into \"" + vname + "\" has no source to apply the grant policy to");
		}
		for (auto &column : node.columns) {
			RequireWritableColumn(policy, column, vname);
		}
		if (policy.injections.empty()) {
			return;
		}
		vector<Identifier> columns;
		vector<unique_ptr<ParsedExpression>> items;
		for (auto &column : node.columns) {
			bool injected = false;
			for (auto &injection : policy.injections) {
				if (StringUtil::CIEquals(injection.first, column.GetIdentifierName())) {
					injected = true; // the supplied value is dropped: the grant assigns this column
					break;
				}
			}
			if (!injected) {
				columns.push_back(column);
				items.push_back(make_uniq<ColumnRefExpression>(column));
			}
		}
		for (auto &injection : policy.injections) {
			columns.push_back(Identifier(injection.first));
			items.push_back(InjectedValue(injection, vname));
		}
		auto source = make_uniq<SubqueryRef>(std::move(node.select_statement), Identifier("__acl_insert"));
		source->column_name_alias = node.columns;
		auto select = make_uniq<SelectNode>();
		select->from_table = std::move(source);
		select->select_list = std::move(items);
		auto statement = make_uniq<SelectStatement>();
		statement->node = std::move(select);
		node.select_statement = std::move(statement);
		node.columns = std::move(columns);
	}

	//! RETURNING reads the physical table, so under a column policy it must not become a way back to
	//! what the grant hid or masked: only columns the grant exposes as-is may be named, and a star -
	//! which expands to every physical column - never is.
	void RequireReadableReturning(const vector<unique_ptr<ParsedExpression>> &returning, const TablePolicy &policy,
	                              const string &vname) {
		if (policy.write_columns.empty()) {
			return; // no column policy: the relation is the table, and RETURNING reads the table
		}
		for (auto &item : returning) {
			RequireReadableExpr(*item, policy, vname);
		}
	}

	void RequireReadableExpr(const ParsedExpression &expr, const TablePolicy &policy, const string &vname) {
		if (expr.GetExpressionClass() == ExpressionClass::STAR) {
			Deny("RETURNING * on \"" + vname + "\" is not allowed under a column policy");
		}
		if (expr.GetExpressionClass() == ExpressionClass::COLUMN_REF) {
			auto &names = expr.Cast<ColumnRefExpression>().ColumnNames();
			if (names.empty()) {
				return;
			}
			auto name = names.back().GetIdentifierName();
			bool masked = false;
			for (auto &injection : policy.injections) {
				if (StringUtil::CIEquals(injection.first, name)) {
					masked = true; // the grant computes this column, so the stored value is not readable
					break;
				}
			}
			if (masked || !policy.write_columns.count(name)) {
				Deny("column \"" + name + "\" of \"" + vname + "\" is not readable");
			}
			return;
		}
		ParsedExpressionIterator::EnumerateChildren(
		    expr, [&](const ParsedExpression &child) { RequireReadableExpr(child, policy, vname); });
	}

	//! Qualify every bare column reference with the target's alias. Without this, a column of the same
	//! name on the other relation in scope captures the grant's predicate and it filters the wrong rows.
	static void QualifyWithTarget(unique_ptr<ParsedExpression> &expr, const Identifier &alias) {
		if (!expr) {
			return;
		}
		if (expr->GetExpressionClass() == ExpressionClass::SUBQUERY) {
			// The operand of `x IN (SELECT …)` is in the outer scope and needs the target's name; the
			// subquery's own body does not - a bare name in there belongs to its own scope, and the
			// grant is known to bind against its target (spec 021), so leaving it alone keeps its meaning.
			QualifyWithTarget(expr->Cast<SubqueryExpression>().GetChildMutable(), alias);
			return;
		}
		if (expr->GetExpressionClass() == ExpressionClass::COLUMN_REF) {
			auto &names = expr->Cast<ColumnRefExpression>().ColumnNamesMutable();
			if (names.size() == 1) {
				names.insert(names.begin(), alias);
			}
			return;
		}
		ParsedExpressionIterator::EnumerateChildren(
		    *expr, [&](unique_ptr<ParsedExpression> &child) { QualifyWithTarget(child, alias); });
	}

	//! The name the target answers to after ResolveDmlTarget: its alias, which is the virtual name
	//! unless the principal wrote one of their own (spec 019).
	static Identifier TargetAliasOf(const unique_ptr<TableRef> &target) {
		if (target && target->type == TableReferenceType::BASE_TABLE) {
			auto &base = target->Cast<BaseTableRef>();
			return base.alias.empty() ? base.Table() : base.alias;
		}
		return Identifier();
	}

	//! Whether an expression contains a subquery anywhere - the one part QualifyWithTarget leaves in
	//! its own scope, and therefore the one part whose meaning depends on the predicate having been
	//! bound against its target.
	static bool ContainsSubquery(const ParsedExpression &expr) {
		if (expr.GetExpressionClass() == ExpressionClass::SUBQUERY) {
			return true;
		}
		bool found = false;
		ParsedExpressionIterator::EnumerateChildren(
		    expr, [&](const ParsedExpression &child) { found = found || ContainsSubquery(child); });
		return found;
	}

	//! The grant's predicate, baked and bound to the target by name; nullptr when the grant has none
	unique_ptr<ParsedExpression> TargetPredicate(const TablePolicy &policy, const Identifier &alias,
	                                             const string &vname) {
		if (policy.rls.empty()) {
			return nullptr;
		}
		auto predicate = store.InstantiateExpr(policy.rls, template_options);
		BakeMarkers(predicate, nullptr);
		// Here a second relation is in scope, and a subquery's body keeps its own scope (see
		// QualifyWithTarget) - which is safe exactly because the predicate was bound against its target
		// when it was written (spec 021). Without that verdict a bare name in there could resolve
		// against the source instead, and quietly filter the wrong rows (spec 027).
		if (policy.rls_unchecked && ContainsSubquery(*predicate)) {
			throw BinderException("acl: the predicate of \"%s\" contains a subquery and was never checked against "
			                      "the object, so it cannot be used where a second relation is in scope - run "
			                      "acl_refresh_schema() with the object reachable, or rewrite the grant",
			                      vname);
		}
		QualifyWithTarget(predicate, alias);
		return predicate;
	}

	static void AndInto(unique_ptr<ParsedExpression> &condition, unique_ptr<ParsedExpression> predicate) {
		if (!predicate) {
			return;
		}
		if (!condition) {
			condition = std::move(predicate);
			return;
		}
		condition = make_uniq<ConjunctionExpression>(ExpressionType::CONJUNCTION_AND, std::move(condition),
		                                             std::move(predicate));
	}

	//! Resolve a DML target in place (name -> physical), enforcing the required capability
	TablePolicy ResolveDmlTarget(unique_ptr<TableRef> &target, const string &capability) {
		if (!target || target->type != TableReferenceType::BASE_TABLE) {
			return TablePolicy();
		}
		auto &base = target->Cast<BaseTableRef>();
		return ResolveDmlTarget(target, base.GetQualifiedNameMutable(), capability);
	}

	TablePolicy ResolveDmlTarget(unique_ptr<TableRef> &target_ref, QualifiedName &target_name,
	                             const string &capability) {
		string key;
		if (target_ref && target_ref->type == TableReferenceType::BASE_TABLE) {
			key = VirtualKey(target_ref->Cast<BaseTableRef>().GetQualifiedName());
		} else {
			key = VirtualKey(target_name);
		}
		TablePolicy policy;
		if (!store.ResolveTable(principal, key, policy)) {
			// a name the principal *does* have, of a kind that is called rather than written: say which
			// rather than leave an administrator reading "no access" about an object they can see
			TablePolicy called;
			if (store.ResolveTableFunction(principal, key, called) ||
			    store.ResolveScalarFunction(principal, key, called)) {
				Deny("\"" + key + "\" is a function, which is called rather than written");
			}
			Deny("no access to object \"" + key + "\"");
		}
		// a view / masked / computed relation is read-only; a grant that only narrows a real table
		// keeps it writable - the narrowing moves onto the written values and the WHERE (spec 011)
		if (!policy.writable) {
			Deny(capability + " into read-only relation \"" + key + "\" is not allowed");
		}
		if (!policy.caps.count(capability)) {
			Deny(capability + " on \"" + key + "\" is not allowed");
		}
		auto phys = ParsePhysName(policy.phys);
		if (target_ref && target_ref->type == TableReferenceType::BASE_TABLE) {
			// Keep the virtual name as an alias, exactly as the read path does: a statement that
			// qualifies its own columns still resolves after the swap, and MERGE's ON clause has no
			// other way to name the target.
			auto &base = target_ref->Cast<BaseTableRef>();
			auto virtual_name = base.Table();
			base.SetQualifiedName(phys);
			if (base.alias.empty()) {
				base.alias = virtual_name;
			}
		}
		target_name = phys;
		dml_target_name = key;
		return policy;
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
				// its template is admin-authored SQL that may read a physical table, so calling it is
				// a read too: the same capability gates it (spec 012)
				if (!spolicy.caps.count("select")) {
					Deny("select on scalar function \"" + name + "\" is not allowed");
				}
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
	//! Every expression of the node is visited - including the ones inside its FROM clause and its set
	//! operations - because a marker left behind fails closed at bind, which would make a perfectly
	//! reasonable template (a predicate over a subquery, a UNION of two tenant slices) unusable.
	void BakeMarkersInNode(QueryNode &node, const vector<unique_ptr<ParsedExpression>> *args) {
		for (auto &entry : node.cte_map.map) {
			if (entry.second->query_node) {
				BakeMarkersInNode(*entry.second->query_node, args);
			}
		}
		if (node.type == QueryNodeType::CTE_NODE) {
			// a guard, not a live path: a template's WITH clause currently parses into a subquery ref
			// in the FROM, so this node does not reach us - but duckdb's iterator has no case for it
			// and its default throws, and we track duckdb's main branch
			auto &cte = node.Cast<CTENode>();
			if (cte.query) {
				BakeMarkersInNode(*cte.query, args);
			}
			if (cte.child) {
				BakeMarkersInNode(*cte.child, args);
			}
			ParsedExpressionIterator::EnumerateQueryNodeModifiers(
			    node, [&](unique_ptr<ParsedExpression> &child) { BakeMarkers(child, args); });
			return;
		}
		ParsedExpressionIterator::EnumerateQueryNodeChildren(
		    node, [&](unique_ptr<ParsedExpression> &child) { BakeMarkers(child, args); });
	}

	void BakeMarkers(unique_ptr<ParsedExpression> &expr, const vector<unique_ptr<ParsedExpression>> *args) {
		if (!expr) {
			return;
		}
		if (expr->GetExpressionClass() == ExpressionClass::SUBQUERY) {
			// the expression iterator stops at a subquery's boundary, so its own node is walked here
			auto &subquery = expr->Cast<SubqueryExpression>();
			if (subquery.SubqueryMutable() && subquery.SubqueryMutable()->node) {
				BakeMarkersInNode(*subquery.SubqueryMutable()->node, args);
			}
		}
		if (expr->GetExpressionClass() == ExpressionClass::FUNCTION) {
			auto &function = expr->Cast<FunctionExpression>();
			auto marker = StringUtil::Lower(function.FunctionName().GetIdentifierName());
			if (marker == "acl_claim" && keep_claim_markers) {
				return; // stored body: this claim is resolved by whoever reads it, not by its author
			}
			if (marker == "acl_claim" || marker == "acl_arg") {
				// the marker may be the whole select item (`acl_claim('tenant') AS tenant`), so its
				// alias has to survive the replacement - otherwise the column loses its name
				auto alias = expr->GetAlias();
				expr = marker == "acl_claim" ? make_uniq<ConstantExpression>(ClaimValue(function))
				                             : ArgExpression(function, args);
				if (!alias.GetIdentifierName().empty()) {
					expr->SetAlias(alias);
				}
				return; // replaced whole node; nothing below to recurse into
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
	//! the virtual name of the DML target currently being rewritten (for diagnostics and mapping)
	string dml_target_name;
	//! While rewriting a body that will be *stored* (a role's CREATE VIEW, spec 018): names and policy
	//! resolve now, with the creator's rights, but `acl_claim` stays a marker so every later reader is
	//! filtered by their own claims. `acl_arg` is still substituted - it belongs to a call that is
	//! happening now and would mean nothing in a stored body.
	bool keep_claim_markers = false;
	ParserOptions template_options;
	case_insensitive_set_t cte_scope;
};

} // namespace

namespace {

void BakeNullMarkersInNode(QueryNode &node, const vector<string> &param_types, const ParserOptions &options);

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
			// a claim is a string by construction (the principal carries them as such), so a mask over
			// one is VARCHAR and the probe can say so; only an argument's type has to be declared
			if (marker == "acl_claim") {
				type = "VARCHAR";
			}
			if (marker == "acl_arg") {
				auto &args = function.GetArguments();
				if (args.size() == 1 && args[0].GetExpression().GetExpressionClass() == ExpressionClass::CONSTANT) {
					auto position = args[0].GetExpression().Cast<ConstantExpression>().GetValue().GetValue<int64_t>();
					if (position >= 1 && static_cast<idx_t>(position) <= param_types.size()) {
						type = param_types[NumericCast<idx_t>(position - 1)];
					}
				}
			}
			// The replacement is a different node, so the alias the marker carried has to be carried
			// over: a probe reads the column *names* a projection produces, and dropping it stored a
			// column with no name in `grant_columns` - which then appeared in every listing, sharing an
			// ordinal with the column it was supposed to be (spec 042).
			//
			// The *type* is deliberately left untyped where the signature does not give one: the baked
			// template is serialised back to text, and a bare `NULL` binds against anything, which is
			// what lets a predicate like `amount >= acl_arg(1)` be probed at all.
			auto alias = expr->GetAlias();
			if (type.empty()) {
				expr = make_uniq<ConstantExpression>(Value(LogicalType::VARCHAR));
			} else {
				// parse the cast rather than resolving the type name by hand (no context needed here)
				auto casted = Parser::ParseExpressionList("CAST(NULL AS " + type + ")", options);
				expr = std::move(casted[0]);
			}
			if (!alias.GetIdentifierName().empty()) {
				expr->SetAlias(alias);
			}
			return;
		}
	}
	if (expr->GetExpressionClass() == ExpressionClass::SUBQUERY) {
		auto &subquery = expr->Cast<SubqueryExpression>().SubqueryMutable();
		if (subquery) {
			BakeNullMarkersInNode(*subquery->node, param_types, options);
		}
	}
	ParsedExpressionIterator::EnumerateChildren(
	    *expr, [&](unique_ptr<ParsedExpression> &child) { BakeNullMarkers(child, param_types, options); });
}

//! Every expression the node owns, at any depth: a marker left standing anywhere makes the probe
//! unbindable, and a resolved body puts the author's policy in a FROM subquery rather than on top.
void BakeNullMarkersInNode(QueryNode &node, const vector<string> &param_types, const ParserOptions &options) {
	ParsedExpressionIterator::EnumerateQueryNodeChildren(
	    node, [&](unique_ptr<ParsedExpression> &child) { BakeNullMarkers(child, param_types, options); });
}

} // namespace

vector<std::pair<string, string>> QualifiedColumnRefs(const string &expression, const ParserOptions &options) {
	ParserOptions inner = options;
	inner.parser_override_setting = AllowParserOverride::DEFAULT_OVERRIDE;
	auto parsed = Parser::ParseExpressionList(expression, inner);
	if (parsed.size() != 1) {
		throw BinderException("acl: a join expression must be a single expression");
	}
	vector<std::pair<string, string>> refs;
	std::function<void(const ParsedExpression &)> walk = [&](const ParsedExpression &expr) {
		if (expr.GetExpressionClass() == ExpressionClass::COLUMN_REF) {
			auto &names = expr.Cast<ColumnRefExpression>().ColumnNames();
			if (names.size() < 2) {
				throw BinderException("acl: \"%s\" is not qualified - a join expression must name the side of "
				                      "every column, so the reference can be checked against what a role sees",
				                      names.empty() ? string("?") : names.back().GetIdentifierName());
			}
			refs.emplace_back(names[names.size() - 2].GetIdentifierName(), names.back().GetIdentifierName());
			return;
		}
		ParsedExpressionIterator::EnumerateChildren(expr, [&](const ParsedExpression &child) { walk(child); });
	};
	walk(*parsed[0]);
	return refs;
}

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
	vector<unique_ptr<SQLStatement>> rewritten;
	for (auto &stmt : statements) {
		rewriter.follow_ups.clear();
		rewriter.drop_statement = false;
		rewriter.replacement = nullptr;
		rewriter.RewriteStatement(*stmt);
		if (rewriter.replacement) {
			rewritten.push_back(std::move(rewriter.replacement));
		} else if (!rewriter.drop_statement) {
			rewritten.push_back(std::move(stmt));
		}
		// a DDL statement's catalog record is appended right after it, so the batch stays in order
		for (auto &follow_up : rewriter.follow_ups) {
			rewritten.push_back(std::move(follow_up));
		}
	}
	statements = std::move(rewritten);
}

} // namespace acl
} // namespace duckdb
