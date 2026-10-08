// spec 107: the edges of a bound logical plan - see acl_lineage_walker.hpp.
#include "acl_lineage_walker.hpp"

#include "duckdb/catalog/catalog_entry/table_catalog_entry.hpp"
#include "duckdb/common/types.hpp"
#include "duckdb/function/lambda_functions.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/planner/column_binding_map.hpp"
#include "duckdb/planner/expression/list.hpp"
#include "duckdb/planner/expression_iterator.hpp"
#include "duckdb/planner/operator/list.hpp"
#include "duckdb/planner/parsed_data/bound_create_table_info.hpp"

namespace duckdb {
namespace acl {

idx_t LineageWalk::EdgeCount() const {
	idx_t count = whole_target.size();
	for (auto &output : outputs) {
		count += output.sources.size();
	}
	return count;
}

idx_t LineageWalk::DatasetIndex(const LineageDatasetKey &key) {
	for (idx_t i = 0; i < datasets.size(); i++) {
		if (datasets[i] == key) {
			return i;
		}
	}
	datasets.push_back(key);
	return datasets.size() - 1;
}

namespace {

constexpr const char *DIRECT = "DIRECT";
constexpr const char *INDIRECT = "INDIRECT";

//! What one binding (or one expression) is made of.
struct BindingLineage {
	vector<LineageContribution> direct;   // DIRECT contributions of the value itself
	vector<LineageContribution> indirect; // INDIRECT contributions decided at the field (CASE conditions)
};

void AddUnique(vector<LineageContribution> &into, const LineageContribution &item) {
	for (auto &existing : into) {
		if (existing == item) {
			return;
		}
	}
	into.push_back(item);
}

void Merge(BindingLineage &into, const BindingLineage &from) {
	for (auto &item : from.direct) {
		AddUnique(into.direct, item);
	}
	for (auto &item : from.indirect) {
		AddUnique(into.indirect, item);
	}
}

//! An expression over a value: an IDENTITY becomes a TRANSFORMATION; an AGGREGATION stays one.
BindingLineage Transformed(BindingLineage lineage) {
	for (auto &item : lineage.direct) {
		if (item.subtype == "IDENTITY") {
			item.subtype = "TRANSFORMATION";
		}
	}
	return lineage;
}

//! Everything a key expression reads, as INDIRECT contributions of one subtype.
vector<LineageContribution> AsIndirect(const BindingLineage &lineage, const string &subtype) {
	vector<LineageContribution> out;
	for (auto items : {&lineage.direct, &lineage.indirect}) {
		for (auto item : *items) {
			item.type = INDIRECT;
			item.subtype = subtype;
			item.masking = false;
			AddUnique(out, item);
		}
	}
	return out;
}

string LowerName(const string &name) {
	return StringUtil::Lower(name);
}

//! The field name a struct_extract / struct_extract_at reads, or "" when the key is not a constant.
string StructKey(BoundFunctionExpression &function) {
	if (function.GetChildren().size() < 2 ||
	    function.GetChildren()[1]->GetExpressionClass() != ExpressionClass::BOUND_CONSTANT) {
		return string();
	}
	auto &key = function.GetChildren()[1]->Cast<BoundConstantExpression>().GetValue();
	if (key.IsNull()) {
		return string();
	}
	auto name = LowerName(function.Function().GetName().GetIdentifierName());
	if (name == "struct_extract" && key.type().id() == LogicalTypeId::VARCHAR) {
		return key.GetValue<string>();
	}
	auto &struct_type = function.GetChildren()[0]->GetReturnType();
	if (struct_type.id() != LogicalTypeId::STRUCT) {
		return string();
	}
	if (name == "struct_extract_at" || (name == "struct_extract" && key.type().IsIntegral())) {
		auto position = key.DefaultCastAs(LogicalType::BIGINT).GetValue<int64_t>();
		auto &children = StructType::GetChildTypes(struct_type);
		if (position >= 1 && idx_t(position) <= children.size()) {
			return children[idx_t(position) - 1].first.GetIdentifierName();
		}
	}
	return string();
}

bool IsStructExtract(const string &name) {
	return name == "struct_extract" || name == "struct_extract_at";
}

//! For a lambda body `x.a.b` over the lambda's first parameter: ".a.b"; "" when it is anything else.
string LambdaFieldSuffix(Expression &body, const LogicalType &element) {
	vector<string> keys;
	reference<Expression> current(body);
	while (current.get().GetExpressionClass() == ExpressionClass::BOUND_FUNCTION) {
		auto &function = current.get().Cast<BoundFunctionExpression>();
		if (!IsStructExtract(LowerName(function.Function().GetName().GetIdentifierName()))) {
			return string();
		}
		auto key = StructKey(function);
		if (key.empty()) {
			return string();
		}
		keys.push_back(key);
		current = *function.GetChildren()[0];
	}
	// the parameter: a lambda ref while bound, a reference into the lambda's input once moved into the
	// function's bind data - recognised by being of the list's element type
	auto parameter_class = current.get().GetExpressionClass();
	if (keys.empty() ||
	    (parameter_class != ExpressionClass::BOUND_LAMBDA_REF && parameter_class != ExpressionClass::BOUND_REF) ||
	    current.get().GetReturnType() != element) {
		return string();
	}
	string suffix;
	for (auto it = keys.rbegin(); it != keys.rend(); ++it) {
		suffix += "." + *it;
	}
	return suffix;
}

class Walker {
public:
	Walker(LineageWalk &walk_p, const LineageWalkOptions &options_p) : walk(walk_p), options(options_p) {
	}

	void Visit(LogicalOperator &op);
	void FinishRoot(LogicalOperator &root);

private:
	LineageWalk &walk;
	const LineageWalkOptions &options;
	column_binding_map_t<BindingLineage> bindings;
	unordered_map<idx_t, vector<ColumnBinding>> ctes; // a CTE's table index -> its definition's bindings

	BindingLineage Lookup(const ColumnBinding &binding) {
		auto entry = bindings.find(binding);
		if (entry == bindings.end()) {
			walk.approximate = true;
			return BindingLineage();
		}
		return entry->second;
	}
	void Set(const ColumnBinding &binding, BindingLineage lineage) {
		bindings[binding] = std::move(lineage);
	}
	void AddWhole(const BindingLineage &lineage, const string &subtype) {
		for (auto &item : AsIndirect(lineage, subtype)) {
			if (walk.EdgeCount() >= options.max_edges) {
				walk.truncated = true;
				return;
			}
			AddUnique(walk.whole_target, item);
		}
	}
	void AddOutput(const string &name, const BindingLineage &lineage) {
		LineageOutput output;
		output.name = name;
		for (auto items : {&lineage.direct, &lineage.indirect}) {
			for (auto &item : *items) {
				if (walk.EdgeCount() + output.sources.size() >= options.max_edges) {
					walk.truncated = true;
					break;
				}
				AddUnique(output.sources, item);
			}
		}
		walk.outputs.push_back(std::move(output));
	}

	BindingLineage Resolve(Expression &expr);
	BindingLineage ResolveFunction(BoundFunctionExpression &function);
	void VisitGet(LogicalGet &get);
	void VisitInsert(LogicalInsert &insert);
	void VisitUpdate(LogicalUpdate &update);
	void VisitMerge(LogicalMergeInto &merge);
	void SetTarget(TableCatalogEntry &table, const string &operation);
	string TableColumnName(TableCatalogEntry &table, idx_t physical);
};

BindingLineage Walker::ResolveFunction(BoundFunctionExpression &function) {
	auto name = LowerName(function.Function().GetName().GetIdentifierName());
	if (IsStructExtract(name)) {
		auto key = StructKey(function);
		if (!key.empty()) {
			auto lineage = Resolve(*function.GetChildren()[0]);
			for (auto &item : lineage.direct) {
				if (!item.field.empty()) {
					item.field += "." + key;
				}
			}
			return lineage;
		}
	}
	if (name == "list_transform" && !function.GetChildren().empty() &&
	    function.GetChildren()[0]->GetReturnType().id() == LogicalTypeId::LIST) {
		auto &element = ListType::GetChildType(function.GetChildren()[0]->GetReturnType());
		optional_ptr<Expression> body;
		if (function.GetChildren().size() == 2 &&
		    function.GetChildren()[1]->GetExpressionClass() == ExpressionClass::BOUND_LAMBDA) {
			body = function.GetChildren()[1]->Cast<BoundLambdaExpression>().LambdaExpr().get();
		} else if (function.BindInfo()) {
			body = function.BindInfo()->Cast<ListLambdaBindData>().lambda_expr.get();
		}
		auto suffix = body ? LambdaFieldSuffix(*body, element) : string();
		if (!suffix.empty()) {
			auto lineage = Resolve(*function.GetChildren()[0]);
			for (auto &item : lineage.direct) {
				if (!item.field.empty()) {
					item.field += "[]" + suffix;
				}
			}
			return lineage;
		}
	}
	BindingLineage lineage;
	for (auto &child : function.GetChildren()) {
		if (child->GetExpressionClass() == ExpressionClass::BOUND_LAMBDA) {
			// a lambda's body reads its parameters (the list's elements) and its captures
			auto &lambda = child->Cast<BoundLambdaExpression>();
			for (auto &capture : lambda.Captures()) {
				Merge(lineage, Resolve(*capture));
			}
			continue;
		}
		Merge(lineage, Resolve(*child));
	}
	return Transformed(std::move(lineage));
}

BindingLineage Walker::Resolve(Expression &expr) {
	switch (expr.GetExpressionClass()) {
	case ExpressionClass::BOUND_COLUMN_REF:
		return Lookup(expr.Cast<BoundColumnRefExpression>().Binding());
	case ExpressionClass::BOUND_CONSTANT:
	case ExpressionClass::BOUND_PARAMETER:
	case ExpressionClass::BOUND_DEFAULT:
	case ExpressionClass::BOUND_LAMBDA_REF:
		return BindingLineage();
	case ExpressionClass::BOUND_FUNCTION:
		return ResolveFunction(expr.Cast<BoundFunctionExpression>());
	case ExpressionClass::BOUND_CASE: {
		auto &bound_case = expr.Cast<BoundCaseExpression>();
		BindingLineage lineage;
		for (auto &check : bound_case.CaseChecks()) {
			for (auto &item : AsIndirect(Resolve(*check.when_expr), "CONDITIONAL")) {
				AddUnique(lineage.indirect, item);
			}
			Merge(lineage, Transformed(Resolve(*check.then_expr)));
		}
		if (bound_case.ElseExpression()) {
			Merge(lineage, Transformed(Resolve(*bound_case.ElseExpression())));
		}
		return lineage;
	}
	case ExpressionClass::BOUND_AGGREGATE: {
		auto &aggregate = expr.Cast<BoundAggregateExpression>();
		BindingLineage lineage;
		for (auto &child : aggregate.GetChildren()) {
			Merge(lineage, Resolve(*child));
		}
		for (auto &item : lineage.direct) {
			item.subtype = "AGGREGATION";
		}
		if (aggregate.GetFilter()) {
			for (auto &item : AsIndirect(Resolve(*aggregate.GetFilter()), "FILTER")) {
				AddUnique(lineage.indirect, item);
			}
		}
		return lineage;
	}
	case ExpressionClass::BOUND_WINDOW: {
		auto &window = expr.Cast<BoundWindowExpression>();
		BindingLineage lineage;
		for (auto &child : window.GetChildren()) {
			Merge(lineage, Resolve(*child));
		}
		for (auto &item : lineage.direct) {
			item.subtype = "AGGREGATION";
		}
		BindingLineage keys;
		for (auto &partition : window.Partitions()) {
			Merge(keys, Resolve(*partition));
		}
		for (auto &order : window.OrderBy()) {
			Merge(keys, Resolve(*order.expression));
		}
		for (auto &item : AsIndirect(keys, "WINDOW")) {
			AddUnique(lineage.indirect, item);
		}
		if (window.Filter()) {
			for (auto &item : AsIndirect(Resolve(*window.Filter()), "FILTER")) {
				AddUnique(lineage.indirect, item);
			}
		}
		return lineage;
	}
	case ExpressionClass::BOUND_SUBQUERY:
		// planned subqueries are joins by now; one left as an expression is not followed
		walk.approximate = true;
		return BindingLineage();
	default: {
		BindingLineage lineage;
		ExpressionIterator::EnumerateChildren(expr, [&](Expression &child) { Merge(lineage, Resolve(child)); });
		return Transformed(std::move(lineage));
	}
	}
}

void Walker::VisitGet(LogicalGet &get) {
	LineageDatasetKey key;
	if (!options.classify || !options.classify(get, key)) {
		key.kind = "function";
		key.name = get.function.GetName().GetIdentifierName();
		walk.approximate = true;
	}
	auto dataset = walk.DatasetIndex(key);
	auto &column_ids = get.GetColumnIds();
	for (idx_t i = 0; i < column_ids.size(); i++) {
		auto &column = column_ids[i];
		BindingLineage lineage;
		if (!column.IsRowIdColumn() && !column.IsVirtualColumn() && column.GetPrimaryIndex() < get.names.size()) {
			LineageContribution item;
			item.dataset = dataset;
			item.field = get.names[column.GetPrimaryIndex()].GetIdentifierName();
			item.type = DIRECT;
			item.subtype = "IDENTITY";
			lineage.direct.push_back(std::move(item));
		}
		Set(ColumnBinding(get.table_index, ProjectionIndex(i)), std::move(lineage));
	}
}

string Walker::TableColumnName(TableCatalogEntry &table, idx_t physical) {
	return table.GetColumns().GetColumn(PhysicalIndex(physical)).Name().GetIdentifierName();
}

void Walker::SetTarget(TableCatalogEntry &table, const string &operation) {
	walk.has_target = true;
	walk.target.kind = "physical";
	walk.target.catalog = table.ParentCatalog().GetName().GetIdentifierName();
	walk.target.schema = table.ParentSchema().name.GetIdentifierName();
	walk.target.name = table.name.GetIdentifierName();
	walk.target_operation = operation;
}

void Walker::VisitInsert(LogicalInsert &insert) {
	SetTarget(insert.table, "INSERT");
	if (insert.children.empty()) {
		// VALUES bound into the operator: constants, no sources - the columns are still written
		for (auto &column : insert.table.GetColumns().Physical()) {
			AddOutput(column.Name().GetIdentifierName(), BindingLineage());
		}
		return;
	}
	auto child_bindings = insert.children[0]->GetColumnBindings();
	auto column_count = insert.table.GetColumns().PhysicalColumnCount();
	for (idx_t physical = 0; physical < column_count; physical++) {
		BindingLineage lineage;
		// an empty map is the identity: the source's columns are in the table's order
		auto source = insert.column_index_map.empty()             ? physical
		              : physical < insert.column_index_map.size() ? insert.column_index_map[PhysicalIndex(physical)]
		                                                          : DConstants::INVALID_INDEX;
		if (source != DConstants::INVALID_INDEX && source < child_bindings.size()) {
			lineage = Lookup(child_bindings[source]);
		}
		AddOutput(TableColumnName(insert.table, physical), lineage);
	}
}

void Walker::VisitUpdate(LogicalUpdate &update) {
	SetTarget(update.table, "UPDATE");
	for (idx_t i = 0; i < update.columns.size() && i < update.expressions.size(); i++) {
		AddOutput(TableColumnName(update.table, update.columns[i].index), Resolve(*update.expressions[i]));
	}
}

void Walker::VisitMerge(LogicalMergeInto &merge) {
	SetTarget(merge.table, "MERGE");
	for (auto &entry : merge.actions) {
		for (auto &action : entry.second) {
			if (action->condition) {
				AddWhole(Resolve(*action->condition), "CONDITIONAL");
			}
			if (action->action_type == MergeActionType::MERGE_UPDATE) {
				for (idx_t i = 0; i < action->columns.size() && i < action->expressions.size(); i++) {
					AddOutput(TableColumnName(merge.table, action->columns[i].index), Resolve(*action->expressions[i]));
				}
			} else if (action->action_type == MergeActionType::MERGE_INSERT) {
				auto column_count = merge.table.GetColumns().PhysicalColumnCount();
				for (idx_t physical = 0; physical < column_count; physical++) {
					if (physical >= action->column_index_map.size()) {
						continue;
					}
					auto source = action->column_index_map[PhysicalIndex(physical)];
					if (source != DConstants::INVALID_INDEX && source < action->expressions.size()) {
						AddOutput(TableColumnName(merge.table, physical), Resolve(*action->expressions[source]));
					}
				}
			}
		}
	}
}

void Walker::Visit(LogicalOperator &op) {
	switch (op.type) {
	case LogicalOperatorType::LOGICAL_MATERIALIZED_CTE: {
		auto &cte = op.Cast<LogicalCTE>();
		Visit(*op.children[0]);
		ctes[cte.table_index.index] = op.children[0]->GetColumnBindings();
		for (idx_t i = 1; i < op.children.size(); i++) {
			Visit(*op.children[i]);
		}
		return;
	}
	case LogicalOperatorType::LOGICAL_RECURSIVE_CTE: {
		auto &cte = op.Cast<LogicalCTE>();
		Visit(*op.children[0]);
		auto base = op.children[0]->GetColumnBindings();
		ctes[cte.table_index.index] = base;
		Visit(*op.children[1]);
		auto recursive = op.children[1]->GetColumnBindings();
		for (idx_t i = 0; i < cte.column_count; i++) {
			BindingLineage lineage;
			if (i < base.size()) {
				Merge(lineage, Lookup(base[i]));
			}
			if (i < recursive.size()) {
				Merge(lineage, Lookup(recursive[i]));
			}
			Set(ColumnBinding(cte.table_index, ProjectionIndex(i)), std::move(lineage));
		}
		return;
	}
	default:
		break;
	}
	for (auto &child : op.children) {
		Visit(*child);
	}
	switch (op.type) {
	case LogicalOperatorType::LOGICAL_GET:
		VisitGet(op.Cast<LogicalGet>());
		break;
	case LogicalOperatorType::LOGICAL_PROJECTION: {
		auto &projection = op.Cast<LogicalProjection>();
		for (idx_t i = 0; i < projection.expressions.size(); i++) {
			Set(ColumnBinding(projection.table_index, ProjectionIndex(i)), Resolve(*projection.expressions[i]));
		}
		break;
	}
	case LogicalOperatorType::LOGICAL_AGGREGATE_AND_GROUP_BY: {
		auto &aggregate = op.Cast<LogicalAggregate>();
		for (idx_t i = 0; i < aggregate.groups.size(); i++) {
			auto lineage = Resolve(*aggregate.groups[i]);
			AddWhole(lineage, "GROUP_BY");
			Set(ColumnBinding(aggregate.group_index, ProjectionIndex(i)), std::move(lineage));
		}
		for (idx_t i = 0; i < aggregate.expressions.size(); i++) {
			Set(ColumnBinding(aggregate.aggregate_index, ProjectionIndex(i)), Resolve(*aggregate.expressions[i]));
		}
		break;
	}
	case LogicalOperatorType::LOGICAL_WINDOW: {
		auto &window = op.Cast<LogicalWindow>();
		for (idx_t i = 0; i < window.expressions.size(); i++) {
			Set(ColumnBinding(window.window_index, ProjectionIndex(i)), Resolve(*window.expressions[i]));
		}
		break;
	}
	case LogicalOperatorType::LOGICAL_FILTER:
		for (auto &expression : op.expressions) {
			AddWhole(Resolve(*expression), "FILTER");
		}
		break;
	case LogicalOperatorType::LOGICAL_COMPARISON_JOIN:
	case LogicalOperatorType::LOGICAL_DELIM_JOIN:
	case LogicalOperatorType::LOGICAL_ASOF_JOIN: {
		auto &join = op.Cast<LogicalComparisonJoin>();
		for (auto &condition : join.conditions) {
			if (condition.IsComparison()) {
				AddWhole(Resolve(condition.GetLHS()), "JOIN");
				AddWhole(Resolve(condition.GetRHS()), "JOIN");
			} else {
				AddWhole(Resolve(condition.GetJoinExpression()), "JOIN");
			}
		}
		break;
	}
	case LogicalOperatorType::LOGICAL_ANY_JOIN: {
		auto &join = op.Cast<LogicalAnyJoin>();
		if (join.condition) {
			AddWhole(Resolve(*join.condition), "JOIN");
		}
		break;
	}
	case LogicalOperatorType::LOGICAL_ORDER_BY:
		for (auto &order : op.Cast<LogicalOrder>().orders) {
			AddWhole(Resolve(*order.expression), "SORT");
		}
		break;
	case LogicalOperatorType::LOGICAL_TOP_N:
		for (auto &order : op.Cast<LogicalTopN>().orders) {
			AddWhole(Resolve(*order.expression), "SORT");
		}
		break;
	case LogicalOperatorType::LOGICAL_UNION:
	case LogicalOperatorType::LOGICAL_EXCEPT:
	case LogicalOperatorType::LOGICAL_INTERSECT: {
		auto &set_operation = op.Cast<LogicalSetOperation>();
		vector<vector<ColumnBinding>> children;
		for (auto &child : op.children) {
			children.push_back(child->GetColumnBindings());
		}
		for (idx_t i = 0; i < set_operation.column_count; i++) {
			BindingLineage lineage;
			for (idx_t c = 0; c < children.size(); c++) {
				if (i >= children[c].size()) {
					continue;
				}
				if (c > 0 && op.type != LogicalOperatorType::LOGICAL_UNION) {
					// EXCEPT / INTERSECT: the right side decides which rows stay, its values are not output
					AddWhole(Lookup(children[c][i]), "FILTER");
					continue;
				}
				Merge(lineage, Lookup(children[c][i]));
			}
			Set(ColumnBinding(set_operation.table_index, ProjectionIndex(i)), std::move(lineage));
		}
		break;
	}
	case LogicalOperatorType::LOGICAL_UNNEST: {
		auto &unnest = op.Cast<LogicalUnnest>();
		for (idx_t i = 0; i < unnest.expressions.size(); i++) {
			Set(ColumnBinding(unnest.unnest_index, ProjectionIndex(i)), Transformed(Resolve(*unnest.expressions[i])));
		}
		break;
	}
	case LogicalOperatorType::LOGICAL_CTE_REF: {
		auto &ref = op.Cast<LogicalCTERef>();
		auto definition = ctes.find(ref.cte_index.index);
		auto bound = ref.GetColumnBindings();
		for (idx_t i = 0; i < bound.size(); i++) {
			BindingLineage lineage;
			if (definition != ctes.end() && i < definition->second.size()) {
				lineage = Lookup(definition->second[i]);
			} else {
				walk.approximate = true;
			}
			Set(bound[i], std::move(lineage));
		}
		break;
	}
	case LogicalOperatorType::LOGICAL_INSERT:
		VisitInsert(op.Cast<LogicalInsert>());
		break;
	case LogicalOperatorType::LOGICAL_UPDATE:
		VisitUpdate(op.Cast<LogicalUpdate>());
		break;
	case LogicalOperatorType::LOGICAL_DELETE:
		SetTarget(op.Cast<LogicalDelete>().table, "DELETE");
		break;
	case LogicalOperatorType::LOGICAL_MERGE_INTO:
		VisitMerge(op.Cast<LogicalMergeInto>());
		break;
	case LogicalOperatorType::LOGICAL_CREATE_TABLE: {
		auto &create = op.Cast<LogicalCreateTable>();
		auto &base = create.info->Base();
		walk.has_target = true;
		walk.target.kind = "physical";
		auto &qualified = base.GetQualifiedName();
		walk.target.catalog = qualified.Catalog().GetIdentifierName();
		walk.target.schema = qualified.Schema().GetIdentifierName();
		walk.target.name = base.GetTableName().GetIdentifierName();
		walk.target_operation = "CREATE_TABLE_AS";
		if (!op.children.empty()) {
			auto child_bindings = op.children[0]->GetColumnBindings();
			idx_t i = 0;
			for (auto &column : base.columns.Logical()) {
				AddOutput(column.Name().GetIdentifierName(),
				          i < child_bindings.size() ? Lookup(child_bindings[i]) : BindingLineage());
				i++;
			}
		}
		break;
	}
	default: {
		// an operator that passes its child's bindings through needs nothing; one that makes new
		// bindings we do not know leaves them unresolved, and Lookup marks the walk approximate
		break;
	}
	}
}

void Walker::FinishRoot(LogicalOperator &root) {
	if (walk.has_target) {
		return;
	}
	auto root_bindings = root.GetColumnBindings();
	for (idx_t i = 0; i < root_bindings.size(); i++) {
		string name;
		if (i < options.output_names.size()) {
			name = options.output_names[i];
		} else if (root.type == LogicalOperatorType::LOGICAL_PROJECTION && i < root.expressions.size() &&
		           !root.expressions[i]->GetAlias().empty()) {
			name = root.expressions[i]->GetAlias().GetIdentifierName();
		} else {
			name = "col" + std::to_string(i);
		}
		AddOutput(name, Lookup(root_bindings[i]));
	}
}

} // namespace

LineageWalk WalkLineage(LogicalOperator &root, const LineageWalkOptions &options) {
	LineageWalk walk;
	Walker walker(walk, options);
	walker.Visit(root);
	walker.FinishRoot(root);
	return walk;
}

} // namespace acl
} // namespace duckdb
