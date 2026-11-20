// spec 179: what a management statement answers - `(ok BOOLEAN, message VARCHAR)`, whatever its call returns.

#include "acl_mgmt_answer.hpp"

#include "acl_door_common.hpp"

#include "duckdb/common/string_util.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/parser/expression/constant_expression.hpp"
#include "duckdb/parser/expression/function_expression.hpp"
#include "duckdb/parser/expression/star_expression.hpp"
#include "duckdb/parser/tableref/emptytableref.hpp"
#include "duckdb/parser/tableref/subqueryref.hpp"
#include "duckdb/parser/query_node/select_node.hpp"
#include "duckdb/parser/statement/select_statement.hpp"
#include "duckdb/planner/expression.hpp"

namespace duckdb {
namespace acl {

namespace {

//! The words of a call that answers false: what did not happen
string FalseMessage(const string &function) {
	if (function == "acl_resume") {
		return "the node was not draining";
	}
	if (function == "acl_session_kill" || function == "acl_session_audit_level" || function == "acl_session_profile") {
		return "no session has that id";
	}
	return "nothing changed";
}

//! The words of a call that answers a count
string CountMessage(const string &function, int64_t count) {
	auto n = std::to_string(count);
	if (function == "acl_drain") {
		return n + (count == 1 ? " session still open" : " sessions still open");
	}
	if (function == "acl_repair_relation") {
		return n + (count == 1 ? " entry changed" : " entries changed");
	}
	if (function == "acl_refresh_schema") {
		return n + (count == 1 ? " object refreshed" : " objects refreshed");
	}
	if (function == "acl_refresh_schema_objects") {
		return n + (count == 1 ? " record added or removed" : " records added or removed");
	}
	return n;
}

bool IsOkOrMessage(const Identifier &name) {
	return StringUtil::CIEquals(name.GetIdentifierName(), "ok") ||
	       StringUtil::CIEquals(name.GetIdentifierName(), "message");
}

LogicalType AnswerType(const LogicalType &value) {
	child_list_t<LogicalType> children {{"ok", LogicalType::BOOLEAN}, {"message", LogicalType::VARCHAR}};
	if (value.id() == LogicalTypeId::STRUCT) {
		for (auto &child : StructType::GetChildTypes(value)) {
			if (!IsOkOrMessage(child.first)) {
				children.push_back(child);
			}
		}
	}
	return LogicalType::STRUCT(std::move(children));
}

//! A value read as ok: NULL, or one that is no BOOLEAN, is not ok - never a throw (the write has committed)
bool Truth(const Value &value) {
	if (value.IsNull()) {
		return false;
	}
	auto as_bool = value.DefaultTryCastAs(LogicalType::BOOLEAN);
	return as_bool && !as_bool->IsNull() && as_bool->GetValue<bool>();
}

//! Whether the call did what it said - the platform part notes only after such a call
bool Succeeded(const Value &value) {
	if (value.IsNull()) {
		return false;
	}
	if (value.type().id() == LogicalTypeId::BOOLEAN) {
		return value.GetValue<bool>();
	}
	if (value.type().id() == LogicalTypeId::STRUCT) {
		auto &types = StructType::GetChildTypes(value.type());
		auto &values = StructValue::GetChildren(value);
		for (idx_t i = 0; i < types.size(); i++) {
			if (StringUtil::CIEquals(types[i].first.GetIdentifierName(), "ok")) {
				return Truth(values[i]);
			}
		}
	}
	return true;
}

unique_ptr<FunctionData> AnswerBind(BindScalarFunctionInput &input) {
	auto &arguments = input.GetArguments();
	if (arguments.size() < 2) {
		throw InvalidInputException("acl_answer: a function name and its value are required");
	}
	input.GetBoundFunction().SetReturnType(AnswerType(arguments[1]->GetReturnType()));
	return nullptr;
}

void AnswerFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &store = StoreOf(state);
	auto &context = state.GetContext();
	auto &type = args.data[1].GetType();
	for (idx_t row = 0; row < args.size(); row++) {
		auto function = args.data[0].GetValue(row);
		auto name = function.IsNull() ? string() : function.ToString();
		auto value = args.data[1].GetValue(row);
		string note;
		if (Succeeded(value)) {
			vector<Value> call_args;
			for (idx_t c = 2; c < args.ColumnCount(); c++) {
				call_args.push_back(args.data[c].GetValue(row));
			}
			try {
				note = store.ManagementNote(context, name, call_args);
			} catch (std::exception &) {
				// the write has committed on the store's own connection: a note that fails is dropped, never the
				// answer of a change that stands
				note.clear();
			}
		}
		result.SetValue(row, ManagementAnswer(name, value, type, note));
	}
}

} // namespace

Value ManagementAnswer(const string &function, const Value &value, const LogicalType &type, const string &note) {
	Value ok = Value::BOOLEAN(true);
	string message;
	bool has_message = false;
	child_list_t<Value> rest;
	if (value.IsNull()) {
		ok = Value::BOOLEAN(false);
		message = "the call answered nothing";
		has_message = true;
		if (type.id() == LogicalTypeId::STRUCT) {
			for (auto &child : StructType::GetChildTypes(type)) {
				if (!IsOkOrMessage(child.first)) {
					rest.emplace_back(child.first, Value(child.second));
				}
			}
		}
	} else if (type.id() == LogicalTypeId::BOOLEAN) {
		ok = value;
		if (!value.GetValue<bool>()) {
			message = FalseMessage(function);
			has_message = true;
		}
	} else if (type.id() == LogicalTypeId::STRUCT) {
		auto &types = StructType::GetChildTypes(type);
		auto &values = StructValue::GetChildren(value);
		for (idx_t i = 0; i < types.size(); i++) {
			auto &field = types[i].first.GetIdentifierName();
			if (StringUtil::CIEquals(field, "ok")) {
				ok = Value::BOOLEAN(Truth(values[i]));
			} else if (StringUtil::CIEquals(field, "message")) {
				if (!values[i].IsNull()) {
					message = values[i].ToString();
					has_message = !message.empty();
				}
			} else {
				rest.emplace_back(types[i].first, values[i]);
			}
		}
	} else if (type.IsIntegral()) {
		auto count = value.DefaultTryCastAs(LogicalType::BIGINT);
		message = count && !count->IsNull() ? CountMessage(function, count->GetValue<int64_t>()) : value.ToString();
		has_message = true;
	} else {
		message = value.ToString();
		has_message = true;
	}
	if (!note.empty()) {
		message = has_message ? message + "; " + note : note;
		has_message = true;
	}
	child_list_t<Value> children {{"ok", ok}, {"message", has_message ? Value(message) : Value(LogicalType::VARCHAR)}};
	for (auto &field : rest) {
		children.push_back(std::move(field));
	}
	return Value::STRUCT(std::move(children));
}

void AnswerManagement(vector<unique_ptr<SQLStatement>> &statements) {
	for (auto &statement : statements) {
		if (!statement || statement->type != StatementType::SELECT_STATEMENT) {
			continue;
		}
		auto &node = *statement->Cast<SelectStatement>().node;
		if (node.type != QueryNodeType::SELECT_NODE) {
			continue;
		}
		auto &select = node.Cast<SelectNode>();
		bool from_nothing = !select.from_table || select.from_table->type == TableReferenceType::EMPTY_FROM;
		if (!from_nothing || select.select_list.size() != 1 ||
		    select.select_list[0]->GetExpressionClass() != ExpressionClass::FUNCTION) {
			continue; // a table call answers its rows (CHECK, a platform read)
		}
		auto &call = select.select_list[0]->Cast<FunctionExpression>();
		auto name = call.FunctionName().GetIdentifierName();
		vector<unique_ptr<ParsedExpression>> children;
		children.push_back(ConstantExpression::FromValue(Value(name)));
		auto inner = call.Copy();
		inner->ClearAlias();
		children.push_back(std::move(inner));
		for (auto &argument : call.GetArguments()) {
			// the note reads the arguments again: a constant or a parameter is the value the call read; anything
			// else (no form writes one today) would be evaluated a second time, so the note gets NULL for it
			auto &expression = argument.GetExpression();
			auto kind = expression.GetExpressionClass();
			children.push_back(kind == ExpressionClass::CONSTANT || kind == ExpressionClass::PARAMETER
			                       ? expression.Copy()
			                       : ConstantExpression::FromValue(Value()));
		}
		// `SELECT __acl_answer.* FROM (SELECT acl_answer(…) AS __acl_answer)`: the struct's star reads the column
		// once - an `unnest(acl_answer(…))` is one struct_extract per field, each running the call
		auto answer = make_uniq<FunctionExpression>(Identifier("acl_answer"), std::move(children));
		answer->SetAlias(Identifier("__acl_answer"));
		auto inner_node = make_uniq<SelectNode>();
		inner_node->select_list.push_back(std::move(answer));
		inner_node->from_table = make_uniq<EmptyTableRef>();
		auto inner_statement = make_uniq<SelectStatement>();
		inner_statement->node = std::move(inner_node);
		select.select_list[0] = make_uniq<StarExpression>(Identifier("__acl_answer"));
		select.from_table = make_uniq<SubqueryRef>(std::move(inner_statement), Identifier("__acl_call"));
	}
}

void RegisterAclAnswer(ExtensionLoader &loader, const shared_ptr<PolicyStore> &store) {
	ScalarFunction function(Identifier("acl_answer"), {LogicalType::VARCHAR, LogicalType::ANY}, LogicalType::ANY,
	                        AnswerFunc, AnswerBind, nullptr, nullptr, LogicalType::ANY);
	MarkAclScalar(function, store);
	function.SetNullHandling(FunctionNullHandling::SPECIAL_HANDLING);
	loader.RegisterFunction(function);
}

} // namespace acl
} // namespace duckdb
