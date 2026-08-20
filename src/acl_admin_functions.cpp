#include "acl_admin_functions.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/helper.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/execution/expression_executor_state.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/planner/expression/bound_function_expression.hpp"

namespace duckdb {
namespace acl {
namespace {

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

} // namespace

void RegisterAclAdminFunctions(ExtensionLoader &loader, shared_ptr<PolicyStore> store) {
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

} // namespace acl
} // namespace duckdb
