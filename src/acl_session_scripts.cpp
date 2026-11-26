//===----------------------------------------------------------------------===//
// acl_session_scripts.cpp - spec 181: a session's scripts, run as the node when it opens
//
// What the doors share: which scripts a session runs (the store resolves and caches them), the variables set before
// them, running each on the session's own connection, and what a failure does. Plus the policy bundle's listing,
// acl_session_scripts(role[, group]) - platform.session_scripts.
//===----------------------------------------------------------------------===//

#include "acl_session_scripts.hpp"
#include "acl_policy_catalog.hpp"
#include "duckdb/common/error_data.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/exception/binder_exception.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/main/connection.hpp"
#include "duckdb/main/valid_checker.hpp"
#include "duckdb/transaction/meta_transaction.hpp"
#include "duckdb/main/extension/extension_loader.hpp"

namespace duckdb {
namespace acl {

namespace {

//! An error's class as the audit keeps it - its type's name, never its message (spec 136's rule)
string ErrorClass(const ErrorData &error) {
	return Exception::ExceptionTypeToString(error.Type());
}

string VarcharList(const vector<string> &items) {
	vector<Value> values;
	for (auto &item : items) {
		values.emplace_back(item);
	}
	return Value::LIST(LogicalType::VARCHAR, std::move(values)).ToSQLString() + "::VARCHAR[]";
}

string VarcharOrNull(const string &text) {
	return text.empty() ? string("NULL::VARCHAR") : Value(text).ToSQLString();
}

//! A script hands the client no open transaction: whatever it left open is committed after it ran, and an invalidated
//! one (a statement of it failed), or a COMMIT that fails, is rolled back and is that script's failure. So a client
//! never starts inside a transaction it did not begin - its writes never land in one a move would lose, and the
//! connection a CONTINUE serves always answers. Returns '' when the connection is in autocommit after it, else the
//! failure's class.
string SettleTransaction(Connection &con) {
	if (con.IsAutoCommit()) {
		return string();
	}
	auto rollback = [&]() {
		try {
			if (!con.IsAutoCommit()) {
				con.Query("ROLLBACK");
			}
		} catch (...) { // NOLINT: the connection is the session's; what it refuses next is the client's to see
		}
	};
	auto &transaction = con.context->transaction;
	if (transaction.HasActiveTransaction() && ValidChecker::IsInvalidated(transaction.ActiveTransaction())) {
		rollback();
		return Exception::ExceptionTypeToString(ExceptionType::TRANSACTION);
	}
	auto commit = con.Query("COMMIT");
	if (commit->HasError()) {
		auto error_class = ErrorClass(commit->GetErrorObject());
		rollback();
		return error_class;
	}
	if (!con.IsAutoCommit()) {
		rollback();
		return Exception::ExceptionTypeToString(ExceptionType::TRANSACTION);
	}
	return string();
}

} // namespace

bool SessionScriptsOf(PolicyStore &store, const string &handle, const string &door, vector<SessionScript> &scripts) {
	scripts.clear();
	PolicyStore::SessionRef ref;
	if (!store.SessionRefOf(handle, ref)) {
		return true;
	}
	try {
		scripts = store.SessionScriptsFor(ref.principal.roles, store.SessionScriptGroup(ref.limits));
		return true;
	} catch (std::exception &ex) {
		// the policy source did not answer: a session whose scripts are unknown is not served as if it had none
		store.AuditSessionScript(door, handle, nullptr, ErrorClass(ErrorData(ex)), "refused");
		return false;
	}
}

bool RunSessionScripts(PolicyStore &store, Connection &con, const string &handle, const vector<SessionScript> &scripts,
                       const string &door) {
	if (scripts.empty()) {
		return true;
	}
	PolicyStore::SessionRef ref;
	if (!store.SessionRefOf(handle, ref)) {
		return false; // ended while it was being prepared
	}
	try {
		// what a script branches on: only the principal's own roles and groups, and the group its first layer is
		auto variables = "SET VARIABLE acl_session_roles = " + VarcharList(ref.principal.roles) +
		                 "; SET VARIABLE acl_session_groups = " + VarcharList(ref.limits.groups) +
		                 "; SET VARIABLE acl_session_group = " + VarcharOrNull(store.SessionScriptGroup(ref.limits)) +
		                 "; SET VARIABLE acl_session_subject = " + VarcharOrNull(ref.principal.subject);
		auto set = con.Query(variables);
		if (set->HasError()) {
			store.AuditSessionScript(door, handle, nullptr, ErrorClass(set->GetErrorObject()), "refused");
			return false;
		}
		for (auto &script : scripts) {
			// as the node: unprefixed, as written - the override leaves a text that is no ACL statement alone
			auto result = con.Query(script.sql);
			auto error_class = result->HasError() ? ErrorClass(result->GetErrorObject()) : string();
			// what it left open is committed - or, invalidated or refused at COMMIT, rolled back and its failure
			auto settled = SettleTransaction(con);
			if (error_class.empty()) {
				error_class = settled;
			}
			if (error_class.empty()) {
				// SQL that ran unprefixed leaves no statement nor profile event: this is its trace
				store.AuditSessionScript(door, handle, &script, string(), "script_ran");
				continue;
			}
			store.AuditSessionScript(door, handle, &script, error_class,
			                         script.fail_session ? "refused" : "script_failed");
			if (script.fail_session) {
				return false;
			}
		}
		return true;
	} catch (std::exception &ex) {
		store.AuditSessionScript(door, handle, nullptr, ErrorClass(ErrorData(ex)), "refused");
		return false;
	}
}

bool PrepareSession(PolicyStore &store, Connection &con, const string &handle, const string &door) {
	vector<SessionScript> scripts;
	if (!SessionScriptsOf(store, handle, door, scripts)) {
		return false;
	}
	return RunSessionScripts(store, con, handle, scripts, door);
}

//===--------------------------------------------------------------------===//
// acl_session_scripts(role[, group]) - what a session of the role runs on a node of the group
//===--------------------------------------------------------------------===//

namespace {

struct ScriptsInfo : TableFunctionInfo {
	explicit ScriptsInfo(shared_ptr<PolicyStore> store_p) : store(std::move(store_p)) {
	}
	shared_ptr<PolicyStore> store;
};

struct ScriptsBind : TableFunctionData {
	shared_ptr<PolicyStore> store;
	vector<Value> arguments;
};

struct ScriptsState : GlobalTableFunctionState {
	vector<vector<Value>> rows;
	idx_t next = 0;
};

unique_ptr<FunctionData> ScriptsBindFn(ClientContext &, TableFunctionBindInput &input, vector<LogicalType> &types,
                                       vector<Identifier> &names) {
	auto bind = make_uniq<ScriptsBind>();
	bind->store = input.info->Cast<ScriptsInfo>().store;
	bind->arguments = input.inputs;
	names.push_back(Identifier("pos"));
	types.push_back(LogicalType::INTEGER);
	for (auto name : {"level", "group", "role", "on_error", "sql"}) {
		names.push_back(Identifier(name));
		types.push_back(LogicalType::VARCHAR);
	}
	return std::move(bind);
}

unique_ptr<GlobalTableFunctionState> ScriptsInit(ClientContext &, TableFunctionInitInput &input) {
	auto &bind = input.bind_data->Cast<ScriptsBind>();
	auto &store = *bind.store;
	if (!store.catalog || store.catalog->FunctionMode()) {
		throw BinderException("acl: acl_session_scripts needs a policy catalog (acl_use_db)");
	}
	auto text = [&](idx_t index) {
		return index < bind.arguments.size() && !bind.arguments[index].IsNull() ? bind.arguments[index].ToString()
		                                                                        : string();
	};
	auto role = text(0);
	if (role.empty()) {
		throw BinderException("acl_session_scripts(role[, group]): name a role");
	}
	case_insensitive_set_t known;
	store.catalog->KnownRoles({role}, known);
	if (known.empty()) {
		throw BinderException("acl admin: role \"%s\" does not exist", role);
	}
	string group;
	if (bind.arguments.size() > 1) {
		group = text(1);
	} else {
		// the group a session of the role would take: the node's, else the role's own (spec 096's placement aside)
		Principal principal;
		principal.roles = {role};
		group = store.SessionScriptGroup(store.ResolveResourceLimits(principal));
	}
	auto state = make_uniq<ScriptsState>();
	int32_t pos = 0;
	for (auto &script : store.SessionScriptsFor({role}, group)) {
		state->rows.push_back({Value::INTEGER(++pos), Value(script.level),
		                       script.group.empty() ? Value(LogicalType::VARCHAR) : Value(script.group),
		                       script.role.empty() ? Value(LogicalType::VARCHAR) : Value(script.role),
		                       Value(script.fail_session ? "fail" : "continue"), Value(script.sql)});
	}
	return std::move(state);
}

void ScriptsScan(ClientContext &, TableFunctionInput &data, DataChunk &output) {
	auto &state = data.global_state->Cast<ScriptsState>();
	idx_t count = 0;
	while (state.next < state.rows.size() && count < STANDARD_VECTOR_SIZE) {
		auto &row = state.rows[state.next++];
		for (idx_t c = 0; c < row.size(); c++) {
			output.data[c].SetValue(count, row[c]);
		}
		count++;
	}
	output.SetChildCardinality(count);
}

} // namespace

void RegisterAclSessionScripts(ExtensionLoader &loader, const shared_ptr<PolicyStore> &store) {
	TableFunctionSet set((Identifier("acl_session_scripts")));
	for (idx_t arity : {1, 2}) {
		TableFunction function(Identifier("acl_session_scripts"), vector<LogicalType>(arity, LogicalType::VARCHAR),
		                       ScriptsScan, ScriptsBindFn, ScriptsInit);
		function.function_info = make_shared_ptr<ScriptsInfo>(store);
		set.AddFunction(function);
	}
	loader.RegisterFunction(set);
}

} // namespace acl
} // namespace duckdb
