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
#include "duckdb/common/operator/cast_operators.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/main/connection.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/statement_iterator.hpp"
#include "duckdb/main/valid_checker.hpp"

#include <atomic>
#include <chrono>
#include <thread>
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

//! What a script branches on (spec 181): only the principal's own roles and groups, and the group its first layer is
string VariablesSql(const vector<string> &roles, const vector<string> &groups, const string &group,
                    const string &subject) {
	return "SET VARIABLE acl_session_roles = " + VarcharList(roles) +
	       "; SET VARIABLE acl_session_groups = " + VarcharList(groups) +
	       "; SET VARIABLE acl_session_group = " + VarcharOrNull(group) +
	       "; SET VARIABLE acl_session_subject = " + VarcharOrNull(subject);
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
		auto set = con.Query(VariablesSql(ref.principal.roles, ref.limits.groups, store.SessionScriptGroup(ref.limits),
		                                  ref.principal.subject));
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

//===--------------------------------------------------------------------===//
// spec 183: acl_try_session_script(group, role, sql[, on_error[, session_role[, session_group]]]) - what a session
// would run with the edited script in its place, run on a connection made for the trial and dropped after
//===--------------------------------------------------------------------===//

namespace {

constexpr const char *TRY_FN = "acl_try_session_script";

//! a layer's place in the run order (spec 181): the group's, then each role's, then each grant's
int Layer(const string &level) {
	return level == "group" ? 0 : level == "role" ? 1 : 2;
}

//! the byte `offset` of `text` as a line and a column in characters, both from 1
void LineColumn(const string &text, idx_t offset, int32_t &line, int32_t &column) {
	line = 1;
	column = 1;
	for (idx_t i = 0; i < text.size() && i < offset; i++) {
		auto c = static_cast<unsigned char>(text[i]);
		if (c == '\n') {
			line++;
			column = 1;
		} else if ((c & 0xC0) != 0x80) {
			column++;
		}
	}
}

//! A script's run in a trial: its failure's class and message, and where in the text (none when it ran)
struct ScriptRun {
	string error_class;
	string message;
	optional_idx offset;
};

//! Run a script as a session runs it - duckdb's own loop, each statement parsed after the one before it ran (a LOAD may
//! bring the grammar of the next) - one statement at a time, so a failure says where: a parse error at its own
//! position, any other at the start of the statement that failed. The connection's settings are left as they are: on
//! a platform node the configuration is locked after the boot.
ScriptRun RunScript(Connection &con, const string &sql) {
	ScriptRun run;
	try {
		auto statements = con.context->IterateStatements(sql);
		idx_t cursor = 0;
		bool more = statements.Peek();
		while (more) {
			auto statement = statements.GetStatementForExecution();
			more = statements.HasMore();
			if (!statement) {
				continue;
			}
			// the parser hands each statement its own text, located from 0: found in the script after the one before
			auto found = sql.find(statement->query, cursor);
			idx_t start = found == string::npos ? cursor : found;
			cursor = start + statement->query.size();
			while (start < sql.size() && StringUtil::CharacterIsSpace(sql[start])) {
				start++;
			}
			auto result = con.Query(std::move(statement));
			if (result->HasError()) {
				auto &error = result->GetErrorObject();
				run.error_class = Exception::ExceptionTypeToString(error.Type());
				run.message = error.RawMessage();
				run.offset = start;
				return run;
			}
		}
	} catch (std::exception &ex) {
		// the parser's: its position is still its own, read before any formatting
		ErrorData error(ex);
		run.error_class = Exception::ExceptionTypeToString(error.Type());
		run.message = error.RawMessage();
		auto position = error.ExtraInfo().find("position");
		idx_t offset = 0;
		if (position != error.ExtraInfo().end() && TryCast::Operation(string_t(position->second), offset)) {
			run.offset = offset;
		}
	}
	return run;
}

Value TextOrNull(const string &text) {
	return text.empty() ? Value(LogicalType::VARCHAR) : Value(text);
}

Value IntOrNull(int32_t n) {
	return n > 0 ? Value::INTEGER(n) : Value(LogicalType::INTEGER);
}

struct TryInfo : TableFunctionInfo {
	explicit TryInfo(shared_ptr<PolicyStore> store_p) : store(std::move(store_p)) {
	}
	shared_ptr<PolicyStore> store;
};

unique_ptr<FunctionData> TryBindFn(ClientContext &, TableFunctionBindInput &input, vector<LogicalType> &types,
                                   vector<Identifier> &names) {
	auto bind = make_uniq<ScriptsBind>();
	bind->store = input.info->Cast<TryInfo>().store;
	bind->arguments = input.inputs;
	auto add = [&](const char *name, const LogicalType &type) {
		names.push_back(Identifier(name));
		types.push_back(type);
	};
	add("pos", LogicalType::INTEGER);
	for (auto name : {"level", "group", "role", "on_error"}) {
		add(name, LogicalType::VARCHAR);
	}
	add("edited", LogicalType::BOOLEAN);
	add("ok", LogicalType::BOOLEAN);
	add("error_class", LogicalType::VARCHAR);
	add("message", LogicalType::VARCHAR);
	add("line", LogicalType::INTEGER);
	add("column", LogicalType::INTEGER);
	return std::move(bind);
}

unique_ptr<GlobalTableFunctionState> TryInit(ClientContext &context, TableFunctionInitInput &input) {
	auto &bind = input.bind_data->Cast<ScriptsBind>();
	auto &store = *bind.store;
	if (!store.catalog || store.catalog->FunctionMode()) {
		throw BinderException("acl: %s needs a policy catalog (acl_use_db)", TRY_FN);
	}
	auto text = [&](idx_t index) {
		return index < bind.arguments.size() && !bind.arguments[index].IsNull() ? bind.arguments[index].ToString()
		                                                                        : string();
	};
	auto group = text(0);
	auto role = text(1);
	auto sql = text(2);
	auto on_error = StringUtil::Lower(text(3).empty() ? string("fail") : text(3));
	if (on_error != "fail" && on_error != "continue") {
		throw InvalidInputException("%s: on_error is fail or continue, got \"%s\"", TRY_FN, on_error);
	}
	// the owner exists, a grant's binding too - in the writer's words
	store.CatalogRequireScriptOwner(group, role, TRY_FN);
	if (sql.empty()) {
		throw InvalidInputException("%s: the script is empty", TRY_FN);
	}
	auto session_role = text(4).empty() ? role : text(4);
	if (!session_role.empty()) {
		case_insensitive_set_t known;
		store.catalog->KnownRoles({session_role}, known);
		if (known.empty()) {
			throw BinderException("acl admin: role \"%s\" does not exist", session_role);
		}
	}
	Principal principal;
	if (!session_role.empty()) {
		principal.roles = {session_role};
	}
	auto limits = store.ResolveResourceLimits(principal);
	auto session_group = text(5).empty() ? group : text(5);
	if (!text(5).empty()) {
		store.CatalogRequireScriptOwner(session_group, string(), TRY_FN);
	}
	if (session_group.empty()) {
		session_group = store.SessionScriptGroup(limits);
	}
	// the edited script must be one this session runs
	SessionScript edited;
	edited.level = !group.empty() && !role.empty() ? "grant" : !group.empty() ? "group" : "role";
	edited.group = group;
	edited.role = role;
	edited.sql = sql;
	edited.fail_session = on_error == "fail";
	if ((!role.empty() && role != session_role) || (!group.empty() && group != session_group)) {
		throw InvalidInputException("%s: a session of role \"%s\" on a node of group \"%s\" does not run the %s's "
		                            "script - name a session_role / session_group it runs for",
		                            TRY_FN, session_role, session_group, edited.level);
	}
	// the session's scripts as the policy resolves them, the edited one in its place
	auto scripts = store.SessionScriptsFor(principal.roles, session_group);
	auto place = scripts.end();
	bool replaced = false;
	for (auto it = scripts.begin(); it != scripts.end(); ++it) {
		if (it->level == edited.level && it->group == edited.group && it->role == edited.role) {
			*it = edited;
			place = it;
			replaced = true;
			break;
		}
		if (place == scripts.end() &&
		    (Layer(it->level) > Layer(edited.level) || (it->level == edited.level && it->role > edited.role))) {
			place = it;
		}
	}
	if (!replaced) {
		place = scripts.insert(place, edited);
	}
	auto edited_index = idx_t(place - scripts.begin());

	auto state = make_uniq<ScriptsState>();
	// a connection of the node made for the trial, closed when this returns: what the scripts set on it ends with it
	Connection con(DatabaseInstance::GetDatabase(context));
	vector<string> groups = session_group.empty() ? limits.groups : vector<string> {session_group};
	auto set = con.Query(VariablesSql(principal.roles, groups, session_group, string()));
	if (set->HasError()) {
		set->ThrowError();
	}
	// the caller's cancel reaches the trial's connection: a script that hangs (a remote source) ends with the call
	std::atomic<bool> done {false};
	std::thread watcher([&]() {
		while (!done.load()) {
			if (context.IsInterrupted()) {
				con.Interrupt();
				return;
			}
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
		}
	});
	struct Join {
		std::atomic<bool> &done;
		std::thread &watcher;
		~Join() {
			done.store(true);
			watcher.join();
		}
	} join {done, watcher};
	string refused_by;
	for (idx_t i = 0; i < scripts.size(); i++) {
		context.InterruptCheck();
		auto &script = scripts[i];
		auto run = RunScript(con, script.sql);
		auto &error_class = run.error_class;
		auto &message = run.message;
		int32_t line = 0;
		int32_t column = 0;
		if (run.offset.IsValid()) {
			LineColumn(script.sql, run.offset.GetIndex(), line, column);
		}
		// what it left open is committed, or rolled back and its failure - as a session settles it
		auto settled = SettleTransaction(con);
		if (error_class.empty() && !settled.empty()) {
			error_class = settled;
			message = "the transaction it left open could not be committed";
		}
		state->rows.push_back({Value::INTEGER(int32_t(i + 1)), Value(script.level), TextOrNull(script.group),
		                       TextOrNull(script.role), Value(script.fail_session ? "fail" : "continue"),
		                       Value::BOOLEAN(i == edited_index), Value::BOOLEAN(error_class.empty()),
		                       TextOrNull(error_class), TextOrNull(message), IntOrNull(line), IntOrNull(column)});
		if (!error_class.empty() && script.fail_session) {
			refused_by = script.level;
			break;
		}
	}
	auto null_text = Value(LogicalType::VARCHAR);
	state->rows.push_back({Value(LogicalType::INTEGER), Value("session"), TextOrNull(session_group),
	                       TextOrNull(session_role), null_text, Value::BOOLEAN(false),
	                       Value::BOOLEAN(refused_by.empty()), null_text,
	                       Value(refused_by.empty() ? string("served") : "refused by the " + refused_by + " script"),
	                       Value(LogicalType::INTEGER), Value(LogicalType::INTEGER)});
	return std::move(state);
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

	TableFunctionSet trial((Identifier(TRY_FN)));
	for (idx_t arity : {3, 4, 5, 6}) {
		TableFunction function(Identifier(TRY_FN), vector<LogicalType>(arity, LogicalType::VARCHAR), ScriptsScan,
		                       TryBindFn, TryInit);
		function.function_info = make_shared_ptr<TryInfo>(store);
		trial.AddFunction(function);
	}
	loader.RegisterFunction(trial);
}

} // namespace acl
} // namespace duckdb
