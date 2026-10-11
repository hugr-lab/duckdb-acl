// spec 121: one plan for the Flight door's own statement.
//
// At our pin duckdb's optimizer marks every prepared statement that reads a data source `always_require_rebind`
// ("optimizers can embed the current database state in the executable plan"), so an Execute after the Prepare binds
// and optimizes the statement again. Every statement under a principal reads the policy store, and the door prepares
// at GetFlightInfo / CreatePreparedStatement (the schema, an early refusal) and executes at DoGet - two plans for what
// is not a prepared statement in the classic sense. So the door, and only the door, takes the flag off its own
// statement's prepare (duckdb would not keep the plan otherwise) and keeps the plan for the FIRST execution of a
// READ-ONLY statement that comes within a short window of its prepare: the plan
// is as fresh as a statement planned at GetFlightInfo and run at once (Flight SQL's own "GetFlightInfo: execute the
// query"). A re-execution - a client reusing its prepared statement - and a late first one rebind as duckdb wants;
// nothing global changes (the CLI, the gateway path, quack, a user's PREPARE keep duckdb's behaviour).
#pragma once

#include "duckdb/main/client_context.hpp"
#include "duckdb/main/client_data.hpp"
#include "duckdb/main/prepared_statement.hpp"
#include "duckdb/main/prepared_statement_data.hpp"

#include "duckdb/main/database.hpp"

#include <atomic>
#include <chrono>

namespace duckdb {
namespace acl {

//! How long after its prepare a door statement's first execution keeps the prepare's plan
constexpr std::chrono::seconds DOOR_PLAN_WINDOW {10};

//! Around the door's own Prepare: duckdb drops a prepared plan it must rebind anyway, so the flag has to come off
//! while the prepare is optimized (the door's optimizer extension, RegisterDoorPlanOnce) - for a read-only statement
//! whose flag is the data-source rule's (the LogicalPrepare still has its plan; a flag the binder set for a reason of
//! meaning - a function consistent within a query, a table function that cannot be cached - leaves no plan to keep).
//! Kept(): whether this prepare kept its plan for the door's first execution.
class DoorPrepareScope {
public:
	explicit DoorPrepareScope(ClientContext &context);
	~DoorPrepareScope();
	DoorPrepareScope(const DoorPrepareScope &) = delete;
	DoorPrepareScope &operator=(const DoorPrepareScope &) = delete;
	bool Kept() const;

private:
	ClientContext *previous;
	bool previous_kept;
};

//! Register the optimizer extension DoorPrepareScope relies on (once per instance, with the door)
void RegisterDoorPlanOnce(DatabaseInstance &db);

//! For one execution of a statement whose prepare kept its plan: the first one, soon after its prepare, runs that
//! plan; afterwards - or for a late first one, before it - the flag is back, so duckdb rebinds as it wants
class DoorPlanOnce {
public:
	DoorPlanOnce(ClientContext &context, PreparedStatement &statement, bool kept, bool first,
	             std::chrono::steady_clock::time_point prepared_at, std::atomic<int64_t> &counted) {
		if (!kept || statement.HasError()) {
			return;
		}
		auto &statements = ClientData::Get(context).prepared_statements;
		auto entry = statements.find(Identifier(statement.GetName()));
		if (entry == statements.end() || !entry->second) {
			return;
		}
		if (first && std::chrono::steady_clock::now() - prepared_at <= DOOR_PLAN_WINDOW) {
			data = entry->second; // the prepare's plan, this once
			counted++;
		} else {
			entry->second->properties.always_require_rebind = true; // a late or a repeated execution rebinds
		}
	}
	~DoorPlanOnce() {
		if (data) {
			data->properties.always_require_rebind = true;
		}
	}
	DoorPlanOnce(const DoorPlanOnce &) = delete;
	DoorPlanOnce &operator=(const DoorPlanOnce &) = delete;

private:
	shared_ptr<PreparedStatementData> data;
};

} // namespace acl
} // namespace duckdb
