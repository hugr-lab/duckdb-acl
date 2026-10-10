//===----------------------------------------------------------------------===//
// acl_profile.cpp - spec 074: the execution profile
//===----------------------------------------------------------------------===//
#include "acl_profile.hpp"
#include "acl_lineage.hpp"
#include "acl_session_hooks.hpp"

#include "acl_audit_pipeline.hpp"
#include "acl_policy.hpp"

#include "duckdb/common/enums/physical_operator_type.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/tree_renderer.hpp"
#include "duckdb/common/tree_renderer/base_tree_renderer.hpp"
#include "duckdb/main/client_config.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/client_context_state.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/main/connection_manager.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/main/extension_callback_manager.hpp"
#include "duckdb/main/profiler/profiling_node.hpp"
#include "duckdb/main/profiler/profiling_utils.hpp"
#include "duckdb/main/query_profiler.hpp"
#include "duckdb/planner/extension_callback.hpp"

#include <algorithm>
#include <chrono>
#include <deque>

namespace duckdb {
namespace acl {

namespace {

//! The limits of what one event carries (spec 074): past them `truncated` is set and the tail of
//! the plan is dropped; the rollup is always over the whole tree.
constexpr idx_t MAX_PLAN_NODES = 256;
constexpr idx_t MAX_PLAN_DEPTH = 32;
constexpr idx_t MAX_TEXT = 128;

constexpr const char *STATE_KEY = "acl_profile";

int64_t NowMicros() {
	return std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now().time_since_epoch())
	    .count();
}

//! The notes of the statements the override decided on this thread, in the order their executions
//! come (a batch executes its statements in order, on the thread that parsed it).
//!
//! A POINTER, never the deque itself (spec 088): a thread_local with a non-trivial destructor is
//! destroyed at thread exit, and on MinGW (winpthreads' emulated TLS) that destructor ran on freed
//! storage - a worker thread joined by ~DatabaseInstance crashed in ~deque, about one run in thirty.
//! The deque lives only while notes are pending and is freed when they are taken, so a thread ends
//! holding nothing to destroy; one that ends with notes still pending leaks them, a few hundred bytes.
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
thread_local std::deque<ProfileNote> *pending_notes = nullptr;

std::deque<ProfileNote> &PendingNotes() {
	if (!pending_notes) {
		pending_notes = new std::deque<ProfileNote>(); // NOLINT(cppcoreguidelines-owning-memory): see above
	}
	return *pending_notes;
}

void DropPendingNotes() {
	delete pending_notes; // NOLINT(cppcoreguidelines-owning-memory)
	pending_notes = nullptr;
}

string Bounded(const string &text) {
	return text.size() <= MAX_TEXT ? text : text.substr(0, MAX_TEXT);
}

//! The number of items of a scanner's list (`Filters`: conjuncts joined by ` AND `; `Projections`:
//! names, one per line or comma-separated) at bracket depth zero. Counted, never quoted: the text
//! carries literals a policy wrote.
int64_t CountItems(const string &text, const string &separator) {
	if (text.empty()) {
		return 0;
	}
	int64_t items = 1;
	int depth = 0;
	for (idx_t i = 0; i < text.size(); i++) {
		auto c = text[i];
		if (c == '(' || c == '[') {
			depth++;
		} else if (c == ')' || c == ']') {
			depth = depth > 0 ? depth - 1 : 0;
		} else if (depth == 0 && text.compare(i, separator.size(), separator) == 0) {
			items++;
			i += separator.size() - 1;
		}
	}
	return items;
}

int64_t CountConjuncts(const string &filters) {
	return CountItems(filters, " AND ");
}

int64_t CountProjections(const string &projections) {
	// duckdb joins the names with newlines; a scanner's own rendering may use commas
	auto lines = CountItems(projections, "\n");
	return lines > 1 ? lines : CountItems(projections, ",");
}

//! `Table` from a scan's extra_info against the physical names the rewrite resolved: the database
//! of the first that is the table or ends in `.<table>`; a fully qualified duckdb name
//! (`memory.main.t`) names its own database when nothing resolved to it.
string SourceOf(const string &table, const vector<string> &physical) {
	auto database_of = [](const string &qualified) {
		auto dot = qualified.find('.');
		return dot == string::npos ? string() : qualified.substr(0, dot);
	};
	for (auto &key : physical) {
		// spec 116: a physical name is a stored key - its parts, whatever they hold
		NamePath phys;
		string error;
		if (!NamePath::TryFromKey(key, phys, error)) {
			continue;
		}
		auto joined = StringUtil::Join(phys.Parts(), ".");
		if (StringUtil::CIEquals(joined, table) || StringUtil::CIEquals(phys.Leaf(), table) ||
		    (joined.size() > table.size() + 1 && joined[joined.size() - table.size() - 1] == '.' &&
		     StringUtil::CIEquals(joined.substr(joined.size() - table.size()), table))) {
			return phys.Size() > 1 ? phys.Head() : string();
		}
	}
	if (std::count(table.begin(), table.end(), '.') == 2) {
		return database_of(table);
	}
	return string();
}

//! The tree, walked once: the plan in preorder within its limits, the rollup over all of it.
struct ProfileWalk {
	explicit ProfileWalk(const vector<string> &physical) : physical(physical) {
	}
	const vector<string> &physical;
	vector<AuditPlanNode> plan;
	vector<AuditSource> sources;
	int64_t cpu_us = 0;
	int64_t rows_scanned = 0;
	int64_t rows_out = -1;
	bool truncated = false;
	int64_t next_id = 0;

	AuditSource &SourceFor(const string &source, const string &kind) {
		for (auto &entry : sources) {
			if (entry.source == source && entry.kind == kind) {
				return entry;
			}
		}
		sources.emplace_back();
		sources.back().source = source;
		sources.back().kind = kind;
		return sources.back();
	}

	void Visit(const ProfilingNode &node, int64_t parent) {
		auto &metrics = node.GetOperatorMetrics();
		AuditPlanNode entry;
		entry.id = next_id++;
		entry.parent = parent;
		entry.depth = NumericCast<int64_t>(node.depth);
		entry.type = Bounded(PhysicalOperatorToString(metrics.operator_type));
		entry.rows = NumericCast<int64_t>(metrics.elements_returned);
		entry.rows_scanned = NumericCast<int64_t>(metrics.rows_scanned);
		entry.timing_us = static_cast<int64_t>(metrics.time * 1e6);
		entry.bytes = NumericCast<int64_t>(metrics.intermediate_size_bytes);
		entry.peak_memory_observed = NumericCast<int64_t>(metrics.system_peak_buffer_manager_memory);
		cpu_us += entry.timing_us;
		if (rows_out < 0 && metrics.operator_type != PhysicalOperatorType::RESULT_COLLECTOR &&
		    metrics.operator_type != PhysicalOperatorType::EXECUTE) {
			rows_out = entry.rows; // the top operator's: the collector and an EXECUTE wrapper return nothing
		}
		if (metrics.operator_type == PhysicalOperatorType::TABLE_SCAN) {
			auto &info = metrics.GetExtraInfo();
			auto lookup = [&](const char *key) -> string {
				auto it = info.find(key);
				return it == info.end() ? string() : it->second;
			};
			// the scanner is the operator's own name (SEQ_SCAN, PARQUET_SCAN, POSTGRES_SCAN, ...)
			entry.kind = Bounded(StringUtil::Lower(metrics.name.substr(0, metrics.name.find(' '))));
			auto table = lookup("Table");
			entry.source = table.empty() ? string() : Bounded(SourceOf(table, physical));
			entry.filters = CountConjuncts(lookup("Filters"));
			entry.projections = CountProjections(lookup("Projections"));
			entry.dynamic_filters = info.find("Dynamic Filters") != info.end();
			int64_t scans = 1;
			auto files = lookup("Total Files Read");
			if (!files.empty()) {
				try {
					scans = std::stoll(files);
				} catch (...) {
				}
			}
			auto &source = SourceFor(entry.source, entry.kind);
			source.scans += scans;
			source.rows += entry.rows;
			source.rows_scanned += entry.rows_scanned;
			source.timing_us += entry.timing_us;
			source.bytes += entry.bytes;
			source.filters += entry.filters;
			source.projections += entry.projections;
			source.dynamic_filters = source.dynamic_filters || entry.dynamic_filters;
			rows_scanned += entry.rows_scanned;
		}
		auto id = entry.id;
		if (plan.size() < MAX_PLAN_NODES && node.depth <= MAX_PLAN_DEPTH) {
			plan.push_back(std::move(entry));
		} else {
			truncated = true;
		}
		for (auto &child : node.children) {
			if (child) {
				Visit(*child, id);
			}
		}
	}
};

//! The one way to the profiler's tree: `RenderProfilingNodeTree` hands the root to a renderer.
struct RootCollector : TreeRenderer {
	optional_ptr<const ProfilingNode> root;
	void Render(const ProfilingNode &op, BaseTreeRenderer &) override {
		root = &op;
	}
	void ToStreamInternal(RenderTree &, BaseTreeRenderer &) override {
	}
};

struct NullSink : BaseTreeRenderer {
	void Render(const string &, TreeRenderType) override {
	}
};

//! Per connection (spec 074): the note of the statement executing, the profiler's ownership, and
//! the QueryEnd that turns duckdb's tree into the event.
class AclProfileState : public ClientContextState {
public:
	explicit AclProfileState(weak_ptr<AuditPipeline> pipeline_p) : pipeline(std::move(pipeline_p)) {
	}

	weak_ptr<AuditPipeline> pipeline;
	//! The notes of the batch this connection is executing: the thread's queue, taken whole at the
	//! first QueryBegin after the parse (the batch's first statement begins before anything it runs
	//! on another connection of the same thread can), and popped one per statement after that.
	std::deque<ProfileNote> batch;
	//! The statement's note; kept past its statement for the executions of the same text - a
	//! PREPARE's (whose own tree is skipped) and each EXECUTE of the prepared statement carry the
	//! text that was prepared - and dropped by the next parse on the thread or a text that differs.
	bool has_note = false;
	ProfileNote note;
	//! Whether this module switched the profiler on for this connection - the only case it may
	//! switch it off again - and the format and coverage it found, given back then.
	bool we_enabled = false;
	string their_format;
	ProfilingCoverage their_coverage = ProfilingCoverage::SELECT;
	int64_t began_us = 0;
	//! spec 078: this state put a session on the connection's AclConnection for the running statement
	bool published_session = false;
	//! spec 107: a physical statement's lineage, captured by the pre-optimize hook, emitted at QueryEnd
	shared_ptr<PhysicalLineage> physical_lineage;
	//! spec 107: the running statement is a PREPARE (the hook saw LOGICAL_PREPARE): not an execution
	bool preparing = false;
	//! spec 112: a door's Connection::Prepare is running - its QueryEnd is no execution (duckdb plans
	//! it as a PREPARE whose own plan the optimizer hook never sees, so `preparing` cannot say so)
	idx_t door_preparing = 0;
	//! spec 112 §2: a door's batch scope - the run its executions count towards, and whether any failed
	bool batch_open = false;
	shared_ptr<LineageJob> batch_job;
	uint64_t batch_text = 0; // the batch's statement, by its text: a rebind parses it again (a new job)
	bool batch_failed = false;
	//! spec 112 §6: the runs of a client's explicit transaction, waiting for its end - commit hands
	//! them on as they are, rollback as RUN_ABORT. A definition (physical DDL) waits the same way.
	vector<shared_ptr<LineageJob>> held_runs;
	vector<shared_ptr<PhysicalLineage>> held_physical;

	void QueryBegin(ClientContext &context) override {
		if (pending_notes && !pending_notes->empty()) {
			// a new parse on this thread, and this statement is its first: what an earlier batch
			// left, and the note kept for re-executions, are over
			batch = std::move(*pending_notes);
			DropPendingNotes();
			has_note = false;
		}
		// the note is the execution's only when the text is: a follow-up the rewrite appended, a
		// statement nobody decided (native, a door's own) or another connection's takes none, and a
		// note kept past its statement serves the executions of that very text alone
		auto current = StatementTextHash(context.GetCurrentQuery());
		if (!batch.empty() && batch.front().text_hash == current) {
			note = std::move(batch.front());
			batch.pop_front();
			has_note = true;
		} else if (has_note && note.text_hash != current) {
			has_note = false;
		}
		began_us = NowMicros();
		preparing = false;
		physical_lineage.reset();
		// spec 078: a statement under a session shows it on its connection while it runs, and nothing
		// else does - on a gateway's shared connection the next statement may be another principal's
		if (has_note && !note.proto.session.empty()) {
			AclSessionView view;
			view.session_id = note.proto.session;
			view.principal = note.proto.principal;
			view.door = note.proto.door;
			view.opened_at = note.session_opened_at;
			view.expires_at = note.session_expires_at;
			view.correlation_id = note.proto.correlation_id;
			view.traceparent = note.proto.traceparent;
			published_session = PublishStatementSession(context, std::move(view));
		} else if (published_session) {
			WithdrawStatementSession(context);
			published_session = false;
		}
		if (!has_note) {
			return; // nobody's statement: the profiler stays as the last decided one left it
		}
		auto locked = pipeline.lock();
		if (!locked) {
			return;
		}
		if (!note.proto.door.empty() && note.proto.door != "gateway") {
			return; // a door decided for this statement before running it (ProfileConnectionFor)
		}
		// the gateway path: the profiler starts at plan, after this, so the level decides here -
		// per statement, from the note's own trace when the level samples
		auto level =
		    ProfileLevelFor(context, *locked, note.proto.principal, note.proto.door, note.session_profile_override);
		bool wanted =
		    level == ProfileLevel::ALL || (level == ProfileLevel::SAMPLED && TraceSampled(note.proto.traceparent));
		if (wanted) {
			Enable(context);
		} else {
			Disable(context);
		}
	}

	void QueryEnd(ClientContext &context, optional_ptr<ErrorData> error) override {
		if (published_session) {
			// spec 078: whatever ended the statement - done, failed, interrupted - its session comes off
			WithdrawStatementSession(context);
			published_session = false;
		}
		try {
			Emit(context, error);
		} catch (...) {
			// a profile is never worth the statement; the decision event is already out
		}
		try {
			EndLineage(context, error);
		} catch (...) {
			// lineage is never worth the statement
		}
		if (error) {
			batch.clear(); // an error ends the batch: the statements after it never run
		}
	}

	//! spec 107: one run per execution, handed to the worker with its outcome - never waited on; a
	//! PREPARE is no execution (the hook marked it: its executions are the runs).
	void EndLineage(ClientContext &context, optional_ptr<ErrorData> error) {
		bool was_preparing = preparing;
		preparing = false;
		auto captured = std::move(physical_lineage);
		physical_lineage.reset();
		if (was_preparing || door_preparing > 0) {
			return;
		}
		if (has_note && note.lineage) {
			if (batch_open && (!batch_job || batch_text == note.text_hash)) {
				if (!batch_job) {
					batch_job = note.lineage; // one run for the batch, however many rows it executes
					batch_text = note.text_hash;
				}
				batch_failed = batch_failed || error;
			} else {
				SettleRun(context, note.lineage, bool(error));
			}
		}
		if (captured) {
			if (!error && InExplicitTransaction(context)) {
				held_physical.push_back(std::move(captured));
			} else {
				EmitPhysical(context, *captured, error ? LineageOutcome::FAIL : LineageOutcome::COMPLETE);
			}
		}
	}

	//! A finished run: a failure is final at once; a success inside a client's transaction waits for it
	void SettleRun(ClientContext &context, const shared_ptr<LineageJob> &job, bool failed) {
		if (!failed && InExplicitTransaction(context)) {
			held_runs.push_back(job);
			return;
		}
		EnqueueLineageRun(job, failed ? LineageOutcome::FAIL : LineageOutcome::COMPLETE);
	}

	void BatchBegin() {
		batch_open = true;
		batch_job.reset();
		batch_text = 0;
		batch_failed = false;
	}

	void BatchEnd(ClientContext &context) {
		batch_open = false;
		auto job = std::move(batch_job);
		batch_job.reset();
		if (job) {
			SettleRun(context, job, batch_failed);
		}
	}

	static bool InExplicitTransaction(ClientContext &context) {
		// at QueryEnd an autocommit statement's transaction has already ended (committed or not)
		return context.transaction.HasActiveTransaction() && !context.transaction.IsAutoCommit();
	}

	void EmitPhysical(ClientContext &context, const PhysicalLineage &captured, LineageOutcome outcome) {
		auto locked = pipeline.lock();
		if (locked) {
			EmitPhysicalLineage(captured, *locked, *context.db, outcome);
		}
	}

	void ReleaseHeld(ClientContext &context, LineageOutcome outcome) {
		auto runs = std::move(held_runs);
		held_runs.clear();
		auto physical = std::move(held_physical);
		held_physical.clear();
		try {
			for (auto &job : runs) {
				EnqueueLineageRun(job, outcome);
			}
			for (auto &captured : physical) {
				EmitPhysical(context, *captured, outcome);
			}
		} catch (...) {
			// lineage is never worth the transaction
		}
	}

	void TransactionCommit(MetaTransaction &, ClientContext &context) override {
		ReleaseHeld(context, LineageOutcome::COMPLETE);
	}

	void TransactionRollback(MetaTransaction &, ClientContext &context, optional_ptr<ErrorData>) override {
		ReleaseHeld(context, LineageOutcome::ABORT);
	}

	//! Switch the profiler on for what this connection runs next, unless somebody else did.
	void Enable(ClientContext &context) {
		auto &config = ClientConfig::GetConfig(context);
		if (config.enable_profiler) {
			return; // theirs: the format and the coverage are theirs too
		}
		their_format = config.profiler_print_format;
		their_coverage = config.profiling_coverage;
		config.enable_profiler = true;
		config.profiler_print_format = "no_output";
		config.profiling_coverage = ProfilingCoverage::ALL;
		we_enabled = true;
	}

	void Disable(ClientContext &context) {
		if (!we_enabled) {
			return;
		}
		auto &config = ClientConfig::GetConfig(context);
		config.enable_profiler = false;
		config.profiler_print_format = their_format;
		config.profiling_coverage = their_coverage;
		we_enabled = false;
	}

private:
	void Emit(ClientContext &context, optional_ptr<ErrorData> error) {
		if (!has_note) {
			return; // a statement nobody decided is nobody's profile (spec 074)
		}
		auto locked = pipeline.lock();
		if (!locked) {
			return;
		}
		auto &profiler = QueryProfiler::Get(context);
		bool failed = error != nullptr;
		bool measured = profiler.IsEnabled() && profiler.HasRoot();
		if (!failed && !measured) {
			return; // nobody profiles this connection, or nothing ran yet: the note waits
		}
		RootCollector collector;
		if (measured) {
			NullSink sink;
			profiler.RenderProfilingNodeTree(collector, sink);
			if (collector.root && !failed &&
			    collector.root->GetOperatorMetrics().operator_type == PhysicalOperatorType::PREPARE) {
				return; // a Prepare: the note is the execution's, which follows on this connection
			}
		}
		auto level =
		    ProfileLevelFor(context, *locked, note.proto.principal, note.proto.door, note.session_profile_override);
		if (level == ProfileLevel::OFF) {
			return;
		}
		AuditEvent event = note.proto;
		event.statement = note.statement;
		event.objects = note.objects;
		event.decision_seq = note.decision_seq;
		if (event.traceparent.empty() || event.correlation_id.empty()) {
			string correlation_id, traceparent;
			TraceFromContext(context, correlation_id, traceparent);
			if (event.correlation_id.empty()) {
				event.correlation_id = correlation_id;
			}
			if (event.traceparent.empty()) {
				event.traceparent = traceparent;
			}
		}
		if (level == ProfileLevel::SAMPLED && !TraceSampled(event.traceparent)) {
			return;
		}
		event.kind = "profile";
		event.level = AuditLevel::DECISIONS;
		event.recorded = true; // the profile level decided; the audit level is another knob
		event.error = failed;
		event.allowed = !failed;
		event.reason_code = string();
		event.reason = string();
		event.rewrite_us = -1;
		// a failure's class, never its text (spec 069): a bind error names a column, an execution
		// error a value
		event.detail = failed ? Exception::ExceptionTypeToString(error->Type()) : string();
		event.exec_us = NowMicros() - began_us;
		if (measured) {
			auto &query = profiler.GetQueryMetrics();
			event.peak_memory = NumericCast<int64_t>(query.system_peak_buffer_memory);
			event.memory_allocated = NumericCast<int64_t>(query.total_memory_allocated.load());
			event.bytes_read = NumericCast<int64_t>(query.bytes_read.load());
			event.bytes_written = NumericCast<int64_t>(query.bytes_written.load());
			event.blocked_us = static_cast<int64_t>(query.blocked_thread_time * 1e6);
		}
		if (collector.root) {
			ProfileWalk walk(note.physical);
			walk.Visit(*collector.root, -1);
			event.cpu_us = walk.cpu_us;
			event.rows_scanned = walk.rows_scanned;
			event.rows_out = walk.rows_out;
			event.truncated = walk.truncated;
			event.sources = std::move(walk.sources);
			event.plan = std::move(walk.plan);
		}
		locked->Emit(std::move(event)); // the note stays: a prepared statement executes again
	}
};

shared_ptr<AclProfileState> StateOf(ClientContext &context, weak_ptr<AuditPipeline> pipeline) {
	return context.registered_state->GetOrCreate<AclProfileState>(STATE_KEY, std::move(pipeline));
}

//! Every connection of the instance gets its state as it opens (and, at registration, every one
//! already open). The profiler stays off until a decided statement wants it: duckdb starts it at
//! plan, after QueryBegin, so the first such statement profiles too.
struct AclProfileCallback : ExtensionCallback {
	explicit AclProfileCallback(weak_ptr<AuditPipeline> pipeline_p) : pipeline(std::move(pipeline_p)) {
	}
	weak_ptr<AuditPipeline> pipeline;

	void OnConnectionOpened(ClientContext &context) override {
		try {
			StateOf(context, pipeline);
		} catch (...) {
		}
	}
};

} // namespace

uint64_t StatementTextHash(const string &text) {
	return std::hash<string> {}(text);
}

bool StatementDecidedVirtual(ClientContext &context, Principal &principal, string &door) {
	auto state = context.registered_state->Get<AclProfileState>(STATE_KEY);
	if (!state || !state->has_note) {
		return false;
	}
	if (state->note.statement != "native") {
		return true;
	}
	principal = state->note.proto.principal;
	door = state->note.proto.door;
	return false;
}

void SetPhysicalLineage(ClientContext &context, shared_ptr<PhysicalLineage> lineage) {
	auto state = context.registered_state->Get<AclProfileState>(STATE_KEY);
	if (state) {
		state->physical_lineage = std::move(lineage);
	}
}

LineagePrepareScope::LineagePrepareScope(ClientContext &context_p) : context(context_p) {
	auto state = context.registered_state->Get<AclProfileState>(STATE_KEY);
	if (state) {
		state->door_preparing++;
	}
}

LineagePrepareScope::~LineagePrepareScope() {
	auto state = context.registered_state->Get<AclProfileState>(STATE_KEY);
	if (state && state->door_preparing > 0) {
		state->door_preparing--;
	}
}

void LineageBatchBegin(ClientContext &context) {
	auto state = context.registered_state->Get<AclProfileState>(STATE_KEY);
	if (state) {
		state->BatchBegin();
	}
}

void LineageBatchEnd(ClientContext &context) {
	auto state = context.registered_state->Get<AclProfileState>(STATE_KEY);
	if (state) {
		try {
			state->BatchEnd(context);
		} catch (...) {
			// lineage is never worth the statement
		}
	}
}

void MarkPreparing(ClientContext &context) {
	auto state = context.registered_state->Get<AclProfileState>(STATE_KEY);
	if (state) {
		state->preparing = true;
	}
}

void PushProfileNote(ProfileNote note) {
	PendingNotes().push_back(std::move(note));
}

void ClearProfileNotes() {
	DropPendingNotes();
}

void PushProfileBoundary() {
	auto &notes = PendingNotes();
	notes.clear();
	notes.emplace_back(); // text hash 0: taken by no execution, ends what was kept
}

bool TakeConnectionProfileNote(ClientContext &context, ProfileNote &out) {
	auto state = context.registered_state->Get<AclProfileState>(STATE_KEY);
	if (!state || !state->has_note) {
		return false;
	}
	out = std::move(state->note);
	state->has_note = false;
	return true;
}

void SetConnectionProfileNote(ClientContext &context, ProfileNote note) {
	auto state = context.registered_state->Get<AclProfileState>(STATE_KEY);
	if (!state) {
		return;
	}
	state->note = std::move(note);
	state->has_note = true;
}

bool TraceSampled(const string &traceparent) {
	// 00-<32 hex>-<16 hex>-<2 hex>; the flags are the last field
	auto dash = traceparent.rfind('-');
	if (dash == string::npos || traceparent.size() - dash - 1 != 2) {
		return false;
	}
	auto flags = traceparent.substr(dash + 1);
	try {
		return (std::stoi(flags, nullptr, 16) & 1) != 0;
	} catch (...) {
		return false;
	}
}

ProfileLevel ProfileLevelFor(ClientContext &context, AuditPipeline &pipeline, const Principal &principal,
                             const string &door, int8_t session_override) {
	if (session_override >= 0) {
		return static_cast<ProfileLevel>(session_override);
	}
	ProfileLevel level;
	if (pipeline.ProfileForSession(principal, door, level)) {
		return level;
	}
	// the connection's own value first (a SET SESSION by an operator on the connection it runs),
	// then the instance's GLOBAL - what duckdb answers for the connection
	Value value;
	if (context.TryGetCurrentSetting(Identifier("acl_profile_level"), value) && !value.IsNull() &&
	    ParseProfileLevel(value.ToString(), level)) {
		return level;
	}
	return pipeline.InstanceProfileLevel();
}

void ProfileConnectionFor(ClientContext &context, const shared_ptr<AuditPipeline> &pipeline, const Principal &principal,
                          const string &door, const string &traceparent, int8_t session_override) {
	if (!pipeline) {
		return;
	}
	auto level = ProfileLevelFor(context, *pipeline, principal, door, session_override);
	bool wanted = level == ProfileLevel::ALL || (level == ProfileLevel::SAMPLED && TraceSampled(traceparent));
	auto state = context.registered_state->GetOrCreate<AclProfileState>(STATE_KEY, weak_ptr<AuditPipeline>(pipeline));
	if (state->pipeline.expired()) {
		// a connection opened before this module registered still profiles, through the pipeline
		// the door reached
		state->pipeline = pipeline;
	}
	if (wanted) {
		state->Enable(context);
	} else {
		state->Disable(context);
	}
}

void RegisterAclProfile(ExtensionLoader &loader, const shared_ptr<PolicyStore> &store) {
	auto &db = loader.GetDatabaseInstance();
	auto callback = make_shared_ptr<AclProfileCallback>(weak_ptr<AuditPipeline>(store->audit));
	DBConfig::GetConfig(db).GetCallbackManager().Register(callback);
	// the connections open before the load - the one loading, a gateway's pool - get theirs now
	for (auto &context : db.GetConnectionManager().GetConnectionList()) {
		callback->OnConnectionOpened(*context);
	}
}

} // namespace acl
} // namespace duckdb
