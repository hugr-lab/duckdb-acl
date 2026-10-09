// spec 107: the runtime lineage of a decided statement - its job, the worker, the scratch mirror.
//
// A statement the override decided under a principal names VIRTUAL objects, and its lineage must too
// (the owner's principle: how a virtual object is built from physical ones is already in the catalog,
// from the static events). So the worker does not look at the rewritten plan. It mirrors what the
// principal reads into a scratch database: for every relation the statement names, the worker
// rewrites and binds `SELECT * FROM <name>` under the same principal on the node (what the role sees,
// names and types), and creates an EMPTY table of that shape under the same catalog, schema and name
// in a scratch in-memory DuckDB. The statement as written is then bound there - never executed - and
// walked: its tables ARE the virtual datasets, its DML target a real operator the walker knows.
//
// The scratch database has no external access and no extension autoloading, holds no data, and lives
// for one job; nothing the principal wrote is executed anywhere. All of it runs on the worker's
// thread, after the statement's own execution ended: the statement never waits on lineage.
#include "acl_lineage.hpp"
#include "acl_attach_lineage.hpp"

#include "acl_audit_pipeline.hpp"
#include "acl_policy.hpp"
#include "acl_policy_catalog.hpp"
#include "acl_profile.hpp"
#include "acl_rewriter.hpp"

#include "duckdb/catalog/catalog_entry/table_catalog_entry.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/connection.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/parser/expression/constant_expression.hpp"
#include "duckdb/parser/expression/subquery_expression.hpp"
#include "duckdb/parser/expression/parameter_expression.hpp"
#include "duckdb/parser/parsed_expression_iterator.hpp"
#include "duckdb/parser/parser.hpp"
#include "duckdb/parser/query_node/list.hpp"
#include "duckdb/parser/statement/list.hpp"
#include "duckdb/parser/tableref/basetableref.hpp"
#include "duckdb/parser/tableref/pivotref.hpp"
#include "duckdb/parser/parsed_data/create_table_info.hpp"
#include "duckdb/planner/operator/logical_get.hpp"
#include "duckdb/planner/operator/logical_prepare.hpp"
#include "duckdb/planner/planner.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/main/extension_helper.hpp"
#include "duckdb/main/database_manager.hpp"
#include "duckdb/main/attached_database.hpp"
#include "duckdb/catalog/catalog.hpp"
#include "duckdb/main/client_data.hpp"
#include "duckdb/catalog/catalog_search_path.hpp"
#include "duckdb/optimizer/optimizer_extension.hpp"
#include "duckdb/parser/parsed_data/alter_info.hpp"
#include "duckdb/parser/parsed_data/create_view_info.hpp"
#include "duckdb/parser/parsed_data/drop_info.hpp"
#include "duckdb/planner/operator/logical_alter.hpp"
#include "duckdb/planner/operator/logical_attach.hpp"
#include "duckdb/planner/operator/logical_detach.hpp"
#include "duckdb/parser/parsed_data/attach_info.hpp"
#include "duckdb/parser/parsed_data/detach_info.hpp"
#include "duckdb/planner/operator/logical_create.hpp"
#include "duckdb/planner/operator/logical_create_table.hpp"
#include "duckdb/planner/operator/logical_drop.hpp"
#include "duckdb/planner/parsed_data/bound_create_table_info.hpp"

#include <condition_variable>
#include <deque>
#include <thread>

namespace duckdb {
namespace acl {

class LineageWorker : public std::enable_shared_from_this<LineageWorker> {
public:
	LineageWorker(weak_ptr<PolicyStore> store_p, shared_ptr<AuditPipeline> pipeline_p, weak_ptr<DatabaseInstance> db_p)
	    : store(std::move(store_p)), pipeline(std::move(pipeline_p)), db(std::move(db_p)) {
	}

	//! One unit of work: a statement's run (job + outcome) or a static event's task.
	struct Item {
		shared_ptr<LineageJob> job;
		bool failed = false;
		std::function<void(PolicyStore &)> task;
	};

	void Enqueue(shared_ptr<LineageJob> job, bool failed) {
		Item item;
		item.job = std::move(job);
		item.failed = failed;
		Push(std::move(item));
	}

	bool EnqueueTask(std::function<void(PolicyStore &)> task) {
		Item item;
		item.task = std::move(task);
		return Push(std::move(item));
	}

	bool Push(Item item) {
		{
			std::lock_guard<std::mutex> guard(lock);
			if (stopping) {
				return false;
			}
			if (queue.size() >= 1000) {
				pipeline->Hooks().Counters().Add("acl.lineage.dropped", {});
				return false;
			}
			queue.push_back(std::move(item));
			enqueued++;
			if (!thread.joinable()) {
				auto self = shared_from_this();
				try {
					thread = std::thread([self]() { self->Run(); });
				} catch (std::exception &) {
					queue.pop_back();
					enqueued--;
					return false;
				}
			}
		}
		cv.notify_one();
		return true;
	}

	void Stop() {
		{
			std::lock_guard<std::mutex> guard(lock);
			stopping = true;
			queue.clear();
		}
		cv.notify_all();
		drained.notify_all();
		if (thread.joinable()) {
			if (thread.get_id() == std::this_thread::get_id()) {
				thread.detach(); // the instance's teardown ran on this very thread: the loop ends by itself
			} else {
				thread.join();
			}
		}
	}

	bool Flush(int64_t timeout_ms) {
		std::unique_lock<std::mutex> guard(lock);
		auto target = enqueued;
		return drained.wait_for(guard, std::chrono::milliseconds(timeout_ms),
		                        [&]() { return handled >= target || stopping; });
	}

private:
	void Run() {
		for (;;) {
			Item next;
			{
				std::unique_lock<std::mutex> guard(lock);
				cv.wait(guard, [&]() { return stopping || !queue.empty(); });
				if (stopping) {
					return;
				}
				next = std::move(queue.front());
				queue.pop_front();
			}
			try {
				if (next.task) {
					RunTask(next.task);
				} else if (next.job) {
					Process(*next.job, next.failed);
				}
			} catch (...) {
				pipeline->Hooks().Counters().Add("acl.lineage.errors", {});
			}
			{
				std::lock_guard<std::mutex> guard(lock);
				handled++;
			}
			drained.notify_all();
		}
	}

	void Process(LineageJob &job, bool failed);

	void RunTask(const std::function<void(PolicyStore &)> &task) {
		auto locked_store = store.lock();
		auto locked_db = db.lock(); // what the task reads goes through the instance: held for the task
		if (!locked_store || !locked_db) {
			return;
		}
		task(*locked_store);
	}

	weak_ptr<PolicyStore> store;
	shared_ptr<AuditPipeline> pipeline;
	weak_ptr<DatabaseInstance> db;
	std::mutex lock;
	std::condition_variable cv;
	std::condition_variable drained;
	std::deque<Item> queue;
	int64_t enqueued = 0;
	int64_t handled = 0;
	bool stopping = false;
	std::thread thread;
};

namespace {

//! A relation the statement names, as written.
struct NamedRelation {
	vector<string> parts; // [catalog,] [schema,] name - as written
	string Key() const {
		return StringUtil::Lower(StringUtil::Join(parts, "."));
	}
};

string Quoted(const vector<string> &parts) {
	vector<string> quoted;
	for (auto &part : parts) {
		quoted.push_back(acl_detail::Ident(part));
	}
	return StringUtil::Join(quoted, ".");
}

NamedRelation FromQualified(const QualifiedName &name) {
	NamedRelation relation;
	if (!name.Catalog().GetIdentifierName().empty()) {
		relation.parts.push_back(name.Catalog().GetIdentifierName());
	}
	if (!name.Schema().GetIdentifierName().empty()) {
		relation.parts.push_back(name.Schema().GetIdentifierName());
	}
	relation.parts.push_back(name.Name().GetIdentifierName());
	return relation;
}

//! Every base table the statement names, and every CTE name it defines (those are not relations).
class RelationCollector {
public:
	vector<NamedRelation> relations;
	case_insensitive_set_t ctes;

	void Node(QueryNode &node) {
		for (auto &entry : node.cte_map.map) {
			ctes.insert(entry.first.GetIdentifierName());
		}
		ParsedExpressionIterator::EnumerateQueryNodeChildren(
		    node, [&](unique_ptr<ParsedExpression> &child) { Expression(*child); }, [&](TableRef &ref) { Ref(ref); });
	}

private:
	void Expression(ParsedExpression &expr) {
		if (expr.GetExpressionClass() == ExpressionClass::SUBQUERY) {
			auto &subquery = expr.Cast<SubqueryExpression>();
			if (subquery.Subquery() && subquery.Subquery()->node) {
				Node(*subquery.SubqueryMutable()->node);
			}
		}
		ParsedExpressionIterator::EnumerateChildren(expr, [&](ParsedExpression &child) { Expression(child); });
	}
	void Ref(TableRef &ref) {
		if (ref.type != TableReferenceType::BASE_TABLE) {
			return;
		}
		auto relation = FromQualified(ref.Cast<BaseTableRef>().GetQualifiedName());
		if (relation.parts.size() == 1 && ctes.count(relation.parts[0])) {
			return;
		}
		for (auto &known : relations) {
			if (known.Key() == relation.Key()) {
				return;
			}
		}
		relations.push_back(std::move(relation));
	}
};

//! The root query node of a statement in scope, or null.
optional_ptr<QueryNode> RootNode(SQLStatement &statement) {
	switch (statement.type) {
	case StatementType::SELECT_STATEMENT:
		return statement.Cast<SelectStatement>().node.get();
	case StatementType::INSERT_STATEMENT:
		return statement.Cast<InsertStatement>().node.get();
	case StatementType::UPDATE_STATEMENT:
		return statement.Cast<UpdateStatement>().node.get();
	case StatementType::DELETE_STATEMENT:
		return statement.Cast<DeleteStatement>().node.get();
	case StatementType::MERGE_INTO_STATEMENT:
		return statement.Cast<MergeIntoStatement>().node.get();
	case StatementType::CREATE_STATEMENT: {
		auto &info = statement.Cast<CreateStatement>().info;
		if (info && info->type == CatalogType::TABLE_ENTRY) {
			auto &table = info->Cast<CreateTableInfo>();
			if (table.query && table.query->node) {
				return table.query->node.get();
			}
		}
		return nullptr;
	}
	default:
		return nullptr;
	}
}

//! What the principal sees of one relation: its canonical virtual name and its columns.
struct Mirror {
	string vcat;  // the virtual catalog
	string vname; // the object's name inside it (`schema.name` or `name`)
	vector<std::pair<string, LogicalType>> columns;
};

//! Rewrite + bind `SELECT * FROM <relation>` under the principal, on the node, without executing it.
bool Resolve(PolicyStore &store, DatabaseInstance &db, const Principal &principal, const NamedRelation &relation,
             Mirror &out) {
	try {
		Parser parser(ParserOptions::Builtin());
		parser.ParseQuery("SELECT * FROM " + Quoted(relation.parts));
		AuditTrail trail;
		RewriteStatements(parser.statements, principal, ParserOptions::Builtin(), store, &trail);
		// the object the name resolves to for this principal - what the rewrite above also resolved
		TablePolicy policy;
		if (!store.ResolveTable(principal, StringUtil::Join(relation.parts, "."), policy)) {
			return false;
		}
		auto canonical = policy.canonical;
		auto dot = canonical.find('.');
		if (dot == string::npos || parser.statements.empty()) {
			return false;
		}
		out.vcat = canonical.substr(0, dot);
		out.vname = canonical.substr(dot + 1);
		Connection con(db);
		bool bound = false;
		con.context->RunFunctionInTransaction([&]() {
			Planner planner(*con.context);
			planner.CreatePlan(std::move(parser.statements[0]));
			for (idx_t i = 0; i < planner.names.size() && i < planner.types.size(); i++) {
				out.columns.emplace_back(planner.names[i].GetIdentifierName(), planner.types[i]);
			}
			bound = true;
		});
		return bound;
	} catch (std::exception &) {
		return false;
	}
}

//! A DML target the principal may write but not read (an insert-only sink grant): `SELECT *` under
//! the principal refuses, so its shape is the physical relation's under the names the principal writes
//! (spec 042's write order, spec 010's renames). Never for a relation the principal holds no write on.
bool ResolveTarget(PolicyStore &store, DatabaseInstance &db, const Principal &principal, const NamedRelation &relation,
                   Mirror &out) {
	try {
		TablePolicy policy;
		if (!store.ResolveTable(principal, StringUtil::Join(relation.parts, "."), policy) || policy.phys.empty()) {
			return false;
		}
		if (!policy.caps.count("insert") && !policy.caps.count("update") && !policy.caps.count("delete") &&
		    !policy.caps.count("merge")) {
			return false;
		}
		auto dot = policy.canonical.find('.');
		if (dot == string::npos) {
			return false;
		}
		out.vcat = policy.canonical.substr(0, dot);
		out.vname = policy.canonical.substr(dot + 1);
		case_insensitive_map_t<LogicalType> physical;
		vector<string> physical_order;
		Connection con(db);
		con.context->RunFunctionInTransaction([&]() {
			Parser parser(ParserOptions::Builtin());
			parser.ParseQuery("SELECT * FROM " + policy.phys);
			Planner planner(*con.context);
			planner.CreatePlan(std::move(parser.statements[0]));
			for (idx_t i = 0; i < planner.names.size() && i < planner.types.size(); i++) {
				physical[planner.names[i].GetIdentifierName()] = planner.types[i];
				physical_order.push_back(planner.names[i].GetIdentifierName());
			}
		});
		case_insensitive_map_t<string> to_physical;
		case_insensitive_map_t<string> to_virtual;
		for (auto &rename : policy.renames) {
			to_physical[rename.first] = rename.second;
			to_virtual[rename.second] = rename.first;
		}
		auto type_of = [&](const string &name) {
			auto entry = physical.find(name);
			return entry == physical.end() ? LogicalType(LogicalType::VARCHAR) : entry->second;
		};
		if (!policy.write_order.empty()) {
			for (auto &name : policy.write_order) {
				auto renamed = to_physical.find(name);
				out.columns.emplace_back(name, type_of(renamed == to_physical.end() ? name : renamed->second));
			}
		} else {
			for (auto &name : physical_order) {
				auto renamed = to_virtual.find(name);
				out.columns.emplace_back(renamed == to_virtual.end() ? name : renamed->second, type_of(name));
			}
		}
		return !out.columns.empty();
	} catch (std::exception &) {
		return false;
	}
}

//! Where a relation lives in the scratch database: under the name AS WRITTEN (a schema alias, a
//! two-part name bind there as they did on the node), the virtual catalog standing in for a missing one.
//! A two-part name is `catalog.name` when it names the virtual catalog the node resolved it in, else
//! `schema.name` (both at once would be ambiguous to the binder).
vector<vector<string>> ScratchPlacements(const NamedRelation &relation, const string &vcat) {
	auto &parts = relation.parts;
	if (parts.size() >= 3) {
		return {{parts[parts.size() - 3], parts[parts.size() - 2], parts.back()}};
	}
	if (parts.size() == 2) {
		if (StringUtil::CIEquals(parts[0], vcat)) {
			return {{vcat, "main", parts[1]}};
		}
		return {{vcat, parts[0], parts[1]}};
	}
	return {{vcat, "main", parts.back()}};
}

//! The scratch database's statements that mirror one relation: an empty table of its shape.
void MirrorInto(Connection &scratch, case_insensitive_set_t &attached, const Mirror &mirror,
                const vector<string> &name_parts) {
	if (!attached.count(name_parts[0])) {
		scratch.Query("ATTACH ':memory:' AS " + acl_detail::Ident(name_parts[0]));
		attached.insert(name_parts[0]);
	}
	if (!StringUtil::CIEquals(name_parts[1], "main")) {
		scratch.Query("CREATE SCHEMA IF NOT EXISTS " + Quoted({name_parts[0], name_parts[1]}));
	}
	vector<string> columns;
	for (auto &column : mirror.columns) {
		columns.push_back(acl_detail::Ident(column.first) + " " + column.second.ToString());
	}
	auto created = scratch.Query("CREATE TABLE IF NOT EXISTS " + Quoted(name_parts) + " (" +
	                             StringUtil::Join(columns, ", ") + ")");
	if (created->HasError()) {
		// a type the scratch database does not know (an extension's): the names still carry the edges
		columns.clear();
		for (auto &column : mirror.columns) {
			columns.push_back(acl_detail::Ident(column.first) + " VARCHAR");
		}
		scratch.Query("CREATE TABLE IF NOT EXISTS " + Quoted(name_parts) + " (" + StringUtil::Join(columns, ", ") +
		              ")");
	}
}

//! The canonical dataset key of a scratch table: its catalog is the virtual catalog, `main` is no schema.
LineageDatasetKey VirtualKey(const string &catalog, const string &schema, const string &name) {
	LineageDatasetKey key;
	key.kind = "virtual";
	key.catalog = catalog;
	key.name = StringUtil::CIEquals(schema, "main") || schema.empty() ? name : schema + "." + name;
	return key;
}

//! Every constant of the statement replaced by `?` - the SQL facet and the default job name never
//! carry a value.
void NormalizeConstants(QueryNode &node);

void NormalizeExpression(unique_ptr<ParsedExpression> &expr) {
	if (expr->GetExpressionClass() == ExpressionClass::CONSTANT) {
		auto placeholder = make_uniq<ParameterExpression>();
		placeholder->IdentifierMutable() = Identifier("?");
		placeholder->SetAlias(expr->GetAlias());
		expr = std::move(placeholder);
		return;
	}
	if (expr->GetExpressionClass() == ExpressionClass::SUBQUERY) {
		auto &subquery = expr->Cast<SubqueryExpression>();
		if (subquery.Subquery() && subquery.Subquery()->node) {
			NormalizeConstants(*subquery.SubqueryMutable()->node);
		}
	}
	ParsedExpressionIterator::EnumerateChildren(
	    *expr, [&](unique_ptr<ParsedExpression> &child) { NormalizeExpression(child); });
}

//! A PIVOT's values are no expressions (`IN ('a', 'b')` is a vector of values), and its pivot and
//! UNPIVOT expressions are not visited by the iterator: each is blanked here.
void NormalizePivot(TableRef &ref) {
	if (ref.type != TableReferenceType::PIVOT) {
		return;
	}
	for (auto &column : ref.Cast<PivotRef>().pivots) {
		for (auto &expr : column.pivot_expressions) {
			NormalizeExpression(expr);
		}
		for (auto &entry : column.entries) {
			for (auto &value : entry.values) {
				value = Value("?");
			}
			if (entry.expr) {
				NormalizeExpression(entry.expr);
			}
		}
		if (column.subquery) {
			NormalizeConstants(*column.subquery);
		}
	}
}

void NormalizeConstants(QueryNode &node) {
	ParsedExpressionIterator::EnumerateQueryNodeChildren(
	    node, [&](unique_ptr<ParsedExpression> &child) { NormalizeExpression(child); }, NormalizePivot);
	ParsedExpressionIterator::EnumerateQueryNodeModifiers(
	    node, [&](unique_ptr<ParsedExpression> &child) { NormalizeExpression(child); });
}

string NormalizedText(const SQLStatement &statement) {
	auto copy = statement.Copy();
	auto root = RootNode(*copy);
	if (root) {
		NormalizeConstants(*root);
	}
	auto text = copy->ToString();
	// `$?` is how a placeholder prints; the facet says `?`
	return StringUtil::Replace(text, "$?", "?");
}

string Hex(uint64_t value) {
	static const char *digits = "0123456789abcdef";
	string out(16, '0');
	for (int i = 15; i >= 0; i--) {
		out[idx_t(i)] = digits[value & 0xF];
		value >>= 4;
	}
	return out;
}

} // namespace

void LineageWorker::Process(LineageJob &job, bool failed) {
	auto locked_store = store.lock();
	auto locked_db = db.lock();
	if (!locked_store || !locked_db || !job.statement) {
		return;
	}
	auto settings = LineageSettings::Read(*locked_db);
	if (!settings.on) {
		return;
	}
	auto statement = job.statement->Copy();
	auto statement_copy = job.statement->Copy(); // the planner consumes `statement`
	auto root = RootNode(*statement);
	LineageWalk walk;
	bool walked = false;
	// scratch table (catalog.schema.name, lower) -> the virtual object it stands for, and its columns
	case_insensitive_map_t<LineageDatasetKey> mirrored;
	case_insensitive_map_t<vector<std::pair<string, LogicalType>>> mirrored_columns;
	auto Canonical = [&](const string &catalog, const string &schema, const string &name) {
		auto found = mirrored.find(StringUtil::Lower(catalog + "." + schema + "." + name));
		return found != mirrored.end() ? found->second : VirtualKey(catalog, schema, name);
	};
	if (root) {
		RelationCollector collector;
		collector.Node(*root);
		if (statement->type == StatementType::INSERT_STATEMENT) {
			auto &insert = statement->Cast<InsertStatement>();
			if (insert.node && !insert.node->table_ref) {
				collector.relations.push_back(FromQualified(insert.node->qualified_name));
			}
		}
		// the scratch database: what the principal reads, as empty tables under the same names. No
		// extension is loaded but the function sets a statement binds against - acl itself never: a
		// second override, store and worker per job is what a scratch must not be
		DBConfig config;
		config.options.load_extensions = false;
		config.SetOptionByName("enable_external_access", Value::BOOLEAN(false));
		config.SetOptionByName("autoload_known_extensions", Value::BOOLEAN(false));
		config.SetOptionByName("autoinstall_known_extensions", Value::BOOLEAN(false));
		config.SetOptionByName("threads", Value::BIGINT(1));
		config.SetOptionByName("memory_limit", Value("64MB"));
		DuckDB scratch_db(nullptr, &config);
		for (auto extension : {"core_functions", "json", "icu"}) {
			try {
				ExtensionHelper::LoadExtension(scratch_db, extension);
			} catch (std::exception &) {
				// not linked into this build: its functions do not bind, the walk says approximate
			}
		}
		Connection scratch(scratch_db);
		case_insensitive_set_t attached;
		string default_catalog;
		bool all_resolved = true;
		for (auto &relation : collector.relations) {
			Mirror mirror;
			if (!Resolve(*locked_store, *locked_db, job.principal, relation, mirror) &&
			    !ResolveTarget(*locked_store, *locked_db, job.principal, relation, mirror)) {
				all_resolved = false; // a CTAS target, a name the role cannot read: no mirror, maybe no bind
				continue;
			}
			if (relation.parts.size() < 3 && default_catalog.empty()) {
				default_catalog = mirror.vcat;
			}
			auto dot = mirror.vname.find('.');
			LineageDatasetKey key;
			key.kind = "virtual";
			key.catalog = mirror.vcat;
			key.name = dot != string::npos && StringUtil::CIEquals(mirror.vname.substr(0, dot), "main")
			               ? mirror.vname.substr(dot + 1)
			               : mirror.vname;
			for (auto &placement : ScratchPlacements(relation, mirror.vcat)) {
				MirrorInto(scratch, attached, mirror, placement);
				mirrored[StringUtil::Lower(StringUtil::Join(placement, "."))] = key;
				mirrored_columns[StringUtil::Lower(StringUtil::Join(placement, "."))] = mirror.columns;
			}
		}
		if (statement->type == StatementType::CREATE_STATEMENT) {
			// a CREATE TABLE AS writes into a granted schema: the schema must exist where it binds
			auto &info = statement->Cast<CreateStatement>().info->Cast<CreateTableInfo>();
			auto &qualified = info.GetQualifiedName();
			if (!qualified.Catalog().GetIdentifierName().empty() && !qualified.Schema().GetIdentifierName().empty()) {
				auto catalog = qualified.Catalog().GetIdentifierName();
				if (!attached.count(catalog)) {
					scratch.Query("ATTACH ':memory:' AS " + acl_detail::Ident(catalog));
					attached.insert(catalog);
				}
				scratch.Query("CREATE SCHEMA IF NOT EXISTS " +
				              Quoted({catalog, qualified.Schema().GetIdentifierName()}));
			}
		}
		if (!default_catalog.empty()) {
			scratch.Query("USE " + acl_detail::Ident(default_catalog));
		}
		LineageWalkOptions options;
		options.max_edges = settings.max_edges;
		options.classify = [&](LogicalGet &get, LineageDatasetKey &key) {
			auto table = get.GetTable();
			if (!table) {
				return false; // a table function in the statement: a function dataset, approximate
			}
			key = Canonical(table->ParentCatalog().GetName().GetIdentifierName(),
			                table->ParentSchema().name.GetIdentifierName(), table->name.GetIdentifierName());
			return true;
		};
		try {
			scratch.context->RunFunctionInTransaction([&]() {
				Planner planner(*scratch.context);
				planner.CreatePlan(std::move(statement));
				for (auto &name : planner.names) {
					options.output_names.push_back(name.GetIdentifierName());
				}
				walk = WalkLineage(*planner.plan, options);
				walked = true;
			});
		} catch (std::exception &) {
			walked = false;
		}
		if (walked && walk.has_target) {
			walk.target = Canonical(walk.target.catalog, walk.target.schema, walk.target.name);
		}
		if (!walked && statement_copy && statement_copy->type == StatementType::INSERT_STATEMENT) {
			// an INSERT whose source does not bind here - a door's ingest reads the client's stream
			// (arrow_scan, a quack drain) - still wrote its target: its fields, sources the client's
			auto &insert = statement_copy->Cast<InsertStatement>();
			auto target = FromQualified(insert.node->qualified_name);
			auto placement_key =
			    StringUtil::Lower(StringUtil::Join(ScratchPlacements(target, default_catalog)[0], "."));
			auto found = mirrored.find(placement_key);
			if (found != mirrored.end()) {
				walk = LineageWalk();
				walk.has_target = true;
				walk.target = found->second;
				walk.target_operation = "INSERT";
				vector<string> names;
				for (auto &column : insert.node->columns) {
					names.push_back(column.GetIdentifierName());
				}
				if (names.empty()) {
					for (auto &column : mirrored_columns[placement_key]) {
						names.push_back(column.first);
					}
				}
				for (auto &name : names) {
					LineageOutput output;
					output.name = name;
					walk.outputs.push_back(std::move(output));
				}
				walk.approximate = true;
				walked = true;
			}
		}
		if (!all_resolved) {
			walk.approximate = true;
		}
	}
	if (!walked) {
		walk = LineageWalk();
		walk.approximate = true;
	}
	if (job.declared_read) {
		// a read under a declared parent: what it read, no target and no edges
		walk.has_target = false;
		walk.outputs.clear();
		walk.whole_target.clear();
	}
	auto lineage = LineageFromWalk(walk, settings);
	lineage->event_type = failed ? "RUN_FAIL" : "RUN_COMPLETE";
	lineage->run_id = LineageRunId();
	auto client = job.door.empty() ? string("gateway") : job.door;
	lineage->job_ns = settings.ns + "/client/" + client;
	auto normalized = NormalizedText(*job.statement);
	lineage->job_name = job.context.job.empty() ? "sql:" + Hex(StatementTextHash(normalized)) : job.context.job;
	lineage->parent = ParseLineageRunRef(job.context.parent);
	lineage->root_parent = ParseLineageRunRef(job.context.root_parent);
	if (settings.sql) {
		lineage->sql = normalized;
		lineage->dialect = "duckdb";
	}
	if (settings.identity != "none") {
		lineage->client = client; // the door it came through: flight, quack, session, the gateway
		lineage->issuer = job.principal.issuer;
		lineage->roles = job.principal.roles;
		Value group;
		if (locked_db->TryGetCurrentSetting("acl_node_group", group) && !group.IsNull()) {
			lineage->node_group = group.ToString();
		}
		if (settings.identity == "subject") {
			lineage->subject = job.principal.subject;
		}
	}
	AuditEvent event;
	event.kind = "lineage";
	event.door = job.door;
	event.level = AuditLevel::ALL;
	event.recorded = true;
	event.decision_seq = job.decision_seq;
	event.lineage = std::move(lineage);
	pipeline->Emit(std::move(event));
}

namespace {

struct LineageOptimizerInfo : OptimizerExtensionInfo {
	explicit LineageOptimizerInfo(weak_ptr<PolicyStore> store_p) : store(std::move(store_p)) {
	}
	weak_ptr<PolicyStore> store;
};

//! A physical object's key, its catalog filled in from the connection's default when the SQL left it out.
LineageDatasetKey PhysicalKey(ClientContext &context, const QualifiedName &name) {
	LineageDatasetKey key;
	key.kind = "physical";
	key.catalog = name.Catalog().GetIdentifierName();
	if (key.catalog.empty()) {
		key.catalog = DatabaseManager::GetDefaultDatabase(context).GetIdentifierName();
	}
	key.schema = name.Schema().GetIdentifierName().empty() ? string("main") : name.Schema().GetIdentifierName();
	key.name = name.Name().GetIdentifierName();
	return key;
}

//! The node's own bookkeeping is nobody's lineage: the policy catalog, the system and temp catalogs.
bool Bookkeeping(PolicyStore &store, const string &catalog) {
	if (StringUtil::CIEquals(catalog, "system") || StringUtil::CIEquals(catalog, "temp")) {
		return true;
	}
	return store.catalog && StringUtil::CIEquals(catalog, store.catalog->db_name);
}

LineageWalkOptions PhysicalOptions(idx_t max_edges) {
	LineageWalkOptions options;
	options.max_edges = max_edges;
	options.classify = [](LogicalGet &get, LineageDatasetKey &key) {
		auto table = get.GetTable();
		if (!table) {
			return false;
		}
		key.kind = "physical";
		key.catalog = table->ParentCatalog().GetName().GetIdentifierName();
		key.schema = table->ParentSchema().name.GetIdentifierName();
		key.name = table->name.GetIdentifierName();
		return true;
	};
	return options;
}

//! The DML / CTAS operator under a plan's root (a RETURNING puts a projection above it), or null.
optional_ptr<LogicalOperator> WriteOperator(LogicalOperator &plan) {
	reference<LogicalOperator> current(plan);
	for (;;) {
		switch (current.get().type) {
		case LogicalOperatorType::LOGICAL_INSERT:
		case LogicalOperatorType::LOGICAL_UPDATE:
		case LogicalOperatorType::LOGICAL_DELETE:
		case LogicalOperatorType::LOGICAL_MERGE_INTO:
			return &current.get();
		case LogicalOperatorType::LOGICAL_CREATE_TABLE:
			return current.get().children.empty() ? nullptr : &current.get();
		case LogicalOperatorType::LOGICAL_PROJECTION:
			if (current.get().children.size() != 1) {
				return nullptr;
			}
			current = *current.get().children[0];
			continue;
		default:
			return nullptr;
		}
	}
}

//! Whether the hook captures a statement of this shape at all - the cheap test, before any setting.
bool CapturedShape(LogicalOperator &plan) {
	switch (plan.type) {
	case LogicalOperatorType::LOGICAL_CREATE_TABLE:
	case LogicalOperatorType::LOGICAL_CREATE_VIEW:
	case LogicalOperatorType::LOGICAL_DROP:
	case LogicalOperatorType::LOGICAL_ALTER:
	case LogicalOperatorType::LOGICAL_ATTACH:
	case LogicalOperatorType::LOGICAL_DETACH:
		return true;
	default:
		return WriteOperator(plan) != nullptr;
	}
}

void CapturePhysical(OptimizerExtensionInput &input, unique_ptr<LogicalOperator> &plan);

void LineagePreOptimize(OptimizerExtensionInput &input, unique_ptr<LogicalOperator> &plan) {
	if (!plan || !input.info) {
		return;
	}
	if (plan->type == LogicalOperatorType::LOGICAL_PREPARE) {
		// a PREPARE is no execution: QueryEnd must not count it as one. A physical statement it prepares
		// is bound again by each execution - as duckdb does itself for one that reads a database - so the
		// hook sees every execution's plan (one without parameters is otherwise never optimized again)
		MarkPreparing(input.context);
		if (plan->children.empty() || !CapturedShape(*plan->children[0])) {
			return;
		}
		try {
			auto &info = static_cast<LineageOptimizerInfo &>(*input.info);
			Principal principal;
			string door;
			if (!info.store.lock() || StatementDecidedVirtual(input.context, principal, door) ||
			    !LineageOn(*input.context.db)) {
				return;
			}
			plan->Cast<LogicalPrepare>().prepared->properties.always_require_rebind = true;
		} catch (...) {
		}
		return;
	}
	if (plan->type == LogicalOperatorType::LOGICAL_EXECUTE) {
		// SQL `EXECUTE p`: the rebound plan of the prepared statement is its child (none when duckdb
		// kept the prepared plan - then nothing was planned again and nothing is captured)
		if (!plan->children.empty()) {
			CapturePhysical(input, plan->children[0]);
		}
		return;
	}
	CapturePhysical(input, plan);
}

void CapturePhysical(OptimizerExtensionInput &input, unique_ptr<LogicalOperator> &plan) {
	// first and cheapest: a read (the overwhelming case) leaves here, before any setting is read
	if (!CapturedShape(*plan)) {
		return;
	}
	try {
		auto &info = static_cast<LineageOptimizerInfo &>(*input.info);
		auto store = info.store.lock();
		if (!store) {
			return;
		}
		// a statement decided under a principal's virtual catalog is the worker's, in its own names
		Principal principal;
		string door;
		if (StatementDecidedVirtual(input.context, principal, door)) {
			return;
		}
		auto &db = *input.context.db;
		auto settings = LineageSettings::Read(db);
		if (!settings.on) {
			return;
		}
		auto captured = make_shared_ptr<PhysicalLineage>();
		captured->principal = principal;
		captured->door = door;
		if (auto write = WriteOperator(*plan)) {
			captured->walk = WalkLineage(*plan, PhysicalOptions(settings.max_edges));
			if (!captured->walk.has_target || Bookkeeping(*store, captured->walk.target.catalog)) {
				return;
			}
			(void)write;
			SetPhysicalLineage(input.context, std::move(captured));
			return;
		}
		switch (plan->type) {
		case LogicalOperatorType::LOGICAL_CREATE_TABLE: {
			auto &create = plan->Cast<LogicalCreateTable>();
			auto &base = create.info->Base();
			captured->object =
			    PhysicalKey(input.context, QualifiedName(base.GetQualifiedName().Catalog(),
			                                             base.GetQualifiedName().Schema(), base.GetTableName()));
			for (auto &column : base.columns.Logical()) {
				LineageOutput output;
				output.name = column.Name().GetIdentifierName();
				captured->walk.outputs.push_back(std::move(output));
			}
			captured->dataset_type = "TABLE";
			captured->lifecycle = "CREATE";
			break;
		}
		case LogicalOperatorType::LOGICAL_CREATE_VIEW: {
			auto &view = plan->Cast<LogicalCreate>().info->Cast<CreateViewInfo>();
			captured->object = PhysicalKey(input.context, view.GetQualifiedName());
			bool walked = false;
			if (view.query) {
				// bound right here, in the statement's own transaction: what the view reads may have
				// been created by this very transaction
				// duckdb strips the view's own catalog from its body (BindCreateViewInfo), so the body
				// binds against the view's catalog and schema - as duckdb binds it - then the path is back
				auto &search = *ClientData::Get(input.context).catalog_search_path;
				auto saved = search.GetSetPaths();
				auto view_catalog = view.GetQualifiedName().Catalog().GetIdentifierName().empty()
				                        ? DatabaseManager::GetDefaultDatabase(input.context)
				                        : view.GetQualifiedName().Catalog();
				auto view_schema = view.GetQualifiedName().Schema().GetIdentifierName().empty()
				                       ? Identifier("main")
				                       : view.GetQualifiedName().Schema();
				try {
					search.Set(CatalogSearchEntry(view_catalog, view_schema), CatalogSetPathType::SET_SCHEMA);
					Planner planner(input.context);
					planner.CreatePlan(view.query->Copy());
					auto options = PhysicalOptions(settings.max_edges);
					for (auto &name : planner.names) {
						options.output_names.push_back(name.GetIdentifierName());
					}
					captured->walk = WalkLineage(*planner.plan, options);
					walked = true;
				} catch (std::exception &) {
					walked = false;
				}
				try {
					search.Set(saved, CatalogSetPathType::SET_SCHEMAS);
				} catch (std::exception &) {
					// a path that no longer sets (a schema the statement dropped): the default, never ours
					try {
						search.Reset();
					} catch (std::exception &) {
					}
				}
			}
			if (!walked) {
				captured->walk = LineageWalk();
				captured->walk.approximate = true;
			}
			captured->dataset_type = "VIEW";
			captured->lifecycle = "CREATE";
			break;
		}
		case LogicalOperatorType::LOGICAL_DROP: {
			auto &drop = *plan->Cast<LogicalDrop>().info;
			if (drop.type != CatalogType::TABLE_ENTRY && drop.type != CatalogType::VIEW_ENTRY) {
				return;
			}
			captured->object = PhysicalKey(input.context, drop.GetQualifiedName());
			captured->dataset_type = drop.type == CatalogType::VIEW_ENTRY ? "VIEW" : "TABLE";
			captured->lifecycle = "DROP";
			break;
		}
		case LogicalOperatorType::LOGICAL_ALTER: {
			auto &alter = *plan->Cast<LogicalAlter>().info;
			if (alter.type != AlterType::ALTER_TABLE && alter.type != AlterType::ALTER_VIEW) {
				return;
			}
			captured->object = PhysicalKey(input.context, alter.GetQualifiedName());
			captured->dataset_type = alter.type == AlterType::ALTER_VIEW ? "VIEW" : "TABLE";
			captured->lifecycle = "ALTER";
			break;
		}
		case LogicalOperatorType::LOGICAL_ATTACH: {
			auto &attach = *plan->Cast<LogicalAttach>().info;
			captured->object.kind = "physical";
			captured->object.catalog = attach.name.GetIdentifierName();
			string type;
			for (auto &option : attach.options) {
				if (StringUtil::CIEquals(option.first, "type") && !option.second.IsNull()) {
					type = option.second.ToString();
				}
			}
			if (type.empty()) {
				// a scanner's prefix names the source; anything else - a file, s3://, https:// - is a
				// database file wherever it lives
				type = "duckdb";
				auto colon = attach.path.find(':');
				if (colon != string::npos && colon > 1) {
					auto prefix = StringUtil::Lower(attach.path.substr(0, colon));
					for (auto known : {"postgres", "postgresql", "mysql", "sqlite", "ducklake", "quack", "mssql", "md",
					                   "motherduck"}) {
						if (prefix == known) {
							type = prefix;
						}
					}
				}
			}
			captured->source_type = StringUtil::Lower(type);
			captured->declared_identity = AttachLineageIdentity(input.context.GetCurrentQuery());
			captured->namespace_event = true;
			captured->lifecycle = "CREATE";
			break;
		}
		case LogicalOperatorType::LOGICAL_DETACH: {
			auto &detach = *plan->Cast<LogicalDetach>().info;
			captured->object.kind = "physical";
			captured->object.catalog = detach.name.GetIdentifierName();
			// still attached while the plan is made: its type is the catalog's own
			auto attached = DatabaseManager::Get(input.context).GetDatabase(input.context, detach.name);
			if (attached) {
				captured->source_type = StringUtil::Lower(attached->GetCatalog().GetCatalogType());
			}
			captured->namespace_event = true;
			captured->lifecycle = "DROP";
			break;
		}
		default:
			return;
		}
		if (captured->object.catalog.empty() || Bookkeeping(*store, captured->object.catalog)) {
			return;
		}
		captured->definition = true;
		SetPhysicalLineage(input.context, std::move(captured));
	} catch (...) {
		// the hook is never worth the statement
	}
}

} // namespace

void RegisterLineageOptimizer(DatabaseInstance &db, const shared_ptr<PolicyStore> &store) {
	OptimizerExtension extension;
	extension.pre_optimize_function = LineagePreOptimize;
	extension.optimizer_info = make_shared_ptr<LineageOptimizerInfo>(store);
	OptimizerExtension::Register(DBConfig::GetConfig(db), extension);
}

void EmitPhysicalLineage(const PhysicalLineage &captured, AuditPipeline &pipeline, DatabaseInstance &db, bool failed) {
	auto settings = LineageSettings::Read(db);
	if (!settings.on) {
		return;
	}
	if (captured.definition && failed) {
		return; // a definition that did not happen defines nothing
	}
	if (captured.namespace_event) {
		// a source's namespace (spec 107 §3): nothing finer is derived - the operator relates it to the
		// real address in the catalog itself
		auto lineage = make_shared_ptr<AuditLineage>();
		lineage->event_type = "NAMESPACE";
		AuditLineageDataset source;
		source.ns = settings.ns + "/source/" + captured.object.catalog;
		string identity_ns, identity_name;
		if (LineageSourceNameFor(db, captured.object.catalog, string(), string(), identity_ns, identity_name,
		                         captured.declared_identity)) {
			source.ns = identity_ns; // spec 112 §9: the source's own name, from its provider or its operator
		}
		source.dataset_type = StringUtil::Upper(captured.source_type.empty() ? string("source") : captured.source_type);
		source.physical = true;
		source.lifecycle = captured.lifecycle;
		lineage->datasets.push_back(std::move(source));
		lineage->outputs.push_back(0);
		if (!settings.physical) {
			return;
		}
		AuditEvent event;
		event.kind = "lineage";
		event.door = captured.door;
		event.level = AuditLevel::ALL;
		event.recorded = true;
		event.lineage = std::move(lineage);
		pipeline.Emit(std::move(event));
		return;
	}
	LineageWalk walk = captured.walk;
	if (captured.definition) {
		walk.has_target = true;
		walk.target = captured.object;
		walk.target_operation = captured.lifecycle;
	}
	auto lineage = LineageFromWalk(walk, settings);
	if (captured.definition) {
		lineage->event_type = "DATASET";
		for (auto &dataset : lineage->datasets) {
			auto expected = LineageDatasetFor(captured.object, settings);
			if (dataset.ns == expected.ns && dataset.name == expected.name) {
				dataset.lifecycle = captured.lifecycle;
				dataset.dataset_type = captured.dataset_type;
				for (auto &output : captured.walk.outputs) {
					AuditLineageField field;
					field.name = output.name;
					dataset.schema.push_back(std::move(field));
				}
			}
		}
	} else {
		lineage->event_type = failed ? "RUN_FAIL" : "RUN_COMPLETE";
		lineage->run_id = LineageRunId();
		lineage->job_ns = settings.ns + "/client/" + (captured.door.empty() ? string("operator") : captured.door);
		lineage->job_name = "physical:" + walk.target_operation;
	}
	if (settings.identity != "none" && !captured.principal.roles.empty()) {
		lineage->issuer = captured.principal.issuer;
		lineage->roles = captured.principal.roles;
		if (settings.identity == "subject") {
			lineage->subject = captured.principal.subject;
		}
	}
	AuditEvent event;
	event.kind = "lineage";
	event.door = captured.door;
	event.level = AuditLevel::ALL;
	event.recorded = true;
	event.lineage = std::move(lineage);
	pipeline.Emit(std::move(event));
}

shared_ptr<LineageJob> CaptureLineageJob(PolicyStore &store, const SQLStatement &statement, const Principal &principal,
                                         const string &door, const LineageContext &context) {
	if (!store.lineage_worker) {
		return nullptr;
	}
	bool write = false;
	bool read = false;
	switch (statement.type) {
	case StatementType::INSERT_STATEMENT:
	case StatementType::UPDATE_STATEMENT:
	case StatementType::DELETE_STATEMENT:
	case StatementType::MERGE_INTO_STATEMENT:
		write = true;
		break;
	case StatementType::CREATE_STATEMENT: {
		auto &info = statement.Cast<CreateStatement>().info;
		write = info && info->type == CatalogType::TABLE_ENTRY && info->Cast<CreateTableInfo>().query;
		break;
	}
	case StatementType::SELECT_STATEMENT:
		read = !context.parent.empty();
		break;
	default:
		break;
	}
	if (!write && !read) {
		return nullptr; // a read - the overwhelming case - leaves before any setting is read
	}
	auto db = store.instance.lock();
	if (!db || !LineageOn(*db)) {
		return nullptr;
	}
	auto job = make_shared_ptr<LineageJob>();
	job->statement = statement.Copy();
	// the claims ride along in memory: the worker's rewrite under the principal bakes them again, and
	// no event ever carries one
	job->principal = principal;
	job->context = context;
	job->door = door;
	job->declared_read = read;
	job->worker = store.lineage_worker;
	return job;
}

void EnqueueLineageRun(const shared_ptr<LineageJob> &job, bool failed) {
	if (!job) {
		return;
	}
	auto worker = job->worker.lock();
	if (worker) {
		worker->Enqueue(job, failed);
	}
}

shared_ptr<LineageWorker> StartLineageWorker(const shared_ptr<PolicyStore> &store,
                                             const shared_ptr<AuditPipeline> &pipeline, DatabaseInstance &db) {
	return make_shared_ptr<LineageWorker>(store, pipeline, db.shared_from_this());
}

void StopLineageWorker(LineageWorker &worker) {
	worker.Stop();
}

bool EnqueueLineageTask(LineageWorker &worker, std::function<void(PolicyStore &)> task) {
	return worker.EnqueueTask(std::move(task));
}

bool FlushLineageWorker(LineageWorker &worker, int64_t timeout_ms) {
	return worker.Flush(timeout_ms);
}

} // namespace acl
} // namespace duckdb
