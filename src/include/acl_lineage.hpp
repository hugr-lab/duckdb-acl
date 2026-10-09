//===----------------------------------------------------------------------===//
// acl_lineage.hpp - spec 107: lineage facts for OpenLineage
//
// The node's side of the `lineage` event kind (duckdb-ext-common spec 014, acl_audit v3): the
// settings, the names datasets get, the conversion of a walk (acl_lineage_walker.hpp) into the
// contract's payload, the JSON a ring row and a test read, and `acl_lineage_events()`. The transport
// to OpenLineage is acl-otel's; nothing here talks to a backend.
//===----------------------------------------------------------------------===//

#pragma once

#include "acl_audit.hpp"
#include "acl_principal.hpp"
#include "acl_lineage_walker.hpp"

#include <functional>

namespace duckdb {

class DatabaseInstance;
class ExtensionLoader;
struct DBConfig;

class SQLStatement;

namespace acl {

class AuditPipeline;
struct PolicyStore;
class LineageWorker;

//! The node's lineage settings (all GLOBAL, all cluster-profile items), read where an event is made.
struct LineageSettings {
	//! acl_lineage_level = on AND a namespace is set (spec 112: no namespace, no lineage - the switch)
	bool on = false;
	string ns;                  // acl_lineage_namespace: the cluster's (a cluster-profile item); no default
	string identity = "client"; // acl_lineage_identity: none / client / subject
	bool sql = false;           // acl_lineage_sql = normalized
	bool physical = true;       // acl_lineage_physical
	idx_t max_edges = 4096;     // acl_lineage_max_edges
	//! spec 112 §9: the instance the settings were read from - where a physical source's name is
	//! asked (the provider registry, the declared identities); valid while the reader holds it
	optional_ptr<DatabaseInstance> db;
	static LineageSettings Read(DatabaseInstance &db);
};

//! spec 112: why lineage is or is not sent - `on`, `off`, or `no namespace: …`
string LineageStatus(DatabaseInstance &db);

//! spec 112 §9: a physical dataset's name from its source's identity - a provider of the
//! acl_lineage_sources registry (hugr_node), then the identity the operator declared
//! (acl_lineage_source / ATTACH … LINEAGE); false = neither, the alias form stands. `schema` and
//! `name` empty ask about the catalog itself (its namespace).
bool LineageSourceNameFor(DatabaseInstance &db, const string &catalog, const string &schema, const string &name,
                          string &out_ns, string &out_name, const string &declared = string());
//! An identity has no userinfo (`user:pass@`): it is a name, never a credential.
bool LineageIdentityClean(const string &identity);

//! The client's lineage context of one statement: the job and the external run it is a step of.
struct LineageContext {
	string job;         // acl_lineage_job / x-openlineage-job / JOB marker
	string parent;      // OPENLINEAGE_PARENT_ID format: <namespace>/<job>/<runId>
	string root_parent; // the same format
};

//! Register the settings (session ones on spec 068's allowlist: acl_lineage_parent / _root_parent / _job).
void AddLineageOptions(DBConfig &config);
//! The three session settings a principal may SET on a session of its own (spec 068 + 107).
bool LineageClientSetting(const string &name);

//! The OpenLineage name of a dataset the walk found.
AuditLineageDataset LineageDatasetFor(const LineageDatasetKey &key, const LineageSettings &settings);
//! Parse `<namespace>/<job>/<runId>`; an empty or malformed reference is empty.
AuditLineageRunRef ParseLineageRunRef(const string &text);
//! spec 109: whether a parent / root parent is `<namespace>/<job>/<runId>` with a UUID runId (what
//! OpenLineage's ParentRunFacet requires); '' is no parent and passes. `error` says what is expected,
//! never echoing the value.
bool LineageRunRefCheck(const string &text, string &error);

//! A walk's datasets and edges as the contract's payload; `writes` = the walk's target is an output.
//! Physical datasets (and their edges) are dropped when the settings say so.
shared_ptr<AuditLineage> LineageFromWalk(const LineageWalk &walk, const LineageSettings &settings);

//! The payload as one JSON object - the ring row's `payload` column; acl-otel renders its own.
string AuditLineageJson(const AuditLineage &lineage);

//! A random v4 UUID for a run.
string LineageRunId();

//! Bind `sql` (a definition: a view's SQL, an object's projection over its source - markers already
//! baked) on a fresh connection of `db`, without executing it, and walk the plan. Tables are physical
//! datasets (their attached catalog, schema, name); false when it does not bind.
bool WalkDefinition(DatabaseInstance &db, const string &sql, idx_t max_edges, LineageWalk &out);

//! A static event: what a virtual object of `vcat` is defined as (`walk` may be null: a DROP, or a
//! definition that did not bind - then `approximate`). Emitted only when acl_lineage_level is on.
void EmitDefinitionLineage(AuditPipeline &pipeline, DatabaseInstance &db, const string &vcat, const string &vname,
                           const string &dataset_type, const string &lifecycle, const LineageWalk *walk,
                           const vector<AuditLineageTag> &tags = {});

//! A statement the override decided that lineage covers (a write, or a read under a declared parent):
//! what the worker needs to say, off the statement's path, what it read and wrote in the principal's
//! own names. Made at decision time, run once per execution (QueryEnd) with its outcome.
struct LineageJob {
	unique_ptr<SQLStatement> statement; // the statement as written, before the rewrite
	Principal principal;
	LineageContext context;
	string door;
	int64_t decision_seq = -1;
	bool declared_read = false; // a SELECT under a parent: inputs only
	weak_ptr<LineageWorker> worker;
};

//! The override, before the rewrite: a job when lineage is on and the statement is in scope (DML, a
//! CREATE TABLE AS, a read when `context.parent` is set), else null. Copies the statement.
shared_ptr<LineageJob> CaptureLineageJob(PolicyStore &store, const SQLStatement &statement, const Principal &principal,
                                         const string &door, const LineageContext &context);
//! QueryEnd: hand one execution of a job to the worker (never blocks; a full queue drops, counted).
void EnqueueLineageRun(const shared_ptr<LineageJob> &job, bool failed);
//! The store's worker: started at load, stopped by the store's teardown (from any thread, its own too).
shared_ptr<LineageWorker> StartLineageWorker(const shared_ptr<PolicyStore> &store,
                                             const shared_ptr<AuditPipeline> &pipeline, DatabaseInstance &db);
void StopLineageWorker(LineageWorker &worker);
//! A static event's work (spec 107: a definition read back, probed, bound; per-role tags), run on the
//! worker with the store and the instance it holds for the job; false when the worker no longer runs.
bool EnqueueLineageTask(LineageWorker &worker, std::function<void(PolicyStore &)> task);
//! Whether acl_lineage_level is on - the one setting a statement's own path reads.
bool LineageOn(DatabaseInstance &db);
//! Wait until the jobs queued so far are done (tests: `acl_lineage_flush()`); false on timeout.
bool FlushLineageWorker(LineageWorker &worker, int64_t timeout_ms = 30000);

//! A statement nobody decided under a principal's virtual catalog - an operator's or a gateway's own
//! SQL, `ACL NATIVE` - that writes or defines something physical: its lineage, taken from the bound
//! plan by the pre-optimize hook, emitted by QueryEnd with the outcome. Physical names: there is no
//! rewrite to undo.
struct PhysicalLineage {
	LineageWalk walk;
	bool definition = false; // a DDL statement: a DatasetEvent (emitted only when it succeeded)
	string lifecycle;        // CREATE / ALTER / DROP
	string dataset_type;     // TABLE / VIEW
	LineageDatasetKey object;
	//! ATTACH / DETACH (and the cluster items that run them): a source's namespace, its type
	bool namespace_event = false;
	string source_type;
	//! spec 112 §9: the identity an `ATTACH … LINEAGE '<x>'` declares - its own NAMESPACE event is
	//! named by it already (the declaring call runs after the ATTACH)
	string declared_identity;
	Principal principal; // `ACL NATIVE`'s principal; empty for the node's operator
	string door;
};

//! Register the pre-optimize hook that captures physical statements (spec 107).
void RegisterLineageOptimizer(DatabaseInstance &db, const shared_ptr<PolicyStore> &store);
//! QueryEnd: the event of a physical statement's lineage.
void EmitPhysicalLineage(const PhysicalLineage &lineage, AuditPipeline &pipeline, DatabaseInstance &db, bool failed);

//! `acl_lineage_events()` - the operator's view of the lineage ring - and `acl_lineage_flush()`, which
//! waits for the worker and the audit queue (tests). Never a principal's: `acl_` is spec 072's never set.
void RegisterAclLineage(ExtensionLoader &loader, const shared_ptr<PolicyStore> &store,
                        const shared_ptr<AuditPipeline> &pipeline);

} // namespace acl
} // namespace duckdb
