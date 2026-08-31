// Per-principal policy state (specs/001): the policy shape, the per-instance PolicyStore with its
// resolver methods and template cache, and the info carriers that attach the store to DuckDB's parser
// extension and to the admin functions. In production the resolver methods become the read-only,
// role-aware ACL callbacks behind this same seam.

#pragma once

#include "duckdb/common/case_insensitive_map.hpp"
#include "duckdb/common/mutex.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/parser/parser_extension.hpp"
#include "duckdb/parser/qualified_name.hpp"
#include "duckdb/parser/query_node.hpp"
#include "duckdb/parser/statement/select_statement.hpp"

#include <functional>
#include <list>
#include <set>
#include <unordered_map>

namespace duckdb {
class DatabaseInstance;
class ClientContext;

namespace acl {

struct Principal {
	//! The token's subject within its issuer (spec 050 F5): part of a principal's identity, so two
	//! users sharing roles+claims are not one session. Empty for the ROLE form and the dev stub.
	string subject;
	vector<string> roles; // multi-role since spec 006 (union semantics); single-element until spec 007
	case_insensitive_map_t<string> claims;
	//! The one quack stream this principal is draining, when the statement being rewritten is the
	//! ingest INSERT the server generated for it (spec 042). Empty for every statement a client or a
	//! gateway wrote - which is what keeps the exemption it carries from reaching any of them.
	string ingest_stream;
	//! The statement is the Flight door's own composed ingest INSERT (spec 049): the function gate
	//! passes its arrow_scan source and nothing else. Set only by the ACL INGEST prefix, which only
	//! the door's C++ composes - never a client's or a gateway's text.
	bool arrow_ingest = false;
};

//! The exec-context seam (spec 050): the ClientContext of the connection a statement is being
//! prepared on, stashed in a thread-local by a door that owns the Prepare call site (the Flight door
//! does; quack's Prepare is quack's). The rewriter reads it to resolve session temp names
//! authoritatively; unset, it falls back to temp-qualifying, which binds only against the private
//! temp catalog and can never reach a physical object. `ParserOptions` carries no context, and a
//! live catalog lookup during the statement's own parse throws - this seam is what remains.
void SetTempScanContext(ClientContext *context);
ClientContext *TempScanContext();
//! Whether this connection's private temp catalog holds a table of this name - a direct read of the
//! committed entries via the no-context, no-transaction DuckCatalog scan (~70ns, measured;
//! independent of attached-catalog size). Safe on the parse thread: the door holds the connection's
//! exec lock around Prepare, so nothing else runs on the connection while this reads it.
bool TempCatalogHas(ClientContext &context, const string &name);
//! Every temp table name of the connection, for the metadata surfaces (spec 050): a session lists
//! its own temp objects and nobody else's - per-connection by construction.
vector<string> TempCatalogNames(ClientContext &context);

//! Policy for one virtual relation (table or view) under one role. The resolver picks the replacement
//! form: RENAME (subquery_form=false) swaps the name in place for a physical object - it stays a real
//! table, so it is writable; SUBQUERY (subquery_form=true) wraps a SELECT - projection with computed
//! columns / masks, an RLS predicate, or a full view SQL - and is read-only by construction (you cannot
//! write through a subquery). Claim values are baked in for either RLS or view/computed SQL.
struct TablePolicy {
	bool subquery_form = true; // true: wrap a SELECT (read-only); false: rename in place (writable)
	string phys;               // physical relation reference, e.g. "phys.main.orders_physical"
	vector<string> projection; // SQL select items (SUBQUERY), e.g. {"id", "NULL AS ssn", "amount*2 AS total"}
	string rls;                // predicate template (SUBQUERY); may contain acl_claim('<name>'); empty = none
	//! Whether some part of `rls` was never bound against this object (spec 027): the object did not
	//! exist where the predicate was written, so nothing judged what its names refer to. Harmless on a
	//! read - the binder decides - but a write with a second relation in scope must not inject a
	//! subquery whose free names could resolve against the source instead of the target (spec 020).
	bool rls_unchecked = false;
	string query; // full SELECT template for a view (SUBQUERY; replaces phys/projection/rls)
	//! How a grant narrows a *table function's* result (spec 038). The function's returns cannot be
	//! known without calling it, so the narrowing is expressed as SQL the engine resolves while it
	//! binds: masks in an inner `REPLACE` (which errors when the column is not there) and the listed
	//! names in an outer `COLUMNS(lambda …)` (which keeps what matches and ignores what does not).
	//! Wraps the call, which appears in it as the placeholder `"__acl_inner"`. Empty = no projection.
	string wrap_sql;
	case_insensitive_set_t caps; // {"select","insert","update","delete","merge"}
	//! Column renames of a writable (alias-form) relation: virtual name -> physical name. Renaming is
	//! not a restriction, so it does not force the read-only subquery form: reads go through
	//! `SELECT * RENAME (...)` (by name, so a new physical column can never shift an alias) and writes
	//! map the names back (spec 010). A restricting projection stays subquery-form and read-only.
	vector<std::pair<string, string>> renames;

	// --- grant-level policy (spec 011): a grant narrows an object without redefining it ------------
	//! Whether DML may target this relation. Independent of `subquery_form` since spec 011: a grant's
	//! predicate and injected values force the read-only *shape* on reads, while writes still go to
	//! the physical table with the predicate AND-ed in and the values assigned.
	bool writable = false;
	//! Columns a grant assigns on writes: physical column name -> value template (claims/constants
	//! only). On INSERT the value is added when absent and overridden when supplied; on UPDATE a SET
	//! of the column is overridden - so a row cannot be written outside the grant's slice.
	vector<std::pair<string, string>> injections;
	//! The physical columns a grant allows to be written; empty = unrestricted. Writing anything else
	//! is refused rather than silently dropped.
	case_insensitive_set_t write_columns;
	//! The same columns under the names the principal knows them by, in the order the object is
	//! published in (spec 042). duckdb matches an INSERT that names no columns by *position* against
	//! the table's full width and never by name, while a client counts the columns spec 035 published
	//! - so the list has to be supplied, or the client is counting columns it was never shown.
	vector<string> write_order;
};

//! Where a principal's DDL lands (spec 016): the virtual schema the written name belongs to, the
//! physical schema its grant creates in, and whether the catalog needs a record for what is made.
struct DdlTarget {
	string vcat;        // the virtual catalog
	string schema_path; // the virtual schema inside it
	string phys_schema; // `db.schema` the object is created in / dropped from
	bool needs_record;  // an expansion shows only its records, so a new object needs one
	bool virtual_only;  // the role may register existing objects, never create them
	string origin;      // the expansion's source, stamped on the record so REFRESH owns it too
};

//! One row set of the introspection surface (spec 010 part 3): the shape follows the active source,
//! so a listing never has to declare a schema of its own.
struct IntrospectionRows {
	vector<string> names;
	vector<LogicalType> types;
	vector<vector<Value>> rows;
};

//! Whether a function reference is a scalar/aggregate (expression position) or a table function (FROM)
enum class FunctionKind : uint8_t { SCALAR, TABLE };

//! What a principal may do with the ACL itself (spec 009). NONE is the default: the ACL is managed
//! by the gateway, not by the roles it serves.
enum class AdminScope : uint8_t { NONE, MANAGE, PASSTHROUGH };

//! Parse/print the scope names used by the admin functions, the grammar and the policy source
AdminScope ParseAdminScope(const string &scope);
const char *AdminScopeName(AdminScope scope);

//! One issuer's offline JWT verification config (spec 007): a row of acl.issuers, or the in-memory
//! issuer map. Keys are data, never fetched: the gateway/admin rotates them.
struct IssuerConfig {
	string issuer;
	string keys_json;            // JWKS ({"keys":[...]}: RSA n/e, EC P-256 x/y, oct k) or a PEM public key
	vector<string> audiences;    // allowlist; the token's aud (string or array) must intersect
	case_insensitive_set_t algs; // allowlist of {RS256, ES256, HS256}; anything else (incl. none) is refused
	string role_claim;           // dot path to the roles claim ("roles", "realm_access.roles", "groups")
	string claim_map;            // JSON: {"<jwt dot path>": "<acl_claim name>"}
	//! Where the keys are read from when they are not pasted in (spec 023): anything duckdb's own
	//! filesystem opens - an https JWKS URL (needs httpfs) or a file an operator refreshes out of
	//! band. Empty means `keys_json` is the whole truth.
	string jwks_uri;
};

//! duckdb answers "what is in this catalog?" three ways - a table function, a view of the same name
//! and `information_schema` - and under a principal all three are replaced by a listing of the
//! principal's own catalog (spec 010 part 3). Returns the surface a written name maps to, or nullptr.
//! The names are reserved: a virtual object may not take one, or it would be listed but unreachable.
const char *MetadataSurfaceOf(const string &name);

//! Split a comma-style list on top-level delimiters only: a delimiter inside quotes or inside
//! parentheses belongs to an expression, not to the list. Without this a column list breaks on the
//! first `coalesce(a, b)` - and breaks it silently, into two nonsense entries.
vector<string> SplitTopLevel(const string &text, char delimiter);

//! Whether a column list renames and nothing else - every entry is `virtual = <plain column>`. Such a
//! list keeps a relation in the writable alias form; anything else (a mask, a computed column) makes
//! it a read-only subquery. Since spec 029 both restrict alike, so this decides writability only -
//! and it is shared, because ADD and ALTER giving the same list two different forms is a bug.
bool RenameOnlyColumns(const vector<std::pair<string, string>> &columns);

//! Which functions are gated is a policy question, not the rewriter's: every function reference is
//! routed through the resolver, which decides. Most functions - the vast majority extensions add -
//! are pure transforms (e.g. ST_AsGeoJSON) and pass; only functions that read external data or route
//! queries past the ACL are denied (source readers like ST_Read/read_csv, cross-source scanners and
//! SQL passthrough like postgres_query/mssql_scan/query, session/secret access like getvariable). This
//! default denylist is a stub for the future role-aware ACL callback, which may classify differently
//! (and, for table functions it does not recognize, should lean to default-deny).
case_insensitive_set_t DefaultDeniedFunctions();

//! A small bounded LRU of parsed template prototypes. On a hit it returns a fresh Copy() of the
//! prototype (so the caller may bake markers into the copy); on a miss it parses via `parse`, caches the
//! prototype, and copies. Keyed by the exact template text, so a re-registered policy is a new key.
template <class T>
struct TemplateCache {
	static constexpr idx_t CAPACITY = 256;
	mutex lock;
	std::unordered_map<string, unique_ptr<T>> entries;
	std::list<string> recency; // front = least recently used
	std::unordered_map<string, std::list<string>::iterator> positions;

	unique_ptr<T> GetCopy(const string &key, const std::function<unique_ptr<T>()> &parse) {
		lock_guard<mutex> guard(lock);
		auto entry = entries.find(key);
		if (entry == entries.end()) {
			auto prototype = parse(); // may throw on a malformed template; nothing is cached then
			if (entries.size() >= CAPACITY && !recency.empty()) {
				auto victim = recency.front();
				entries.erase(victim);
				positions.erase(victim);
				recency.pop_front();
			}
			recency.push_back(key);
			positions[key] = std::prev(recency.end());
			entry = entries.emplace(key, std::move(prototype)).first;
		} else {
			recency.erase(positions[key]);
			recency.push_back(key);
			positions[key] = std::prev(recency.end());
		}
		return entry->second->Copy();
	}
};

namespace acl_detail {
struct CatalogBackend; // catalog-DB policy backend (spec 006), defined in acl_policy_catalog.cpp
} // namespace acl_detail

//! Per-database policy store: the seam the rewriter and the admin functions talk to. Two backends:
//! the in-memory maps below (default; dev/tests) and, once acl_use_db() ran, the catalog backend
//! (spec 006) reading policy from an ATTACHed database in standard duckdb dialect. Owned by
//! AclParserInfo (reached from the parser override) and shared with the admin setup functions via
//! ScalarFunctionInfo - no process-global state, so DB instances stay isolated.
struct PolicyStore {
	mutex lock;
	// role -> virtual name -> policy (tables and views share one namespace)
	case_insensitive_map_t<case_insensitive_map_t<TablePolicy>> tables;
	// role -> virtual table-function name -> policy (a separate namespace from relations)
	case_insensitive_map_t<case_insensitive_map_t<TablePolicy>> table_functions;
	// role -> virtual scalar-function name -> policy (subquery_form=true: expr macro; false: alias)
	case_insensitive_map_t<case_insensitive_map_t<TablePolicy>> scalar_functions;
	// token -> principal (the dev stub; a JWT-shaped token takes the real verification path instead)
	case_insensitive_map_t<Principal> tokens;
	//! Served sessions (spec 040): a door verifies a token once and every statement afterwards carries
	//! the handle instead. Handles are cryptographically random and case-sensitive, so this is a plain
	//! map. In-memory and per-instance for now; the shared backends a cluster needs come later.
	struct Session {
		Principal principal;
		//! A short, NON-secret id for the ops surface (spec 050): the handle is a bearer credential and
		//! must never appear in a listing or a log, so acl_sessions()/acl_session_kill() speak this
		//! instead. It authenticates nothing - only the handle/cookie can act as the session.
		string id;
		int64_t expires_at = 0; // seconds since the epoch; 0 = the token carried none (the dev stub)
		//! When it was last opened or resolved (spec 044). `exp` bounds a credential and says nothing
		//! about whether anyone is still there; a door sees connections that simply stop, so this is
		//! what ends them.
		int64_t last_used = 0;
	};
	unordered_map<string, Session> sessions;
	//! A door's own connection id -> our handle (spec 041). quack hands its `session_id` to the
	//! authentication callback and the same value as `connection_id` on every later message, so this
	//! is what turns "which connection is this" into "which principal is this" without the door ever
	//! holding one.
	unordered_map<string, string> session_bindings;
	//! Whether a door of ours is serving on this instance (spec 043); see SetDoorOpen.
	bool door_open = false;
	//! When sessions were last swept (spec 044), so the automatic sweep inside SessionOpen runs at most
	//! once a minute rather than on every arrival.
	int64_t last_sweep = 0;
	// issuer registry + external->role mappings (spec 007), memory-mode counterparts of the catalog
	case_insensitive_map_t<IssuerConfig> issuers;
	case_insensitive_map_t<case_insensitive_map_t<vector<string>>> role_mappings; // issuer -> external -> roles
	// role -> global administration scope (spec 009); per-catalog manage lives in the catalog grant
	case_insensitive_map_t<AdminScope> admin_scopes;
	// role -> default claims (used by the ROLE form, which carries no token)
	case_insensitive_map_t<case_insensitive_map_t<string>> role_claims;
	//! What an issuer's JWKS URI last yielded (spec 023). Reading is the whole mechanism: a TTL says
	//! when to read again, and a bounded staleness says how long a failed read may be survived.
	struct JwksEntry {
		string uri; // what these keys were read from: a different location is a different cache entry
		string keys_json;
		int64_t fetched_at = 0; // seconds since epoch of the last successful read; 0 = never
		int64_t tried_at = 0;   // last attempt, successful or not - the floor under retries
		string error;
	};
	case_insensitive_map_t<JwksEntry> jwks_cache;
	// gateway-wide function denylist (readers / rights-bypass); everything else passes
	case_insensitive_set_t denied_functions = DefaultDeniedFunctions();
	// parsed rewrite-template prototypes, so a template is parsed once and only copied per request
	TemplateCache<QueryNode> select_cache;      // relation / table-function subquery templates
	TemplateCache<ParsedExpression> expr_cache; // scalar macro templates
	// catalog backend (spec 006); present after acl_use_db()
	unique_ptr<acl_detail::CatalogBackend> catalog;

	// ctor/dtor out of line: the inline-defaulted versions would need ~CatalogBackend, incomplete here
	PolicyStore();
	~PolicyStore();

	//! Switch to the catalog backend: read policy from schema `schema` of the ATTACHed database
	//! `db_name` (standard duckdb dialect only). init=true creates/migrates the managed schema first.
	void EnableCatalog(DatabaseInstance &db, const string &db_name, const string &schema, bool init);
	//! Switch to the function-driver backend (spec 008): policy comes from registered table-function
	//! callbacks named by an explicit slot map (JSON); read-only by definition, fails closed at enable.
	void EnableFunctions(DatabaseInstance &db, const string &slots_json);
	bool CatalogEnabled() const {
		return catalog != nullptr;
	}

	// catalog admin operations (spec 006); each throws unless the catalog backend is enabled.
	// columns are (name, expr) pairs with an empty expr for a plain projected column.
	void CatalogCreate(const string &vcat, const string &comment);
	void CatalogAddRelation(const string &vcat, const string &vname, const string &form, const string &phys,
	                        const string &view_sql, const string &rls, const vector<std::pair<string, string>> &columns,
	                        const string &returns = string(), const string &pk = string(),
	                        const case_insensitive_map_t<int8_t> &nullable_marks = {});
	//! The declared primary key of an existing object (spec 048): empty csv drops it. Declared,
	//! never enforced; validated against the object's declared columns where they are known.
	void CatalogSetKey(const string &vcat, const string &vname, const string &kind, const string &pk);
	string ExistingKeyCsv(const string &vcat, const string &vname, const string &kind);
	//! Whether `db.schema.name` exists physically - what VIRTUAL ONLY checks before recording it
	bool PhysicalObjectExists(const string &phys);
	//! Record a view a role created (spec 018): its body was resolved with the author's rights, with
	//! claims left as markers, so reading it is decided by the grant on the view itself
	void CatalogRegisterView(const string &vcat, const string &vname, const string &body);
	//! Record an object a principal's own DDL just created (spec 016): alias form, the schema's
	//! origin, nothing else to choose
	void CatalogRegisterCreated(const string &vcat, const string &vname, const string &phys,
	                            const string &origin = string());
	//! The SQL behind a metadata surface for this principal (spec 010 part 3): duckdb's own shape,
	//! filtered to what the roles hold, with virtual names in place of physical ones. False when the
	//! active source cannot enumerate (memory mode); the driver mode throws with the reason.
	bool MetadataListing(const Principal &principal, const string &surface, string &sql);
	//! Read one listing of the active policy source for an operator (spec 010 part 3). `listing` names
	//! a table of the policy model ("relations", "grants", …) or "status". Throws when the active
	//! source cannot enumerate - silence on an admin surface reads as "nothing is configured".
	IntrospectionRows Introspect(const string &listing);
	//! Resolve where a principal's `CREATE`/`DROP` of `vname` lands, requiring `capability`
	//! (`create` or `drop`) on the virtual schema that owns the name (spec 016). False = no such
	//! schema for this principal; a schema without the capability throws.
	bool ResolveDdlTarget(const Principal &principal, const string &vname, const string &capability, DdlTarget &out);
	//! Grant/revoke one schema to a role (spec 015): capabilities only, `manage` refused. Both
	//! rematerialise the subtree, so the stored rows always show what a role effectively has.
	void CatalogGrantSchema(const string &role, const string &vcat, const string &path, const string &caps_json,
	                        const string &comment = string(), const string &into = string(), bool virtual_only = false);
	void CatalogRevokeSchema(const string &role, const string &vcat, const string &path);
	//! "Rebuild this subtree from the nearest ancestor that states capabilities" - idempotent, so
	//! grants, schema DDL and drift repair are all the same call (spec 015)
	void CatalogRematerializeSchemaCaps(const string &vcat, const string &path);
	//! Expand a physical schema into one virtual record per object (spec 014): a snapshot the admin
	//! can then edit object by object, unlike the live alias
	void CatalogExpandSchema(const string &vcat, const string &path, const string &phys_path);
	//! Re-read an expansion's source: add what appeared, and with `prune` remove what is gone. A
	//! record dropped on purpose is not resurrected. Returns how many rows changed.
	int64_t CatalogRefreshSchemaObjects(const string &vcat, const string &path, bool prune);
	//! One schema row (spec 014): a physical path makes it a live alias, an origin makes it an
	//! expansion whose content is the catalog's own records, neither makes it a plain namespace
	void CatalogAddSchemaAlias(const string &vcat, const string &alias_path, const string &phys_path,
	                           const string &origin = string());
	//! `params`/`returns` are the declared signature and result ("name TYPE, …"): a declared result is
	//! stored as-is and never probed - an argument-dependent template cannot be typed from NULLs, and
	//! binding admin SQL at write time would touch the sources (spec 010)
	void CatalogAddFunction(const string &vcat, const string &vname, const string &kind, const string &form,
	                        const string &target, const string &template_sql, const string &params = string(),
	                        const string &returns = string(), const string &pk = string(),
	                        const case_insensitive_map_t<int8_t> &nullable_marks = {}, bool pk_carried = false);
	//! spec 022: a reference is a declared join path between two objects - a hint, never a constraint.
	//! Either `pairs` ("from_col=to_col, …") or `expr` (a qualified SQL condition), never both.
	//! `to_kind` is "relation" or "function": a table function end is fed arguments (a lateral call),
	//! so the pairs read "source column => parameter" and are checked against its declared signature.
	void CatalogAddReference(const string &vcat, const string &name, const string &from_vname, const string &to_vname,
	                         const string &to_kind, const string &args, const string &pairs, const string &expr,
	                         const string &cardinality, bool optional, const string &join_method,
	                         const string &comment);
	void CatalogDropReference(const string &vcat, const string &name);
	void CatalogGrant(const string &role, const string &vcat, const string &caps_json, bool is_main,
	                  const string &rls = "", const string &columns = "");
	void CatalogRevoke(const string &role, const string &vcat);
	void CatalogDropRelation(const string &vcat, const string &vname);
	// DROP of the remaining virtual-catalog elements (spec 010). Dropping a catalog removes its own
	// definitions always; the role grants pointing at it need `cascade`, so an accidental drop cannot
	// silently revoke people's access.
	//! Comments on virtual objects and their columns (spec 010); `kind` is relation|table|scalar,
	//! `column` empty means the object itself
	void CatalogSetComment(const string &vcat, const string &vname, const string &kind, const string &column,
	                       const string &comment);
	//! Re-derive the stored column schema of query-defined objects: one object, or a whole catalog
	idx_t CatalogRefreshSchema(const string &vcat, const string &vname);
	void CatalogDropCatalog(const string &vcat, bool cascade);
	void CatalogDropSchemaAlias(const string &vcat, const string &alias_path, bool cascade = false);
	void CatalogDropFunction(const string &vcat, const string &vname, const string &kind);
	void CatalogDropRole(const string &role);
	void CatalogDropIssuer(const string &issuer);
	void CatalogDropRoleMapping(const string &issuer, const string &source, const string &external_value,
	                            const string &role);
	void CatalogDefineRole(const string &role, const case_insensitive_map_t<string> &claims);
	//! remove=true deletes the gate row (fall back to the default denylist); otherwise upserts it
	void CatalogSetFunctionGate(const string &name, bool allowed, bool remove);
	void CatalogDefineIssuer(const IssuerConfig &config);
	// ALTER operations (spec 009): partial change of an EXISTING object - unlike the ADD/GRANT
	// upserts, a missing target is an error. field names the single property being set.
	void CatalogAlterRelation(const string &vcat, const string &vname, const string &field, const string &value,
	                          const vector<std::pair<string, string>> &columns,
	                          const case_insensitive_map_t<int8_t> &nullable_marks = {});
	void CatalogAlterSchemaAlias(const string &vcat, const string &alias_path, const string &phys_path);
	void CatalogAlterFunction(const string &vcat, const string &vname, const string &kind, const string &form,
	                          const string &definition);
	void CatalogAlterCatalog(const string &vcat, const string &comment);
	void CatalogAlterRole(const string &role, const case_insensitive_map_t<string> &claims);
	void CatalogAlterGrant(const string &role, const string &vcat, const string &field, const string &value);
	void CatalogAlterIssuer(const string &issuer, const string &field, const string &value);
	void CatalogGrantAdmin(const string &role, const string &scope);
	void CatalogRevokeAdmin(const string &role);
	//! role -> (scope, vcat) rows of the principal; missing roles simply do not appear
	//! Both administration sources of the principal, version-cached: the catalogs whose grant carries
	//! the "manage" capability, and the (scope, vcat) rows of acl.admins (a non-empty vcat restricts
	//! a manage scope to that catalog; the driver may return several rows per role)
	void CatalogAdminRights(const Principal &principal, std::set<string> &catalogs,
	                        vector<std::pair<string, string>> &scopes);
	bool CatalogAnonymousAdminAllowed();
	void CatalogMapRole(const string &issuer, const string &source, const string &external_value, const string &role);
	//! per-object grant: its capabilities and (spec 011) the policy it imposes on the object
	void CatalogSetObjectCaps(const string &role, const string &vcat, const string &vname, const string &caps_json,
	                          const string &rls = "", const string &columns = "");
	//! Whether an object of that kind already exists - what CREATE / CREATE OR REPLACE /
	//! CREATE IF NOT EXISTS decide on (spec 013). kind: catalog|role|issuer|schema|relation|table|scalar
	bool CatalogObjectExists(const string &vcat, const string &vname, const string &kind);
	//! refuse a grant naming an object nobody defined - a policy that never applies is worse than none
	//! - and a policy on a scalar function, which has neither rows nor columns to narrow
	void CatalogRequireGrantTarget(const string &vcat, const string &vname, bool with_policy, const string &caps_json);
	//! ensure a role->catalog grant row exists without clobbering an existing one
	void CatalogEnsureGrant(const string &role, const string &vcat, bool is_main);

	//! Instantiate a SELECT template: a fresh SelectStatement whose node is a copy of the cached
	//! prototype (parsed once). The caller bakes markers into the copy.
	unique_ptr<SelectStatement> InstantiateSelect(const string &sql, const ParserOptions &options);
	//! Instantiate an expression template: a fresh copy of the cached parsed prototype.
	unique_ptr<ParsedExpression> InstantiateExpr(const string &expr, const ParserOptions &options);

	//! Does a capability sit EXPLICITLY on the principal's MAIN catalog grant (spec 050)? Explicit
	//! means written: an unstated caps column defaults to the data capabilities (spec 012), and
	//! `temp` is deliberately not among them, so this answers false unless somebody granted it.
	//! Memory mode has no catalog grants and answers false - the session-temp surface needs a policy
	//! catalog, like the rest of the served story.
	bool PrincipalMainCap(const Principal &principal, const string &capability);
	bool CatalogPrincipalMainCap(const Principal &principal, const string &capability);

	//! Verify a principal offline. A JWT-shaped token goes through real signature verification against
	//! the issuer registry (spec 007, throws with a specific reason on failure); a non-JWT token is a
	//! dev-stub lookup in the in-memory map; the ROLE form trusts the gateway.
	bool VerifyPrincipal(bool is_token, const string &value, Principal &out, bool ignore_exp = false);
	//! Verify a token and mint an opaque handle for it (spec 040). Empty when the token does not
	//! verify: a door refuses rather than learning why, and the reason belongs to whoever verified.
	string SessionOpen(const string &token);
	//! The principal behind a handle, or false with `reason` saying which of "unknown" / "expired" it
	//! is - a client that reconnects needs to tell those apart.
	bool SessionPrincipal(const string &handle, Principal &out, string &reason);
	//! Is this session live right now, without touching its idle clock. The door's connection sweep
	//! asks this for every held connection, and an observer must not keep the observed alive.
	bool SessionAlive(const string &handle);
	//! Why a handle is not usable, judged read-only (no bump, no erase, like SessionAlive): one of
	//! "live", "expired" (the token's exp passed), "idle" (swept for inactivity) or "unknown" (no such
	//! session - closed, never opened, or already swept). Spec 054: a client that reconnects needs to
	//! tell "get a fresh token" (expired) from "reopen with the same one" (idle/unknown), which one
	//! NULL never told it. Read-only so it survives a prior SessionSql that returned NULL.
	string SessionReason(const string &handle);
	//! The statement a door should run instead of the client's: the same SQL with `ACL SESSION '<h>'`
	//! in front, or empty when the session is not usable. The whole outward contract of spec 040 in one
	//! call, so that a second door composes it the same way the first one does rather than similarly.
	string SessionSql(const string &handle, const string &sql);
	//! End a session. Idempotent: closing an unknown handle is not an error, since a door may retry.
	void SessionClose(const string &handle);
	//! Bind a door's connection id to a handle, and look one up. Binding an id that is already bound
	//! replaces it: a door that reconnects under the same id gets the session it just authenticated.
	void SessionBind(const string &external_id, const string &handle);
	bool SessionHandleFor(const string &external_id, string &handle);
	//! Drop every session and binding, and say how many there were. What a door does when it closes:
	//! the connections it served will never come back, and nothing else can tell that they are gone.
	idx_t SessionCloseAll();

	//! Drop every session that has expired or gone idle, and the bindings pointing at them; returns how
	//! many went (spec 044). Runs on request through `acl_session_sweep()`, and by itself inside
	//! SessionOpen - the operation that grows the map is the one that pays to clean it, so there is no
	//! thread to own and no cost on a quiet instance.
	idx_t SessionSweep();
	//! Every issuer the policy names, for the doors' discovery documents (spec 062).
	vector<string> ListIssuers();
	//! The sweep proper; the caller holds the lock and has read the settings before taking it.
	idx_t SweepLocked(int64_t now, int64_t skew, int64_t idle, bool exp_binds);
	//! How many sessions are live right now. Denied to a principal, like the rest of this surface.
	idx_t SessionCount();
	//! One live session, for the admin ops surface (spec 050) - never the handle.
	struct SessionInfo {
		string id;
		string subject;
		vector<string> roles;
		int64_t expires_at = 0;
		int64_t idle_seconds = 0;
	};
	//! A snapshot of the live sessions - admin-only (the door's, not a principal's).
	vector<SessionInfo> SessionList();
	//! End the session with this ops id; true if one was found. Admin-only.
	bool SessionKill(const string &id);
	//! Settings behind the two rules (spec 044): seconds a session may go unused before it is dead
	//! (0 = never), and how many may live at once (0 = unlimited).
	int64_t SessionIdleTimeout();
	//! spec 059: true when acl_session_token_binding = every_use - the token exp is re-judged on every
	//! use of a live session; false (connect, the default) binds freshness to establishment only.
	bool SessionExpEveryUse();
	int64_t MaxIngestRows();
	int64_t MaxSessions();

	//! Is an ACL door serving on this instance (spec 043)? Set by `acl_quack_serve`, cleared when the
	//! last door stops. It gates the one thing we do to statements nobody prefixed: refusing a drained
	//! quack stream. That refusal exists because a client *we serve* caused the statement; where no
	//! door of ours is open, a plain quack server's own ingest is its business, and breaking it would
	//! be us disabling an unrelated feature for anyone who merely loads this extension. Measured, not
	//! supposed: the throughput benchmark's un-ACL'd baseline could not bulk-load at all.
	void SetDoorOpen(bool open);
	bool DoorOpen();

	//! Register an issuer / map an external role value (memory mode; catalog mode via the Catalog* ops)
	void DefineIssuer(IssuerConfig config);
	void MapRole(const string &issuer, const string &source, const string &external_value, const string &role);

	//! Grant/revoke a GLOBAL ACL-administration scope for a role (spec 009). Managing one catalog is
	//! not granted here - it is a capability of the catalog grant itself ({"manage": true}).
	void GrantAdmin(const string &role, AdminScope scope);
	void RevokeAdmin(const string &role);
	//! What a principal may do with the ACL. `unrestricted_manage` is a separate flag rather than a
	//! sentinel inside `catalogs`: an empty/odd catalog name must never widen a grant (spec 009).
	struct AdminRights {
		AdminScope scope = AdminScope::NONE;
		bool unrestricted_manage = false;
		//! catalogs this principal may manage, compared exactly - the policy source compares vcat with
		//! SQL `=`, so authorizing case-insensitively would authorize a different catalog
		std::set<string> catalogs;
	};
	//! The principal's effective rights: the strongest over its roles and its catalog grants
	AdminRights AdminRightsOf(const Principal &principal);
	//! Whether an anonymous `ACL ADMIN` (no principal) is still permitted: always in the in-memory
	//! dev mode, and with a policy source only when acl_allow_anonymous_admin is on (spec 009).
	bool AnonymousAdminAllowed();

	bool ResolveTable(const Principal &principal, const string &vname, TablePolicy &out);
	bool ResolveTableFunction(const Principal &principal, const string &vname, TablePolicy &out);
	bool ResolveScalarFunction(const Principal &principal, const string &vname, TablePolicy &out);

	//! The resolver seam every non-virtual function flows through. Catalog backend: function_gate rows
	//! (per-role, then global) decide first; otherwise the built-in denylist passes everything except
	//! source readers / rights-bypass functions (matching the last name component, so a qualified alias
	//! db.schema.read_csv cannot slip past).
	bool FunctionAllowed(const Principal &principal, const QualifiedName &name);

	//! The current `allow_parser_override_extension` value. DEFAULT means duckdb skips every parser
	//! override, so no `ACL …` statement parses and nothing is enforced (spec 017).
	string ParserOverrideMode();

private:
	bool Resolve(const case_insensitive_map_t<case_insensitive_map_t<TablePolicy>> &space, const Principal &principal,
	             const string &vname, TablePolicy &out);

	//! The real JWT path of VerifyPrincipal (spec 007): issuer lookup -> acl_token verification ->
	//! role mapping -> claims; throws on any failure. Defined in acl_policy.cpp.
	void VerifyJwtPrincipal(const string &token, const string &issuer, Principal &out, bool ignore_exp = false);
	bool LookupIssuer(const string &issuer, IssuerConfig &out);
	//! spec 023: the keys to verify with. An issuer that names a JWKS URI has them read through
	//! duckdb's filesystem and cached per instance; one that pastes a JWKS keeps using it. `kid` is
	//! the token's, so a key that rotated in since the last read triggers one extra read.
	string ResolveIssuerKeys(const IssuerConfig &config, const string &kid);
	//! acl_jwt_clock_skew setting (seconds); the memory mode uses the 60s default (no db handle)
	int64_t JwtClockSkew();
	int64_t JwksRefreshInterval();
	int64_t JwksMaxStale();
	//! Map raw role-claim values through role_mappings; unmapped values pass only if the role exists
	vector<string> MapExternalRoles(const string &issuer, const vector<string> &raw_roles);

	// catalog-backend bridges, defined in acl_policy_catalog.cpp (the backend type stays private there)
	bool CatalogResolveTable(const Principal &principal, const string &vname, TablePolicy &out);
	bool CatalogResolveFunction(const Principal &principal, const string &vname, bool table_kind, TablePolicy &out);
	//! returns true when a gate row decides; `allowed` then carries the verdict
	bool CatalogFunctionGate(const Principal &principal, const QualifiedName &name, bool &allowed);
	void CatalogLoadRoleClaims(Principal &principal);
	bool CatalogLookupIssuer(const string &issuer, IssuerConfig &out);
	void CatalogListIssuers(vector<string> &out);
	//! (external_value -> mapped roles) for the given values; also flags which candidates exist as roles
	void CatalogMapExternalRoles(const string &issuer, const vector<string> &values,
	                             case_insensitive_map_t<vector<string>> &mapped, case_insensitive_set_t &known_roles);
};

//! Carried on the parser extension (parser_info); the override reads the store from it.
struct AclParserInfo : ParserExtensionInfo {
	explicit AclParserInfo(shared_ptr<PolicyStore> store_p) : store(std::move(store_p)) {
	}
	shared_ptr<PolicyStore> store;
};

//! Carried on each admin setup scalar function (function_info); reaches the same store at execution.
struct AclScalarInfo : ScalarFunctionInfo {
	explicit AclScalarInfo(shared_ptr<PolicyStore> store_p) : store(std::move(store_p)) {
	}
	shared_ptr<PolicyStore> store;
};

} // namespace acl
} // namespace duckdb
