//===----------------------------------------------------------------------===//
// acl_platform.hpp — the `platform` catalog (spec 117)
//
// A system virtual catalog that answers an administrator's questions and takes its changes without
// `ACL NATIVE`: views over the policy and the node (typed columns, rows scoped to the caller) and
// management functions `platform.<op>(…)` called at the top level of a statement. It is synthesized -
// never stored in the policy catalog - and its name is reserved.
//
// This module is the ONE authorizer of administration: every compiled management call - the grammar's
// (`ACL <mgmt>`, or the bare form under a principal) and a direct `platform.<op>(…)` - is judged here by
// the right its operation requires, against the principal's bundles, its catalogs' manage and its point
// grants on `platform`. The views and functions a principal holds are what the listings show of
// `platform`, so a tool's tree is exactly what the admin may use.
//===----------------------------------------------------------------------===//

#pragma once

#include "acl_policy.hpp"
#include "acl_function_categories.hpp"

#include <functional>

namespace duckdb {
class SQLStatement;
class ExtensionLoader;
class ParsedExpression;

namespace acl {

//! The reserved name of the catalog
constexpr const char *PLATFORM_CATALOG = "platform";

//! Whether a catalog name (a key or an identifier) is the reserved `platform` (compared as names compare)
bool IsPlatformCatalog(const string &name);

//! Who reads a view with a bundle, and how its rows narrow
enum class PlatformViewClass : uint8_t {
	NODE,    //! the node's state - the observe bundle
	POLICY,  //! the policy - the policy bundle, all rows
	CATALOG, //! the policy - the policy bundle (all rows), or a catalog admin (its catalogs' rows)
	ROLES,   //! role names - the policy bundle (every role), or a catalog admin (the roles holding its catalogs)
	CLUSTER  //! the cluster profile - passthrough alone until spec 118's `cluster` bundle
};

//! The right a management operation requires (what spec 009's provenance table said, as a class)
enum class PlatformRight : uint8_t {
	CATALOG,        //! the policy bundle, or manage on the catalog its catalog argument names
	POLICY,         //! the policy bundle (not catalog-specific)
	HANDS_OUT,      //! the policy bundle: handing out access is privilege administration
	ESCALATES,      //! passthrough only: the admin scopes and the grants on `platform`
	INFRASTRUCTURE, //! passthrough only: the cluster profile (spec 093) - until spec 118's `cluster`
	OPERATE,        //! passthrough only: a node / session operation (a session's profile) - until spec 118's `operate`
	OPEN            //! every principal holding anything on `platform` (console_info)
};

struct PlatformColumn {
	const char *name;
	const char *type;
};

struct PlatformView {
	const char *name;
	PlatformViewClass view_class;
	vector<PlatformColumn> columns;
	const char *comment;
};

struct PlatformParam {
	const char *name;
	//! carries authorization (a catalog, a role, an object): must be a constant - it is judged before
	//! the call runs, and a parameter cannot be
	bool authz;
	//! the argument's type in the target signature ("VARCHAR" | "BOOLEAN" | "VARCHAR[]")
	const char *type;
	//! what an argument left out stands for when a later one is given (the target's own fallback): a
	//! NULL would make the whole call NULL, the admin functions' NULL handling being the default one
	const char *fallback;
};

struct PlatformFunction {
	const char *name;   //! platform.main.<name>
	const char *target; //! the acl_* function it is
	vector<PlatformParam> params;
	vector<idx_t> arities; //! the target's signatures, ascending
	int catalog_arg;       //! the parameter naming the catalog, -1 none
	PlatformRight right;
	bool table;          //! a table function, called in FROM (read-only)
	const char *returns; //! the result type, for the listings
	const char *comment;
};

const vector<PlatformView> &PlatformViews();
const vector<PlatformFunction> &PlatformFunctions();
optional_ptr<const PlatformView> FindPlatformView(const string &name);
optional_ptr<const PlatformFunction> FindPlatformFunction(const string &name);
//! The platform function an acl_* call is, or nullptr
optional_ptr<const PlatformFunction> PlatformFunctionByTarget(const string &target);

//! The leaf a written name gives `platform`'s objects - `platform.x` / `platform.main.x` (parts as
//! written, the object's own name last); false when the name is not `platform`'s
bool PlatformObjectName(const vector<string> &parts, string &leaf);

//! What a principal holds on `platform`, decided from its rights (spec 117 §5)
struct PlatformAccess {
	const PolicyStore::AdminRights *rights = nullptr;
	//! may read this view; `rows_scoped` = only the rows of `rights->catalogs` (a catalog admin)
	bool ReadsView(const PlatformView &view, bool &rows_scoped) const;
	//! may call this function at all (the per-call judgement - which catalog - is the authorizer's)
	bool CallsFunction(const PlatformFunction &function) const;
	//! holds anything on `platform`: the catalog appears in the listings, console_info answers
	bool Any() const;
};

//! The one authorizer (spec 009's AuthorizeMgmt, moved and widened): every compiled management call of
//! the batch is judged against `rights`, a refusal anywhere throws before any statement runs, and a call
//! it does not know is refused, never waved through.
void AuthorizeMgmt(vector<unique_ptr<SQLStatement>> &statements, const PolicyStore::AdminRights &rights);
void AuthorizeAdminCall(SQLStatement &statement, const PolicyStore::AdminRights &rights);
//! What the static table cannot see (spec 117 review): a role mapping whose target role administers hands
//! that administration to whoever holds the claim - spec 095 admits it because the mapping is the client's
//! own - so mapping to a privileged role is the passthrough scope's alone, as granting the bundle is
void AuthorizeRoleTargets(vector<unique_ptr<SQLStatement>> &statements, const PolicyStore::AdminRights &rights,
                          PolicyStore &store);

//! The shape a stored definition body is written in
enum class BodyShape : uint8_t { SELECT, EXPRESSION, COLUMNS, FUNCTION_NAME };
//! Every function a stored body calls, as written (a table function's kind TABLE) - the markers acl_claim /
//! acl_arg left out. Throws when the body does not parse (a body nobody can judge is refused).
void WalkBodyCalls(const string &text, BodyShape shape,
                   const std::function<void(const QualifiedName &name, FunctionKind kind)> &callback);
//! spec 117 review D1: the bodies a compiled management call stores (a view, a macro template, an alias
//! target, an RLS, a column / mask expression, a remap) run as the node when read - so a principal who is
//! not passthrough may store only what its OWN function gate admits (spec 072: its roles' categories and
//! grants by name, a deny wins, the never set always refused). The anonymous gateway and the operator's
//! connection stay trusted.
void AuthorizeBodies(vector<unique_ptr<SQLStatement>> &statements, const PolicyStore::AdminRights &rights,
                     PolicyStore &store, const Principal &author);
//! spec 117 review D2: a change to an issuer or a client that carries a mapping to a role holding
//! administration repoints the trust anchor behind it - passthrough's alone. Inside AuthorizeRoleTargets.

//! A top-level `SELECT platform.f(<args>)` (one item, no FROM / WHERE / CTE / modifiers) or
//! `CALL platform.f(<args>)` of a management function, compiled to the acl_* call it is (named
//! arguments put in place, typed ones converted, gaps filled). False when the statement is not one;
//! throws when it is one written wrongly (an unknown function, a parameter where authorization is
//! carried, an argument it does not take).
bool CompilePlatformCall(SQLStatement &statement, unique_ptr<SQLStatement> &compiled);

//! spec 117: whether a written function name is one of `platform`'s management functions
bool IsPlatformFunctionName(const vector<string> &parts);

//! The SQL that answers one view for this principal, or false when the principal may not read it (the
//! object then does not exist for it). Throws when the view needs a policy catalog the store lacks.
bool PlatformViewSql(PolicyStore &store, const PolicyStore::AdminRights &rights, const string &view, string &sql);
//! `FROM platform.check_catalog([vcat])` / `platform.console_info()`: the read functions, compiled; the
//! arguments are constants. False when the principal may not call it.
bool PlatformReadFunctionSql(PolicyStore &store, const Principal &principal, const PolicyStore::AdminRights &rights,
                             const string &function, const vector<Value> &arguments, string &sql);

//! The listings' share (spec 117 §1): CTE bodies of the objects and the columns of `platform` this
//! principal holds, as constant VALUES - `pobjects(vname, kind, comment)` and
//! `pcolumns(vname, pos, name, type)` - or empty strings when it holds nothing (the catalog is absent)
void PlatformListingCtes(const PolicyStore::AdminRights &rights, string &objects, string &columns);
//! The functions of `platform` this principal may call, for duckdb_functions()
struct PlatformFunctionRow {
	string name;
	string kind; // table | scalar
	string returns;
	vector<string> parameters;
	vector<string> parameter_types;
	string comment;
};
vector<PlatformFunctionRow> PlatformFunctionRows(const PolicyStore::AdminRights &rights);

//! The node-state table functions behind the node views (acl_platform_*) and the typed conversions the
//! policy views read packed columns through (acl_platform_caps / _list / _map / _conditions /
//! _attributes). Every one is an acl_* name - in the never set, reached only by substitution.
void RegisterAclPlatform(ExtensionLoader &loader, const shared_ptr<PolicyStore> &store);

} // namespace acl
} // namespace duckdb
