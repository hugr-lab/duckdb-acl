// The catalog-DB policy backend (spec 006), shared by the module's translation units: the SQL
// helpers, the grant-union policy types and the CatalogBackend declaration. The read path and the
// PolicyStore delegations are acl_policy_catalog.cpp, the writers acl_catalog_admin.cpp, the
// metadata listings acl_metadata_listing.cpp, the probe/bind validators acl_catalog_validation.cpp.

#pragma once

#include "acl_policy.hpp"

#include "duckdb/common/exception/binder_exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/types/value.hpp"
#include "duckdb/main/connection.hpp"
#include "duckdb/main/database.hpp"
#include "yyjson.hpp"

#include <set>

#include <chrono>

namespace duckdb {
namespace acl {
namespace acl_detail {

inline string Ident(const string &value) {
	return "\"" + StringUtil::Replace(value, "\"", "\"\"") + "\"";
}

inline string Lit(const string &value) {
	return "'" + StringUtil::Replace(value, "'", "''") + "'";
}

inline string LitList(const vector<string> &values) {
	vector<string> quoted;
	for (auto &value : values) {
		quoted.push_back(Lit(value));
	}
	return StringUtil::Join(quoted, ", ");
}

//! A grant's column list, in the same `name` / `name=expr` csv form the object definitions use.
//! Split at top level only, so an expression may contain commas of its own (`coalesce(a, b)`).
inline vector<std::pair<string, string>> ParseColumnList(const string &csv) {
	vector<std::pair<string, string>> columns;
	for (auto &part : SplitTopLevel(csv, ',')) {
		auto item = part;
		if (item.empty()) {
			continue;
		}
		auto pos = item.find('=');
		if (pos == string::npos) {
			columns.emplace_back(item, string());
			continue;
		}
		auto name = item.substr(0, pos);
		auto expr = item.substr(pos + 1);
		StringUtil::Trim(name);
		StringUtil::Trim(expr);
		columns.emplace_back(name, expr);
	}
	return columns;
}

//! The policy one role's grant chain imposes on one object (spec 011). Levels compose by narrowing:
//! predicates are AND-ed and column lists intersected on the way down (catalog -> object), so a more
//! specific grant can hide or mask more but never re-expose.
struct GrantPolicy {
	bool restricts = false;                    // a column list was given somewhere in the chain
	bool unchecked = false;                    // some level's predicate was never bound (spec 027)
	vector<std::pair<string, string>> columns; // visible columns, name -> expr ("" = as-is)
	vector<string> predicates;                 // AND-ed together

	//! Fold one level of the chain in; empty strings mean "this level says nothing". `rls_checked`
	//! records whether that level's predicate was actually bound when it was written (spec 027).
	void Narrow(const string &rls, const string &column_csv, bool rls_checked = true) {
		if (!rls.empty()) {
			predicates.push_back(rls);
			if (!rls_checked) {
				unchecked = true;
			}
		}
		auto level = ParseColumnList(column_csv);
		if (level.empty()) {
			return;
		}
		if (!restricts) {
			restricts = true;
			columns = std::move(level);
			return;
		}
		vector<std::pair<string, string>> intersected;
		for (auto &column : columns) {
			for (auto &narrower : level) {
				if (!StringUtil::CIEquals(column.first, narrower.first)) {
					continue;
				}
				// the narrower level may mask harder, never un-mask what the wider one computed
				intersected.emplace_back(column.first, narrower.second.empty() ? column.second : narrower.second);
				break;
			}
		}
		columns = std::move(intersected);
	}

	string Predicate() const {
		if (predicates.empty()) {
			return string();
		}
		if (predicates.size() == 1) {
			return predicates[0];
		}
		vector<string> wrapped;
		for (auto &predicate : predicates) {
			wrapped.push_back("(" + predicate + ")");
		}
		return StringUtil::Join(wrapped, " AND ");
	}
};

//! The union of what the principal's roles are granted on one object: a principal may do what any of
//! its roles may, so predicates are OR-ed (a role without one lifts the restriction entirely) and
//! column lists unioned (a plain column beats a masked one).
struct GrantUnion {
	bool any = false;                  // at least one role's grant was seen
	bool unrestricted_rls = false;     // some role has no predicate -> no predicate at all
	bool unrestricted_columns = false; // some role has no column list -> the object's own
	bool unchecked = false;            // some contributing predicate was never bound (spec 027)
	vector<string> predicates;
	vector<std::pair<string, string>> columns;

	void Add(const GrantPolicy &policy) {
		any = true;
		auto predicate = policy.Predicate();
		if (predicate.empty()) {
			unrestricted_rls = true;
		} else {
			predicates.push_back(predicate);
			unchecked = unchecked || policy.unchecked;
		}
		if (!policy.restricts) {
			unrestricted_columns = true;
			return;
		}
		for (auto &column : policy.columns) {
			bool merged = false;
			for (auto &existing : columns) {
				if (!StringUtil::CIEquals(existing.first, column.first)) {
					continue;
				}
				if (column.second.empty() || existing.second.empty()) {
					existing.second.clear(); // one role sees it unmasked, so the principal does
				} else if (existing.second != column.second) {
					// two roles mask the same column differently and neither is wider: there is no
					// order on expressions, so picking one would depend on the row order the join
					// happens to return. Refuse instead of masking non-deterministically.
					throw BinderException("acl: the principal's roles mask column \"%s\" differently (\"%s\" vs "
					                      "\"%s\") - grant the same expression, or drop one of the grants",
					                      column.first, existing.second, column.second);
				}
				merged = true;
				break;
			}
			if (!merged) {
				columns.push_back(column);
			}
		}
	}

	//! Only meaningful together with a non-empty Predicate(): a role without one lifts the restriction
	//! entirely, and there is then no predicate left to have gone unchecked.
	bool Unchecked() const {
		return unchecked && !unrestricted_rls && !predicates.empty();
	}

	string Predicate() const {
		if (unrestricted_rls || predicates.empty()) {
			return string();
		}
		if (predicates.size() == 1) {
			return predicates[0];
		}
		vector<string> wrapped;
		for (auto &predicate : predicates) {
			wrapped.push_back("(" + predicate + ")");
		}
		return StringUtil::Join(wrapped, " OR ");
	}
	bool Restricts() const {
		return any && !unrestricted_columns;
	}
};

//! Parse a caps JSON object ({"select": true, "insert": false, ...}) into the set of enabled
//! capability names, with duckdb's bundled yyjson. Anything but a flat object of booleans is refused.
inline case_insensitive_set_t ParseCaps(const string &json) {
	case_insensitive_set_t caps;
	auto trimmed = json;
	StringUtil::Trim(trimmed);
	if (trimmed.empty()) {
		return caps; // empty/NULL caps -> no capabilities
	}
	auto doc = duckdb_yyjson::yyjson_read(trimmed.c_str(), trimmed.size(), 0);
	if (!doc) {
		throw BinderException("acl catalog: malformed caps JSON: %s", json);
	}
	string error;
	auto root = duckdb_yyjson::yyjson_doc_get_root(doc);
	if (!duckdb_yyjson::yyjson_is_obj(root)) {
		error = "caps must be a JSON object";
	} else {
		duckdb_yyjson::yyjson_obj_iter iter;
		duckdb_yyjson::yyjson_obj_iter_init(root, &iter);
		duckdb_yyjson::yyjson_val *key;
		while ((key = duckdb_yyjson::yyjson_obj_iter_next(&iter))) {
			auto value = duckdb_yyjson::yyjson_obj_iter_get_val(key);
			if (!duckdb_yyjson::yyjson_is_bool(value)) {
				error = "caps values must be true/false";
				break;
			}
			if (duckdb_yyjson::yyjson_get_bool(value)) {
				caps.insert(duckdb_yyjson::yyjson_get_str(key));
			}
		}
	}
	duckdb_yyjson::yyjson_doc_free(doc);
	if (!error.empty()) {
		throw BinderException("acl catalog: %s: %s", error, json);
	}
	return caps;
}

//! The capabilities of one grant row. An *absent* value (NULL, or the empty string a driver returns
//! for "not specified") means **every data capability**: a source that hands out a catalog without
//! saying what may be done with it has already made the access decision, and the caps are how that
//! decision is narrowed. An explicit `{}` is the opposite - "no capabilities" - so the two are never
//! conflated. `manage` is never part of the default: administering the ACL is granted explicitly and
//! only explicitly (spec 009).
inline case_insensitive_set_t EffectiveCaps(const Value &stored) {
	auto text = stored.IsNull() ? string() : stored.ToString();
	auto trimmed = text;
	StringUtil::Trim(trimmed);
	if (!trimmed.empty()) {
		return ParseCaps(text);
	}
	case_insensitive_set_t caps;
	for (auto capability : {"select", "insert", "update", "delete", "merge"}) {
		caps.insert(capability);
	}
	return caps;
}

//! Parse a flat JSON object of string values ({"slot": "function_name", ...})
inline case_insensitive_map_t<string> ParseStringMap(const string &json) {
	case_insensitive_map_t<string> map;
	auto doc = duckdb_yyjson::yyjson_read(json.c_str(), json.size(), 0);
	if (!doc) {
		throw BinderException("acl catalog: malformed JSON map: %s", json);
	}
	string error;
	auto root = duckdb_yyjson::yyjson_doc_get_root(doc);
	if (!duckdb_yyjson::yyjson_is_obj(root)) {
		error = "expected a JSON object";
	} else {
		duckdb_yyjson::yyjson_obj_iter iter;
		duckdb_yyjson::yyjson_obj_iter_init(root, &iter);
		duckdb_yyjson::yyjson_val *key;
		while ((key = duckdb_yyjson::yyjson_obj_iter_next(&iter))) {
			auto value = duckdb_yyjson::yyjson_obj_iter_get_val(key);
			if (!duckdb_yyjson::yyjson_is_str(value)) {
				error = "values must be strings";
				break;
			}
			map[duckdb_yyjson::yyjson_get_str(key)] = duckdb_yyjson::yyjson_get_str(value);
		}
	}
	duckdb_yyjson::yyjson_doc_free(doc);
	if (!error.empty()) {
		throw BinderException("acl catalog: %s: %s", error, json);
	}
	return map;
}

struct CatalogBackend {
	CatalogBackend(DatabaseInstance &db_p, string db_name_p, string schema_p)
	    : db(db_p.shared_from_this()), db_name(std::move(db_name_p)), schema(std::move(schema_p)) {
	}
	//! function-driver mode (spec 008): sources are registered callbacks, not tables
	CatalogBackend(DatabaseInstance &db_p, case_insensitive_map_t<string> slots_p)
	    : db(db_p.shared_from_this()), function_mode(true), slots(std::move(slots_p)) {
	}

	weak_ptr<DatabaseInstance> db;
	string db_name;
	string schema;
	bool function_mode = false;
	case_insensitive_map_t<string> slots; // contract slot -> registered function name

	//! one grant row of the function mode's prefetch (the table mode joins the table directly)
	struct GrantRow {
		string role;
		string vcat;
		bool is_main;
		string caps;
	};

	mutex lock;
	// version state
	int64_t version = -1;
	std::chrono::steady_clock::time_point last_check;
	bool checked_once = false;
	// result caches, invalidated on a version bump; maps are size-capped by ClearIfOversized().
	// keys carry the principal's sorted role set: the effective policy depends on it.
	static constexpr idx_t CACHE_CAPACITY = 4096;
	std::unordered_map<string, std::pair<bool, TablePolicy>> objects;    // rolesig \x1f written name
	std::unordered_map<string, std::pair<bool, TablePolicy>> functions;  // rolesig \x1f kind \x1f name
	std::unordered_map<string, std::pair<bool, bool>> gates;             // rolesig \x1f name -> decided, allowed
	case_insensitive_map_t<case_insensitive_map_t<string>> claims_cache; // role -> claims
	case_insensitive_set_t claims_loaded;
	case_insensitive_map_t<std::pair<bool, IssuerConfig>> issuer_cache; // issuer -> (found, config)
	//! rolesig -> (manage catalogs, acl.admins rows); administration statements hit this per batch
	std::unordered_map<string, std::pair<std::set<string>, vector<std::pair<string, string>>>> rights_cache;
	case_insensitive_map_t<vector<GrantRow>> fn_grants; // function mode: role -> rows
	case_insensitive_set_t fn_grants_loaded;

	string Tbl(const char *table);

	shared_ptr<DatabaseInstance> Db();

	//! Run one read query on a fresh connection; throws on error
	unique_ptr<MaterializedQueryResult> Query(const string &sql);

	//! Run a read-modify-write as ONE transaction on ONE connection: `body` receives a query callback
	//! (its reads see the same snapshot the writes commit into) and the statement sink. Without this,
	//! two concurrent ALTERs of the same object read the same pre-image and the second whole-row
	//! rewrite silently discards the first - which can drop an RLS predicate or a column mask.
	void
	WriteWithReads(const std::function<void(const std::function<unique_ptr<MaterializedQueryResult>(const string &)> &,
	                                        vector<string> &)> &body);

	//! Run admin write statements + the policy_version bump in one transaction
	void Write(const vector<string> &statements);

	int64_t CheckIntervalMs();

	//! Re-read policy_version at most once per interval; a bump clears every cache (fail-fresh)
	void EnsureFresh();

	template <class MAP>
	void ClearIfOversized(MAP &map) {
		if (map.size() > CACHE_CAPACITY) {
			map.clear(); // crude bound; an LRU can replace this when profiles ask for it
		}
	}

	string RoleSig(const Principal &principal);

	bool HasSlot(const char *slot);

	string Slot(const char *slot);

	//! A SQL list literal for callback arguments - the arguments ARE the pushdown (spec 008)
	static string ListLit(const vector<string> &values);

	//! Function mode: fetch (and cache) the principal's grant rows through the role_catalogs callback
	vector<GrantRow> Grants(const vector<string> &roles);

	//! The granted catalogs of the principal (function mode; callback arguments need them)
	vector<string> GrantedCatalogs(const Principal &principal);

	//! The shared query prelude: the principal's grants and the unique-main guard, computed in SQL.
	//! Table mode scans role_catalogs; function mode embeds the prefetched grants as VALUES.
	string GrantsCte(const Principal &principal);

	//! FROM-sources of the resolution queries: a table reference, or a callback invocation whose
	//! literal arguments carry the keys (both name interpretations, the granted catalogs)
	string RelationsSource(const Principal &principal, const vector<string> &names);
	string ColumnsSource(const Principal &principal, const vector<string> &names);
	string AliasesSource(const Principal &principal);
	string FunctionsSource(const Principal &principal, const vector<string> &names);
	bool FunctionMode() const;
	//! One value of the meta table ('schema_version', 'policy_version'); empty when absent
	string MetaValue(const char *key);
	//! the caps column of a resolution query; without an object_caps source there is no override
	bool HasObjectCaps();
	string ObjectCapsSource(const Principal &principal, const vector<string> &names);
	//! The capabilities of the longest schema prefix of `name` this role holds (spec 015). Inheritance
	//! is materialised on the write path, so this picks one row instead of composing a chain.
	string SchemaCapsExpr(const string &name_expr, const string &vcat_expr);
	//! The effective capabilities of one grant row: the most specific level that states them wins -
	//! object, then schema, then catalog - and a level that says nothing (NULL, empty or blank) is
	//! "unspecified", which is not "none" (spec 012).
	string CapsExpr(const string &name_expr = "r.\"vname\"", const string &vcat_expr = "r.\"vcat\"");
	//! The same visibility test as an object's, written against a `functions f` row instead of a
	//! `relations r` one - a function is granted like any other object of the catalog.
	string FunctionVisibleExpr();

	//! The grant chain's policy columns (spec 011): the catalog grant's and the object grant's own RLS
	//! and column list. The function-driver's slots do not carry them, so it composes to no narrowing.
	string GrantPolicyExprs();
	//! Fold the six policy columns of one result row into the chain of one role. A NULL `rls_checked`
	//! is a row written before spec 027 existed, and counts as unchecked: `acl_refresh_schema` judges
	//! those and fills the verdict in.
	static GrantPolicy RowPolicy(MaterializedQueryResult &result, idx_t row, idx_t first_column);

	//! Split a written name into its qualified interpretation; empty head = no qualified branch
	static void SplitName(const string &vname, string &head, string &rest);

	bool ResolveTable(const Principal &principal, const string &vname, TablePolicy &out);

	//! One JOIN resolves the object: both name interpretations, the unique-main guard, the per-role
	//! effective caps (object override beats the catalog default) and the projected columns (as a
	//! list() aggregate) come back in a single result - the engine does the selection.
	bool LookupRelation(const Principal &principal, const string &vname, TablePolicy &out);

	//! Compose the grant chain onto the object's own definition (spec 011). A grant only narrows: its
	//! predicate is AND-ed onto the object's, its column list intersects the object's, and on the
	//! write path its value columns become assignments - so a narrowed table stays writable.
	static void ApplyGrantPolicy(const string &vname, const GrantUnion &grants,
	                             vector<std::pair<string, string>> &object_columns, TablePolicy &out);

	//! The longest granted schema-alias prefix, picked by the query (ORDER BY prefix length);
	//! the matched prefix RENAMEs into the physical schema, the binder validates existence.
	bool LookupSchemaAlias(const Principal &principal, const string &vname, TablePolicy &out);

	bool ResolveFunction(const Principal &principal, const string &vname, bool table_kind, TablePolicy &out);

	//! A grant narrows a table function the same way it narrows a relation, only the result is not a
	//! table but the function's output: the rewriter wraps the expanded/retargeted call in
	//! `SELECT <columns> FROM (<call>) WHERE <predicate>`. A scalar function has neither rows nor
	//! columns, so a policy on one is refused rather than silently ignored (spec 011).
	static void ApplyFunctionGrantPolicy(const string &vname, bool table_kind, const GrantUnion &grants,
	                                     TablePolicy &out);

	//! Whether `capability` is written EXPLICITLY on the principal's MAIN catalog grant (spec 050).
	//! EffectiveCaps carries spec 012's rule for free: an unstated caps column defaults to the data
	//! capabilities, which never include `temp` - so anything beyond them is here only if granted.
	bool PrincipalMainCap(const Principal &principal, const string &capability);

	//! Where a `CREATE`/`DROP` of `vname` lands for this principal (spec 016). One query: the longest
	//! virtual schema prefix of the name that the principal's roles hold, with the grant that states
	//! the capability - so a schema nobody granted, or granted without it, simply does not answer.
	bool DdlTarget(const Principal &principal, const string &vname, const string &capability, acl::DdlTarget &out);

	//! The SQL behind a metadata surface (spec 010 part 3): the principal's own catalog, in the shape
	//! duckdb's own metadata has. The shape is not rebuilt by hand - the physical row is joined and its
	//! identity columns are REPLACEd with the virtual ones, so every other column (types, nullability,
	//! whatever duckdb adds next) stays correct for free. Objects without a physical row (a view, a
	//! query-defined function) are added through UNION ALL BY NAME, which fills the rest with NULL.
	string MetadataListingSql(const Principal &principal, const string &surface);

	//! Targeted gate lookup: only the rows for this name and these roles leave the database ('' as
	//! role means a global row - NULL cannot be part of the primary key). Role-specific rows beat
	//! global rows; among role rows an explicit deny wins.
	bool FunctionGate(const Principal &principal, const string &name, bool &allowed);

	void LoadRoleClaims(Principal &principal);

	bool SettingBool(const char *name, bool fallback);

	string SettingString(const char *name, const char *fallback);
	int64_t SettingInt64(const char *name, int64_t fallback);

	//! Every issuer the policy names - the discovery document's content (spec 062). Function-driver
	//! mode has no issuers table to enumerate, so discovery is empty there rather than guessed.
	void ListIssuers(vector<string> &out);

	bool LookupIssuer(const string &issuer, IssuerConfig &out);

	//! Load (and cache) both administration sources for the principal in one go
	void LoadRights(const Principal &principal, std::set<string> &catalogs, vector<std::pair<string, string>> &scopes);

	//! The catalogs the principal may MANAGE: a capability of the catalog grant itself, so a role can
	//! manage many catalogs (and manage one without being able to read it)
	void ManageCatalogs(const Principal &principal, std::set<string> &out);

	//! The admin scopes of the principal's roles; the function-driver may serve them through a slot
	void AdminScopes(const Principal &principal, vector<std::pair<string, string>> &out);

	//! One query maps external role values and checks which raw values exist as internal roles
	void MapExternalRoles(const string &issuer, const vector<string> &values,
	                      case_insensitive_map_t<vector<string>> &mapped, case_insensitive_set_t &known_roles);

	//! Bind a template (markers baked to NULL) without reading data, and return its column schema.
	//! Runs on the write path, so introspection later costs nothing; a failure is not fatal - the
	//! object is stored with an unknown schema and `acl_refresh_schema` can try again.
	bool ProbeSchema(const string &sql, bool expression, const vector<string> &param_types,
	                 vector<std::pair<string, string>> &out);

	//! A projection entry that merely renames reads the physical column as it is; anything else is
	//! an expression whose NULL-capability the declaration cannot see (spec 048).
	static bool BareIdentifier(const string &expr);

	//! The declared key's rows (spec 048). `known` are the lowercased column names the caller could
	//! establish; empty means nothing checkable, and the key is stored as written - the same
	//! best-effort rule as an unbindable predicate. An explicitly nullable key column is a
	//! contradiction refused outright.
	//! The keys rows of one declaration. A stated key is validated strictly and a violation refused;
	//! a `carried` key - one an ALTER or a replace reads out of the store and passes back - lapses
	//! instead when the new shape no longer supports it (only the DELETE is written): the redefinition
	//! is the admin's decision, and blocking it over a key they did not state helps nobody.
	vector<string> KeyStatements(const string &vcat, const string &vname, const string &kind, const string &pk,
	                             const vector<string> &known, const case_insensitive_map_t<int8_t> &nullable_marks,
	                             const vector<std::pair<string, string>> *masked = nullptr, bool carried = false);

	//! Bind a grant's predicate against the object it filters, without reading data. Returns the
	//! binder's message when the predicate is at fault and an empty string when it binds.
	//!
	//! The target is bound on its own first: if *that* fails there is nothing to judge the predicate
	//! against - the source may simply not be attached yet - and the predicate is accepted, exactly as
	//! a schema probe that cannot bind is not fatal.
	string PredicateError(const string &source, const string &rls, bool *checked = nullptr);

	//! A catalog grant's predicate filters every object of the catalog, so there is no single object to
	//! bind it against: it is judged against all of them, and counts as checked only when every object
	//! that binds at all accepted it. Unlike an object's own predicate this never refuses the write - a
	//! catalog predicate that does not fit one object is a real (if questionable) configuration, and it
	//! was allowed before the flag existed.
	bool CatalogPredicateChecked(const std::function<unique_ptr<MaterializedQueryResult>(const string &)> &read,
	                             const string &vcat, const string &rls);

	//! What an object exposes, in its own order: the column list it declares, or - when it declares
	//! none - the columns of the source it stands for. False when the source cannot be bound here, in
	//! which case the object is not ours to judge and a grant on it is left alone (spec 037).
	bool ExposedColumns(const string &source, const vector<string> &declared, vector<string> &out);

	//! Bind a projection over a relation and return the columns it produces (spec 026). Never fatal: an
	//! unbindable projection leaves the listing as it was rather than refusing the grant.
	//! Returns the binder's message when the projection is at fault, and an empty string when it binds -
	//! or when the object itself does not bind, since then there is nothing to judge it against. The
	//! same two steps as a predicate's check (spec 021), for the same reason.
	string ProjectionSchema(const string &source, const string &column_csv, const case_insensitive_map_t<string> &own,
	                        vector<std::pair<string, string>> &out, bool *checked = nullptr);

	//! Read a document through duckdb's own filesystem (spec 023). A local path works out of the box;
	//! an https URL needs httpfs, and duckdb says so itself - which is the error an operator needs.
	bool ReadText(const string &uri, string &out, string &error);

	//! Whether a relation has a column of that name. False only when the relation itself binds and the
	//! column does not: a source that cannot be reached at all answers true, since it cannot answer.
	bool ColumnBinds(const string &source, const string &column);

	//! "name TYPE, name TYPE" -> the pieces; a bare "TYPE" (a scalar's RETURNS) yields an empty name
	static vector<std::pair<string, string>> ParseDeclaration(const string &declaration);

	static vector<string> DeclaredTypes(const string &declaration);

	//! Statements replacing one object's stored column schema
	vector<string> ColumnSchemaStatements(const string &vcat, const string &vname, const string &kind,
	                                      const vector<std::pair<string, string>> &columns, bool derived,
	                                      const case_insensitive_map_t<int8_t> &nullable_marks = {});

	//! Substitute the schema file's placeholders: `<schema>` is the qualified schema of the catalog
	//! being initialised and `<name>` one of its tables. Only `<lower_case_word>` counts, so the `<`
	//! of a comparison in the file is left alone.
	string ResolveSchemaNames(const string &sql);

	//! The catalog says which shape it is; this build knows one. A schema applied by hand (spec 034)
	//! is the case that makes them differ, and the failure without this check is a missing column in
	//! the middle of somebody's query rather than a word at the moment the catalog is chosen.
	void RequireSchemaVersion();

	//! What a key column is declared as, by the kind of catalog it lives in. Everywhere but SQL Server
	//! that is a plain VARCHAR; the mssql scanner maps every VARCHAR - length or not - to
	//! NVARCHAR(MAX), which SQL Server refuses to index, so key columns take its own bounded type.
	//! 255 characters is then a real limit on a name, a role or a schema path there (spec 033).
	string KeyColumnType();

	//! Every table carries a primary key: sources without rowids need one for DELETE/UPDATE
	void InitSchema();
};

} // namespace acl_detail

} // namespace acl
} // namespace duckdb
