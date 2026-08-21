// The catalog-DB policy backend (spec 006): policy lives in an ATTACHed database, spoken to only in
// standard duckdb dialect (source agnostic). Virtual catalogs (shared object definitions) are
// separated from role grants; caches are keyed by acl.meta's policy_version, re-checked at most once
// per acl_version_check_interval ms. The selection logic lives in SQL: one resolve miss is one JOIN
// over role_catalogs/relations/role_object_caps (columns folded in as a list() aggregate), with the
// qualified-vs-main interpretation and the unique-main guard decided by the query - duckdb's engine
// does the work, base-table filters push down into the scanners. Every table carries a primary key
// (sources without rowids need one for DELETE/UPDATE). Reads open short-lived connections (a stored
// Connection would cycle DatabaseInstance -> config -> store -> connection).

#include "acl_policy.hpp"

#include "acl_token.hpp"

#include "acl_rewriter.hpp"

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
namespace {

string Ident(const string &value) {
	return "\"" + StringUtil::Replace(value, "\"", "\"\"") + "\"";
}

string Lit(const string &value) {
	return "'" + StringUtil::Replace(value, "'", "''") + "'";
}

string LitList(const vector<string> &values) {
	vector<string> quoted;
	for (auto &value : values) {
		quoted.push_back(Lit(value));
	}
	return StringUtil::Join(quoted, ", ");
}

//! A grant's column list, in the same `name` / `name=expr` csv form the object definitions use.
//! Split at top level only, so an expression may contain commas of its own (`coalesce(a, b)`).
vector<std::pair<string, string>> ParseColumnList(const string &csv) {
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
case_insensitive_set_t ParseCaps(const string &json) {
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
case_insensitive_set_t EffectiveCaps(const Value &stored) {
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
case_insensitive_map_t<string> ParseStringMap(const string &json) {
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

} // namespace

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

	string Tbl(const char *table) {
		return Ident(db_name) + "." + Ident(schema) + "." + Ident(table);
	}

	shared_ptr<DatabaseInstance> Db() {
		auto instance = db.lock();
		if (!instance) {
			throw BinderException("acl catalog: database instance is gone");
		}
		return instance;
	}

	//! Run one read query on a fresh connection; throws on error
	unique_ptr<MaterializedQueryResult> Query(const string &sql) {
		auto instance = Db();
		Connection con(*instance);
		auto result = con.Query(sql);
		if (result->HasError()) {
			throw BinderException("acl catalog: query failed: %s", result->GetError());
		}
		return result;
	}

	//! Run a read-modify-write as ONE transaction on ONE connection: `body` receives a query callback
	//! (its reads see the same snapshot the writes commit into) and the statement sink. Without this,
	//! two concurrent ALTERs of the same object read the same pre-image and the second whole-row
	//! rewrite silently discards the first - which can drop an RLS predicate or a column mask.
	void
	WriteWithReads(const std::function<void(const std::function<unique_ptr<MaterializedQueryResult>(const string &)> &,
	                                        vector<string> &)> &body) {
		auto instance = Db();
		Connection con(*instance);
		auto begin = con.Query("BEGIN");
		if (begin->HasError()) {
			throw BinderException("acl catalog: %s", begin->GetError());
		}
		auto rollback = [&]() {
			con.Query("ROLLBACK");
		};
		vector<string> statements;
		try {
			auto read = [&](const string &sql) {
				auto result = con.Query(sql);
				if (result->HasError()) {
					throw BinderException("acl catalog: query failed: %s", result->GetError());
				}
				return result;
			};
			body(read, statements);
		} catch (...) {
			rollback();
			throw;
		}
		for (auto &sql : statements) {
			auto result = con.Query(sql);
			if (result->HasError()) {
				rollback();
				throw BinderException("acl catalog: write failed: %s", result->GetError());
			}
		}
		auto bump = con.Query("UPDATE " + Tbl("meta") +
		                      " SET \"value\" = CAST(CAST(\"value\" AS BIGINT) + 1 AS VARCHAR)"
		                      " WHERE \"key\" = 'policy_version'");
		if (bump->HasError()) {
			rollback();
			throw BinderException("acl catalog: version bump failed: %s", bump->GetError());
		}
		auto commit = con.Query("COMMIT");
		if (commit->HasError()) {
			throw BinderException("acl catalog: %s", commit->GetError());
		}
		lock_guard<mutex> guard(lock);
		checked_once = false;
	}

	//! Run admin write statements + the policy_version bump in one transaction
	void Write(const vector<string> &statements) {
		if (function_mode) {
			throw BinderException("acl catalog: the function-driver policy source is read-only");
		}
		auto instance = Db();
		Connection con(*instance);
		auto begin = con.Query("BEGIN");
		if (begin->HasError()) {
			throw BinderException("acl catalog: %s", begin->GetError());
		}
		for (auto &sql : statements) {
			auto result = con.Query(sql);
			if (result->HasError()) {
				con.Query("ROLLBACK");
				throw BinderException("acl catalog: write failed: %s", result->GetError());
			}
		}
		auto bump = con.Query("UPDATE " + Tbl("meta") +
		                      " SET \"value\" = CAST(CAST(\"value\" AS BIGINT) + 1 AS VARCHAR)"
		                      " WHERE \"key\" = 'policy_version'");
		if (bump->HasError()) {
			con.Query("ROLLBACK");
			throw BinderException("acl catalog: version bump failed: %s", bump->GetError());
		}
		auto commit = con.Query("COMMIT");
		if (commit->HasError()) {
			throw BinderException("acl catalog: %s", commit->GetError());
		}
		lock_guard<mutex> guard(lock);
		checked_once = false; // force a version re-read on the next resolve
	}

	int64_t CheckIntervalMs() {
		Value value;
		if (Db()->TryGetCurrentSetting("acl_version_check_interval", value) && !value.IsNull()) {
			return value.GetValue<int64_t>();
		}
		return 1000;
	}

	//! Re-read policy_version at most once per interval; a bump clears every cache (fail-fresh)
	void EnsureFresh() {
		{
			lock_guard<mutex> guard(lock);
			auto now = std::chrono::steady_clock::now();
			auto interval = std::chrono::milliseconds(CheckIntervalMs());
			if (checked_once && now - last_check < interval) {
				return;
			}
			last_check = now;
			checked_once = true;
		}
		auto result = function_mode
		                  ? Query("SELECT * FROM " + Slot("policy_version") + "()")
		                  : Query("SELECT \"value\" FROM " + Tbl("meta") + " WHERE \"key\" = 'policy_version'");
		if (result->RowCount() != 1) {
			throw BinderException("acl catalog: the policy_version source returned %lld rows, expected 1",
			                      result->RowCount());
		}
		auto current = result->GetValue(0, 0).GetValue<int64_t>();
		lock_guard<mutex> guard(lock);
		if (current != version) {
			version = current;
			objects.clear();
			functions.clear();
			gates.clear();
			claims_cache.clear();
			claims_loaded.clear();
			issuer_cache.clear();
			rights_cache.clear();
			fn_grants.clear();
			fn_grants_loaded.clear();
		}
	}

	template <class MAP>
	void ClearIfOversized(MAP &map) {
		if (map.size() > CACHE_CAPACITY) {
			map.clear(); // crude bound; an LRU can replace this when profiles ask for it
		}
	}

	string RoleSig(const Principal &principal) {
		auto roles = principal.roles;
		std::sort(roles.begin(), roles.end());
		return StringUtil::Join(roles, ",");
	}

	bool HasSlot(const char *slot) {
		return slots.count(slot) > 0;
	}

	string Slot(const char *slot) {
		auto entry = slots.find(slot);
		if (entry == slots.end()) {
			throw BinderException("acl catalog: the function-driver map has no \"%s\" slot", slot);
		}
		return Ident(entry->second);
	}

	//! A SQL list literal for callback arguments - the arguments ARE the pushdown (spec 008)
	static string ListLit(const vector<string> &values) {
		if (values.empty()) {
			return "CAST([] AS VARCHAR[])";
		}
		vector<string> quoted;
		for (auto &value : values) {
			quoted.push_back(Lit(value));
		}
		return "[" + StringUtil::Join(quoted, ", ") + "]";
	}

	//! Function mode: fetch (and cache) the principal's grant rows through the role_catalogs callback
	vector<GrantRow> Grants(const vector<string> &roles) {
		vector<string> missing;
		{
			lock_guard<mutex> guard(lock);
			for (auto &role : roles) {
				if (!fn_grants_loaded.count(role)) {
					missing.push_back(role);
				}
			}
		}
		if (!missing.empty()) {
			// positional contract: (role, vcat, is_main, caps)
			auto result = Query("SELECT * FROM " + Slot("role_catalogs") + "(" + ListLit(missing) + ")");
			lock_guard<mutex> guard(lock);
			for (auto &role : missing) {
				fn_grants_loaded.insert(role);
				fn_grants[role];
			}
			for (idx_t row = 0; row < result->RowCount(); row++) {
				GrantRow grant;
				grant.role = result->GetValue(0, row).ToString();
				grant.vcat = result->GetValue(1, row).ToString();
				auto is_main = result->GetValue(2, row);
				grant.is_main = !is_main.IsNull() && is_main.GetValue<bool>();
				auto caps = result->GetValue(3, row);
				grant.caps = caps.IsNull() ? string() : caps.ToString();
				fn_grants[grant.role].push_back(grant);
			}
		}
		lock_guard<mutex> guard(lock);
		vector<GrantRow> rows;
		for (auto &role : roles) {
			auto entry = fn_grants.find(role);
			if (entry == fn_grants.end()) {
				continue;
			}
			rows.insert(rows.end(), entry->second.begin(), entry->second.end());
		}
		return rows;
	}

	//! The granted catalogs of the principal (function mode; callback arguments need them)
	vector<string> GrantedCatalogs(const Principal &principal) {
		case_insensitive_set_t seen;
		vector<string> catalogs;
		for (auto &grant : Grants(principal.roles)) {
			if (!seen.count(grant.vcat)) {
				seen.insert(grant.vcat);
				catalogs.push_back(grant.vcat);
			}
		}
		return catalogs;
	}

	//! The shared query prelude: the principal's grants and the unique-main guard, computed in SQL.
	//! Table mode scans role_catalogs; function mode embeds the prefetched grants as VALUES.
	string GrantsCte(const Principal &principal) {
		string grants;
		if (!function_mode) {
			grants = "SELECT \"role\", \"vcat\", \"is_main\", \"caps\", \"rls\", \"columns\", \"rls_checked\" FROM " +
			         Tbl("role_catalogs") + " WHERE \"role\" IN (" + LitList(principal.roles) + ")";
		} else {
			string values;
			for (auto &grant : Grants(principal.roles)) {
				values += (values.empty() ? "" : ", ") + string("(") + Lit(grant.role) + ", " + Lit(grant.vcat) + ", " +
				          (grant.is_main ? "true" : "false") + ", " + Lit(grant.caps) + ")";
			}
			// the driver contract has no policy columns (a platform expresses policy in its own
			// callbacks), so function mode carries NULLs and composes to "no grant-level narrowing"
			grants = values.empty()
			             ? string("SELECT '' AS \"role\", '' AS \"vcat\", false AS \"is_main\", '' AS \"caps\","
			                      " NULL AS \"rls\", NULL AS \"columns\", NULL AS \"rls_checked\" WHERE false")
			             : "SELECT *, NULL AS \"rls\", NULL AS \"columns\", NULL AS \"rls_checked\" FROM (VALUES " +
			                   values + ") v(\"role\", \"vcat\", \"is_main\", \"caps\")";
		}
		return "WITH grants AS (" + grants +
		       "), main_ok AS (SELECT count(DISTINCT \"vcat\") = 1 AS unique_main FROM grants WHERE \"is_main\") ";
	}

	//! FROM-sources of the resolution queries: a table reference, or a callback invocation whose
	//! literal arguments carry the keys (both name interpretations, the granted catalogs)
	string RelationsSource(const Principal &principal, const vector<string> &names) {
		return function_mode
		           ? Slot("relations") + "(" + ListLit(GrantedCatalogs(principal)) + ", " + ListLit(names) + ")"
		           : Tbl("relations");
	}
	string ColumnsSource(const Principal &principal, const vector<string> &names) {
		return function_mode
		           ? Slot("relation_columns") + "(" + ListLit(GrantedCatalogs(principal)) + ", " + ListLit(names) + ")"
		           : Tbl("relation_columns");
	}
	string AliasesSource(const Principal &principal) {
		// the driver contract keeps its alias-shaped slot (a platform expresses aliases, not comments),
		// so table mode projects the schema table into the same three columns
		return function_mode ? Slot("schema_aliases") + "(" + ListLit(GrantedCatalogs(principal)) + ")"
		                     : "(SELECT \"vcat\", \"path\" AS \"alias_path\", \"phys_path\" FROM " + Tbl("schemas") +
		                           " WHERE \"phys_path\" IS NOT NULL)";
	}
	string FunctionsSource(const Principal &principal, const vector<string> &names) {
		return function_mode
		           ? Slot("functions") + "(" + ListLit(GrantedCatalogs(principal)) + ", " + ListLit(names) + ")"
		           : Tbl("functions");
	}
	bool FunctionMode() const {
		return function_mode;
	}
	//! One value of the meta table ('schema_version', 'policy_version'); empty when absent
	string MetaValue(const char *key) {
		auto result = Query("SELECT \"value\" FROM " + Tbl("meta") + " WHERE \"key\" = " + Lit(key));
		return result->RowCount() == 0 || result->GetValue(0, 0).IsNull() ? string()
		                                                                  : result->GetValue(0, 0).ToString();
	}
	bool HasObjectCaps() {
		return !function_mode || HasSlot("object_caps");
	}
	string ObjectCapsSource(const Principal &principal, const vector<string> &names) {
		return function_mode ? Slot("object_caps") + "(" + ListLit(principal.roles) + ", " +
		                           ListLit(GrantedCatalogs(principal)) + ", " + ListLit(names) + ")"
		                     : Tbl("role_object_caps");
	}
	//! the caps column of a resolution query; without an object_caps source there is no override
	//! The capabilities of the longest schema prefix of `name` this role holds (spec 015). Inheritance
	//! is materialised on the write path, so this picks one row instead of composing a chain.
	string SchemaCapsExpr(const string &name_expr, const string &vcat_expr) {
		if (function_mode) {
			return string(); // the driver contract has no schema level
		}
		return "(SELECT nullif(trim(sc.\"caps\"), '') FROM " + Tbl("role_schemas") +
		       " sc WHERE sc.\"role\" = g.\"role\" AND sc.\"vcat\" = " + vcat_expr + " AND substr(" + name_expr +
		       ", 1, length(sc.\"schema_path\") + 1) = sc.\"schema_path\" || '.'"
		       " ORDER BY length(sc.\"schema_path\") DESC LIMIT 1)";
	}
	//! The effective capabilities of one grant row: the most specific level that states them wins -
	//! object, then schema, then catalog - and a level that says nothing (NULL, empty or blank) is
	//! "unspecified", which is not "none" (spec 012).
	string CapsExpr(const string &name_expr = "r.\"vname\"", const string &vcat_expr = "r.\"vcat\"") {
		string caps = HasObjectCaps() ? "nullif(trim(oc.\"caps\"), '')" : string();
		auto schema_caps = SchemaCapsExpr(name_expr, vcat_expr);
		if (caps.empty() && schema_caps.empty()) {
			return "g.\"caps\"";
		}
		vector<string> terms;
		if (!caps.empty()) {
			terms.push_back(caps);
		}
		if (!schema_caps.empty()) {
			terms.push_back(schema_caps);
		}
		terms.push_back("g.\"caps\"");
		return "coalesce(" + StringUtil::Join(terms, ", ") + ")";
	}
	//! The same visibility test as an object's, written against a `functions f` row instead of a
	//! `relations r` one - a function is granted like any other object of the catalog.
	string FunctionVisibleExpr() {
		auto caps = CapsExpr("f.\"vname\"", "f.\"vcat\"");
		return "(" + caps + " IS NULL OR trim(" + caps + ") = '' OR trim(" + caps + ") <> '{}')";
	}

	//! The grant chain's policy columns (spec 011): the catalog grant's and the object grant's own RLS
	//! and column list. The function-driver's slots do not carry them, so it composes to no narrowing.
	string GrantPolicyExprs() {
		return function_mode ? "NULL AS crls, NULL AS ccols, false AS cchk, NULL AS orls, NULL AS ocols,"
		                       " false AS ochk"
		                     : "g.\"rls\" AS crls, g.\"columns\" AS ccols, g.\"rls_checked\" AS cchk,"
		                       " oc.\"rls\" AS orls, oc.\"columns\" AS ocols, oc.\"rls_checked\" AS ochk";
	}
	//! Fold the six policy columns of one result row into the chain of one role. A NULL `rls_checked`
	//! is a row written before spec 027 existed, and counts as unchecked: `acl_refresh_schema` judges
	//! those and fills the verdict in.
	static GrantPolicy RowPolicy(MaterializedQueryResult &result, idx_t row, idx_t first_column) {
		auto text = [&](idx_t column) {
			auto value = result.GetValue(column, row);
			return value.IsNull() ? string() : value.ToString();
		};
		auto flag = [&](idx_t column) {
			auto value = result.GetValue(column, row);
			return !value.IsNull() && value.GetValue<bool>();
		};
		GrantPolicy policy;
		policy.Narrow(text(first_column), text(first_column + 1), flag(first_column + 2));     // catalog level
		policy.Narrow(text(first_column + 3), text(first_column + 4), flag(first_column + 5)); // object level
		return policy;
	}

	//! Split a written name into its qualified interpretation; empty head = no qualified branch
	static void SplitName(const string &vname, string &head, string &rest) {
		auto dot = vname.find('.');
		if (dot == string::npos) {
			head.clear();
			rest.clear();
		} else {
			head = vname.substr(0, dot);
			rest = vname.substr(dot + 1);
		}
	}

	bool ResolveTable(const Principal &principal, const string &vname, TablePolicy &out) {
		if (principal.roles.empty()) {
			return false;
		}
		EnsureFresh();
		auto key = RoleSig(principal) + "\x1f" + vname;
		{
			lock_guard<mutex> guard(lock);
			auto entry = objects.find(key);
			if (entry != objects.end()) {
				out = entry->second.second;
				return entry->second.first;
			}
		}
		TablePolicy policy;
		bool found = LookupRelation(principal, vname, policy) || LookupSchemaAlias(principal, vname, policy);
		lock_guard<mutex> guard(lock);
		ClearIfOversized(objects);
		objects[key] = {found, policy};
		if (found) {
			out = policy;
		}
		return found;
	}

	//! One JOIN resolves the object: both name interpretations, the unique-main guard, the per-role
	//! effective caps (object override beats the catalog default) and the projected columns (as a
	//! list() aggregate) come back in a single result - the engine does the selection.
	bool LookupRelation(const Principal &principal, const string &vname, TablePolicy &out) {
		string head, rest;
		SplitName(vname, head, rest);
		string qualified_cond =
		    head.empty() ? string("false") : "r.\"vcat\" = " + Lit(head) + " AND r.\"vname\" = " + Lit(rest);
		vector<string> names = head.empty() ? vector<string> {vname} : vector<string> {vname, rest};
		string oc_join = HasObjectCaps() ? " LEFT JOIN " + ObjectCapsSource(principal, names) +
		                                       " oc ON oc.\"role\" = g.\"role\" AND oc.\"vcat\" = r.\"vcat\""
		                                       " AND oc.\"vname\" = r.\"vname\""
		                                 : string();
		auto sql = GrantsCte(principal) + "SELECT r.\"form\", r.\"phys\", r.\"view_sql\", r.\"rls\", " + CapsExpr() +
		           " AS caps, " + GrantPolicyExprs() +
		           ","
		           " CASE WHEN " +
		           qualified_cond +
		           " THEN 1 ELSE 2 END AS prio,"
		           " (SELECT list(struct_pack(cname := c.\"name\", cexpr := c.\"expr\") ORDER BY c.\"pos\") FROM " +
		           ColumnsSource(principal, names) +
		           " c WHERE c.\"vcat\" = r.\"vcat\" AND c.\"vname\" = r.\"vname\") AS cols, " +
		           (function_mode ? "NULL" : "r.\"rls_checked\"") +
		           " AS rchk"
		           " FROM " +
		           RelationsSource(principal, names) + " r JOIN grants g ON g.\"vcat\" = r.\"vcat\"" + oc_join +
		           " WHERE (" + qualified_cond +
		           ") OR (g.\"is_main\" AND (SELECT unique_main FROM main_ok) AND r.\"vname\" = " + Lit(vname) +
		           ") ORDER BY prio";
		auto result = Query(sql);
		if (result->RowCount() == 0) {
			return false;
		}
		auto prio = result->GetValue(11, 0).GetValue<int64_t>();
		auto form = result->GetValue(0, 0).ToString();
		auto phys = result->GetValue(1, 0);
		auto view_sql = result->GetValue(2, 0);
		auto rls = result->GetValue(3, 0);
		out.phys = phys.IsNull() ? string() : phys.ToString();
		out.query = view_sql.IsNull() ? string() : view_sql.ToString();
		out.rls = rls.IsNull() ? string() : rls.ToString();
		auto rchk = result->GetValue(13, 0);
		out.rls_unchecked = !out.rls.empty() && (rchk.IsNull() || !rchk.GetValue<bool>());
		out.subquery_form = form != "alias";
		out.writable = form == "alias"; // a real table stays writable, however a grant narrows it
		vector<std::pair<string, string>> object_columns;
		auto cols = result->GetValue(12, 0);
		if (!cols.IsNull() && form != "view") {
			for (auto &item : ListValue::GetChildren(cols)) {
				auto &fields = StructValue::GetChildren(item);
				auto name = fields[0].ToString();
				auto expr = fields[1].IsNull() ? string() : fields[1].ToString();
				if (form == "alias") {
					// an alias-form column list is a rename list (virtual -> physical): it keeps the
					// relation writable, so reads rename by name and writes map the names back
					if (!expr.empty()) {
						out.renames.emplace_back(name, expr);
					}
					continue;
				}
				object_columns.emplace_back(name, expr);
			}
		}
		// remaining rows of the winning interpretation differ only by role: union their caps, and the
		// policies of their grant chains (spec 011)
		GrantUnion grants;
		for (idx_t row = 0; row < result->RowCount(); row++) {
			if (result->GetValue(11, row).GetValue<int64_t>() != prio) {
				break; // ordered by prio; the losing interpretation starts here
			}
			auto caps = result->GetValue(4, row);
			for (auto &cap : EffectiveCaps(caps)) {
				out.caps.insert(cap);
			}
			grants.Add(RowPolicy(*result, row, 5));
		}
		ApplyGrantPolicy(vname, grants, object_columns, out);
		return true;
	}

	//! Compose the grant chain onto the object's own definition (spec 011). A grant only narrows: its
	//! predicate is AND-ed onto the object's, its column list intersects the object's, and on the
	//! write path its value columns become assignments - so a narrowed table stays writable.
	static void ApplyGrantPolicy(const string &vname, const GrantUnion &grants,
	                             vector<std::pair<string, string>> &object_columns, TablePolicy &out) {
		auto predicate = grants.Predicate();
		bool restricts = grants.Restricts();
		out.rls_unchecked = out.rls_unchecked || grants.Unchecked();
		if (predicate.empty() && !restricts) {
			for (auto &column : object_columns) {
				out.projection.push_back(column.second.empty() ? column.first : column.second + " AS " + column.first);
			}
			return;
		}
		if (!out.query.empty()) {
			// a view has no column list of its own to intersect: wrap its SQL, so the grant's columns
			// and predicate apply to the view's output
			vector<string> items;
			for (auto &column : grants.columns) {
				items.push_back(column.second.empty() ? Ident(column.first)
				                                      : column.second + " AS " + Ident(column.first));
			}
			out.query = "SELECT " + (restricts ? StringUtil::Join(items, ", ") : string("*")) + " FROM (" + out.query +
			            ") AS __acl_granted" + (predicate.empty() ? "" : " WHERE " + predicate);
			return;
		}
		if (!predicate.empty()) {
			out.rls = out.rls.empty() ? predicate : "(" + out.rls + ") AND (" + predicate + ")";
		}
		if (!restricts) {
			for (auto &column : object_columns) {
				out.projection.push_back(column.second.empty() ? column.first : column.second + " AS " + column.first);
			}
			out.subquery_form = out.subquery_form || !out.rls.empty();
			return;
		}
		// the visible columns of the relation as the object defines it: its own projection, or (for an
		// alias-form table) every physical column under its virtual name
		for (auto &column : grants.columns) {
			string source = column.first; // what to read the value from, in physical terms
			bool known = object_columns.empty();
			for (auto &defined : object_columns) {
				if (StringUtil::CIEquals(defined.first, column.first)) {
					source = defined.second.empty() ? defined.first : defined.second;
					known = true;
					break;
				}
			}
			if (!known) {
				// the object does not expose it, and a grant may never re-expose what it hid
				throw BinderException("acl: grant on \"%s\" lists column \"%s\", which the object does not expose",
				                      vname, column.first);
			}
			for (auto &rename : out.renames) {
				if (StringUtil::CIEquals(rename.first, column.first)) {
					source = rename.second;
					break;
				}
				if (StringUtil::CIEquals(rename.second, column.first)) {
					throw BinderException("acl: grant on \"%s\" lists column \"%s\", which the object renamed away",
					                      vname, column.first);
				}
			}
			auto expr = column.second.empty() ? source : column.second;
			out.projection.push_back(expr == column.first ? expr : expr + " AS " + Ident(column.first));
			if (!out.writable) {
				continue;
			}
			out.write_columns.insert(source);
			if (!column.second.empty()) {
				out.injections.emplace_back(source, column.second);
			}
		}
		out.subquery_form = true; // a narrowed read is a projection, so it needs the subquery shape
	}

	//! The longest granted schema-alias prefix, picked by the query (ORDER BY prefix length);
	//! the matched prefix RENAMEs into the physical schema, the binder validates existence.
	bool LookupSchemaAlias(const Principal &principal, const string &vname, TablePolicy &out) {
		string head, rest;
		SplitName(vname, head, rest);
		auto prefix_match = [](const string &path, const string &alias_expr) {
			return "substr(" + path + ", 1, length(" + alias_expr + ") + 1) = " + alias_expr + " || '.'";
		};
		string qualified_cond =
		    head.empty() ? string("false")
		                 : "sa.\"vcat\" = " + Lit(head) + " AND " + prefix_match(Lit(rest), "sa.\"alias_path\"");
		auto path_case = "CASE WHEN sa.\"vcat\" = " + (head.empty() ? Lit("") : Lit(head)) + " THEN " + Lit(rest) +
		                 " ELSE " + Lit(vname) + " END";
		vector<string> names = head.empty() ? vector<string> {vname} : vector<string> {vname, rest};
		string oc_join = HasObjectCaps() ? " LEFT JOIN " + ObjectCapsSource(principal, names) +
		                                       " oc ON oc.\"role\" = g.\"role\" AND oc.\"vcat\" = sa.\"vcat\""
		                                       " AND oc.\"vname\" = " +
		                                       path_case
		                                 : string();
		auto sql = GrantsCte(principal) + "SELECT sa.\"vcat\", sa.\"alias_path\", sa.\"phys_path\", " +
		           CapsExpr(path_case, "sa.\"vcat\"") + " AS caps, " + GrantPolicyExprs() +
		           ","
		           " CASE WHEN " +
		           qualified_cond +
		           " THEN 1 ELSE 2 END AS prio"
		           " FROM " +
		           AliasesSource(principal) + " sa JOIN grants g ON g.\"vcat\" = sa.\"vcat\"" + oc_join + " WHERE (" +
		           qualified_cond + ") OR (g.\"is_main\" AND (SELECT unique_main FROM main_ok) AND " +
		           prefix_match(Lit(vname), "sa.\"alias_path\"") + ") ORDER BY prio, length(sa.\"alias_path\") DESC";
		auto result = Query(sql);
		if (result->RowCount() == 0) {
			return false;
		}
		auto prio = result->GetValue(10, 0).GetValue<int64_t>();
		auto vcat = result->GetValue(0, 0).ToString();
		auto alias_path = result->GetValue(1, 0).ToString();
		auto &path = prio == 1 ? rest : vname;
		out.subquery_form = false;
		out.writable = true; // an aliased schema maps onto real tables
		out.phys = result->GetValue(2, 0).ToString() + path.substr(alias_path.size());
		// rows of the same winning alias differ only by role: union their caps and grant policies
		GrantUnion grants;
		for (idx_t row = 0; row < result->RowCount(); row++) {
			if (result->GetValue(10, row).GetValue<int64_t>() != prio || result->GetValue(0, row).ToString() != vcat ||
			    result->GetValue(1, row).ToString() != alias_path) {
				continue;
			}
			auto caps = result->GetValue(3, row);
			for (auto &cap : EffectiveCaps(caps)) {
				out.caps.insert(cap);
			}
			grants.Add(RowPolicy(*result, row, 4));
		}
		vector<std::pair<string, string>> no_columns;
		ApplyGrantPolicy(vname, grants, no_columns, out);
		return true;
	}

	bool ResolveFunction(const Principal &principal, const string &vname, bool table_kind, TablePolicy &out) {
		if (principal.roles.empty()) {
			return false;
		}
		EnsureFresh();
		auto kind = table_kind ? "table" : "scalar";
		auto key = RoleSig(principal) + "\x1f" + kind + "\x1f" + vname;
		{
			lock_guard<mutex> guard(lock);
			auto entry = functions.find(key);
			if (entry != functions.end()) {
				out = entry->second.second;
				return entry->second.first;
			}
		}
		string head, rest;
		SplitName(vname, head, rest);
		string qualified_cond =
		    head.empty() ? string("false") : "f.\"vcat\" = " + Lit(head) + " AND f.\"vname\" = " + Lit(rest);
		vector<string> names = head.empty() ? vector<string> {vname} : vector<string> {vname, rest};
		string oc_join = HasObjectCaps() ? " LEFT JOIN " + ObjectCapsSource(principal, names) +
		                                       " oc ON oc.\"role\" = g.\"role\" AND oc.\"vcat\" = f.\"vcat\""
		                                       " AND oc.\"vname\" = f.\"vname\""
		                                 : string();
		auto sql = GrantsCte(principal) + "SELECT f.\"vcat\", f.\"form\", f.\"target\", f.\"template\", " +
		           CapsExpr("f.\"vname\"", "f.\"vcat\"") + " AS caps, " + GrantPolicyExprs() +
		           ","
		           " CASE WHEN " +
		           qualified_cond +
		           " THEN 1 ELSE 2 END AS prio"
		           " FROM " +
		           FunctionsSource(principal, names) + " f JOIN grants g ON g.\"vcat\" = f.\"vcat\"" + oc_join +
		           " WHERE f.\"kind\" = '" + kind + "' AND ((" + qualified_cond +
		           ") OR (g.\"is_main\" AND (SELECT unique_main FROM main_ok) AND f.\"vname\" = " + Lit(vname) +
		           ")) ORDER BY prio";
		auto result = Query(sql);
		TablePolicy policy;
		bool found = result->RowCount() > 0;
		if (found) {
			auto vcat = result->GetValue(0, 0).ToString();
			auto form = result->GetValue(1, 0).ToString();
			auto target = result->GetValue(2, 0);
			auto template_sql = result->GetValue(3, 0);
			auto prio = result->GetValue(11, 0).GetValue<int64_t>();
			policy.subquery_form = form != "alias";
			policy.phys = target.IsNull() ? string() : target.ToString();
			policy.query = template_sql.IsNull() ? string() : template_sql.ToString();
			// rows of the same winning function differ only by role: union their caps (spec 012 - a
			// call is a read, so it needs one) and their grant policies
			GrantUnion grants;
			for (idx_t row = 0; row < result->RowCount(); row++) {
				if (result->GetValue(11, row).GetValue<int64_t>() != prio ||
				    result->GetValue(0, row).ToString() != vcat) {
					continue;
				}
				auto caps = result->GetValue(4, row);
				for (auto &cap : EffectiveCaps(caps)) {
					policy.caps.insert(cap);
				}
				grants.Add(RowPolicy(*result, row, 5));
			}
			ApplyFunctionGrantPolicy(vname, table_kind, grants, policy);
		}
		lock_guard<mutex> guard(lock);
		ClearIfOversized(functions);
		functions[key] = {found, policy};
		if (found) {
			out = policy;
		}
		return found;
	}

	//! A grant narrows a table function the same way it narrows a relation, only the result is not a
	//! table but the function's output: the rewriter wraps the expanded/retargeted call in
	//! `SELECT <columns> FROM (<call>) WHERE <predicate>`. A scalar function has neither rows nor
	//! columns, so a policy on one is refused rather than silently ignored (spec 011).
	static void ApplyFunctionGrantPolicy(const string &vname, bool table_kind, const GrantUnion &grants,
	                                     TablePolicy &out) {
		auto predicate = grants.Predicate();
		bool restricts = grants.Restricts();
		out.rls_unchecked = grants.Unchecked();
		if (predicate.empty() && !restricts) {
			return;
		}
		if (!table_kind) {
			throw BinderException("acl: the grant on scalar function \"%s\" carries a policy, but a scalar "
			                      "function has no rows or columns to narrow",
			                      vname);
		}
		out.rls = predicate;
		if (!restricts) {
			return;
		}
		for (auto &column : grants.columns) {
			out.projection.push_back(column.second.empty() ? Ident(column.first)
			                                               : column.second + " AS " + Ident(column.first));
		}
	}

	//! Where a `CREATE`/`DROP` of `vname` lands for this principal (spec 016). One query: the longest
	//! virtual schema prefix of the name that the principal's roles hold, with the grant that states
	//! the capability - so a schema nobody granted, or granted without it, simply does not answer.
	bool DdlTarget(const Principal &principal, const string &vname, const string &capability, acl::DdlTarget &out) {
		if (principal.roles.empty() || function_mode) {
			return false; // the driver contract has no schema grants, so it has no DDL target
		}
		EnsureFresh();
		auto sql = GrantsCte(principal) +
		           "SELECT s.\"vcat\", s.\"path\", s.\"phys_path\", s.\"origin\", rs.\"caps\", rs.\"into\","
		           " rs.\"virtual_only\" FROM " +
		           Tbl("schemas") + " s JOIN grants g ON g.\"vcat\" = s.\"vcat\" JOIN " + Tbl("role_schemas") +
		           " rs ON rs.\"role\" = g.\"role\" AND rs.\"vcat\" = s.\"vcat\""
		           " AND rs.\"schema_path\" = s.\"path\" WHERE substr(" +
		           Lit(vname) +
		           ", 1, length(s.\"path\") + 1) = s.\"path\" || '.'"
		           " ORDER BY length(s.\"path\") DESC";
		auto result = Query(sql);
		for (idx_t row = 0; row < result->RowCount(); row++) {
			auto caps_value = result->GetValue(4, row);
			if (!EffectiveCaps(caps_value).count(capability)) {
				continue; // this role may not; another role of the principal still might
			}
			auto phys_path = result->GetValue(2, row);
			auto origin = result->GetValue(3, row);
			auto into = result->GetValue(5, row);
			auto only = result->GetValue(6, row);
			out.vcat = result->GetValue(0, row).ToString();
			out.schema_path = result->GetValue(1, row).ToString();
			out.origin = origin.IsNull() ? string() : origin.ToString();
			// an alias shows the physical schema live, so nothing has to be recorded; an expansion
			// shows only its own records, so a new object needs one
			out.needs_record = phys_path.IsNull();
			out.virtual_only = !only.IsNull() && only.GetValue<bool>();
			// the grant chooses where this role creates; without a choice the declaration decides
			out.phys_schema =
			    !into.IsNull() ? into.ToString() : (phys_path.IsNull() ? out.origin : phys_path.ToString());
			if (out.phys_schema.empty() && !out.virtual_only) {
				continue; // a schema that is neither an alias nor an expansion has nowhere to create
			}
			return true;
		}
		if (result->RowCount() > 0) {
			throw BinderException("acl: %s on schema \"%s\" is not allowed", capability,
			                      result->GetValue(1, 0).ToString());
		}
		return false;
	}

	//! The SQL behind a metadata surface (spec 010 part 3): the principal's own catalog, in the shape
	//! duckdb's own metadata has. The shape is not rebuilt by hand - the physical row is joined and its
	//! identity columns are REPLACEd with the virtual ones, so every other column (types, nullability,
	//! whatever duckdb adds next) stays correct for free. Objects without a physical row (a view, a
	//! query-defined function) are added through UNION ALL BY NAME, which fills the rest with NULL.
	string MetadataListingSql(const Principal &principal, const string &surface) {
		if (function_mode) {
			throw BinderException("acl: this policy source does not expose enumeration, so %s cannot be listed "
			                      "for a principal",
			                      surface);
		}
		// an object appears when the role holds something on it; '{}' is an explicit nothing (spec 012)
		auto visible =
		    "(" + CapsExpr() + " IS NULL OR trim(" + CapsExpr() + ") = '' OR trim(" + CapsExpr() + ") <> '{}')";
		string oc_join = HasObjectCaps() ? " LEFT JOIN " + Tbl("role_object_caps") +
		                                       " oc ON oc.\"role\" = g.\"role\" AND oc.\"vcat\" = r.\"vcat\""
		                                       " AND oc.\"vname\" = r.\"vname\""
		                                 : string();
		// the written path splits into a virtual schema and a name; a bare name sits in `main`
		string objects = "objects AS (SELECT DISTINCT r.\"vcat\" AS vcat,"
		                 " CASE WHEN position('.' IN r.\"vname\") > 0"
		                 " THEN regexp_extract(r.\"vname\", '^(.*)[.][^.]*$', 1) ELSE 'main' END AS vschema,"
		                 " regexp_extract(r.\"vname\", '([^.]*)$', 1) AS vname, r.\"form\" AS form,"
		                 " r.\"comment\" AS comment,"
		                 " str_split(r.\"phys\", '.') AS parts FROM " +
		                 Tbl("relations") + " r JOIN grants g ON g.\"vcat\" = r.\"vcat\"" + oc_join + " WHERE " +
		                 visible + ")";
		// an alias schema shows the physical schema live, so its visibility is the role's capabilities
		// on that schema (its own grant if it has one, otherwise the catalog's) - without this filter a
		// role granted an explicit nothing would still read the names out of the source
		auto schema_caps = "coalesce(nullif(trim((SELECT sc.\"caps\" FROM " + Tbl("role_schemas") +
		                   " sc WHERE sc.\"role\" = g.\"role\" AND sc.\"vcat\" = s.\"vcat\""
		                   " AND sc.\"schema_path\" = s.\"path\")), ''), g.\"caps\")";
		auto schema_visible =
		    "(" + schema_caps + " IS NULL OR trim(" + schema_caps + ") = '' OR trim(" + schema_caps + ") <> '{}')";
		string aliases = "aliases AS (SELECT DISTINCT s.\"vcat\" AS vcat, s.\"path\" AS path,"
		                 " str_split(s.\"phys_path\", '.') AS parts FROM " +
		                 Tbl("schemas") +
		                 " s JOIN grants g ON g.\"vcat\" = s.\"vcat\""
		                 " WHERE s.\"phys_path\" IS NOT NULL AND " +
		                 schema_visible + ")";
		// a schema exists for the principal when something inside it does
		string schemas = "vschemas AS (SELECT vcat, path FROM aliases UNION SELECT vcat, vschema FROM objects)";
		// spec 011 narrows columns per grant level, and the listing has to narrow with it: the object
		// row is kept per role here (unlike `objects`, which collapses them) so that "visible for at
		// least one role" can be asked column by column.
		string vfunctions = "vfunctions AS (SELECT DISTINCT f.\"vcat\" AS vcat, f.\"vname\" AS vname FROM " +
		                    Tbl("functions") + " f JOIN grants g ON g.\"vcat\" = f.\"vcat\"" +
		                    (HasObjectCaps() ? " LEFT JOIN " + Tbl("role_object_caps") +
		                                           " oc ON oc.\"role\" = g.\"role\" AND oc.\"vcat\" = f.\"vcat\""
		                                           " AND oc.\"vname\" = f.\"vname\""
		                                     : string()) +
		                    " WHERE f.\"kind\" = 'table' AND " + FunctionVisibleExpr() + ")";
		string grant_columns = "gcolumns AS (SELECT r.\"vcat\" AS vcat, r.\"vname\" AS vname, g.\"role\" AS role,"
		                       " g.\"columns\" AS cat_columns, " +
		                       string(HasObjectCaps() ? "oc.\"columns\"" : "NULL") + " AS obj_columns FROM " +
		                       Tbl("relations") + " r JOIN grants g ON g.\"vcat\" = r.\"vcat\"" + oc_join + " WHERE " +
		                       visible + ")";
		// spec 026: what a grant's own projection produces - a mask that changes a column's type, or a
		// computed column the object never had. Probed when the grant is written, so a listing can
		// describe what the role reads rather than what the physical table holds.
		string projected = "gprojection AS (SELECT DISTINCT pc.\"vcat\" AS vcat, pc.\"vname\" AS vname,"
		                   " pc.\"name\" AS name, pc.\"type\" AS type, pc.\"pos\" AS pos FROM " +
		                   Tbl("grant_columns") +
		                   " pc JOIN grants g ON g.\"role\" = pc.\"role\" AND g.\"vcat\" = pc.\"vcat\")";
		auto prelude = GrantsCte(principal) + ", " + objects + ", " + aliases + ", " + schemas + ", " + grant_columns +
		               ", " + vfunctions + ", " + projected + " ";
		if (surface == "databases") {
			// one row per granted catalog, and no physical database name ever appears
			return prelude + "SELECT DISTINCT vcat AS database_name, NULL AS path, NULL AS comment,"
			                 " NULL AS tags, false AS internal, NULL AS type, NULL AS database_oid,"
			                 " false AS readonly FROM vschemas";
		}
		if (surface == "schemata") {
			return prelude + "SELECT DISTINCT vcat AS catalog_name, path AS schema_name, NULL AS schema_owner,"
			                 " NULL AS default_character_set_catalog, NULL AS default_character_set_schema,"
			                 " NULL AS default_character_set_name, NULL AS sql_path, false AS internal,"
			                 " NULL AS comment FROM vschemas";
		}
		auto physical = "i.\"table_catalog\" = o.parts[1] AND i.\"table_schema\" = o.parts[2]"
		                " AND i.\"table_name\" = o.parts[3]";
		if (surface == "tables") {
			return prelude +
			       "SELECT i.* REPLACE (o.vcat AS table_catalog, o.vschema AS table_schema, o.vname AS table_name)"
			       " FROM objects o JOIN information_schema.tables i ON " +
			       physical +
			       " WHERE len(o.parts) = 3"
			       " UNION ALL BY NAME"
			       " SELECT o.vcat AS table_catalog, o.vschema AS table_schema, o.vname AS table_name,"
			       " 'VIEW' AS table_type FROM objects o WHERE o.form = 'view'"
			       " UNION ALL BY NAME"
			       " SELECT i.* REPLACE (a.vcat AS table_catalog, a.path AS table_schema)"
			       " FROM aliases a JOIN information_schema.tables i"
			       " ON i.\"table_catalog\" = a.parts[1] AND i.\"table_schema\" = a.parts[2]"
			       " WHERE len(a.parts) = 2";
		}
		if (surface != "columns" && surface != "references") {
			throw BinderException("acl: unknown metadata surface \"%s\"", surface);
		}
		// the columns a role actually sees: an object's own projection when it has one (its rows in
		// relation_columns name the visible columns, and for an alias form they map virtual -> physical)
		string projection = " LEFT JOIN " + Tbl("relation_columns") +
		                    " c ON c.\"vcat\" = o.vcat AND c.\"vname\" = CASE WHEN o.vschema = 'main' THEN o.vname"
		                    " ELSE o.vschema || '.' || o.vname END";
		// An `alias` relation is the physical table under a virtual name (possibly with renamed
		// columns), so its listing is the physical row with the identity columns replaced - the rich
		// shape, for free. Anything else - a projection, a view - is described by its own stored
		// schema: a masked or computed column has no physical row to borrow, and leaving it out would
		// hide a column the role can read.
		string columns_sql =
		    string("SELECT i.* REPLACE (o.vcat AS table_catalog, o.vschema AS table_schema, o.vname AS table_name,"
		           " coalesce(c.\"name\", i.\"column_name\") AS column_name)"
		           " FROM objects o JOIN information_schema.columns i ON ") +
		    physical + projection +
		    " AND c.\"expr\" = i.\"column_name\""
		    " WHERE len(o.parts) = 3 AND o.form = 'alias'"
		    " AND (c.\"name\" IS NOT NULL OR NOT EXISTS"
		    " (SELECT 1 FROM " +
		    Tbl("relation_columns") +
		    " c2 WHERE c2.\"vcat\" = o.vcat AND c2.\"vname\" = CASE WHEN o.vschema = 'main' THEN o.vname"
		    " ELSE o.vschema || '.' || o.vname END))"
		    " UNION ALL BY NAME"
		    " SELECT o.vcat AS table_catalog, o.vschema AS table_schema, o.vname AS table_name,"
		    " oc.\"name\" AS column_name, oc.\"pos\" + 1 AS ordinal_position, oc.\"type\" AS data_type,"
		    " oc.\"comment\" AS comment FROM objects o JOIN " +
		    Tbl("object_columns") +
		    " oc ON oc.\"vcat\" = o.vcat AND oc.\"kind\" = 'relation'"
		    " AND oc.\"vname\" = CASE WHEN o.vschema = 'main' THEN o.vname"
		    " ELSE o.vschema || '.' || o.vname END WHERE o.form <> 'alias'"
		    " UNION ALL BY NAME"
		    " SELECT i.* REPLACE (a.vcat AS table_catalog, a.path AS table_schema)"
		    " FROM aliases a JOIN information_schema.columns i"
		    " ON i.\"table_catalog\" = a.parts[1] AND i.\"table_schema\" = a.parts[2]"
		    " WHERE len(a.parts) = 2";
		// The names a grant states: split the list and take the part before '=' of a masked item. A
		// mask's expression may itself contain a comma, which splits into a fragment that matches no
		// column - harmless, since only the names on the left of '=' can ever match one.
		auto stated = [](const string &column_expr) {
			return "list_transform(str_split(" + column_expr +
			       ", ','), lambda y: lower(trim(CASE WHEN position('=' IN y) > 0"
			       " THEN regexp_extract(y, '^([^=]*)=', 1) ELSE y END)))";
		};
		auto keeps = [&](const string &column_expr, const string &name_expr) {
			return "(" + column_expr + " IS NULL OR trim(" + column_expr + ") = '' OR list_contains(" +
			       stated(column_expr) + ", lower(" + name_expr + ")))";
		};
		// Visible for at least one role: a principal may read what any of its roles may (spec 011). A
		// row with no grant row at all is not an object of the catalog - it is a column of a live
		// schema alias, whose visibility is the schema's, decided in `aliases` - so it is left alone.
		auto column_visible = [&](const string &vcat_expr, const string &vname_expr, const string &name_expr) {
			string key = "gc.vcat = " + vcat_expr + " AND gc.vname = " + vname_expr;
			return "(NOT EXISTS (SELECT 1 FROM gcolumns gc WHERE " + key + ")" +
			       " OR EXISTS (SELECT 1 FROM gcolumns gc"
			       " WHERE " +
			       key + " AND " + keeps("gc.cat_columns", name_expr) + " AND " + keeps("gc.obj_columns", name_expr) +
			       "))";
		};
		auto path = [](const string &alias) {
			return "CASE WHEN " + alias + ".vschema = 'main' THEN " + alias + ".vname ELSE " + alias +
			       ".vschema || '.' || " + alias + ".vname END";
		};
		string listed_path = "CASE WHEN l.table_schema = 'main' THEN l.table_name"
		                     " ELSE l.table_schema || '.' || l.table_name END";
		// A grant's own projection wins over the object's row for the names it defines - it is what the
		// role actually reads - and adds the ones the object never had (spec 026).
		string effective_columns =
		    "SELECT * FROM (" + columns_sql + ") l WHERE " +
		    column_visible("l.table_catalog", listed_path, "l.column_name") +
		    " AND NOT EXISTS (SELECT 1 FROM gprojection gp WHERE gp.vcat = l.table_catalog AND gp.vname = " +
		    listed_path + " AND gp.name = l.column_name)" +
		    " UNION ALL BY NAME"
		    " SELECT gp.vcat AS table_catalog,"
		    " CASE WHEN position('.' IN gp.vname) > 0 THEN regexp_extract(gp.vname, '^(.*)[.][^.]*$', 1)"
		    " ELSE 'main' END AS table_schema,"
		    " regexp_extract(gp.vname, '([^.]*)$', 1) AS table_name,"
		    " gp.name AS column_name, gp.pos + 1 AS ordinal_position, gp.type AS data_type"
		    " FROM gprojection gp WHERE EXISTS (SELECT 1 FROM objects o WHERE o.vcat = gp.vcat AND " +
		    path("o") + " = gp.vname)";
		if (surface == "columns") {
			return prelude + effective_columns;
		}
		// spec 022: a reference is visible when both of its ends are, and when every column it names is
		// a column the role can see. Anything else would describe an object - or a column - the role
		// has no access to, which is what a listing must never do.
		string column_path = "CASE WHEN vc.table_schema = 'main' THEN vc.table_name"
		                     " ELSE vc.table_schema || '.' || vc.table_name END";
		return prelude + ", vcolumns AS (" + effective_columns + ") " +
		       "SELECT r.\"vcat\" AS vcat, r.\"name\" AS name, r.\"from_vname\" AS from_object,"
		       " r.\"to_vname\" AS to_object,"
		       // the arguments a function end is called with, and - separately - the columns of the join
		       // condition: an argument's source column is a `from` column that also names a parameter
		       " (SELECT string_agg(rc.\"param\" || ' => ' || rc.\"column\", ', ' ORDER BY rc.\"pos\") FROM " +
		       Tbl("reference_columns") +
		       " rc WHERE rc.\"vcat\" = r.\"vcat\" AND rc.\"name\" = r.\"name\" AND rc.\"param\" IS NOT NULL)"
		       " AS arguments,"
		       " (SELECT string_agg(rc.\"column\", ', ' ORDER BY rc.\"pos\") FROM " +
		       Tbl("reference_columns") +
		       " rc WHERE rc.\"vcat\" = r.\"vcat\" AND rc.\"name\" = r.\"name\" AND rc.\"side\" = 'from'"
		       " AND rc.\"param\" IS NULL)"
		       " AS from_columns,"
		       " (SELECT string_agg(rc.\"column\", ', ' ORDER BY rc.\"pos\") FROM " +
		       Tbl("reference_columns") +
		       " rc WHERE rc.\"vcat\" = r.\"vcat\" AND rc.\"name\" = r.\"name\" AND rc.\"side\" = 'to')"
		       " AS to_columns,"
		       " r.\"to_kind\" AS to_kind, r.\"expr\" AS expression, r.\"cardinality\" AS cardinality,"
		       " r.\"optional\" AS optional, r.\"join_method\" AS join_method, r.\"comment\" AS comment FROM " +
		       Tbl("references") + " r WHERE EXISTS (SELECT 1 FROM objects o WHERE o.vcat = r.\"vcat\" AND " +
		       path("o") + " = r.\"from_vname\")" +
		       // the far end is an object, or - for a lateral call - a table function the role may use
		       " AND (CASE WHEN r.\"to_kind\" = 'function'"
		       " THEN EXISTS (SELECT 1 FROM vfunctions vf WHERE vf.vcat = r.\"vcat\""
		       " AND vf.vname = r.\"to_vname\")"
		       " ELSE EXISTS (SELECT 1 FROM objects o WHERE o.vcat = r.\"vcat\" AND " +
		       path("o") + " = r.\"to_vname\") END)" +
		       // every column it names must be one the role sees. The `to` side of a lateral call names
		       // parameters, not columns, so there is nothing there to hide or to check.
		       " AND NOT EXISTS (SELECT 1 FROM " + Tbl("reference_columns") +
		       " rc WHERE rc.\"vcat\" = r.\"vcat\" AND rc.\"name\" = r.\"name\""
		       " AND NOT (r.\"to_kind\" = 'function' AND rc.\"side\" = 'to')"
		       " AND NOT EXISTS (SELECT 1 FROM vcolumns vc WHERE vc.table_catalog = r.\"vcat\" AND " +
		       column_path +
		       " = CASE WHEN rc.\"side\" = 'from' THEN r.\"from_vname\" ELSE r.\"to_vname\" END"
		       " AND vc.column_name = rc.\"column\"))";
	}

	//! Targeted gate lookup: only the rows for this name and these roles leave the database ('' as
	//! role means a global row - NULL cannot be part of the primary key). Role-specific rows beat
	//! global rows; among role rows an explicit deny wins.
	bool FunctionGate(const Principal &principal, const string &name, bool &allowed) {
		EnsureFresh();
		auto lowered = StringUtil::Lower(name);
		auto key = RoleSig(principal) + "\x1f" + lowered;
		{
			lock_guard<mutex> guard(lock);
			auto entry = gates.find(key);
			if (entry != gates.end()) {
				allowed = entry->second.second;
				return entry->second.first;
			}
		}
		idx_t role_col = 0, allowed_col = 1;
		unique_ptr<MaterializedQueryResult> result;
		if (function_mode) {
			if (!HasSlot("function_gate")) { // no gate source: fall back to the built-in denylist
				lock_guard<mutex> guard(lock);
				gates[key] = {false, true};
				return false;
			}
			// positional contract: (role, name, kind, allowed)
			result = Query("SELECT * FROM " + Slot("function_gate") + "(" + ListLit(principal.roles) + ", " +
			               ListLit({lowered}) + ")");
			allowed_col = 3;
		} else {
			string role_filter = "\"role\" = ''";
			if (!principal.roles.empty()) {
				role_filter += " OR \"role\" IN (" + LitList(principal.roles) + ")";
			}
			result = Query("SELECT \"role\", \"allowed\" FROM " + Tbl("function_gate") +
			               " WHERE lower(\"name\") = " + Lit(lowered) + " AND (" + role_filter + ")");
		}
		bool have_role_row = false, role_allowed = true;
		bool have_global_row = false, global_allowed = true;
		for (idx_t row = 0; row < result->RowCount(); row++) {
			auto verdict_value = result->GetValue(allowed_col, row);
			bool verdict = !verdict_value.IsNull() && verdict_value.GetValue<bool>();
			if (result->GetValue(role_col, row).ToString().empty()) {
				have_global_row = true;
				global_allowed = verdict;
			} else {
				have_role_row = true;
				role_allowed = role_allowed && verdict;
			}
		}
		bool decided = have_role_row || have_global_row;
		bool verdict = have_role_row ? role_allowed : global_allowed;
		lock_guard<mutex> guard(lock);
		ClearIfOversized(gates);
		gates[key] = {decided, verdict};
		allowed = verdict;
		return decided;
	}

	void LoadRoleClaims(Principal &principal) {
		EnsureFresh();
		vector<string> missing;
		{
			lock_guard<mutex> guard(lock);
			for (auto &role : principal.roles) {
				if (!claims_loaded.count(role)) {
					missing.push_back(role);
				}
			}
		}
		if (function_mode && !HasSlot("role_claims")) {
			return; // optional slot: no source, no role-default claims
		}
		if (!missing.empty()) {
			// positional contract of the callback: (role, claim, value)
			auto result = function_mode ? Query("SELECT * FROM " + Slot("role_claims") + "(" + ListLit(missing) + ")")
			                            : Query("SELECT \"role\", \"claim\", \"value\" FROM " + Tbl("role_claims") +
			                                    " WHERE \"role\" IN (" + LitList(missing) + ")");
			lock_guard<mutex> guard(lock);
			for (auto &role : missing) {
				claims_loaded.insert(role);
				claims_cache[role];
			}
			for (idx_t row = 0; row < result->RowCount(); row++) {
				claims_cache[result->GetValue(0, row).ToString()][result->GetValue(1, row).ToString()] =
				    result->GetValue(2, row).ToString();
			}
		}
		lock_guard<mutex> guard(lock);
		for (auto &role : principal.roles) {
			auto entry = claims_cache.find(role);
			if (entry == claims_cache.end()) {
				continue;
			}
			for (auto &claim : entry->second) {
				if (!principal.claims.count(claim.first)) { // explicit claims win over role defaults
					principal.claims[claim.first] = claim.second;
				}
			}
		}
	}

	bool SettingBool(const char *name, bool fallback) {
		Value value;
		if (Db()->TryGetCurrentSetting(name, value) && !value.IsNull()) {
			return value.GetValue<bool>();
		}
		return fallback;
	}

	string SettingString(const char *name, const char *fallback) {
		Value value;
		if (Db()->TryGetCurrentSetting(name, value) && !value.IsNull()) {
			return value.ToString();
		}
		return fallback;
	}
	int64_t SettingInt64(const char *name, int64_t fallback) {
		Value value;
		if (Db()->TryGetCurrentSetting(name, value) && !value.IsNull()) {
			return value.GetValue<int64_t>();
		}
		return fallback;
	}

	bool LookupIssuer(const string &issuer, IssuerConfig &out) {
		EnsureFresh();
		{
			lock_guard<mutex> guard(lock);
			auto entry = issuer_cache.find(issuer);
			if (entry != issuer_cache.end()) {
				out = entry->second.second;
				return entry->second.first;
			}
		}
		unique_ptr<MaterializedQueryResult> result;
		idx_t base = 0;
		if (function_mode) {
			if (!HasSlot("issuer")) { // optional slot: no JWT issuers through this source
				lock_guard<mutex> guard(lock);
				issuer_cache[issuer] = {false, IssuerConfig()};
				return false;
			}
			// positional contract: (issuer, keys_json, audiences, algs, role_claim, claim_map)
			result = Query("SELECT * FROM " + Slot("issuer") + "(" + Lit(issuer) + ")");
			base = 1;
		} else {
			result = Query("SELECT \"keys_json\", \"audiences\", \"algs\", \"role_claim\", \"claim_map\","
			               " \"jwks_uri\" FROM " +
			               Tbl("issuers") + " WHERE \"issuer\" = " + Lit(issuer));
		}
		IssuerConfig config;
		bool found = result->RowCount() > 0;
		if (found) {
			config.issuer = issuer;
			auto keys = result->GetValue(base + 0, 0);
			config.keys_json = keys.IsNull() ? string() : keys.ToString();
			auto audiences = result->GetValue(base + 1, 0);
			for (auto &aud : StringUtil::Split(audiences.IsNull() ? string() : audiences.ToString(), ',')) {
				StringUtil::Trim(aud);
				if (!aud.empty()) {
					config.audiences.push_back(aud);
				}
			}
			auto algs = result->GetValue(base + 2, 0);
			for (auto &alg : StringUtil::Split(algs.IsNull() ? string() : algs.ToString(), ',')) {
				StringUtil::Trim(alg);
				if (!alg.empty()) {
					config.algs.insert(alg);
				}
			}
			auto role_claim = result->GetValue(base + 3, 0);
			config.role_claim = role_claim.IsNull() ? string() : role_claim.ToString();
			auto claim_map = result->GetValue(base + 4, 0);
			config.claim_map = claim_map.IsNull() ? string() : claim_map.ToString();
			// the function-driver slot has no jwks_uri column: its platform hands over the keys itself
			if (result->ColumnCount() > base + 5) {
				auto jwks_uri = result->GetValue(base + 5, 0);
				config.jwks_uri = jwks_uri.IsNull() ? string() : jwks_uri.ToString();
			}
		}
		lock_guard<mutex> guard(lock);
		issuer_cache[issuer] = {found, config};
		out = config;
		return found;
	}

	//! The catalogs the principal may MANAGE: a capability of the catalog grant itself, so a role can
	//! manage many catalogs (and manage one without being able to read it)
	//! Load (and cache) both administration sources for the principal in one go
	void LoadRights(const Principal &principal, std::set<string> &catalogs, vector<std::pair<string, string>> &scopes) {
		if (principal.roles.empty()) {
			return;
		}
		EnsureFresh();
		auto key = RoleSig(principal);
		{
			lock_guard<mutex> guard(lock);
			auto entry = rights_cache.find(key);
			if (entry != rights_cache.end()) {
				catalogs = entry->second.first;
				scopes = entry->second.second;
				return;
			}
		}
		ManageCatalogs(principal, catalogs);
		AdminScopes(principal, scopes);
		lock_guard<mutex> guard(lock);
		ClearIfOversized(rights_cache);
		rights_cache[key] = {catalogs, scopes};
	}

	void ManageCatalogs(const Principal &principal, std::set<string> &out) {
		if (principal.roles.empty()) {
			return;
		}
		EnsureFresh();
		if (function_mode) {
			for (auto &grant : Grants(principal.roles)) {
				// an empty catalog name is not a catalog: never let it stand for "all of them"
				if (!grant.vcat.empty() && ParseCaps(grant.caps).count("manage")) {
					out.insert(grant.vcat);
				}
			}
			return;
		}
		auto result = Query("SELECT \"vcat\", \"caps\" FROM " + Tbl("role_catalogs") + " WHERE \"role\" IN (" +
		                    LitList(principal.roles) + ")");
		for (idx_t row = 0; row < result->RowCount(); row++) {
			auto caps = result->GetValue(1, row);
			auto vcat = result->GetValue(0, row).ToString();
			if (!vcat.empty() && ParseCaps(caps.IsNull() ? string() : caps.ToString()).count("manage")) {
				out.insert(vcat);
			}
		}
	}

	//! The admin scopes of the principal's roles; the function-driver may serve them through a slot
	void AdminScopes(const Principal &principal, vector<std::pair<string, string>> &out) {
		if (principal.roles.empty()) {
			return;
		}
		EnsureFresh();
		unique_ptr<MaterializedQueryResult> result;
		if (function_mode) {
			if (!HasSlot("admin_scopes")) { // optional slot: no admin grants through this source
				return;
			}
			// positional contract: (role, scope, vcat)
			result = Query("SELECT * FROM " + Slot("admin_scopes") + "(" + ListLit(principal.roles) + ")");
		} else {
			result = Query("SELECT \"role\", \"scope\", \"vcat\" FROM " + Tbl("admins") + " WHERE \"role\" IN (" +
			               LitList(principal.roles) + ")");
		}
		for (idx_t row = 0; row < result->RowCount(); row++) {
			auto vcat = result->GetValue(2, row);
			out.emplace_back(result->GetValue(1, row).ToString(), vcat.IsNull() ? string() : vcat.ToString());
		}
	}

	//! One query maps external role values and checks which raw values exist as internal roles
	void MapExternalRoles(const string &issuer, const vector<string> &values,
	                      case_insensitive_map_t<vector<string>> &mapped, case_insensitive_set_t &known_roles) {
		if (values.empty()) {
			return;
		}
		EnsureFresh();
		if (function_mode) {
			if (HasSlot("role_mappings")) {
				// positional contract: (external_value, role)
				auto result =
				    Query("SELECT * FROM " + Slot("role_mappings") + "(" + Lit(issuer) + ", " + ListLit(values) + ")");
				for (idx_t row = 0; row < result->RowCount(); row++) {
					mapped[result->GetValue(0, row).ToString()].push_back(result->GetValue(1, row).ToString());
				}
			}
			// a raw value is a known role iff the role_catalogs callback grants it anything
			for (auto &grant : Grants(values)) {
				known_roles.insert(grant.role);
			}
			return;
		}
		auto result =
		    Query("SELECT \"external_value\", \"role\" FROM " + Tbl("role_mappings") +
		          " WHERE \"issuer\" = " + Lit(issuer) + " AND \"external_value\" IN (" + LitList(values) + ")");
		for (idx_t row = 0; row < result->RowCount(); row++) {
			mapped[result->GetValue(0, row).ToString()].push_back(result->GetValue(1, row).ToString());
		}
		auto known = Query("SELECT \"role\" FROM " + Tbl("roles") + " WHERE \"role\" IN (" + LitList(values) +
		                   ") UNION SELECT DISTINCT \"role\" FROM " + Tbl("role_catalogs") + " WHERE \"role\" IN (" +
		                   LitList(values) + ")");
		for (idx_t row = 0; row < known->RowCount(); row++) {
			known_roles.insert(known->GetValue(0, row).ToString());
		}
	}

	//! Bind a template (markers baked to NULL) without reading data, and return its column schema.
	//! Runs on the write path, so introspection later costs nothing; a failure is not fatal - the
	//! object is stored with an unknown schema and `acl_refresh_schema` can try again.
	bool ProbeSchema(const string &sql, bool expression, const vector<string> &param_types,
	                 vector<std::pair<string, string>> &out) {
		auto instance = Db();
		string probe;
		try {
			ParserOptions options;
			auto baked = BakeTemplateForProbe(sql, options, expression, param_types);
			probe = expression ? "SELECT (" + baked + ") AS \"value\" WHERE false"
			                   : "SELECT * FROM (" + baked + ") WHERE false";
		} catch (std::exception &) {
			return false; // an unparsable template: the definition itself will report it
		}
		Connection con(*instance);
		auto result = con.Query(probe);
		if (result->HasError()) {
			return false; // stored as "schema unknown"; acl_refresh_schema can try again later
		}
		auto &types = result->GetTypes();
		for (idx_t col = 0; col < result->ColumnCount(); col++) {
			out.emplace_back(result->ColumnName(col).GetIdentifierName(), types[col].ToString());
		}
		return true;
	}

	//! Bind a grant's predicate against the object it filters, without reading data. Returns the
	//! binder's message when the predicate is at fault and an empty string when it binds.
	//!
	//! The target is bound on its own first: if *that* fails there is nothing to judge the predicate
	//! against - the source may simply not be attached yet - and the predicate is accepted, exactly as
	//! a schema probe that cannot bind is not fatal.
	string PredicateError(const string &source, const string &rls, bool *checked = nullptr) {
		if (checked) {
			*checked = false;
		}
		if (rls.empty() || source.empty()) {
			return string();
		}
		auto instance = Db();
		Connection con(*instance);
		auto base = con.Query("SELECT * FROM " + source + " WHERE false");
		if (base->HasError()) {
			return string(); // the object itself does not bind here; not the predicate's fault
		}
		if (checked) {
			*checked = true; // whatever the answer, the predicate was judged rather than waved through
		}
		string baked;
		try {
			ParserOptions options;
			baked = BakeTemplateForProbe("SELECT * FROM " + source + " WHERE (" + rls + ")", options, false, {});
		} catch (std::exception &error) {
			return string(error.what());
		}
		auto probe = con.Query("SELECT * FROM (" + baked + ") WHERE false");
		if (probe->HasError()) {
			return probe->GetError();
		}
		return string();
	}

	//! A catalog grant's predicate filters every object of the catalog, so there is no single object to
	//! bind it against: it is judged against all of them, and counts as checked only when every object
	//! that binds at all accepted it. Unlike an object's own predicate this never refuses the write - a
	//! catalog predicate that does not fit one object is a real (if questionable) configuration, and it
	//! was allowed before the flag existed.
	bool CatalogPredicateChecked(const std::function<unique_ptr<MaterializedQueryResult>(const string &)> &read,
	                             const string &vcat, const string &rls) {
		if (rls.empty()) {
			return true; // nothing to judge
		}
		auto rows =
		    read("SELECT \"form\", \"phys\", \"view_sql\" FROM " + Tbl("relations") + " WHERE \"vcat\" = " + Lit(vcat));
		bool any = false;
		for (idx_t row = 0; row < rows->RowCount(); row++) {
			auto text = [&](idx_t column) {
				auto value = rows->GetValue(column, row);
				return value.IsNull() ? string() : value.ToString();
			};
			auto form = text(0);
			auto source = form == "view" ? "(" + text(2) + ")" : text(1);
			bool checked = false;
			auto error = PredicateError(source, rls, &checked);
			if (!checked) {
				continue; // this object cannot be bound here; it judges nothing either way
			}
			if (!error.empty()) {
				return false;
			}
			any = true;
		}
		return any;
	}

	//! Bind a projection over a relation and return the columns it produces (spec 026). Never fatal: an
	//! unbindable projection leaves the listing as it was rather than refusing the grant.
	//! Returns the binder's message when the projection is at fault, and an empty string when it binds -
	//! or when the object itself does not bind, since then there is nothing to judge it against. The
	//! same two steps as a predicate's check (spec 021), for the same reason.
	string ProjectionSchema(const string &source, const string &column_csv, const case_insensitive_map_t<string> &own,
	                        vector<std::pair<string, string>> &out, bool *checked = nullptr) {
		if (checked) {
			*checked = false;
		}
		vector<string> items;
		for (auto &column : ParseColumnList(column_csv)) {
			if (!column.second.empty()) {
				items.push_back(column.second + " AS " + column.first); // the grant computes it
				continue;
			}
			auto object = own.find(column.first);
			// a bare name is the object's column, which its own projection may have renamed
			items.push_back((object != own.end() && !object->second.empty() ? object->second : column.first) + " AS " +
			                column.first);
		}
		if (items.empty()) {
			return string();
		}
		auto instance = Db();
		Connection con(*instance);
		if (con.Query("SELECT * FROM " + source + " WHERE false")->HasError()) {
			return string(); // the object does not bind here; not the projection's fault
		}
		if (checked) {
			*checked = true; // whatever the answer, the projection was probed rather than waved through
		}
		auto sql = "SELECT " + StringUtil::Join(items, ", ") + " FROM " + source;
		if (ProbeSchema(sql, false, {}, out)) {
			return string();
		}
		auto probe = con.Query("SELECT * FROM (" + sql + ") WHERE false");
		return probe->HasError() ? probe->GetError() : string("the projection could not be described");
	}

	//! Read a document through duckdb's own filesystem (spec 023). A local path works out of the box;
	//! an https URL needs httpfs, and duckdb says so itself - which is the error an operator needs.
	bool ReadText(const string &uri, string &out, string &error) {
		auto instance = Db();
		Connection con(*instance);
		auto result = con.Query("SELECT content FROM read_text(" + Lit(uri) + ")");
		if (result->HasError()) {
			error = result->GetError();
			return false;
		}
		if (result->RowCount() == 0) {
			error = "there is no document there";
			return false;
		}
		if (result->RowCount() != 1 || result->GetValue(0, 0).IsNull()) {
			error = "the location holds no single document";
			return false;
		}
		out = result->GetValue(0, 0).ToString();
		return true;
	}

	//! Whether a relation has a column of that name. False only when the relation itself binds and the
	//! column does not: a source that cannot be reached at all answers true, since it cannot answer.
	bool ColumnBinds(const string &source, const string &column) {
		auto instance = Db();
		Connection con(*instance);
		auto base = con.Query("SELECT * FROM " + source + " WHERE false");
		if (base->HasError()) {
			return true;
		}
		auto quoted = "\"" + StringUtil::Replace(column, "\"", "\"\"") + "\"";
		return !con.Query("SELECT " + quoted + " FROM " + source + " WHERE false")->HasError();
	}

	//! "name TYPE, name TYPE" -> the pieces; a bare "TYPE" (a scalar's RETURNS) yields an empty name
	static vector<std::pair<string, string>> ParseDeclaration(const string &declaration) {
		vector<std::pair<string, string>> parts;
		for (auto &item : StringUtil::Split(declaration, ',')) {
			auto trimmed = item;
			StringUtil::Trim(trimmed);
			if (trimmed.empty()) {
				continue;
			}
			auto space = trimmed.find(' ');
			if (space == string::npos) {
				parts.emplace_back(string(), trimmed);
				continue;
			}
			auto name = trimmed.substr(0, space);
			auto type = trimmed.substr(space + 1);
			StringUtil::Trim(type);
			parts.emplace_back(name, type);
		}
		return parts;
	}

	static vector<string> DeclaredTypes(const string &declaration) {
		vector<string> types;
		for (auto &part : ParseDeclaration(declaration)) {
			types.push_back(part.second);
		}
		return types;
	}

	//! Statements replacing one object's stored column schema
	vector<string> ColumnSchemaStatements(const string &vcat, const string &vname, const string &kind,
	                                      const vector<std::pair<string, string>> &columns, bool derived) {
		vector<string> statements;
		statements.push_back("DELETE FROM " + Tbl("object_columns") + " WHERE \"vcat\" = " + Lit(vcat) +
		                     " AND \"vname\" = " + Lit(vname) + " AND \"kind\" = " + Lit(kind));
		idx_t pos = 0;
		for (auto &column : columns) {
			statements.push_back("INSERT INTO " + Tbl("object_columns") + " VALUES (" + Lit(vcat) + ", " + Lit(vname) +
			                     ", " + Lit(kind) + ", " + std::to_string(pos++) + ", " + Lit(column.first) + ", " +
			                     Lit(column.second) + ", NULL, " + (derived ? "true" : "false") + ")");
		}
		return statements;
	}

	//! Every table carries a primary key: sources without rowids need one for DELETE/UPDATE
	void InitSchema() {
		auto instance = Db();
		Connection con(*instance);
		vector<string> ddl = {
		    "CREATE SCHEMA IF NOT EXISTS " + Ident(db_name) + "." + Ident(schema),
		    "CREATE TABLE IF NOT EXISTS " + Tbl("meta") + "(\"key\" VARCHAR PRIMARY KEY, \"value\" VARCHAR)",
		    "CREATE TABLE IF NOT EXISTS " + Tbl("catalogs") + "(\"vcat\" VARCHAR PRIMARY KEY, \"comment\" VARCHAR)",
		    "CREATE TABLE IF NOT EXISTS " + Tbl("relations") +
		        "(\"vcat\" VARCHAR, \"vname\" VARCHAR, \"form\" VARCHAR, \"phys\" VARCHAR, \"view_sql\" VARCHAR,"
		        " \"rls\" VARCHAR, PRIMARY KEY (\"vcat\", \"vname\"))",
		    "CREATE TABLE IF NOT EXISTS " + Tbl("relation_columns") +
		        "(\"vcat\" VARCHAR, \"vname\" VARCHAR, \"pos\" INTEGER, \"name\" VARCHAR, \"expr\" VARCHAR,"
		        " PRIMARY KEY (\"vcat\", \"vname\", \"pos\"))",
		    "CREATE TABLE IF NOT EXISTS " + Tbl("schema_aliases") +
		        "(\"vcat\" VARCHAR, \"alias_path\" VARCHAR, \"phys_path\" VARCHAR,"
		        " PRIMARY KEY (\"vcat\", \"alias_path\"))",
		    "CREATE TABLE IF NOT EXISTS " + Tbl("functions") +
		        "(\"vcat\" VARCHAR, \"vname\" VARCHAR, \"kind\" VARCHAR, \"form\" VARCHAR, \"target\" VARCHAR,"
		        " \"template\" VARCHAR, PRIMARY KEY (\"vcat\", \"vname\", \"kind\"))",
		    "CREATE TABLE IF NOT EXISTS " + Tbl("roles") + "(\"role\" VARCHAR PRIMARY KEY, \"comment\" VARCHAR)",
		    "CREATE TABLE IF NOT EXISTS " + Tbl("role_claims") +
		        "(\"role\" VARCHAR, \"claim\" VARCHAR, \"value\" VARCHAR, PRIMARY KEY (\"role\", \"claim\"))",
		    "CREATE TABLE IF NOT EXISTS " + Tbl("role_catalogs") +
		        "(\"role\" VARCHAR, \"vcat\" VARCHAR, \"is_main\" BOOLEAN, \"caps\" VARCHAR,"
		        " PRIMARY KEY (\"role\", \"vcat\"))",
		    "CREATE TABLE IF NOT EXISTS " + Tbl("role_object_caps") +
		        "(\"role\" VARCHAR, \"vcat\" VARCHAR, \"vname\" VARCHAR, \"caps\" VARCHAR,"
		        " PRIMARY KEY (\"role\", \"vcat\", \"vname\"))",
		    // '' as role/kind means "global"/"any kind": NULL cannot be part of the primary key
		    "CREATE TABLE IF NOT EXISTS " + Tbl("function_gate") +
		        "(\"role\" VARCHAR, \"name\" VARCHAR, \"kind\" VARCHAR, \"allowed\" BOOLEAN,"
		        " PRIMARY KEY (\"role\", \"name\", \"kind\"))",
		    "CREATE TABLE IF NOT EXISTS " + Tbl("issuers") +
		        "(\"issuer\" VARCHAR PRIMARY KEY, \"keys_json\" VARCHAR, \"audiences\" VARCHAR,"
		        " \"algs\" VARCHAR, \"role_claim\" VARCHAR, \"claim_map\" VARCHAR)",
		    // '' as vcat means "every catalog": NULL cannot be part of the primary key
		    "CREATE TABLE IF NOT EXISTS " + Tbl("admins") +
		        "(\"role\" VARCHAR PRIMARY KEY, \"scope\" VARCHAR, \"vcat\" VARCHAR)",
		    "CREATE TABLE IF NOT EXISTS " + Tbl("role_mappings") +
		        "(\"issuer\" VARCHAR, \"source\" VARCHAR, \"external_value\" VARCHAR, \"role\" VARCHAR,"
		        " PRIMARY KEY (\"issuer\", \"source\", \"external_value\", \"role\"))",
		    // spec 010 (schema v2): comments, and the column schema of every object - declared by an
		    // admin or derived by binding the template at write time (a query-defined object has no
		    // physical row to read names and types from). Runs after every CREATE TABLE above.
		    "CREATE TABLE IF NOT EXISTS " + Tbl("object_columns") +
		        "(\"vcat\" VARCHAR, \"vname\" VARCHAR, \"kind\" VARCHAR, \"pos\" INTEGER, \"name\" VARCHAR,"
		        " \"type\" VARCHAR, \"comment\" VARCHAR, \"derived\" BOOLEAN,"
		        " PRIMARY KEY (\"vcat\", \"vname\", \"kind\", \"pos\"))",
		    // spec 014 (schema v4): a schema is an object of the catalog, not just a prefix rule - it
		    // carries a comment, and `phys_path` says which kind it is: non-NULL = a live alias that
		    // resolves through, NULL = a schema whose content is the catalog's own relation records
		    "CREATE TABLE IF NOT EXISTS " + Tbl("schemas") +
		        "(\"vcat\" VARCHAR, \"path\" VARCHAR, \"phys_path\" VARCHAR, \"comment\" VARCHAR,"
		        " PRIMARY KEY (\"vcat\", \"path\"))",
		    "INSERT INTO " + Tbl("schemas") +
		        "(\"vcat\", \"path\", \"phys_path\") SELECT a.\"vcat\", a.\"alias_path\", a.\"phys_path\" FROM " +
		        Tbl("schema_aliases") + " a WHERE NOT EXISTS (SELECT 1 FROM " + Tbl("schemas") +
		        " s WHERE s.\"vcat\" = a.\"vcat\" AND s.\"path\" = a.\"alias_path\")",
		    "ALTER TABLE " + Tbl("relations") + " ADD COLUMN IF NOT EXISTS \"comment\" VARCHAR",
		    // spec 014: an expansion's source, and the record's memory of where it came from - which is
		    // how REFRESH tells its own records from ones an admin registered by hand. Column order
		    // differs between a fresh catalog and a migrated one, so every INSERT names its columns.
		    "ALTER TABLE " + Tbl("schemas") + " ADD COLUMN IF NOT EXISTS \"origin\" VARCHAR",
		    "ALTER TABLE " + Tbl("relations") + " ADD COLUMN IF NOT EXISTS \"origin\" VARCHAR",
		    // spec 015 (schema v5): the middle level of the grant chain. Capabilities only - policy stays
		    // two-level - and `inherited` says whether the row was materialised from an ancestor or
		    // granted as it stands, which is what makes the cascade repeatable.
		    "CREATE TABLE IF NOT EXISTS " + Tbl("role_schemas") +
		        "(\"role\" VARCHAR, \"vcat\" VARCHAR, \"schema_path\" VARCHAR, \"caps\" VARCHAR,"
		        " \"inherited\" BOOLEAN, \"comment\" VARCHAR,"
		        " PRIMARY KEY (\"role\", \"vcat\", \"schema_path\"))",
		    // spec 016: where this role creates - a physical schema of its own (`INTO`), or nothing at
		    // all (`VIRTUAL ONLY`: it may only register objects that already exist)
		    "ALTER TABLE " + Tbl("role_schemas") + " ADD COLUMN IF NOT EXISTS \"into\" VARCHAR",
		    "ALTER TABLE " + Tbl("role_schemas") + " ADD COLUMN IF NOT EXISTS \"virtual_only\" BOOLEAN",
		    // a record dropped on purpose must not come back on the next REFRESH
		    "CREATE TABLE IF NOT EXISTS " + Tbl("schema_dropped") +
		        "(\"vcat\" VARCHAR, \"path\" VARCHAR, \"name\" VARCHAR,"
		        " PRIMARY KEY (\"vcat\", \"path\", \"name\"))",
		    // spec 011 (schema v3): a grant carries its own policy, not only capabilities - an RLS
		    // predicate and a column list that narrow the object for this role (and supply values on
		    // writes). Both levels of the chain are grant rows, so both gain the two columns.
		    "ALTER TABLE " + Tbl("role_catalogs") + " ADD COLUMN IF NOT EXISTS \"rls\" VARCHAR",
		    "ALTER TABLE " + Tbl("role_catalogs") + " ADD COLUMN IF NOT EXISTS \"columns\" VARCHAR",
		    "ALTER TABLE " + Tbl("role_object_caps") + " ADD COLUMN IF NOT EXISTS \"rls\" VARCHAR",
		    "ALTER TABLE " + Tbl("role_object_caps") + " ADD COLUMN IF NOT EXISTS \"columns\" VARCHAR",
		    "ALTER TABLE " + Tbl("functions") + " ADD COLUMN IF NOT EXISTS \"comment\" VARCHAR",
		    // the declared signature ("name TYPE, …"): it makes a probe meaningful (typed NULLs) and,
		    // together with a declared result, unnecessary
		    "ALTER TABLE " + Tbl("functions") + " ADD COLUMN IF NOT EXISTS \"params\" VARCHAR",
		    // spec 022 (schema v7): references - declared join paths between objects of the virtual
		    // catalog. Not foreign keys: nothing is enforced, the ends may live in different sources,
		    // and the record is a hint an agent reads. The columns live in their own table so that
		    // visibility is an anti-join rather than the parsing of a packed string.
		    "CREATE TABLE IF NOT EXISTS " + Tbl("references") +
		        "(\"vcat\" VARCHAR, \"name\" VARCHAR, \"from_vname\" VARCHAR, \"to_vname\" VARCHAR,"
		        " \"to_kind\" VARCHAR, \"expr\" VARCHAR, \"cardinality\" VARCHAR, \"optional\" BOOLEAN,"
		        " \"join_method\" VARCHAR, \"comment\" VARCHAR, PRIMARY KEY (\"vcat\", \"name\"))",
		    // one row per column the reference names, with the side it belongs to: 'from' or 'to'.
		    // A pair join writes two rows per position; an expression writes one row per name it
		    // mentions, attributed at write time by its qualifier.
		    "CREATE TABLE IF NOT EXISTS " + Tbl("reference_columns") +
		        "(\"vcat\" VARCHAR, \"name\" VARCHAR, \"pos\" INTEGER, \"side\" VARCHAR, \"column\" VARCHAR,"
		        " \"param\" VARCHAR, PRIMARY KEY (\"vcat\", \"name\", \"pos\", \"side\"))",
		    // spec 023 (schema v8): where an issuer's keys come from. A JWKS the operator pasted stays
		    // valid; a URI is read through duckdb's own filesystem, so an https URL (with httpfs) and a
		    // file an operator refreshes out of band are the same mechanism.
		    "ALTER TABLE " + Tbl("issuers") + " ADD COLUMN IF NOT EXISTS \"jwks_uri\" VARCHAR",
		    // spec 026 (schema v9): the columns a *grant's* projection produces. An object's own columns
		    // are probed when it is defined (spec 010), but a grant may mask one into another type or
		    // add a computed one the object never had - and a listing that cannot see those describes
		    // something the role does not read.
		    "CREATE TABLE IF NOT EXISTS " + Tbl("grant_columns") +
		        "(\"role\" VARCHAR, \"vcat\" VARCHAR, \"vname\" VARCHAR, \"pos\" INTEGER, \"name\" VARCHAR,"
		        " \"type\" VARCHAR, PRIMARY KEY (\"role\", \"vcat\", \"vname\", \"pos\"))",
		    // spec 027 (schema v10): whether a predicate was actually bound when it was written. Spec 021
		    // binds one where it can, and accepts it unchecked when the object cannot be bound at all -
		    // so "it was accepted" and "it was judged" are different facts, and only the second one lets
		    // a write with a second relation in scope trust a subquery inside it.
		    "ALTER TABLE " + Tbl("relations") + " ADD COLUMN IF NOT EXISTS \"rls_checked\" BOOLEAN",
		    "ALTER TABLE " + Tbl("role_object_caps") + " ADD COLUMN IF NOT EXISTS \"rls_checked\" BOOLEAN",
		    "ALTER TABLE " + Tbl("role_catalogs") + " ADD COLUMN IF NOT EXISTS \"rls_checked\" BOOLEAN",
		    "INSERT INTO " + Tbl("meta") + " SELECT 'schema_version', '10' WHERE NOT EXISTS (SELECT 1 FROM " +
		        Tbl("meta") + " WHERE \"key\" = 'schema_version')",
		    "UPDATE " + Tbl("meta") + " SET \"value\" = '10' WHERE \"key\" = 'schema_version' AND \"value\" < '10'",
		    "INSERT INTO " + Tbl("meta") + " SELECT 'policy_version', '1' WHERE NOT EXISTS (SELECT 1 FROM " +
		        Tbl("meta") + " WHERE \"key\" = 'policy_version')",
		};
		for (auto &sql : ddl) {
			auto result = con.Query(sql);
			if (result->HasError()) {
				throw BinderException("acl catalog: init failed at [%s]: %s", sql, result->GetError());
			}
		}
	}
};

} // namespace acl_detail

using acl_detail::CatalogBackend;
using acl_detail::Lit;

PolicyStore::PolicyStore() {
}

PolicyStore::~PolicyStore() {
}

void PolicyStore::EnableCatalog(DatabaseInstance &db, const string &db_name, const string &schema, bool init) {
	auto backend = make_uniq<CatalogBackend>(db, db_name, schema);
	if (init) {
		backend->InitSchema();
	}
	backend->EnsureFresh(); // validates reachability and the schema before switching over
	lock_guard<mutex> guard(lock);
	catalog = std::move(backend);
}

void PolicyStore::EnableFunctions(DatabaseInstance &db, const string &slots_json) {
	auto slots = acl_detail::ParseStringMap(slots_json);
	auto backend = make_uniq<CatalogBackend>(db, slots);
	// explicit slot map, fail closed at enable (design decision): the core slots are required and
	// every named function must actually be registered
	for (auto required :
	     {"policy_version", "role_catalogs", "relations", "relation_columns", "schema_aliases", "functions"}) {
		if (!backend->HasSlot(required)) {
			throw BinderException("acl_use_functions: required slot \"%s\" is missing", required);
		}
	}
	for (auto &slot : slots) {
		auto exists = backend->Query("SELECT count(*) FROM duckdb_functions() WHERE \"function_name\" = " +
		                             acl_detail::Lit(slot.second));
		if (exists->GetValue(0, 0).GetValue<int64_t>() == 0) {
			throw BinderException("acl_use_functions: slot \"%s\" names an unknown function \"%s\"", slot.first,
			                      slot.second);
		}
	}
	backend->EnsureFresh(); // probes the policy_version callback before switching over
	lock_guard<mutex> guard(lock);
	catalog = std::move(backend);
}

bool PolicyStore::CatalogResolveTable(const Principal &principal, const string &vname, TablePolicy &out) {
	return catalog->ResolveTable(principal, vname, out);
}

bool PolicyStore::CatalogResolveFunction(const Principal &principal, const string &vname, bool table_kind,
                                         TablePolicy &out) {
	return catalog->ResolveFunction(principal, vname, table_kind, out);
}

bool PolicyStore::CatalogFunctionGate(const Principal &principal, const QualifiedName &name, bool &allowed) {
	return catalog->FunctionGate(principal, name.Name().GetIdentifierName(), allowed);
}

void PolicyStore::CatalogLoadRoleClaims(Principal &principal) {
	catalog->LoadRoleClaims(principal);
}

bool PolicyStore::CatalogLookupIssuer(const string &issuer, IssuerConfig &out) {
	return catalog->LookupIssuer(issuer, out);
}

void PolicyStore::CatalogMapExternalRoles(const string &issuer, const vector<string> &values,
                                          case_insensitive_map_t<vector<string>> &mapped,
                                          case_insensitive_set_t &known_roles) {
	catalog->MapExternalRoles(issuer, values, mapped, known_roles);
}

string PolicyStore::ParserOverrideMode() {
	if (!catalog) {
		return "STRICT"; // the memory store has no database handle; it is a dev/test path
	}
	return catalog->SettingString("allow_parser_override_extension", "DEFAULT");
}

int64_t PolicyStore::JwtClockSkew() {
	if (catalog) {
		return catalog->SettingInt64("acl_jwt_clock_skew", 60);
	}
	return 60; // the memory mode has no database handle to read the setting from
}

int64_t PolicyStore::JwksRefreshInterval() {
	if (!catalog) {
		return 300;
	}
	return catalog->SettingInt64("acl_jwks_refresh_interval", 300);
}

int64_t PolicyStore::JwksMaxStale() {
	if (!catalog) {
		return 3600;
	}
	return catalog->SettingInt64("acl_jwks_max_stale", 3600);
}

//! spec 023: the key set a token is judged against. An issuer that pastes a JWKS keeps it; one that
//! names a URI has it read through duckdb's filesystem, cached here, and re-read when the TTL expires
//! or when the token names a key the cached document does not have.
string PolicyStore::ResolveIssuerKeys(const IssuerConfig &config, const string &kid) {
	if (config.jwks_uri.empty()) {
		return config.keys_json;
	}
	if (!catalog) {
		throw BinderException("acl_rewrite: token rejected: issuer \"%s\" reads its keys from \"%s\", which needs "
		                      "a policy catalog - the in-memory store cannot read documents",
		                      config.issuer, config.jwks_uri);
	}
	auto now =
	    std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
	auto refresh = JwksRefreshInterval();
	JwksEntry entry;
	{
		lock_guard<mutex> guard(lock);
		auto found = jwks_cache.find(config.issuer);
		// an issuer repointed at another location starts from nothing: keys read from the old one say
		// nothing about the new one, and waiting out the TTL is not what an operator repointing it means
		if (found != jwks_cache.end() && found->second.uri == config.jwks_uri) {
			entry = found->second;
		}
	}
	entry.uri = config.jwks_uri;
	bool expired = entry.keys_json.empty() || now - entry.fetched_at >= refresh;
	// a key that rotated in since the last read: worth one more read, but not once per token, so the
	// same floor as any other retry applies
	bool rotated = !expired && !JwksHasKid(entry.keys_json, kid);
	static constexpr int64_t RETRY_FLOOR_SECONDS = 10;
	if ((expired || rotated) && now - entry.tried_at >= (rotated ? RETRY_FLOOR_SECONDS : 0)) {
		string document, error;
		entry.tried_at = now;
		if (catalog->ReadText(config.jwks_uri, document, error)) {
			entry.keys_json = std::move(document);
			entry.fetched_at = now;
			entry.error.clear();
		} else {
			entry.error = std::move(error);
		}
		lock_guard<mutex> guard(lock);
		jwks_cache[config.issuer] = entry;
	}
	if (entry.keys_json.empty()) {
		throw BinderException("acl_rewrite: token rejected: the keys of issuer \"%s\" could not be read from "
		                      "\"%s\": %s",
		                      config.issuer, config.jwks_uri, entry.error);
	}
	// keys that can no longer be read are used for a bounded while and then stop being trusted: an
	// issuer that has been unreachable for a day says nothing about a key that may have been revoked
	auto max_stale = JwksMaxStale();
	if (!entry.error.empty() && (max_stale <= 0 || now - entry.fetched_at > max_stale)) {
		throw BinderException("acl_rewrite: token rejected: the keys of issuer \"%s\" were last read %lld seconds "
		                      "ago and \"%s\" is still unreadable (%s); acl_jwks_max_stale is %lld",
		                      config.issuer, static_cast<long long>(now - entry.fetched_at), config.jwks_uri,
		                      entry.error, static_cast<long long>(max_stale));
	}
	return entry.keys_json;
}

namespace {

void RequireCatalog(const unique_ptr<CatalogBackend> &catalog, const char *what) {
	if (!catalog) {
		throw BinderException("%s requires a policy catalog - run acl_use_db() first", what);
	}
}

} // namespace

void PolicyStore::CatalogCreate(const string &vcat, const string &comment) {
	RequireCatalog(catalog, "acl_create_catalog");
	catalog->Write({"DELETE FROM " + catalog->Tbl("catalogs") + " WHERE \"vcat\" = " + Lit(vcat),
	                "INSERT INTO " + catalog->Tbl("catalogs") + " VALUES (" + Lit(vcat) + ", " + Lit(comment) + ")"});
}

namespace {

//! The statements that (re)write one relation - shared by ADD and the transactional ALTER
vector<string> RelationStatements(CatalogBackend &catalog, const string &vcat, const string &vname, const string &form,
                                  const string &phys, const string &view_sql, const string &rls,
                                  const vector<std::pair<string, string>> &columns, const string &comment,
                                  const string &returns, const string &origin = string()) {
	vector<string> statements;
	statements.push_back("DELETE FROM " + catalog.Tbl("relations") + " WHERE \"vcat\" = " + Lit(vcat) +
	                     " AND \"vname\" = " + Lit(vname));
	statements.push_back("DELETE FROM " + catalog.Tbl("relation_columns") + " WHERE \"vcat\" = " + Lit(vcat) +
	                     " AND \"vname\" = " + Lit(vname));
	// a predicate is checked where it is written, not where it is used (spec 021): a predicate that
	// cannot bind against its own object is a mistake, and it only ever surfaced for whoever queried
	bool checked = false;
	if (!rls.empty()) {
		auto source = form == "view" ? "(" + view_sql + ")" : phys;
		auto error = catalog.PredicateError(source, rls, &checked);
		if (!error.empty()) {
			throw InvalidInputException("acl: the predicate of \"%s\" does not bind against it: %s", vname, error);
		}
	}
	// the comment is read by the caller BEFORE the delete above and carried through: a definition
	// change is not a reason to lose an operator's documentation
	statements.push_back("INSERT INTO " + catalog.Tbl("relations") +
	                     "(\"vcat\", \"vname\", \"form\", \"phys\", \"view_sql\", \"rls\", \"comment\", \"origin\","
	                     " \"rls_checked\")"
	                     " VALUES (" +
	                     Lit(vcat) + ", " + Lit(vname) + ", " + Lit(form) + ", " + Lit(phys) + ", " + Lit(view_sql) +
	                     ", " + Lit(rls) + ", " + (comment.empty() ? string("NULL") : Lit(comment)) + ", " +
	                     (origin.empty() ? string("NULL") : Lit(origin)) + ", " +
	                     (rls.empty() ? "NULL" : (checked ? "true" : "false")) + ")");
	idx_t pos = 0;
	for (auto &column : columns) {
		statements.push_back("INSERT INTO " + catalog.Tbl("relation_columns") + " VALUES (" + Lit(vcat) + ", " +
		                     Lit(vname) + ", " + std::to_string(pos++) + ", " + Lit(column.first) + ", " +
		                     Lit(column.second) + ")");
	}
	// the object's column schema (spec 010): a view has no physical row and no declared projection,
	// so bind its SQL once, here on the write path; anything else keeps the projected names
	vector<std::pair<string, string>> schema;
	bool derived = false;
	if (!returns.empty()) {
		schema = CatalogBackend::ParseDeclaration(returns); // declared: never probed
	} else if (form == "view") {
		derived = catalog.ProbeSchema(view_sql, false, {}, schema);
	} else if (form == "subquery" && !phys.empty() && !columns.empty()) {
		// A projection is what the role sees, and a computed or masked column (`total = amount * 2`,
		// `ssn = NULL`) has no physical column to read a type from - so bind the projection once, here
		// on the write path, exactly as a view's SQL is bound (spec 010). Without this the column is
		// readable but typeless, and metadata cannot describe it (spec 010 part 3).
		vector<string> items;
		for (auto &column : columns) {
			items.push_back(column.second.empty() ? column.first : column.second + " AS " + column.first);
		}
		derived = catalog.ProbeSchema("SELECT " + StringUtil::Join(items, ", ") + " FROM " + phys, false, {}, schema);
		if (!derived) {
			schema.clear();
			for (auto &column : columns) {
				schema.emplace_back(column.first, string()); // the probe could not bind: names only
			}
		}
	} else {
		for (auto &column : columns) {
			schema.emplace_back(column.first, string()); // type filled from the physical catalog on read
		}
	}
	for (auto &statement : catalog.ColumnSchemaStatements(vcat, vname, "relation", schema, derived)) {
		statements.push_back(statement);
	}
	return statements;
}

//! What a grant's projection actually produces, folded the way the resolver folds it (spec 026), as
//! the `grant_columns` rows for one grant. Shared by the write path, where a projection that cannot
//! bind is a mistake worth refusing, and by `acl_refresh_schema`, where it is only a fact that has
//! not become true yet (spec 027) - `strict` picks between the two.
using ReadFn = std::function<unique_ptr<MaterializedQueryResult>(const string &)>;

void GrantProjectionStatements(CatalogBackend &catalog, const ReadFn &read, const string &role, const string &vcat,
                               const string &vname, const string &columns, vector<string> &statements, bool strict) {
	auto clear = "DELETE FROM " + catalog.Tbl("grant_columns") + " WHERE \"role\" = " + Lit(role) +
	             " AND \"vcat\" = " + Lit(vcat) + " AND \"vname\" = " + Lit(vname);
	if (strict) {
		// the grant is being rewritten, so whatever an earlier projection produced is gone either way
		statements.push_back(clear);
	}
	if (columns.empty()) {
		return;
	}
	auto shape = read("SELECT \"form\", \"phys\", \"view_sql\" FROM " + catalog.Tbl("relations") +
	                  " WHERE \"vcat\" = " + Lit(vcat) + " AND \"vname\" = " + Lit(vname));
	if (shape->RowCount() == 0) {
		return;
	}
	auto text = [&](idx_t column) {
		auto value = shape->GetValue(column, 0);
		return value.IsNull() ? string() : value.ToString();
	};
	auto form = text(0);
	// What the role actually gets is the two levels folded together, the way the resolver folds them:
	// a grant's *expression* is evaluated over the physical row, while a bare name in it refers to the
	// object's own column - which a rename may have moved.
	string source = form == "view" ? "(" + text(2) + ")" : text(1);
	case_insensitive_map_t<string> own;
	if (form != "view") {
		auto rows = read("SELECT \"name\", \"expr\" FROM " + catalog.Tbl("relation_columns") +
		                 " WHERE \"vcat\" = " + Lit(vcat) + " AND \"vname\" = " + Lit(vname));
		for (idx_t i = 0; i < rows->RowCount(); i++) {
			own[rows->GetValue(0, i).ToString()] =
			    rows->GetValue(1, i).IsNull() ? string() : rows->GetValue(1, i).ToString();
		}
	}
	vector<std::pair<string, string>> derived;
	if (source.empty()) {
		return;
	}
	bool probed = false;
	auto error = catalog.ProjectionSchema(source, columns, own, derived, &probed);
	if (!error.empty() || !probed) {
		if (!strict) {
			return; // the object still cannot judge it; leave what an earlier probe found in place
		}
		if (!probed) {
			return; // accepted unprobed, exactly as spec 026 wrote it
		}
		throw InvalidInputException("acl: the projection of the grant on \"%s\" does not bind against it: %s", vname,
		                            error);
	}
	if (!strict) {
		statements.push_back(clear); // re-probed: replace the earlier rows rather than lose them
	}
	idx_t pos = 0;
	for (auto &column : derived) {
		statements.push_back("INSERT INTO " + catalog.Tbl("grant_columns") + " VALUES (" + Lit(role) + ", " +
		                     Lit(vcat) + ", " + Lit(vname) + ", " + std::to_string(pos++) + ", " + Lit(column.first) +
		                     ", " + Lit(column.second) + ")");
	}
}

} // namespace

namespace {

//! A virtual object may not take a metadata surface's name: the surface wins when the name is
//! written, so the object would be listed and unreachable (spec 010 part 3).
void RequireNotReserved(const string &vname) {
	if (MetadataSurfaceOf(vname)) {
		throw BinderException("acl admin: \"%s\" is a metadata surface, so it cannot name a virtual object - a "
		                      "principal's query resolves that name to the catalog listing",
		                      vname);
	}
}

} // namespace

void PolicyStore::CatalogAddRelation(const string &vcat, const string &vname, const string &form, const string &phys,
                                     const string &view_sql, const string &rls,
                                     const vector<std::pair<string, string>> &columns, const string &returns) {
	RequireCatalog(catalog, "acl_add_relation");
	RequireNotReserved(vname);
	catalog->WriteWithReads([&](const std::function<unique_ptr<MaterializedQueryResult>(const string &)> &read,
	                            vector<string> &statements) {
		auto existing = read("SELECT \"comment\" FROM " + catalog->Tbl("relations") + " WHERE \"vcat\" = " + Lit(vcat) +
		                     " AND \"vname\" = " + Lit(vname));
		string comment;
		if (existing->RowCount() > 0 && !existing->GetValue(0, 0).IsNull()) {
			comment = existing->GetValue(0, 0).ToString();
		}
		statements = RelationStatements(*catalog, vcat, vname, form, phys, view_sql, rls, columns, comment, returns);
	});
}

namespace {

//! "a=b" -> the two halves, trimmed; refuses anything else so a typo is not stored as a column name
std::pair<string, string> SplitPair(const string &text, const string &name) {
	auto eq = text.find('=');
	if (eq == string::npos) {
		throw InvalidInputException("acl: reference \"%s\": \"%s\" is not a column pair (expected from=to)", name,
		                            text);
	}
	auto left = text.substr(0, eq);
	auto right = text.substr(eq + 1);
	StringUtil::Trim(left);
	StringUtil::Trim(right);
	if (left.empty() || right.empty()) {
		throw InvalidInputException("acl: reference \"%s\": \"%s\" is not a column pair (expected from=to)", name,
		                            text);
	}
	return {left, right};
}

} // namespace

void PolicyStore::CatalogAddReference(const string &vcat, const string &name, const string &from_vname,
                                      const string &to_vname, const string &to_kind, const string &args,
                                      const string &pairs, const string &expr, const string &cardinality, bool optional,
                                      const string &join_method, const string &comment) {
	RequireCatalog(catalog, "acl_add_reference");
	RequireNotReserved(name);
	static const case_insensitive_set_t CARDINALITIES = {"many_to_one", "one_to_many", "one_to_one", "many_to_many"};
	if (!cardinality.empty() && !CARDINALITIES.count(cardinality)) {
		throw InvalidInputException("acl: reference \"%s\": unknown cardinality \"%s\" (expected many_to_one, "
		                            "one_to_many, one_to_one or many_to_many)",
		                            name, cardinality);
	}
	static const case_insensitive_set_t METHODS = {"asof", "positional"};
	if (!join_method.empty() && !METHODS.count(join_method)) {
		throw InvalidInputException("acl: reference \"%s\": unknown join method \"%s\" (expected asof or "
		                            "positional)",
		                            name, join_method);
	}
	if (!pairs.empty() && !expr.empty()) {
		throw InvalidInputException("acl: reference \"%s\" joins either by column pairs or by an expression, not "
		                            "both",
		                            name);
	}
	bool to_function = StringUtil::CIEquals(to_kind, "function");
	if (pairs.empty() && expr.empty() && args.empty()) {
		// a condition may be left out only when the arguments are the whole relationship: the function
		// is called with the row's values and its result is what the row relates to
		throw InvalidInputException("acl: reference \"%s\" states neither a join condition nor arguments", name);
	}
	if (!args.empty() && !to_function) {
		throw InvalidInputException("acl: reference \"%s\" substitutes arguments, which only a table function end "
		                            "takes",
		                            name);
	}
	catalog->WriteWithReads([&](const std::function<unique_ptr<MaterializedQueryResult>(const string &)> &read,
	                            vector<string> &statements) {
		// a reference between objects that do not exist describes nothing
		auto require_relation = [&](const string &end) {
			auto found = read("SELECT 1 FROM " + catalog->Tbl("relations") + " WHERE \"vcat\" = " + Lit(vcat) +
			                  " AND \"vname\" = " + Lit(end));
			if (found->RowCount() == 0) {
				throw InvalidInputException("acl: reference \"%s\": \"%s\" is not an object of \"%s\"", name, end,
				                            vcat);
			}
		};
		require_relation(from_vname);
		// The declared parameters of a table function end. Read, never bound: a template carries
		// acl_arg(n) markers and its result depends on the arguments, so binding it would prove
		// nothing the declaration does not already say (spec 010).
		vector<string> parameters;
		if (to_function) {
			auto found = read("SELECT \"params\" FROM " + catalog->Tbl("functions") + " WHERE \"vcat\" = " + Lit(vcat) +
			                  " AND \"vname\" = " + Lit(to_vname) + " AND \"kind\" = 'table'");
			if (found->RowCount() == 0) {
				throw InvalidInputException("acl: reference \"%s\": \"%s\" is not a table function of \"%s\"", name,
				                            to_vname, vcat);
			}
			if (!found->GetValue(0, 0).IsNull()) {
				for (auto &parameter : CatalogBackend::ParseDeclaration(found->GetValue(0, 0).ToString())) {
					if (!parameter.first.empty()) {
						parameters.push_back(parameter.first);
					}
				}
			}
		} else {
			require_relation(to_vname);
		}
		// pos, side, column, parameter ("" unless the column is substituted into an argument)
		vector<std::tuple<idx_t, string, string, string>> columns;
		idx_t pos = 0;
		// An argument substitution names a column of the source row, so it is a `from` column for
		// every purpose - existence, visibility - and carries the parameter it feeds alongside.
		for (auto &item : SplitTopLevel(args, ',')) {
			auto trimmed = item;
			StringUtil::Trim(trimmed);
			if (trimmed.empty()) {
				continue;
			}
			auto arrow = trimmed.find("=>");
			if (arrow == string::npos) {
				throw InvalidInputException("acl: reference \"%s\": \"%s\" is not an argument (expected "
				                            "parameter => column)",
				                            name, trimmed);
			}
			auto parameter = trimmed.substr(0, arrow);
			auto column = trimmed.substr(arrow + 2);
			StringUtil::Trim(parameter);
			StringUtil::Trim(column);
			if (parameter.empty() || column.empty()) {
				throw InvalidInputException("acl: reference \"%s\": \"%s\" is not an argument (expected "
				                            "parameter => column)",
				                            name, trimmed);
			}
			columns.emplace_back(pos++, "from", column, parameter);
		}
		// the join condition: column pairs read from -> to, or a qualified expression
		if (!pairs.empty()) {
			for (auto &item : SplitTopLevel(pairs, ',')) {
				auto trimmed = item;
				StringUtil::Trim(trimmed);
				if (trimmed.empty()) {
					continue;
				}
				auto pair = SplitPair(trimmed, name);
				columns.emplace_back(pos, "from", pair.first, string());
				columns.emplace_back(pos, "to", pair.second, string());
				pos++;
			}
		} else if (!expr.empty()) {
			ParserOptions options;
			auto from_tail = SplitTopLevel(from_vname, '.').back();
			auto to_tail = SplitTopLevel(to_vname, '.').back();
			for (auto &ref : QualifiedColumnRefs(expr, options)) {
				string side;
				if (StringUtil::CIEquals(ref.first, from_tail)) {
					side = "from";
				} else if (StringUtil::CIEquals(ref.first, to_tail)) {
					side = "to";
				} else {
					throw InvalidInputException("acl: reference \"%s\": \"%s\" names neither end (expected \"%s\" "
					                            "or \"%s\")",
					                            name, ref.first, from_tail, to_tail);
				}
				columns.emplace_back(pos++, side, ref.second, string());
			}
		}
		if (columns.empty()) {
			throw InvalidInputException("acl: reference \"%s\" names no columns", name);
		}
		// A name the end does not have is a mistake, and it would make the reference invisible to
		// everyone once visibility is checked. The names are the *virtual* ones - what a role sees -
		// so they are looked for where the catalog keeps those: a declared projection first (which is
		// also where a rename lives), then a probed schema, and finally the physical table itself for
		// a plain alias, whose columns the catalog does not store. If none of the three can answer -
		// the source is not attached - the reference is accepted, as spec 021 does for a predicate.
		for (auto &column : columns) {
			bool from_side = std::get<1>(column) == "from";
			auto &end = from_side ? from_vname : to_vname;
			auto &column_name = std::get<2>(column);
			auto &parameter = std::get<3>(column);
			if (!parameter.empty()) {
				// the parameter side of an argument: the declared signature is the whole truth, and a
				// function that declares none cannot be judged at all
				if (!parameters.empty()) {
					bool declared = false;
					for (auto &candidate : parameters) {
						if (StringUtil::CIEquals(candidate, parameter)) {
							declared = true;
							break;
						}
					}
					if (!declared) {
						throw InvalidInputException("acl: reference \"%s\": \"%s\" has no parameter \"%s\" "
						                            "(declared: %s)",
						                            name, to_vname, parameter, StringUtil::Join(parameters, ", "));
					}
				}
			}
			auto missing = [&]() {
				throw InvalidInputException("acl: reference \"%s\": \"%s\" has no column \"%s\"", name, end,
				                            column_name);
			};
			if (!from_side && to_function) {
				// the far side of the condition names columns of the function's *result*, which the
				// catalog stores whether they were declared or probed
				auto known = read("SELECT count(*) FILTER (WHERE \"name\" = " + Lit(column_name) + "), count(*) FROM " +
				                  catalog->Tbl("object_columns") + " WHERE \"vcat\" = " + Lit(vcat) +
				                  " AND \"kind\" = 'table' AND \"vname\" = " + Lit(to_vname));
				if (known->GetValue(1, 0).GetValue<int64_t>() > 0 && known->GetValue(0, 0).GetValue<int64_t>() == 0) {
					missing();
				}
				continue;
			}
			auto declared = read("SELECT count(*) FILTER (WHERE \"name\" = " + Lit(column_name) + "), count(*) FROM " +
			                     catalog->Tbl("relation_columns") + " WHERE \"vcat\" = " + Lit(vcat) +
			                     " AND \"vname\" = " + Lit(end));
			if (declared->GetValue(1, 0).GetValue<int64_t>() > 0) {
				if (declared->GetValue(0, 0).GetValue<int64_t>() == 0) {
					missing();
				}
				continue;
			}
			auto probed = read("SELECT count(*) FILTER (WHERE \"name\" = " + Lit(column_name) + "), count(*) FROM " +
			                   catalog->Tbl("object_columns") + " WHERE \"vcat\" = " + Lit(vcat) +
			                   " AND \"kind\" = 'relation' AND \"vname\" = " + Lit(end));
			if (probed->GetValue(1, 0).GetValue<int64_t>() > 0) {
				if (probed->GetValue(0, 0).GetValue<int64_t>() == 0) {
					missing();
				}
				continue;
			}
			auto phys = read("SELECT \"phys\" FROM " + catalog->Tbl("relations") + " WHERE \"vcat\" = " + Lit(vcat) +
			                 " AND \"vname\" = " + Lit(end));
			if (phys->RowCount() == 0 || phys->GetValue(0, 0).IsNull()) {
				continue;
			}
			auto source = phys->GetValue(0, 0).ToString();
			if (!catalog->ColumnBinds(source, column_name)) {
				missing();
			}
		}
		statements.push_back("DELETE FROM " + catalog->Tbl("reference_columns") + " WHERE \"vcat\" = " + Lit(vcat) +
		                     " AND \"name\" = " + Lit(name));
		statements.push_back("DELETE FROM " + catalog->Tbl("references") + " WHERE \"vcat\" = " + Lit(vcat) +
		                     " AND \"name\" = " + Lit(name));
		statements.push_back(
		    "INSERT INTO " + catalog->Tbl("references") + " VALUES (" + Lit(vcat) + ", " + Lit(name) + ", " +
		    Lit(from_vname) + ", " + Lit(to_vname) + ", " + Lit(to_function ? "function" : "relation") + ", " +
		    (expr.empty() ? string("NULL") : Lit(expr)) + ", " +
		    (cardinality.empty() ? string("NULL") : Lit(cardinality)) + ", " + (optional ? "true" : "false") + ", " +
		    (join_method.empty() ? string("NULL") : Lit(join_method)) + ", " +
		    (comment.empty() ? string("NULL") : Lit(comment)) + ")");
		for (auto &column : columns) {
			statements.push_back("INSERT INTO " + catalog->Tbl("reference_columns") + " VALUES (" + Lit(vcat) + ", " +
			                     Lit(name) + ", " + std::to_string(std::get<0>(column)) + ", " +
			                     Lit(std::get<1>(column)) + ", " + Lit(std::get<2>(column)) + ", " +
			                     (std::get<3>(column).empty() ? string("NULL") : Lit(std::get<3>(column))) + ")");
		}
	});
}

void PolicyStore::CatalogDropReference(const string &vcat, const string &name) {
	RequireCatalog(catalog, "acl_drop_reference");
	catalog->Write({"DELETE FROM " + catalog->Tbl("reference_columns") + " WHERE \"vcat\" = " + Lit(vcat) +
	                    " AND \"name\" = " + Lit(name),
	                "DELETE FROM " + catalog->Tbl("references") + " WHERE \"vcat\" = " + Lit(vcat) +
	                    " AND \"name\" = " + Lit(name)});
}

void PolicyStore::CatalogAddSchemaAlias(const string &vcat, const string &alias_path, const string &phys_path,
                                        const string &origin) {
	RequireCatalog(catalog, "acl_add_schema_alias");
	// a schema is one row either way (spec 014): with a physical path it is a live alias, without one
	// it is a schema whose content is the catalog's own records. The comment survives a redefinition.
	catalog->WriteWithReads([&](const std::function<unique_ptr<MaterializedQueryResult>(const string &)> &read,
	                            vector<string> &statements) {
		auto where = " WHERE \"vcat\" = " + Lit(vcat) + " AND \"path\" = " + Lit(alias_path);
		auto current = read("SELECT \"comment\" FROM " + catalog->Tbl("schemas") + where);
		string comment = "NULL";
		if (current->RowCount() > 0 && !current->GetValue(0, 0).IsNull()) {
			comment = Lit(current->GetValue(0, 0).ToString());
		}
		statements.push_back("DELETE FROM " + catalog->Tbl("schemas") + where);
		statements.push_back("INSERT INTO " + catalog->Tbl("schemas") +
		                     "(\"vcat\", \"path\", \"phys_path\", \"comment\", \"origin\") VALUES (" + Lit(vcat) +
		                     ", " + Lit(alias_path) + ", " + (phys_path.empty() ? "NULL" : Lit(phys_path)) + ", " +
		                     comment + ", " + (origin.empty() ? "NULL" : Lit(origin)) + ")");
		// the legacy table is kept in step for one version, so a rollback still resolves
		statements.push_back("DELETE FROM " + catalog->Tbl("schema_aliases") + " WHERE \"vcat\" = " + Lit(vcat) +
		                     " AND \"alias_path\" = " + Lit(alias_path));
		if (!phys_path.empty()) {
			statements.push_back("INSERT INTO " + catalog->Tbl("schema_aliases") + " VALUES (" + Lit(vcat) + ", " +
			                     Lit(alias_path) + ", " + Lit(phys_path) + ")");
		}
	});
	// a schema created under a granted parent inherits its capabilities at creation (spec 015)
	CatalogRematerializeSchemaCaps(vcat, alias_path);
}

namespace {

//! `db.schema` -> the two parts duckdb's catalog views are keyed by
void SplitPhysSchema(const string &phys_path, string &database, string &schema) {
	auto dot = phys_path.find('.');
	if (dot == string::npos) {
		throw BinderException("acl admin: \"%s\" must be written as <database>.<schema>", phys_path);
	}
	database = phys_path.substr(0, dot);
	schema = phys_path.substr(dot + 1);
}

//! What the source holds right now. Read on the write path only - a principal's query never triggers
//! it - the same way the schema probe of spec 010 reads the physical catalog.
vector<string> PhysicalObjects(acl_detail::CatalogBackend &catalog, const string &phys_path) {
	string database, schema;
	SplitPhysSchema(phys_path, database, schema);
	// an empty result is ambiguous - an empty schema, or one that is not there (or a database nobody
	// attached). Expanding a source that does not exist would leave a schema that can never resolve
	// anything, so ask first and fail closed with the reason.
	auto known = catalog.Query("SELECT 1 FROM duckdb_schemas() WHERE database_name = " + Lit(database) +
	                           " AND schema_name = " + Lit(schema));
	if (known->RowCount() == 0) {
		throw BinderException("acl admin: physical schema \"%s\" does not exist (is its database attached?)",
		                      phys_path);
	}
	auto listing =
	    catalog.Query("SELECT table_name AS name FROM duckdb_tables() WHERE database_name = " + Lit(database) +
	                  " AND schema_name = " + Lit(schema) +
	                  " UNION SELECT view_name FROM duckdb_views() WHERE database_name = " + Lit(database) +
	                  " AND schema_name = " + Lit(schema) + " AND NOT internal ORDER BY 1");
	vector<string> names;
	for (idx_t row = 0; row < listing->RowCount(); row++) {
		names.push_back(listing->GetValue(0, row).ToString());
	}
	return names;
}

} // namespace

bool PolicyStore::PhysicalObjectExists(const string &phys) {
	RequireCatalog(catalog, "acl catalog");
	auto dot = phys.rfind('.');
	if (dot == string::npos) {
		return false;
	}
	string database, schema;
	SplitPhysSchema(phys.substr(0, dot), database, schema);
	auto name = phys.substr(dot + 1);
	return catalog
	           ->Query("SELECT 1 FROM duckdb_tables() WHERE database_name = " + Lit(database) +
	                   " AND schema_name = " + Lit(schema) + " AND table_name = " + Lit(name) +
	                   " UNION ALL SELECT 1 FROM duckdb_views() WHERE database_name = " + Lit(database) +
	                   " AND schema_name = " + Lit(schema) + " AND view_name = " + Lit(name))
	           ->RowCount() > 0;
}

void PolicyStore::CatalogRegisterView(const string &vcat, const string &vname, const string &body) {
	RequireCatalog(catalog, "acl_register_view");
	RequireNotReserved(vname);
	// fixed shape, like the record of a created table: a body and nothing else to choose
	catalog->WriteWithReads([&](const std::function<unique_ptr<MaterializedQueryResult>(const string &)> &read,
	                            vector<string> &statements) {
		statements = RelationStatements(*catalog, vcat, vname, "view", "", body, "", {}, "", "");
	});
}

void PolicyStore::CatalogRegisterCreated(const string &vcat, const string &vname, const string &phys,
                                         const string &origin) {
	RequireCatalog(catalog, "acl_register_created");
	// fixed shape: an alias-form record of the object just created, stamped with the schema's origin
	// so REFRESH and PRUNE own it like the rest of the expansion
	catalog->WriteWithReads([&](const std::function<unique_ptr<MaterializedQueryResult>(const string &)> &read,
	                            vector<string> &statements) {
		statements = RelationStatements(*catalog, vcat, vname, "alias", phys, "", "", {}, "", "", origin);
		// creating a name that was dropped on purpose earlier makes it current again
		auto dot = vname.rfind('.');
		if (dot != string::npos) {
			statements.push_back("DELETE FROM " + catalog->Tbl("schema_dropped") + " WHERE \"vcat\" = " + Lit(vcat) +
			                     " AND \"path\" = " + Lit(vname.substr(0, dot)) +
			                     " AND \"name\" = " + Lit(vname.substr(dot + 1)));
		}
	});
}

IntrospectionRows PolicyStore::Introspect(const string &listing) {
	// what an operator may read of the policy source itself. The issuer's keys are deliberately absent:
	// a listing describes the policy, and an HS256 key is a shared secret, not metadata.
	static const case_insensitive_map_t<string> LISTINGS = {
	    {"catalogs", "SELECT \"vcat\", \"comment\" FROM %s"},
	    {"schemas", "SELECT \"vcat\", \"path\", \"phys_path\", \"origin\", \"comment\" FROM %s"},
	    {"relations", "SELECT \"vcat\", \"vname\", \"form\", \"phys\", \"view_sql\", \"rls\", \"rls_checked\","
	                  " \"origin\", \"comment\" FROM %s"},
	    {"relation_columns", "SELECT \"vcat\", \"vname\", \"pos\", \"name\", \"expr\" FROM %s"},
	    {"object_columns", "SELECT \"vcat\", \"vname\", \"kind\", \"pos\", \"name\", \"type\", \"comment\","
	                       " \"derived\" FROM %s"},
	    {"functions", "SELECT \"vcat\", \"vname\", \"kind\", \"form\", \"target\", \"template\", \"params\","
	                  " \"comment\" FROM %s"},
	    {"references", "SELECT \"vcat\", \"name\", \"from_vname\", \"to_vname\", \"to_kind\", \"expr\","
	                   " \"cardinality\", \"optional\", \"join_method\", \"comment\" FROM %s"},
	    {"reference_columns", "SELECT \"vcat\", \"name\", \"pos\", \"side\", \"column\", \"param\" FROM %s"},
	    {"roles", "SELECT \"role\", \"comment\" FROM %s"},
	    {"role_claims", "SELECT \"role\", \"claim\", \"value\" FROM %s"},
	    {"grants", "SELECT \"role\", \"vcat\", \"is_main\", \"caps\", \"rls\", \"rls_checked\", \"columns\""
	               " FROM %s"},
	    {"schema_grants", "SELECT \"role\", \"vcat\", \"schema_path\", \"caps\", \"inherited\", \"into\","
	                      " \"virtual_only\", \"comment\" FROM %s"},
	    {"object_grants", "SELECT \"role\", \"vcat\", \"vname\", \"caps\", \"rls\", \"rls_checked\", \"columns\""
	                      " FROM %s"},
	    {"grant_columns", "SELECT \"role\", \"vcat\", \"vname\", \"pos\", \"name\", \"type\" FROM %s"},
	    {"admins", "SELECT \"role\", \"scope\", \"vcat\" FROM %s"},
	    {"issuers", "SELECT \"issuer\", \"audiences\", \"algs\", \"role_claim\", \"claim_map\", \"jwks_uri\""
	                " FROM %s"},
	    {"role_mappings", "SELECT \"issuer\", \"source\", \"external_value\", \"role\" FROM %s"},
	    {"function_gate", "SELECT \"role\", \"name\", \"kind\", \"allowed\" FROM %s"},
	};
	static const case_insensitive_map_t<string> TABLES = {
	    {"catalogs", "catalogs"},
	    {"schemas", "schemas"},
	    {"relations", "relations"},
	    {"relation_columns", "relation_columns"},
	    {"object_columns", "object_columns"},
	    {"functions", "functions"},
	    {"references", "references"},
	    {"reference_columns", "reference_columns"},
	    {"roles", "roles"},
	    {"role_claims", "role_claims"},
	    {"grants", "role_catalogs"},
	    {"schema_grants", "role_schemas"},
	    {"object_grants", "role_object_caps"},
	    {"grant_columns", "grant_columns"},
	    {"admins", "admins"},
	    {"issuers", "issuers"},
	    {"role_mappings", "role_mappings"},
	    {"function_gate", "function_gate"},
	};
	IntrospectionRows out;
	if (StringUtil::CIEquals(listing, "status")) {
		out.names = {"backend", "schema_version", "policy_version", "version_check_interval", "enumerates"};
		out.types = {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::BIGINT,
		             LogicalType::BOOLEAN};
		string backend = catalog ? (catalog->FunctionMode() ? "functions" : "catalog") : "memory";
		Value schema_version, policy_version;
		int64_t interval = 0;
		if (catalog && !catalog->FunctionMode()) {
			schema_version = Value(catalog->MetaValue("schema_version"));
			policy_version = Value(catalog->MetaValue("policy_version"));
			interval = catalog->SettingInt64("acl_version_check_interval", 1000);
		}
		out.rows.push_back({Value(backend), schema_version, policy_version, Value::BIGINT(interval),
		                    Value::BOOLEAN(catalog && !catalog->FunctionMode())});
		return out;
	}
	auto entry = LISTINGS.find(listing);
	if (entry == LISTINGS.end()) {
		throw BinderException("acl: there is no listing called \"%s\"", listing);
	}
	if (!catalog) {
		throw BinderException("acl: no policy source is active, so there is nothing to list - run acl_use_db() or "
		                      "acl_use_functions() first (the in-memory store is a dev stub and does not enumerate)");
	}
	if (catalog->FunctionMode()) {
		throw BinderException("acl: this policy source does not expose enumeration, so \"%s\" cannot be listed - "
		                      "the driver contract is keyed lookup, and an empty answer would read as \"nothing is "
		                      "configured\"",
		                      listing);
	}
	auto table = TABLES.find(listing)->second;
	auto result = catalog->Query(StringUtil::Replace(entry->second, "%s", catalog->Tbl(table.c_str())));
	for (auto &name : result->GetNames()) {
		out.names.push_back(name.GetIdentifierName());
	}
	out.types = result->GetTypes();
	for (idx_t row = 0; row < result->RowCount(); row++) {
		vector<Value> values;
		for (idx_t col = 0; col < result->ColumnCount(); col++) {
			values.push_back(result->GetValue(col, row));
		}
		out.rows.push_back(std::move(values));
	}
	return out;
}

bool PolicyStore::MetadataListing(const Principal &principal, const string &surface, string &sql) {
	if (!catalog) {
		return false; // the memory store has no catalog to list; the surface stays denied
	}
	sql = catalog->MetadataListingSql(principal, surface);
	return true;
}

bool PolicyStore::ResolveDdlTarget(const Principal &principal, const string &vname, const string &capability,
                                   DdlTarget &out) {
	if (!catalog) {
		return false; // the memory store has no schema grants (dev/tests)
	}
	return catalog->DdlTarget(principal, vname, capability, out);
}

void PolicyStore::CatalogGrantSchema(const string &role, const string &vcat, const string &path,
                                     const string &caps_json, const string &comment, const string &into,
                                     bool virtual_only) {
	RequireCatalog(catalog, "acl_grant_schema");
	if (acl_detail::ParseCaps(caps_json).count("manage")) {
		throw BinderException("acl admin: `manage` is granted per catalog, not per schema - administering the ACL is "
		                      "catalog-scoped (spec 009)");
	}
	if (!CatalogObjectExists(vcat, path, "schema")) {
		throw BinderException("acl admin: schema \"%s.%s\" does not exist", vcat, path);
	}
	if (!into.empty()) {
		// a target checked when granted, not when a CREATE first lands on it (spec 016)
		string database, schema;
		SplitPhysSchema(into, database, schema);
		if (catalog
		        ->Query("SELECT 1 FROM duckdb_schemas() WHERE database_name = " + Lit(database) +
		                " AND schema_name = " + Lit(schema))
		        ->RowCount() == 0) {
			throw BinderException("acl admin: physical schema \"%s\" does not exist (is its database attached?)", into);
		}
	}
	if (virtual_only && !into.empty()) {
		throw BinderException("acl admin: INTO and VIRTUAL ONLY are opposites - one names where the role creates, "
		                      "the other says it never does");
	}
	catalog->Write({"DELETE FROM " + catalog->Tbl("role_schemas") + " WHERE \"role\" = " + Lit(role) +
	                    " AND \"vcat\" = " + Lit(vcat) + " AND \"schema_path\" = " + Lit(path),
	                "INSERT INTO " + catalog->Tbl("role_schemas") +
	                    "(\"role\", \"vcat\", \"schema_path\", \"caps\", \"inherited\", \"comment\", \"into\","
	                    " \"virtual_only\") VALUES (" +
	                    Lit(role) + ", " + Lit(vcat) + ", " + Lit(path) + ", " + Lit(caps_json) + ", false, " +
	                    (comment.empty() ? "NULL" : Lit(comment)) + ", " + (into.empty() ? "NULL" : Lit(into)) + ", " +
	                    (virtual_only ? "true" : "false") + ")"});
	CatalogRematerializeSchemaCaps(vcat, path);
}

void PolicyStore::CatalogRevokeSchema(const string &role, const string &vcat, const string &path) {
	RequireCatalog(catalog, "acl_revoke_schema");
	catalog->Write({"DELETE FROM " + catalog->Tbl("role_schemas") + " WHERE \"role\" = " + Lit(role) +
	                " AND \"vcat\" = " + Lit(vcat) + " AND \"schema_path\" = " + Lit(path)});
	// the subtree now inherits from whatever ancestor still states capabilities - or from nothing
	CatalogRematerializeSchemaCaps(vcat, path);
}

void PolicyStore::CatalogRematerializeSchemaCaps(const string &vcat, const string &path) {
	RequireCatalog(catalog, "acl_rematerialize_schema_caps");
	// One idempotent operation, many callers: granting, revoking, schema DDL and drift repair all
	// reduce to "rebuild this subtree from the nearest ancestor that states capabilities" (spec 015).
	catalog->WriteWithReads([&](const std::function<unique_ptr<MaterializedQueryResult>(const string &)> &read,
	                            vector<string> &statements) {
		auto prefix = path.empty() ? string() : path + ".";
		auto in_subtree = [&](const string &column) {
			return path.empty() ? string("true")
			                    : "(" + column + " = " + Lit(path) + " OR substr(" + column + ", 1, " +
			                          std::to_string(prefix.size()) + ") = " + Lit(prefix) + ")";
		};
		auto schemas = read("SELECT \"path\" FROM " + catalog->Tbl("schemas") + " WHERE \"vcat\" = " + Lit(vcat) +
		                    " AND " + in_subtree("\"path\"") + " ORDER BY length(\"path\")");
		// every explicit grant of the catalog, per role, longest path first: the first ancestor in
		// that order is the nearest one, which is also what makes an explicit row stop the cascade
		auto rows = read("SELECT \"role\", \"schema_path\", \"caps\", \"into\", \"virtual_only\" FROM " +
		                 catalog->Tbl("role_schemas") + " WHERE \"vcat\" = " + Lit(vcat) +
		                 " AND NOT \"inherited\""
		                 " ORDER BY \"role\", length(\"schema_path\") DESC");
		struct SchemaGrant {
			string path;
			string caps;
			string into;
			bool virtual_only;
		};
		vector<string> roles;
		case_insensitive_map_t<vector<SchemaGrant>> granted;
		for (idx_t row = 0; row < rows->RowCount(); row++) {
			auto role = rows->GetValue(0, row).ToString();
			auto caps = rows->GetValue(2, row);
			auto into = rows->GetValue(3, row);
			auto only = rows->GetValue(4, row);
			if (!granted.count(role)) {
				roles.push_back(role);
			}
			granted[role].push_back({rows->GetValue(1, row).ToString(), caps.IsNull() ? string() : caps.ToString(),
			                         into.IsNull() ? string() : into.ToString(),
			                         !only.IsNull() && only.GetValue<bool>()});
		}
		// drop what was inherited inside the subtree: it is about to be recomputed
		statements.push_back("DELETE FROM " + catalog->Tbl("role_schemas") + " WHERE \"vcat\" = " + Lit(vcat) +
		                     " AND \"inherited\" AND " + in_subtree("\"schema_path\""));
		for (idx_t row = 0; row < schemas->RowCount(); row++) {
			auto schema_path = schemas->GetValue(0, row).ToString();
			for (auto &role : roles) {
				for (auto &grant : granted[role]) {
					if (grant.path == schema_path) {
						break; // the schema states its own capabilities for this role
					}
					auto ancestor = grant.path + ".";
					if (schema_path.size() <= ancestor.size() ||
					    schema_path.compare(0, ancestor.size(), ancestor) != 0) {
						continue; // not an ancestor of this schema
					}
					statements.push_back("INSERT INTO " + catalog->Tbl("role_schemas") +
					                     "(\"role\", \"vcat\", \"schema_path\", \"caps\", \"inherited\","
					                     " \"into\", \"virtual_only\") VALUES (" +
					                     Lit(role) + ", " + Lit(vcat) + ", " + Lit(schema_path) + ", " +
					                     (grant.caps.empty() ? "NULL" : Lit(grant.caps)) + ", true, " +
					                     (grant.into.empty() ? "NULL" : Lit(grant.into)) + ", " +
					                     (grant.virtual_only ? "true" : "false") + ")");
					break; // nearest ancestor found for this role; the next role is independent
				}
			}
		}
	});
}

void PolicyStore::CatalogExpandSchema(const string &vcat, const string &path, const string &phys_path) {
	RequireCatalog(catalog, "acl_expand_schema");
	auto names = PhysicalObjects(*catalog, phys_path);
	// the schema itself carries no physical path: what is visible inside it are the records below,
	// each of which can then be altered, dropped or granted on its own
	CatalogAddSchemaAlias(vcat, path, "", phys_path);
	catalog->WriteWithReads([&](const std::function<unique_ptr<MaterializedQueryResult>(const string &)> &read,
	                            vector<string> &statements) {
		for (auto &name : names) {
			auto vname = path + "." + name;
			auto exists = read("SELECT 1 FROM " + catalog->Tbl("relations") + " WHERE \"vcat\" = " + Lit(vcat) +
			                   " AND \"vname\" = " + Lit(vname));
			if (exists->RowCount() > 0) {
				continue; // an admin already registered this name: an expansion never overwrites
			}
			for (auto &statement : RelationStatements(*catalog, vcat, vname, "alias", phys_path + "." + name, "", "",
			                                          {}, "", "", phys_path)) {
				statements.push_back(statement);
			}
		}
		// re-expanding forgets earlier deliberate drops: the admin asked for the source as it is now
		statements.push_back("DELETE FROM " + catalog->Tbl("schema_dropped") + " WHERE \"vcat\" = " + Lit(vcat) +
		                     " AND \"path\" = " + Lit(path));
	});
	CatalogRematerializeSchemaCaps(vcat, path);
}

int64_t PolicyStore::CatalogRefreshSchemaObjects(const string &vcat, const string &path, bool prune) {
	RequireCatalog(catalog, "acl_refresh_schema_objects");
	auto source = catalog->Query("SELECT \"origin\" FROM " + catalog->Tbl("schemas") +
	                             " WHERE \"vcat\" = " + Lit(vcat) + " AND \"path\" = " + Lit(path));
	if (source->RowCount() == 0) {
		throw BinderException("acl admin: schema \"%s.%s\" does not exist", vcat, path);
	}
	auto origin_value = source->GetValue(0, 0);
	if (origin_value.IsNull()) {
		throw BinderException("acl admin: schema \"%s.%s\" is a live alias, so it has nothing to refresh - it "
		                      "already shows what the source holds",
		                      vcat, path);
	}
	auto origin = origin_value.ToString();
	auto names = PhysicalObjects(*catalog, origin);
	int64_t changed = 0;
	catalog->WriteWithReads([&](const std::function<unique_ptr<MaterializedQueryResult>(const string &)> &read,
	                            vector<string> &statements) {
		changed = 0;
		for (auto &name : names) {
			auto vname = path + "." + name;
			auto known = read("SELECT 1 FROM " + catalog->Tbl("relations") + " WHERE \"vcat\" = " + Lit(vcat) +
			                  " AND \"vname\" = " + Lit(vname) + " UNION ALL SELECT 1 FROM " +
			                  catalog->Tbl("schema_dropped") + " WHERE \"vcat\" = " + Lit(vcat) +
			                  " AND \"path\" = " + Lit(path) + " AND \"name\" = " + Lit(name));
			if (known->RowCount() > 0) {
				continue; // already registered, or dropped on purpose and not to be resurrected
			}
			for (auto &statement :
			     RelationStatements(*catalog, vcat, vname, "alias", origin + "." + name, "", "", {}, "", "", origin)) {
				statements.push_back(statement);
			}
			changed++;
		}
		if (!prune) {
			return;
		}
		// only records this expansion produced are pruned: what an admin registered by hand is theirs
		auto stale = read("SELECT \"vname\" FROM " + catalog->Tbl("relations") + " WHERE \"vcat\" = " + Lit(vcat) +
		                  " AND \"origin\" = " + Lit(origin) + " AND substr(\"vname\", 1, " +
		                  std::to_string(path.size() + 1) + ") = " + Lit(path + "."));
		for (idx_t row = 0; row < stale->RowCount(); row++) {
			auto vname = stale->GetValue(0, row).ToString();
			auto name = vname.substr(path.size() + 1);
			if (std::find(names.begin(), names.end(), name) != names.end()) {
				continue;
			}
			for (auto table : {"relations", "relation_columns", "role_object_caps"}) {
				statements.push_back("DELETE FROM " + catalog->Tbl(table) + " WHERE \"vcat\" = " + Lit(vcat) +
				                     " AND \"vname\" = " + Lit(vname));
			}
			statements.push_back("DELETE FROM " + catalog->Tbl("object_columns") + " WHERE \"vcat\" = " + Lit(vcat) +
			                     " AND \"vname\" = " + Lit(vname) + " AND \"kind\" = 'relation'");
			changed++;
		}
	});
	return changed;
}

void PolicyStore::CatalogAddFunction(const string &vcat, const string &vname, const string &kind, const string &form,
                                     const string &target, const string &template_sql, const string &params,
                                     const string &returns) {
	RequireCatalog(catalog, "acl_add_function");
	RequireNotReserved(vname);
	vector<string> statements = {"DELETE FROM " + catalog->Tbl("functions") + " WHERE \"vcat\" = " + Lit(vcat) +
	                                 " AND \"vname\" = " + Lit(vname) + " AND \"kind\" = " + Lit(kind),
	                             "DELETE FROM " + catalog->Tbl("object_columns") + " WHERE \"vcat\" = " + Lit(vcat) +
	                                 " AND \"vname\" = " + Lit(vname) + " AND \"kind\" = " + Lit(kind),
	                             "INSERT INTO " + catalog->Tbl("functions") + " VALUES (" + Lit(vcat) + ", " +
	                                 Lit(vname) + ", " + Lit(kind) + ", " + Lit(form) + ", " + Lit(target) + ", " +
	                                 Lit(template_sql) + ", NULL, " + Lit(params) + ")"};
	// A declared result is the truth and needs no probe: an argument-dependent template cannot be
	// typed from NULLs anyway, and binding admin SQL at write time touches the sources.
	vector<std::pair<string, string>> schema;
	bool derived = false;
	if (!returns.empty()) {
		schema = CatalogBackend::ParseDeclaration(returns);
		if (kind == "scalar" && schema.size() == 1 && schema[0].first.empty()) {
			schema[0].first = "value"; // a scalar declares only its type
		}
	} else if (form == "macro") {
		derived = catalog->ProbeSchema(template_sql, kind == "scalar", CatalogBackend::DeclaredTypes(params), schema);
	}
	for (auto &statement : catalog->ColumnSchemaStatements(vcat, vname, kind, schema, derived)) {
		statements.push_back(statement);
	}
	catalog->Write(statements);
}

void PolicyStore::CatalogGrant(const string &role, const string &vcat, const string &caps_json, bool is_main,
                               const string &rls, const string &columns) {
	RequireCatalog(catalog, "acl_grant_catalog");
	if (vcat.empty()) {
		throw BinderException("acl admin: a grant needs a catalog name");
	}
	acl_detail::ParseCaps(caps_json); // validate before persisting
	// the verdict is read on the connection that writes it (spec 027), so what it judges the predicate
	// against is the catalog this grant commits into
	catalog->WriteWithReads([&](const std::function<unique_ptr<MaterializedQueryResult>(const string &)> &read,
	                            vector<string> &statements) {
		auto checked = catalog->CatalogPredicateChecked(read, vcat, rls);
		statements.push_back("DELETE FROM " + catalog->Tbl("role_catalogs") + " WHERE \"role\" = " + Lit(role) +
		                     " AND \"vcat\" = " + Lit(vcat));
		statements.push_back("INSERT INTO " + catalog->Tbl("role_catalogs") +
		                     "(\"role\", \"vcat\", \"is_main\", \"caps\", \"rls\", \"columns\", \"rls_checked\")"
		                     " VALUES (" +
		                     Lit(role) + ", " + Lit(vcat) + ", " + (is_main ? "true" : "false") + ", " +
		                     Lit(caps_json) + ", " + Lit(rls) + ", " + Lit(columns) + ", " +
		                     (rls.empty() ? "NULL" : (checked ? "true" : "false")) + ")");
	});
}

void PolicyStore::CatalogRevoke(const string &role, const string &vcat) {
	RequireCatalog(catalog, "acl_revoke_catalog");
	catalog->Write({"DELETE FROM " + catalog->Tbl("role_catalogs") + " WHERE \"role\" = " + Lit(role) +
	                    " AND \"vcat\" = " + Lit(vcat),
	                "DELETE FROM " + catalog->Tbl("role_object_caps") + " WHERE \"role\" = " + Lit(role) +
	                    " AND \"vcat\" = " + Lit(vcat),
	                "DELETE FROM " + catalog->Tbl("grant_columns") + " WHERE \"role\" = " + Lit(role) +
	                    " AND \"vcat\" = " + Lit(vcat)});
}

void PolicyStore::CatalogDropRelation(const string &vcat, const string &vname) {
	RequireCatalog(catalog, "acl_drop_relation");
	// dropping something that is not there is an error, not a silent success (spec 010) - the other
	// kinds already said so; the relation drop was the one that stayed quiet. DROP … IF EXISTS is
	// how a re-runnable script asks for the silent version (spec 013).
	if (!CatalogObjectExists(vcat, vname, "relation")) {
		throw BinderException("acl admin: relation \"%s.%s\" does not exist", vcat, vname);
	}
	// a record an expansion produced is remembered as dropped, so the next REFRESH does not bring it
	// back: excluding one object is the whole reason to expand a schema instead of aliasing it
	auto origin = catalog->Query("SELECT \"origin\" FROM " + catalog->Tbl("relations") +
	                             " WHERE \"vcat\" = " + Lit(vcat) + " AND \"vname\" = " + Lit(vname));
	vector<string> tombstone;
	if (origin->RowCount() > 0 && !origin->GetValue(0, 0).IsNull()) {
		auto dot = vname.rfind('.');
		if (dot != string::npos) {
			tombstone.push_back("INSERT OR IGNORE INTO " + catalog->Tbl("schema_dropped") + " VALUES (" + Lit(vcat) +
			                    ", " + Lit(vname.substr(0, dot)) + ", " + Lit(vname.substr(dot + 1)) + ")");
		}
	}
	catalog->Write({"DELETE FROM " + catalog->Tbl("relations") + " WHERE \"vcat\" = " + Lit(vcat) +
	                    " AND \"vname\" = " + Lit(vname),
	                "DELETE FROM " + catalog->Tbl("object_columns") + " WHERE \"vcat\" = " + Lit(vcat) +
	                    " AND \"vname\" = " + Lit(vname) + " AND \"kind\" = 'relation'",
	                "DELETE FROM " + catalog->Tbl("relation_columns") + " WHERE \"vcat\" = " + Lit(vcat) +
	                    " AND \"vname\" = " + Lit(vname),
	                "DELETE FROM " + catalog->Tbl("role_object_caps") + " WHERE \"vcat\" = " + Lit(vcat) +
	                    " AND \"vname\" = " + Lit(vname),
	                "DELETE FROM " + catalog->Tbl("grant_columns") + " WHERE \"vcat\" = " + Lit(vcat) +
	                    " AND \"vname\" = " + Lit(vname)});
	if (!tombstone.empty()) {
		catalog->Write(tombstone);
	}
}

void PolicyStore::CatalogSetComment(const string &vcat, const string &vname, const string &kind, const string &column,
                                    const string &comment) {
	RequireCatalog(catalog, "acl_comment");
	catalog->WriteWithReads([&](const std::function<unique_ptr<MaterializedQueryResult>(const string &)> &read,
	                            vector<string> &statements) {
		auto value = comment.empty() ? string("NULL") : Lit(comment);
		if (!column.empty()) {
			auto exists = read("SELECT 1 FROM " + catalog->Tbl("object_columns") + " WHERE \"vcat\" = " + Lit(vcat) +
			                   " AND \"vname\" = " + Lit(vname) + " AND \"kind\" = " + Lit(kind) +
			                   " AND \"name\" = " + Lit(column));
			if (exists->RowCount() == 0) {
				throw BinderException("acl admin: \"%s.%s\" has no column \"%s\" (its schema may be unknown - "
				                      "run acl_refresh_schema)",
				                      vcat, vname, column);
			}
			statements.push_back("UPDATE " + catalog->Tbl("object_columns") + " SET \"comment\" = " + value +
			                     " WHERE \"vcat\" = " + Lit(vcat) + " AND \"vname\" = " + Lit(vname) +
			                     " AND \"kind\" = " + Lit(kind) + " AND \"name\" = " + Lit(column));
			return;
		}
		if (kind == "schema") {
			auto where = " WHERE \"vcat\" = " + Lit(vcat) + " AND \"path\" = " + Lit(vname);
			auto exists = read("SELECT 1 FROM " + catalog->Tbl("schemas") + where);
			if (exists->RowCount() == 0) {
				throw BinderException("acl admin: schema \"%s.%s\" does not exist", vcat, vname);
			}
			statements.push_back("UPDATE " + catalog->Tbl("schemas") + " SET \"comment\" = " + value + where);
			return;
		}
		auto table = kind == "relation" ? "relations" : "functions";
		auto where = " WHERE \"vcat\" = " + Lit(vcat) + " AND \"vname\" = " + Lit(vname) +
		             (kind == "relation" ? string() : " AND \"kind\" = " + Lit(kind));
		auto exists = read("SELECT 1 FROM " + catalog->Tbl(table) + where);
		if (exists->RowCount() == 0) {
			throw BinderException("acl admin: \"%s.%s\" does not exist", vcat, vname);
		}
		statements.push_back("UPDATE " + catalog->Tbl(table) + " SET \"comment\" = " + value + where);
	});
}

idx_t PolicyStore::CatalogRefreshSchema(const string &vcat, const string &vname) {
	RequireCatalog(catalog, "acl_refresh_schema");
	idx_t refreshed = 0;
	catalog->WriteWithReads([&](const std::function<unique_ptr<MaterializedQueryResult>(const string &)> &read,
	                            vector<string> &statements) {
		string name_filter = vname.empty() ? string() : " AND \"vname\" = " + Lit(vname);
		// a declared schema is never re-derived: it is the admin's statement of fact
		auto declared = read("SELECT \"vname\", \"kind\" FROM " + catalog->Tbl("object_columns") +
		                     " WHERE \"vcat\" = " + Lit(vcat) + " AND \"derived\" = false" + name_filter);
		case_insensitive_set_t declared_keys;
		for (idx_t row = 0; row < declared->RowCount(); row++) {
			declared_keys.insert(declared->GetValue(0, row).ToString() + "\x1f" +
			                     declared->GetValue(1, row).ToString());
		}
		// only query-defined objects have a derived schema; an alias reads the physical catalog live
		auto views = read("SELECT \"vname\", \"view_sql\" FROM " + catalog->Tbl("relations") +
		                  " WHERE \"vcat\" = " + Lit(vcat) + " AND \"form\" = 'view'" + name_filter);
		for (idx_t row = 0; row < views->RowCount(); row++) {
			auto object = views->GetValue(0, row).ToString();
			if (declared_keys.count(object + "\x1frelation")) {
				continue;
			}
			auto sql = views->GetValue(1, row);
			vector<std::pair<string, string>> schema;
			bool derived = !sql.IsNull() && catalog->ProbeSchema(sql.ToString(), false, {}, schema);
			for (auto &statement : catalog->ColumnSchemaStatements(vcat, object, "relation", schema, derived)) {
				statements.push_back(statement);
			}
			refreshed++;
		}
		auto macros = read("SELECT \"vname\", \"kind\", \"template\", \"params\" FROM " + catalog->Tbl("functions") +
		                   " WHERE \"vcat\" = " + Lit(vcat) + " AND \"form\" = 'macro'" + name_filter);
		for (idx_t row = 0; row < macros->RowCount(); row++) {
			auto object = macros->GetValue(0, row).ToString();
			auto kind = macros->GetValue(1, row).ToString();
			if (declared_keys.count(object + "\x1f" + kind)) {
				continue;
			}
			auto sql = macros->GetValue(2, row);
			auto params = macros->GetValue(3, row);
			vector<std::pair<string, string>> schema;
			bool derived = !sql.IsNull() &&
			               catalog->ProbeSchema(
			                   sql.ToString(), kind == "scalar",
			                   CatalogBackend::DeclaredTypes(params.IsNull() ? string() : params.ToString()), schema);
			for (auto &statement : catalog->ColumnSchemaStatements(vcat, object, kind, schema, derived)) {
				statements.push_back(statement);
			}
			refreshed++;
		}
		// spec 027: the verdicts, not only the schemas. A predicate written while its object could not
		// be bound was accepted unchecked (spec 021), and a grant's projection was left unprobed for
		// the same reason (spec 026) - both are facts about the physical world, and this is the moment
		// the physical world is looked at again.
		auto shapes = read("SELECT \"vname\", \"form\", \"phys\", \"view_sql\", \"rls\" FROM " +
		                   catalog->Tbl("relations") + " WHERE \"vcat\" = " + Lit(vcat) + name_filter);
		case_insensitive_map_t<string> sources;
		for (idx_t row = 0; row < shapes->RowCount(); row++) {
			auto text = [&](idx_t column) {
				auto value = shapes->GetValue(column, row);
				return value.IsNull() ? string() : value.ToString();
			};
			auto object = text(0);
			auto source = text(1) == "view" ? "(" + text(3) + ")" : text(2);
			sources[object] = source;
			auto rls = text(4);
			if (rls.empty()) {
				continue;
			}
			bool checked = false;
			auto error = catalog->PredicateError(source, rls, &checked);
			// a predicate that now binds and fails is broken, and every read of the object already
			// says so - recording the verdict is what an operator can act on, aborting the refresh of
			// a whole catalog is not
			statements.push_back("UPDATE " + catalog->Tbl("relations") +
			                     " SET \"rls_checked\" = " + (checked && error.empty() ? "true" : "false") +
			                     " WHERE \"vcat\" = " + Lit(vcat) + " AND \"vname\" = " + Lit(object));
			refreshed++;
		}
		auto grants = read("SELECT \"role\", \"vname\", \"rls\", \"columns\" FROM " + catalog->Tbl("role_object_caps") +
		                   " WHERE \"vcat\" = " + Lit(vcat) + name_filter);
		for (idx_t row = 0; row < grants->RowCount(); row++) {
			auto text = [&](idx_t column) {
				auto value = grants->GetValue(column, row);
				return value.IsNull() ? string() : value.ToString();
			};
			auto role = text(0);
			auto object = text(1);
			auto rls = text(2);
			auto columns = text(3);
			auto source = sources.find(object);
			if (source == sources.end()) {
				continue; // the grant names something that is not a relation; nothing to bind against
			}
			if (!rls.empty()) {
				bool checked = false;
				auto error = catalog->PredicateError(source->second, rls, &checked);
				statements.push_back("UPDATE " + catalog->Tbl("role_object_caps") + " SET \"rls_checked\" = " +
				                     (checked && error.empty() ? "true" : "false") + " WHERE \"role\" = " + Lit(role) +
				                     " AND \"vcat\" = " + Lit(vcat) + " AND \"vname\" = " + Lit(object));
			}
			if (!columns.empty()) {
				GrantProjectionStatements(*catalog, read, role, vcat, object, columns, statements, false);
			}
			if (!rls.empty() || !columns.empty()) {
				refreshed++;
			}
		}
		// the catalog level of the chain has no single object to bind against, so it is judged against
		// all of them - which is exactly what a refresh has just made current
		if (vname.empty()) {
			auto catalog_grants = read("SELECT \"role\", \"rls\" FROM " + catalog->Tbl("role_catalogs") +
			                           " WHERE \"vcat\" = " + Lit(vcat) + " AND \"rls\" IS NOT NULL AND \"rls\" <> ''");
			for (idx_t row = 0; row < catalog_grants->RowCount(); row++) {
				auto role = catalog_grants->GetValue(0, row).ToString();
				auto rls = catalog_grants->GetValue(1, row).ToString();
				statements.push_back("UPDATE " + catalog->Tbl("role_catalogs") + " SET \"rls_checked\" = " +
				                     (catalog->CatalogPredicateChecked(read, vcat, rls) ? "true" : "false") +
				                     " WHERE \"role\" = " + Lit(role) + " AND \"vcat\" = " + Lit(vcat));
				refreshed++;
			}
		}
	});
	return refreshed;
}

void PolicyStore::CatalogDropCatalog(const string &vcat, bool cascade) {
	RequireCatalog(catalog, "acl_drop_catalog");
	catalog->WriteWithReads([&](const std::function<unique_ptr<MaterializedQueryResult>(const string &)> &read,
	                            vector<string> &statements) {
		auto exists = read("SELECT 1 FROM " + catalog->Tbl("catalogs") + " WHERE \"vcat\" = " + Lit(vcat));
		if (exists->RowCount() == 0) {
			throw BinderException("acl admin: catalog \"%s\" does not exist", vcat);
		}
		auto holders = read("SELECT \"role\" FROM " + catalog->Tbl("role_catalogs") + " WHERE \"vcat\" = " + Lit(vcat) +
		                    " ORDER BY \"role\"");
		if (holders->RowCount() > 0 && !cascade) {
			vector<string> roles;
			for (idx_t row = 0; row < holders->RowCount(); row++) {
				roles.push_back(holders->GetValue(0, row).ToString());
			}
			throw BinderException("acl admin: catalog \"%s\" is still granted to %s - repeat with CASCADE to "
			                      "drop those grants too",
			                      vcat, StringUtil::Join(roles, ", "));
		}
		for (auto table :
		     {"relations", "relation_columns", "schemas", "schema_aliases", "functions", "object_columns"}) {
			statements.push_back("DELETE FROM " + catalog->Tbl(table) + " WHERE \"vcat\" = " + Lit(vcat));
		}
		if (cascade) {
			for (auto table : {"role_catalogs", "role_object_caps"}) {
				statements.push_back("DELETE FROM " + catalog->Tbl(table) + " WHERE \"vcat\" = " + Lit(vcat));
			}
		}
		statements.push_back("DELETE FROM " + catalog->Tbl("catalogs") + " WHERE \"vcat\" = " + Lit(vcat));
	});
}

void PolicyStore::CatalogDropSchemaAlias(const string &vcat, const string &alias_path, bool cascade) {
	RequireCatalog(catalog, "acl_drop_schema_alias");
	catalog->WriteWithReads([&](const std::function<unique_ptr<MaterializedQueryResult>(const string &)> &read,
	                            vector<string> &statements) {
		auto where = " WHERE \"vcat\" = " + Lit(vcat) + " AND \"path\" = " + Lit(alias_path);
		auto exists = read("SELECT 1 FROM " + catalog->Tbl("schemas") + where);
		if (exists->RowCount() == 0) {
			throw BinderException("acl admin: schema \"%s.%s\" does not exist", vcat, alias_path);
		}
		// an expansion's records are relations of the catalog in their own right, so they go only with
		// CASCADE - the rule DROP VIRTUAL CATALOG already follows for grants (spec 010)
		auto prefix =
		    " AND substr(\"vname\", 1, " + std::to_string(alias_path.size() + 1) + ") = " + Lit(alias_path + ".");
		auto records =
		    read("SELECT count(*) FROM " + catalog->Tbl("relations") + " WHERE \"vcat\" = " + Lit(vcat) + prefix);
		auto count = records->GetValue(0, 0).GetValue<int64_t>();
		if (count > 0 && !cascade) {
			throw BinderException("acl admin: schema \"%s.%s\" still holds %lld object(s) - repeat with CASCADE to "
			                      "drop them too",
			                      vcat, alias_path, count);
		}
		if (cascade) {
			for (auto table : {"relations", "relation_columns", "role_object_caps"}) {
				statements.push_back("DELETE FROM " + catalog->Tbl(table) + " WHERE \"vcat\" = " + Lit(vcat) + prefix);
			}
			statements.push_back("DELETE FROM " + catalog->Tbl("schema_dropped") + " WHERE \"vcat\" = " + Lit(vcat) +
			                     " AND \"path\" = " + Lit(alias_path));
		}
		statements.push_back("DELETE FROM " + catalog->Tbl("schemas") + where);
		statements.push_back("DELETE FROM " + catalog->Tbl("schema_aliases") + " WHERE \"vcat\" = " + Lit(vcat) +
		                     " AND \"alias_path\" = " + Lit(alias_path));
		// the schema is gone, and so are the grants that named it - inherited or not
		statements.push_back("DELETE FROM " + catalog->Tbl("role_schemas") + " WHERE \"vcat\" = " + Lit(vcat) +
		                     " AND \"schema_path\" = " + Lit(alias_path));
	});
}

void PolicyStore::CatalogDropFunction(const string &vcat, const string &vname, const string &kind) {
	RequireCatalog(catalog, "acl_drop_function");
	catalog->WriteWithReads([&](const std::function<unique_ptr<MaterializedQueryResult>(const string &)> &read,
	                            vector<string> &statements) {
		auto exists = read("SELECT 1 FROM " + catalog->Tbl("functions") + " WHERE \"vcat\" = " + Lit(vcat) +
		                   " AND \"vname\" = " + Lit(vname) + " AND \"kind\" = " + Lit(kind));
		if (exists->RowCount() == 0) {
			throw BinderException("acl admin: %s function \"%s.%s\" does not exist", kind, vcat, vname);
		}
		statements.push_back("DELETE FROM " + catalog->Tbl("functions") + " WHERE \"vcat\" = " + Lit(vcat) +
		                     " AND \"vname\" = " + Lit(vname) + " AND \"kind\" = " + Lit(kind));
		statements.push_back("DELETE FROM " + catalog->Tbl("object_columns") + " WHERE \"vcat\" = " + Lit(vcat) +
		                     " AND \"vname\" = " + Lit(vname) + " AND \"kind\" = " + Lit(kind));
	});
}

void PolicyStore::CatalogDropRole(const string &role) {
	RequireCatalog(catalog, "acl_drop_role");
	catalog->WriteWithReads([&](const std::function<unique_ptr<MaterializedQueryResult>(const string &)> &read,
	                            vector<string> &statements) {
		auto exists = read("SELECT 1 FROM " + catalog->Tbl("roles") + " WHERE \"role\" = " + Lit(role));
		if (exists->RowCount() == 0) {
			throw BinderException("acl admin: role \"%s\" does not exist", role);
		}
		// everything that points at a role goes with it - nothing may dangle
		for (auto table :
		     {"role_claims", "role_catalogs", "role_object_caps", "role_schemas", "admins", "role_mappings"}) {
			statements.push_back("DELETE FROM " + catalog->Tbl(table) + " WHERE \"role\" = " + Lit(role));
		}
		statements.push_back("DELETE FROM " + catalog->Tbl("roles") + " WHERE \"role\" = " + Lit(role));
	});
}

void PolicyStore::CatalogDropIssuer(const string &issuer) {
	RequireCatalog(catalog, "acl_drop_issuer");
	catalog->WriteWithReads([&](const std::function<unique_ptr<MaterializedQueryResult>(const string &)> &read,
	                            vector<string> &statements) {
		auto exists = read("SELECT 1 FROM " + catalog->Tbl("issuers") + " WHERE \"issuer\" = " + Lit(issuer));
		if (exists->RowCount() == 0) {
			throw BinderException("acl admin: issuer \"%s\" does not exist", issuer);
		}
		statements.push_back("DELETE FROM " + catalog->Tbl("role_mappings") + " WHERE \"issuer\" = " + Lit(issuer));
		statements.push_back("DELETE FROM " + catalog->Tbl("issuers") + " WHERE \"issuer\" = " + Lit(issuer));
	});
}

void PolicyStore::CatalogDropRoleMapping(const string &issuer, const string &source, const string &external_value,
                                         const string &role) {
	RequireCatalog(catalog, "acl_drop_role_mapping");
	catalog->WriteWithReads([&](const std::function<unique_ptr<MaterializedQueryResult>(const string &)> &read,
	                            vector<string> &statements) {
		auto where = " WHERE \"issuer\" = " + Lit(issuer) + " AND \"source\" = " + Lit(source) +
		             " AND \"external_value\" = " + Lit(external_value) + " AND \"role\" = " + Lit(role);
		auto exists = read("SELECT 1 FROM " + catalog->Tbl("role_mappings") + where);
		if (exists->RowCount() == 0) {
			throw BinderException("acl admin: no mapping of %s \"%s\" from issuer \"%s\" to role \"%s\"", source,
			                      external_value, issuer, role);
		}
		statements.push_back("DELETE FROM " + catalog->Tbl("role_mappings") + where);
	});
}

void PolicyStore::CatalogDefineRole(const string &role, const case_insensitive_map_t<string> &claims) {
	RequireCatalog(catalog, "acl_define_role");
	vector<string> statements;
	statements.push_back("DELETE FROM " + catalog->Tbl("roles") + " WHERE \"role\" = " + Lit(role));
	statements.push_back("INSERT INTO " + catalog->Tbl("roles") + " VALUES (" + Lit(role) + ", '')");
	statements.push_back("DELETE FROM " + catalog->Tbl("role_claims") + " WHERE \"role\" = " + Lit(role));
	for (auto &claim : claims) {
		statements.push_back("INSERT INTO " + catalog->Tbl("role_claims") + " VALUES (" + Lit(role) + ", " +
		                     Lit(claim.first) + ", " + Lit(claim.second) + ")");
	}
	catalog->Write(statements);
}

void PolicyStore::CatalogSetFunctionGate(const string &name, bool allowed, bool remove) {
	RequireCatalog(catalog, "acl_deny_function/acl_allow_function");
	vector<string> statements = {"DELETE FROM " + catalog->Tbl("function_gate") +
	                             " WHERE \"role\" = '' AND \"name\" = " + Lit(StringUtil::Lower(name))};
	if (!remove) {
		statements.push_back("INSERT INTO " + catalog->Tbl("function_gate") + " VALUES ('', " +
		                     Lit(StringUtil::Lower(name)) + ", '', " + (allowed ? "true" : "false") + ")");
	}
	catalog->Write(statements);
}

namespace {

//! ALTER targets must exist: read the single row, or fail with a specific message
unique_ptr<MaterializedQueryResult> RequireRow(CatalogBackend &catalog, const string &sql, const string &what) {
	auto result = catalog.Query(sql);
	if (result->RowCount() == 0) {
		throw BinderException("acl admin: %s does not exist", what);
	}
	return result;
}

} // namespace

void PolicyStore::CatalogAlterRelation(const string &vcat, const string &vname, const string &field,
                                       const string &value, const vector<std::pair<string, string>> &columns) {
	RequireCatalog(catalog, "acl_alter_relation");
	catalog->WriteWithReads([&](const std::function<unique_ptr<MaterializedQueryResult>(const string &)> &read,
	                            vector<string> &statements) {
		auto current = read("SELECT \"form\", \"phys\", \"view_sql\", \"rls\" FROM " + catalog->Tbl("relations") +
		                    " WHERE \"vcat\" = " + Lit(vcat) + " AND \"vname\" = " + Lit(vname));
		if (current->RowCount() == 0) {
			throw BinderException("acl admin: relation \"%s.%s\" does not exist", vcat, vname);
		}
		auto form = current->GetValue(0, 0).ToString();
		// the statement kind must match what the object is: silently turning a masked/RLS table into
		// a view (or vice versa) would drop enforcement while the catalog still shows it
		bool target_is_view = form == "view";
		if ((field == "view") != target_is_view) {
			throw BinderException("acl admin: \"%s.%s\" is %s - use ALTER VIRTUAL %s", vcat, vname,
			                      target_is_view ? "a view" : "a table", target_is_view ? "VIEW" : "TABLE");
		}
		auto phys = current->GetValue(1, 0);
		auto view_sql = current->GetValue(2, 0);
		auto rls = current->GetValue(3, 0);
		string new_phys = phys.IsNull() ? string() : phys.ToString();
		string new_view = view_sql.IsNull() ? string() : view_sql.ToString();
		string new_rls = rls.IsNull() ? string() : rls.ToString();
		vector<std::pair<string, string>> new_columns;
		if (field == "columns") {
			new_columns = columns;
		} else { // keep the current projection when another property is being set
			auto rows = read("SELECT \"name\", \"expr\" FROM " + catalog->Tbl("relation_columns") +
			                 " WHERE \"vcat\" = " + Lit(vcat) + " AND \"vname\" = " + Lit(vname) + " ORDER BY \"pos\"");
			for (idx_t row = 0; row < rows->RowCount(); row++) {
				auto expr = rows->GetValue(1, row);
				new_columns.emplace_back(rows->GetValue(0, row).ToString(), expr.IsNull() ? string() : expr.ToString());
			}
		}
		if (field == "phys") {
			new_phys = value;
		} else if (field == "rls") {
			new_rls = value;
		} else if (field == "view") {
			new_view = value;
		} else if (field != "columns") {
			throw BinderException("acl admin: unknown relation property \"%s\"", field);
		}
		// the form follows the content, exactly as it does for ADD
		string new_form = !new_view.empty() ? "view" : (new_columns.empty() && new_rls.empty() ? "alias" : "subquery");
		auto stored = read("SELECT \"comment\", \"origin\" FROM " + catalog->Tbl("relations") +
		                   " WHERE \"vcat\" = " + Lit(vcat) + " AND \"vname\" = " + Lit(vname));
		string comment, origin;
		if (stored->RowCount() > 0) {
			if (!stored->GetValue(0, 0).IsNull()) {
				comment = stored->GetValue(0, 0).ToString();
			}
			// editing a record an expansion produced does not take it out of the expansion: REFRESH
			// still leaves it alone (it never rewrites), and PRUNE still removes it if its source is
			// gone - which is right, because it would then point at nothing
			if (!stored->GetValue(1, 0).IsNull()) {
				origin = stored->GetValue(1, 0).ToString();
			}
		}
		// ALTER keeps the stored schema policy: a declared result is re-declared explicitly, not here
		statements = RelationStatements(*catalog, vcat, vname, new_form, new_phys, new_view, new_rls, new_columns,
		                                comment, string(), origin);
	});
}

void PolicyStore::CatalogAlterSchemaAlias(const string &vcat, const string &alias_path, const string &phys_path) {
	RequireCatalog(catalog, "acl_alter_schema_alias");
	RequireRow(*catalog,
	           "SELECT 1 FROM " + catalog->Tbl("schemas") + " WHERE \"vcat\" = " + Lit(vcat) +
	               " AND \"path\" = " + Lit(alias_path),
	           "schema \"" + vcat + "." + alias_path + "\"");
	CatalogAddSchemaAlias(vcat, alias_path, phys_path);
}

void PolicyStore::CatalogAlterFunction(const string &vcat, const string &vname, const string &kind, const string &form,
                                       const string &definition) {
	RequireCatalog(catalog, "acl_alter_function");
	RequireRow(*catalog,
	           "SELECT 1 FROM " + catalog->Tbl("functions") + " WHERE \"vcat\" = " + Lit(vcat) +
	               " AND \"vname\" = " + Lit(vname) + " AND \"kind\" = " + Lit(kind),
	           kind + " function \"" + vcat + "." + vname + "\"");
	bool is_alias = form == "alias";
	CatalogAddFunction(vcat, vname, kind, form, is_alias ? definition : "", is_alias ? "" : definition);
}

void PolicyStore::CatalogAlterCatalog(const string &vcat, const string &comment) {
	RequireCatalog(catalog, "acl_alter_catalog");
	RequireRow(*catalog, "SELECT 1 FROM " + catalog->Tbl("catalogs") + " WHERE \"vcat\" = " + Lit(vcat),
	           "catalog \"" + vcat + "\"");
	CatalogCreate(vcat, comment);
}

void PolicyStore::CatalogAlterRole(const string &role, const case_insensitive_map_t<string> &claims) {
	RequireCatalog(catalog, "acl_alter_role");
	RequireRow(*catalog, "SELECT 1 FROM " + catalog->Tbl("roles") + " WHERE \"role\" = " + Lit(role),
	           "role \"" + role + "\"");
	CatalogDefineRole(role, claims);
}

void PolicyStore::CatalogAlterGrant(const string &role, const string &vcat, const string &field, const string &value) {
	RequireCatalog(catalog, "acl_alter_grant");
	auto current =
	    RequireRow(*catalog,
	               "SELECT \"is_main\", \"caps\", \"rls\", \"columns\" FROM " + catalog->Tbl("role_catalogs") +
	                   " WHERE \"role\" = " + Lit(role) + " AND \"vcat\" = " + Lit(vcat),
	               "grant of catalog \"" + vcat + "\" to role \"" + role + "\"");
	auto is_main_value = current->GetValue(0, 0);
	bool is_main = !is_main_value.IsNull() && is_main_value.GetValue<bool>();
	auto text = [&](idx_t column) {
		auto stored = current->GetValue(column, 0);
		return stored.IsNull() ? string() : stored.ToString();
	};
	string caps = text(1); // NULL stays unspecified rather than becoming an explicit "{}"
	string rls = text(2);
	string columns = text(3);
	if (field == "caps") {
		caps = value;
	} else if (field == "rls") {
		rls = value;
	} else if (field == "columns") {
		columns = value;
	} else if (field == "main") {
		if (!StringUtil::CIEquals(value, "true") && !StringUtil::CIEquals(value, "false")) {
			throw BinderException("acl admin: MAIN expects true or false, got \"%s\"", value);
		}
		is_main = StringUtil::CIEquals(value, "true");
	} else {
		throw BinderException("acl admin: unknown grant property \"%s\"", field);
	}
	CatalogGrant(role, vcat, caps, is_main, rls, columns);
}

void PolicyStore::CatalogAlterIssuer(const string &issuer, const string &field, const string &value) {
	RequireCatalog(catalog, "acl_alter_issuer");
	IssuerConfig config;
	if (!CatalogLookupIssuer(issuer, config)) {
		throw BinderException("acl admin: issuer \"%s\" does not exist", issuer);
	}
	auto split_csv = [](const string &csv) {
		vector<string> parts;
		for (auto &part : StringUtil::Split(csv, ',')) {
			StringUtil::Trim(part);
			if (!part.empty()) {
				parts.push_back(part);
			}
		}
		return parts;
	};
	if (field == "keys") {
		// the two are alternatives, so setting one clears the other: an issuer whose keys were pasted
		// and then pointed at a document must not keep verifying against the old paste
		config.keys_json = value;
		config.jwks_uri.clear();
	} else if (field == "jwks_uri") {
		config.jwks_uri = value;
		config.keys_json.clear();
	} else if (field == "audiences") {
		config.audiences = split_csv(value);
		if (config.audiences.empty()) {
			// an empty allowlist means "accept any aud" downstream - never let that happen silently
			throw BinderException("acl admin: AUDIENCES must list at least one audience (use '*' to "
			                      "accept any)");
		}
	} else if (field == "algs") {
		config.algs.clear();
		for (auto &alg : split_csv(value)) {
			config.algs.insert(alg);
		}
	} else if (field == "role_claim") {
		config.role_claim = value;
	} else if (field == "claim_map") {
		config.claim_map = value;
	} else {
		throw BinderException("acl admin: unknown issuer property \"%s\"", field);
	}
	CatalogDefineIssuer(config);
}

void PolicyStore::CatalogGrantAdmin(const string &role, const string &scope) {
	RequireCatalog(catalog, "acl_grant_admin");
	catalog->Write({"DELETE FROM " + catalog->Tbl("admins") + " WHERE \"role\" = " + Lit(role),
	                "INSERT INTO " + catalog->Tbl("admins") + " VALUES (" + Lit(role) + ", " + Lit(scope) + ", '')"});
}

void PolicyStore::CatalogRevokeAdmin(const string &role) {
	RequireCatalog(catalog, "acl_revoke_admin");
	// de-privileging a role must remove ALL of its administration: the global scope and the
	// per-catalog manage capabilities, which live in the catalog grants
	auto grants = catalog->Query("SELECT \"vcat\", \"caps\" FROM " + catalog->Tbl("role_catalogs") +
	                             " WHERE \"role\" = " + Lit(role));
	vector<string> statements = {"DELETE FROM " + catalog->Tbl("admins") + " WHERE \"role\" = " + Lit(role)};
	for (idx_t row = 0; row < grants->RowCount(); row++) {
		auto caps_value = grants->GetValue(1, row);
		auto caps = acl_detail::ParseCaps(caps_value.IsNull() ? string() : caps_value.ToString());
		if (!caps.erase("manage")) {
			continue;
		}
		vector<string> kept;
		for (auto &cap : caps) {
			kept.push_back("\"" + cap + "\": true");
		}
		statements.push_back("UPDATE " + catalog->Tbl("role_catalogs") + " SET \"caps\" = " +
		                     Lit("{" + StringUtil::Join(kept, ", ") + "}") + " WHERE \"role\" = " + Lit(role) +
		                     " AND \"vcat\" = " + Lit(grants->GetValue(0, row).ToString()));
	}
	catalog->Write(statements);
}

void PolicyStore::CatalogAdminRights(const Principal &principal, std::set<string> &catalogs,
                                     vector<std::pair<string, string>> &scopes) {
	catalog->LoadRights(principal, catalogs, scopes);
}

bool PolicyStore::CatalogAnonymousAdminAllowed() {
	return catalog->SettingBool("acl_allow_anonymous_admin", false);
}

void PolicyStore::CatalogDefineIssuer(const IssuerConfig &config) {
	RequireCatalog(catalog, "acl_define_issuer");
	auto audiences = StringUtil::Join(config.audiences, ",");
	vector<string> algs_list;
	for (auto &alg : config.algs) {
		algs_list.push_back(alg);
	}
	auto algs = StringUtil::Join(algs_list, ",");
	catalog->Write({"DELETE FROM " + catalog->Tbl("issuers") + " WHERE \"issuer\" = " + Lit(config.issuer),
	                "INSERT INTO " + catalog->Tbl("issuers") + " VALUES (" + Lit(config.issuer) + ", " +
	                    Lit(config.keys_json) + ", " + Lit(audiences) + ", " + Lit(algs) + ", " +
	                    Lit(config.role_claim) + ", " + Lit(config.claim_map) + ", " +
	                    (config.jwks_uri.empty() ? string("NULL") : Lit(config.jwks_uri)) + ")"});
}

void PolicyStore::CatalogMapRole(const string &issuer, const string &source, const string &external_value,
                                 const string &role) {
	RequireCatalog(catalog, "acl_map_role");
	catalog->Write({"DELETE FROM " + catalog->Tbl("role_mappings") + " WHERE \"issuer\" = " + Lit(issuer) +
	                    " AND \"source\" = " + Lit(source) + " AND \"external_value\" = " + Lit(external_value) +
	                    " AND \"role\" = " + Lit(role),
	                "INSERT INTO " + catalog->Tbl("role_mappings") + " VALUES (" + Lit(issuer) + ", " + Lit(source) +
	                    ", " + Lit(external_value) + ", " + Lit(role) + ")"});
}

void PolicyStore::CatalogSetObjectCaps(const string &role, const string &vcat, const string &vname,
                                       const string &caps_json, const string &rls, const string &columns) {
	RequireCatalog(catalog, "acl catalog");
	acl_detail::ParseCaps(caps_json);
	catalog->WriteWithReads([&](const std::function<unique_ptr<MaterializedQueryResult>(const string &)> &read,
	                            vector<string> &statements) {
		// the grant's predicate is checked against the object it filters, here rather than at query
		// time (spec 021) - a predicate that cannot bind is a mistake, whoever eventually runs into it
		bool checked = false;
		if (!rls.empty()) {
			auto shape = read("SELECT \"form\", \"phys\", \"view_sql\" FROM " + catalog->Tbl("relations") +
			                  " WHERE \"vcat\" = " + Lit(vcat) + " AND \"vname\" = " + Lit(vname));
			if (shape->RowCount() > 0) {
				auto form = shape->GetValue(0, 0).IsNull() ? string() : shape->GetValue(0, 0).ToString();
				auto phys = shape->GetValue(1, 0).IsNull() ? string() : shape->GetValue(1, 0).ToString();
				auto view_sql = shape->GetValue(2, 0).IsNull() ? string() : shape->GetValue(2, 0).ToString();
				auto source = form == "view" ? "(" + view_sql + ")" : phys;
				auto error = catalog->PredicateError(source, rls, &checked);
				if (!error.empty()) {
					throw InvalidInputException("acl: the predicate of the grant on \"%s\" does not bind "
					                            "against it: %s",
					                            vname, error);
				}
			}
		}
		// what this projection actually produces: names a mask renames the type of, and columns the
		// object never had. Probed here, where it is written, so a listing can describe what the role
		// reads rather than what the physical table holds (spec 026).
		GrantProjectionStatements(*catalog, read, role, vcat, vname, columns, statements, true);
		statements.push_back("DELETE FROM " + catalog->Tbl("role_object_caps") + " WHERE \"role\" = " + Lit(role) +
		                     " AND \"vcat\" = " + Lit(vcat) + " AND \"vname\" = " + Lit(vname));
		statements.push_back("INSERT INTO " + catalog->Tbl("role_object_caps") +
		                     "(\"role\", \"vcat\", \"vname\", \"caps\", \"rls\", \"columns\", \"rls_checked\")"
		                     " VALUES (" +
		                     Lit(role) + ", " + Lit(vcat) + ", " + Lit(vname) + ", " + Lit(caps_json) + ", " +
		                     Lit(rls) + ", " + Lit(columns) + ", " +
		                     (rls.empty() ? "NULL" : (checked ? "true" : "false")) + ")");
	});
}

bool PolicyStore::CatalogObjectExists(const string &vcat, const string &vname, const string &kind) {
	RequireCatalog(catalog, "acl catalog");
	string sql;
	if (kind == "catalog") {
		sql = "SELECT 1 FROM " + catalog->Tbl("catalogs") + " WHERE \"vcat\" = " + Lit(vcat);
	} else if (kind == "role") {
		sql = "SELECT 1 FROM " + catalog->Tbl("roles") + " WHERE \"role\" = " + Lit(vname);
	} else if (kind == "issuer") {
		sql = "SELECT 1 FROM " + catalog->Tbl("issuers") + " WHERE \"issuer\" = " + Lit(vname);
	} else if (kind == "schema") {
		sql = "SELECT 1 FROM " + catalog->Tbl("schemas") + " WHERE \"vcat\" = " + Lit(vcat) +
		      " AND \"path\" = " + Lit(vname);
	} else if (kind == "relation") {
		sql = "SELECT 1 FROM " + catalog->Tbl("relations") + " WHERE \"vcat\" = " + Lit(vcat) +
		      " AND \"vname\" = " + Lit(vname);
	} else if (kind == "reference") {
		sql = "SELECT 1 FROM " + catalog->Tbl("references") + " WHERE \"vcat\" = " + Lit(vcat) +
		      " AND \"name\" = " + Lit(vname);
	} else {
		// a function's kind is part of its identity: a table function and a scalar may share a name
		sql = "SELECT 1 FROM " + catalog->Tbl("functions") + " WHERE \"vcat\" = " + Lit(vcat) +
		      " AND \"vname\" = " + Lit(vname) + " AND \"kind\" = " + Lit(kind);
	}
	return catalog->Query(sql)->RowCount() > 0;
}

void PolicyStore::CatalogRequireGrantTarget(const string &vcat, const string &vname, bool with_policy) {
	RequireCatalog(catalog, "acl_grant_object");
	// what the name is, in the terms resolution uses: a relation, a table reached through a schema
	// alias, a function - or the bare alias path, which resolution never looks up by itself
	auto result = catalog->Query(
	    "SELECT 'relation' AS kind FROM " + catalog->Tbl("relations") + " WHERE \"vcat\" = " + Lit(vcat) +
	    " AND \"vname\" = " + Lit(vname) + " UNION ALL SELECT \"kind\" FROM " + catalog->Tbl("functions") +
	    " WHERE \"vcat\" = " + Lit(vcat) + " AND \"vname\" = " + Lit(vname) +
	    " UNION ALL SELECT CASE WHEN \"path\" = " + Lit(vname) + " THEN 'alias' ELSE 'relation' END FROM " +
	    catalog->Tbl("schemas") + " WHERE \"vcat\" = " + Lit(vcat) + " AND (\"path\" = " + Lit(vname) + " OR substr(" +
	    Lit(vname) + ", 1, length(\"path\") + 1) = \"path\" || '.')");
	if (result->RowCount() == 0) {
		throw BinderException("acl admin: object \"%s.%s\" does not exist", vcat, vname);
	}
	case_insensitive_set_t kinds;
	for (idx_t row = 0; row < result->RowCount(); row++) {
		kinds.insert(result->GetValue(0, row).ToString());
	}
	if (kinds.count("relation") || kinds.count("table")) {
		return; // rows to narrow, and capabilities that resolution will find
	}
	if (kinds.count("alias")) {
		// a schema alias is a prefix, never a relation of its own: resolution looks up the written
		// path, so a grant on the bare alias would never be found
		throw BinderException("acl admin: \"%s.%s\" is a schema alias, so a grant on it would never apply - "
		                      "grant the table inside it (\"%s.<table>\")",
		                      vcat, vname, vname);
	}
	if (with_policy) {
		// a scalar function returns a value, not rows: an RLS predicate or a column list on one would
		// silently do nothing, so the grant is refused instead
		throw BinderException("acl admin: scalar function \"%s.%s\" has no rows or columns to narrow", vcat, vname);
	}
}

void PolicyStore::CatalogEnsureGrant(const string &role, const string &vcat, bool is_main) {
	RequireCatalog(catalog, "acl catalog");
	catalog->Write({"INSERT INTO " + catalog->Tbl("role_catalogs") +
	                "(\"role\", \"vcat\", \"is_main\", \"caps\") SELECT " + Lit(role) + ", " + Lit(vcat) + ", " +
	                (is_main ? "true" : "false") + ", '{}' WHERE NOT EXISTS (SELECT 1 FROM " +
	                catalog->Tbl("role_catalogs") + " WHERE \"role\" = " + Lit(role) + " AND \"vcat\" = " + Lit(vcat) +
	                ")"});
}

} // namespace acl
} // namespace duckdb
