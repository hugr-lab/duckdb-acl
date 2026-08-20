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
	vector<std::pair<string, string>> columns; // visible columns, name -> expr ("" = as-is)
	vector<string> predicates;                 // AND-ed together

	//! Fold one level of the chain in; empty strings mean "this level says nothing"
	void Narrow(const string &rls, const string &column_csv) {
		if (!rls.empty()) {
			predicates.push_back(rls);
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
	vector<string> predicates;
	vector<std::pair<string, string>> columns;

	void Add(const GrantPolicy &policy) {
		any = true;
		auto predicate = policy.Predicate();
		if (predicate.empty()) {
			unrestricted_rls = true;
		} else {
			predicates.push_back(predicate);
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
			grants = "SELECT \"role\", \"vcat\", \"is_main\", \"caps\", \"rls\", \"columns\" FROM " +
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
			                      " NULL AS \"rls\", NULL AS \"columns\" WHERE false")
			             : "SELECT *, NULL AS \"rls\", NULL AS \"columns\" FROM (VALUES " + values +
			                   ") v(\"role\", \"vcat\", \"is_main\", \"caps\")";
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
	bool HasObjectCaps() {
		return !function_mode || HasSlot("object_caps");
	}
	string ObjectCapsSource(const Principal &principal, const vector<string> &names) {
		return function_mode ? Slot("object_caps") + "(" + ListLit(principal.roles) + ", " +
		                           ListLit(GrantedCatalogs(principal)) + ", " + ListLit(names) + ")"
		                     : Tbl("role_object_caps");
	}
	//! the caps column of a resolution query; without an object_caps source there is no override
	string CapsExpr() {
		// nullif over the trimmed value: an object row that says nothing about capabilities - NULL,
		// empty or blank - falls back to the catalog grant instead of replacing it, because
		// "unspecified" is not "none" (spec 012)
		return HasObjectCaps() ? "coalesce(nullif(trim(oc.\"caps\"), ''), g.\"caps\")" : "g.\"caps\"";
	}
	//! The grant chain's policy columns (spec 011): the catalog grant's and the object grant's own RLS
	//! and column list. The function-driver's slots do not carry them, so it composes to no narrowing.
	string GrantPolicyExprs() {
		return function_mode ? "NULL AS crls, NULL AS ccols, NULL AS orls, NULL AS ocols"
		                     : "g.\"rls\" AS crls, g.\"columns\" AS ccols, oc.\"rls\" AS orls,"
		                       " oc.\"columns\" AS ocols";
	}
	//! Fold the four policy columns of one result row into the chain of one role
	static GrantPolicy RowPolicy(MaterializedQueryResult &result, idx_t row, idx_t first_column) {
		auto text = [&](idx_t column) {
			auto value = result.GetValue(column, row);
			return value.IsNull() ? string() : value.ToString();
		};
		GrantPolicy policy;
		policy.Narrow(text(first_column), text(first_column + 1));     // catalog level
		policy.Narrow(text(first_column + 2), text(first_column + 3)); // object level
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
		           " c WHERE c.\"vcat\" = r.\"vcat\" AND c.\"vname\" = r.\"vname\") AS cols"
		           " FROM " +
		           RelationsSource(principal, names) + " r JOIN grants g ON g.\"vcat\" = r.\"vcat\"" + oc_join +
		           " WHERE (" + qualified_cond +
		           ") OR (g.\"is_main\" AND (SELECT unique_main FROM main_ok) AND r.\"vname\" = " + Lit(vname) +
		           ") ORDER BY prio";
		auto result = Query(sql);
		if (result->RowCount() == 0) {
			return false;
		}
		auto prio = result->GetValue(9, 0).GetValue<int64_t>();
		auto form = result->GetValue(0, 0).ToString();
		auto phys = result->GetValue(1, 0);
		auto view_sql = result->GetValue(2, 0);
		auto rls = result->GetValue(3, 0);
		out.phys = phys.IsNull() ? string() : phys.ToString();
		out.query = view_sql.IsNull() ? string() : view_sql.ToString();
		out.rls = rls.IsNull() ? string() : rls.ToString();
		out.subquery_form = form != "alias";
		out.writable = form == "alias"; // a real table stays writable, however a grant narrows it
		vector<std::pair<string, string>> object_columns;
		auto cols = result->GetValue(10, 0);
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
			if (result->GetValue(9, row).GetValue<int64_t>() != prio) {
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
		auto sql = GrantsCte(principal) + "SELECT sa.\"vcat\", sa.\"alias_path\", sa.\"phys_path\", " + CapsExpr() +
		           " AS caps, " + GrantPolicyExprs() +
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
		auto prio = result->GetValue(8, 0).GetValue<int64_t>();
		auto vcat = result->GetValue(0, 0).ToString();
		auto alias_path = result->GetValue(1, 0).ToString();
		auto &path = prio == 1 ? rest : vname;
		out.subquery_form = false;
		out.writable = true; // an aliased schema maps onto real tables
		out.phys = result->GetValue(2, 0).ToString() + path.substr(alias_path.size());
		// rows of the same winning alias differ only by role: union their caps and grant policies
		GrantUnion grants;
		for (idx_t row = 0; row < result->RowCount(); row++) {
			if (result->GetValue(8, row).GetValue<int64_t>() != prio || result->GetValue(0, row).ToString() != vcat ||
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
		auto sql = GrantsCte(principal) + "SELECT f.\"vcat\", f.\"form\", f.\"target\", f.\"template\", " + CapsExpr() +
		           " AS caps, " + GrantPolicyExprs() +
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
			auto prio = result->GetValue(9, 0).GetValue<int64_t>();
			policy.subquery_form = form != "alias";
			policy.phys = target.IsNull() ? string() : target.ToString();
			policy.query = template_sql.IsNull() ? string() : template_sql.ToString();
			// rows of the same winning function differ only by role: union their caps (spec 012 - a
			// call is a read, so it needs one) and their grant policies
			GrantUnion grants;
			for (idx_t row = 0; row < result->RowCount(); row++) {
				if (result->GetValue(9, row).GetValue<int64_t>() != prio ||
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
			result = Query("SELECT \"keys_json\", \"audiences\", \"algs\", \"role_claim\", \"claim_map\" FROM " +
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
		    "INSERT INTO " + Tbl("meta") + " SELECT 'schema_version', '4' WHERE NOT EXISTS (SELECT 1 FROM " +
		        Tbl("meta") + " WHERE \"key\" = 'schema_version')",
		    "UPDATE " + Tbl("meta") + " SET \"value\" = '4' WHERE \"key\" = 'schema_version' AND \"value\" < '4'",
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

int64_t PolicyStore::JwtClockSkew() {
	if (catalog) {
		return catalog->SettingInt64("acl_jwt_clock_skew", 60);
	}
	return 60; // the memory mode has no database handle to read the setting from
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
	// the comment is read by the caller BEFORE the delete above and carried through: a definition
	// change is not a reason to lose an operator's documentation
	statements.push_back("INSERT INTO " + catalog.Tbl("relations") +
	                     "(\"vcat\", \"vname\", \"form\", \"phys\", \"view_sql\", \"rls\", \"comment\", \"origin\")"
	                     " VALUES (" +
	                     Lit(vcat) + ", " + Lit(vname) + ", " + Lit(form) + ", " + Lit(phys) + ", " + Lit(view_sql) +
	                     ", " + Lit(rls) + ", " + (comment.empty() ? string("NULL") : Lit(comment)) + ", " +
	                     (origin.empty() ? string("NULL") : Lit(origin)) + ")");
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

} // namespace

void PolicyStore::CatalogAddRelation(const string &vcat, const string &vname, const string &form, const string &phys,
                                     const string &view_sql, const string &rls,
                                     const vector<std::pair<string, string>> &columns, const string &returns) {
	RequireCatalog(catalog, "acl_add_relation");
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
	catalog->Write({"DELETE FROM " + catalog->Tbl("role_catalogs") + " WHERE \"role\" = " + Lit(role) +
	                    " AND \"vcat\" = " + Lit(vcat),
	                "INSERT INTO " + catalog->Tbl("role_catalogs") +
	                    "(\"role\", \"vcat\", \"is_main\", \"caps\", \"rls\", \"columns\") VALUES (" + Lit(role) +
	                    ", " + Lit(vcat) + ", " + (is_main ? "true" : "false") + ", " + Lit(caps_json) + ", " +
	                    Lit(rls) + ", " + Lit(columns) + ")"});
}

void PolicyStore::CatalogRevoke(const string &role, const string &vcat) {
	RequireCatalog(catalog, "acl_revoke_catalog");
	catalog->Write({"DELETE FROM " + catalog->Tbl("role_catalogs") + " WHERE \"role\" = " + Lit(role) +
	                    " AND \"vcat\" = " + Lit(vcat),
	                "DELETE FROM " + catalog->Tbl("role_object_caps") + " WHERE \"role\" = " + Lit(role) +
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
		for (auto table : {"role_claims", "role_catalogs", "role_object_caps", "admins", "role_mappings"}) {
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
		auto comment_value = read("SELECT \"comment\" FROM " + catalog->Tbl("relations") +
		                          " WHERE \"vcat\" = " + Lit(vcat) + " AND \"vname\" = " + Lit(vname));
		string comment;
		if (comment_value->RowCount() > 0 && !comment_value->GetValue(0, 0).IsNull()) {
			comment = comment_value->GetValue(0, 0).ToString();
		}
		// ALTER keeps the stored schema policy: a declared result is re-declared explicitly, not here
		statements = RelationStatements(*catalog, vcat, vname, new_form, new_phys, new_view, new_rls, new_columns,
		                                comment, string());
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
		config.keys_json = value;
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
	                    Lit(config.role_claim) + ", " + Lit(config.claim_map) + ")"});
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
	catalog->Write({"DELETE FROM " + catalog->Tbl("role_object_caps") + " WHERE \"role\" = " + Lit(role) +
	                    " AND \"vcat\" = " + Lit(vcat) + " AND \"vname\" = " + Lit(vname),
	                "INSERT INTO " + catalog->Tbl("role_object_caps") +
	                    "(\"role\", \"vcat\", \"vname\", \"caps\", \"rls\", \"columns\") VALUES (" + Lit(role) + ", " +
	                    Lit(vcat) + ", " + Lit(vname) + ", " + Lit(caps_json) + ", " + Lit(rls) + ", " + Lit(columns) +
	                    ")"});
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
