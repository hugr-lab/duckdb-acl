// The catalog-DB policy backend (spec 006): policy lives in an ATTACHed database, spoken to only in
// standard duckdb dialect (source agnostic). Virtual catalogs (shared object definitions) are
// separated from role grants; caches are keyed by acl.meta's policy_version, re-checked at most once
// per acl_version_check_interval ms. The selection logic lives in SQL: one resolve miss is one JOIN
// over role_catalogs/relations/role_object_caps (columns folded in as a list() aggregate), with the
// qualified-vs-main interpretation and the unique-main guard decided by the query - duckdb's engine
// does the work, base-table filters push down into the scanners. Every table carries a primary key
// (sources without rowids need one for DELETE/UPDATE). Reads open short-lived connections (a stored
// Connection would cycle DatabaseInstance -> config -> store -> connection).
//
// This translation unit is the security-critical read path: the backend's queries and caches, the
// resolution of a principal's names to policy, the function gate, the rights lookups - and the
// PolicyStore methods that delegate to them. The writers, the metadata listings and the validators
// are the other three units of the module (release plan 4.2).

#include "acl_result_rows.hpp"
#include "acl_policy_catalog.hpp"
#include "acl_types.hpp"
#include "acl_placement.hpp"
#include "acl_rewriter.hpp"
#include "acl_schema_sql.hpp"
#include "acl_token.hpp"
#include "duckdb/common/error_data.hpp"

namespace duckdb {
namespace acl {
namespace acl_detail {

string CatalogBackend::Tbl(const char *table) {
	return Ident(db_name) + "." + Ident(schema) + "." + Ident(table);
}

shared_ptr<DatabaseInstance> CatalogBackend::Db() {
	auto instance = db.lock();
	if (!instance) {
		throw BinderException("acl catalog: database instance is gone");
	}
	return instance;
}

unique_ptr<QueryResult> CatalogBackend::Query(const string &sql) {
	auto instance = Db();
	Connection con(*instance);
	auto result = con.Query(sql);
	if (result->HasError()) {
		throw BinderException("acl catalog: query failed: %s", result->GetError());
	}
	return result;
}

void CatalogBackend::WriteWithReads(
    const std::function<void(const std::function<unique_ptr<QueryResult>(const string &)> &, vector<string> &)> &body) {
	WriteWithReads(body, "policy_version", nullptr);
}

int64_t CatalogBackend::WriteWithReads(
    const std::function<void(const std::function<unique_ptr<QueryResult>(const string &)> &, vector<string> &)> &body,
    const char *version_key, const std::function<void(int64_t)> &before_commit) {
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
		RequireWritableSchema(con);
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
	                      " WHERE \"key\" = " +
	                      Lit(version_key));
	if (bump->HasError()) {
		rollback();
		throw BinderException("acl catalog: version bump failed: %s", bump->GetError());
	}
	int64_t version = 0;
	auto read_back =
	    con.Query("SELECT CAST(\"value\" AS BIGINT) FROM " + Tbl("meta") + " WHERE \"key\" = " + Lit(version_key));
	if (read_back->HasError() || read_back->RowCount() != 1) {
		rollback();
		throw BinderException("acl catalog: the catalog has no %s - migrate it (schema/migrations)", version_key);
	}
	version = read_back->Collection().GetValue(0, 0).GetValue<int64_t>();
	if (before_commit) {
		try {
			before_commit(version);
		} catch (...) {
			rollback();
			throw;
		}
	}
	auto commit = con.Query("COMMIT");
	if (commit->HasError()) {
		throw BinderException("acl catalog: %s", commit->GetError());
	}
	lock_guard<mutex> guard(lock);
	checked_once = false;
	local_writes++;
	return version;
}

void CatalogBackend::Write(const vector<string> &statements) {
	if (function_mode) {
		throw BinderException("acl catalog: the function-driver policy source is read-only");
	}
	auto instance = Db();
	Connection con(*instance);
	auto begin = con.Query("BEGIN");
	if (begin->HasError()) {
		throw BinderException("acl catalog: %s", begin->GetError());
	}
	try {
		RequireWritableSchema(con);
	} catch (...) {
		con.Query("ROLLBACK");
		throw;
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
	if (on_policy) {
		on_policy("written", string());
	}
	lock_guard<mutex> guard(lock);
	checked_once = false; // force a version re-read on the next resolve
	local_writes++;
}

int64_t CatalogBackend::CheckIntervalMs() {
	Value value;
	if (Db()->TryGetCurrentSetting("acl_version_check_interval", value) && !value.IsNull()) {
		return value.GetValue<int64_t>();
	}
	return 1000;
}

void CatalogBackend::EnsureFresh() {
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
	int64_t current;
	try {
		auto result = function_mode
		                  ? Query("SELECT * FROM " + Slot("policy_version") + "()")
		                  : Query("SELECT \"value\" FROM " + Tbl("meta") + " WHERE \"key\" = 'policy_version'");
		if (result->RowCount() != 1) {
			throw BinderException("acl catalog: the policy_version source returned %lld rows, expected 1",
			                      result->RowCount());
		}
		current = result->Collection().GetValue(0, 0).GetValue<int64_t>();
		if (!function_mode) {
			// spec 094: a catalog migrated under a running node - into its window (served, never
			// written) or out of it (refused, fail closed)
			auto stamp = Query("SELECT \"key\", \"value\" FROM " + Tbl("meta") +
			                   " WHERE \"key\" IN ('schema_version', 'min_reader_version')");
			int64_t stamped = -1, min_reader = -1;
			for (idx_t row = 0; row < stamp->RowCount(); row++) {
				auto key = stamp->Collection().GetValue(0, row).ToString();
				auto value = std::stoll(stamp->Collection().GetValue(1, row).ToString());
				(key == "schema_version" ? stamped : min_reader) = value;
			}
			JudgeSchema(stamped, min_reader, "at a freshness check");
		}
	} catch (std::exception &ex) {
		// the source did not answer: the statement that asked is refused (fail closed), the refusal
		// names the source rather than the principal, and the node's counters see it (spec 069)
		NoteDenyReason(Reason::SOURCE_ERROR);
		if (on_policy) {
			on_policy("source_error", ErrorData(ex).RawMessage());
		}
		throw;
	}
	lock_guard<mutex> guard(lock);
	if (current != version) {
		if (version != -1 && on_policy) {
			on_policy("reloaded", string()); // a version this node had already adopted was replaced
		}
		version = current;
		objects.clear();
		functions.clear();
		function_model.reset();
		claims_cache.clear();
		claims_loaded.clear();
		identity_model.reset();
		rights_cache.clear();
		fn_grants.clear();
		fn_grants_loaded.clear();
	}
}

string CatalogBackend::RoleSig(const Principal &principal) {
	auto roles = principal.roles;
	std::sort(roles.begin(), roles.end());
	return StringUtil::Join(roles, ",");
}

bool CatalogBackend::HasSlot(const char *slot) {
	return slots.count(slot) > 0;
}

string CatalogBackend::Slot(const char *slot) {
	auto entry = slots.find(slot);
	if (entry == slots.end()) {
		throw BinderException("acl catalog: the function-driver map has no \"%s\" slot", slot);
	}
	return Ident(entry->second);
}

string CatalogBackend::ListLit(const vector<string> &values) {
	if (values.empty()) {
		return "CAST([] AS VARCHAR[])";
	}
	vector<string> quoted;
	for (auto &value : values) {
		quoted.push_back(Lit(value));
	}
	return "[" + StringUtil::Join(quoted, ", ") + "]";
}

vector<CatalogBackend::GrantRow> CatalogBackend::Grants(const vector<string> &roles) {
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
		ResultRows result_rows(*result);
		lock_guard<mutex> guard(lock);
		for (auto &role : missing) {
			fn_grants_loaded.insert(role);
			fn_grants[role];
		}
		for (idx_t row = 0; row < result->RowCount(); row++) {
			GrantRow grant;
			grant.role = result_rows.GetValue(0, row).ToString();
			grant.vcat = result_rows.GetValue(1, row).ToString();
			auto is_main = result_rows.GetValue(2, row);
			grant.is_main = !is_main.IsNull() && is_main.GetValue<bool>();
			auto caps = result_rows.GetValue(3, row);
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

vector<string> CatalogBackend::GrantedCatalogs(const Principal &principal) {
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

string CatalogBackend::GrantsCte(const Principal &principal) {
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
	       "), main_ok AS (SELECT count(DISTINCT \"vcat\") = 1 AS unique_main FROM grants WHERE \"is_main\" = "
	       "true) ";
}

string CatalogBackend::RelationsSource(const Principal &principal, const vector<string> &names) {
	return function_mode ? Slot("relations") + "(" + ListLit(GrantedCatalogs(principal)) + ", " + ListLit(names) + ")"
	                     : Tbl("relations");
}

string CatalogBackend::ColumnsSource(const Principal &principal, const vector<string> &names) {
	return function_mode
	           ? Slot("relation_columns") + "(" + ListLit(GrantedCatalogs(principal)) + ", " + ListLit(names) + ")"
	           : Tbl("relation_columns");
}

string CatalogBackend::AliasesSource(const Principal &principal) {
	// the driver contract keeps its alias-shaped slot (a platform expresses aliases, not comments),
	// so table mode projects the schema table into the same three columns
	return function_mode ? Slot("schema_aliases") + "(" + ListLit(GrantedCatalogs(principal)) + ")"
	                     : "(SELECT \"vcat\", \"path\" AS \"alias_path\", \"phys_path\" FROM " + Tbl("schemas") +
	                           " WHERE \"phys_path\" IS NOT NULL)";
}

string CatalogBackend::FunctionsSource(const Principal &principal, const vector<string> &names) {
	return function_mode ? Slot("functions") + "(" + ListLit(GrantedCatalogs(principal)) + ", " + ListLit(names) + ")"
	                     : Tbl("functions");
}

bool CatalogBackend::FunctionMode() const {
	return function_mode;
}

string CatalogBackend::MetaValue(const char *key) {
	auto result = Query("SELECT \"value\" FROM " + Tbl("meta") + " WHERE \"key\" = " + Lit(key));
	return result->RowCount() == 0 || result->Collection().GetValue(0, 0).IsNull()
	           ? string()
	           : result->Collection().GetValue(0, 0).ToString();
}

bool CatalogBackend::HasObjectCaps() {
	return !function_mode || HasSlot("object_caps");
}

string CatalogBackend::ObjectCapsSource(const Principal &principal, const vector<string> &names) {
	return function_mode ? Slot("object_caps") + "(" + ListLit(principal.roles) + ", " +
	                           ListLit(GrantedCatalogs(principal)) + ", " + ListLit(names) + ")"
	                     : Tbl("role_object_caps");
}

string CatalogBackend::SchemaCapsExpr(const string &name_expr, const string &vcat_expr) {
	if (function_mode) {
		return string(); // the driver contract has no schema level
	}
	return "(SELECT nullif(trim(sc.\"caps\"), '') FROM " + Tbl("role_schemas") +
	       " sc WHERE sc.\"role\" = g.\"role\" AND sc.\"vcat\" = " + vcat_expr + " AND substr(" + name_expr +
	       ", 1, length(sc.\"schema_path\") + 1) = sc.\"schema_path\" || '.'"
	       " ORDER BY length(sc.\"schema_path\") DESC LIMIT 1)";
}

string CatalogBackend::CapsExpr(const string &name_expr, const string &vcat_expr) {
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

string CatalogBackend::FunctionVisibleExpr() {
	auto caps = CapsExpr("f.\"vname\"", "f.\"vcat\"");
	return "(" + caps + " IS NULL OR trim(" + caps + ") = '' OR trim(" + caps + ") <> '{}')";
}

string CatalogBackend::GrantPolicyExprs() {
	return function_mode ? "NULL AS crls, NULL AS ccols, false AS cchk, NULL AS orls, NULL AS ocols,"
	                       " false AS ochk"
	                     : "g.\"rls\" AS crls, g.\"columns\" AS ccols, g.\"rls_checked\" AS cchk,"
	                       " oc.\"rls\" AS orls, oc.\"columns\" AS ocols, oc.\"rls_checked\" AS ochk";
}

GrantPolicy CatalogBackend::RowPolicy(const ResultRows &result_rows, idx_t row, idx_t first_column) {
	auto text = [&](idx_t column) {
		auto value = result_rows.GetValue(column, row);
		return value.IsNull() ? string() : value.ToString();
	};
	auto flag = [&](idx_t column) {
		auto value = result_rows.GetValue(column, row);
		return !value.IsNull() && value.GetValue<bool>();
	};
	GrantPolicy policy;
	policy.Narrow(text(first_column), text(first_column + 1), flag(first_column + 2));     // catalog level
	policy.Narrow(text(first_column + 3), text(first_column + 4), flag(first_column + 5)); // object level
	return policy;
}

void CatalogBackend::SplitName(const string &vname, string &head, string &rest) {
	auto dot = vname.find('.');
	if (dot == string::npos) {
		head.clear();
		rest.clear();
	} else {
		head = vname.substr(0, dot);
		rest = vname.substr(dot + 1);
	}
}

bool CatalogBackend::ResolveTable(const Principal &principal, const string &vname, TablePolicy &out) {
	if (principal.roles.empty()) {
		return false;
	}
	EnsureFresh();
	// spec 099: the node's type settings shape the read, so a SET GLOBAL never serves a stale one
	auto instance = Db();
	auto key = RoleSig(principal) + "\x1f" + vname + "\x1f" + (NodeStripsAliases(*instance) ? "b" : "k") +
	           (NodeEnumsToVarchar(*instance) ? "v" : "k");
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

bool CatalogBackend::LookupRelation(const Principal &principal, const string &vname, TablePolicy &out) {
	string head, rest;
	SplitName(vname, head, rest);
	string qualified_cond =
	    head.empty() ? string("false") : "r.\"vcat\" = " + Lit(head) + " AND r.\"vname\" = " + Lit(rest);
	// An object of the default schema is stored under a bare name, so `main.orders` names the same
	// thing `orders` does. A client that loaded a catalog addresses tables that way - it is what a
	// quack client pushes to the server - and refusing it left a served connection unable to read
	// its own objects (spec 041). The qualified interpretation still wins, so a catalog actually
	// named `main` is unaffected.
	string unqualified = vname;
	if (StringUtil::CIEquals(head, "main")) {
		unqualified = rest;
	}
	vector<string> names = head.empty() ? vector<string> {vname} : vector<string> {vname, rest};
	if (unqualified != vname) {
		names.push_back(unqualified);
	}
	string oc_join = HasObjectCaps() ? " LEFT JOIN " + ObjectCapsSource(principal, names) +
	                                       " oc ON oc.\"role\" = g.\"role\" AND oc.\"vcat\" = r.\"vcat\""
	                                       " AND oc.\"vname\" = r.\"vname\""
	                                 : string();
	auto sql =
	    GrantsCte(principal) + "SELECT r.\"form\", r.\"phys\", r.\"view_sql\", r.\"rls\", " + CapsExpr() +
	    " AS caps, " + GrantPolicyExprs() +
	    ","
	    " CASE WHEN " +
	    qualified_cond +
	    " THEN 1 ELSE 2 END AS prio,"
	    " (SELECT list(struct_pack(cname := c.\"name\", cexpr := c.\"expr\") ORDER BY c.\"pos\") FROM " +
	    ColumnsSource(principal, names) + " c WHERE c.\"vcat\" = r.\"vcat\" AND c.\"vname\" = r.\"vname\") AS cols, " +
	    (function_mode ? "NULL" : "r.\"rls_checked\"") + " AS rchk, " +
	    // spec 099: the relation's type policy and its source's type facts (a driver has neither)
	    (function_mode
	         ? string("NULL, NULL, NULL")
	         : "r.\"alias_types\", r.\"enum_types\", (SELECT list(struct_pack(tcol := t.\"column\","
	           " tbase := t.\"as_base\", tvarchar := t.\"as_varchar\", tboth := t.\"as_both\")) FROM " +
	               Tbl("relation_types") + " t WHERE t.\"vcat\" = r.\"vcat\" AND t.\"vname\" = r.\"vname\")") +
	    " FROM " + RelationsSource(principal, names) + " r JOIN grants g ON g.\"vcat\" = r.\"vcat\"" + oc_join +
	    " WHERE (" + qualified_cond +
	    ") OR (g.\"is_main\" = true AND (SELECT unique_main FROM main_ok) AND r.\"vname\" = " + Lit(unqualified) +
	    // by role, so a principal holding several of them merges their column lists in one
	    // order rather than in whatever order the store returned (spec 036)
	    ") ORDER BY prio, g.\"role\"";
	auto result = Query(sql);
	ResultRows result_rows(*result);
	if (result->RowCount() == 0) {
		return false;
	}
	auto prio = result->Collection().GetValue(11, 0).GetValue<int64_t>();
	auto form = result->Collection().GetValue(0, 0).ToString();
	auto phys = result->Collection().GetValue(1, 0);
	auto view_sql = result->Collection().GetValue(2, 0);
	auto rls = result->Collection().GetValue(3, 0);
	out.phys = phys.IsNull() ? string() : phys.ToString();
	out.query = view_sql.IsNull() ? string() : view_sql.ToString();
	out.rls = rls.IsNull() ? string() : rls.ToString();
	auto rchk = result->Collection().GetValue(13, 0);
	out.rls_unchecked = !out.rls.empty() && (rchk.IsNull() || !rchk.GetValue<bool>());
	out.subquery_form = form != "alias";
	out.writable = form == "alias"; // a real table stays writable, however a grant narrows it
	ApplyTypeFacts(result_rows, out);
	vector<std::pair<string, string>> object_columns;
	auto cols = result->Collection().GetValue(12, 0);
	if (!cols.IsNull() && form != "view") {
		for (auto &item : ListValue::GetChildren(cols)) {
			auto &fields = StructValue::GetChildren(item);
			auto name = fields[0].ToString();
			auto expr = fields[1].IsNull() ? string() : fields[1].ToString();
			if (form == "alias" && !expr.empty()) {
				// the list maps virtual -> physical, and a write maps the name back (spec 010)
				out.renames.emplace_back(name, expr);
			}
			object_columns.emplace_back(name, expr);
		}
	}
	// spec 029: a column list is a projection at every level, whatever it is made of. An alias-form
	// list still maps names back on writes and still leaves the relation writable - what it no
	// longer does is pass the columns it did not list straight through, which is what a list made
	// only of renames used to do while every metadata surface said otherwise.
	if (form == "alias" && !object_columns.empty()) {
		out.subquery_form = true;
		for (auto &column : object_columns) {
			out.write_columns.insert(column.second.empty() ? column.first : column.second);
		}
	}
	// remaining rows of the winning interpretation differ only by role: union their caps, and the
	// policies of their grant chains (spec 011)
	GrantUnion grants;
	for (idx_t row = 0; row < result->RowCount(); row++) {
		if (result_rows.GetValue(11, row).GetValue<int64_t>() != prio) {
			break; // ordered by prio; the losing interpretation starts here
		}
		auto caps = result_rows.GetValue(4, row);
		for (auto &cap : EffectiveCaps(caps)) {
			out.caps.insert(cap);
		}
		grants.Add(RowPolicy(result_rows, row, 5));
	}
	ApplyGrantPolicy(vname, grants, object_columns, out);
	return true;
}

void CatalogBackend::ApplyTypeFacts(ResultRows &row, TablePolicy &out) {
	auto alias_types = row.GetValue(14, 0);
	auto enum_types = row.GetValue(15, 0);
	auto facts = row.GetValue(16, 0);
	if (facts.IsNull()) {
		return;
	}
	auto instance = Db();
	bool strip_alias = alias_types.IsNull() ? NodeStripsAliases(*instance) : alias_types.ToString() == "base";
	bool enums_to_varchar = enum_types.IsNull() ? NodeEnumsToVarchar(*instance) : enum_types.ToString() == "varchar";
	if (!strip_alias && !enums_to_varchar) {
		return;
	}
	idx_t field = strip_alias && enums_to_varchar ? 3 : (strip_alias ? 1 : 2);
	for (auto &item : ListValue::GetChildren(facts)) {
		auto &fields = StructValue::GetChildren(item);
		if (!fields[field].IsNull()) {
			out.casts.emplace_back(fields[0].ToString(), fields[field].ToString());
		}
	}
}

namespace {

//! One column a grant lists (spec 102): shown as it is, masked whole, or narrowed to some of its fields
struct ListedColumn {
	string name;
	string mask;                // masked whole
	unique_ptr<FieldNode> tree; // narrowed: the fields the role reads (and masks within them)

	//! A narrowed column is written through unless its tree steps into list elements (spec 102)
	bool Writable() const {
		return !tree || !HasElementStep(*tree);
	}
	//! The tree as COLUMNS items rooted at `root` - what a write rebuilds it from
	string TreeItems(const string &root) const {
		vector<std::pair<string, string>> items;
		auto copy = tree->Clone();
		copy->name = root;
		SerializeNode(*copy, ColumnTrees::RootName(*copy), items);
		vector<string> parts;
		for (auto &item : items) {
			parts.push_back(item.second.empty() ? item.first : item.first + " = " + item.second);
		}
		return StringUtil::Join(parts, ", ");
	}

	//! What the role reads of the column, over `source` (its value in physical terms)
	string Read(const string &source) const {
		if (tree) {
			return CompileNode(*tree, "(" + source + ")");
		}
		return mask.empty() ? source : mask;
	}
};

vector<ListedColumn> ListColumns(const vector<std::pair<string, string>> &items) {
	vector<ListedColumn> listed;
	for (auto &column : ColumnTrees::From(items).columns) {
		ListedColumn entry;
		entry.name = column->name;
		if (column->masked) {
			entry.mask = column->mask;
		} else if (!column->Plain()) {
			entry.tree = column->Clone();
		}
		listed.push_back(std::move(entry));
	}
	return listed;
}

//! The grant's items over a view's output, where every column is its own source
vector<string> ViewItems(const vector<std::pair<string, string>> &items) {
	vector<string> out;
	for (auto &column : ListColumns(items)) {
		auto read = column.Read(Ident(column.name));
		out.push_back(read == Ident(column.name) ? read : read + " AS " + Ident(column.name));
	}
	return out;
}

} // namespace

void CatalogBackend::ApplyGrantPolicy(const string &vname, const GrantUnion &grants,
                                      vector<std::pair<string, string>> &object_columns, TablePolicy &out) {
	auto predicate = grants.Predicate();
	bool restricts = grants.Restricts();
	out.rls_unchecked = out.rls_unchecked || grants.Unchecked();
	if (!out.query.empty() && !out.casts.empty()) {
		// spec 099: a view's output is cast right above the grant's row filter - the predicate reads
		// the view's own values, the grant's columns and masks the exposed ones
		auto filtered = "SELECT " + TablePolicy::CastItems(out.casts) + " FROM (" + out.query + ") AS __acl_typed" +
		                (predicate.empty() ? "" : " WHERE " + predicate);
		out.casts.clear();
		auto items = ViewItems(grants.columns);
		out.query = restricts ? "SELECT " + StringUtil::Join(items, ", ") + " FROM (" + filtered + ") AS __acl_granted"
		                      : filtered;
		return;
	}
	if (predicate.empty() && !restricts) {
		for (auto &column : object_columns) {
			// the stored name is bare (spec 065 unquotes at parse), so quoting is the emitter's job
			out.projection.push_back(column.second.empty() ? Ident(column.first)
			                                               : column.second + " AS " + Ident(column.first));
		}
		return;
	}
	if (!out.query.empty()) {
		// a view has no column list of its own to intersect: wrap its SQL, so the grant's columns
		// and predicate apply to the view's output
		auto items = ViewItems(grants.columns);
		out.query = "SELECT " + (restricts ? StringUtil::Join(items, ", ") : string("*")) + " FROM (" + out.query +
		            ") AS __acl_granted" + (predicate.empty() ? "" : " WHERE " + predicate);
		return;
	}
	if (!predicate.empty()) {
		out.rls = out.rls.empty() ? predicate : "(" + out.rls + ") AND (" + predicate + ")";
	}
	if (!restricts) {
		for (auto &column : object_columns) {
			out.projection.push_back(column.second.empty() ? Ident(column.first)
			                                               : column.second + " AS " + Ident(column.first));
		}
		out.subquery_form = out.subquery_form || !out.rls.empty();
		return;
	}
	// the visible columns of the relation as the object defines it: its own projection, or - when it
	// declares none - every physical column under its own name. The grant's list is a subset of the
	// object's (checked below), so it replaces what the object allowed rather than adding to it.
	out.write_columns.clear();
	out.write_order.clear();
	// spec 038: where the object states its own columns, the grant is folded into them - in the
	// object's order, so a column's position belongs to the object rather than to whoever asks. A
	// listed name the object does not have is a *bare name* that grants nothing (it intersects
	// away) or a *mask* that cannot be applied (it refuses): protection that is silently skipped
	// is the one failure mode worth refusing over.
	// spec 102: a column may be listed through paths into its fields; the tree compiles to what the
	// role reads, over the column's physical value. A narrowed column is not written through (yet).
	auto listed = ListColumns(grants.columns);
	if (!object_columns.empty()) {
		for (auto &column : listed) {
			bool known = false;
			for (auto &defined : object_columns) {
				if (StringUtil::CIEquals(defined.first, column.name)) {
					known = true;
					break;
				}
			}
			if (!known && (!column.mask.empty() || column.tree)) {
				throw BinderException("acl: the grant on \"%s\" masks column \"%s\", which the object does not "
				                      "have - a mask that cannot be applied would leave it unprotected",
				                      vname, column.name);
			}
		}
		vector<ListedColumn> ordered;
		for (auto &defined : object_columns) {
			for (auto &column : listed) {
				if (StringUtil::CIEquals(defined.first, column.name)) {
					ordered.push_back(std::move(column));
					column.name.clear();
					break;
				}
			}
		}
		listed = std::move(ordered);
	}
	if (object_columns.empty()) {
		// spec 038: the object's own columns are not known here and we do not probe for them - the
		// engine answers while it binds the statement we generate. A mask goes into an inner
		// REPLACE, which errors when the column is not there (a mask that cannot be applied must
		// never be silently skipped); the listed names go into an outer COLUMNS(lambda ...), which
		// keeps what matches and ignores what does not. Both keep the source's own order, which is
		// the object's. The predicate stays inside, so RLS reads physical values, not masked ones.
		vector<string> replaces;
		vector<string> names;
		for (auto &column : listed) {
			names.push_back(Lit(StringUtil::Lower(column.name)));
			if (!column.mask.empty() || column.tree) {
				replaces.push_back(column.Read(Ident(column.name)) + " AS " + Ident(column.name));
			}
		}
		string inner = "SELECT *";
		if (!replaces.empty()) {
			inner += " REPLACE (" + StringUtil::Join(replaces, ", ") + ")";
		}
		inner += out.ReadFrom();
		out.query = "SELECT COLUMNS(lambda __acl_col: lower(__acl_col) IN (" + StringUtil::Join(names, ", ") +
		            ")) FROM (" + inner + ")";
		for (auto &column : listed) {
			if (!out.writable || !column.Writable()) {
				continue;
			}
			out.write_columns.insert(column.name);
			out.write_order.push_back(column.name);
			if (!column.mask.empty()) {
				out.injections.emplace_back(column.name, column.mask);
			}
			if (column.tree) {
				out.field_writes.emplace_back(column.name, column.TreeItems(column.name));
			}
		}
		out.subquery_form = true;
		return;
	}
	for (auto &column : listed) {
		string source = column.name; // what to read the value from, in physical terms
		for (auto &defined : object_columns) {
			if (StringUtil::CIEquals(defined.first, column.name)) {
				source = defined.second.empty() ? defined.first : defined.second;
				break;
			}
		}
		for (auto &rename : out.renames) {
			if (StringUtil::CIEquals(rename.first, column.name)) {
				source = rename.second;
				break;
			}
			if (StringUtil::CIEquals(rename.second, column.name)) {
				throw BinderException("acl: grant on \"%s\" lists column \"%s\", which the object renamed away", vname,
				                      column.name);
			}
		}
		auto expr = column.Read(source);
		out.projection.push_back(expr == column.name ? expr : expr + " AS " + Ident(column.name));
		if (!out.writable || !column.Writable()) {
			continue;
		}
		out.write_columns.insert(source);
		out.write_order.push_back(column.name);
		if (!column.mask.empty()) {
			out.injections.emplace_back(source, column.mask);
		}
		if (column.tree) {
			out.field_writes.emplace_back(source, column.TreeItems(source));
		}
	}
	out.subquery_form = true; // a narrowed read is a projection, so it needs the subquery shape
}

bool CatalogBackend::LookupSchemaAlias(const Principal &principal, const string &vname, TablePolicy &out) {
	string head, rest;
	SplitName(vname, head, rest);
	auto prefix_match = [](const string &path, const string &alias_expr) {
		return "substr(" + path + ", 1, length(" + alias_expr + ") + 1) = " + alias_expr + " || '.'";
	};
	string qualified_cond = head.empty()
	                            ? string("false")
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
	           qualified_cond + ") OR (g.\"is_main\" = true AND (SELECT unique_main FROM main_ok) AND " +
	           prefix_match(Lit(vname), "sa.\"alias_path\"") +
	           ") ORDER BY prio, length(sa.\"alias_path\") DESC, g.\"role\"";
	auto result = Query(sql);
	ResultRows result_rows(*result);
	if (result->RowCount() == 0) {
		return false;
	}
	auto prio = result->Collection().GetValue(10, 0).GetValue<int64_t>();
	auto vcat = result->Collection().GetValue(0, 0).ToString();
	auto alias_path = result->Collection().GetValue(1, 0).ToString();
	auto &path = prio == 1 ? rest : vname;
	out.subquery_form = false;
	out.writable = true; // an aliased schema maps onto real tables
	out.phys = result->Collection().GetValue(2, 0).ToString() + path.substr(alias_path.size());
	// rows of the same winning alias differ only by role: union their caps and grant policies
	GrantUnion grants;
	for (idx_t row = 0; row < result->RowCount(); row++) {
		if (result_rows.GetValue(10, row).GetValue<int64_t>() != prio ||
		    result_rows.GetValue(0, row).ToString() != vcat || result_rows.GetValue(1, row).ToString() != alias_path) {
			continue;
		}
		auto caps = result_rows.GetValue(3, row);
		for (auto &cap : EffectiveCaps(caps)) {
			out.caps.insert(cap);
		}
		grants.Add(RowPolicy(result_rows, row, 4));
	}
	vector<std::pair<string, string>> no_columns;
	ApplyGrantPolicy(vname, grants, no_columns, out);
	return true;
}

bool CatalogBackend::ResolveFunction(const Principal &principal, const string &vname, bool table_kind,
                                     TablePolicy &out) {
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
	           ") OR (g.\"is_main\" = true AND (SELECT unique_main FROM main_ok) AND f.\"vname\" = " + Lit(vname) +
	           ")) ORDER BY prio, g.\"role\"";
	auto result = Query(sql);
	ResultRows result_rows(*result);
	TablePolicy policy;
	bool found = result->RowCount() > 0;
	if (found) {
		auto vcat = result->Collection().GetValue(0, 0).ToString();
		auto form = result->Collection().GetValue(1, 0).ToString();
		auto target = result->Collection().GetValue(2, 0);
		auto template_sql = result->Collection().GetValue(3, 0);
		auto prio = result->Collection().GetValue(11, 0).GetValue<int64_t>();
		policy.subquery_form = form != "alias";
		policy.phys = target.IsNull() ? string() : target.ToString();
		policy.query = template_sql.IsNull() ? string() : template_sql.ToString();
		// rows of the same winning function differ only by role: union their caps (spec 012 - a
		// call is a read, so it needs one) and their grant policies
		GrantUnion grants;
		for (idx_t row = 0; row < result->RowCount(); row++) {
			if (result_rows.GetValue(11, row).GetValue<int64_t>() != prio ||
			    result_rows.GetValue(0, row).ToString() != vcat) {
				continue;
			}
			auto caps = result_rows.GetValue(4, row);
			for (auto &cap : EffectiveCaps(caps)) {
				policy.caps.insert(cap);
			}
			grants.Add(RowPolicy(result_rows, row, 5));
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

void CatalogBackend::ApplyFunctionGrantPolicy(const string &vname, bool table_kind, const GrantUnion &grants,
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
	// spec 038: a function's returns cannot be known without calling it, so the grant is not folded
	// in here but expressed as SQL the engine resolves while binding - the same shape a plain alias
	// gets. A bare name the function does not return intersects away; a mask it cannot apply
	// refuses. Naming and shaping a function's output stays with its declaration in the catalog.
	vector<string> replaces;
	vector<string> names;
	for (auto &column : grants.columns) {
		names.push_back(Lit(StringUtil::Lower(column.first)));
		if (!column.second.empty()) {
			replaces.push_back(column.second + " AS " + Ident(column.first));
		}
	}
	string inner = "SELECT *";
	if (!replaces.empty()) {
		inner += " REPLACE (" + StringUtil::Join(replaces, ", ") + ")";
	}
	inner += " FROM \"__acl_inner\"";
	if (!out.rls.empty()) {
		inner += " WHERE " + out.rls;
	}
	out.wrap_sql = "SELECT COLUMNS(lambda __acl_col: lower(__acl_col) IN (" + StringUtil::Join(names, ", ") +
	               ")) FROM (" + inner + ")";
}

bool CatalogBackend::PrincipalMainCap(const Principal &principal, const string &capability) {
	if (principal.roles.empty()) {
		return false;
	}
	EnsureFresh();
	auto sql = GrantsCte(principal) +
	           "SELECT \"caps\" FROM grants WHERE \"is_main\" = true AND (SELECT unique_main FROM main_ok)";
	auto result = Query(sql);
	ResultRows result_rows(*result);
	for (idx_t row = 0; row < result->RowCount(); row++) {
		if (EffectiveCaps(result_rows.GetValue(0, row)).count(capability)) {
			return true;
		}
	}
	return false;
}

bool CatalogBackend::DdlTarget(const Principal &principal, const string &vname, const string &capability,
                               acl::DdlTarget &out) {
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
	ResultRows result_rows(*result);
	for (idx_t row = 0; row < result->RowCount(); row++) {
		auto caps_value = result_rows.GetValue(4, row);
		if (!EffectiveCaps(caps_value).count(capability)) {
			continue; // this role may not; another role of the principal still might
		}
		auto phys_path = result_rows.GetValue(2, row);
		auto origin = result_rows.GetValue(3, row);
		auto into = result_rows.GetValue(5, row);
		auto only = result_rows.GetValue(6, row);
		out.vcat = result_rows.GetValue(0, row).ToString();
		out.schema_path = result_rows.GetValue(1, row).ToString();
		out.origin = origin.IsNull() ? string() : origin.ToString();
		// an alias shows the physical schema live, so nothing has to be recorded; an expansion
		// shows only its own records, so a new object needs one
		out.needs_record = phys_path.IsNull();
		out.virtual_only = !only.IsNull() && only.GetValue<bool>();
		// the grant chooses where this role creates; without a choice the declaration decides
		out.phys_schema = !into.IsNull() ? into.ToString() : (phys_path.IsNull() ? out.origin : phys_path.ToString());
		if (out.phys_schema.empty() && !out.virtual_only) {
			continue; // a schema that is neither an alias nor an expansion has nowhere to create
		}
		return true;
	}
	if (result->RowCount() > 0) {
		throw BinderException("acl: %s on schema \"%s\" is not allowed", capability,
		                      result->Collection().GetValue(1, 0).ToString());
	}
	return false;
}

shared_ptr<const FunctionCategoryModel> CatalogBackend::FunctionModel() {
	EnsureFresh();
	{
		lock_guard<mutex> guard(lock);
		if (function_model) {
			return function_model;
		}
	}
	if (function_mode && !HasSlot("function_categories")) {
		// a function-driver source without the category slots (spec 072 slice 3): no categories of its
		// own, and the seed decides (the store falls back to it on nullptr). EnableFunctions refused a
		// map that declares only some of the three, so one absent means all absent.
		return nullptr;
	}
	// the three sources, whole: a few thousand rows, read once per policy version. In table mode the
	// tables; in function mode the slots, each a listing with no arguments and the positional
	// contract the tables have.
	auto rows = [&](const char *name, const string &columns) {
		if (function_mode) {
			return Query("SELECT * FROM " + Slot(name) + "()");
		}
		return Query("SELECT " + columns + " FROM " + Tbl(name));
	};
	auto model = make_shared_ptr<FunctionCategoryModel>();
	auto categories = rows("function_categories", "\"category\", \"comment\", \"builtin\"");
	ResultRows categories_rows(*categories);
	for (idx_t row = 0; row < categories->RowCount(); row++) {
		auto builtin = categories_rows.GetValue(2, row);
		model->AddCategory(categories_rows.GetValue(0, row).ToString(), categories_rows.GetValue(1, row).ToString(),
		                   !builtin.IsNull() && builtin.GetValue<bool>());
	}
	auto members = rows("function_category_members", "\"category\", \"database\", \"schema\", \"name\", \"kind\"");
	ResultRows members_rows(*members);
	for (idx_t row = 0; row < members->RowCount(); row++) {
		FunctionKey key;
		key.database = members_rows.GetValue(1, row).ToString();
		key.schema = members_rows.GetValue(2, row).ToString();
		key.name = members_rows.GetValue(3, row).ToString();
		if (!ParseFunctionKind(members_rows.GetValue(4, row).ToString(), key.kind)) {
			continue; // a kind this build does not know is no key it can resolve
		}
		model->AddMember(members_rows.GetValue(0, row).ToString(), key);
	}
	auto grants =
	    rows("function_grants", "\"role\", \"category\", \"database\", \"schema\", \"name\", \"kind\", \"allowed\"");
	ResultRows grants_rows(*grants);
	for (idx_t row = 0; row < grants->RowCount(); row++) {
		auto allowed_value = grants_rows.GetValue(6, row);
		bool allowed = !allowed_value.IsNull() && allowed_value.GetValue<bool>();
		auto role = grants_rows.GetValue(0, row).ToString();
		auto category = grants_rows.GetValue(1, row).ToString();
		if (!category.empty()) {
			model->AddCategoryGrant(role, category, allowed);
			continue;
		}
		FunctionKey key;
		key.database = grants_rows.GetValue(2, row).ToString();
		key.schema = grants_rows.GetValue(3, row).ToString();
		key.name = grants_rows.GetValue(4, row).ToString();
		if (!ParseFunctionKind(grants_rows.GetValue(5, row).ToString(), key.kind)) {
			continue;
		}
		model->AddNameGrant(role, key, allowed);
	}
	lock_guard<mutex> guard(lock);
	if (!function_model) {
		function_model = std::move(model);
	}
	return function_model;
}

void CatalogBackend::LoadRoleClaims(Principal &principal) {
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
		ResultRows result_rows(*result);
		lock_guard<mutex> guard(lock);
		for (auto &role : missing) {
			claims_loaded.insert(role);
			claims_cache[role];
		}
		for (idx_t row = 0; row < result->RowCount(); row++) {
			claims_cache[result_rows.GetValue(0, row).ToString()][result_rows.GetValue(1, row).ToString()] =
			    result_rows.GetValue(2, row).ToString();
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

bool CatalogBackend::SettingBool(const char *name, bool fallback) {
	Value value;
	if (Db()->TryGetCurrentSetting(name, value) && !value.IsNull()) {
		return value.GetValue<bool>();
	}
	return fallback;
}

string CatalogBackend::SettingString(const char *name, const char *fallback) {
	Value value;
	if (Db()->TryGetCurrentSetting(name, value) && !value.IsNull()) {
		return value.ToString();
	}
	return fallback;
}

int64_t CatalogBackend::SettingInt64(const char *name, int64_t fallback) {
	Value value;
	if (Db()->TryGetCurrentSetting(name, value) && !value.IsNull()) {
		return value.GetValue<int64_t>();
	}
	return fallback;
}

namespace {

string Cell(ResultRows &rows, idx_t col, idx_t row) {
	auto value = rows.GetValue(col, row);
	return value.IsNull() ? string() : value.ToString();
}

} // namespace

IdentityModel CatalogBackend::IdentityFromRows(QueryResult *issuers, QueryResult *clients, QueryResult *mappings) {
	IdentityModel model;
	if (issuers) {
		ResultRows rows(*issuers);
		for (idx_t row = 0; row < issuers->RowCount(); row++) {
			IdentityIssuer issuer;
			issuer.name = Cell(rows, 0, row);
			issuer.url = Cell(rows, 1, row);
			issuer.secret_service = Cell(rows, 2, row);
			issuer.secret = Cell(rows, 3, row);
			model.issuers.push_back(std::move(issuer));
		}
	}
	if (clients) {
		ResultRows rows(*clients);
		for (idx_t row = 0; row < clients->RowCount(); row++) {
			IdentityClient client;
			client.name = Cell(rows, 0, row);
			client.issuer = Cell(rows, 1, row);
			client.audiences = ParseStoredList(Cell(rows, 2, row));
			client.azp = ParseStoredList(Cell(rows, 3, row));
			client.conditions = ParseStoredConditions(Cell(rows, 4, row));
			client.roles_from = ParseStoredList(Cell(rows, 5, row));
			client.roles_constant = ParseStoredList(Cell(rows, 6, row));
			client.unmapped_as_role = Cell(rows, 7, row) == "as_role";
			client.attributes = ParseStoredAttributes(Cell(rows, 8, row));
			client.subject = ParseStoredList(Cell(rows, 9, row));
			client.token_type = Cell(rows, 10, row);
			client.client_id = Cell(rows, 11, row);
			client.flows = ParseStoredList(Cell(rows, 12, row));
			client.secret_service = Cell(rows, 13, row);
			client.secret = Cell(rows, 14, row);
			auto implicit = rows.GetValue(15, row);
			client.implicit = !implicit.IsNull() && BooleanValue::Get(implicit.DefaultCastAs(LogicalType::BOOLEAN));
			model.clients.push_back(std::move(client));
		}
	}
	if (mappings) {
		ResultRows rows(*mappings);
		for (idx_t row = 0; row < mappings->RowCount(); row++) {
			IdentityMapping mapping;
			mapping.scope_kind = Cell(rows, 0, row);
			mapping.scope_name = Cell(rows, 1, row);
			mapping.source = Cell(rows, 2, row);
			mapping.external_value = Cell(rows, 3, row);
			mapping.role = Cell(rows, 4, row);
			model.mappings.push_back(std::move(mapping));
		}
	}
	return model;
}

shared_ptr<const IdentityModel> CatalogBackend::Identity() {
	EnsureFresh();
	int64_t read_at = -1;
	{
		lock_guard<mutex> guard(lock);
		if (identity_model) {
			return identity_model;
		}
		read_at = version;
	}
	unique_ptr<QueryResult> issuers, clients, mappings;
	if (function_mode) {
		// optional slots: a source without them trusts no tokens
		if (HasSlot("issuers")) {
			issuers = Query("SELECT * FROM " + Slot("issuers") + "()");
		}
		if (HasSlot("clients")) {
			clients = Query("SELECT * FROM " + Slot("clients") + "()");
		}
		if (HasSlot("role_mappings")) {
			mappings = Query("SELECT * FROM " + Slot("role_mappings") + "()");
		}
	} else {
		issuers = Query("SELECT \"name\", \"url\", \"secret_service\", \"secret\" FROM " + Tbl("issuers") +
		                " ORDER BY \"name\"");
		clients = Query("SELECT \"name\", \"issuer\", \"audiences\", \"azp\", \"requires\", \"roles_from\","
		                " \"roles_constant\", \"unmapped\", \"attributes\", \"subject\", \"token_type\","
		                " \"client_id\", \"flows\", \"secret_service\", \"secret\", \"implicit\" FROM " +
		                Tbl("clients") + " ORDER BY \"issuer\", \"name\"");
		mappings = Query("SELECT \"scope_kind\", \"scope_name\", \"source\", \"external_value\", \"role\" FROM " +
		                 Tbl("role_mappings"));
	}
	auto model = make_shared_ptr<const IdentityModel>(IdentityFromRows(issuers.get(), clients.get(), mappings.get()));
	lock_guard<mutex> guard(lock);
	if (version == read_at) {
		// a reload that adopted a newer version meanwhile must not get an older model cached under it
		identity_model = model;
	}
	return model;
}

void CatalogBackend::LoadRights(const Principal &principal, std::set<string> &catalogs,
                                vector<std::pair<string, string>> &scopes) {
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

void CatalogBackend::ManageCatalogs(const Principal &principal, std::set<string> &out) {
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
	ResultRows result_rows(*result);
	for (idx_t row = 0; row < result->RowCount(); row++) {
		auto caps = result_rows.GetValue(1, row);
		auto vcat = result_rows.GetValue(0, row).ToString();
		if (!vcat.empty() && ParseCaps(caps.IsNull() ? string() : caps.ToString()).count("manage")) {
			out.insert(vcat);
		}
	}
}

void CatalogBackend::AdminScopes(const Principal &principal, vector<std::pair<string, string>> &out) {
	if (principal.roles.empty()) {
		return;
	}
	EnsureFresh();
	unique_ptr<QueryResult> result;
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
	ResultRows result_rows(*result);
	for (idx_t row = 0; row < result->RowCount(); row++) {
		auto vcat = result_rows.GetValue(2, row);
		out.emplace_back(result_rows.GetValue(1, row).ToString(), vcat.IsNull() ? string() : vcat.ToString());
	}
}

void CatalogBackend::KnownRoles(const vector<string> &values, case_insensitive_set_t &known_roles) {
	if (values.empty()) {
		return;
	}
	EnsureFresh();
	if (function_mode) {
		// a raw value is a known role iff the role_catalogs callback grants it anything
		for (auto &grant : Grants(values)) {
			known_roles.insert(grant.role);
		}
		return;
	}
	auto known = Query("SELECT \"role\" FROM " + Tbl("roles") + " WHERE \"role\" IN (" + LitList(values) +
	                   ") UNION SELECT DISTINCT \"role\" FROM " + Tbl("role_catalogs") + " WHERE \"role\" IN (" +
	                   LitList(values) + ")");
	ResultRows known_rows(*known);
	for (idx_t row = 0; row < known->RowCount(); row++) {
		known_roles.insert(known_rows.GetValue(0, row).ToString());
	}
}

string CatalogBackend::ResolveSchemaNames(const string &sql) {
	string out;
	for (idx_t i = 0; i < sql.size();) {
		if (sql[i] == '<') {
			idx_t j = i + 1;
			while (j < sql.size() && ((sql[j] >= 'a' && sql[j] <= 'z') || sql[j] == '_')) {
				j++;
			}
			if (j > i + 1 && j < sql.size() && sql[j] == '>') {
				auto name = sql.substr(i + 1, j - i - 1);
				out += name == "schema" ? Ident(db_name) + "." + Ident(schema) : Tbl(name.c_str());
				i = j + 1;
				continue;
			}
		}
		out += sql[i++];
	}
	return out;
}

void CatalogBackend::RequireSchemaVersion() {
	auto stored = MetaValue("schema_version");
	if (stored.empty()) {
		throw BinderException("acl catalog: \"%s\".\"%s\" has no schema_version - it is not an acl policy "
		                      "schema, or it was applied without the version stamp (see schema/acl_schema.sql)",
		                      db_name, schema);
	}
	int64_t version = 0;
	try {
		version = std::stoll(stored);
	} catch (std::exception &) {
		throw BinderException("acl catalog: \"%s\".\"%s\" has schema_version \"%s\", which is not a number", db_name,
		                      schema, stored);
	}
	int64_t min_reader = -1;
	auto declared = MetaValue("min_reader_version");
	if (!declared.empty()) {
		try {
			min_reader = std::stoll(declared);
		} catch (std::exception &) {
			min_reader = -1;
		}
	}
	JudgeSchema(version, min_reader, "at open");
}

void CatalogBackend::JudgeSchema(int64_t stamped, int64_t min_reader, const char *on) {
	if (stamped < 0) {
		throw BinderException("acl catalog: \"%s\".\"%s\" has no schema_version (%s)", db_name, schema, on);
	}
	if (min_reader < 0) {
		min_reader = stamped; // a catalog from before spec 094 declares no window: exactly its own build
	}
	if (stamped == ACL_SCHEMA_VERSION) {
		compat_read_only = false;
		return;
	}
	if (stamped < ACL_SCHEMA_VERSION) {
		throw BinderException("acl catalog: \"%s\".\"%s\" is schema version %lld and this build reads %d - migrate "
		                      "it first: SELECT acl_migrate_catalog('%s', '%s') on a node of this build (%s)",
		                      db_name, schema, stamped, ACL_SCHEMA_VERSION, db_name, schema, on);
	}
	if (min_reader <= ACL_SCHEMA_VERSION) {
		compat_read_only = true; // a newer catalog inside its window: served from, never written
		return;
	}
	throw BinderException("acl catalog: \"%s\".\"%s\" is schema version %lld, readable from build %lld on, and "
	                      "this build is %d - upgrade the node (%s)",
	                      db_name, schema, stamped, min_reader, ACL_SCHEMA_VERSION, on);
}

void CatalogBackend::RequireWritableSchema(Connection &con) {
	auto result = con.Query("SELECT \"value\" FROM " + Tbl("meta") + " WHERE \"key\" = 'schema_version'");
	if (result->HasError() || result->RowCount() != 1) {
		throw BinderException("acl catalog: the catalog's schema_version cannot be read - nothing is written");
	}
	auto stamped = result->Collection().GetValue(0, 0).ToString();
	if (stamped != std::to_string(ACL_SCHEMA_VERSION)) {
		throw BinderException("acl catalog: \"%s\".\"%s\" is schema version %s and this node's build writes %d - "
		                      "policy is written from a node of the catalog's build (spec 094); this node only "
		                      "serves from it",
		                      db_name, schema, stamped, ACL_SCHEMA_VERSION);
	}
}

string CatalogBackend::Migrate() {
	string stored;
	try {
		stored = MetaValue("schema_version");
	} catch (std::exception &) {
	}
	if (stored.empty()) {
		throw BinderException("acl_migrate_catalog: \"%s\".\"%s\" is not an acl policy schema - acl_use_db(..., "
		                      "true) creates one",
		                      db_name, schema);
	}
	int64_t from = 0;
	try {
		from = std::stoll(stored);
	} catch (std::exception &) {
		throw BinderException("acl_migrate_catalog: schema_version \"%s\" is not a number", stored);
	}
	if (from == ACL_SCHEMA_VERSION) {
		return StringUtil::Format("\"%s\".\"%s\" is already schema version %d", db_name, schema, ACL_SCHEMA_VERSION);
	}
	if (from > ACL_SCHEMA_VERSION) {
		throw BinderException("acl_migrate_catalog: \"%s\".\"%s\" is schema version %lld, newer than this build "
		                      "(%d) - a catalog is only ever migrated forward, by a node of the newer build",
		                      db_name, schema, from, ACL_SCHEMA_VERSION);
	}
	auto instance = Db();
	Connection con(*instance);
	auto begin = con.Query("BEGIN");
	if (begin->HasError()) {
		throw BinderException("acl_migrate_catalog: %s", begin->GetError());
	}
	int64_t at = from;
	int min_reader = static_cast<int>(from);
	try {
		for (auto &step : ACL_SCHEMA_STEPS) {
			if (step.version <= from) {
				continue;
			}
			if (step.version != at + 1) {
				throw BinderException("acl_migrate_catalog: this build carries no step from schema version %lld to "
				                      "%lld - migrate with an older build first",
				                      at, at + 1);
			}
			for (int i = 0; i < step.count; i++) {
				auto result = con.Query(ResolveSchemaNames(step.statements[i]));
				if (result->HasError()) {
					throw BinderException("acl_migrate_catalog: step v%d failed: %s", step.version, result->GetError());
				}
			}
			for (auto sql : {"DELETE FROM " + Tbl("meta") + " WHERE \"key\" = 'min_reader_version'",
			                 "INSERT INTO " + Tbl("meta") + " VALUES ('min_reader_version', '" +
			                     std::to_string(step.min_reader) + "')"}) {
				auto result = con.Query(sql);
				if (result->HasError()) {
					throw BinderException("acl_migrate_catalog: %s", result->GetError());
				}
			}
			at = step.version;
			min_reader = step.min_reader;
		}
		if (at != ACL_SCHEMA_VERSION) {
			throw BinderException("acl_migrate_catalog: the steps end at %lld, this build is %d", at,
			                      ACL_SCHEMA_VERSION);
		}
		auto stamp = con.Query("SELECT \"value\" FROM " + Tbl("meta") + " WHERE \"key\" = 'schema_version'");
		if (stamp->HasError() || stamp->RowCount() != 1 ||
		    stamp->Collection().GetValue(0, 0).ToString() != std::to_string(ACL_SCHEMA_VERSION)) {
			throw BinderException("acl_migrate_catalog: the steps did not stamp schema version %d", ACL_SCHEMA_VERSION);
		}
	} catch (...) {
		con.Query("ROLLBACK");
		throw;
	}
	auto commit = con.Query("COMMIT");
	if (commit->HasError()) {
		throw BinderException("acl_migrate_catalog: %s", commit->GetError());
	}
	return StringUtil::Format("\"%s\".\"%s\" migrated from schema version %lld to %d (readable from build %d on)",
	                          db_name, schema, from, ACL_SCHEMA_VERSION, min_reader);
}

string CatalogBackend::KeyColumnType() {
	auto result = Query("SELECT \"type\" FROM duckdb_databases() WHERE \"database_name\" = " + Lit(db_name));
	if (result->RowCount() > 0 && !result->Collection().GetValue(0, 0).IsNull() &&
	    StringUtil::CIEquals(result->Collection().GetValue(0, 0).ToString(), "mssql")) {
		return "MSSQL_VARCHAR(255)";
	}
	return "VARCHAR";
}

void CatalogBackend::InitSchema() {
	auto instance = Db();
	Connection con(*instance);
	// spec 034: the schema is written down once, in schema/policy_schema.sql; this header is
	// generated from it, so what an operator applies by hand and what the extension creates here are
	// the same statements.
	// an existing stamp is judged BEFORE anything is applied (spec 048 review): `CREATE TABLE IF
	// NOT EXISTS` cannot add a column to a table that already exists, so replaying the schema over
	// an older catalog and re-stamping it claimed a shape the tables do not have - and destroyed
	// the honest refusal RequireSchemaVersion gives. An older catalog takes its steps from
	// schema/migrations/ (v<n>.sql for every version above its own, in order); a newer one belongs
	// to a newer build. An unreadable stamp is repaired below: init is exactly the moment.
	string stored;
	try {
		stored = MetaValue("schema_version");
	} catch (std::exception &) {
		// no meta table to read: a fresh database, which is exactly what init is for
	}
	int64_t stamped = -1;
	try {
		stamped = stored.empty() ? -1 : std::stoll(stored);
	} catch (std::exception &) {
		stamped = -1;
	}
	if (stamped >= 0 && stamped != ACL_SCHEMA_VERSION) {
		// spec 094: an older catalog is migrated, never re-initialised; a newer one inside its window is
		// served as it is (nothing to apply); one outside it is refused
		int64_t min_reader = -1;
		try {
			auto declared = MetaValue("min_reader_version");
			min_reader = declared.empty() ? -1 : std::stoll(declared);
		} catch (std::exception &) {
			min_reader = -1;
		}
		JudgeSchema(stamped, min_reader, "at init");
		return;
	}
	vector<string> ddl;
	for (auto statement : ACL_SCHEMA_SQL) {
		ddl.push_back(ResolveSchemaNames(statement));
	}
	// spec 033: the type key columns are declared with follows the catalog's own kind. duckdb and
	// postgres index a VARCHAR of any length; SQL Server's scanner creates every VARCHAR as
	// NVARCHAR(MAX), which cannot carry an index at all (error 1750), so there they are declared
	// with the scanner's own bounded type instead.
	auto key_type = KeyColumnType();
	for (auto &sql : ddl) {
		sql = StringUtil::Replace(sql, "ACL_KEY_TEXT", key_type);
	}
	for (auto &sql : ddl) {
		auto result = con.Query(sql);
		if (result->HasError()) {
			throw BinderException("acl catalog: init failed at [%s]: %s", sql, result->GetError());
		}
	}
	if (stamped != ACL_SCHEMA_VERSION) { // fresh, or an unreadable stamp being repaired (spec 034)
		auto stamp = con.Query("UPDATE " + Tbl("meta") + " SET \"value\" = '" + std::to_string(ACL_SCHEMA_VERSION) +
		                       "' WHERE \"key\" = 'schema_version'");
		if (stamp->HasError()) {
			throw BinderException("acl catalog: could not stamp the schema version: %s", stamp->GetError());
		}
	}
}

} // namespace acl_detail

using acl_detail::CatalogBackend;
using acl_detail::Lit;

PolicyStore::PolicyStore() : memory_functions(FunctionCategoryModel::Seed()) {
}

PolicyStore::~PolicyStore() {
	// spec 078: every session an observer heard open hears its close - the instance going away ends
	// the ones still open. No audit event: the pipeline may already be gone.
	try {
		{
			lock_guard<mutex> guard(lock);
			for (auto &entry : sessions) {
				session_notices.QueueClose(entry.second.id, "shutdown");
			}
		}
		session_notices.Flush();
	} catch (...) {
		// a destructor never throws; the observers' own failures are already caught per call
	}
}

void PolicyStore::EnableCatalog(DatabaseInstance &db, const string &db_name, const string &schema, bool init) {
	auto backend = make_uniq<CatalogBackend>(db, db_name, schema);
	backend->on_policy = [this](const string &detail, const string &reason) {
		AuditPolicy(detail, reason);
	};
	if (init) {
		backend->InitSchema();
	}
	backend->RequireSchemaVersion(); // spec 034: a schema applied by hand must be the one this build reads
	backend->EnsureFresh();          // validates reachability and the schema before switching over
	lock_guard<mutex> guard(lock);
	catalog = std::move(backend);
	node_load_policy.valid = false; // spec 096: the report's reads were the old source's
}

void PolicyStore::EnableFunctions(DatabaseInstance &db, const string &slots_json) {
	auto slots = acl_detail::ParseStringMap(slots_json);
	auto backend = make_uniq<CatalogBackend>(db, slots);
	backend->on_policy = [this](const string &detail, const string &reason) {
		AuditPolicy(detail, reason);
	};
	// explicit slot map, fail closed at enable (design decision): the core slots are required and
	// every named function must actually be registered
	for (auto required :
	     {"policy_version", "role_catalogs", "relations", "relation_columns", "schema_aliases", "functions"}) {
		if (!backend->HasSlot(required)) {
			throw BinderException("acl_use_functions: required slot \"%s\" is missing", required);
		}
	}
	// spec 072: the three category slots come together or not at all - a source that lists the
	// members but not the grants would read as "nothing is granted", which is a refusal of every
	// function, not a policy anyone wrote
	idx_t category_slots = 0;
	for (auto name : {"function_categories", "function_category_members", "function_grants"}) {
		if (backend->HasSlot(name)) {
			category_slots++;
		}
	}
	if (category_slots != 0 && category_slots != 3) {
		throw BinderException("acl_use_functions: the function category slots (function_categories, "
		                      "function_category_members, function_grants) are declared together or not at all");
	}
	for (auto &slot : slots) {
		auto exists = backend->Query("SELECT count(*) FROM duckdb_functions() WHERE \"function_name\" = " +
		                             acl_detail::Lit(slot.second));
		if (exists->Collection().GetValue(0, 0).GetValue<int64_t>() == 0) {
			throw BinderException("acl_use_functions: slot \"%s\" names an unknown function \"%s\"", slot.first,
			                      slot.second);
		}
	}
	backend->EnsureFresh(); // probes the policy_version callback before switching over
	lock_guard<mutex> guard(lock);
	catalog = std::move(backend);
	node_load_policy.valid = false; // spec 096: the report's reads were the old source's
}

bool PolicyStore::CatalogResolveTable(const Principal &principal, const string &vname, TablePolicy &out) {
	return catalog->ResolveTable(principal, vname, out);
}

bool PolicyStore::CatalogResolveFunction(const Principal &principal, const string &vname, bool table_kind,
                                         TablePolicy &out) {
	return catalog->ResolveFunction(principal, vname, table_kind, out);
}

shared_ptr<const FunctionCategoryModel> PolicyStore::CatalogFunctionModel() {
	return catalog->FunctionModel();
}

bool PolicyStore::CatalogPrincipalMainCap(const Principal &principal, const string &capability) {
	return catalog->PrincipalMainCap(principal, capability);
}

ResourceLimits CatalogBackend::ResourceLimitsOf(const Principal &principal, const string &node_group) {
	ResourceLimits out;
	if (function_mode) {
		if (!node_group.empty()) {
			out.admitted = false;
			out.refusal = "acl: this node's resource group \"" + node_group +
			              "\" cannot be judged - the function-driver policy source has no resource groups";
		}
		return out;
	}
	EnsureFresh();
	static const char *COLUMNS = "g.\"group\", g.\"window_start\", g.\"window_max\", g.\"batch_bytes\", "
	                             "g.\"max_result_rows\", g.\"queue_priority\", g.\"max_sessions\"";
	// ONE read per open (spec 096): every group, whether the principal's roles hold it and whether it is
	// the default - a policy has few groups, and the node's own must be among them to be known
	string bound = "false";
	if (!principal.roles.empty()) {
		vector<string> roles;
		for (auto &role : principal.roles) {
			roles.push_back(Lit(role));
		}
		bound = "EXISTS (SELECT 1 FROM " + Tbl("role_resource_groups") + " rg WHERE rg.\"group\" = g.\"group\" AND " +
		        "rg.\"role\" IN (" + StringUtil::Join(roles, ", ") + "))";
	}
	auto result = Query(string("SELECT ") + COLUMNS + ", " + bound + ", coalesce(g.\"is_default\", false) FROM " +
	                    Tbl("resource_groups") + " g ORDER BY 1");
	ResultRows result_rows(*result);
	vector<vector<Value>> rows;
	vector<Value> default_row;
	bool known = node_group.empty();
	for (idx_t row = 0; row < result_rows.Count(); row++) {
		vector<Value> values;
		for (idx_t col = 0; col < 7; col++) {
			values.push_back(result_rows.GetValue(col, row));
		}
		if (values[0].ToString() == node_group) {
			known = true;
		}
		if (result_rows.GetValue(7, row).GetValue<bool>()) {
			rows.push_back(values);
		}
		if (default_row.empty() && result_rows.GetValue(8, row).GetValue<bool>()) {
			default_row = std::move(values); // the first by name, should a race have left two
		}
	}
	if (rows.empty() && !default_row.empty()) {
		// a principal whose roles are in no group is a member of the default group
		rows.push_back(std::move(default_row));
	}
	vector<string> groups;
	for (auto &row : rows) {
		groups.push_back(row[0].ToString());
	}
	auto placed = Place(node_group, known, groups);
	if (!placed.admitted) {
		out.admitted = false;
		out.refusal = placed.refusal;
		out.groups = groups;
		return out;
	}
	if (!placed.group.empty()) {
		// a node of a group serves the principal as a member of THAT group: its limits, nothing merged
		vector<vector<Value>> chosen;
		for (auto &row : rows) {
			if (row[0].ToString() == placed.group) {
				chosen.push_back(row);
			}
		}
		rows = std::move(chosen);
	}
	// the most generous value per limit: where 0 means unlimited / off, 0 wins; otherwise the largest
	auto generous = [](optional_idx &into, const Value &value, bool zero_is_unlimited) {
		if (value.IsNull()) {
			return;
		}
		auto v = NumericCast<idx_t>(MaxValue<int64_t>(value.GetValue<int64_t>(), 0));
		if (!into.IsValid()) {
			into = v;
		} else if (zero_is_unlimited && (v == 0 || into.GetIndex() == 0)) {
			into = 0;
		} else if (v > into.GetIndex()) {
			into = v;
		}
	};
	bool any_priority = false;
	bool unlimited_sessions = false;
	for (auto &row : rows) {
		auto group = row[0].ToString();
		out.groups.push_back(group);
		generous(out.window_start, row[1], true);
		generous(out.window_max, row[2], true);
		generous(out.batch_bytes, row[3], false);
		generous(out.max_result_rows, row[4], true);
		auto &priority = row[5];
		if (!priority.IsNull()) {
			auto p = priority.GetValue<int64_t>();
			out.queue_priority = any_priority ? MaxValue(out.queue_priority, p) : p;
			any_priority = true;
		}
		// a group that states no max_sessions, or 0, limits nothing: the session is charged to none
		auto &max_sessions = row[6];
		if (max_sessions.IsNull() || max_sessions.GetValue<int64_t>() <= 0) {
			unlimited_sessions = true;
		} else if (!unlimited_sessions) {
			auto m = NumericCast<idx_t>(max_sessions.GetValue<int64_t>());
			if (out.charged.empty() || m > out.charged_max) {
				out.charged = group; // rows come ordered by name: the first of equals keeps it
				out.charged_max = m;
			}
		}
	}
	if (unlimited_sessions) {
		out.charged.clear();
		out.charged_max = 0;
	}
	return out;
}

ResourceLimits PolicyStore::ResolveResourceLimits(const Principal &principal) {
	string node_group;
	{
		Value value;
		auto db = instance.lock();
		if (db && db->TryGetCurrentSetting("acl_node_group", value) && !value.IsNull()) {
			node_group = value.ToString();
		}
	}
	if (!catalog) {
		ResourceLimits out; // memory mode has no groups
		if (!node_group.empty()) {
			out.admitted = false;
			out.refusal = "acl: this node's resource group \"" + node_group +
			              "\" cannot be judged - the in-memory policy has no resource groups";
		}
		return out;
	}
	return catalog->ResourceLimitsOf(principal, node_group);
}

int64_t PolicyStore::MaxResultRowsFor(const string &handle) {
	{
		lock_guard<mutex> guard(lock);
		auto entry = sessions.find(handle);
		if (entry != sessions.end() && entry->second.limits.max_result_rows.IsValid()) {
			return NumericCast<int64_t>(entry->second.limits.max_result_rows.GetIndex());
		}
	}
	return MaxResultRows();
}

void PolicyStore::CatalogLoadRoleClaims(Principal &principal) {
	catalog->LoadRoleClaims(principal);
}

shared_ptr<const IdentityModel> PolicyStore::CatalogIdentity() {
	return catalog->Identity();
}

void PolicyStore::CatalogKnownRoles(const vector<string> &values, case_insensitive_set_t &known_roles) {
	catalog->KnownRoles(values, known_roles);
}

string PolicyStore::ParserOverrideMode() {
	if (!catalog) {
		return "STRICT"; // the memory store has no database handle; it is a dev/test path
	}
	return catalog->SettingString("allow_parser_override_extension", "DEFAULT");
}

//! spec 095: a setting of the instance the store belongs to - what the memory mode reads now that it
//! verifies through discovery like any other (the catalog reads its own the same way)
static bool InstanceSetting(const weak_ptr<DatabaseInstance> &instance, const char *name, Value &out) {
	auto db = instance.lock();
	return db && db->TryGetCurrentSetting(name, out) && !out.IsNull();
}

int64_t PolicyStore::JwtClockSkew() {
	if (catalog) {
		return catalog->SettingInt64("acl_jwt_clock_skew", 60);
	}
	Value value;
	return InstanceSetting(instance, "acl_jwt_clock_skew", value) ? value.GetValue<int64_t>() : 60;
}

int64_t PolicyStore::SessionIdleTimeout() {
	if (catalog) {
		return catalog->SettingInt64("acl_session_idle_timeout", 900);
	}
	return 900;
}

bool PolicyStore::SessionExpEveryUse() {
	// spec 059: 'connect' (default) binds token freshness to session establishment; 'every_use'
	// re-judges exp per use, the pre-059 behaviour. An unknown value fails CLOSED to the stricter
	// mode - the set-callback refuses unknown values loudly, this is the second line of defence.
	// Memory mode (no catalog) cannot read the setting at all, so it KEEPS the pre-059 strict rule
	// rather than silently ignoring an operator's every_use: stricter, and unchanged from before.
	if (!catalog) {
		return true;
	}
	return !StringUtil::CIEquals(catalog->SettingString("acl_session_token_binding", "connect"), "connect");
}

int64_t PolicyStore::MaxIngestRows() {
	if (catalog) {
		return catalog->SettingInt64("acl_max_ingest_rows", 0);
	}
	return 0;
}

int64_t PolicyStore::MaxResultRows() {
	if (catalog) {
		return catalog->SettingInt64("acl_max_result_rows", 0);
	}
	return 0;
}

int64_t PolicyStore::FlightStreamIdleSeconds() {
	if (catalog) {
		return catalog->SettingInt64("acl_flight_stream_idle", 30);
	}
	return 30;
}

int64_t PolicyStore::MaxSessions() {
	if (catalog) {
		return catalog->SettingInt64("acl_max_sessions", 1000); // the registered default (spec 044)
	}
	return 1000;
}

int64_t PolicyStore::PolicyVersion() {
	// the store's lock first: a gauge reader is not a statement, and acl_use_db may be swapping the
	// backend under it (the 2026-09-04 review)
	lock_guard<mutex> store_guard(lock);
	if (!catalog) {
		return -1;
	}
	lock_guard<mutex> guard(catalog->lock);
	return catalog->version;
}

int64_t PolicyStore::PolicyStalenessSeconds() {
	lock_guard<mutex> store_guard(lock);
	if (!catalog) {
		return -1;
	}
	lock_guard<mutex> guard(catalog->lock);
	if (!catalog->checked_once) {
		return -1;
	}
	auto since = std::chrono::steady_clock::now() - catalog->last_check;
	return std::chrono::duration_cast<std::chrono::seconds>(since).count();
}

int64_t PolicyStore::JwksRefreshInterval() {
	if (!catalog) {
		Value value;
		return InstanceSetting(instance, "acl_jwks_refresh_interval", value) ? value.GetValue<int64_t>() : 300;
	}
	return catalog->SettingInt64("acl_jwks_refresh_interval", 300);
}

int64_t PolicyStore::JwksMaxStale() {
	if (!catalog) {
		Value value;
		return InstanceSetting(instance, "acl_jwks_max_stale", value) ? value.GetValue<int64_t>() : 3600;
	}
	return catalog->SettingInt64("acl_jwks_max_stale", 3600);
}

string PolicyStore::JwksLocations() {
	if (!catalog) {
		Value value;
		return InstanceSetting(instance, "acl_jwks_locations", value) ? value.ToString() : "https://";
	}
	return catalog->SettingString("acl_jwks_locations", "https://");
}

//! spec 071: a location is allowed when it starts with one of the operator's prefixes, compared as
//! written - no URL normalisation, so no normalisation bugs; the list is the operator's to shape
bool PolicyStore::JwksLocationAllowed(const string &uri, string &why) {
	// a prefix admits a directory or an origin, and ".." would walk out of either: refused whatever
	// the list says (review: `/etc/acl/jwks/../../tmp/evil.json` passed a textual prefix)
	if (uri.find("..") != string::npos) {
		why = "\"" + uri + "\" contains \"..\", which no location may";
		return false;
	}
	auto setting = JwksLocations();
	for (auto &item : StringUtil::Split(setting, ',')) {
		auto prefix = item;
		StringUtil::Trim(prefix);
		if (!prefix.empty() && StringUtil::StartsWith(uri, prefix)) {
			why.clear();
			return true;
		}
	}
	why = "\"" + uri + "\" is outside acl_jwks_locations (" + setting + ")";
	return false;
}

bool PolicyStore::ResolveDdlTarget(const Principal &principal, const string &vname, const string &capability,
                                   DdlTarget &out) {
	if (!catalog) {
		return false; // the memory store has no schema grants (dev/tests)
	}
	return catalog->DdlTarget(principal, vname, capability, out);
}

} // namespace acl
} // namespace duckdb

namespace duckdb {
namespace acl {

string PolicyStore::CatalogMigrate(DatabaseInstance &db, const string &db_name, const string &schema) {
	acl_detail::CatalogBackend backend(db, db_name, schema);
	auto answer = backend.Migrate();
	lock_guard<mutex> guard(lock);
	if (catalog && !catalog->function_mode && StringUtil::CIEquals(catalog->db_name, db_name) &&
	    StringUtil::CIEquals(catalog->schema, schema)) {
		lock_guard<mutex> catalog_guard(catalog->lock);
		catalog->checked_once = false; // the next statement re-reads the stamp
	}
	return answer;
}

Value PolicyStore::CatalogSchemaState() {
	Value stamped(LogicalType::BIGINT), min_reader(LogicalType::BIGINT);
	string mode = "none";
	if (catalog && !catalog->function_mode) {
		auto version = catalog->MetaValue("schema_version");
		auto declared = catalog->MetaValue("min_reader_version");
		if (!version.empty()) {
			stamped = Value::BIGINT(std::stoll(version));
		}
		min_reader =
		    Value::BIGINT(declared.empty() ? (version.empty() ? 0 : std::stoll(version)) : std::stoll(declared));
		mode = version == std::to_string(ACL_SCHEMA_VERSION) ? "current"
		       : catalog->compat_read_only                   ? "read_only"
		                                                     : "refused";
	}
	child_list_t<Value> children {{"build", Value::BIGINT(ACL_SCHEMA_VERSION)},
	                              {"build_min_reader", Value::BIGINT(ACL_SCHEMA_MIN_READER)},
	                              {"catalog", stamped},
	                              {"min_reader", min_reader},
	                              {"mode", Value(mode)}};
	return Value::STRUCT(std::move(children));
}

} // namespace acl
} // namespace duckdb
