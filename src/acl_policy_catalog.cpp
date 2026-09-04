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

#include "acl_policy_catalog.hpp"
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

unique_ptr<MaterializedQueryResult> CatalogBackend::Query(const string &sql) {
	auto instance = Db();
	Connection con(*instance);
	auto result = con.Query(sql);
	if (result->HasError()) {
		throw BinderException("acl catalog: query failed: %s", result->GetError());
	}
	return result;
}

void CatalogBackend::WriteWithReads(
    const std::function<void(const std::function<unique_ptr<MaterializedQueryResult>(const string &)> &,
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
		current = result->GetValue(0, 0).GetValue<int64_t>();
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
		gates.clear();
		claims_cache.clear();
		claims_loaded.clear();
		issuer_cache.clear();
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
	return result->RowCount() == 0 || result->GetValue(0, 0).IsNull() ? string() : result->GetValue(0, 0).ToString();
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

GrantPolicy CatalogBackend::RowPolicy(MaterializedQueryResult &result, idx_t row, idx_t first_column) {
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
	    (function_mode ? "NULL" : "r.\"rls_checked\"") +
	    " AS rchk"
	    " FROM " +
	    RelationsSource(principal, names) + " r JOIN grants g ON g.\"vcat\" = r.\"vcat\"" + oc_join + " WHERE (" +
	    qualified_cond +
	    ") OR (g.\"is_main\" = true AND (SELECT unique_main FROM main_ok) AND r.\"vname\" = " + Lit(unqualified) +
	    // by role, so a principal holding several of them merges their column lists in one
	    // order rather than in whatever order the store returned (spec 036)
	    ") ORDER BY prio, g.\"role\"";
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

void CatalogBackend::ApplyGrantPolicy(const string &vname, const GrantUnion &grants,
                                      vector<std::pair<string, string>> &object_columns, TablePolicy &out) {
	auto predicate = grants.Predicate();
	bool restricts = grants.Restricts();
	out.rls_unchecked = out.rls_unchecked || grants.Unchecked();
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
		vector<string> items;
		for (auto &column : grants.columns) {
			items.push_back(column.second.empty() ? Ident(column.first) : column.second + " AS " + Ident(column.first));
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
	auto listed = grants.columns;
	if (!object_columns.empty()) {
		for (auto &column : listed) {
			bool known = false;
			for (auto &defined : object_columns) {
				if (StringUtil::CIEquals(defined.first, column.first)) {
					known = true;
					break;
				}
			}
			if (!known && !column.second.empty()) {
				throw BinderException("acl: the grant on \"%s\" masks column \"%s\", which the object does not "
				                      "have - a mask that cannot be applied would leave it unprotected",
				                      vname, column.first);
			}
		}
		vector<std::pair<string, string>> ordered;
		for (auto &defined : object_columns) {
			for (auto &column : listed) {
				if (StringUtil::CIEquals(defined.first, column.first)) {
					ordered.push_back(column);
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
			names.push_back(Lit(StringUtil::Lower(column.first)));
			if (!column.second.empty()) {
				replaces.push_back(column.second + " AS " + Ident(column.first));
			}
		}
		string inner = "SELECT *";
		if (!replaces.empty()) {
			inner += " REPLACE (" + StringUtil::Join(replaces, ", ") + ")";
		}
		inner += " FROM " + out.phys;
		if (!out.rls.empty()) {
			inner += " WHERE " + out.rls;
		}
		out.query = "SELECT COLUMNS(lambda __acl_col: lower(__acl_col) IN (" + StringUtil::Join(names, ", ") +
		            ")) FROM (" + inner + ")";
		for (auto &column : listed) {
			if (!out.writable) {
				continue;
			}
			out.write_columns.insert(column.first);
			out.write_order.push_back(column.first);
			if (!column.second.empty()) {
				out.injections.emplace_back(column.first, column.second);
			}
		}
		out.subquery_form = true;
		return;
	}
	for (auto &column : listed) {
		string source = column.first; // what to read the value from, in physical terms
		for (auto &defined : object_columns) {
			if (StringUtil::CIEquals(defined.first, column.first)) {
				source = defined.second.empty() ? defined.first : defined.second;
				break;
			}
		}
		for (auto &rename : out.renames) {
			if (StringUtil::CIEquals(rename.first, column.first)) {
				source = rename.second;
				break;
			}
			if (StringUtil::CIEquals(rename.second, column.first)) {
				throw BinderException("acl: grant on \"%s\" lists column \"%s\", which the object renamed away", vname,
				                      column.first);
			}
		}
		auto expr = column.second.empty() ? source : column.second;
		out.projection.push_back(expr == column.first ? expr : expr + " AS " + Ident(column.first));
		if (!out.writable) {
			continue;
		}
		out.write_columns.insert(source);
		out.write_order.push_back(column.first);
		if (!column.second.empty()) {
			out.injections.emplace_back(source, column.second);
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
			if (result->GetValue(11, row).GetValue<int64_t>() != prio || result->GetValue(0, row).ToString() != vcat) {
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
	for (idx_t row = 0; row < result->RowCount(); row++) {
		if (EffectiveCaps(result->GetValue(0, row)).count(capability)) {
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
		out.phys_schema = !into.IsNull() ? into.ToString() : (phys_path.IsNull() ? out.origin : phys_path.ToString());
		if (out.phys_schema.empty() && !out.virtual_only) {
			continue; // a schema that is neither an alias nor an expansion has nowhere to create
		}
		return true;
	}
	if (result->RowCount() > 0) {
		throw BinderException("acl: %s on schema \"%s\" is not allowed", capability, result->GetValue(1, 0).ToString());
	}
	return false;
}

bool CatalogBackend::FunctionGate(const Principal &principal, const string &name, bool &allowed) {
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

void CatalogBackend::ListIssuers(vector<string> &out) {
	if (function_mode) {
		return;
	}
	EnsureFresh();
	auto result = Query("SELECT \"issuer\" FROM " + Tbl("issuers") + " ORDER BY 1");
	for (idx_t row = 0; row < result->RowCount(); row++) {
		out.push_back(result->GetValue(0, row).ToString());
	}
}

bool CatalogBackend::LookupIssuer(const string &issuer, IssuerConfig &out) {
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
		               " \"jwks_uri\", \"client_id\", \"client_secret\" FROM " +
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
		// spec 064: the node-side OAuth client; the function-driver slot may omit both columns
		if (result->ColumnCount() > base + 7) {
			auto client_id = result->GetValue(base + 6, 0);
			config.client_id = client_id.IsNull() ? string() : client_id.ToString();
			auto client_secret = result->GetValue(base + 7, 0);
			config.client_secret = client_secret.IsNull() ? string() : client_secret.ToString();
		}
	}
	lock_guard<mutex> guard(lock);
	issuer_cache[issuer] = {found, config};
	out = config;
	return found;
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
	for (idx_t row = 0; row < result->RowCount(); row++) {
		auto caps = result->GetValue(1, row);
		auto vcat = result->GetValue(0, row).ToString();
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

void CatalogBackend::MapExternalRoles(const string &issuer, const vector<string> &values,
                                      case_insensitive_map_t<vector<string>> &mapped,
                                      case_insensitive_set_t &known_roles) {
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
	auto result = Query("SELECT \"external_value\", \"role\" FROM " + Tbl("role_mappings") +
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

bool CatalogBackend::ReadText(const string &uri, string &out, string &error) {
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
	if (version != ACL_SCHEMA_VERSION) {
		throw BinderException("acl catalog: \"%s\".\"%s\" is schema version %lld, this build reads %d - apply "
		                      "the matching schema/acl_schema.sql, or let acl_use_db(..., true) create it",
		                      db_name, schema, version, ACL_SCHEMA_VERSION);
	}
}

string CatalogBackend::KeyColumnType() {
	auto result = Query("SELECT \"type\" FROM duckdb_databases() WHERE \"database_name\" = " + Lit(db_name));
	if (result->RowCount() > 0 && !result->GetValue(0, 0).IsNull() &&
	    StringUtil::CIEquals(result->GetValue(0, 0).ToString(), "mssql")) {
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
		throw BinderException("acl catalog: \"%s\".\"%s\" is schema version %lld and this build creates %d - "
		                      "an older catalog is migrated (schema/migrations/v<n>.sql for every version "
		                      "above %lld, in order), not re-initialised",
		                      db_name, schema, stamped, ACL_SCHEMA_VERSION, stamped);
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

PolicyStore::PolicyStore() {
}

PolicyStore::~PolicyStore() {
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

bool PolicyStore::CatalogPrincipalMainCap(const Principal &principal, const string &capability) {
	return catalog->PrincipalMainCap(principal, capability);
}

void PolicyStore::CatalogLoadRoleClaims(Principal &principal) {
	catalog->LoadRoleClaims(principal);
}

bool PolicyStore::CatalogLookupIssuer(const string &issuer, IssuerConfig &out) {
	return catalog->LookupIssuer(issuer, out);
}

void PolicyStore::CatalogListIssuers(vector<string> &out) {
	catalog->ListIssuers(out);
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

int64_t PolicyStore::MaxSessions() {
	if (catalog) {
		return catalog->SettingInt64("acl_max_sessions", 1000); // the registered default (spec 044)
	}
	return 1000;
}

int64_t PolicyStore::PolicyVersion() {
	if (!catalog) {
		return -1;
	}
	lock_guard<mutex> guard(catalog->lock);
	return catalog->version;
}

int64_t PolicyStore::PolicyStalenessSeconds() {
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
		AuditKeys(config.issuer, entry.error.empty(), entry.error);
		lock_guard<mutex> guard(lock);
		jwks_cache[config.issuer] = entry;
	}
	if (entry.keys_json.empty()) {
		NoteDenyReason(Reason::SOURCE_ERROR); // the source of the keys, not the principal, is what failed
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

bool PolicyStore::ResolveDdlTarget(const Principal &principal, const string &vname, const string &capability,
                                   DdlTarget &out) {
	if (!catalog) {
		return false; // the memory store has no schema grants (dev/tests)
	}
	return catalog->DdlTarget(principal, vname, capability, out);
}

} // namespace acl
} // namespace duckdb
