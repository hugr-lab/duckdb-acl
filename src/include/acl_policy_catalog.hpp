// The catalog-DB policy backend (spec 006), shared by the module's translation units: the SQL
// helpers, the grant-union policy types and the CatalogBackend declaration. The read path and the
// PolicyStore delegations are acl_policy_catalog.cpp, the writers acl_catalog_admin.cpp, the
// metadata listings acl_metadata_listing.cpp, the probe/bind validators acl_catalog_validation.cpp.

#pragma once

#include "acl_field_paths.hpp"
#include "acl_policy.hpp"

#include "duckdb/common/exception/binder_exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/types/value.hpp"
#include "duckdb/main/connection.hpp"
#include "duckdb/main/query_result.hpp"
#include "duckdb/main/database.hpp"
#include "yyjson.hpp"

#include <algorithm>
#include <set>

#include <atomic>
#include <chrono>

namespace duckdb {
namespace acl {

class ResultRows;
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
		if (HasFieldPaths(columns) || HasFieldPaths(level)) {
			// spec 102: fields narrow like columns - the levels' trees intersect
			columns = IntersectColumnItems(columns, level);
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
		if (HasFieldPaths(columns) || HasFieldPaths(policy.columns)) {
			// spec 102: the roles' trees unite - a visible field beats a masked one, conflicts refuse
			columns = UniteColumnItems(columns, policy.columns);
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

//! spec 146: the union is per object - rows OR-ed, column lists united independently (spec 011) - so two roles that
//! narrow one object differently unite into cells neither reads: B's columns on A's rows. Every such pair, with the
//! items it adds - names as the policy lists them, never a value or a predicate. A's rows are read whole by A and by
//! every role whose filter is A's or none; an item of B is theirs when one lists it or a column / path above it
//! (spec 102) plainly with nothing masked at or under it, or masks that very item too (two masks of one item are
//! refused). B without a filter, or with A's, adds nothing B does not read itself. `known` = the object's columns
//! (empty: unknown) - an item naming none of them is no cell. Predicates compare as given: the caller normalizes.
//! One pair per set of rows (a filter, named by its first role) and B; at most `max_pairs` + 1 (more = there are more).
inline vector<UnionWidening> RoleUnionWidens(const vector<std::pair<string, GrantPolicy>> &roles,
                                             const vector<string> &known, idx_t max_pairs) {
	struct Seen {
		bool all = false;                      // no list: every column
		vector<std::pair<string, bool>> items; // the list, trimmed: name, masked
		case_insensitive_set_t plain;          // listed as they are
		case_insensitive_set_t masked;         // listed masked
		case_insensitive_set_t above_masked;   // a strict prefix of a masked item
	};
	auto trimmed = [](const string &text) {
		auto name = text;
		StringUtil::Trim(name);
		return name;
	};
	auto prefixes = [](const string &name) {
		vector<string> out;
		for (idx_t i = 1; i < name.size(); i++) {
			if (name[i] == '.' || name[i] == '[') {
				out.push_back(name.substr(0, i));
			}
		}
		return out;
	};
	case_insensitive_set_t known_set(known.begin(), known.end());
	auto head_known = [&](const string &name) {
		auto cut = name.find_first_of(".[");
		return known_set.empty() || known_set.count(cut == string::npos ? name : name.substr(0, cut)) > 0;
	};
	vector<Seen> seen(roles.size());
	vector<string> predicates;
	for (idx_t i = 0; i < roles.size(); i++) {
		auto &policy = roles[i].second;
		predicates.push_back(policy.Predicate());
		seen[i].all = !policy.restricts;
		for (auto &item : policy.columns) {
			auto name = trimmed(item.first);
			seen[i].items.emplace_back(name, !item.second.empty());
			if (item.second.empty()) {
				seen[i].plain.insert(name);
				continue;
			}
			seen[i].masked.insert(name);
			for (auto &prefix : prefixes(name)) {
				seen[i].above_masked.insert(prefix);
			}
		}
	}
	auto covers = [&](const Seen &c, const string &name, bool masked_item) {
		if (c.all) {
			return true;
		}
		bool plain = false;
		for (auto &prefix : prefixes(name)) {
			if (c.masked.count(prefix)) {
				return false; // masked above: what the union shows of it is not what c reads
			}
			plain = plain || c.plain.count(prefix) > 0;
		}
		if (c.masked.count(name)) {
			return masked_item;
		}
		return (plain || c.plain.count(name) > 0) && !c.above_masked.count(name);
	};
	// A's rows are read whole by the roles without a filter (the same for every A: their answer per item is kept) and
	// by those with A's filter
	vector<idx_t> open_readers;
	for (idx_t c = 0; c < roles.size(); c++) {
		if (predicates[c].empty()) {
			if (seen[c].all) {
				return {}; // one role reads every cell of the object
			}
			open_readers.push_back(c);
		}
	}
	case_insensitive_map_t<bool> open_covered[2]; // item -> some open reader covers it, by mask kind
	auto covered_open = [&](const string &name, bool masked_item) {
		auto &memo = open_covered[masked_item ? 1 : 0];
		auto entry = memo.find(name);
		if (entry != memo.end()) {
			return entry->second;
		}
		bool answer = false;
		for (auto c : open_readers) {
			if (covers(seen[c], name, masked_item)) {
				answer = true;
				break;
			}
		}
		memo[name] = answer;
		return answer;
	};
	// a set of rows per filter: the first role holding it (by the caller's order) names it, the open readers' rows
	// are every row
	vector<UnionWidening> out;
	vector<string> classes;
	for (idx_t a = 0; a < roles.size(); a++) {
		if (std::find(classes.begin(), classes.end(), predicates[a]) != classes.end()) {
			continue;
		}
		classes.push_back(predicates[a]);
		vector<idx_t> readers; // the roles with A's filter (with none: the open readers again)
		bool all = false;
		for (idx_t c = 0; c < roles.size(); c++) {
			if (predicates[c] == predicates[a]) {
				readers.push_back(c);
				all = all || seen[c].all;
			}
		}
		if (all) {
			continue; // every column of A's rows is read
		}
		auto covered = [&](const string &name, bool masked_item) {
			if (covered_open(name, masked_item)) {
				return true;
			}
			for (auto c : readers) {
				if (covers(seen[c], name, masked_item)) {
					return true;
				}
			}
			return false;
		};
		for (idx_t b = 0; b < roles.size(); b++) {
			if (predicates[b].empty() || predicates[b] == predicates[a]) {
				continue;
			}
			vector<string> extra;
			if (seen[b].all) {
				for (auto &name : known) {
					if (!covered(name, false)) {
						extra.push_back(name);
					}
				}
				if (known.empty()) {
					extra.push_back("*");
				}
			} else {
				for (auto &item : seen[b].items) {
					if (head_known(item.first) && !covered(item.first, item.second)) {
						extra.push_back(item.first);
					}
				}
			}
			if (!extra.empty()) {
				out.push_back(UnionWidening {roles[a].first, roles[b].first, std::move(extra)});
				if (out.size() > max_pairs) {
					return out; // enough to name: the caller says there are more
				}
			}
		}
	}
	return out;
}

//! spec 148: whether a policy expression's text (an RLS, a mask, a computed column) is exactly one expression - no
//! comment, no alias, nothing written after it (FROM, WHERE, a second statement). The node splices this text into
//! statements (the read, the probes), while a parse of its select list alone (ParseExpressionList, the gates' walk)
//! drops what follows it. `problem` says what is wrong.
bool OneExpression(const string &text, string &problem);
//! spec 148: every non-empty text of a stored policy is one expression (verdicts kept per text) - a probe pastes
//! stored text only then, and a read refuses a policy that holds one that is not
bool StoredExpressionsOk(const vector<string> &texts);
//! spec 148: refuse, where it is written, a policy expression that is not one expression
void RequireOneExpression(const char *what, const string &text);
//! spec 148: a name the memory store pastes as it is written must be one column reference
void RequireColumnName(const char *what, const string &name);

//! Parse a caps JSON object ({"select": true, "insert": false, ...}) into the set of enabled
//! capability names, with duckdb's bundled yyjson. Anything but a flat object of booleans is refused. `strict` (where
//! caps are written, spec 150 stage 3d) also refuses what a reader would read otherwise than this one does: a key
//! named twice (names compare case-insensitively; this one counts any true, a JSON reader takes the last) and a key
//! holding a NUL (this one reads up to it). A stored row keeps its reading - nothing is taken back by itself.
inline case_insensitive_set_t ParseCaps(const string &json, bool strict = false) {
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
		case_insensitive_set_t named;
		while ((key = duckdb_yyjson::yyjson_obj_iter_next(&iter))) {
			auto value = duckdb_yyjson::yyjson_obj_iter_get_val(key);
			if (!duckdb_yyjson::yyjson_is_bool(value)) {
				error = "caps values must be true/false";
				break;
			}
			if (strict) {
				string name(duckdb_yyjson::yyjson_get_str(key), duckdb_yyjson::yyjson_get_len(key));
				if (name.find('\0') != string::npos) {
					error = "a capability's name holds a NUL";
					break;
				}
				if (!named.insert(name).second) {
					error = "caps name \"" + name + "\" twice";
					break;
				}
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
	//! spec 096: writes this node committed - a cache of what the catalog says is stale past one
	std::atomic<uint64_t> local_writes {0};
	//! spec 094: the catalog is newer than this build, inside the window it declares - served from,
	//! never written. Re-judged at every freshness check, so a catalog migrated under a running node
	//! moves it here (or out of service) without a restart.
	std::atomic<bool> compat_read_only {false};
	//! The audit's ear on the source (spec 069): `reloaded` when a version change is adopted, `written`
	//! when a write commits, `source_error` (with the reason) when the source did not answer. Set by
	//! the store that owns the backend; unset = nobody listens.
	std::function<void(const string &detail, const string &reason)> on_policy;
	//! spec 146: the principal's roles united into cells none of them reads (RoleUnionWidens) - the object, the
	//! capability and the pairs, as an audit event the operator watches
	std::function<void(const string &object, const string &capability, const vector<UnionWidening> &pairs)>
	    on_union_widens;
	// result caches, invalidated on a version bump; maps are size-capped by ClearIfOversized().
	// keys carry the principal's sorted role set: the effective policy depends on it.
	static constexpr idx_t CACHE_CAPACITY = 4096;
	std::unordered_map<string, std::pair<bool, TablePolicy>> objects;   // rolesig \x1f written name
	std::unordered_map<string, std::pair<bool, TablePolicy>> functions; // rolesig \x1f kind \x1f name
	//! spec 072: the function categories of this policy version, built from the three tables on first
	//! use and dropped on a version bump; nullptr until then (and always in function mode, for now)
	shared_ptr<const FunctionCategoryModel> function_model;
	case_insensitive_map_t<case_insensitive_map_t<string>> claims_cache; // role -> claims
	case_insensitive_set_t claims_loaded;
	//! spec 095: the identity model of this policy version (issuers, clients, role mappings), read
	//! whole on first use and dropped on a version bump; nullptr until then
	shared_ptr<const IdentityModel> identity_model;
	//! rolesig -> (manage catalogs, acl.admins rows, platform grants); administration statements hit
	//! this per batch
	struct RightsRows {
		std::set<string> catalogs;
		vector<std::pair<string, string>> scopes;
		vector<std::pair<string, bool>> platform; // `<kind>:<object>` -> allowed (spec 117)
	};
	std::unordered_map<string, RightsRows> rights_cache;
	//! spec 147: role (exact, as roles compare) -> whether the policy knows it; a gateway statement asks per claimed
	//! role
	std::unordered_map<string, bool> known_roles_cache;
	case_insensitive_map_t<vector<GrantRow>> fn_grants; // function mode: role -> rows
	case_insensitive_set_t fn_grants_loaded;

	string Tbl(const char *table);

	shared_ptr<DatabaseInstance> Db();

	//! Run one read query on a fresh connection; throws on error
	unique_ptr<QueryResult> Query(const string &sql);

	//! Run a read-modify-write as ONE transaction on ONE connection: `body` receives a query callback
	//! (its reads see the same snapshot the writes commit into) and the statement sink. Without this,
	//! two concurrent ALTERs of the same object read the same pre-image and the second whole-row
	//! rewrite silently discards the first - which can drop an RLS predicate or a column mask.
	void WriteWithReads(const std::function<void(const std::function<unique_ptr<QueryResult>(const string &)> &,
	                                             vector<string> &)> &body);
	//! spec 093: the same transaction, bumping `version_key` of meta instead of policy_version, running
	//! `before_commit` after the writes and before COMMIT (a throw there rolls the write back), and
	//! answering the counter's new value
	int64_t WriteWithReads(const std::function<void(const std::function<unique_ptr<QueryResult>(const string &)> &,
	                                                vector<string> &)> &body,
	                       const char *version_key, const std::function<void(int64_t)> &before_commit);

	//! Run admin write statements + the policy_version bump in one transaction
	void Write(const vector<string> &statements);

	//! spec 116: the stored spelling of a name among `names` (keys) - see PolicyStore::SpellName
	static string Spell(const string &key, const vector<string> &names, bool creating, const char *what);
	string StoredCatalog(const string &vcat, bool creating);
	string StoredName(const string &vcat, const string &key, bool creating);
	//! every stored name (key) of `vcat` under one first part - what Spell reads
	vector<string> NamesUnder(const string &vcat, const string &first_key);
	//! whether a NEW `key` would be a second spelling of a stored name
	static bool CaseSibling(const string &key, const vector<string> &names);
	string StoredReference(const string &vcat, const string &name, bool creating);

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
	string MainCatalog(const Principal &principal);
	vector<string> HeldCatalogs(const Principal &principal); // spec 114, either source mode

	//! The shared query prelude: the principal's grants and the unique-main guard, computed in SQL.
	//! Table mode scans role_catalogs; function mode embeds the prefetched grants as VALUES.
	string GrantsCte(const Principal &principal);

	//! FROM-sources of the resolution queries: a table reference, or a callback invocation whose
	//! literal arguments carry the keys (both name interpretations, the granted catalogs)
	string RelationsSource(const Principal &principal, const vector<string> &names);
	//! spec 099: the casts a relation's read needs - its type facts (columns 14..16 of the lookup)
	//! under its own policy, else the node's; a view's are applied by ApplyGrantPolicy
	void ApplyTypeFacts(ResultRows &row, TablePolicy &out);
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
	//! spec 147: `object_level` / `schema_level` false leave out a level no row of the principal's roles holds (a
	//! listing asks once) - the same chain, without a term that is NULL for every row
	string CapsExpr(const string &name_expr = "r.\"vname\"", const string &vcat_expr = "r.\"vcat\"",
	                bool object_level = true, bool schema_level = true);
	//! Spec 120.2: what decides one role's caps on one object, read with the resolver's own expressions
	//! (CapsExpr's terms, the grants CTE, the object-grant join by key) - never a second reading of the tables
	struct GrantDecisionRow {
		bool granted = false; // the role holds a grant on the catalog
		string level;         // object | schema <path> | catalog
		string schema_path;   // the role_schemas row that decided, when level is a schema
		bool schema_inherited = false;
		case_insensitive_set_t caps; // the effective caps (EffectiveCaps of the coalesce)
		bool main = false;           // MAIN and the role's only MAIN catalog (bare names resolve)
		string catalog_rls, object_rls;
		string catalog_columns, object_columns; // the grants' column lists as stated
	};
	//! one per name of `vnames`, in that order - one query for all of them
	vector<GrantDecisionRow> GrantDecisions(const string &role, const string &vcat, const vector<string> &vnames);
	//! The same visibility test as an object's, written against a `functions f` row instead of a
	//! `relations r` one - a function is granted like any other object of the catalog.
	string FunctionVisibleExpr(bool object_level = true, bool schema_level = true);
	//! spec 098: a virtual function a principal can see - what its `duckdb_functions()` row is built of
	struct VisibleFunction {
		string vcat;
		string vname; // as stored: `name`, or `schema.name` in a nested virtual schema
		string kind;  // 'table' | 'scalar'
		string params;
		Value comment;
		Value returns; // a scalar's declared result type
		//! spec 115: a bare call reaches it (a flat name of the one MAIN catalog) - it then shadows an
		//! engine function of its name and kind; any other is called qualified (`c.f`, `c.a.b.f`)
		bool bare = false;
		//! a table function's declared result columns, in order (spec 115: `acl_function_columns`)
		struct Column {
			string name;
			string type;
			Value nullable;
			Value comment;
		};
		vector<Column> columns;
	};
	vector<VisibleFunction> VisibleFunctions(const Principal &principal);
	//! spec 147: role set -> the functions its listings show (CallableFunctions), whole - a listing of ten thousand
	//! functions would cycle the per-name cache past its capacity on every call; cleared with the other caches
	std::unordered_map<string, shared_ptr<const vector<VisibleFunction>>> callable_cache;

	//! The grant chain's policy columns (spec 011): the catalog grant's and the object grant's own RLS
	//! and column list. The function-driver's slots do not carry them, so it composes to no narrowing.
	string GrantPolicyExprs();
	//! Fold the six policy columns of one result row into the chain of one role. A NULL `rls_checked`
	//! is a row written before spec 027 existed, and counts as unchecked: `acl_refresh_schema` judges
	//! those and fills the verdict in.
	static GrantPolicy RowPolicy(const ResultRows &result_rows, idx_t row, idx_t first_column);

	//! Split a written name into its qualified interpretation; empty head = no qualified branch
	static void SplitName(const string &vname, string &head, string &rest);

	//! spec 145: `capability` - the one a statement exercises on the object (`select` for a read, the verb for a DML
	//! target); the policy is the union of the grant rows that hold it, the caps the union of every row
	bool ResolveTable(const Principal &principal, const string &vname, TablePolicy &out,
	                  const string &capability = "select");

	//! One JOIN resolves the object: both name interpretations, the unique-main guard, the per-role
	//! effective caps (object override beats the catalog default) and the projected columns (as a
	//! list() aggregate) come back in a single result - the engine does the selection.
	bool LookupRelation(const Principal &principal, const string &vname, TablePolicy &out, const string &capability);

	//! Compose the grant chain onto the object's own definition (spec 011). A grant only narrows: its
	//! predicate is AND-ed onto the object's, its column list intersects the object's, and on the
	//! write path its value columns become assignments - so a narrowed table stays writable.
	static void ApplyGrantPolicy(const string &vname, const GrantUnion &grants,
	                             vector<std::pair<string, string>> &object_columns, TablePolicy &out);

	//! The longest granted schema-alias prefix, picked by the query (ORDER BY prefix length);
	//! the matched prefix RENAMEs into the physical schema, the binder validates existence.
	bool LookupSchemaAlias(const Principal &principal, const string &vname, TablePolicy &out, const string &capability);
	//! spec 146: report a union of roles that widens (RoleUnionWidens) through `on_union_widens` - the roles by name,
	//! their predicates normalized (parsed and printed); `known` = the object's columns, empty when unknown
	void NoteUnionWidens(const string &object, const string &capability,
	                     const vector<std::pair<string, GrantPolicy>> &united, const vector<string> &known);

	bool ResolveFunction(const Principal &principal, const string &vname, bool table_kind, TablePolicy &out);
	//! spec 147: many functions by their stored keys at once - ResolveFunction's verdict for each, one query a chunk
	struct VirtualFunctionKey {
		string vcat;
		string vname;
		bool table_kind = true;
	};
	struct ResolvedVirtualFunction {
		bool found = false;
		bool refused = false; // resolving it throws (ResolveFunction's BinderException)
		TablePolicy policy;
	};
	void ResolveFunctions(const Principal &principal, const vector<VirtualFunctionKey> &keys,
	                      vector<ResolvedVirtualFunction> &out);
	//! the resolver's select list for a function's rows (prio as given), and the policy from one function's rows
	string FunctionRowColumns(const string &prio_expr, bool schema_level = true);
	//! spec 147: whether the principal's roles hold any object grant / any schema grant with caps - a level none
	//! holds is left out of a caps chain built for many rows (its term is NULL for every one of them)
	void PrincipalCapsLevels(const Principal &principal, bool &object_level, bool &schema_level);
	void FunctionPolicyFrom(ResultRows &rows, idx_t begin, idx_t end, const string &vname, bool table_kind,
	                        TablePolicy &policy);

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
	//! spec 129: the catalogs on whose grant (any of the principal's roles) `capability` is written explicitly
	vector<string> PrincipalCatalogsWithCap(const Principal &principal, const string &capability);

	//! Where a `CREATE`/`DROP` of `vname` lands for this principal (spec 016). One query: the longest
	//! virtual schema prefix of the name that the principal's roles hold, with the grant that states
	//! the capability - so a schema nobody granted, or granted without it, simply does not answer.
	bool DdlTarget(const Principal &principal, const string &vname, const string &capability, acl::DdlTarget &out);
	bool HeldSchema(const Principal &principal, const string &written, string &vcat, string &path);

	//! The SQL behind a metadata surface (spec 010 part 3): the principal's own catalog, in the shape
	//! duckdb's own metadata has. The shape is not rebuilt by hand - the physical row is joined and its
	//! identity columns are REPLACEd with the virtual ones, so every other column (types, nullability,
	//! whatever duckdb adds next) stays correct for free. Objects without a physical row (a view, a
	//! query-defined function) are added through UNION ALL BY NAME, which fills the rest with NULL.
	//! spec 117: `platform_objects` / `platform_columns` are the system catalog's share (constant CTE bodies,
	//! PlatformListingCtes) - empty when the principal holds nothing on it
	string MetadataListingSql(const Principal &principal, const string &surface,
	                          const string &platform_objects = string(), const string &platform_columns = string(),
	                          const ListingScope &scope = ListingScope());

	//! Targeted gate lookup: only the rows for this name and these roles leave the database ('' as
	//! role means a global row - NULL cannot be part of the primary key). Role-specific rows beat
	//! global rows; among role rows an explicit deny wins.
	//! spec 072: the model of the function categories, or nullptr when this source has none
	shared_ptr<const FunctionCategoryModel> FunctionModel();

	//! spec 085: the merged limits of the principal's resource groups (none in the driver contract)
	ResourceLimits ResourceLimitsOf(const Principal &principal, const string &node_group);
	//! spec 096 addendum: whether `group` is the policy's default group (false in the driver contract)
	bool GroupIsDefault(const string &group);
	void LoadRoleClaims(Principal &principal);

	bool SettingBool(const char *name, bool fallback);

	string SettingString(const char *name, const char *fallback);
	int64_t SettingInt64(const char *name, int64_t fallback);

	//! spec 095: the identity model in force - the three tables, or the function driver's optional
	//! `issuers` / `clients` / `role_mappings` slots (no arguments, the tables' columns in order)
	shared_ptr<const IdentityModel> Identity();
	//! The model from rows already read (the write path reads them inside its own transaction)
	static IdentityModel IdentityFromRows(QueryResult *issuers, QueryResult *clients, QueryResult *mappings);

	//! Load (and cache) every administration source for the principal in one go
	void LoadRights(const Principal &principal, RightsRows &out);

	//! The catalogs the principal may MANAGE: a capability of the catalog grant itself, so a role can
	//! manage many catalogs (and manage one without being able to read it)
	void ManageCatalogs(const Principal &principal, std::set<string> &out);

	//! The admin scopes of the principal's roles; the function-driver may serve them through a slot
	void AdminScopes(const Principal &principal, vector<std::pair<string, string>> &out);
	//! spec 117: the point grants on `platform` of the principal's roles (none through a function driver)
	void PlatformGrants(const Principal &principal, vector<std::pair<string, bool>> &out);

	//! spec 095: which of these values exist as roles (UNMAPPED AS ROLE keeps only those)
	void KnownRoles(const vector<string> &values, case_insensitive_set_t &known_roles);

	//! Bind a template (markers baked to NULL) without reading data, and return its column schema.
	//! Runs on the write path, so introspection later costs nothing; a failure is not fatal - the
	//! object is stored with an unknown schema and `acl_refresh_schema` can try again.
	bool ProbeSchema(const string &sql, bool expression, const vector<string> &param_types,
	                 vector<std::pair<string, string>> &out);
	//! The same probe of a relation's SQL, answering the bound types themselves
	bool ProbeTypes(const string &sql, vector<std::pair<string, LogicalType>> &out);
	//! What both answer from: the template bound once, its columns and their types
	bool ProbeBound(const string &sql, bool expression, const vector<string> &param_types,
	                vector<std::pair<string, LogicalType>> &out);

	//! spec 099: the type facts of one relation - every column of its source (the physical relation,
	//! or a view's output) whose exposed type differs from its own under some policy, as the three
	//! exposed spellings (aliases stripped / enums as VARCHAR / both; NULL where the policy changes
	//! nothing). Deletes the old facts first; a source that does not bind leaves none - the read is then
	//! uncast and described uncast, and the catalog check names the source once it binds.
	vector<string> TypeFactStatements(const string &vcat, const string &vname, const string &form, const string &phys,
	                                  const string &view_sql);
	//! One column's facts: the exposed spellings, empty where the policy changes nothing
	struct TypeFact {
		string column, as_base, as_varchar, as_both;
	};
	//! The facts themselves, probed now; false when the source does not bind
	bool ProbeTypeFacts(const string &form, const string &phys, const string &view_sql, vector<TypeFact> &out);

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
	bool CatalogPredicateChecked(const std::function<unique_ptr<QueryResult>(const string &)> &read, const string &vcat,
	                             const string &rls);

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
	//! spec 094: judge a stamp - this build's version, a newer one inside the window (read only), or
	//! one this build does not read (throws, naming what to do). `on` names the moment for the message.
	void JudgeSchema(int64_t stamped, int64_t min_reader, const char *on);
	//! spec 094: inside a write's transaction - the catalog must be exactly this build's version, or a
	//! whole-row rewrite of an older build drops what a newer step added
	void RequireWritableSchema(Connection &con);
	//! spec 094: take this catalog forward to the build's version with the embedded steps, in one
	//! transaction; answers what it did
	string Migrate();

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
