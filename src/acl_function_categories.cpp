// Function categories (spec 072): the model and its resolution. See acl_function_categories.hpp.
#include "acl_function_categories.hpp"

#include "acl_function_seed.hpp"
#include "duckdb/common/helper.hpp"
#include "duckdb/common/string_util.hpp"

#include <algorithm>
#include <cstring>

namespace duckdb {
namespace acl {

bool ParseFunctionKind(const string &text, FunctionKind &out) {
	if (StringUtil::CIEquals(text, "scalar")) {
		out = FunctionKind::SCALAR;
		return true;
	}
	if (StringUtil::CIEquals(text, "table")) {
		out = FunctionKind::TABLE;
		return true;
	}
	return false;
}

string FunctionKey::ToString() const {
	return database + "." + schema + "." + name;
}

string FunctionKey::Serialize() const {
	return StringUtil::Lower(database) + "\x1f" + StringUtil::Lower(schema) + "\x1f" + StringUtil::Lower(name) +
	       "\x1f" + FunctionKindName(kind);
}

bool FunctionNeverCallable(const string &name, const string &database) {
	// the extension's own surface, the lakehouse's, the door's, unity catalog's - and the optimizer's
	// own helpers, which no statement spells by name
	for (auto prefix : {"acl_", "ducklake_", "quack_", "uc_", "__internal_"}) {
		if (StringUtil::StartsWith(name, prefix)) {
			return true;
		}
	}
	// SQL past the rewriter, pointers, generated queries
	static const case_insensitive_set_t NAMES = {
	    "arrow_scan", "arrow_scan_dumb", "seq_scan", "query", "query_table", "json_execute_serialized_sql", "tpch",
	    "tpcds", "sqlsmith", "fuzzyduck", "reduce_sql_statement", "fuzz_all_functions", "scan_data_from_quack_client",
	    // the engine's own: how it invokes, combines and
	    // finalizes, and what a mask says with error()
	    "error", "constant_or_null", "create_sort_key", "invoke", "combine", "finalize", "to_aggregate_state"};
	if (NAMES.count(name)) {
		return true;
	}
	if (FunctionNeverOnlyInSystem(name) && (database.empty() || StringUtil::CIEquals(database, "system"))) {
		return true;
	}
	// a scanner's SQL-under-the-node's-credentials and connection surface: <scanner>_query, _execute,
	// _attach, _clear_cache, and the pool/connection knobs
	static const char *const SCANNERS[] = {"postgres_", "pg_", "mysql_", "mssql_", "sqlite_", "odbc_"};
	static const char *const VERBS[] = {"query",
	                                    "execute",
	                                    "attach",
	                                    "clear_cache",
	                                    "configure_pool",
	                                    "pin_connection",
	                                    "close_pinned_connection",
	                                    "bind_params",
	                                    "create_params"};
	for (auto scanner : SCANNERS) {
		if (!StringUtil::StartsWith(name, scanner)) {
			continue;
		}
		auto rest = name.substr(strlen(scanner));
		for (auto verb : VERBS) {
			if (rest == verb) {
				return true;
			}
		}
	}
	return false;
}

bool FunctionNeverOnlyInSystem(const string &name) {
	// quack's whoami() - the node's identity settings - is the system catalog's; a secrets service's
	// whoami() in its own attached catalog (tresor, spec 082) is not this function
	return name == "whoami";
}

string FunctionDecision::Why(const string &label) const {
	switch (verdict) {
	case FunctionVerdict::ADMITTED:
		return string();
	case FunctionVerdict::NEVER:
		return label + " is not allowed";
	case FunctionVerdict::DENIED:
		return label + " is not allowed" + (category.empty() ? string() : " (category \"" + category + "\" is denied)");
	case FunctionVerdict::NOT_GRANTED:
		return label + " is not allowed: " + key.ToString() + " is in no category granted to this principal";
	case FunctionVerdict::UNCATEGORIZED:
		return label + " is not allowed: it is in no function category";
	case FunctionVerdict::AMBIGUOUS:
		return label + " is ambiguous here: qualify it with its database and schema";
	case FunctionVerdict::UNKNOWN_QUALIFIED:
		return label + " is not allowed: no such function is categorized";
	}
	return label + " is not allowed";
}

void FunctionCategoryModel::AddCategory(const string &name, const string &comment, bool builtin) {
	auto &row = categories[name];
	row.name = name;
	row.comment = comment;
	row.builtin = builtin;
}

bool FunctionCategoryModel::HasCategory(const string &name) const {
	return categories.count(name) > 0;
}

bool FunctionCategoryModel::RemoveCategory(const string &name) {
	if (!categories.erase(name)) {
		return false;
	}
	for (auto by_kind : {&scalars, &tables}) {
		for (auto entry = by_kind->begin(); entry != by_kind->end();) {
			auto &candidates = entry->second;
			for (auto &candidate : candidates) {
				candidate.categories.erase(
				    std::remove_if(candidate.categories.begin(), candidate.categories.end(),
				                   [&](const string &c) { return StringUtil::CIEquals(c, name); }),
				    candidate.categories.end());
			}
			candidates.erase(
			    std::remove_if(candidates.begin(), candidates.end(),
			                   [&](const Candidate &c) { return c.categories.empty() && !NameGranted(c.key); }),
			    candidates.end());
			if (candidates.empty()) {
				entry = by_kind->erase(entry);
			} else {
				entry++;
			}
		}
	}
	for (auto &rule : rules) {
		rule.second.categories_allowed.erase(name);
		rule.second.categories_denied.erase(name);
	}
	return true;
}

optional_ptr<FunctionCategoryModel::Candidate> FunctionCategoryModel::FindCandidate(const FunctionKey &key) {
	auto &by_kind = ByKind(key.kind);
	auto entry = by_kind.find(key.name);
	if (entry == by_kind.end()) {
		return nullptr;
	}
	for (auto &candidate : entry->second) {
		if (StringUtil::CIEquals(candidate.key.database, key.database) &&
		    StringUtil::CIEquals(candidate.key.schema, key.schema)) {
			return &candidate;
		}
	}
	return nullptr;
}

optional_ptr<const FunctionCategoryModel::Candidate>
FunctionCategoryModel::FindCandidate(const FunctionKey &key) const {
	auto &by_kind = ByKind(key.kind);
	auto entry = by_kind.find(key.name);
	if (entry == by_kind.end()) {
		return nullptr;
	}
	for (auto &candidate : entry->second) {
		if (StringUtil::CIEquals(candidate.key.database, key.database) &&
		    StringUtil::CIEquals(candidate.key.schema, key.schema)) {
			return &candidate;
		}
	}
	return nullptr;
}

bool FunctionCategoryModel::AddMember(const string &category, const FunctionKey &key_p) {
	if (!categories.count(category)) {
		AddCategory(category, string(), false);
	}
	FunctionKey key = key_p;
	key.name = StringUtil::Lower(key.name);
	auto existing = FindCandidate(key);
	if (existing) {
		for (auto &c : existing->categories) {
			if (StringUtil::CIEquals(c, category)) {
				return false;
			}
		}
		existing->categories.push_back(category);
		return true;
	}
	Candidate candidate;
	candidate.key = key;
	candidate.categories.push_back(category);
	ByKind(key.kind)[key.name].push_back(std::move(candidate));
	return true;
}

bool FunctionCategoryModel::RemoveMember(const string &category, const FunctionKey &key_p) {
	FunctionKey key = key_p;
	key.name = StringUtil::Lower(key.name);
	auto existing = FindCandidate(key);
	if (!existing) {
		return false;
	}
	auto &cats = existing->categories;
	auto before = cats.size();
	cats.erase(
	    std::remove_if(cats.begin(), cats.end(), [&](const string &c) { return StringUtil::CIEquals(c, category); }),
	    cats.end());
	if (cats.size() == before) {
		return false;
	}
	if (cats.empty()) {
		PruneCandidate(key);
	}
	return true;
}

void FunctionCategoryModel::AddCategoryGrant(const string &role, const string &category, bool allowed) {
	auto &rule = rules[role];
	rule.categories_allowed.erase(category);
	rule.categories_denied.erase(category);
	(allowed ? rule.categories_allowed : rule.categories_denied).insert(category);
}

bool FunctionCategoryModel::NameGranted(const FunctionKey &key) const {
	auto serialized = key.Serialize();
	for (auto &rule : rules) {
		if (rule.second.keys_allowed.count(serialized) || rule.second.keys_denied.count(serialized)) {
			return true;
		}
	}
	return false;
}

void FunctionCategoryModel::PruneCandidate(const FunctionKey &key) {
	// a key that is in no category and named by no grant is no candidate: a bare name that only it
	// could answer reads as uncategorized again
	auto &by_kind = ByKind(key.kind);
	auto entry = by_kind.find(key.name);
	if (entry == by_kind.end()) {
		return;
	}
	auto &candidates = entry->second;
	candidates.erase(
	    std::remove_if(candidates.begin(), candidates.end(),
	                   [&](const Candidate &c) { return c.categories.empty() && c.key == key && !NameGranted(c.key); }),
	    candidates.end());
	if (candidates.empty()) {
		by_kind.erase(entry);
	}
}

void FunctionCategoryModel::AddNameGrant(const string &role, const FunctionKey &key_p, bool allowed) {
	FunctionKey key = key_p;
	key.name = StringUtil::Lower(key.name);
	// a grant by name admits a key in no category (an admin's macro, spec 072), so the key becomes a
	// candidate for the bare name too
	if (!FindCandidate(key)) {
		Candidate candidate;
		candidate.key = key;
		ByKind(key.kind)[key.name].push_back(std::move(candidate));
	}
	auto &rule = rules[role];
	auto serialized = key.Serialize();
	rule.keys_allowed.erase(serialized);
	rule.keys_denied.erase(serialized);
	(allowed ? rule.keys_allowed : rule.keys_denied).insert(serialized);
}

bool FunctionCategoryModel::RemoveCategoryGrant(const string &role, const string &category) {
	auto entry = rules.find(role);
	if (entry == rules.end()) {
		return false;
	}
	auto removed = entry->second.categories_allowed.erase(category) + entry->second.categories_denied.erase(category);
	return removed > 0;
}

bool FunctionCategoryModel::RemoveNameGrant(const string &role, const FunctionKey &key_p) {
	FunctionKey key = key_p;
	key.name = StringUtil::Lower(key.name);
	auto entry = rules.find(role);
	if (entry == rules.end()) {
		return false;
	}
	auto serialized = key.Serialize();
	auto removed = entry->second.keys_allowed.erase(serialized) + entry->second.keys_denied.erase(serialized);
	PruneCandidate(key);
	return removed > 0;
}

namespace {

//! Where a bare name is looked for first: system.main, then system.pg_catalog, then any other system
//! schema (an extension's), then everything else - the order duckdb's own search path has for builtins
int SchemaRank(const FunctionKey &key) {
	if (!StringUtil::CIEquals(key.database, "system")) {
		return 3;
	}
	if (StringUtil::CIEquals(key.schema, "main")) {
		return 0;
	}
	if (StringUtil::CIEquals(key.schema, "pg_catalog")) {
		return 1;
	}
	return 2;
}

} // namespace

void FunctionCategoryModel::Judge(const vector<string> &roles, const Candidate &candidate,
                                  FunctionDecision &out) const {
	out.key = candidate.key;
	auto serialized = candidate.key.Serialize();
	vector<string> everyone = roles;
	everyone.push_back(string());
	// a deny anywhere wins: by name first, then on any category the key sits in
	for (auto &role : everyone) {
		auto entry = rules.find(role);
		if (entry == rules.end()) {
			continue;
		}
		if (entry->second.keys_denied.count(serialized)) {
			out.verdict = FunctionVerdict::DENIED;
			out.decided_by = "name:" + role;
			return;
		}
		for (auto &category : candidate.categories) {
			if (entry->second.categories_denied.count(category)) {
				out.verdict = FunctionVerdict::DENIED;
				out.category = category;
				out.decided_by = "category:" + category + "@" + role;
				return;
			}
		}
	}
	for (auto &role : everyone) {
		auto entry = rules.find(role);
		if (entry == rules.end()) {
			continue;
		}
		if (entry->second.keys_allowed.count(serialized)) {
			out.verdict = FunctionVerdict::ADMITTED;
			out.decided_by = "name:" + role;
			return;
		}
		for (auto &category : candidate.categories) {
			if (entry->second.categories_allowed.count(category)) {
				out.verdict = FunctionVerdict::ADMITTED;
				out.category = category;
				out.decided_by = "category:" + category + "@" + role;
				return;
			}
		}
	}
	out.verdict = FunctionVerdict::NOT_GRANTED;
	out.decided_by = "none";
}

FunctionDecision FunctionCategoryModel::Resolve(const vector<string> &roles, const QualifiedName &written,
                                                FunctionKind kind) const {
	FunctionDecision out;
	auto name = StringUtil::Lower(written.Name().GetIdentifierName());
	out.key.name = name;
	out.key.kind = kind;
	out.key.database = "system";
	out.key.schema = "main";
	if (FunctionNeverCallable(name) && !FunctionNeverOnlyInSystem(name)) {
		out.verdict = FunctionVerdict::NEVER;
		out.decided_by = "never";
		return out;
	}
	// a name that is never only as the system catalog's is judged on the key it resolves to
	auto never_by_key = [&]() {
		if (FunctionNeverCallable(out.key.name, out.key.database)) {
			out.verdict = FunctionVerdict::NEVER;
			out.decided_by = "never";
		}
	};
	auto &by_kind = ByKind(kind);
	auto entry = by_kind.find(name);
	auto &path = written.Path();
	bool qualified = path.size() > 1;
	if (qualified) {
		// as written: `a.b.f` is database a, schema b; `b.f` is schema b of the system catalog first
		// (where every builtin lives), then of any catalog that has such a member
		auto catalog = written.Catalog().GetIdentifierName();
		auto schema = written.Schema().GetIdentifierName();
		optional_ptr<const Candidate> found;
		if (entry != by_kind.end()) {
			for (auto &candidate : entry->second) {
				if (!StringUtil::CIEquals(candidate.key.schema, schema)) {
					continue;
				}
				if (!catalog.empty() && !StringUtil::CIEquals(candidate.key.database, catalog)) {
					continue;
				}
				if (catalog.empty() && !StringUtil::CIEquals(candidate.key.database, "system") && found) {
					continue; // a system member of that schema was found first
				}
				if (!found || (catalog.empty() && StringUtil::CIEquals(candidate.key.database, "system"))) {
					found = &candidate;
				}
			}
			if (!found && catalog.empty()) {
				// `x.f` where x is no schema of a member: duckdb reads it as database x's default schema
				// too (spec 082 - `corp.whoami()` of an attached service)
				for (auto &candidate : entry->second) {
					if (StringUtil::CIEquals(candidate.key.database, schema) &&
					    StringUtil::CIEquals(candidate.key.schema, "main")) {
						found = &candidate;
						break;
					}
				}
			}
		}
		if (!found) {
			out.verdict = FunctionVerdict::UNKNOWN_QUALIFIED;
			out.key.database = catalog;
			out.key.schema = schema;
			out.decided_by = "none";
			return out;
		}
		Judge(roles, *found, out);
		never_by_key();
		return out;
	}
	if (entry == by_kind.end() || entry->second.empty()) {
		out.verdict = FunctionVerdict::UNCATEGORIZED;
		out.decided_by = "none";
		never_by_key(); // a bare name nobody categorized is the system catalog's
		return out;
	}
	// a bare name: the best-ranked candidate; two equally ranked non-system ones are ambiguous
	optional_ptr<const Candidate> best;
	int best_rank = 4;
	bool tie = false;
	for (auto &candidate : entry->second) {
		auto rank = SchemaRank(candidate.key);
		if (rank < best_rank) {
			best = &candidate;
			best_rank = rank;
			tie = false;
		} else if (rank == best_rank && rank == 3) {
			tie = true;
		}
	}
	if (tie) {
		out.verdict = FunctionVerdict::AMBIGUOUS;
		out.decided_by = "none";
		return out;
	}
	Judge(roles, *best, out);
	never_by_key();
	return out;
}

vector<string> FunctionCategoryModel::CategoriesOf(const FunctionKey &key_p) const {
	FunctionKey key = key_p;
	key.name = StringUtil::Lower(key.name);
	auto candidate = FindCandidate(key);
	if (!candidate) {
		return {};
	}
	return candidate->categories;
}

vector<FunctionCategoryModel::CategoryRow> FunctionCategoryModel::Categories() const {
	vector<CategoryRow> out;
	for (auto &entry : categories) {
		out.push_back(entry.second);
	}
	std::sort(out.begin(), out.end(), [](const CategoryRow &a, const CategoryRow &b) { return a.name < b.name; });
	return out;
}

vector<std::pair<string, FunctionKey>> FunctionCategoryModel::Members() const {
	vector<std::pair<string, FunctionKey>> out;
	for (auto by_kind : {&scalars, &tables}) {
		for (auto &entry : *by_kind) {
			for (auto &candidate : entry.second) {
				for (auto &category : candidate.categories) {
					out.emplace_back(category, candidate.key);
				}
			}
		}
	}
	std::sort(out.begin(), out.end(),
	          [](const std::pair<string, FunctionKey> &a, const std::pair<string, FunctionKey> &b) {
		          if (a.first != b.first) {
			          return a.first < b.first;
		          }
		          return a.second.Serialize() < b.second.Serialize();
	          });
	return out;
}

vector<FunctionCategoryModel::GrantRow> FunctionCategoryModel::Grants() const {
	vector<GrantRow> out;
	for (auto &entry : rules) {
		auto emit_categories = [&](const case_insensitive_set_t &set, bool allowed) {
			for (auto &category : set) {
				GrantRow row;
				row.role = entry.first;
				row.category = category;
				row.allowed = allowed;
				out.push_back(std::move(row));
			}
		};
		auto emit_keys = [&](const std::set<string> &set, bool allowed) {
			for (auto &serialized : set) {
				auto parts = StringUtil::Split(serialized, "\x1f");
				if (parts.size() != 4) {
					continue;
				}
				GrantRow row;
				row.role = entry.first;
				row.key.database = parts[0];
				row.key.schema = parts[1];
				row.key.name = parts[2];
				ParseFunctionKind(parts[3], row.key.kind);
				row.allowed = allowed;
				out.push_back(std::move(row));
			}
		};
		emit_categories(entry.second.categories_allowed, true);
		emit_categories(entry.second.categories_denied, false);
		emit_keys(entry.second.keys_allowed, true);
		emit_keys(entry.second.keys_denied, false);
	}
	std::sort(out.begin(), out.end(), [](const GrantRow &a, const GrantRow &b) {
		if (a.role != b.role) {
			return a.role < b.role;
		}
		if (a.category != b.category) {
			return a.category < b.category;
		}
		return a.key.Serialize() < b.key.Serialize();
	});
	return out;
}

idx_t FunctionCategoryModel::MemberCount(const string &category) const {
	idx_t count = 0;
	for (auto by_kind : {&scalars, &tables}) {
		for (auto &entry : *by_kind) {
			for (auto &candidate : entry.second) {
				for (auto &c : candidate.categories) {
					if (StringUtil::CIEquals(c, category)) {
						count++;
					}
				}
			}
		}
	}
	return count;
}

shared_ptr<FunctionCategoryModel> FunctionCategoryModel::Seed() {
	auto model = make_shared_ptr<FunctionCategoryModel>();
	for (auto &category : ACL_FUNCTION_SEED_CATEGORIES) {
		model->AddCategory(category.name, category.comment, true);
		if (category.auto_granted) {
			model->AddCategoryGrant(string(), category.name, true);
		}
	}
	for (auto &member : ACL_FUNCTION_SEED_MEMBERS) {
		FunctionKey key;
		key.database = member.database;
		key.schema = member.schema;
		key.name = member.name;
		ParseFunctionKind(member.kind, key.kind);
		model->AddMember(member.category, key);
	}
	return model;
}

} // namespace acl
} // namespace duckdb
