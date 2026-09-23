// Function categories (spec 072): what a principal may call. A function's key is (database, schema,
// name, kind); a category is a named set of keys; a role holds categories and names by grant, and a
// deny anywhere among a principal's roles wins. The model is built from rows - the policy catalog's
// three tables, or the shipped seed - and is immutable once built: the store swaps a new one in when
// the policy changes. Nothing here touches a database.
#pragma once

#include "duckdb/common/case_insensitive_map.hpp"
#include "duckdb/common/optional_ptr.hpp"
#include "duckdb/common/shared_ptr.hpp"
#include "duckdb/common/string.hpp"
#include "duckdb/common/typedefs.hpp"
#include "duckdb/common/vector.hpp"
#include "duckdb/parser/qualified_name.hpp"

#include <set>
#include <utility>

namespace duckdb {
namespace acl {

//! Whether a function reference is a scalar/aggregate/window (expression position) or a table function
//! (FROM) - the one thing about a call the rewriter knows before bind
enum class FunctionKind : uint8_t { SCALAR, TABLE };

inline const char *FunctionKindName(FunctionKind kind) {
	return kind == FunctionKind::TABLE ? "table" : "scalar";
}

//! Parse 'scalar' / 'table'; false for anything else
bool ParseFunctionKind(const string &text, FunctionKind &out);

struct FunctionKey {
	string database; // 'system' for every builtin and extension function
	string schema;   // 'main', 'pg_catalog', an extension's own schema, or a physical catalog's
	string name;     // lowercased: function names compare case-insensitively
	FunctionKind kind = FunctionKind::SCALAR;

	//! `database.schema.name` - what the refusal names and what the admin sees
	string ToString() const;
	//! `database\x1fschema\x1fname\x1fkind`, the set key
	string Serialize() const;
	bool operator==(const FunctionKey &other) const {
		return kind == other.kind && database == other.database && schema == other.schema && name == other.name;
	}
};

//! The set that is never callable under a principal, whatever the data says: each of these either
//! runs SQL past the rewriter - here or on another server under the node's credentials - or
//! dereferences a pointer. Whoever needs one needs ACL NATIVE, and has it. In code, not in data, so
//! that no grant can re-open one (the review's finding on arrow_scan, kept). `database` is the key's
//! ('' = the system catalog): a few names are never only as the system catalog's - quack's
//! `whoami()` - and an attached catalog's function of that name (tresor's) is categorized like any
//! other (spec 082).
bool FunctionNeverCallable(const string &lowered_name, const string &database = string());
//! Whether `lowered_name` is never callable only as the system catalog's (quack's `whoami`)
bool FunctionNeverOnlyInSystem(const string &lowered_name);

enum class FunctionVerdict : uint8_t {
	ADMITTED,          // call it, qualified to `key`
	NEVER,             // in the never set
	DENIED,            // a deny row - by name or on a category - for one of the roles
	NOT_GRANTED,       // categorized, but no role holds a category of the key or the name
	UNCATEGORIZED,     // no member has this key: a new extension's function, a macro, a name nobody put anywhere
	AMBIGUOUS,         // a bare name with two non-system keys - qualify it
	UNKNOWN_QUALIFIED, // a qualified name that is no member: for the rewriter to treat as a method call
};

struct FunctionDecision {
	FunctionVerdict verdict = FunctionVerdict::UNCATEGORIZED;
	FunctionKey key;   // the key that decided (ADMITTED / DENIED / NOT_GRANTED)
	string category;   // the category that admitted or denied, empty for a name grant
	string decided_by; // `name:<role>`, `category:<cat>@<role>`, `never`, `none` (the admin screen)
	//! The refusal text for the principal: `label` is `function "x"` / `table function "x"` as the
	//! caller shows it; the text adds the key where it helps, never a role
	string Why(const string &label) const;
};

class FunctionCategoryModel {
public:
	struct CategoryRow {
		string name;
		string comment;
		bool builtin = false;
	};
	struct GrantRow {
		string role;
		string category; // set for a category grant
		FunctionKey key; // set for a name grant
		bool allowed = true;
		bool IsCategory() const {
			return !category.empty();
		}
	};

	void AddCategory(const string &name, const string &comment, bool builtin);
	bool RemoveCategory(const string &name); // and its members and grants; false when absent
	bool HasCategory(const string &name) const;
	//! Adds the member (and the category, if unknown, as an operator's); false when already present
	bool AddMember(const string &category, const FunctionKey &key);
	bool RemoveMember(const string &category, const FunctionKey &key);
	//! A grant row: allowed = false is a deny. Replaces a row with the same role and target.
	void AddCategoryGrant(const string &role, const string &category, bool allowed);
	void AddNameGrant(const string &role, const FunctionKey &key, bool allowed);
	bool RemoveCategoryGrant(const string &role, const string &category);
	bool RemoveNameGrant(const string &role, const FunctionKey &key);

	//! Resolve one call for a principal: `written` is the name as the principal wrote it (bare or
	//! qualified), `kind` where it sits. The role '' is implied. Never touches a database.
	FunctionDecision Resolve(const vector<string> &roles, const QualifiedName &written, FunctionKind kind) const;
	//! The categories a key sits in (empty when it is no member)
	vector<string> CategoriesOf(const FunctionKey &key) const;

	// listings, in a stable order
	vector<CategoryRow> Categories() const;
	vector<std::pair<string, FunctionKey>> Members() const;
	vector<GrantRow> Grants() const;
	idx_t MemberCount(const string &category) const;

	//! The shipped categories, members and auto grants (src/acl_function_seed.hpp)
	static shared_ptr<FunctionCategoryModel> Seed();

private:
	struct Candidate {
		FunctionKey key;
		vector<string> categories;
	};
	struct RoleRules {
		case_insensitive_set_t categories_allowed;
		case_insensitive_set_t categories_denied;
		std::set<string> keys_allowed; // FunctionKey::Serialize()
		std::set<string> keys_denied;
	};
	//! The candidates of a bare name, by kind: every key of that name with the categories it sits in
	case_insensitive_map_t<vector<Candidate>> scalars;
	case_insensitive_map_t<vector<Candidate>> tables;
	case_insensitive_map_t<CategoryRow> categories;
	case_insensitive_map_t<RoleRules> rules; // role -> its rows; '' is every role's

	case_insensitive_map_t<vector<Candidate>> &ByKind(FunctionKind kind) {
		return kind == FunctionKind::TABLE ? tables : scalars;
	}
	const case_insensitive_map_t<vector<Candidate>> &ByKind(FunctionKind kind) const {
		return kind == FunctionKind::TABLE ? tables : scalars;
	}
	//! Whether any role's grant names the key (a candidate such a grant made stays while it does)
	bool NameGranted(const FunctionKey &key) const;
	//! Drop the key's candidate when it is in no category and no grant names it
	void PruneCandidate(const FunctionKey &key);
	optional_ptr<Candidate> FindCandidate(const FunctionKey &key);
	optional_ptr<const Candidate> FindCandidate(const FunctionKey &key) const;
	//! The verdict for one candidate over the roles (plus '')
	void Judge(const vector<string> &roles, const Candidate &candidate, FunctionDecision &out) const;
};

} // namespace acl
} // namespace duckdb
