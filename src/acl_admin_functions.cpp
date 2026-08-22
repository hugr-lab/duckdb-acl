#include "duckdb/main/connection.hpp"
#include "acl_admin_functions.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/helper.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/execution/expression_executor_state.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/planner/expression/bound_function_expression.hpp"

namespace duckdb {
namespace acl {
namespace {

//! Retrieve the policy store attached to the currently-executing admin setup function
PolicyStore &StoreOf(ExpressionState &state) {
	return *state.expr.Cast<BoundFunctionExpression>().Function().GetExtraFunctionInfo().Cast<AclScalarInfo>().store;
}

DatabaseInstance &DbOf(ExpressionState &state) {
	return *state.GetContext().db;
}

string Trimmed(string value) {
	StringUtil::Trim(value);
	return value;
}

//! Top-level split: a comma inside quotes or parentheses belongs to an expression, not to the list
vector<string> SplitCsv(const string &csv) {
	vector<string> out;
	for (auto &part : SplitTopLevel(csv, ',')) {
		if (!part.empty()) {
			out.push_back(part);
		}
	}
	return out;
}

case_insensitive_map_t<string> ParseClaims(const string &csv) {
	case_insensitive_map_t<string> claims;
	for (auto &item : SplitCsv(csv)) {
		auto pos = item.find('=');
		if (pos == string::npos) {
			continue;
		}
		claims[Trimmed(item.substr(0, pos))] = Trimmed(item.substr(pos + 1));
	}
	return claims;
}

//! cols_csv items are `name` or `name=expr`; returned as (name, expr) pairs (empty expr = plain)
vector<std::pair<string, string>> ParseColumns(const string &csv) {
	vector<std::pair<string, string>> columns;
	for (auto &item : SplitCsv(csv)) {
		auto pos = item.find('='); // the first '=' separates the name; the rest is the expression
		if (pos == string::npos) {
			columns.emplace_back(item, string());
		} else {
			columns.emplace_back(Trimmed(item.substr(0, pos)), Trimmed(item.substr(pos + 1)));
		}
	}
	return columns;
}

//! The old grant functions carry caps as a csv list; the catalog stores a JSON object
string CapsCsvToJson(const vector<string> &caps) {
	vector<string> items;
	for (auto &cap : caps) {
		items.push_back("\"" + StringUtil::Lower(cap) + "\": true");
	}
	return "{" + StringUtil::Join(items, ", ") + "}";
}

string RequiredArg(DataChunk &args, idx_t col, idx_t row, const char *what, const char *name) {
	auto value = args.GetValue(col, row);
	if (value.IsNull()) {
		throw InvalidInputException("%s: %s must not be NULL", what, name);
	}
	return value.ToString();
}

string OptionalArg(DataChunk &args, idx_t col, idx_t row, const string &fallback) {
	if (col >= args.ColumnCount()) {
		return fallback;
	}
	auto value = args.GetValue(col, row);
	return value.IsNull() ? fallback : value.ToString();
}

//===--------------------------------------------------------------------===//
// Catalog backend control + catalog-model admin functions (spec 006)
//===--------------------------------------------------------------------===//

//! acl_use_db(db_name [, schema [, init]]): switch the store to the catalog backend reading policy
//! Configuring a policy that cannot be enforced is worth saying out loud. The extension turns the
//! override on when it loads, so this fires when something turned it off again - and it fires here,
//! in the admin functions, because they are the only acl_* path duckdb still runs in that state (an
//! `ACL …` statement does not even parse).
void RequireEnforcementEnabled(PolicyStore &store) {
	auto mode = store.ParserOverrideMode();
	if (!StringUtil::CIEquals(mode, "DEFAULT")) {
		return;
	}
	throw BinderException("acl: allow_parser_override_extension is DEFAULT, so no `ACL …` statement is parsed and "
	                      "nothing is enforced - SET GLOBAL allow_parser_override_extension='STRICT' before "
	                      "configuring a policy");
}

//! from the ATTACHed database; init=true creates/migrates the managed schema first.
void AclUseDbFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	RequireEnforcementEnabled(StoreOf(state));
	for (idx_t row = 0; row < args.size(); row++) {
		auto db_name = RequiredArg(args, 0, row, "acl_use_db", "database name");
		auto schema = OptionalArg(args, 1, row, "acl");
		bool init = false;
		if (args.ColumnCount() > 2) {
			auto value = args.GetValue(2, row);
			init = !value.IsNull() && value.GetValue<bool>();
		}
		StoreOf(state).EnableCatalog(DbOf(state), db_name, schema, init);
	}
	result.Reference(Value::BOOLEAN(true), count_t(args.size()));
}

//! acl_use_functions(slot_map_json): switch the store to the function-driver policy source - the
//! contract slots name registered table functions; arguments carry the selection keys (spec 008)
void AclUseFunctionsFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	RequireEnforcementEnabled(StoreOf(state));
	for (idx_t row = 0; row < args.size(); row++) {
		auto map_json = RequiredArg(args, 0, row, "acl_use_functions", "slot map");
		StoreOf(state).EnableFunctions(DbOf(state), map_json);
	}
	result.Reference(Value::BOOLEAN(true), count_t(args.size()));
}

//! What the written statement promised about existence. The legacy `ADD` forms promise nothing and
//! keep upserting; `CREATE` refuses to overwrite, `OR REPLACE` overwrites, `IF NOT EXISTS` skips.
//! Returns false when the write must be skipped (spec 013).
bool AllowWrite(PolicyStore &store, const string &vcat, const string &vname, const string &kind, const string &mode) {
	if (mode.empty() || mode == "upsert" || mode == "replace") {
		return true;
	}
	if (mode != "create" && mode != "skip") {
		throw BinderException("acl admin: unknown write mode \"%s\"", mode);
	}
	if (!store.CatalogObjectExists(vcat, vname, kind)) {
		return true;
	}
	if (mode == "skip") {
		return false;
	}
	throw BinderException("acl admin: \"%s.%s\" already exists - use CREATE OR REPLACE to overwrite it, or "
	                      "CREATE ... IF NOT EXISTS to keep the existing one",
	                      vcat, vname);
}

//! acl_add_reference(vcat, name, from, to [, to_kind, args, pairs, expr, cardinality, optional,
//! join_method, comment, mode]): declare a join path between two objects of the virtual catalog
//! (spec 022). A hint, never enforced. `to_kind` is "relation" (default) or "function"; `args` is the
//! argument substitution of a function end ("param => column, …") and `pairs`/`expr` the join
//! condition, which for a function end names columns of its result.
void AclAddReferenceFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t row = 0; row < args.size(); row++) {
		auto vcat = RequiredArg(args, 0, row, "acl_add_reference", "catalog");
		auto name = RequiredArg(args, 1, row, "acl_add_reference", "name");
		auto from_vname = RequiredArg(args, 2, row, "acl_add_reference", "from");
		auto to_vname = RequiredArg(args, 3, row, "acl_add_reference", "to");
		auto &store = StoreOf(state);
		if (!AllowWrite(store, vcat, name, "reference", OptionalArg(args, 12, row, ""))) {
			continue;
		}
		auto optional_text = OptionalArg(args, 9, row, "");
		store.CatalogAddReference(vcat, name, from_vname, to_vname, OptionalArg(args, 4, row, ""),
		                          OptionalArg(args, 5, row, ""), OptionalArg(args, 6, row, ""),
		                          OptionalArg(args, 7, row, ""), OptionalArg(args, 8, row, ""),
		                          StringUtil::CIEquals(optional_text, "true"), OptionalArg(args, 10, row, ""),
		                          OptionalArg(args, 11, row, ""));
	}
	result.Reference(Value::BOOLEAN(true), count_t(args.size()));
}

//! acl_drop_reference(vcat, name [, mode]): remove a declared join path
void AclDropReferenceFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t row = 0; row < args.size(); row++) {
		auto vcat = RequiredArg(args, 0, row, "acl_drop_reference", "catalog");
		auto name = RequiredArg(args, 1, row, "acl_drop_reference", "name");
		auto &store = StoreOf(state);
		auto mode = OptionalArg(args, 2, row, "");
		if (mode == "skip" && !store.CatalogObjectExists(vcat, name, "reference")) {
			continue;
		}
		if (mode != "skip" && !store.CatalogObjectExists(vcat, name, "reference")) {
			throw BinderException("acl admin: reference \"%s.%s\" does not exist", vcat, name);
		}
		store.CatalogDropReference(vcat, name);
	}
	result.Reference(Value::BOOLEAN(true), count_t(args.size()));
}

//! acl_create_catalog(vcat [, comment]): register a virtual catalog (a shared tree of virtual names)
void AclCreateCatalogFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t row = 0; row < args.size(); row++) {
		auto vcat = RequiredArg(args, 0, row, "acl_create_catalog", "catalog");
		auto &store = StoreOf(state);
		if (!AllowWrite(store, vcat, vcat, "catalog", OptionalArg(args, 2, row, ""))) {
			continue;
		}
		store.CatalogCreate(vcat, OptionalArg(args, 1, row, ""));
	}
	result.Reference(Value::BOOLEAN(true), count_t(args.size()));
}

//! `DROP … IF EXISTS`: nothing to drop is not an error. Any other mode leaves the drop to report a
//! missing target itself, which is what makes a typo visible (spec 010).
bool AllowDrop(PolicyStore &store, const string &vcat, const string &vname, const string &kind, const string &mode) {
	return mode != "skip" || store.CatalogObjectExists(vcat, vname, kind);
}

//! A comment written inline with the object (`… COMMENT '…'`). It is a second write rather than a
//! column of the add: the object's identity is what the add stores, and the comment path (spec 010)
//! already knows where a comment lives for each kind.
void SetInlineComment(PolicyStore &store, const string &vcat, const string &vname, const string &kind,
                      const string &comment) {
	if (comment.empty()) {
		return;
	}
	store.CatalogSetComment(vcat, vname, kind, "", comment);
}

//! acl_add_relation(vcat, vname, phys, cols_csv, rls[, comment, mode]): define a relation inside a
//! virtual catalog; no columns and no RLS -> a writable alias (RENAME), otherwise a read-only subquery
void AclAddRelationFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t row = 0; row < args.size(); row++) {
		auto vcat = RequiredArg(args, 0, row, "acl_add_relation", "catalog");
		auto vname = RequiredArg(args, 1, row, "acl_add_relation", "name");
		auto phys = RequiredArg(args, 2, row, "acl_add_relation", "phys");
		auto columns = ParseColumns(OptionalArg(args, 3, row, ""));
		auto rls = OptionalArg(args, 4, row, "");
		// renaming is not restricting: a pure rename list keeps the relation writable
		auto form = rls.empty() && (columns.empty() || RenameOnlyColumns(columns)) ? "alias" : "subquery";
		auto &store = StoreOf(state);
		if (!AllowWrite(store, vcat, vname, "relation", OptionalArg(args, 6, row, ""))) {
			continue;
		}
		store.CatalogAddRelation(vcat, vname, form, phys, "", rls, columns);
		SetInlineComment(store, vcat, vname, "relation", OptionalArg(args, 5, row, ""));
	}
	result.Reference(Value::BOOLEAN(true), count_t(args.size()));
}

//! acl_add_view(vcat, vname, select_sql): a virtual view (full SQL definition, read-only)
void AclAddViewFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t row = 0; row < args.size(); row++) {
		auto vcat = RequiredArg(args, 0, row, "acl_add_view", "catalog");
		auto vname = RequiredArg(args, 1, row, "acl_add_view", "name");
		auto sql = RequiredArg(args, 2, row, "acl_add_view", "SQL");
		// a declared column list (the CREATE VIEW shape) is stored as-is instead of being probed
		auto &store = StoreOf(state);
		if (!AllowWrite(store, vcat, vname, "relation", OptionalArg(args, 5, row, ""))) {
			continue;
		}
		store.CatalogAddRelation(vcat, vname, "view", "", sql, "", {}, OptionalArg(args, 3, row, ""));
		SetInlineComment(store, vcat, vname, "relation", OptionalArg(args, 4, row, ""));
	}
	result.Reference(Value::BOOLEAN(true), count_t(args.size()));
}

//! acl_add_schema_alias(vcat, alias_path, phys_path): expose a whole physical schema under a virtual
//! prefix; any name below it RENAMEs in place, existence is the binder's business
void AclAddSchemaAliasFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t row = 0; row < args.size(); row++) {
		auto vcat = RequiredArg(args, 0, row, "acl_add_schema_alias", "catalog");
		auto alias = RequiredArg(args, 1, row, "acl_add_schema_alias", "alias path");
		auto phys = RequiredArg(args, 2, row, "acl_add_schema_alias", "phys path");
		auto &store = StoreOf(state);
		if (!AllowWrite(store, vcat, alias, "schema", OptionalArg(args, 4, row, ""))) {
			continue;
		}
		store.CatalogAddSchemaAlias(vcat, alias, phys);
		SetInlineComment(store, vcat, alias, "schema", OptionalArg(args, 3, row, ""));
	}
	result.Reference(Value::BOOLEAN(true), count_t(args.size()));
}

//! acl_register_created(vcat, vname, phys, origin): the one write a principal's own DDL performs
//! (spec 016). Deliberately narrow - it can only add an alias-form record for an object that was just
//! created, with no form, projection or policy to choose - and it is unreachable from a principal's
//! query, where every acl_* name is denied (spec 009).
void AclRegisterCreatedFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t row = 0; row < args.size(); row++) {
		auto vcat = RequiredArg(args, 0, row, "acl_register_created", "catalog");
		auto vname = RequiredArg(args, 1, row, "acl_register_created", "name");
		auto phys = RequiredArg(args, 2, row, "acl_register_created", "phys");
		StoreOf(state).CatalogRegisterCreated(vcat, vname, phys, OptionalArg(args, 3, row, ""));
	}
	result.Reference(Value::BOOLEAN(true), count_t(args.size()));
}

//! acl_register_view(vcat, vname, body): the write a role's own CREATE VIEW performs (spec 018) -
//! the body as written, in virtual names, and nothing else to choose
void AclRegisterViewFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t row = 0; row < args.size(); row++) {
		auto vcat = RequiredArg(args, 0, row, "acl_register_view", "catalog");
		auto vname = RequiredArg(args, 1, row, "acl_register_view", "name");
		auto body = RequiredArg(args, 2, row, "acl_register_view", "body");
		StoreOf(state).CatalogRegisterView(vcat, vname, body);
	}
	result.Reference(Value::BOOLEAN(true), count_t(args.size()));
}

//! acl_register_existing(vcat, vname, phys, origin): the VIRTUAL ONLY form of the above - it records
//! an object that must already exist physically, and refuses if it does not (spec 016)
void AclRegisterExistingFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t row = 0; row < args.size(); row++) {
		auto vcat = RequiredArg(args, 0, row, "acl_register_existing", "catalog");
		auto vname = RequiredArg(args, 1, row, "acl_register_existing", "name");
		auto phys = RequiredArg(args, 2, row, "acl_register_existing", "phys");
		auto &store = StoreOf(state);
		if (!store.PhysicalObjectExists(phys)) {
			throw BinderException("acl: \"%s\" does not exist - this role may register objects, not create them "
			                      "(VIRTUAL ONLY)",
			                      phys);
		}
		store.CatalogRegisterCreated(vcat, vname, phys, OptionalArg(args, 3, row, ""));
	}
	result.Reference(Value::BOOLEAN(true), count_t(args.size()));
}

//! acl_grant_schema(role, vcat, path, caps_json[, comment]) / acl_revoke_schema(role, vcat, path):
//! the middle level of the grant chain (spec 015) - capabilities only, materialised down the subtree
void AclGrantSchemaFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t row = 0; row < args.size(); row++) {
		auto role = RequiredArg(args, 0, row, "acl_grant_schema", "role");
		auto vcat = RequiredArg(args, 1, row, "acl_grant_schema", "catalog");
		auto path = RequiredArg(args, 2, row, "acl_grant_schema", "schema path");
		auto &store = StoreOf(state);
		store.CatalogEnsureGrant(role, vcat, false);
		bool virtual_only = false;
		if (args.ColumnCount() > 6) {
			auto value = args.GetValue(6, row);
			virtual_only = !value.IsNull() && value.GetValue<bool>();
		}
		store.CatalogGrantSchema(role, vcat, path, OptionalArg(args, 3, row, ""), OptionalArg(args, 4, row, ""),
		                         OptionalArg(args, 5, row, ""), virtual_only);
	}
	result.Reference(Value::BOOLEAN(true), count_t(args.size()));
}

void AclRevokeSchemaFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t row = 0; row < args.size(); row++) {
		auto role = RequiredArg(args, 0, row, "acl_revoke_schema", "role");
		auto vcat = RequiredArg(args, 1, row, "acl_revoke_schema", "catalog");
		auto path = RequiredArg(args, 2, row, "acl_revoke_schema", "schema path");
		StoreOf(state).CatalogRevokeSchema(role, vcat, path);
	}
	result.Reference(Value::BOOLEAN(true), count_t(args.size()));
}

//! acl_rematerialize_schema_caps(vcat[, path]): rebuild a subtree's inherited grants - the repair
//! call for a materialisation that drifted (spec 015)
void AclRematerializeSchemaCapsFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t row = 0; row < args.size(); row++) {
		auto vcat = RequiredArg(args, 0, row, "acl_rematerialize_schema_caps", "catalog");
		StoreOf(state).CatalogRematerializeSchemaCaps(vcat, OptionalArg(args, 1, row, ""));
	}
	result.Reference(Value::BOOLEAN(true), count_t(args.size()));
}

//! acl_expand_schema(vcat, path, phys_path[, comment, mode]): register one virtual record per object
//! the physical schema holds right now (spec 014)
void AclExpandSchemaFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t row = 0; row < args.size(); row++) {
		auto vcat = RequiredArg(args, 0, row, "acl_expand_schema", "catalog");
		auto path = RequiredArg(args, 1, row, "acl_expand_schema", "schema path");
		auto phys = RequiredArg(args, 2, row, "acl_expand_schema", "phys path");
		auto &store = StoreOf(state);
		if (!AllowWrite(store, vcat, path, "schema", OptionalArg(args, 4, row, ""))) {
			continue;
		}
		store.CatalogExpandSchema(vcat, path, phys);
		SetInlineComment(store, vcat, path, "schema", OptionalArg(args, 3, row, ""));
	}
	result.Reference(Value::BOOLEAN(true), count_t(args.size()));
}

//! acl_refresh_schema_objects(vcat, path[, prune]): re-read an expansion's source; returns how many
//! records were added (and, with prune, removed)
void AclRefreshSchemaObjectsFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	vector<Value> counts;
	for (idx_t row = 0; row < args.size(); row++) {
		auto vcat = RequiredArg(args, 0, row, "acl_refresh_schema_objects", "catalog");
		auto path = RequiredArg(args, 1, row, "acl_refresh_schema_objects", "schema path");
		bool prune = false;
		if (args.ColumnCount() > 2) {
			auto value = args.GetValue(2, row);
			prune = !value.IsNull() && value.GetValue<bool>();
		}
		counts.push_back(Value::BIGINT(StoreOf(state).CatalogRefreshSchemaObjects(vcat, path, prune)));
	}
	for (idx_t row = 0; row < args.size(); row++) {
		result.SetValue(row, counts[row]);
	}
}

void AddFunction(DataChunk &args, ExpressionState &state, Vector &result, const char *what, const char *kind,
                 const char *form) {
	for (idx_t row = 0; row < args.size(); row++) {
		auto vcat = RequiredArg(args, 0, row, what, "catalog");
		auto vname = RequiredArg(args, 1, row, what, "name");
		auto definition = RequiredArg(args, 2, row, what, "definition");
		bool is_alias = string(form) == "alias";
		// the declared signature and result (the CREATE MACRO shape): the signature types the probe's
		// NULLs, and a declared result replaces the probe entirely
		auto &store = StoreOf(state);
		if (!AllowWrite(store, vcat, vname, kind, OptionalArg(args, 6, row, ""))) {
			continue;
		}
		store.CatalogAddFunction(vcat, vname, kind, form, is_alias ? definition : "", is_alias ? "" : definition,
		                         OptionalArg(args, 3, row, ""), OptionalArg(args, 4, row, ""));
		SetInlineComment(store, vcat, vname, kind, OptionalArg(args, 5, row, ""));
	}
	result.Reference(Value::BOOLEAN(true), count_t(args.size()));
}

//! acl_add_table_function(vcat, vname, sql_template) / _alias(vcat, vname, target)
void AclAddTableFunctionFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	AddFunction(args, state, result, "acl_add_table_function", "table", "macro");
}
void AclAddTableFunctionAliasFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	AddFunction(args, state, result, "acl_add_table_function_alias", "table", "alias");
}
//! acl_add_scalar(vcat, vname, expr_template) / _alias(vcat, vname, target)
void AclAddScalarCatalogFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	AddFunction(args, state, result, "acl_add_scalar", "scalar", "macro");
}
void AclAddScalarAliasCatalogFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	AddFunction(args, state, result, "acl_add_scalar_alias", "scalar", "alias");
}

//! acl_grant_catalog(role, vcat, caps_json, is_main[, rls, columns]): grant a virtual catalog to a
//! role. rls/columns are the grant's own policy (spec 011): they narrow every object of the catalog
//! for this role - the predicate is AND-ed onto the objects', the column list intersects theirs.
void AclGrantCatalogFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t row = 0; row < args.size(); row++) {
		auto role = RequiredArg(args, 0, row, "acl_grant_catalog", "role");
		auto vcat = RequiredArg(args, 1, row, "acl_grant_catalog", "catalog");
		// an omitted caps argument is "unspecified", which the resolver reads as the read-only
		// default; an explicit '{}' is "no capabilities" (spec 012)
		auto caps = OptionalArg(args, 2, row, "");
		bool is_main = false;
		if (args.ColumnCount() > 3) {
			auto value = args.GetValue(3, row);
			is_main = !value.IsNull() && value.GetValue<bool>();
		}
		StoreOf(state).CatalogGrant(role, vcat, caps, is_main, OptionalArg(args, 4, row, ""),
		                            OptionalArg(args, 5, row, ""));
	}
	result.Reference(Value::BOOLEAN(true), count_t(args.size()));
}

//! acl_grant_object(role, vcat, vname, caps_json[, rls, columns]): grant one object of a catalog,
//! with the capabilities and the policy this role gets on it (spec 011)
void AclGrantObjectFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t row = 0; row < args.size(); row++) {
		auto role = RequiredArg(args, 0, row, "acl_grant_object", "role");
		auto vcat = RequiredArg(args, 1, row, "acl_grant_object", "catalog");
		auto vname = RequiredArg(args, 2, row, "acl_grant_object", "name");
		auto caps = OptionalArg(args, 3, row, "");
		auto rls = OptionalArg(args, 4, row, "");
		auto columns = OptionalArg(args, 5, row, "");
		auto &store = StoreOf(state);
		// a grant on an object nobody defined is a policy that never applies: refuse it now
		store.CatalogRequireGrantTarget(vcat, vname, !rls.empty() || !columns.empty(), caps);
		store.CatalogEnsureGrant(role, vcat, false);
		store.CatalogSetObjectCaps(role, vcat, vname, caps, rls, columns);
	}
	result.Reference(Value::BOOLEAN(true), count_t(args.size()));
}

void AclRevokeCatalogFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t row = 0; row < args.size(); row++) {
		auto role = RequiredArg(args, 0, row, "acl_revoke_catalog", "role");
		auto vcat = RequiredArg(args, 1, row, "acl_revoke_catalog", "catalog");
		StoreOf(state).CatalogRevoke(role, vcat);
	}
	result.Reference(Value::BOOLEAN(true), count_t(args.size()));
}

void AclDropRelationFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t row = 0; row < args.size(); row++) {
		auto vcat = RequiredArg(args, 0, row, "acl_drop_relation", "catalog");
		auto vname = RequiredArg(args, 1, row, "acl_drop_relation", "name");
		auto &store = StoreOf(state);
		if (AllowDrop(store, vcat, vname, "relation", OptionalArg(args, 2, row, ""))) {
			store.CatalogDropRelation(vcat, vname);
		}
	}
	result.Reference(Value::BOOLEAN(true), count_t(args.size()));
}

//===--------------------------------------------------------------------===//
// Original admin functions; with a catalog enabled they become compatibility wrappers writing the
// same content into the implicit virtual catalog 'default' (per-object caps preserved, spec 006)
//===--------------------------------------------------------------------===//

//! acl_grant_table(role, vname, phys, cols_csv, rls, caps_csv): register a virtual-table policy.
//! cols_csv items are `name` or `name=expr` (expr masks/renames as `expr AS name`); denied columns
//! are simply omitted. caps_csv is a comma list of {select,insert,update,delete,merge}.
void AclGrantTableFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t row = 0; row < args.size(); row++) {
		auto role = RequiredArg(args, 0, row, "acl_grant_table", "role");
		auto vname = RequiredArg(args, 1, row, "acl_grant_table", "name");
		auto phys = RequiredArg(args, 2, row, "acl_grant_table", "phys");
		auto columns = ParseColumns(OptionalArg(args, 3, row, ""));
		auto rls = OptionalArg(args, 4, row, "");
		auto cap_list = SplitCsv(OptionalArg(args, 5, row, "select"));
		if (cap_list.empty()) {
			cap_list.push_back("select");
		}
		auto &store = StoreOf(state);
		if (store.CatalogEnabled()) {
			auto form = columns.empty() && rls.empty() ? "alias" : "subquery";
			store.CatalogEnsureGrant(role, "default", true);
			store.CatalogAddRelation("default", vname, form, phys, "", rls, columns);
			store.CatalogSetObjectCaps(role, "default", vname, CapsCsvToJson(cap_list));
			continue;
		}
		TablePolicy policy;
		policy.phys = phys;
		for (auto &column : columns) {
			policy.projection.push_back(column.second.empty() ? column.first : column.second + " AS " + column.first);
		}
		policy.rls = rls;
		// no projection and no RLS: expose the physical table as-is via RENAME (writable); otherwise a
		// read-only SUBQUERY (masking / computed columns / RLS need a wrapping subquery)
		policy.subquery_form = !policy.projection.empty() || !policy.rls.empty();
		policy.writable = !policy.subquery_form;
		for (auto &cap : cap_list) {
			policy.caps.insert(StringUtil::Lower(cap));
		}
		lock_guard<mutex> guard(store.lock);
		store.tables[role][vname] = std::move(policy);
	}
	result.Reference(Value::BOOLEAN(true), count_t(args.size()));
}

//! acl_grant_view(role, vname, select_sql): map a virtual name to a view (its SQL is the definition).
//! The SQL may contain acl_claim('<name>') markers; they are baked to constants at rewrite time.
void AclGrantViewFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t row = 0; row < args.size(); row++) {
		auto role = RequiredArg(args, 0, row, "acl_grant_view", "role");
		auto vname = RequiredArg(args, 1, row, "acl_grant_view", "name");
		auto sql = RequiredArg(args, 2, row, "acl_grant_view", "SQL");
		auto &store = StoreOf(state);
		if (store.CatalogEnabled()) {
			store.CatalogEnsureGrant(role, "default", true);
			store.CatalogAddRelation("default", vname, "view", "", sql, "", {});
			store.CatalogSetObjectCaps(role, "default", vname, "{\"select\": true}");
			continue;
		}
		TablePolicy policy;
		policy.subquery_form = true; // a view is always a read-only SUBQUERY
		policy.query = sql;
		policy.caps.insert("select");
		lock_guard<mutex> guard(store.lock);
		store.tables[role][vname] = std::move(policy);
	}
	result.Reference(Value::BOOLEAN(true), count_t(args.size()));
}

void GrantFunctionWrapper(DataChunk &args, ExpressionState &state, Vector &result, const char *what, const char *kind,
                          bool is_alias,
                          case_insensitive_map_t<case_insensitive_map_t<TablePolicy>> PolicyStore::*space) {
	for (idx_t row = 0; row < args.size(); row++) {
		auto role = RequiredArg(args, 0, row, what, "role");
		auto vname = RequiredArg(args, 1, row, what, "name");
		auto definition = RequiredArg(args, 2, row, what, "definition");
		auto &store = StoreOf(state);
		if (store.CatalogEnabled()) {
			store.CatalogEnsureGrant(role, "default", true);
			store.CatalogAddFunction("default", vname, kind, is_alias ? "alias" : "macro", is_alias ? definition : "",
			                         is_alias ? "" : definition);
			continue;
		}
		TablePolicy policy;
		policy.subquery_form = !is_alias;
		// calling a virtual function is a read, so it carries the select capability in either form
		// (spec 012); an alias is a rename of a physical function, not a lesser grant
		policy.caps.insert("select");
		if (is_alias) {
			policy.phys = definition;
		} else {
			policy.query = definition;
		}
		lock_guard<mutex> guard(store.lock);
		(store.*space)[role][vname] = std::move(policy);
	}
	result.Reference(Value::BOOLEAN(true), count_t(args.size()));
}

//! acl_grant_table_function(role, vname, sql_template): a virtual table function whose SQL is expanded
//! as a read-only subquery; arguments via acl_arg(n), RLS via acl_claim('<name>').
void AclGrantTableFunctionFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	GrantFunctionWrapper(args, state, result, "acl_grant_table_function", "table", false,
	                     &PolicyStore::table_functions);
}

//! acl_grant_table_function_alias(role, vname, phys_function): retarget the call in place
void AclGrantTableFunctionAliasFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	GrantFunctionWrapper(args, state, result, "acl_grant_table_function_alias", "table", true,
	                     &PolicyStore::table_functions);
}

//! acl_grant_scalar(role, vname, expr_template): a virtual scalar replaced by an expression macro
void AclGrantScalarFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	GrantFunctionWrapper(args, state, result, "acl_grant_scalar", "scalar", false, &PolicyStore::scalar_functions);
}

//! acl_grant_scalar_alias(role, vname, phys_function): retarget the call in place
void AclGrantScalarAliasFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	GrantFunctionWrapper(args, state, result, "acl_grant_scalar_alias", "scalar", true, &PolicyStore::scalar_functions);
}

//! acl_deny_function(fname) / acl_allow_function(fname): gate a function (scalar or table) by name.
//! With a catalog: an explicit gate row (allow overrides the default denylist); in memory: the
//! denylist set is edited directly.
void SetFunctionGate(DataChunk &args, ExpressionState &state, Vector &result, const char *what, bool allowed) {
	for (idx_t row = 0; row < args.size(); row++) {
		auto fname = RequiredArg(args, 0, row, what, "name");
		auto &store = StoreOf(state);
		if (store.CatalogEnabled()) {
			store.CatalogSetFunctionGate(fname, allowed, false);
			continue;
		}
		lock_guard<mutex> guard(store.lock);
		if (allowed) {
			store.denied_functions.erase(fname);
		} else {
			store.denied_functions.insert(fname);
		}
	}
	result.Reference(Value::BOOLEAN(true), count_t(args.size()));
}

void AclDenyFunctionFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	SetFunctionGate(args, state, result, "acl_deny_function", false);
}

void AclAllowFunctionFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	SetFunctionGate(args, state, result, "acl_allow_function", true);
}

//===--------------------------------------------------------------------===//
// ALTER: partial change of an EXISTING object (spec 009). Unlike the ADD/GRANT upserts, a missing
// target is an error, and every property not named keeps its current value.
//===--------------------------------------------------------------------===//

//! acl_alter_relation(vcat, vname, field, value): field is phys | columns | rls | view
void AclAlterRelationFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t row = 0; row < args.size(); row++) {
		auto vcat = RequiredArg(args, 0, row, "acl_alter_relation", "catalog");
		auto vname = RequiredArg(args, 1, row, "acl_alter_relation", "name");
		auto field = StringUtil::Lower(RequiredArg(args, 2, row, "acl_alter_relation", "property"));
		auto value = OptionalArg(args, 3, row, "");
		StoreOf(state).CatalogAlterRelation(
		    vcat, vname, field, value, field == "columns" ? ParseColumns(value) : vector<std::pair<string, string>>());
	}
	result.Reference(Value::BOOLEAN(true), count_t(args.size()));
}

//! acl_alter_schema_alias(vcat, alias_path, phys_path): retarget an existing schema alias
void AclAlterSchemaAliasFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t row = 0; row < args.size(); row++) {
		auto vcat = RequiredArg(args, 0, row, "acl_alter_schema_alias", "catalog");
		auto alias = RequiredArg(args, 1, row, "acl_alter_schema_alias", "alias path");
		auto phys = RequiredArg(args, 2, row, "acl_alter_schema_alias", "phys path");
		StoreOf(state).CatalogAlterSchemaAlias(vcat, alias, phys);
	}
	result.Reference(Value::BOOLEAN(true), count_t(args.size()));
}

//! acl_alter_function(vcat, vname, kind, form, definition): redefine an existing virtual function
void AclAlterFunctionFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t row = 0; row < args.size(); row++) {
		auto vcat = RequiredArg(args, 0, row, "acl_alter_function", "catalog");
		auto vname = RequiredArg(args, 1, row, "acl_alter_function", "name");
		auto kind = StringUtil::Lower(RequiredArg(args, 2, row, "acl_alter_function", "kind"));
		auto form = StringUtil::Lower(RequiredArg(args, 3, row, "acl_alter_function", "form"));
		auto definition = RequiredArg(args, 4, row, "acl_alter_function", "definition");
		StoreOf(state).CatalogAlterFunction(vcat, vname, kind, form, definition);
	}
	result.Reference(Value::BOOLEAN(true), count_t(args.size()));
}

//! acl_alter_catalog(vcat, comment) / acl_alter_role(role, claims_csv)
void AclAlterCatalogFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t row = 0; row < args.size(); row++) {
		auto vcat = RequiredArg(args, 0, row, "acl_alter_catalog", "catalog");
		StoreOf(state).CatalogAlterCatalog(vcat, OptionalArg(args, 1, row, ""));
	}
	result.Reference(Value::BOOLEAN(true), count_t(args.size()));
}

void AclAlterRoleFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t row = 0; row < args.size(); row++) {
		auto role = RequiredArg(args, 0, row, "acl_alter_role", "role");
		StoreOf(state).CatalogAlterRole(role, ParseClaims(OptionalArg(args, 1, row, "")));
	}
	result.Reference(Value::BOOLEAN(true), count_t(args.size()));
}

//! acl_alter_grant(role, vcat, field, value): field is caps | main
void AclAlterGrantFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t row = 0; row < args.size(); row++) {
		auto role = RequiredArg(args, 0, row, "acl_alter_grant", "role");
		auto vcat = RequiredArg(args, 1, row, "acl_alter_grant", "catalog");
		auto field = StringUtil::Lower(RequiredArg(args, 2, row, "acl_alter_grant", "property"));
		auto value = OptionalArg(args, 3, row, "");
		StoreOf(state).CatalogAlterGrant(role, vcat, field, value);
	}
	result.Reference(Value::BOOLEAN(true), count_t(args.size()));
}

//! acl_alter_issuer(issuer, field, value): field is keys | jwks_uri | audiences | algs | role_claim |
//! claim_map. `keys` and `jwks_uri` are alternatives, so setting either clears the other.
void AclAlterIssuerFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t row = 0; row < args.size(); row++) {
		auto issuer = RequiredArg(args, 0, row, "acl_alter_issuer", "issuer");
		auto field = StringUtil::Lower(RequiredArg(args, 1, row, "acl_alter_issuer", "property"));
		auto value = OptionalArg(args, 2, row, "");
		StoreOf(state).CatalogAlterIssuer(issuer, field, value);
	}
	result.Reference(Value::BOOLEAN(true), count_t(args.size()));
}

//! acl_comment(vcat, vname, kind, column, comment): document a virtual object or one of its columns
void AclCommentFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t row = 0; row < args.size(); row++) {
		auto vcat = RequiredArg(args, 0, row, "acl_comment", "catalog");
		auto vname = RequiredArg(args, 1, row, "acl_comment", "name");
		auto kind = StringUtil::Lower(OptionalArg(args, 2, row, "relation"));
		auto column = OptionalArg(args, 3, row, "");
		auto comment = OptionalArg(args, 4, row, "");
		StoreOf(state).CatalogSetComment(vcat, vname, kind, column, comment);
	}
	result.Reference(Value::BOOLEAN(true), count_t(args.size()));
}

//! acl_refresh_schema(vcat [, vname]): re-derive the stored schema of query-defined objects after the
//! physical schema moved under them; returns how many objects were re-probed
void AclRefreshSchemaFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	vector<Value> counts;
	for (idx_t row = 0; row < args.size(); row++) {
		auto vcat = RequiredArg(args, 0, row, "acl_refresh_schema", "catalog");
		counts.push_back(Value::BIGINT(
		    NumericCast<int64_t>(StoreOf(state).CatalogRefreshSchema(vcat, OptionalArg(args, 1, row, "")))));
	}
	for (idx_t row = 0; row < args.size(); row++) {
		result.SetValue(row, counts[row]);
	}
}

//===--------------------------------------------------------------------===//
// DROP of virtual-catalog elements (spec 010): cleanup, not access control - REVOKE takes access
// away, ADD overwrites definitions; these remove what was created so nothing dangles.
//===--------------------------------------------------------------------===//

//! acl_drop_catalog(vcat [, cascade]): definitions always; the role grants need cascade
void AclDropCatalogFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t row = 0; row < args.size(); row++) {
		auto vcat = RequiredArg(args, 0, row, "acl_drop_catalog", "catalog");
		bool cascade = false;
		if (args.ColumnCount() > 1) {
			auto value = args.GetValue(1, row);
			cascade = !value.IsNull() && value.GetValue<bool>();
		}
		auto &store = StoreOf(state);
		if (AllowDrop(store, vcat, vcat, "catalog", OptionalArg(args, 2, row, ""))) {
			store.CatalogDropCatalog(vcat, cascade);
		}
	}
	result.Reference(Value::BOOLEAN(true), count_t(args.size()));
}

void AclDropSchemaAliasFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t row = 0; row < args.size(); row++) {
		auto vcat = RequiredArg(args, 0, row, "acl_drop_schema_alias", "catalog");
		auto alias = RequiredArg(args, 1, row, "acl_drop_schema_alias", "alias path");
		auto &store = StoreOf(state);
		bool cascade = false;
		if (args.ColumnCount() > 3) {
			auto value = args.GetValue(3, row);
			cascade = !value.IsNull() && value.GetValue<bool>();
		}
		if (AllowDrop(store, vcat, alias, "schema", OptionalArg(args, 2, row, ""))) {
			store.CatalogDropSchemaAlias(vcat, alias, cascade);
		}
	}
	result.Reference(Value::BOOLEAN(true), count_t(args.size()));
}

void AclDropFunctionFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t row = 0; row < args.size(); row++) {
		auto vcat = RequiredArg(args, 0, row, "acl_drop_function", "catalog");
		auto vname = RequiredArg(args, 1, row, "acl_drop_function", "name");
		auto kind = StringUtil::Lower(RequiredArg(args, 2, row, "acl_drop_function", "kind"));
		auto &store = StoreOf(state);
		if (AllowDrop(store, vcat, vname, kind, OptionalArg(args, 3, row, ""))) {
			store.CatalogDropFunction(vcat, vname, kind);
		}
	}
	result.Reference(Value::BOOLEAN(true), count_t(args.size()));
}

void AclDropRoleFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t row = 0; row < args.size(); row++) {
		auto role = RequiredArg(args, 0, row, "acl_drop_role", "role");
		auto &store = StoreOf(state);
		if (AllowDrop(store, "", role, "role", OptionalArg(args, 1, row, ""))) {
			store.CatalogDropRole(role);
		}
	}
	result.Reference(Value::BOOLEAN(true), count_t(args.size()));
}

void AclDropIssuerFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t row = 0; row < args.size(); row++) {
		auto issuer = RequiredArg(args, 0, row, "acl_drop_issuer", "issuer");
		auto &store = StoreOf(state);
		if (AllowDrop(store, "", issuer, "issuer", OptionalArg(args, 1, row, ""))) {
			store.CatalogDropIssuer(issuer);
		}
	}
	result.Reference(Value::BOOLEAN(true), count_t(args.size()));
}

void AclDropRoleMappingFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t row = 0; row < args.size(); row++) {
		auto issuer = RequiredArg(args, 0, row, "acl_drop_role_mapping", "issuer");
		auto source = RequiredArg(args, 1, row, "acl_drop_role_mapping", "source");
		auto external = RequiredArg(args, 2, row, "acl_drop_role_mapping", "external value");
		auto role = RequiredArg(args, 3, row, "acl_drop_role_mapping", "role");
		StoreOf(state).CatalogDropRoleMapping(issuer, source, external, role);
	}
	result.Reference(Value::BOOLEAN(true), count_t(args.size()));
}

//! acl_grant_admin(role, scope): a GLOBAL administration scope (spec 009) - 'manage' (the management
//! grammar over every catalog, plus the statements that belong to no catalog) or 'passthrough'
//! (anything, including native SQL - god mode). Managing ONE catalog is not granted here: it is a
//! capability of the catalog grant, `acl_grant_catalog(role, vcat, '{"manage": true}')`.
void AclGrantAdminFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t row = 0; row < args.size(); row++) {
		auto role = RequiredArg(args, 0, row, "acl_grant_admin", "role");
		auto scope = RequiredArg(args, 1, row, "acl_grant_admin", "scope");
		StoreOf(state).GrantAdmin(role, ParseAdminScope(scope));
	}
	result.Reference(Value::BOOLEAN(true), count_t(args.size()));
}

//! acl_revoke_admin(role): drop the role's ACL-administration scope
void AclRevokeAdminFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t row = 0; row < args.size(); row++) {
		StoreOf(state).RevokeAdmin(RequiredArg(args, 0, row, "acl_revoke_admin", "role"));
	}
	result.Reference(Value::BOOLEAN(true), count_t(args.size()));
}

//! acl_define_issuer(issuer, keys_json, audiences_csv, algs_csv, role_claim, claim_map_json[, jwks_uri]):
//! register an offline JWT issuer (spec 007). keys_json is a JWKS (RSA n/e, EC x/y, oct k) or a PEM
//! public key; jwks_uri (spec 023) names a document to read them from instead - an https URL or a file
//! an operator refreshes. Exactly one of the two carries the keys.
void AclDefineIssuerFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t row = 0; row < args.size(); row++) {
		IssuerConfig config;
		config.issuer = RequiredArg(args, 0, row, "acl_define_issuer", "issuer");
		config.keys_json = OptionalArg(args, 1, row, "");
		config.jwks_uri = OptionalArg(args, 6, row, "");
		if (config.keys_json.empty() == config.jwks_uri.empty()) {
			throw BinderException("acl_define_issuer: an issuer carries its keys either as a document or as a "
			                      "location to read one from, and must state exactly one of them");
		}
		for (auto &aud : SplitCsv(OptionalArg(args, 2, row, ""))) {
			config.audiences.push_back(aud);
		}
		for (auto &alg : SplitCsv(OptionalArg(args, 3, row, "RS256"))) {
			config.algs.insert(alg);
		}
		config.role_claim = OptionalArg(args, 4, row, "roles");
		config.claim_map = OptionalArg(args, 5, row, "");
		StoreOf(state).DefineIssuer(std::move(config));
	}
	result.Reference(Value::BOOLEAN(true), count_t(args.size()));
}

//! acl_map_role(issuer, source, external_value, role): map a claim value or an EntraID group GUID
//! to an internal role; one external value may map to several roles
void AclMapRoleFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t row = 0; row < args.size(); row++) {
		auto issuer = RequiredArg(args, 0, row, "acl_map_role", "issuer");
		auto source = RequiredArg(args, 1, row, "acl_map_role", "source");
		auto external = RequiredArg(args, 2, row, "acl_map_role", "external value");
		auto role = RequiredArg(args, 3, row, "acl_map_role", "role");
		StoreOf(state).MapRole(issuer, source, external, role);
	}
	result.Reference(Value::BOOLEAN(true), count_t(args.size()));
}

//! The statement a live session runs, with its prefix in front - or empty when the session is not
//! usable. The one place the prefix is composed, so every door spells it the same way.
string PrefixedForSession(PolicyStore &store, const string &handle, const string &sql) {
	Principal principal;
	string reason;
	if (!store.SessionPrincipal(handle, principal, reason)) {
		return string();
	}
	return "ACL SESSION '" + StringUtil::Replace(handle, "'", "''") + "' " + sql;
}

//! acl_quack_serve(uri[, token]): the safe way to open the quack door (spec 041). It installs the two
//! callbacks and starts quack's server - but only from an instance a client cannot step out of, and it
//! says which condition is missing rather than serving something half-configured. Everything it sets
//! could be set by hand; the point of the function is that it is all of it or none.
void AclQuackServeFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &context = state.GetContext();
	result.SetVectorType(VectorType::FLAT_VECTOR);
	for (idx_t row = 0; row < args.size(); row++) {
		auto uri = RequiredArg(args, 0, row, "acl_quack_serve", "listen uri");
		auto token = args.ColumnCount() > 1 ? OptionalArg(args, 1, row, "") : string();
		auto &store = StoreOf(state);
		if (!store.CatalogEnabled()) {
			throw BinderException("acl_quack_serve: no policy source is configured - a served instance "
			                      "resolves every statement against one, so `acl_use_db` (or the function "
			                      "driver) comes first");
		}
		if (store.CatalogAnonymousAdminAllowed()) {
			throw BinderException("acl_quack_serve: `acl_allow_anonymous_admin` is on, so a served client "
			                      "could administer the ACL with a bare `ACL ADMIN` - turn it off before "
			                      "opening the door");
		}
		Value override_setting;
		if (context.TryGetCurrentSetting("allow_parser_override_extension", override_setting) &&
		    !StringUtil::CIEquals(override_setting.ToString(), "strict")) {
			throw BinderException("acl_quack_serve: the parser override is \"%s\", not STRICT - a served "
			                      "statement that failed to parse as ACL would fall through to plain SQL",
			                      override_setting.ToString());
		}
		if (token.empty()) {
			throw BinderException("acl_quack_serve: pass a server token explicitly. It is not what admits a "
			                      "client - their JWT is - but a default-configured quack accepts whatever a "
			                      "caller sends, and this is the outer fence around that");
		}
		// quack listens in the clear by construction, so a non-local bind belongs behind a proxy
		Connection con(*context.db);
		auto install = con.Query("SET GLOBAL quack_authentication_function = 'acl_quack_authenticate'; "
		                         "SET GLOBAL quack_authorization_function = 'acl_quack_authorize';");
		if (install->HasError()) {
			throw BinderException("acl_quack_serve: quack is not loaded (%s)", install->GetError());
		}
		auto quoted = [](const string &value) {
			return "'" + StringUtil::Replace(value, "'", "''") + "'";
		};
		auto served =
		    con.Query("SELECT listen_uri FROM quack_serve(" + quoted(uri) + ", token := " + quoted(token) + ")");
		if (served->HasError()) {
			throw BinderException("acl_quack_serve: %s", served->GetError());
		}
		// From here the fence on unprefixed statements applies: a drained stream is now ours to judge
		// (spec 043). Set after the listener is up, so a refused serve leaves nothing behind.
		store.SetDoorOpen(true);
		result.SetValue(row, served->RowCount() > 0 ? served->GetValue(0, 0) : Value(uri));
	}
}

//! acl_quack_stop(uri): close the door, and the sessions it served with it (spec 041). Stopping the
//! listener leaves every session bound to a connection that will never come back, and nothing else
//! can tell that they are gone - a door is the only thing that knows it closed.
//!
//! quack does not tell a callback which server a connection arrived at, so sessions cannot be
//! attributed to one. They are therefore swept only when no quack server is left in the instance:
//! with two doors open, stopping one says what it did rather than guessing whose sessions to drop.
void AclQuackStopFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &context = state.GetContext();
	result.SetVectorType(VectorType::FLAT_VECTOR);
	for (idx_t row = 0; row < args.size(); row++) {
		auto uri = RequiredArg(args, 0, row, "acl_quack_stop", "listen uri");
		auto quoted = [](const string &value) {
			return "'" + StringUtil::Replace(value, "'", "''") + "'";
		};
		Connection con(*context.db);
		auto stopped = con.Query("SELECT * FROM quack_stop(" + quoted(uri) + ")");
		if (stopped->HasError()) {
			throw BinderException("acl_quack_stop: %s", stopped->GetError());
		}
		auto remaining = con.Query("SELECT count(*) FROM quack_server_list()");
		bool last_door =
		    !remaining->HasError() && remaining->RowCount() > 0 && remaining->GetValue(0, 0).GetValue<int64_t>() == 0;
		string note = stopped->RowCount() > 0 ? stopped->GetValue(0, 0).ToString() : uri;
		if (!last_door) {
			result.SetValue(row, Value(note + " (another quack server is still open, so its sessions stay)"));
			continue;
		}
		auto &store = StoreOf(state);
		// The last door is closed, so the fence on unprefixed statements lifts with it: a drained
		// stream is once again nobody's business but quack's own (spec 043).
		store.SetDoorOpen(false);
		auto closed = store.SessionCloseAll();
		result.SetValue(row, Value(note + " (" + std::to_string(closed) + " session(s) closed)"));
	}
}

//! acl_quack_authenticate(session_id, client_token, server_token): quack's authentication callback
//! (spec 041). The client's token is a JWT we verify for ourselves, so quack's own shared token is
//! not what admits anyone - it stays the operator's outer fence, and this decides the principal.
//! Binding is by quack's `session_id`, which is the `connection_id` every later message carries.
void AclQuackAuthenticateFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	result.SetVectorType(VectorType::FLAT_VECTOR);
	for (idx_t row = 0; row < args.size(); row++) {
		auto session_id = RequiredArg(args, 0, row, "acl_quack_authenticate", "session id");
		auto token = RequiredArg(args, 1, row, "acl_quack_authenticate", "client token");
		auto &store = StoreOf(state);
		auto handle = store.SessionOpen(token);
		if (handle.empty()) {
			result.SetValue(row, Value::BOOLEAN(false));
			continue;
		}
		store.SessionBind(session_id, handle);
		result.SetValue(row, Value::BOOLEAN(true));
	}
}

//! acl_quack_authorize(connection_id, query): quack's authorization callback (spec 041). A VARCHAR
//! return replaces the SQL quack executes, so returning the prefixed statement is the whole of
//! serving under the ACL; NULL is a refusal, which is what an unknown or expired session gets.
//!
//! One statement arrives here that quack does *not* execute: before a stream starts it asks about the
//! write with `INSERT INTO <schema>.<table> VALUES (NULL)` and reads only whether the answer is NULL.
//! It gets the same treatment as everything else - prefixed, not special-cased - for two reasons. The
//! write itself is judged where the server generates it (spec 042), so refusing here would refuse
//! every bulk load; and a prefixed answer is the safe one to hand back for a statement we are told is
//! never run, because if quack ever does run it, it runs through the ACL rather than around it.
void AclQuackAuthorizeFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	result.SetVectorType(VectorType::FLAT_VECTOR);
	for (idx_t row = 0; row < args.size(); row++) {
		auto connection_id = RequiredArg(args, 0, row, "acl_quack_authorize", "connection id");
		auto sql = RequiredArg(args, 1, row, "acl_quack_authorize", "query");
		auto &store = StoreOf(state);
		string handle;
		if (!store.SessionHandleFor(connection_id, handle)) {
			result.SetValue(row, Value());
			continue;
		}
		auto prefixed = PrefixedForSession(store, handle, sql);
		result.SetValue(row, prefixed.empty() ? Value() : Value(prefixed));
	}
}

//! acl_session_open(token): verify a token once and mint an opaque handle for it (spec 040). NULL
//! when it does not verify - a door refuses rather than learning why.
void AclSessionOpenFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &context = state.GetContext();
	result.SetVectorType(VectorType::FLAT_VECTOR);
	for (idx_t row = 0; row < args.size(); row++) {
		auto token = RequiredArg(args, 0, row, "acl_session_open", "token");
		auto handle = StoreOf(state).SessionOpen(token);
		if (handle.empty()) {
			result.SetValue(row, Value());
			continue;
		}
		result.SetValue(row, Value(handle));
	}
}

//! acl_session_sql(handle, sql): the statement to run, with the session's prefix in front of it.
//! NULL when the session is not usable, which is the whole of a door's decision.
void AclSessionSqlFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	result.SetVectorType(VectorType::FLAT_VECTOR);
	for (idx_t row = 0; row < args.size(); row++) {
		auto handle = RequiredArg(args, 0, row, "acl_session_sql", "handle");
		auto sql = RequiredArg(args, 1, row, "acl_session_sql", "sql");
		Principal principal;
		string reason;
		if (!StoreOf(state).SessionPrincipal(handle, principal, reason)) {
			result.SetValue(row, Value());
			continue;
		}
		result.SetValue(row, Value("ACL SESSION '" + StringUtil::Replace(handle, "'", "''") + "' " + sql));
	}
}

//! acl_session_sweep(): drop every session that has expired or gone idle, and say how many went
//! (spec 044). The same pass SessionOpen runs by itself; here it is an operator's tool, and what makes
//! sweeping observable to a test rather than inferred from behaviour.
void AclSessionSweepFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	auto swept = Value::BIGINT(NumericCast<int64_t>(StoreOf(state).SessionSweep()));
	result.Reference(swept, count_t(args.size()));
}

//! acl_session_count(): how many sessions are live. Denied to a principal like the rest of this
//! surface - a client may not learn how many others there are.
void AclSessionCountFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	auto live = Value::BIGINT(NumericCast<int64_t>(StoreOf(state).SessionCount()));
	result.Reference(live, count_t(args.size()));
}

//! acl_session_close(handle): end it. Idempotent, so a door may retry a disconnect.
void AclSessionCloseFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t row = 0; row < args.size(); row++) {
		StoreOf(state).SessionClose(RequiredArg(args, 0, row, "acl_session_close", "handle"));
	}
	result.Reference(Value::BOOLEAN(true), count_t(args.size()));
}

//! acl_define_token(token, role, claims_csv): bind a non-JWT token to a principal - the dev stub
//! (a JWT-shaped token always takes the real verification path, spec 007).
void AclDefineTokenFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t row = 0; row < args.size(); row++) {
		auto token = RequiredArg(args, 0, row, "acl_define_token", "token");
		auto role = RequiredArg(args, 1, row, "acl_define_token", "role");
		Principal principal;
		principal.roles = {role};
		principal.claims = ParseClaims(OptionalArg(args, 2, row, ""));
		auto &store = StoreOf(state);
		lock_guard<mutex> guard(store.lock);
		store.tokens[token] = std::move(principal);
	}
	result.Reference(Value::BOOLEAN(true), count_t(args.size()));
}

//! acl_define_role(role, claims_csv): default claims carried by the bare ROLE form
void AclDefineRoleFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t row = 0; row < args.size(); row++) {
		auto role = RequiredArg(args, 0, row, "acl_define_role", "role");
		auto claims = ParseClaims(OptionalArg(args, 1, row, ""));
		auto &store = StoreOf(state);
		if (store.CatalogEnabled()) {
			if (!AllowWrite(store, "", role, "role", OptionalArg(args, 2, row, ""))) {
				continue;
			}
			store.CatalogDefineRole(role, claims);
			continue;
		}
		lock_guard<mutex> guard(store.lock);
		store.role_claims[role] = std::move(claims);
	}
	result.Reference(Value::BOOLEAN(true), count_t(args.size()));
}

} // namespace

void RegisterAclAdminFunctions(ExtensionLoader &loader, shared_ptr<PolicyStore> store) {
	// register an admin setup function, attaching the shared store via its function_info
	auto register_admin = [&](const string &name, vector<LogicalType> arguments, scalar_function_t fn) {
		ScalarFunction function(Identifier(name), std::move(arguments), LogicalType::BOOLEAN, fn);
		function.SetExtraFunctionInfo(make_shared_ptr<AclScalarInfo>(store));
		// an admin function refuses at execution time - a bad predicate, a name in use, a missing
		// target - and an unmarked function turns those refusals into INTERNAL errors
		function.SetFallible();
		loader.RegisterFunction(function);
	};

	// overloaded admin functions register as one set under the shared store
	auto register_admin_set = [&](const string &name, vector<vector<LogicalType>> signatures, scalar_function_t fn) {
		ScalarFunctionSet set((Identifier(name)));
		for (auto &arguments : signatures) {
			ScalarFunction function(Identifier(name), std::move(arguments), LogicalType::BOOLEAN, fn);
			function.SetExtraFunctionInfo(make_shared_ptr<AclScalarInfo>(store));
			function.SetFallible();
			set.AddFunction(function);
		}
		loader.RegisterFunction(set);
	};

	const LogicalType &v = LogicalType::VARCHAR;
	const LogicalType &b = LogicalType::BOOLEAN;
	// catalog backend control + catalog-model admin (spec 006)
	register_admin_set("acl_use_db", {{v}, {v, v}, {v, v, b}}, AclUseDbFunc);
	register_admin("acl_use_functions", {v}, AclUseFunctionsFunc);
	// the trailing argument of the object writers is the write mode of spec 013 (create/replace/skip);
	// omitted, it is the legacy upsert every ADD form promises
	register_admin_set("acl_create_catalog", {{v}, {v, v}, {v, v, v}}, AclCreateCatalogFunc);
	register_admin_set("acl_add_relation", {{v, v, v, v, v}, {v, v, v, v, v, v}, {v, v, v, v, v, v, v}},
	                   AclAddRelationFunc);
	register_admin_set("acl_add_view", {{v, v, v}, {v, v, v, v}, {v, v, v, v, v}, {v, v, v, v, v, v}}, AclAddViewFunc);
	register_admin_set("acl_add_schema_alias", {{v, v, v}, {v, v, v, v}, {v, v, v, v, v}}, AclAddSchemaAliasFunc);
	register_admin_set("acl_expand_schema", {{v, v, v}, {v, v, v, v}, {v, v, v, v, v}}, AclExpandSchemaFunc);
	register_admin_set("acl_grant_schema", {{v, v, v, v}, {v, v, v, v, v}, {v, v, v, v, v, v, b}}, AclGrantSchemaFunc);
	register_admin_set("acl_register_created", {{v, v, v}, {v, v, v, v}}, AclRegisterCreatedFunc);
	register_admin_set("acl_register_existing", {{v, v, v}, {v, v, v, v}}, AclRegisterExistingFunc);
	register_admin("acl_register_view", {v, v, v}, AclRegisterViewFunc);
	register_admin("acl_revoke_schema", {v, v, v}, AclRevokeSchemaFunc);
	register_admin_set("acl_rematerialize_schema_caps", {{v}, {v, v}}, AclRematerializeSchemaCapsFunc);
	register_admin_set("acl_add_table_function",
	                   {{v, v, v}, {v, v, v, v, v}, {v, v, v, v, v, v}, {v, v, v, v, v, v, v}},
	                   AclAddTableFunctionFunc);
	register_admin_set("acl_add_table_function_alias", {{v, v, v}, {v, v, v, v, v, v}, {v, v, v, v, v, v, v}},
	                   AclAddTableFunctionAliasFunc);
	register_admin_set("acl_add_scalar", {{v, v, v}, {v, v, v, v, v}, {v, v, v, v, v, v}, {v, v, v, v, v, v, v}},
	                   AclAddScalarCatalogFunc);
	register_admin_set("acl_add_scalar_alias", {{v, v, v}, {v, v, v, v, v, v}, {v, v, v, v, v, v, v}},
	                   AclAddScalarAliasCatalogFunc);
	register_admin_set("acl_grant_catalog", {{v, v, v}, {v, v, v, b}, {v, v, v, b, v, v}}, AclGrantCatalogFunc);
	register_admin_set("acl_grant_object", {{v, v, v, v}, {v, v, v, v, v, v}}, AclGrantObjectFunc);
	register_admin("acl_revoke_catalog", {v, v}, AclRevokeCatalogFunc);
	register_admin_set("acl_drop_relation", {{v, v}, {v, v, v}}, AclDropRelationFunc);
	// metadata (spec 010)
	register_admin_set("acl_comment", {{v, v, v, v, v}}, AclCommentFunc);
	// DROP of the remaining elements (spec 010)
	register_admin_set("acl_drop_catalog", {{v}, {v, b}, {v, b, v}}, AclDropCatalogFunc);
	register_admin_set("acl_drop_schema_alias", {{v, v}, {v, v, v}, {v, v, v, b}}, AclDropSchemaAliasFunc);
	register_admin_set("acl_drop_function", {{v, v, v}, {v, v, v, v}}, AclDropFunctionFunc);
	register_admin_set("acl_drop_role", {{v}, {v, v}}, AclDropRoleFunc);
	register_admin_set("acl_drop_issuer", {{v}, {v, v}}, AclDropIssuerFunc);
	register_admin("acl_drop_role_mapping", {v, v, v, v}, AclDropRoleMappingFunc);
	// spec 022: declared join paths
	register_admin_set("acl_add_reference",
	                   {{v, v, v, v},
	                    {v, v, v, v, v},
	                    {v, v, v, v, v, v},
	                    {v, v, v, v, v, v, v},
	                    {v, v, v, v, v, v, v, v},
	                    {v, v, v, v, v, v, v, v, v},
	                    {v, v, v, v, v, v, v, v, v, v},
	                    {v, v, v, v, v, v, v, v, v, v, v},
	                    {v, v, v, v, v, v, v, v, v, v, v, v},
	                    {v, v, v, v, v, v, v, v, v, v, v, v, v}},
	                   AclAddReferenceFunc);
	register_admin_set("acl_drop_reference", {{v, v}, {v, v, v}}, AclDropReferenceFunc);
	// re-derive stored schemas; returns the number of objects re-probed
	auto register_refresh = [&](vector<LogicalType> arguments) {
		ScalarFunction function(Identifier("acl_refresh_schema"), std::move(arguments), LogicalType::BIGINT,
		                        AclRefreshSchemaFunc);
		function.SetExtraFunctionInfo(make_shared_ptr<AclScalarInfo>(store));
		function.SetFallible();
		loader.RegisterFunction(function);
	};
	register_refresh({v});
	register_refresh({v, v});
	// re-read an expansion's source (spec 014); returns how many records were added or removed
	auto register_refresh_objects = [&](vector<LogicalType> arguments) {
		ScalarFunction function(Identifier("acl_refresh_schema_objects"), std::move(arguments), LogicalType::BIGINT,
		                        AclRefreshSchemaObjectsFunc);
		function.SetExtraFunctionInfo(make_shared_ptr<AclScalarInfo>(store));
		function.SetFallible();
		loader.RegisterFunction(function);
	};
	register_refresh_objects({v, v});
	register_refresh_objects({v, v, b});
	// original stubs / compatibility wrappers
	register_admin("acl_grant_table", {v, v, v, v, v, v}, AclGrantTableFunc);
	register_admin("acl_grant_view", {v, v, v}, AclGrantViewFunc);
	register_admin("acl_grant_table_function", {v, v, v}, AclGrantTableFunctionFunc);
	register_admin("acl_grant_table_function_alias", {v, v, v}, AclGrantTableFunctionAliasFunc);
	register_admin("acl_grant_scalar", {v, v, v}, AclGrantScalarFunc);
	register_admin("acl_grant_scalar_alias", {v, v, v}, AclGrantScalarAliasFunc);
	register_admin("acl_deny_function", {v}, AclDenyFunctionFunc);
	register_admin("acl_allow_function", {v}, AclAllowFunctionFunc);
	// the session contract both doors stand on (spec 040): open once, prefix every statement, close
	auto register_session_text = [&](const string &name, vector<LogicalType> arguments, scalar_function_t fn) {
		ScalarFunction function(Identifier(name), std::move(arguments), LogicalType::VARCHAR, fn);
		function.SetExtraFunctionInfo(make_shared_ptr<AclScalarInfo>(store));
		function.SetFallible();
		loader.RegisterFunction(function);
	};
	// the quack door (spec 041): the two callbacks quack calls, both thin over the contract above
	register_admin("acl_quack_authenticate", {v, v, v}, AclQuackAuthenticateFunc);
	register_session_text("acl_quack_serve", {v, v}, AclQuackServeFunc);
	register_session_text("acl_quack_stop", {v}, AclQuackStopFunc);
	register_session_text("acl_quack_authorize", {v, v}, AclQuackAuthorizeFunc);
	register_session_text("acl_session_open", {v}, AclSessionOpenFunc);
	register_session_text("acl_session_sql", {v, v}, AclSessionSqlFunc);
	register_admin("acl_session_close", {v}, AclSessionCloseFunc);
	// the bound on all of the above (spec 044): sweeping and counting, both the door's, never a client's
	auto register_session_bigint = [&](const string &name, scalar_function_t fn) {
		ScalarFunction function(Identifier(name), {}, LogicalType::BIGINT, fn);
		function.SetExtraFunctionInfo(make_shared_ptr<AclScalarInfo>(store));
		function.SetFallible();
		loader.RegisterFunction(function);
	};
	register_session_bigint("acl_session_sweep", AclSessionSweepFunc);
	register_session_bigint("acl_session_count", AclSessionCountFunc);
	register_admin("acl_define_token", {v, v, v}, AclDefineTokenFunc);
	register_admin_set("acl_define_role", {{v, v}, {v, v, v}}, AclDefineRoleFunc);
	// offline JWT verification (spec 007)
	register_admin_set("acl_define_issuer", {{v, v, v, v, v, v}, {v, v, v, v, v, v, v}}, AclDefineIssuerFunc);
	register_admin("acl_map_role", {v, v, v, v}, AclMapRoleFunc);
	// ALTER of existing objects (spec 009)
	register_admin("acl_alter_relation", {v, v, v, v}, AclAlterRelationFunc);
	register_admin("acl_alter_schema_alias", {v, v, v}, AclAlterSchemaAliasFunc);
	register_admin("acl_alter_function", {v, v, v, v, v}, AclAlterFunctionFunc);
	register_admin("acl_alter_catalog", {v, v}, AclAlterCatalogFunc);
	register_admin("acl_alter_role", {v, v}, AclAlterRoleFunc);
	register_admin("acl_alter_grant", {v, v, v, v}, AclAlterGrantFunc);
	register_admin("acl_alter_issuer", {v, v, v}, AclAlterIssuerFunc);
	// ACL administration scopes (spec 009)
	register_admin("acl_grant_admin", {v, v}, AclGrantAdminFunc);
	register_admin("acl_revoke_admin", {v}, AclRevokeAdminFunc);
}

} // namespace acl
} // namespace duckdb
