// Spec 039: catalog maintenance. The source changes under the virtual catalog and nothing on the
// query path may look (spec 065: no probing, anywhere). What is left is the administrator, off the
// query path: acl_check_catalog([vcat]) probes every stored fact of a catalog against the source and
// answers what no longer holds - one row per finding, with the repair it wants - and
// acl_repair_relation(vcat, vname, action[, spec]) mends a declared COLUMNS list on purpose, never
// dropping a mask silently (spec 038's rule, applied to the repair).

#include "acl_maintenance.hpp"

#include "acl_door_common.hpp"
#include "acl_policy_catalog.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/execution/expression_executor_state.hpp"
#include "duckdb/function/function_set.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/connection.hpp"

#include <algorithm>

namespace duckdb {
namespace acl {

using acl_detail::CatalogBackend;
using acl_detail::Ident;
using acl_detail::Lit;
using acl_detail::ParseColumnList;

namespace {

using Finding = PolicyStore::CatalogFinding;
using Columns = vector<std::pair<string, string>>;

string Text(const Value &value) {
	return value.IsNull() ? string() : value.ToString();
}

//! the first line of a duckdb error - the sentence, not the envelope
string FirstLine(const string &error) {
	auto newline = error.find('\n');
	return newline == string::npos ? error : error.substr(0, newline);
}

//! Does `sql` bind on a fresh connection? The error's first line when not. A probe on the admin's
//! call, exactly as acl_refresh_schema probes - never on a principal's query.
bool Binds(CatalogBackend &catalog, const string &sql, string &error) {
	auto instance = catalog.Db();
	Connection con(*instance);
	auto result = con.Query(sql);
	if (result->HasError()) {
		error = FirstLine(result->GetError());
		return false;
	}
	error.clear();
	return true;
}

bool SourceBinds(CatalogBackend &catalog, const string &source, string &error) {
	return Binds(catalog, "SELECT * FROM " + source + " WHERE false", error);
}

//! A declared entry's expression over its source, written exactly as the read path writes it: the
//! expression verbatim, a bare name quoted.
string EntryItem(const std::pair<string, string> &entry) {
	return entry.second.empty() ? Ident(entry.first) : entry.second;
}

bool ItemBinds(CatalogBackend &catalog, const string &source, const string &item, string &error) {
	return Binds(catalog, "SELECT " + item + " AS __acl_probe FROM " + source + " WHERE false", error);
}

//! What the object's stored schema says (spec 010), and whether it was derived by a probe or declared
//! by the admin - a declared schema is the admin's word and is never compared against the source.
Columns StoredSchema(CatalogBackend &catalog, const string &vcat, const string &vname, const string &kind,
                     bool &derived) {
	Columns stored;
	derived = false;
	auto rows = catalog.Query("SELECT \"name\", \"type\", \"derived\" FROM " + catalog.Tbl("object_columns") +
	                          " WHERE \"vcat\" = " + Lit(vcat) + " AND \"vname\" = " + Lit(vname) +
	                          " AND \"kind\" = " + Lit(kind) + " ORDER BY \"pos\"");
	for (idx_t row = 0; row < rows->RowCount(); row++) {
		stored.emplace_back(rows->GetValue(0, row).ToString(), Text(rows->GetValue(1, row)));
		auto flag = rows->GetValue(2, row);
		derived = derived || (!flag.IsNull() && flag.GetValue<bool>());
	}
	return stored;
}

//! How two schemas differ, as a sentence; "" when they agree (names case-insensitively, types as text)
string SchemaDiff(const Columns &stored, const Columns &probed) {
	case_insensitive_map_t<string> was, now;
	for (auto &column : stored) {
		was[column.first] = column.second;
	}
	for (auto &column : probed) {
		now[column.first] = column.second;
	}
	vector<string> added, removed, retyped;
	for (auto &column : probed) {
		auto old = was.find(column.first);
		if (old == was.end()) {
			added.push_back(column.first + " " + column.second);
		} else if (!old->second.empty() && !StringUtil::CIEquals(old->second, column.second)) {
			retyped.push_back(column.first + " " + old->second + " -> " + column.second);
		}
	}
	for (auto &column : stored) {
		if (now.find(column.first) == now.end()) {
			removed.push_back(column.first);
		}
	}
	vector<string> parts;
	if (!added.empty()) {
		parts.push_back("added: " + StringUtil::Join(added, ", "));
	}
	if (!removed.empty()) {
		parts.push_back("removed: " + StringUtil::Join(removed, ", "));
	}
	if (!retyped.empty()) {
		parts.push_back("retyped: " + StringUtil::Join(retyped, ", "));
	}
	return StringUtil::Join(parts, "; ");
}

//! A relation as the check reads it, kept for the grants and references that name it
struct Relation {
	string vname, form, phys, view_sql;
	Columns declared;                   // the COLUMNS list (name -> expression), empty for a bare alias
	case_insensitive_map_t<string> own; // the same, for ProjectionSchema
	vector<string> known;               // the column names the catalog knows for it (declared, else stored)
	bool dead = false;                  // its source does not bind: nothing below it can be judged
	string Source() const {
		return form == "view" ? "(" + view_sql + ")" : phys;
	}
};

//! One catalog's check: every stored fact against the source, one finding per thing that no longer
//! holds. Reads through the backend's own query path; probes on fresh connections.
class CatalogChecker {
public:
	CatalogChecker(CatalogBackend &catalog_p, string vcat_p, vector<Finding> &out_p)
	    : catalog(catalog_p), vcat(std::move(vcat_p)), out(out_p) {
	}

	void Run() {
		CheckRelations();
		CheckFunctions();
		CheckGrants();
		CheckSchemas();
		CheckReferences();
	}

private:
	void Add(const string &kind, const string &object, const string &role, const string &problem, const string &detail,
	         const string &repair) {
		out.push_back(Finding {vcat, kind, object, role, problem, detail, repair});
	}
	string Named(const string &vname) const {
		return vcat + "." + vname;
	}
	unique_ptr<MaterializedQueryResult> Read(const string &sql) {
		return catalog.Query(sql);
	}

	void CheckRelations() {
		auto rows = Read("SELECT \"vname\", \"form\", \"phys\", \"view_sql\", \"rls\", \"rls_checked\" FROM " +
		                 catalog.Tbl("relations") + " WHERE \"vcat\" = " + Lit(vcat) + " ORDER BY \"vname\"");
		for (idx_t row = 0; row < rows->RowCount(); row++) {
			Relation relation;
			relation.vname = rows->GetValue(0, row).ToString();
			relation.form = Text(rows->GetValue(1, row));
			relation.phys = Text(rows->GetValue(2, row));
			relation.view_sql = Text(rows->GetValue(3, row));
			auto rls = Text(rows->GetValue(4, row));
			auto rls_checked = rows->GetValue(5, row);
			auto declared = Read("SELECT \"name\", \"expr\" FROM " + catalog.Tbl("relation_columns") +
			                     " WHERE \"vcat\" = " + Lit(vcat) + " AND \"vname\" = " + Lit(relation.vname) +
			                     " ORDER BY \"pos\"");
			for (idx_t i = 0; i < declared->RowCount(); i++) {
				auto name = declared->GetValue(0, i).ToString();
				auto expr = Text(declared->GetValue(1, i));
				relation.declared.emplace_back(name, expr);
				relation.own[name] = expr;
				relation.known.push_back(name);
			}
			bool is_view = relation.form == "view";
			auto kind = is_view ? "view" : "table";
			bool stored_derived = false;
			auto stored = StoredSchema(catalog, vcat, relation.vname, "relation", stored_derived);
			if (relation.known.empty()) {
				for (auto &column : stored) {
					relation.known.push_back(column.first);
				}
			}
			string error;
			if (is_view) {
				Columns probed;
				if (!catalog.ProbeSchema(relation.view_sql, false, {}, probed)) {
					SourceBinds(catalog, relation.Source(), error);
					Add(kind, relation.vname, "", "definition_broken", "the view's SQL does not bind: " + error,
					    "CREATE OR REPLACE VIRTUAL VIEW " + Named(relation.vname) + " AS '<sql>'");
					relation.dead = true;
				} else if (stored_derived || stored.empty()) {
					auto diff = SchemaDiff(stored, probed);
					if (!diff.empty()) {
						Add(kind, relation.vname, "", "schema_stale",
						    "the stored schema no longer matches what the SQL binds to (" + diff + ")",
						    "ANALYZE VIRTUAL VIEW " + Named(relation.vname));
					}
				}
			} else if (!SourceBinds(catalog, relation.phys, error)) {
				Add(kind, relation.vname, "", "source_missing",
				    "the source \"" + relation.phys + "\" does not bind: " + error,
				    "ALTER VIRTUAL TABLE " + Named(relation.vname) + " SET PHYS <path>  -- or DROP VIRTUAL TABLE " +
				        Named(relation.vname));
				relation.dead = true;
			} else if (!relation.declared.empty()) {
				bool any_missing = false;
				vector<string> items;
				for (auto &entry : relation.declared) {
					auto item = EntryItem(entry);
					items.push_back(item + " AS " + Ident(entry.first));
					if (ItemBinds(catalog, relation.phys, item, error)) {
						continue;
					}
					any_missing = true;
					Add(kind, relation.vname, "", "column_missing",
					    "declared column \"" + entry.first + "\" reads " +
					        (entry.second.empty() ? "a source column of that name" : "\"" + entry.second + "\"") +
					        ", which \"" + relation.phys + "\" no longer has: " + error,
					    "REPAIR VIRTUAL TABLE " + Named(relation.vname) + " REMAP (" + entry.first +
					        " = <column>)  -- or DROP MISSING COLUMNS");
				}
				if (!any_missing && stored_derived) {
					Columns probed;
					if (catalog.ProbeSchema("SELECT " + StringUtil::Join(items, ", ") + " FROM " + relation.phys, false,
					                        {}, probed)) {
						auto diff = SchemaDiff(stored, probed);
						if (!diff.empty()) {
							Add(kind, relation.vname, "", "schema_stale",
							    "the stored schema no longer matches what the projection binds to (" + diff + ")",
							    "ANALYZE VIRTUAL TABLE " + Named(relation.vname));
						}
					}
				}
			}
			if (!relation.dead && !rls.empty()) {
				JudgePredicate(kind, relation, "", rls, rls_checked,
				               "ALTER VIRTUAL " + string(is_view ? "VIEW " : "TABLE ") + Named(relation.vname) +
				                   " SET RLS '<predicate>'");
			}
			relations[relation.vname] = std::move(relation);
		}
	}

	//! spec 027's verdict, taken again: a predicate that fails to bind, or one nobody ever judged
	void JudgePredicate(const string &kind, const Relation &relation, const string &role, const string &rls,
	                    const Value &rls_checked, const string &repair) {
		bool checked = false;
		auto error = catalog.PredicateError(relation.Source(), rls, &checked);
		string who = role.empty() ? string() : " of role \"" + role + "\"";
		if (!error.empty()) {
			Add(kind, relation.vname, role, "rls_broken",
			    "the predicate" + who + " does not bind against \"" + Named(relation.vname) + "\": " + FirstLine(error),
			    repair);
		} else if (checked && !rls_checked.IsNull() && !rls_checked.GetValue<bool>()) {
			Add(kind, relation.vname, role, "rls_unchecked",
			    "the predicate" + who + " was accepted unchecked when it was written (spec 027) and binds now",
			    "ANALYZE VIRTUAL CATALOG " + vcat);
		}
	}

	void CheckFunctions() {
		auto rows = Read("SELECT \"vname\", \"kind\", \"form\", \"target\", \"template\", \"params\" FROM " +
		                 catalog.Tbl("functions") + " WHERE \"vcat\" = " + Lit(vcat) + " ORDER BY \"vname\", \"kind\"");
		for (idx_t row = 0; row < rows->RowCount(); row++) {
			auto vname = rows->GetValue(0, row).ToString();
			auto kind = Text(rows->GetValue(1, row));
			auto form = Text(rows->GetValue(2, row));
			auto target = Text(rows->GetValue(3, row));
			auto sql = Text(rows->GetValue(4, row));
			auto params = Text(rows->GetValue(5, row));
			bool scalar = kind == "scalar";
			if (form == "alias") {
				// the target is a function of this instance: gone with its extension, or renamed
				auto name = target.substr(target.rfind('.') == string::npos ? 0 : target.rfind('.') + 1);
				auto found = Read("SELECT 1 FROM duckdb_functions() WHERE lower(function_name) = " +
				                  Lit(StringUtil::Lower(name)) + " LIMIT 1");
				if (found->RowCount() == 0) {
					Add("function", vname, "", "definition_broken",
					    "the target function \"" + target +
					        "\" is not defined in this instance (is its extension loaded?)",
					    "acl_alter_function(" + Lit(vcat) + ", " + Lit(vname) + ", " + Lit(kind) +
					        ", 'alias', '<target>')");
				}
				continue;
			}
			Columns probed;
			if (!catalog.ProbeSchema(sql, scalar, CatalogBackend::DeclaredTypes(params), probed)) {
				Add("function", vname, "", "definition_broken",
				    string("the ") + kind + " macro's template does not bind with its declared parameters",
				    "acl_alter_function(" + Lit(vcat) + ", " + Lit(vname) + ", " + Lit(kind) +
				        ", 'macro', '<definition>')");
				continue;
			}
			bool stored_derived = false;
			auto stored = StoredSchema(catalog, vcat, vname, kind, stored_derived);
			if (!stored_derived && !stored.empty()) {
				continue; // declared by the admin: their word, not the probe's
			}
			auto diff = SchemaDiff(stored, probed);
			if (!diff.empty()) {
				Add("function", vname, "", "schema_stale",
				    "the stored schema no longer matches what the template binds to (" + diff + ")",
				    string("ANALYZE VIRTUAL ") + (scalar ? "SCALAR " : "TABLE FUNCTION ") + Named(vname));
			}
		}
	}

	//! The columns a relation exposes right now: its declared names (the contract), else what its
	//! source binds to NOW - not the stored schema, which is exactly what may be stale
	bool Exposed(const Relation &relation, case_insensitive_set_t &out) {
		vector<string> declared;
		for (auto &entry : relation.declared) {
			declared.push_back(entry.first);
		}
		vector<string> names;
		if (!catalog.ExposedColumns(relation.Source(), declared, names)) {
			return false;
		}
		for (auto &name : names) {
			out.insert(name);
		}
		return true;
	}

	//! A grant's list against one object (spec 038's semantics, read back): a bare item that matches
	//! nothing intersects away - the role reads less than the grant says; a mask on a column the
	//! object does not expose, or whose expression does not bind, refuses every read of the object.
	//! `matched` collects the bare items that did match (a catalog grant's are judged across objects).
	void JudgeColumns(const Relation &relation, const string &role, const Columns &items, bool object_grant,
	                  const string &repair, case_insensitive_set_t *matched) {
		case_insensitive_set_t exposed;
		if (!Exposed(relation, exposed)) {
			return;
		}
		for (auto &item : items) {
			if (item.second.empty()) {
				if (exposed.count(item.first)) {
					if (matched) {
						matched->insert(item.first);
					}
				} else if (object_grant) {
					Add("grant", relation.vname, role, "grant_column_missing",
					    "the COLUMNS item \"" + item.first + "\" matches no column of \"" + Named(relation.vname) +
					        "\" - it intersects away, and the role reads less than the grant says",
					    repair);
				}
				continue;
			}
			if (!exposed.count(item.first)) {
				Add("grant", relation.vname, role, "mask_broken",
				    "the mask \"" + item.first + " = " + item.second + "\" names a column \"" + Named(relation.vname) +
				        "\" does not expose - every read of it by this role refuses (spec 038)",
				    repair);
				continue;
			}
			Columns derived;
			bool probed = false;
			auto error = catalog.ProjectionSchema(relation.Source(), item.first + " = " + item.second, relation.own,
			                                      derived, &probed);
			if (!error.empty()) {
				Add("grant", relation.vname, role, "mask_broken",
				    "the mask \"" + item.first + " = " + item.second + "\" does not bind over \"" +
				        Named(relation.vname) + "\": " + FirstLine(error),
				    repair);
			}
		}
	}

	//! A list without one item, as the csv the writers take
	static string Without(const Columns &items, const string &name) {
		vector<string> kept;
		for (auto &item : items) {
			if (StringUtil::CIEquals(item.first, name)) {
				continue;
			}
			kept.push_back(item.second.empty() ? item.first : item.first + " = " + item.second);
		}
		return StringUtil::Join(kept, ", ");
	}

	void CheckGrants() {
		auto objects =
		    Read("SELECT \"role\", \"vname\", \"caps\", \"rls\", \"columns\", \"rls_checked\" FROM " +
		         catalog.Tbl("role_object_caps") + " WHERE \"vcat\" = " + Lit(vcat) + " ORDER BY \"role\", \"vname\"");
		for (idx_t row = 0; row < objects->RowCount(); row++) {
			auto role = objects->GetValue(0, row).ToString();
			auto vname = objects->GetValue(1, row).ToString();
			auto caps = Text(objects->GetValue(2, row));
			auto rls = Text(objects->GetValue(3, row));
			auto columns = Text(objects->GetValue(4, row));
			auto found = relations.find(vname);
			if (found == relations.end() || found->second.dead) {
				continue; // a function's grant, or an object whose own finding says it all
			}
			auto &relation = found->second;
			// the re-grant that keeps everything but the item: an object grant has no ALTER form, and
			// GRANT OBJECT with fewer clauses would reset what it does not state
			auto regrant = [&](const string &columns_text) {
				return "SELECT acl_grant_object(" + Lit(role) + ", " + Lit(vcat) + ", " + Lit(vname) + ", " +
				       Lit(caps) + ", " + Lit(rls) + ", " + Lit(columns_text) + ")";
			};
			if (!rls.empty()) {
				JudgePredicate("grant", relation, role, rls, objects->GetValue(5, row),
				               regrant(columns) + "  -- with a predicate that binds");
			}
			if (!columns.empty()) {
				auto items = ParseColumnList(columns);
				for (auto &item : items) {
					// judged one item at a time so the repair can name the list without it
					JudgeColumns(relation, role, {item}, true, regrant(Without(items, item.first)), nullptr);
				}
			}
		}
		auto catalogs = Read("SELECT \"role\", \"rls\", \"columns\", \"rls_checked\" FROM " +
		                     catalog.Tbl("role_catalogs") + " WHERE \"vcat\" = " + Lit(vcat) + " ORDER BY \"role\"");
		for (idx_t row = 0; row < catalogs->RowCount(); row++) {
			auto role = catalogs->GetValue(0, row).ToString();
			auto rls = Text(catalogs->GetValue(1, row));
			auto columns = Text(catalogs->GetValue(2, row));
			auto rls_checked = catalogs->GetValue(3, row);
			auto items = ParseColumnList(columns);
			case_insensitive_set_t matched;
			for (auto &entry : relations) {
				auto &relation = entry.second;
				if (relation.dead) {
					continue;
				}
				// the catalog level has no single object to bind against, so it is judged against
				// every one (spec 027): a predicate or a mask that fails on an object fails that
				// object's reads
				if (!rls.empty()) {
					JudgePredicate("grant", relation, role, rls, rls_checked,
					               "ALTER GRANT CATALOG " + vcat + " TO ROLE " + role + " SET RLS '<predicate>'");
				}
				for (auto &item : items) {
					JudgeColumns(relation, role, {item}, false,
					             "ALTER GRANT CATALOG " + vcat + " TO ROLE " + role + " SET COLUMNS " +
					                 Lit(Without(items, item.first)),
					             &matched);
				}
			}
			// a catalog-wide bare name applies where an object has it and is absent elsewhere by
			// design (spec 038) - it is a finding only when no object of the catalog has it any more
			for (auto &item : items) {
				if (item.second.empty() && !matched.count(item.first) && !relations.empty()) {
					Add("grant", "*", role, "grant_column_missing",
					    "the catalog-wide COLUMNS item \"" + item.first + "\" matches no column of any object of \"" +
					        vcat + "\" - the role reads less than the grant says",
					    "ALTER GRANT CATALOG " + vcat + " TO ROLE " + role + " SET COLUMNS " +
					        Lit(Without(items, item.first)));
				}
			}
		}
	}

	//! `database.schema` of a physical schema path - the same split the schema writers make
	static void SplitSchema(const string &phys_path, string &database, string &schema) {
		auto dot = phys_path.find('.');
		database = dot == string::npos ? phys_path : phys_path.substr(0, dot);
		schema = dot == string::npos ? string() : phys_path.substr(dot + 1);
	}

	void CheckSchemas() {
		// a live alias keeps its path in phys_path; an expansion keeps the source it was read from
		// in origin (spec 014) - either way, that is the physical schema the check asks about
		auto rows = Read("SELECT \"path\", \"phys_path\", \"origin\" FROM " + catalog.Tbl("schemas") +
		                 " WHERE \"vcat\" = " + Lit(vcat) + " ORDER BY \"path\"");
		for (idx_t row = 0; row < rows->RowCount(); row++) {
			auto path = rows->GetValue(0, row).ToString();
			auto origin = Text(rows->GetValue(2, row));
			auto phys_path = Text(rows->GetValue(1, row));
			if (phys_path.empty()) {
				phys_path = origin;
			}
			if (phys_path.empty()) {
				continue; // a schema that is only a name (a granted home, spec 016): nothing physical to ask
			}
			string database, schema;
			SplitSchema(phys_path, database, schema);
			auto known = Read("SELECT 1 FROM duckdb_schemas() WHERE database_name = " + Lit(database) +
			                  " AND schema_name = " + Lit(schema));
			if (known->RowCount() == 0) {
				Add("schema", path, "", "schema_missing",
				    "the physical schema \"" + phys_path + "\" does not exist (is its database attached?)",
				    "ALTER VIRTUAL SCHEMA " + Named(path) + " SET PHYS <path>  -- or DROP VIRTUAL SCHEMA " +
				        Named(path));
				continue;
			}
			if (origin.empty()) {
				continue; // a live alias shows what the source holds, by definition
			}
			// an expansion is a snapshot plus edits (spec 014): what the source gained since, and what
			// it lost, is what REFRESH [PRUNE] would change
			auto listing =
			    Read("SELECT table_name AS name FROM duckdb_tables() WHERE database_name = " + Lit(database) +
			         " AND schema_name = " + Lit(schema) +
			         " UNION SELECT view_name FROM duckdb_views() WHERE database_name = " + Lit(database) +
			         " AND schema_name = " + Lit(schema) + " AND NOT internal ORDER BY 1");
			case_insensitive_set_t source_names;
			vector<string> unrecorded, gone;
			auto recorded =
			    Read("SELECT \"vname\" FROM " + catalog.Tbl("relations") + " WHERE \"vcat\" = " + Lit(vcat) +
			         " AND \"origin\" = " + Lit(origin) + " AND substr(\"vname\", 1, " +
			         std::to_string(path.size() + 1) + ") = " + Lit(path + ".") + " ORDER BY 1");
			auto dropped = Read("SELECT \"name\" FROM " + catalog.Tbl("schema_dropped") +
			                    " WHERE \"vcat\" = " + Lit(vcat) + " AND \"path\" = " + Lit(path));
			case_insensitive_set_t recorded_names, dropped_names;
			for (idx_t i = 0; i < recorded->RowCount(); i++) {
				recorded_names.insert(recorded->GetValue(0, i).ToString().substr(path.size() + 1));
			}
			for (idx_t i = 0; i < dropped->RowCount(); i++) {
				dropped_names.insert(dropped->GetValue(0, i).ToString());
			}
			for (idx_t i = 0; i < listing->RowCount(); i++) {
				auto name = listing->GetValue(0, i).ToString();
				source_names.insert(name);
				if (!recorded_names.count(name) && !dropped_names.count(name)) {
					unrecorded.push_back(name);
				}
			}
			for (auto &name : recorded_names) {
				if (!source_names.count(name)) {
					gone.push_back(name);
				}
			}
			std::sort(gone.begin(), gone.end());
			if (unrecorded.empty() && gone.empty()) {
				continue;
			}
			vector<string> parts;
			if (!unrecorded.empty()) {
				parts.push_back(std::to_string(unrecorded.size()) + " source object(s) not recorded (" +
				                StringUtil::Join(unrecorded, ", ") + ")");
			}
			if (!gone.empty()) {
				parts.push_back(std::to_string(gone.size()) + " recorded object(s) whose source is gone (" +
				                StringUtil::Join(gone, ", ") + ")");
			}
			Add("schema", path, "", "expansion_stale", StringUtil::Join(parts, "; "),
			    "ALTER VIRTUAL SCHEMA " + Named(path) + " REFRESH" + (gone.empty() ? "" : " PRUNE"));
		}
	}

	void CheckReferences() {
		auto rows = Read("SELECT \"name\", \"from_vname\", \"to_vname\", \"to_kind\" FROM " +
		                 catalog.Tbl("references") + " WHERE \"vcat\" = " + Lit(vcat) + " ORDER BY \"name\"");
		for (idx_t row = 0; row < rows->RowCount(); row++) {
			auto name = rows->GetValue(0, row).ToString();
			auto from = Text(rows->GetValue(1, row));
			auto to = Text(rows->GetValue(2, row));
			auto to_kind = Text(rows->GetValue(3, row));
			auto repair = "DROP VIRTUAL REFERENCE " + Named(name);
			vector<string> problems;
			if (relations.find(from) == relations.end()) {
				problems.push_back("its FROM end \"" + from + "\" is not an object of the catalog");
			}
			bool to_function = StringUtil::CIEquals(to_kind, "function");
			if (to_function) {
				auto found = Read("SELECT 1 FROM " + catalog.Tbl("functions") + " WHERE \"vcat\" = " + Lit(vcat) +
				                  " AND \"vname\" = " + Lit(to) + " AND \"kind\" = 'table'");
				if (found->RowCount() == 0) {
					problems.push_back("its TO end \"" + to + "\" is not a table function of the catalog");
				}
			} else if (relations.find(to) == relations.end()) {
				problems.push_back("its TO end \"" + to + "\" is not an object of the catalog");
			}
			// the columns it names, against what the catalog knows of each end (a bare alias with no
			// stored schema is unknown here - not probed, as spec 022's visibility rule is not either)
			auto columns =
			    Read("SELECT \"side\", \"column\" FROM " + catalog.Tbl("reference_columns") +
			         " WHERE \"vcat\" = " + Lit(vcat) + " AND \"name\" = " + Lit(name) + " ORDER BY \"pos\"");
			for (idx_t i = 0; i < columns->RowCount(); i++) {
				auto side = columns->GetValue(0, i).ToString();
				auto column = Text(columns->GetValue(1, i));
				bool from_side = StringUtil::CIEquals(side, "from");
				auto end = from_side ? from : to;
				if (!from_side && to_function) {
					continue;
				}
				auto found = relations.find(end);
				if (found == relations.end() || found->second.known.empty()) {
					continue;
				}
				bool has = false;
				for (auto &known : found->second.known) {
					has = has || StringUtil::CIEquals(known, column);
				}
				if (!has) {
					problems.push_back("it names column \"" + column + "\" of \"" + end +
					                   "\", which the object no longer has");
				}
			}
			if (!problems.empty()) {
				Add("reference", name, "", "reference_dangling", StringUtil::Join(problems, "; "), repair);
			}
		}
	}

	CatalogBackend &catalog;
	string vcat;
	vector<Finding> &out;
	case_insensitive_map_t<Relation> relations;
};

} // namespace

vector<PolicyStore::CatalogFinding> PolicyStore::CatalogCheck(const string &only) {
	if (!catalog) {
		throw BinderException("acl_check_catalog requires a policy catalog - run acl_use_db() first");
	}
	vector<CatalogFinding> out;
	auto catalogs = catalog->Query("SELECT \"vcat\" FROM " + catalog->Tbl("catalogs") +
	                               (only.empty() ? string() : " WHERE \"vcat\" = " + Lit(only)) + " ORDER BY 1");
	if (!only.empty() && catalogs->RowCount() == 0) {
		throw BinderException("acl admin: catalog \"%s\" does not exist", only);
	}
	for (idx_t row = 0; row < catalogs->RowCount(); row++) {
		CatalogChecker checker(*catalog, catalogs->GetValue(0, row).ToString(), out);
		checker.Run();
	}
	return out;
}

int64_t PolicyStore::CatalogRepairRelation(const string &vcat, const string &vname, const string &action_p,
                                           const string &spec) {
	if (!catalog) {
		throw BinderException("acl_repair_relation requires a policy catalog - run acl_use_db() first");
	}
	auto action = StringUtil::Lower(action_p);
	auto shape = catalog->Query("SELECT \"form\", \"phys\" FROM " + catalog->Tbl("relations") +
	                            " WHERE \"vcat\" = " + Lit(vcat) + " AND \"vname\" = " + Lit(vname));
	if (shape->RowCount() == 0) {
		throw BinderException("acl admin: relation \"%s.%s\" does not exist", vcat, vname);
	}
	if (Text(shape->GetValue(0, 0)) == "view") {
		throw BinderException("acl admin: \"%s.%s\" is a view - ANALYZE VIRTUAL VIEW re-derives its schema, CREATE OR "
		                      "REPLACE VIRTUAL VIEW redefines it",
		                      vcat, vname);
	}
	auto phys = Text(shape->GetValue(1, 0));
	auto rows =
	    catalog->Query("SELECT \"name\", \"expr\", \"nullable\" FROM " + catalog->Tbl("relation_columns") +
	                   " WHERE \"vcat\" = " + Lit(vcat) + " AND \"vname\" = " + Lit(vname) + " ORDER BY \"pos\"");
	if (rows->RowCount() == 0) {
		throw BinderException("acl admin: \"%s.%s\" declares no COLUMNS list - a bare alias reads the source live and "
		                      "has nothing to repair (declare COLUMNS to give it a shape)",
		                      vcat, vname);
	}
	Columns columns;
	case_insensitive_map_t<int8_t> marks;
	for (idx_t row = 0; row < rows->RowCount(); row++) {
		auto name = rows->GetValue(0, row).ToString();
		columns.emplace_back(name, Text(rows->GetValue(1, row)));
		auto nullable = rows->GetValue(2, row);
		if (!nullable.IsNull()) {
			marks[name] = nullable.GetValue<bool>() ? 1 : 0;
		}
	}
	int64_t changed = 0;
	string error;
	if (action == "remap") {
		if (spec.empty()) {
			throw BinderException("acl admin: REMAP needs a list: name = expression, ...");
		}
		for (auto &item : ParseColumnList(spec)) {
			if (item.second.empty()) {
				throw BinderException("acl admin: REMAP item \"%s\" states no expression (expected name = expression)",
				                      item.first);
			}
			auto entry = std::find_if(columns.begin(), columns.end(), [&](const std::pair<string, string> &column) {
				return StringUtil::CIEquals(column.first, item.first);
			});
			if (entry == columns.end()) {
				throw BinderException("acl admin: \"%s.%s\" declares no column \"%s\"", vcat, vname, item.first);
			}
			// probed to bind before anything is written: a remap to a name that is not there either
			// would trade one dead object for another
			if (!ItemBinds(*catalog, phys, item.second, error)) {
				throw BinderException("acl admin: \"%s.%s\": \"%s = %s\" does not bind against \"%s\": %s", vcat, vname,
				                      item.first, item.second, phys, error);
			}
			entry->second = item.second;
			changed++;
		}
	} else if (action == "drop_missing" || action == "drop_missing_and_masks") {
		bool and_masks = action == "drop_missing_and_masks";
		case_insensitive_set_t missing;
		for (auto &column : columns) {
			if (!ItemBinds(*catalog, phys, EntryItem(column), error)) {
				missing.insert(column.first);
			}
		}
		if (missing.empty()) {
			return 0;
		}
		// The masks that would be orphaned: the object grants on this object. A catalog grant's mask
		// is not touched either way - it protects the column on every other object, and spec 038
		// refuses this object's reads for it, which the check reports as mask_broken.
		auto grants =
		    catalog->Query("SELECT \"role\", \"caps\", \"rls\", \"columns\" FROM " + catalog->Tbl("role_object_caps") +
		                   " WHERE \"vcat\" = " + Lit(vcat) + " AND \"vname\" = " + Lit(vname) + " ORDER BY \"role\"");
		struct Affected {
			string role, caps, rls;
			Columns items;
		};
		vector<Affected> affected;
		vector<string> orphaned;
		for (idx_t row = 0; row < grants->RowCount(); row++) {
			Affected grant {grants->GetValue(0, row).ToString(), Text(grants->GetValue(1, row)),
			                Text(grants->GetValue(2, row)), ParseColumnList(Text(grants->GetValue(3, row)))};
			bool touched = false;
			for (auto &item : grant.items) {
				if (!item.second.empty() && missing.count(item.first)) {
					orphaned.push_back("\"" + item.first + "\" (role \"" + grant.role + "\")");
					touched = true;
				}
			}
			if (touched) {
				affected.push_back(std::move(grant));
			}
		}
		if (!orphaned.empty() && !and_masks) {
			throw BinderException(
			    "acl admin: \"%s.%s\": dropping the missing column(s) would orphan the mask(s) on %s - "
			    "REMAP the column, alter those grants, or DROP MISSING COLUMNS AND MASKS",
			    vcat, vname, StringUtil::Join(orphaned, ", "));
		}
		// Not one transaction (each writer is its own, spec 034's version bump included), so the
		// order is what keeps a failure midway harmless: the grants lose their mask items FIRST -
		// a grant with fewer items reads less, never more - and the object's list is cut after.
		// A grant rewrite that fails leaves the object whole and the dead entry unreadable as
		// before; a cut that fails leaves masks gone from grants that could not read the column
		// anyway. Nothing on either path widens.
		for (auto &grant : affected) {
			vector<string> items;
			for (auto &item : grant.items) {
				if (!item.second.empty() && missing.count(item.first)) {
					changed++;
					continue;
				}
				items.push_back(item.second.empty() ? item.first : item.first + " = " + item.second);
			}
			CatalogSetObjectCaps(grant.role, vcat, vname, grant.caps, grant.rls, StringUtil::Join(items, ", "));
		}
		Columns kept;
		for (auto &column : columns) {
			if (!missing.count(column.first)) {
				kept.push_back(column);
			}
		}
		columns = std::move(kept);
		changed += NumericCast<int64_t>(missing.size());
		CatalogAlterRelation(vcat, vname, "columns", "", columns, marks);
		CatalogRefreshSchema(vcat, vname);
		return changed;
	} else {
		throw BinderException("acl admin: unknown repair action \"%s\" (remap, drop_missing, drop_missing_and_masks)",
		                      action_p);
	}
	CatalogAlterRelation(vcat, vname, "columns", "", columns, marks);
	CatalogRefreshSchema(vcat, vname); // the grants' projections and verdicts, over the mended object
	return changed;
}

namespace {

//! Carried on the table function: the store the check runs against
struct MaintenanceInfo : TableFunctionInfo {
	explicit MaintenanceInfo(shared_ptr<PolicyStore> store_p) : store(std::move(store_p)) {
	}
	shared_ptr<PolicyStore> store;
};

struct CheckBindData : FunctionData {
	string vcat;
	shared_ptr<PolicyStore> store;
	unique_ptr<FunctionData> Copy() const override {
		auto copy = make_uniq<CheckBindData>();
		copy->vcat = vcat;
		copy->store = store;
		return std::move(copy);
	}
	bool Equals(const FunctionData &other) const override {
		return vcat == other.Cast<CheckBindData>().vcat;
	}
};

struct CheckState : GlobalTableFunctionState {
	vector<Finding> rows;
	idx_t next = 0;
};

unique_ptr<FunctionData> CheckBind(ClientContext &, TableFunctionBindInput &input, vector<LogicalType> &return_types,
                                   vector<Identifier> &names) {
	for (auto name : {"vcat", "kind", "object", "role", "problem", "detail", "repair"}) {
		names.push_back(Identifier(name));
		return_types.push_back(LogicalType::VARCHAR);
	}
	auto bind = make_uniq<CheckBindData>();
	bind->store = input.info->Cast<MaintenanceInfo>().store;
	if (!input.inputs.empty() && !input.inputs[0].IsNull()) {
		bind->vcat = input.inputs[0].ToString();
	}
	return std::move(bind);
}

unique_ptr<GlobalTableFunctionState> CheckInit(ClientContext &, TableFunctionInitInput &input) {
	auto &bind = input.bind_data->Cast<CheckBindData>();
	auto state = make_uniq<CheckState>();
	state->rows = bind.store->CatalogCheck(bind.vcat); // the probes run here, once per scan
	return std::move(state);
}

void CheckScan(ClientContext &, TableFunctionInput &data, DataChunk &output) {
	auto &state = data.global_state->Cast<CheckState>();
	idx_t count = 0;
	while (state.next < state.rows.size() && count < STANDARD_VECTOR_SIZE) {
		auto &row = state.rows[state.next++];
		output.data[0].SetValue(count, Value(row.vcat));
		output.data[1].SetValue(count, Value(row.kind));
		output.data[2].SetValue(count, Value(row.object));
		output.data[3].SetValue(count, row.role.empty() ? Value(LogicalType::VARCHAR) : Value(row.role));
		output.data[4].SetValue(count, Value(row.problem));
		output.data[5].SetValue(count, Value(row.detail));
		output.data[6].SetValue(count, Value(row.repair));
		count++;
	}
	output.SetChildCardinality(count);
}

//! acl_repair_relation(vcat, vname, action[, spec]) -> entries changed
void RepairRelationFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	vector<Value> counts;
	for (idx_t row = 0; row < args.size(); row++) {
		auto vcat = RequiredArg(args, 0, row, "acl_repair_relation", "catalog");
		auto vname = RequiredArg(args, 1, row, "acl_repair_relation", "name");
		auto action = RequiredArg(args, 2, row, "acl_repair_relation", "action");
		auto spec = OptionalArg(args, 3, row, "");
		counts.push_back(Value::BIGINT(StoreOf(state).CatalogRepairRelation(vcat, vname, action, spec)));
	}
	for (idx_t row = 0; row < args.size(); row++) {
		result.SetValue(row, counts[row]);
	}
}

} // namespace

void RegisterAclMaintenance(ExtensionLoader &loader, const shared_ptr<PolicyStore> &store) {
	auto info = make_shared_ptr<MaintenanceInfo>(store);
	TableFunctionSet check(Identifier("acl_check_catalog"));
	for (auto &arguments : {vector<LogicalType> {}, vector<LogicalType> {LogicalType::VARCHAR}}) {
		TableFunction function(Identifier("acl_check_catalog"), arguments, CheckScan, CheckBind, CheckInit);
		function.function_info = info;
		check.AddFunction(function);
	}
	loader.RegisterFunction(check);
	ScalarFunctionSet repair((Identifier("acl_repair_relation")));
	const LogicalType &v = LogicalType::VARCHAR;
	for (auto &arguments : {vector<LogicalType> {v, v, v}, vector<LogicalType> {v, v, v, v}}) {
		ScalarFunction function(Identifier("acl_repair_relation"), arguments, LogicalType::BIGINT, RepairRelationFunc);
		MarkAclScalar(function, store);
		repair.AddFunction(function);
	}
	loader.RegisterFunction(repair);
}

} // namespace acl
} // namespace duckdb
