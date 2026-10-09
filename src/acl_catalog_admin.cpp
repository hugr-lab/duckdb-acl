// The writers of the catalog backend: every PolicyStore::Catalog* method an administration
// function or a management statement compiles to, with the statement builders they share. Each
// write is validated where it is written (acl_catalog_validation.cpp) and lands in one
// transaction. Split from acl_policy_catalog.cpp (plan 4.2).

#include "acl_result_rows.hpp"
#include "acl_policy_catalog.hpp"
#include "acl_lineage.hpp"
#include "acl_rewriter.hpp"

namespace duckdb {
namespace acl {
namespace acl_detail {

vector<string> CatalogBackend::KeyStatements(const string &vcat, const string &vname, const string &kind,
                                             const string &pk, const vector<string> &known,
                                             const case_insensitive_map_t<int8_t> &nullable_marks,
                                             const vector<std::pair<string, string>> *masked, bool carried) {
	vector<string> statements;
	statements.push_back("DELETE FROM " + Tbl("keys") + " WHERE \"vcat\" = " + Lit(vcat) +
	                     " AND \"vname\" = " + Lit(vname) + " AND \"kind\" = " + Lit(kind));
	vector<string> inserts;
	idx_t pos = 0;
	for (auto &item : StringUtil::Split(pk, ',')) {
		auto column = item;
		StringUtil::Trim(column);
		if (column.size() >= 2 && column.front() == '"' && column.back() == '"') {
			// a quoted identifier stores and compares as its name, exactly as a column does
			column = StringUtil::Replace(column.substr(1, column.size() - 2), "\"\"", "\"");
		}
		if (column.empty()) {
			continue;
		}
		if (!known.empty() && std::find(known.begin(), known.end(), StringUtil::Lower(column)) == known.end()) {
			if (carried) {
				return statements;
			}
			throw InvalidInputException("acl: the primary key of \"%s\" names \"%s\", which is not a column "
			                            "of its declaration",
			                            vname, column);
		}
		auto mark = nullable_marks.find(column);
		if (mark != nullable_marks.end() && mark->second != 0) {
			if (carried) {
				return statements;
			}
			throw InvalidInputException("acl: \"%s\" is declared nullable and named in the primary key of "
			                            "\"%s\" - a key column cannot be nullable",
			                            column, vname);
		}
		// a computed or masked column may be NULL whatever the physical rows hold, so a key over one
		// is a promise the declaration cannot see through - unless the admin states NOT NULL
		// explicitly, which is theirs to make (spec 048)
		if (masked && (mark == nullable_marks.end() || mark->second != 0)) {
			for (auto &pair : *masked) {
				if (StringUtil::CIEquals(pair.first, column) && !pair.second.empty() && !BareIdentifier(pair.second)) {
					if (carried) {
						return statements;
					}
					throw InvalidInputException(
					    "acl: \"%s\" is computed by an expression, so the primary key of \"%s\" cannot "
					    "vouch that it is never NULL - declare the column NOT NULL explicitly to key it",
					    column, vname);
				}
			}
		}
		inserts.push_back("INSERT INTO " + Tbl("keys") + " VALUES (" + Lit(vcat) + ", " + Lit(vname) + ", " +
		                  Lit(kind) + ", " + std::to_string(pos++) + ", " + Lit(column) + ")");
	}
	statements.insert(statements.end(), inserts.begin(), inserts.end());
	return statements;
}

vector<string> CatalogBackend::ColumnSchemaStatements(const string &vcat, const string &vname, const string &kind,
                                                      const vector<std::pair<string, string>> &columns, bool derived,
                                                      const case_insensitive_map_t<int8_t> &nullable_marks) {
	vector<string> statements;
	statements.push_back("DELETE FROM " + Tbl("object_columns") + " WHERE \"vcat\" = " + Lit(vcat) +
	                     " AND \"vname\" = " + Lit(vname) + " AND \"kind\" = " + Lit(kind));
	idx_t pos = 0;
	for (auto &column : columns) {
		auto mark = nullable_marks.find(column.first);
		string nullable = mark == nullable_marks.end() ? "NULL" : (mark->second ? "true" : "false");
		statements.push_back("INSERT INTO " + Tbl("object_columns") + " VALUES (" + Lit(vcat) + ", " + Lit(vname) +
		                     ", " + Lit(kind) + ", " + std::to_string(pos++) + ", " + Lit(column.first) + ", " +
		                     Lit(column.second) + ", NULL, " + (derived ? "true" : "false") + ", " + nullable + ")");
	}
	return statements;
}

} // namespace acl_detail

using acl_detail::CatalogBackend;
using acl_detail::Lit;

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
//! The declared shape of spec 048 rides the same write: `pk` is the csv of key columns (empty =
//! none), `nullable_marks` the explicit per-column declarations (absent = undeclared). Both are
//! validated here, where the admin writes them, against whatever column names the write itself
//! establishes - and never enforced anywhere.
vector<string> RelationStatements(CatalogBackend &catalog, const string &vcat, const string &vname, const string &form,
                                  const string &phys, const string &view_sql, const string &rls,
                                  const vector<std::pair<string, string>> &columns, const string &comment,
                                  const string &returns, const string &origin = string(), const string &pk = string(),
                                  const case_insensitive_map_t<int8_t> &nullable_marks = {}, bool pk_carried = false,
                                  const string &alias_types = string(), const string &enum_types = string()) {
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
	                     " \"rls_checked\", \"alias_types\", \"enum_types\")"
	                     " VALUES (" +
	                     Lit(vcat) + ", " + Lit(vname) + ", " + Lit(form) + ", " + Lit(phys) + ", " + Lit(view_sql) +
	                     ", " + Lit(rls) + ", " + (comment.empty() ? string("NULL") : Lit(comment)) + ", " +
	                     (origin.empty() ? string("NULL") : Lit(origin)) + ", " +
	                     (rls.empty() ? "NULL" : (checked ? "true" : "false")) + ", " +
	                     (alias_types.empty() ? string("NULL") : Lit(alias_types)) + ", " +
	                     (enum_types.empty() ? string("NULL") : Lit(enum_types)) + ")");
	// spec 099: the source's types, probed here so the read can cast them without looking
	for (auto &statement : catalog.TypeFactStatements(vcat, vname, form, phys, view_sql)) {
		statements.push_back(statement);
	}
	idx_t pos = 0;
	for (auto &column : columns) {
		auto mark = nullable_marks.find(column.first);
		string nullable = mark == nullable_marks.end() ? "NULL" : (mark->second ? "true" : "false");
		statements.push_back("INSERT INTO " + catalog.Tbl("relation_columns") +
		                     "(\"vcat\", \"vname\", \"pos\", \"name\", \"expr\", \"nullable\") VALUES (" + Lit(vcat) +
		                     ", " + Lit(vname) + ", " + std::to_string(pos++) + ", " + Lit(column.first) + ", " +
		                     Lit(column.second) + ", " + nullable + ")");
	}
	// the object's column schema (spec 010): a view has no physical row and no declared projection,
	// so bind its SQL once, here on the write path; anything else keeps the projected names
	vector<std::pair<string, string>> schema;
	bool derived = false;
	if (!returns.empty()) {
		schema = CatalogBackend::ParseDeclaration(returns); // declared: never probed
	} else if (form == "view") {
		derived = catalog.ProbeSchema(view_sql, false, {}, schema);
	} else if ((form == "subquery" || form == "alias") && !phys.empty() && !columns.empty()) {
		// A projection is what the role sees, and a computed or masked column (`total = amount * 2`,
		// `ssn = NULL`) has no physical column to read a type from - so bind the projection once, here
		// on the write path, exactly as a view's SQL is bound (spec 010). Without this the column is
		// readable but typeless, and metadata cannot describe it (spec 010 part 3).
		vector<string> items;
		for (auto &column : columns) {
			items.push_back(column.second.empty() ? acl_detail::Ident(column.first)
			                                      : column.second + " AS " + acl_detail::Ident(column.first));
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
	for (auto &statement : catalog.ColumnSchemaStatements(vcat, vname, "relation", schema, derived, nullable_marks)) {
		statements.push_back(statement);
	}
	// the declared key (spec 048): validated against the names this very write establishes - the
	// projection, the declared/probed schema, or (for a bare alias) the source probed here for the
	// validation alone, storing nothing. A source that does not bind stays uncheckable, and the key
	// is then accepted the way an uncheckable predicate is.
	vector<string> known;
	for (auto &column : columns) {
		known.push_back(StringUtil::Lower(column.first));
	}
	for (auto &entry : schema) {
		known.push_back(StringUtil::Lower(entry.first));
	}
	if (known.empty() && !pk.empty() && !phys.empty()) {
		vector<std::pair<string, string>> probed;
		if (catalog.ProbeSchema("SELECT * FROM " + phys, false, {}, probed)) {
			for (auto &entry : probed) {
				known.push_back(StringUtil::Lower(entry.first));
			}
		}
	}
	for (auto &statement :
	     catalog.KeyStatements(vcat, vname, "relation", pk, known, nullable_marks, &columns, pk_carried)) {
		statements.push_back(statement);
	}
	return statements;
}

//! What a grant's projection actually produces, folded the way the resolver folds it (spec 026), as
//! the `grant_columns` rows for one grant. Shared by the write path, where a projection that cannot
//! bind is a mistake worth refusing, and by `acl_refresh_schema`, where it is only a fact that has
//! not become true yet (spec 027) - `strict` picks between the two.
using ReadFn = std::function<unique_ptr<QueryResult>(const string &)>;

//! The types of the columns an object exposes (spec 102's path check): its declared projection, or
//! the source's own columns. Empty when it does not bind here - the read path decides then.
vector<std::pair<string, LogicalType>> ExposedTypes(CatalogBackend &catalog, const ReadFn &read, const string &vcat,
                                                    const string &vname, const string &source) {
	auto rows = read("SELECT \"name\", \"expr\" FROM " + catalog.Tbl("relation_columns") +
	                 " WHERE \"vcat\" = " + Lit(vcat) + " AND \"vname\" = " + Lit(vname) + " ORDER BY \"pos\"");
	ResultRows rows_rows(*rows);
	vector<string> items;
	for (idx_t i = 0; i < rows->RowCount(); i++) {
		auto name = rows_rows.GetValue(0, i).ToString();
		auto expr = rows_rows.GetValue(1, i);
		items.push_back(expr.IsNull() || expr.ToString().empty() ? acl_detail::Ident(name)
		                                                         : expr.ToString() + " AS " + acl_detail::Ident(name));
	}
	vector<std::pair<string, LogicalType>> types;
	catalog.ProbeTypes("SELECT " + (items.empty() ? string("*") : StringUtil::Join(items, ", ")) + " FROM " + source,
	                   types);
	return types;
}

//! Every step of a column's tree against its type, the fields put in the type's order; a step into
//! anything but a STRUCT field or a LIST / ARRAY element is refused (a MAP's keys are data, a UNION's
//! members are not fields - spec 102, decision 5)
void OrderAndCheckFields(acl_detail::FieldNode &node, const LogicalType &type, const string &vname,
                         const string &path) {
	if (node.masked) {
		return;
	}
	if (node.element) {
		if (type.id() != LogicalTypeId::LIST && type.id() != LogicalTypeId::ARRAY) {
			throw InvalidInputException("acl: the grant on \"%s\" lists \"%s[]\", but \"%s\" is %s, not a list", vname,
			                            path, path, type.ToString());
		}
		auto &child = type.id() == LogicalTypeId::LIST ? ListType::GetChildType(type) : ArrayType::GetChildType(type);
		OrderAndCheckFields(*node.element, child, vname, path + "[]");
	}
	if (node.fields.empty()) {
		return;
	}
	if (type.id() != LogicalTypeId::STRUCT) {
		throw InvalidInputException("acl: the grant on \"%s\" lists fields of \"%s\", which is %s - only a STRUCT's "
		                            "fields can be named (a MAP or a UNION is shown or masked whole)",
		                            vname, path, type.ToString());
	}
	vector<unique_ptr<acl_detail::FieldNode>> ordered;
	for (auto &field : StructType::GetChildTypes(type)) {
		for (auto &child : node.fields) {
			if (child && StringUtil::CIEquals(child->name, field.first.GetIdentifierName())) {
				child->name = field.first.GetIdentifierName();
				OrderAndCheckFields(*child, field.second, vname, path + "." + acl_detail::FieldName(child->name));
				ordered.push_back(std::move(child));
				break;
			}
		}
	}
	for (auto &child : node.fields) {
		if (child) {
			throw InvalidInputException("acl: the grant on \"%s\" lists \"%s.%s\", which the type %s does not have",
			                            vname, path, child->name, type.ToString());
		}
	}
	node.fields = std::move(ordered);
}

//! A grant hides and masks; naming, computing and ordering belong to the virtual catalog (spec 037).
//! So a grant's column list may only name columns the object exposes, and the order it was written in
//! carries no meaning - the list is stored in the object's order, which makes a column's position a
//! property of the object rather than of whoever asks. An object this cannot be judged against (not
//! written yet, or a source that does not bind here) is left alone; the read path still refuses a
//! column the object does not expose.
string NormaliseGrantColumns(CatalogBackend &catalog, const ReadFn &read, const string &vcat, const string &vname,
                             const string &columns) {
	if (columns.empty()) {
		return columns;
	}
	auto shape = read("SELECT \"form\", \"phys\", \"view_sql\" FROM " + catalog.Tbl("relations") +
	                  " WHERE \"vcat\" = " + Lit(vcat) + " AND \"vname\" = " + Lit(vname));
	if (shape->RowCount() == 0) {
		return columns;
	}
	auto text = [&](idx_t column) {
		auto value = shape->Collection().GetValue(column, 0);
		return value.IsNull() ? string() : value.ToString();
	};
	auto form = text(0);
	string source = form == "view" ? "(" + text(2) + ")" : text(1);
	if (source.empty()) {
		return columns;
	}
	vector<string> declared;
	auto rows = read("SELECT \"name\" FROM " + catalog.Tbl("relation_columns") + " WHERE \"vcat\" = " + Lit(vcat) +
	                 " AND \"vname\" = " + Lit(vname) + " ORDER BY \"pos\"");
	ResultRows rows_rows(*rows);
	for (idx_t i = 0; i < rows->RowCount(); i++) {
		declared.push_back(rows_rows.GetValue(0, i).ToString());
	}
	vector<string> exposed;
	if (!catalog.ExposedColumns(source, declared, exposed)) {
		return columns;
	}
	auto listed = acl_detail::ParseColumnList(columns);
	// a name the object has as it is written is that column, dots and all (Parquet's `odd.col`), never a
	// path into `odd`: quoted so it reads back as one name
	for (auto &item : listed) {
		auto name = item.first;
		StringUtil::Trim(name);
		for (auto &column : exposed) {
			if (StringUtil::CIEquals(column, name) &&
			    (name.find('.') != string::npos || name.find('[') != string::npos)) {
				item.first = acl_detail::QuotedName(column);
			}
		}
	}
	auto trees = acl_detail::ColumnTrees::From(listed);
	for (auto &column : trees.columns) {
		bool found = false;
		for (auto &name : exposed) {
			if (StringUtil::CIEquals(name, column->name)) {
				found = true;
				column->name = name; // the object's spelling: one column, whatever case the grant wrote
				break;
			}
		}
		if (!found) {
			throw InvalidInputException(
			    "acl: the grant on \"%s\" lists \"%s\", which the object does not have - a grant may hide or mask a "
			    "column, but naming, computing and ordering belong to the virtual catalog (spec 037)",
			    vname, column->name);
		}
	}
	// spec 102: a path is checked against the column's type where the grant is written - every step a
	// field of a STRUCT or `[]` of a LIST / ARRAY - and its fields are put in the source's order
	if (acl_detail::HasFieldPaths(listed)) {
		auto types = ExposedTypes(catalog, read, vcat, vname, source);
		for (auto &column : trees.columns) {
			for (auto &type : types) {
				if (StringUtil::CIEquals(type.first, column->name)) {
					OrderAndCheckFields(*column, type.second, vname, column->name);
					break;
				}
			}
		}
	}
	vector<std::pair<string, string>> items;
	for (auto &name : exposed) {
		auto column = trees.Find(name);
		if (column) {
			acl_detail::SerializeNode(*column, acl_detail::ColumnTrees::RootName(*column), items);
		}
	}
	return acl_detail::ItemsCsv(items);
}

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
		auto value = shape->Collection().GetValue(column, 0);
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
		ResultRows rows_rows(*rows);
		for (idx_t i = 0; i < rows->RowCount(); i++) {
			own[rows_rows.GetValue(0, i).ToString()] =
			    rows_rows.GetValue(1, i).IsNull() ? string() : rows_rows.GetValue(1, i).ToString();
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

//! spec 102: a declared COLUMNS list may name fields (`address.city`): each such column becomes the
//! expression that reads only them, checked against the source's type where it is written and in the
//! source's field order, emitted once where the column first appears (a bare `address` beside its
//! paths keeps it whole). The relation is then the projection form, and the narrowed column is
//! read-only by design (spec 102 §7): a write narrows through a grant. A field mask is a grant's,
//! never the object's. Untouched when no entry is a path.
bool CompileDeclaredPaths(CatalogBackend &catalog, const string &phys, const string &vname,
                          vector<std::pair<string, string>> &columns) {
	auto is_path = [](const string &name) {
		acl_detail::FieldPath path;
		string error;
		return acl_detail::HasFieldPaths({{name, string()}}) && acl_detail::ParseFieldPath(name, path, error) &&
		       !path.IsColumn();
	};
	case_insensitive_set_t heads;
	for (auto &column : columns) {
		if (!is_path(column.first)) {
			continue;
		}
		if (!column.second.empty()) {
			throw InvalidInputException("acl: \"%s = %s\" masks a field in the object's own COLUMNS - a field mask "
			                            "belongs to a grant (GRANT TABLE ... COLUMNS (...)); the object names fields",
			                            column.first, column.second);
		}
		acl_detail::FieldPath path;
		string error;
		acl_detail::ParseFieldPath(column.first, path, error);
		heads.insert(path.head);
	}
	if (heads.empty()) {
		return false;
	}
	// the column's items - its paths, and a bare entry of it if there is one - as one tree
	vector<std::pair<string, string>> items;
	for (auto &column : columns) {
		if (!column.second.empty()) {
			continue;
		}
		acl_detail::FieldPath path;
		string error;
		auto head =
		    is_path(column.first) && acl_detail::ParseFieldPath(column.first, path, error) ? path.head : column.first;
		if (heads.count(head)) {
			items.push_back(column);
		}
	}
	auto trees = acl_detail::ColumnTrees::From(items);
	vector<std::pair<string, LogicalType>> types;
	if (!phys.empty()) {
		catalog.ProbeTypes("SELECT * FROM " + phys, types);
	}
	for (auto &column : trees.columns) {
		for (auto &type : types) {
			if (StringUtil::CIEquals(type.first, column->name)) {
				OrderAndCheckFields(*column, type.second, vname, column->name);
				break;
			}
		}
	}
	vector<std::pair<string, string>> compiled;
	case_insensitive_set_t emitted;
	for (auto &column : columns) {
		acl_detail::FieldPath path;
		string error;
		auto head =
		    column.second.empty() && is_path(column.first) && acl_detail::ParseFieldPath(column.first, path, error)
		        ? path.head
		        : column.first;
		if (!column.second.empty() || !heads.count(head)) {
			compiled.push_back(column);
			continue;
		}
		if (emitted.count(head)) {
			continue; // the column's tree was emitted where it first appeared
		}
		emitted.insert(head);
		auto tree = trees.Find(head);
		compiled.emplace_back(head, tree->Plain() ? string() : acl_detail::CompileNode(*tree, acl_detail::Ident(head)));
	}
	columns = std::move(compiled);
	return true;
}

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

void PolicyStore::CatalogAddRelation(const string &vcat, const string &vname, const string &form_p, const string &phys,
                                     const string &view_sql, const string &rls,
                                     const vector<std::pair<string, string>> &columns_p, const string &returns,
                                     const string &pk, const case_insensitive_map_t<int8_t> &nullable_marks) {
	RequireCatalog(catalog, "acl_add_relation");
	RequireNotReserved(vname);
	auto columns = columns_p;
	auto form = form_p;
	if (CompileDeclaredPaths(*catalog, phys, vname, columns)) {
		form = "subquery";
	}
	bool existed = false;
	catalog->WriteWithReads([&](const ReadFn &read, vector<string> &statements) {
		auto existing = read("SELECT \"comment\", \"alias_types\", \"enum_types\" FROM " + catalog->Tbl("relations") +
		                     " WHERE \"vcat\" = " + Lit(vcat) + " AND \"vname\" = " + Lit(vname));
		existed = existing->RowCount() > 0;
		// the comment and the type policy (spec 099) are the operator's, kept across a redeclaration
		string comment, alias_types, enum_types;
		if (existing->RowCount() > 0) {
			ResultRows kept(*existing);
			comment = kept.GetValue(0, 0).IsNull() ? string() : kept.GetValue(0, 0).ToString();
			alias_types = kept.GetValue(1, 0).IsNull() ? string() : kept.GetValue(1, 0).ToString();
			enum_types = kept.GetValue(2, 0).IsNull() ? string() : kept.GetValue(2, 0).ToString();
		}
		// a replace that states no key keeps the one declared before, exactly as the comment is kept: a
		// redeclaration is not a reason to lose it. It lapses only when the new shape no longer supports
		// it; removing one on purpose is ALTER ... DROP PRIMARY KEY (spec 048).
		string kept_pk = pk;
		bool pk_carried = false;
		if (pk.empty()) {
			auto keyed = read("SELECT \"column\" FROM " + catalog->Tbl("keys") + " WHERE \"vcat\" = " + Lit(vcat) +
			                  " AND \"vname\" = " + Lit(vname) + " AND \"kind\" = 'relation' ORDER BY \"pos\"");
			ResultRows keyed_rows(*keyed);
			vector<string> parts;
			for (idx_t row = 0; row < keyed->RowCount(); row++) {
				parts.push_back(keyed_rows.GetValue(0, row).ToString());
			}
			kept_pk = StringUtil::Join(parts, ", ");
			pk_carried = !kept_pk.empty();
		}
		statements = RelationStatements(*catalog, vcat, vname, form, phys, view_sql, rls, columns, comment, returns,
		                                string(), kept_pk, nullable_marks, pk_carried, alias_types, enum_types);
	});
	NoteDefinitionLineage(vcat, vname, existed ? "ALTER" : "CREATE");
}

namespace {

//! "expr AS name" -> (expr, name); a bare item is (name, name). The name unquoted.
std::pair<string, string> SplitProjectionItem(const string &item) {
	auto as = StringUtil::Lower(item).rfind(" as ");
	if (as == string::npos) {
		auto name = item;
		StringUtil::Trim(name);
		if (name.size() > 1 && name.front() == '"' && name.back() == '"') {
			name = StringUtil::Replace(name.substr(1, name.size() - 2), "\"\"", "\"");
		}
		return {name, name};
	}
	auto expr = item.substr(0, as);
	auto name = item.substr(as + 4);
	StringUtil::Trim(expr);
	StringUtil::Trim(name);
	if (name.size() > 1 && name.front() == '"' && name.back() == '"') {
		name = StringUtil::Replace(name.substr(1, name.size() - 2), "\"\"", "\"");
	}
	return {expr, name};
}

//! spec 107 §4: what each role holding `vcat` sees of `vcat.vname`, as OpenLineage tags - the
//! capabilities on the dataset, `visible` / `masked` per field path, `.rls` when a predicate applies.
//! A field the role does not see has no tag of that role. Resolved through the same policy a read
//! uses, one role at a time; nothing is bound and no claim is needed (the predicate is only present).
vector<AuditLineageTag> RoleTags(PolicyStore &store, CatalogBackend &catalog, const string &vcat, const string &vname,
                                 const vector<string> &fields, const case_insensitive_set_t &source_columns) {
	vector<AuditLineageTag> tags;
	vector<string> roles;
	try {
		auto rows = catalog.Query("SELECT DISTINCT \"role\" FROM " + catalog.Tbl("role_catalogs") +
		                          " WHERE \"vcat\" = " + Lit(vcat) + " UNION SELECT \"role\" FROM " +
		                          catalog.Tbl("role_object_caps") + " WHERE \"vcat\" = " + Lit(vcat) +
		                          " AND \"vname\" = " + Lit(vname) + " ORDER BY 1");
		ResultRows role_rows(*rows);
		for (idx_t i = 0; i < rows->RowCount(); i++) {
			roles.push_back(role_rows.GetValue(0, i).ToString());
		}
	} catch (std::exception &) {
		return tags;
	}
	for (auto &role : roles) {
		Principal principal;
		principal.roles = {role};
		TablePolicy policy;
		try {
			if (!store.ResolveTable(principal, vcat + "." + vname, policy) || policy.caps.empty()) {
				continue;
			}
		} catch (std::exception &) {
			continue; // a grant that no longer resolves (a mask over a vanished column, spec 038): no tags
		}
		auto key = "acl.role." + role;
		vector<string> caps(policy.caps.begin(), policy.caps.end());
		std::sort(caps.begin(), caps.end());
		tags.push_back(AuditLineageTag {key, StringUtil::Join(caps, ","), string()});
		if (!policy.rls.empty()) {
			tags.push_back(AuditLineageTag {key + ".rls", "true", string()});
		}
		case_insensitive_map_t<string> narrowed;
		for (auto &entry : policy.narrowed_reads) {
			narrowed[entry.first] = entry.second;
		}
		auto field_tags = [&](const string &column, bool masked) {
			auto entry = narrowed.find(column);
			if (entry == narrowed.end()) {
				tags.push_back(AuditLineageTag {key, masked ? "masked" : "visible", column});
				return;
			}
			// spec 102: the column's own items - `address.city`, `address.ssn = NULL` - one tag per path
			for (auto item : SplitTopLevel(entry->second, ',')) {
				StringUtil::Trim(item);
				auto eq = item.find('=');
				auto path = eq == string::npos ? item : item.substr(0, eq);
				StringUtil::Trim(path);
				tags.push_back(AuditLineageTag {key, eq == string::npos ? "visible" : "masked", path});
			}
		};
		if (policy.projection.empty()) {
			// a writable object a grant narrows keeps its shape: what the role reads is the grant's
			// visible columns (all of them when it names none), a masked one carried as an injection
			case_insensitive_set_t injected;
			for (auto &entry : policy.injections) {
				injected.insert(entry.first);
			}
			for (auto &field : fields) {
				if (!policy.visible_columns.empty() && !policy.visible_columns.count(field) && !narrowed.count(field)) {
					continue;
				}
				field_tags(field, injected.count(field) > 0);
			}
		} else {
			for (auto &item : policy.projection) {
				auto split = SplitProjectionItem(item);
				bool masked = !StringUtil::CIEquals(split.first, split.second) &&
				              !StringUtil::CIEquals(split.first, acl_detail::Ident(split.second)) &&
				              source_columns.count(split.second);
				field_tags(split.second, masked);
			}
		}
	}
	return tags;
}

} // namespace

void PolicyStore::NoteDefinitionLineage(const string &vcat, const string &vname, const string &lifecycle) {
	auto db = instance.lock();
	if (!db || !audit || !catalog || !lineage_worker || !LineageOn(*db)) {
		return;
	}
	EnqueueLineageTask(*lineage_worker, [vcat, vname, lifecycle](PolicyStore &store) {
		store.EmitDefinitionLineageNow(vcat, vname, lifecycle);
	});
}

void PolicyStore::NoteGrantLineage(const string &vcat, const string &vname) {
	auto db = instance.lock();
	if (!db || !audit || !catalog || !lineage_worker || !LineageOn(*db)) {
		return;
	}
	EnqueueLineageTask(*lineage_worker, [vcat, vname](PolicyStore &store) { store.EmitGrantLineageNow(vcat, vname); });
}

void PolicyStore::EmitDefinitionLineageNow(const string &vcat, const string &vname, const string &lifecycle) {
	auto db = instance.lock();
	if (!db || !audit || !catalog) {
		return;
	}
	auto settings = LineageSettings::Read(*db);
	if (!settings.on) {
		return;
	}
	if (lifecycle == "DROP") {
		EmitDefinitionLineage(*audit, *db, vcat, vname, "TABLE", lifecycle, nullptr);
		return;
	}
	// the definition as it now stands - read back after the commit, so every writer (add, alter,
	// repair) reports the same thing: what a read of the object is made of
	string form, phys, view_sql, rls;
	vector<string> items;
	case_insensitive_set_t masks; // `c = expr` over a column the source has: a mask, not a computed column
	case_insensitive_set_t source_columns;
	try {
		auto relation =
		    catalog->Query("SELECT \"form\", \"phys\", \"view_sql\", \"rls\" FROM " + catalog->Tbl("relations") +
		                   " WHERE \"vcat\" = " + Lit(vcat) + " AND \"vname\" = " + Lit(vname));
		if (relation->RowCount() == 0) {
			return;
		}
		ResultRows row(*relation);
		auto text = [&](idx_t col) {
			return row.GetValue(col, 0).IsNull() ? string() : row.GetValue(col, 0).ToString();
		};
		form = text(0);
		phys = text(1);
		view_sql = text(2);
		rls = text(3);
		auto columns =
		    catalog->Query("SELECT \"name\", \"expr\" FROM " + catalog->Tbl("relation_columns") +
		                   " WHERE \"vcat\" = " + Lit(vcat) + " AND \"vname\" = " + Lit(vname) + " ORDER BY \"pos\"");
		ResultRows column_rows(*columns);
		if (form != "view" && !phys.empty()) {
			vector<std::pair<string, string>> probed;
			if (catalog->ProbeSchema("SELECT * FROM " + phys, false, {}, probed)) {
				for (auto &entry : probed) {
					source_columns.insert(entry.first);
				}
			}
		}
		for (idx_t i = 0; i < columns->RowCount(); i++) {
			auto name = column_rows.GetValue(0, i).ToString();
			auto expr = column_rows.GetValue(1, i).IsNull() ? string() : column_rows.GetValue(1, i).ToString();
			items.push_back(expr.empty() ? acl_detail::Ident(name) : expr + " AS " + acl_detail::Ident(name));
			if (!expr.empty() && source_columns.count(name)) {
				masks.insert(name);
			}
		}
	} catch (std::exception &) {
		EmitDefinitionLineage(*audit, *db, vcat, vname, "TABLE", lifecycle, nullptr);
		return;
	}
	string sql;
	if (form == "view") {
		sql = view_sql;
	} else if (!phys.empty()) {
		sql = "SELECT " + (items.empty() ? string("*") : StringUtil::Join(items, ", ")) + " FROM " + phys +
		      (rls.empty() ? string() : " WHERE " + rls);
	}
	LineageWalk walk;
	bool walked = false;
	if (!sql.empty()) {
		try {
			// markers (acl_claim, acl_arg) baked the way a probe bakes them: the plan's shape, no value
			walked = WalkDefinition(*db, BakeTemplateForProbe(sql, ParserOptions::Builtin(), false, {}),
			                        settings.max_edges, walk);
		} catch (std::exception &) {
			walked = false;
		}
	}
	for (auto &output : walk.outputs) {
		if (masks.count(output.name)) {
			for (auto &source : output.sources) {
				if (source.type == "DIRECT") {
					source.masking = true;
				}
			}
		}
	}
	vector<string> fields;
	for (auto &output : walk.outputs) {
		fields.push_back(output.name);
	}
	vector<AuditLineageTag> tags;
	try {
		tags = RoleTags(*this, *catalog, vcat, vname, fields, source_columns);
	} catch (std::exception &) {
		tags.clear(); // the tags could not be made: the definition still goes out
	}
	EmitDefinitionLineage(*audit, *db, vcat, vname, form == "view" ? "VIEW" : "TABLE", lifecycle,
	                      walked ? &walk : nullptr, tags);
}

void PolicyStore::NoteFunctionLineage(const string &vcat, const string &vname, const string &lifecycle) {
	auto db = instance.lock();
	if (!db || !audit || !catalog || !lineage_worker || !LineageOn(*db)) {
		return;
	}
	EnqueueLineageTask(*lineage_worker, [vcat, vname, lifecycle](PolicyStore &store) {
		store.EmitFunctionLineageNow(vcat, vname, lifecycle);
	});
}

void PolicyStore::EmitFunctionLineageNow(const string &vcat, const string &vname, const string &lifecycle) {
	auto db = instance.lock();
	if (!db || !audit || !catalog) {
		return;
	}
	auto settings = LineageSettings::Read(*db);
	if (!settings.on) {
		return;
	}
	if (lifecycle == "DROP") {
		EmitDefinitionLineage(*audit, *db, vcat, vname, "TABLE_FUNCTION", lifecycle, nullptr);
		return;
	}
	string form, template_sql, params;
	vector<string> declared;
	try {
		auto row = catalog->Query("SELECT \"form\", \"template\", \"params\" FROM " + catalog->Tbl("functions") +
		                          " WHERE \"vcat\" = " + Lit(vcat) + " AND \"vname\" = " + Lit(vname) +
		                          " AND \"kind\" = 'table'");
		if (row->RowCount() == 0) {
			return;
		}
		ResultRows rows(*row);
		auto text = [&](idx_t col) {
			return rows.GetValue(col, 0).IsNull() ? string() : rows.GetValue(col, 0).ToString();
		};
		form = text(0);
		template_sql = text(1);
		params = text(2);
		auto columns =
		    catalog->Query("SELECT \"name\" FROM " + catalog->Tbl("object_columns") + " WHERE \"vcat\" = " + Lit(vcat) +
		                   " AND \"vname\" = " + Lit(vname) + " AND \"kind\" = 'table' ORDER BY \"pos\"");
		ResultRows column_rows(*columns);
		for (idx_t i = 0; i < columns->RowCount(); i++) {
			declared.push_back(column_rows.GetValue(0, i).ToString());
		}
	} catch (std::exception &) {
		EmitDefinitionLineage(*audit, *db, vcat, vname, "TABLE_FUNCTION", lifecycle, nullptr);
		return;
	}
	LineageWalk walk;
	bool walked = false;
	if (form == "macro" && !template_sql.empty()) {
		try {
			// the arguments are NULLs of their declared types: the body's shape, never a value
			walked = WalkDefinition(*db,
			                        BakeTemplateForProbe(template_sql, ParserOptions::Builtin(), false,
			                                             CatalogBackend::DeclaredTypes(params)),
			                        settings.max_edges, walk);
		} catch (std::exception &) {
			walked = false;
		}
	}
	if (!walked) {
		// an alias of a physical function, or a body that does not bind: the declared result, no edges
		walk = LineageWalk();
		for (auto &name : declared) {
			LineageOutput output;
			output.name = name;
			walk.outputs.push_back(std::move(output));
		}
		walk.approximate = true;
	}
	EmitDefinitionLineage(*audit, *db, vcat, vname, "TABLE_FUNCTION", lifecycle, &walk);
}

void PolicyStore::EmitGrantLineageNow(const string &vcat, const string &vname) {
	auto db = instance.lock();
	if (!db || !audit || !catalog || !LineageSettings::Read(*db).on) {
		return;
	}
	vector<string> objects;
	if (!vname.empty()) {
		objects.push_back(vname);
	} else {
		try {
			auto rows = catalog->Query("SELECT \"vname\" FROM " + catalog->Tbl("relations") +
			                           " WHERE \"vcat\" = " + Lit(vcat) + " ORDER BY 1");
			ResultRows object_rows(*rows);
			for (idx_t i = 0; i < rows->RowCount(); i++) {
				objects.push_back(object_rows.GetValue(0, i).ToString());
			}
		} catch (std::exception &) {
			return;
		}
	}
	for (auto &object : objects) {
		// the definition again, with the tags as they now stand; a grant is not a lifecycle change.
		// One object that does not resolve (a source that drifted) costs its own event, not the rest's.
		try {
			EmitDefinitionLineageNow(vcat, object, string());
		} catch (std::exception &) {
		}
	}
	if (!vname.empty()) {
		return;
	}
	// the catalog's table functions: their definitions (a function's grant narrows nothing per field)
	vector<string> functions;
	try {
		auto rows = catalog->Query("SELECT \"vname\" FROM " + catalog->Tbl("functions") +
		                           " WHERE \"vcat\" = " + Lit(vcat) + " AND \"kind\" = 'table' ORDER BY 1");
		ResultRows function_rows(*rows);
		for (idx_t i = 0; i < rows->RowCount(); i++) {
			functions.push_back(function_rows.GetValue(0, i).ToString());
		}
	} catch (std::exception &) {
		return;
	}
	for (auto &function : functions) {
		try {
			EmitFunctionLineageNow(vcat, function, string());
		} catch (std::exception &) {
		}
	}
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
	catalog->WriteWithReads([&](const ReadFn &read, vector<string> &statements) {
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
			if (!found->Collection().GetValue(0, 0).IsNull()) {
				for (auto &parameter :
				     CatalogBackend::ParseDeclaration(found->Collection().GetValue(0, 0).ToString())) {
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
			auto options = ParserOptions::Builtin();
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
				if (known->Collection().GetValue(1, 0).GetValue<int64_t>() > 0 &&
				    known->Collection().GetValue(0, 0).GetValue<int64_t>() == 0) {
					missing();
				}
				continue;
			}
			auto declared = read("SELECT count(*) FILTER (WHERE \"name\" = " + Lit(column_name) + "), count(*) FROM " +
			                     catalog->Tbl("relation_columns") + " WHERE \"vcat\" = " + Lit(vcat) +
			                     " AND \"vname\" = " + Lit(end));
			if (declared->Collection().GetValue(1, 0).GetValue<int64_t>() > 0) {
				if (declared->Collection().GetValue(0, 0).GetValue<int64_t>() == 0) {
					missing();
				}
				continue;
			}
			auto probed = read("SELECT count(*) FILTER (WHERE \"name\" = " + Lit(column_name) + "), count(*) FROM " +
			                   catalog->Tbl("object_columns") + " WHERE \"vcat\" = " + Lit(vcat) +
			                   " AND \"kind\" = 'relation' AND \"vname\" = " + Lit(end));
			if (probed->Collection().GetValue(1, 0).GetValue<int64_t>() > 0) {
				if (probed->Collection().GetValue(0, 0).GetValue<int64_t>() == 0) {
					missing();
				}
				continue;
			}
			auto phys = read("SELECT \"phys\" FROM " + catalog->Tbl("relations") + " WHERE \"vcat\" = " + Lit(vcat) +
			                 " AND \"vname\" = " + Lit(end));
			if (phys->RowCount() == 0 || phys->Collection().GetValue(0, 0).IsNull()) {
				continue;
			}
			auto source = phys->Collection().GetValue(0, 0).ToString();
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
	catalog->WriteWithReads([&](const ReadFn &read, vector<string> &statements) {
		auto where = " WHERE \"vcat\" = " + Lit(vcat) + " AND \"path\" = " + Lit(alias_path);
		auto current = read("SELECT \"comment\" FROM " + catalog->Tbl("schemas") + where);
		string comment = "NULL";
		if (current->RowCount() > 0 && !current->Collection().GetValue(0, 0).IsNull()) {
			comment = Lit(current->Collection().GetValue(0, 0).ToString());
		}
		statements.push_back("DELETE FROM " + catalog->Tbl("schemas") + where);
		statements.push_back("INSERT INTO " + catalog->Tbl("schemas") +
		                     "(\"vcat\", \"path\", \"phys_path\", \"comment\", \"origin\") VALUES (" + Lit(vcat) +
		                     ", " + Lit(alias_path) + ", " + (phys_path.empty() ? "NULL" : Lit(phys_path)) + ", " +
		                     comment + ", " + (origin.empty() ? "NULL" : Lit(origin)) + ")");
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
	ResultRows listing_rows(*listing);
	vector<string> names;
	for (idx_t row = 0; row < listing->RowCount(); row++) {
		names.push_back(listing_rows.GetValue(0, row).ToString());
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
	catalog->WriteWithReads([&](const ReadFn &read, vector<string> &statements) {
		statements = RelationStatements(*catalog, vcat, vname, "view", "", body, "", {}, "", "");
	});
}

void PolicyStore::CatalogRegisterCreated(const string &vcat, const string &vname, const string &phys,
                                         const string &origin) {
	RequireCatalog(catalog, "acl_register_created");
	// fixed shape: an alias-form record of the object just created, stamped with the schema's origin
	// so REFRESH and PRUNE own it like the rest of the expansion
	catalog->WriteWithReads([&](const ReadFn &read, vector<string> &statements) {
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

bool PolicyStore::CatalogRelationDeclared(const string &vcat, const string &vname) {
	if (!catalog) {
		return false;
	}
	auto is = [&](const char *table, const string &extra) {
		return catalog
		           ->Query("SELECT 1 FROM " + catalog->Tbl(table) + " WHERE \"vcat\" = " + Lit(vcat) + " AND " + extra +
		                   " LIMIT 1")
		           ->RowCount() > 0;
	};
	auto named = "\"vname\" = " + Lit(vname);
	return is("relations", named + " AND coalesce(\"rls\", '') <> ''") || is("relation_columns", named) ||
	       is("keys", named) || is("role_object_caps", named) || is("grant_columns", named) ||
	       is("references", "(\"from_vname\" = " + Lit(vname) + " OR \"to_vname\" = " + Lit(vname) + ")");
}

void PolicyStore::CatalogRenameRelation(const string &vcat, const string &vname, const string &new_vname,
                                        const string &new_phys) {
	RequireCatalog(catalog, "acl_rename_relation");
	RequireNotReserved(new_vname);
	bool had_record = false;
	catalog->WriteWithReads([&](const ReadFn &read, vector<string> &statements) {
		auto where = [&](const string &name) {
			return " WHERE \"vcat\" = " + Lit(vcat) + " AND \"vname\" = " + Lit(name);
		};
		had_record = read("SELECT 1 FROM " + catalog->Tbl("relations") + where(vname))->RowCount() > 0;
		if (!had_record) {
			return; // a live alias's object: nothing recorded, the physical rename is the whole of it
		}
		statements.push_back("UPDATE " + catalog->Tbl("relations") + " SET \"vname\" = " + Lit(new_vname) +
		                     (new_phys.empty() ? string() : ", \"phys\" = " + Lit(new_phys)) + where(vname));
		for (auto table : {"relation_types", "object_columns"}) {
			statements.push_back("UPDATE " + string(catalog->Tbl(table)) + " SET \"vname\" = " + Lit(new_vname) +
			                     where(vname));
		}
		// the new name is current; the old one is gone on purpose and must not come back by REFRESH
		auto dot = new_vname.rfind('.');
		if (dot != string::npos) {
			statements.push_back("DELETE FROM " + catalog->Tbl("schema_dropped") + " WHERE \"vcat\" = " + Lit(vcat) +
			                     " AND \"path\" = " + Lit(new_vname.substr(0, dot)) +
			                     " AND \"name\" = " + Lit(new_vname.substr(dot + 1)));
		}
	});
	if (had_record) {
		// lineage (spec 107/113): the old name ends, the new one begins - the backend follows a swap
		NoteDefinitionLineage(vcat, vname, "DROP");
		NoteDefinitionLineage(vcat, new_vname, "CREATE");
	}
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
	catalog->WriteWithReads([&](const ReadFn &read, vector<string> &statements) {
		auto prefix = path.empty() ? string() : path + ".";
		auto in_subtree = [&](const string &column) {
			return path.empty() ? string("true")
			                    : "(" + column + " = " + Lit(path) + " OR substr(" + column + ", 1, " +
			                          std::to_string(prefix.size()) + ") = " + Lit(prefix) + ")";
		};
		auto schemas = read("SELECT \"path\" FROM " + catalog->Tbl("schemas") + " WHERE \"vcat\" = " + Lit(vcat) +
		                    " AND " + in_subtree("\"path\"") + " ORDER BY length(\"path\")");
		ResultRows schemas_rows(*schemas);
		// every explicit grant of the catalog, per role, longest path first: the first ancestor in
		// that order is the nearest one, which is also what makes an explicit row stop the cascade
		auto rows = read("SELECT \"role\", \"schema_path\", \"caps\", \"into\", \"virtual_only\" FROM " +
		                 catalog->Tbl("role_schemas") + " WHERE \"vcat\" = " + Lit(vcat) +
		                 " AND NOT \"inherited\""
		                 " ORDER BY \"role\", length(\"schema_path\") DESC");
		ResultRows rows_rows(*rows);
		struct SchemaGrant {
			string path;
			string caps;
			string into;
			bool virtual_only;
		};
		vector<string> roles;
		case_insensitive_map_t<vector<SchemaGrant>> granted;
		for (idx_t row = 0; row < rows->RowCount(); row++) {
			auto role = rows_rows.GetValue(0, row).ToString();
			auto caps = rows_rows.GetValue(2, row);
			auto into = rows_rows.GetValue(3, row);
			auto only = rows_rows.GetValue(4, row);
			if (!granted.count(role)) {
				roles.push_back(role);
			}
			granted[role].push_back({rows_rows.GetValue(1, row).ToString(), caps.IsNull() ? string() : caps.ToString(),
			                         into.IsNull() ? string() : into.ToString(),
			                         !only.IsNull() && only.GetValue<bool>()});
		}
		// drop what was inherited inside the subtree: it is about to be recomputed
		statements.push_back("DELETE FROM " + catalog->Tbl("role_schemas") + " WHERE \"vcat\" = " + Lit(vcat) +
		                     " AND \"inherited\" AND " + in_subtree("\"schema_path\""));
		for (idx_t row = 0; row < schemas->RowCount(); row++) {
			auto schema_path = schemas_rows.GetValue(0, row).ToString();
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
	catalog->WriteWithReads([&](const ReadFn &read, vector<string> &statements) {
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
	auto origin_value = source->Collection().GetValue(0, 0);
	if (origin_value.IsNull()) {
		throw BinderException("acl admin: schema \"%s.%s\" is a live alias, so it has nothing to refresh - it "
		                      "already shows what the source holds",
		                      vcat, path);
	}
	auto origin = origin_value.ToString();
	auto names = PhysicalObjects(*catalog, origin);
	int64_t changed = 0;
	catalog->WriteWithReads([&](const ReadFn &read, vector<string> &statements) {
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
		ResultRows stale_rows(*stale);
		for (idx_t row = 0; row < stale->RowCount(); row++) {
			auto vname = stale_rows.GetValue(0, row).ToString();
			auto name = vname.substr(path.size() + 1);
			if (std::find(names.begin(), names.end(), name) != names.end()) {
				continue;
			}
			for (auto table : {"relations", "relation_columns", "relation_types", "role_object_caps"}) {
				statements.push_back("DELETE FROM " + catalog->Tbl(table) + " WHERE \"vcat\" = " + Lit(vcat) +
				                     " AND \"vname\" = " + Lit(vname));
			}
			// a vanished relation takes only its own key: a same-named table function keeps its rows
			statements.push_back("DELETE FROM " + catalog->Tbl("keys") + " WHERE \"vcat\" = " + Lit(vcat) +
			                     " AND \"vname\" = " + Lit(vname) + " AND \"kind\" = 'relation'");
			statements.push_back("DELETE FROM " + catalog->Tbl("object_columns") + " WHERE \"vcat\" = " + Lit(vcat) +
			                     " AND \"vname\" = " + Lit(vname) + " AND \"kind\" = 'relation'");
			changed++;
		}
	});
	return changed;
}

//! The stored key of one object, as the csv the writers take - what an ALTER carries through so a
//! redefinition does not silently drop a declaration (spec 048).
string PolicyStore::ExistingKeyCsv(const string &vcat, const string &vname, const string &kind) {
	auto rows = catalog->Query("SELECT \"column\" FROM " + catalog->Tbl("keys") + " WHERE \"vcat\" = " + Lit(vcat) +
	                           " AND \"vname\" = " + Lit(vname) + " AND \"kind\" = " + Lit(kind) + " ORDER BY \"pos\"");
	ResultRows rows_rows(*rows);
	vector<string> columns;
	for (idx_t row = 0; row < rows->RowCount(); row++) {
		columns.push_back(rows_rows.GetValue(0, row).ToString());
	}
	return StringUtil::Join(columns, ", ");
}

void PolicyStore::CatalogSetKey(const string &vcat, const string &vname, const string &kind, const string &pk) {
	RequireCatalog(catalog, "acl_set_key");
	// the target must exist: silently keying a name that is not there is a typo kept forever
	if (StringUtil::CIEquals(kind, "relation")) {
		auto exists = catalog->Query("SELECT 1 FROM " + catalog->Tbl("relations") + " WHERE \"vcat\" = " + Lit(vcat) +
		                             " AND \"vname\" = " + Lit(vname));
		if (exists->RowCount() == 0) {
			throw BinderException("acl admin: relation \"%s.%s\" does not exist", vcat, vname);
		}
	} else {
		auto exists = catalog->Query("SELECT 1 FROM " + catalog->Tbl("functions") + " WHERE \"vcat\" = " + Lit(vcat) +
		                             " AND \"vname\" = " + Lit(vname) + " AND \"kind\" = " + Lit(kind));
		if (exists->RowCount() == 0) {
			throw BinderException("acl admin: %s function \"%s.%s\" does not exist", kind, vcat, vname);
		}
	}
	// validate against the stored schema when there is one; none stored = nothing checkable
	vector<string> known;
	auto rows =
	    catalog->Query("SELECT \"name\" FROM " + catalog->Tbl("object_columns") + " WHERE \"vcat\" = " + Lit(vcat) +
	                   " AND \"vname\" = " + Lit(vname) + " AND \"kind\" = " + Lit(kind));
	ResultRows rows_rows(*rows);
	for (idx_t row = 0; row < rows->RowCount(); row++) {
		known.push_back(StringUtil::Lower(rows_rows.GetValue(0, row).ToString()));
	}
	// the declared marks and the projection's expressions: an explicitly nullable or a masked column
	// is refused as a key here exactly as it is where the object is declared (spec 048)
	case_insensitive_map_t<int8_t> marks;
	auto marked = catalog->Query("SELECT \"name\", \"nullable\" FROM " + catalog->Tbl("object_columns") +
	                             " WHERE \"vcat\" = " + Lit(vcat) + " AND \"vname\" = " + Lit(vname) +
	                             " AND \"kind\" = " + Lit(kind) + " AND \"nullable\" IS NOT NULL");
	ResultRows marked_rows(*marked);
	for (idx_t row = 0; row < marked->RowCount(); row++) {
		marks[marked_rows.GetValue(0, row).ToString()] = marked_rows.GetValue(1, row).GetValue<bool>() ? 1 : 0;
	}
	vector<std::pair<string, string>> masked;
	if (StringUtil::CIEquals(kind, "relation")) {
		auto declared =
		    catalog->Query("SELECT \"name\", \"expr\", \"nullable\" FROM " + catalog->Tbl("relation_columns") +
		                   " WHERE \"vcat\" = " + Lit(vcat) + " AND \"vname\" = " + Lit(vname) + " ORDER BY \"pos\"");
		ResultRows declared_rows(*declared);
		vector<string> projected;
		for (idx_t row = 0; row < declared->RowCount(); row++) {
			auto name = declared_rows.GetValue(0, row).ToString();
			auto expr = declared_rows.GetValue(1, row);
			masked.emplace_back(name, expr.IsNull() ? string() : expr.ToString());
			auto nullable = declared_rows.GetValue(2, row);
			if (!nullable.IsNull()) {
				marks[name] = nullable.GetValue<bool>() ? 1 : 0;
			}
			projected.push_back(StringUtil::Lower(name));
		}
		if (known.empty()) {
			known = projected;
		}
	}
	// a bare alias declares nothing, but its source may bind here: probe it for the validation alone,
	// storing nothing - a source that does not bind leaves the key uncheckable-accepted (spec 048)
	if (known.empty() && StringUtil::CIEquals(kind, "relation")) {
		auto phys_row = catalog->Query("SELECT \"phys\" FROM " + catalog->Tbl("relations") +
		                               " WHERE \"vcat\" = " + Lit(vcat) + " AND \"vname\" = " + Lit(vname));
		if (phys_row->RowCount() > 0 && !phys_row->Collection().GetValue(0, 0).IsNull()) {
			auto phys = phys_row->Collection().GetValue(0, 0).ToString();
			vector<std::pair<string, string>> probed;
			if (!phys.empty() && catalog->ProbeSchema("SELECT * FROM " + phys, false, {}, probed)) {
				for (auto &entry : probed) {
					known.push_back(StringUtil::Lower(entry.first));
				}
			}
		}
	}
	catalog->Write(catalog->KeyStatements(vcat, vname, kind, pk, known, marks, &masked)); // Write bumps policy_version
}

void PolicyStore::CatalogAddFunction(const string &vcat, const string &vname, const string &kind, const string &form,
                                     const string &target, const string &template_sql, const string &params,
                                     const string &returns, const string &pk,
                                     const case_insensitive_map_t<int8_t> &nullable_marks, bool pk_carried) {
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
	for (auto &statement : catalog->ColumnSchemaStatements(vcat, vname, kind, schema, derived, nullable_marks)) {
		statements.push_back(statement);
	}
	vector<string> known;
	for (auto &entry : schema) {
		known.push_back(StringUtil::Lower(entry.first));
	}
	for (auto &statement : catalog->KeyStatements(vcat, vname, kind, pk, known, nullable_marks, nullptr, pk_carried)) {
		statements.push_back(statement);
	}
	catalog->Write(statements);
	if (kind == "table") {
		NoteFunctionLineage(vcat, vname, "CREATE");
	}
}

namespace {

//! spec 065: a grant's COLUMNS list is judged where it is written - against the shapes the catalog
//! already knows, never by probing. Only the BARE items are judged: a `name = expr` entry defines a
//! new column (a mask, a computed column - spec 026) and owes nothing to any existing name. Names
//! come from relation_columns (declared mappings) and object_columns (declared/probed shapes,
//! relations and functions alike), read with the same ParseColumnList the read path uses. The
//! judgment fires only when it CAN be right: a scope with no declared shape at all (an empty
//! catalog, a grant written before its objects), one shape-less object, an undeclared table
//! function, or any alias schema - and the write is allowed, because the list may match there. A
//! bare list that matches nothing anywhere known is certainly a typo, and the principal it
//! misconfigures would otherwise meet the engine's error instead of this one.
void ValidateGrantColumns(CatalogBackend &catalog, const string &vcat, const string &columns,
                          const string &object_scope) {
	if (columns.empty() || catalog.FunctionMode()) {
		return; // nothing listed, or a keyed-lookup driver with nothing to enumerate
	}
	vector<string> names;
	for (auto &column : acl_detail::ParseColumnList(columns)) {
		auto name = column.first;
		StringUtil::Trim(name);
		if (!name.empty() && column.second.empty()) {
			names.push_back(Lit(StringUtil::Lower(name)));
		}
	}
	if (names.empty()) {
		return; // every item defines its own column; there is nothing that must already exist
	}
	auto in_list = "(" + StringUtil::Join(names, ", ") + ")";
	string scope = object_scope.empty() ? string() : " AND \"vname\" = " + Lit(object_scope);
	// nothing declared in scope - a fresh catalog, a grant written before its objects - is not
	// judgeable; neither is an object-scope target without a declared shape
	auto shaped =
	    catalog.Query("SELECT 1 FROM (SELECT 1 FROM " + catalog.Tbl("relation_columns") +
	                  " WHERE \"vcat\" = " + Lit(vcat) + scope + " UNION ALL SELECT 1 FROM " +
	                  catalog.Tbl("object_columns") + " WHERE \"vcat\" = " + Lit(vcat) + scope + ") s LIMIT 1");
	if (shaped->RowCount() == 0) {
		return;
	}
	if (object_scope.empty()) {
		// catalog scope: an alias schema or a shape-less object anywhere means we cannot judge
		auto aliases = catalog.Query("SELECT 1 FROM " + catalog.Tbl("schemas") + " WHERE \"vcat\" = " + Lit(vcat) +
		                             " AND \"phys_path\" IS NOT NULL LIMIT 1");
		if (aliases->RowCount() > 0) {
			return;
		}
		auto shapeless = catalog.Query("SELECT 1 FROM (SELECT \"vname\" FROM " + catalog.Tbl("relations") +
		                               " WHERE \"vcat\" = " + Lit(vcat) + " UNION ALL SELECT \"vname\" FROM " +
		                               catalog.Tbl("functions") + " WHERE \"vcat\" = " + Lit(vcat) +
		                               " AND \"kind\" = 'table') o WHERE NOT EXISTS (SELECT 1 FROM " +
		                               catalog.Tbl("relation_columns") + " c WHERE c.\"vcat\" = " + Lit(vcat) +
		                               " AND c.\"vname\" = o.\"vname\")"
		                               " AND NOT EXISTS (SELECT 1 FROM " +
		                               catalog.Tbl("object_columns") + " oc WHERE oc.\"vcat\" = " + Lit(vcat) +
		                               " AND oc.\"vname\" = o.\"vname\") LIMIT 1");
		if (shapeless->RowCount() > 0) {
			return;
		}
	}
	auto match = catalog.Query("SELECT 1 FROM (SELECT lower(\"name\") AS n FROM " + catalog.Tbl("relation_columns") +
	                           " WHERE \"vcat\" = " + Lit(vcat) + scope + " UNION ALL SELECT lower(\"name\") FROM " +
	                           catalog.Tbl("object_columns") + " WHERE \"vcat\" = " + Lit(vcat) + scope +
	                           ") s WHERE n IN " + in_list + " LIMIT 1");
	if (match->RowCount() == 0) {
		throw BinderException(
		    "acl admin: COLUMNS (%s) matches no column of %s - "
		    "every shape this catalog declares was checked, and nothing the list names exists",
		    columns, object_scope.empty() ? "any object of catalog \"" + vcat + "\"" : "\"" + object_scope + "\"");
	}
}

} // namespace

void PolicyStore::CatalogGrant(const string &role, const string &vcat, const string &caps_json, bool is_main,
                               const string &rls, const string &columns, bool judge_columns) {
	RequireCatalog(catalog, "acl_grant_catalog");
	if (vcat.empty()) {
		throw BinderException("acl admin: a grant needs a catalog name");
	}
	acl_detail::ParseCaps(caps_json); // validate before persisting
	if (judge_columns) {              // only where the list itself is being written - never re-judging a stored one
		ValidateGrantColumns(*catalog, vcat, columns, "");
	}
	// the verdict is read on the connection that writes it (spec 027), so what it judges the predicate
	// against is the catalog this grant commits into
	catalog->WriteWithReads([&](const ReadFn &read, vector<string> &statements) {
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
	NoteGrantLineage(vcat); // spec 107: what the role sees changed
}

void PolicyStore::CatalogRevoke(const string &role, const string &vcat) {
	RequireCatalog(catalog, "acl_revoke_catalog");
	catalog->Write({"DELETE FROM " + catalog->Tbl("role_catalogs") + " WHERE \"role\" = " + Lit(role) +
	                    " AND \"vcat\" = " + Lit(vcat),
	                "DELETE FROM " + catalog->Tbl("role_object_caps") + " WHERE \"role\" = " + Lit(role) +
	                    " AND \"vcat\" = " + Lit(vcat),
	                "DELETE FROM " + catalog->Tbl("grant_columns") + " WHERE \"role\" = " + Lit(role) +
	                    " AND \"vcat\" = " + Lit(vcat)});
	NoteGrantLineage(vcat); // spec 107
}

namespace {

//! Builds the name test for a given column, so one call covers a single object (`"vname" = 'x'`) and a
//! whole schema prefix alike.
using NamePred = std::function<string(const char *)>;

NamePred ExactName(const string &vname) {
	return [vname](const char *column) {
		return "\"" + string(column) + "\" = " + Lit(vname);
	};
}

NamePred PrefixName(const string &path) {
	return [path](const char *column) {
		return "substr(\"" + string(column) + "\", 1, " + std::to_string(path.size() + 1) + ") = " + Lit(path + ".");
	};
}

//! A reference is a declared join path between two objects (spec 022). When either end goes the path
//! is not a hint any more, it is a lie - so it goes with the end, and so do the columns it recorded.
//! Nothing is refused: a reference grants nothing, so it must never stand in the way of a drop.
void DropReferencesNaming(CatalogBackend &catalog, const string &vcat, const NamePred &pred,
                          vector<string> &statements) {
	auto in_cat = " WHERE \"vcat\" = " + Lit(vcat) + " AND ";
	auto ends = "(" + pred("from_vname") + " OR " + pred("to_vname") + ")";
	// the columns first: their rows are found through the references they belong to
	statements.push_back("DELETE FROM " + catalog.Tbl("reference_columns") + in_cat +
	                     "\"name\" IN (SELECT \"name\" FROM " + catalog.Tbl("references") + in_cat + ends + ")");
	statements.push_back("DELETE FROM " + catalog.Tbl("references") + in_cat + ends);
}

//! What a grant recorded about one name: the grant itself and the projection probed for it (spec 026).
//! `role_object_caps` is keyed by name alone, so a name shared by a relation and a function has one
//! row for both - which is why this is only called once nothing of that name is left.
void DropGrantRowsFor(CatalogBackend &catalog, const string &vcat, const NamePred &pred, vector<string> &statements) {
	auto in_cat = " WHERE \"vcat\" = " + Lit(vcat) + " AND ";
	for (auto table : {"role_object_caps", "grant_columns"}) {
		statements.push_back("DELETE FROM " + catalog.Tbl(table) + in_cat + pred("vname"));
	}
}

} // namespace

void PolicyStore::CatalogDropRelation(const string &vcat, const string &vname) {
	RequireCatalog(catalog, "acl_drop_relation");
	// dropping something that is not there is an error, not a silent success (spec 010) - the other
	// kinds already said so; the relation drop was the one that stayed quiet. DROP … IF EXISTS is
	// how a re-runnable script asks for the silent version (spec 013).
	if (!CatalogObjectExists(vcat, vname, "relation")) {
		throw BinderException("acl admin: relation \"%s.%s\" does not exist", vcat, vname);
	}
	// One transaction for the reads that decide and every row that goes (the 2026-09-03 review): a
	// drop that read outside and wrote twice could leave the object's grants live after its record
	// was gone - access the admin believed revoked. The other writers already use this shape.
	auto pred = ExactName(vname);
	catalog->WriteWithReads([&](const ReadFn &read, vector<string> &statements) {
		statements.push_back("DELETE FROM " + catalog->Tbl("relations") + " WHERE \"vcat\" = " + Lit(vcat) +
		                     " AND \"vname\" = " + Lit(vname));
		statements.push_back("DELETE FROM " + catalog->Tbl("object_columns") + " WHERE \"vcat\" = " + Lit(vcat) +
		                     " AND \"vname\" = " + Lit(vname) + " AND \"kind\" = 'relation'");
		statements.push_back("DELETE FROM " + catalog->Tbl("relation_columns") + " WHERE \"vcat\" = " + Lit(vcat) +
		                     " AND \"vname\" = " + Lit(vname));
		statements.push_back("DELETE FROM " + catalog->Tbl("relation_types") + " WHERE \"vcat\" = " + Lit(vcat) +
		                     " AND \"vname\" = " + Lit(vname));
		statements.push_back("DELETE FROM " + catalog->Tbl("keys") + " WHERE \"vcat\" = " + Lit(vcat) +
		                     " AND \"vname\" = " + Lit(vname) + " AND \"kind\" = 'relation'");
		// a function of the same name keeps the grant, because the grant row cannot tell them apart
		auto same_named_function =
		    read("SELECT 1 FROM " + catalog->Tbl("functions") + " WHERE \"vcat\" = " + Lit(vcat) +
		         " AND \"vname\" = " + Lit(vname) + " LIMIT 1");
		if (same_named_function->RowCount() == 0) {
			DropGrantRowsFor(*catalog, vcat, pred, statements);
		}
		DropReferencesNaming(*catalog, vcat, pred, statements);
		// a record an expansion produced is remembered as dropped, so the next REFRESH does not
		// bring it back: excluding one object is the whole reason to expand a schema instead of
		// aliasing it
		auto origin = read("SELECT \"origin\" FROM " + catalog->Tbl("relations") + " WHERE \"vcat\" = " + Lit(vcat) +
		                   " AND \"vname\" = " + Lit(vname));
		if (origin->RowCount() > 0 && !origin->Collection().GetValue(0, 0).IsNull()) {
			auto dot = vname.rfind('.');
			if (dot != string::npos) {
				statements.push_back("INSERT OR IGNORE INTO " + catalog->Tbl("schema_dropped") + " VALUES (" +
				                     Lit(vcat) + ", " + Lit(vname.substr(0, dot)) + ", " + Lit(vname.substr(dot + 1)) +
				                     ")");
			}
		}
	});
	NoteDefinitionLineage(vcat, vname, "DROP");
}

void PolicyStore::CatalogSetComment(const string &vcat, const string &vname, const string &kind, const string &column,
                                    const string &comment) {
	RequireCatalog(catalog, "acl_comment");
	catalog->WriteWithReads([&](const ReadFn &read, vector<string> &statements) {
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
	catalog->WriteWithReads([&](const ReadFn &read, vector<string> &statements) {
		string name_filter = vname.empty() ? string() : " AND \"vname\" = " + Lit(vname);
		// a declared schema is never re-derived: it is the admin's statement of fact
		auto declared = read("SELECT \"vname\", \"kind\" FROM " + catalog->Tbl("object_columns") +
		                     " WHERE \"vcat\" = " + Lit(vcat) + " AND \"derived\" = false" + name_filter);
		ResultRows declared_rows(*declared);
		case_insensitive_set_t declared_keys;
		for (idx_t row = 0; row < declared->RowCount(); row++) {
			declared_keys.insert(declared_rows.GetValue(0, row).ToString() + "\x1f" +
			                     declared_rows.GetValue(1, row).ToString());
		}
		// What a re-derivation must not lose: the declared nullability marks (spec 048) and the
		// column comments (spec 010) ride in object_columns beside the derived schema, and the schema
		// statements rewrite the rows - so both are read first and written back after (spec 039
		// review: ANALYZE used to drop them).
		auto rederive = [&](const string &object, const string &kind, const vector<std::pair<string, string>> &schema,
		                    bool derived, case_insensitive_map_t<int8_t> marks) {
			auto kept = read("SELECT \"name\", \"nullable\", \"comment\" FROM " + catalog->Tbl("object_columns") +
			                 " WHERE \"vcat\" = " + Lit(vcat) + " AND \"vname\" = " + Lit(object) + " AND \"kind\" = " +
			                 Lit(kind) + " AND (\"nullable\" IS NOT NULL OR \"comment\" IS NOT NULL)");
			ResultRows kept_rows(*kept);
			vector<std::pair<string, string>> comments;
			for (idx_t i = 0; i < kept->RowCount(); i++) {
				auto name = kept_rows.GetValue(0, i).ToString();
				auto nullable = kept_rows.GetValue(1, i);
				if (!nullable.IsNull() && marks.find(name) == marks.end()) {
					marks[name] = nullable.GetValue<bool>() ? 1 : 0;
				}
				auto comment = kept_rows.GetValue(2, i);
				if (!comment.IsNull()) {
					comments.emplace_back(name, comment.ToString());
				}
			}
			for (auto &statement : catalog->ColumnSchemaStatements(vcat, object, kind, schema, derived, marks)) {
				statements.push_back(statement);
			}
			for (auto &comment : comments) {
				statements.push_back("UPDATE " + catalog->Tbl("object_columns") +
				                     " SET \"comment\" = " + Lit(comment.second) + " WHERE \"vcat\" = " + Lit(vcat) +
				                     " AND \"vname\" = " + Lit(object) + " AND \"kind\" = " + Lit(kind) +
				                     " AND \"name\" = " + Lit(comment.first));
			}
			refreshed++;
		};
		// only query-defined objects have a derived schema; an alias reads the physical catalog live
		auto views = read("SELECT \"vname\", \"view_sql\" FROM " + catalog->Tbl("relations") +
		                  " WHERE \"vcat\" = " + Lit(vcat) + " AND \"form\" = 'view'" + name_filter);
		ResultRows views_rows(*views);
		for (idx_t row = 0; row < views->RowCount(); row++) {
			auto object = views_rows.GetValue(0, row).ToString();
			if (declared_keys.count(object + "\x1frelation")) {
				continue;
			}
			auto sql = views_rows.GetValue(1, row);
			vector<std::pair<string, string>> schema;
			bool derived = !sql.IsNull() && catalog->ProbeSchema(sql.ToString(), false, {}, schema);
			rederive(object, "relation", schema, derived, {});
		}
		// spec 039: a declared-list table's projection schema is derived at write exactly as a view's
		// (RelationStatements binds `expr AS name` over the source once) and drifts exactly as a
		// view's - a retyped source column - so ANALYZE re-derives it the same way. The declared
		// marks on the list itself are carried too.
		auto projections = read(
		    "SELECT r.\"vname\", r.\"phys\" FROM " + catalog->Tbl("relations") + " r WHERE r.\"vcat\" = " + Lit(vcat) +
		    " AND r.\"form\" IN ('alias', 'subquery')" + " AND r.\"phys\" IS NOT NULL AND EXISTS (SELECT 1 FROM " +
		    catalog->Tbl("relation_columns") + " c WHERE c.\"vcat\" = r.\"vcat\" AND c.\"vname\" = r.\"vname\")" +
		    (vname.empty() ? string() : " AND r.\"vname\" = " + Lit(vname)));
		ResultRows projections_rows(*projections);
		for (idx_t row = 0; row < projections->RowCount(); row++) {
			auto object = projections_rows.GetValue(0, row).ToString();
			if (declared_keys.count(object + "\x1frelation")) {
				continue;
			}
			auto phys = projections_rows.GetValue(1, row).ToString();
			auto columns =
			    read("SELECT \"name\", \"expr\", \"nullable\" FROM " + catalog->Tbl("relation_columns") +
			         " WHERE \"vcat\" = " + Lit(vcat) + " AND \"vname\" = " + Lit(object) + " ORDER BY \"pos\"");
			ResultRows columns_rows(*columns);
			vector<string> items;
			vector<std::pair<string, string>> names_only;
			case_insensitive_map_t<int8_t> marks;
			for (idx_t i = 0; i < columns->RowCount(); i++) {
				auto name = columns_rows.GetValue(0, i).ToString();
				auto expr = columns_rows.GetValue(1, i);
				items.push_back(expr.IsNull() || expr.ToString().empty()
				                    ? acl_detail::Ident(name)
				                    : expr.ToString() + " AS " + acl_detail::Ident(name));
				names_only.emplace_back(name, string());
				auto nullable = columns_rows.GetValue(2, i);
				if (!nullable.IsNull()) {
					marks[name] = nullable.GetValue<bool>() ? 1 : 0;
				}
			}
			vector<std::pair<string, string>> schema;
			bool derived =
			    catalog->ProbeSchema("SELECT " + StringUtil::Join(items, ", ") + " FROM " + phys, false, {}, schema);
			rederive(object, "relation", derived ? schema : names_only, derived, marks);
		}
		auto macros = read("SELECT \"vname\", \"kind\", \"template\", \"params\" FROM " + catalog->Tbl("functions") +
		                   " WHERE \"vcat\" = " + Lit(vcat) + " AND \"form\" = 'macro'" + name_filter);
		ResultRows macros_rows(*macros);
		for (idx_t row = 0; row < macros->RowCount(); row++) {
			auto object = macros_rows.GetValue(0, row).ToString();
			auto kind = macros_rows.GetValue(1, row).ToString();
			if (declared_keys.count(object + "\x1f" + kind)) {
				continue;
			}
			auto sql = macros_rows.GetValue(2, row);
			auto params = macros_rows.GetValue(3, row);
			vector<std::pair<string, string>> schema;
			bool derived = !sql.IsNull() &&
			               catalog->ProbeSchema(
			                   sql.ToString(), kind == "scalar",
			                   CatalogBackend::DeclaredTypes(params.IsNull() ? string() : params.ToString()), schema);
			rederive(object, kind, schema, derived, {});
		}
		// spec 027: the verdicts, not only the schemas. A predicate written while its object could not
		// be bound was accepted unchecked (spec 021), and a grant's projection was left unprobed for
		// the same reason (spec 026) - both are facts about the physical world, and this is the moment
		// the physical world is looked at again.
		auto shapes = read("SELECT \"vname\", \"form\", \"phys\", \"view_sql\", \"rls\" FROM " +
		                   catalog->Tbl("relations") + " WHERE \"vcat\" = " + Lit(vcat) + name_filter);
		ResultRows shapes_rows(*shapes);
		case_insensitive_map_t<string> sources;
		for (idx_t row = 0; row < shapes->RowCount(); row++) {
			auto text = [&](idx_t column) {
				auto value = shapes_rows.GetValue(column, row);
				return value.IsNull() ? string() : value.ToString();
			};
			auto object = text(0);
			auto source = text(1) == "view" ? "(" + text(3) + ")" : text(2);
			sources[object] = source;
			// spec 099: the source's types are a fact about the physical world too
			for (auto &statement : catalog->TypeFactStatements(vcat, object, text(1), text(2), text(3))) {
				statements.push_back(statement);
			}
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
		ResultRows grants_rows(*grants);
		for (idx_t row = 0; row < grants->RowCount(); row++) {
			auto text = [&](idx_t column) {
				auto value = grants_rows.GetValue(column, row);
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
			ResultRows catalog_grants_rows(*catalog_grants);
			for (idx_t row = 0; row < catalog_grants->RowCount(); row++) {
				auto role = catalog_grants_rows.GetValue(0, row).ToString();
				auto rls = catalog_grants_rows.GetValue(1, row).ToString();
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
	catalog->WriteWithReads([&](const ReadFn &read, vector<string> &statements) {
		auto exists = read("SELECT 1 FROM " + catalog->Tbl("catalogs") + " WHERE \"vcat\" = " + Lit(vcat));
		if (exists->RowCount() == 0) {
			throw BinderException("acl admin: catalog \"%s\" does not exist", vcat);
		}
		auto holders = read("SELECT \"role\" FROM " + catalog->Tbl("role_catalogs") + " WHERE \"vcat\" = " + Lit(vcat) +
		                    " ORDER BY \"role\"");
		ResultRows holders_rows(*holders);
		if (holders->RowCount() > 0 && !cascade) {
			vector<string> roles;
			for (idx_t row = 0; row < holders->RowCount(); row++) {
				roles.push_back(holders_rows.GetValue(0, row).ToString());
			}
			throw BinderException("acl admin: catalog \"%s\" is still granted to %s - repeat with CASCADE to "
			                      "drop those grants too",
			                      vcat, StringUtil::Join(roles, ", "));
		}
		for (auto table : {"relations", "relation_columns", "relation_types", "schemas", "functions", "object_columns",
		                   "references", "reference_columns", "schema_dropped", "keys"}) {
			statements.push_back("DELETE FROM " + catalog->Tbl(table) + " WHERE \"vcat\" = " + Lit(vcat));
		}
		if (cascade) {
			for (auto table : {"role_catalogs", "role_object_caps", "grant_columns", "role_schemas"}) {
				statements.push_back("DELETE FROM " + catalog->Tbl(table) + " WHERE \"vcat\" = " + Lit(vcat));
			}
		}
		statements.push_back("DELETE FROM " + catalog->Tbl("catalogs") + " WHERE \"vcat\" = " + Lit(vcat));
	});
}

void PolicyStore::CatalogDropSchemaAlias(const string &vcat, const string &alias_path, bool cascade) {
	RequireCatalog(catalog, "acl_drop_schema_alias");
	catalog->WriteWithReads([&](const ReadFn &read, vector<string> &statements) {
		auto where = " WHERE \"vcat\" = " + Lit(vcat) + " AND \"path\" = " + Lit(alias_path);
		auto exists = read("SELECT 1 FROM " + catalog->Tbl("schemas") + where);
		if (exists->RowCount() == 0) {
			throw BinderException("acl admin: schema \"%s.%s\" does not exist", vcat, alias_path);
		}
		// an expansion's records are relations of the catalog in their own right, so they go only with
		// CASCADE - the rule DROP VIRTUAL CATALOG already follows for grants (spec 010)
		auto prefix =
		    " AND substr(\"vname\", 1, " + std::to_string(alias_path.size() + 1) + ") = " + Lit(alias_path + ".");
		auto records = read("SELECT (SELECT count(*) FROM " + catalog->Tbl("relations") +
		                    " WHERE \"vcat\" = " + Lit(vcat) + prefix + ") + (SELECT count(*) FROM " +
		                    catalog->Tbl("functions") + " WHERE \"vcat\" = " + Lit(vcat) + prefix + ")");
		auto count = records->Collection().GetValue(0, 0).GetValue<int64_t>();
		if (count > 0 && !cascade) {
			throw BinderException("acl admin: schema \"%s.%s\" still holds %lld object(s) - repeat with CASCADE to "
			                      "drop them too",
			                      vcat, alias_path, count);
		}
		if (cascade) {
			for (auto table :
			     {"relations", "relation_columns", "relation_types", "object_columns", "functions", "keys"}) {
				statements.push_back("DELETE FROM " + catalog->Tbl(table) + " WHERE \"vcat\" = " + Lit(vcat) + prefix);
			}
			auto under = PrefixName(alias_path);
			DropGrantRowsFor(*catalog, vcat, under, statements);
			DropReferencesNaming(*catalog, vcat, under, statements);
			statements.push_back("DELETE FROM " + catalog->Tbl("schema_dropped") + " WHERE \"vcat\" = " + Lit(vcat) +
			                     " AND \"path\" = " + Lit(alias_path));
		}
		statements.push_back("DELETE FROM " + catalog->Tbl("schemas") + where);
		// the schema is gone, and so are the grants that named it - inherited or not
		statements.push_back("DELETE FROM " + catalog->Tbl("role_schemas") + " WHERE \"vcat\" = " + Lit(vcat) +
		                     " AND \"schema_path\" = " + Lit(alias_path));
	});
}

void PolicyStore::CatalogDropFunction(const string &vcat, const string &vname, const string &kind) {
	RequireCatalog(catalog, "acl_drop_function");
	catalog->WriteWithReads([&](const ReadFn &read, vector<string> &statements) {
		auto exists = read("SELECT 1 FROM " + catalog->Tbl("functions") + " WHERE \"vcat\" = " + Lit(vcat) +
		                   " AND \"vname\" = " + Lit(vname) + " AND \"kind\" = " + Lit(kind));
		if (exists->RowCount() == 0) {
			throw BinderException("acl admin: %s function \"%s.%s\" does not exist", kind, vcat, vname);
		}
		statements.push_back("DELETE FROM " + catalog->Tbl("functions") + " WHERE \"vcat\" = " + Lit(vcat) +
		                     " AND \"vname\" = " + Lit(vname) + " AND \"kind\" = " + Lit(kind));
		statements.push_back("DELETE FROM " + catalog->Tbl("object_columns") + " WHERE \"vcat\" = " + Lit(vcat) +
		                     " AND \"vname\" = " + Lit(vname) + " AND \"kind\" = " + Lit(kind));
		statements.push_back("DELETE FROM " + catalog->Tbl("keys") + " WHERE \"vcat\" = " + Lit(vcat) +
		                     " AND \"vname\" = " + Lit(vname) + " AND \"kind\" = " + Lit(kind));
		auto pred = ExactName(vname);
		// the grant rows name the object, not its kind: they go only once nothing of that name is left
		auto others =
		    read("SELECT 1 FROM " + catalog->Tbl("relations") + " WHERE \"vcat\" = " + Lit(vcat) +
		         " AND \"vname\" = " + Lit(vname) + " UNION ALL SELECT 1 FROM " + catalog->Tbl("functions") +
		         " WHERE \"vcat\" = " + Lit(vcat) + " AND \"vname\" = " + Lit(vname) + " AND \"kind\" <> " + Lit(kind));
		if (others->RowCount() == 0) {
			DropGrantRowsFor(*catalog, vcat, pred, statements);
		}
		DropReferencesNaming(*catalog, vcat, pred, statements);
	});
	if (kind == "table") {
		NoteFunctionLineage(vcat, vname, "DROP");
	}
}

void PolicyStore::CatalogDropRole(const string &role) {
	RequireCatalog(catalog, "acl_drop_role");
	catalog->WriteWithReads([&](const ReadFn &read, vector<string> &statements) {
		auto exists = read("SELECT 1 FROM " + catalog->Tbl("roles") + " WHERE \"role\" = " + Lit(role));
		if (exists->RowCount() == 0) {
			throw BinderException("acl admin: role \"%s\" does not exist", role);
		}
		// everything that points at a role goes with it - nothing may dangle
		for (auto table : {"role_claims", "role_catalogs", "role_object_caps", "grant_columns", "role_schemas",
		                   "admins", "role_mappings", "role_resource_groups"}) {
			statements.push_back("DELETE FROM " + catalog->Tbl(table) + " WHERE \"role\" = " + Lit(role));
		}
		statements.push_back("DELETE FROM " + catalog->Tbl("roles") + " WHERE \"role\" = " + Lit(role));
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

// spec 072: the function categories' writers. A key is stored lowercased throughout - function,
// schema and catalog names compare case-insensitively in duckdb, and the table's primary key does not,
// so `SYSTEM.main.x` and `system.main.x` must be one row.
namespace {

string KeyWhere(const FunctionKey &key) {
	return " \"database\" = " + Lit(StringUtil::Lower(key.database)) +
	       " AND \"schema\" = " + Lit(StringUtil::Lower(key.schema)) +
	       " AND \"name\" = " + Lit(StringUtil::Lower(key.name)) + " AND \"kind\" = " + Lit(FunctionKindName(key.kind));
}

string KeyValues(const FunctionKey &key) {
	return Lit(StringUtil::Lower(key.database)) + ", " + Lit(StringUtil::Lower(key.schema)) + ", " +
	       Lit(StringUtil::Lower(key.name)) + ", " + Lit(FunctionKindName(key.kind));
}

} // namespace

void PolicyStore::CatalogCreateFunctionCategory(const string &name, const string &comment) {
	RequireCatalog(catalog, "acl_create_function_category");
	catalog->WriteWithReads([&](const ReadFn &read, vector<string> &statements) {
		auto exists =
		    read("SELECT 1 FROM " + catalog->Tbl("function_categories") + " WHERE \"category\" = " + Lit(name));
		if (exists->RowCount() > 0) {
			// the comment is the one thing a re-create may change; the members and grants stay
			statements.push_back("UPDATE " + catalog->Tbl("function_categories") +
			                     " SET \"comment\" = " + Lit(comment) + " WHERE \"category\" = " + Lit(name));
			return;
		}
		statements.push_back("INSERT INTO " + catalog->Tbl("function_categories") + " VALUES (" + Lit(name) + ", " +
		                     Lit(comment) + ", false)");
	});
}

void PolicyStore::CatalogDropFunctionCategory(const string &name, bool if_exists) {
	RequireCatalog(catalog, "acl_drop_function_category");
	catalog->WriteWithReads([&](const ReadFn &read, vector<string> &statements) {
		auto exists =
		    read("SELECT 1 FROM " + catalog->Tbl("function_categories") + " WHERE \"category\" = " + Lit(name));
		if (exists->RowCount() == 0) {
			if (if_exists) {
				return; // IF EXISTS: nothing to drop is not an error
			}
			throw BinderException("acl admin: function category \"%s\" does not exist", name);
		}
		// its members and every grant on it go with it: a grant on a category that is gone would be a
		// row nothing reads, and a member of it a key nobody could reach through it
		statements.push_back("DELETE FROM " + catalog->Tbl("function_grants") + " WHERE \"category\" = " + Lit(name));
		statements.push_back("DELETE FROM " + catalog->Tbl("function_category_members") +
		                     " WHERE \"category\" = " + Lit(name));
		statements.push_back("DELETE FROM " + catalog->Tbl("function_categories") +
		                     " WHERE \"category\" = " + Lit(name));
	});
}

void PolicyStore::CatalogFunctionCategoryMembers(const string &name, const vector<FunctionKey> &keys, bool add) {
	RequireCatalog(catalog, add ? "acl_function_category_add" : "acl_function_category_remove");
	catalog->WriteWithReads([&](const ReadFn &read, vector<string> &statements) {
		auto exists =
		    read("SELECT 1 FROM " + catalog->Tbl("function_categories") + " WHERE \"category\" = " + Lit(name));
		if (exists->RowCount() == 0) {
			throw BinderException("acl admin: function category \"%s\" does not exist", name);
		}
		for (auto &key : keys) {
			statements.push_back("DELETE FROM " + catalog->Tbl("function_category_members") +
			                     " WHERE \"category\" = " + Lit(name) + " AND" + KeyWhere(key));
			if (add) {
				statements.push_back("INSERT INTO " + catalog->Tbl("function_category_members") + " VALUES (" +
				                     Lit(name) + ", " + KeyValues(key) + ")");
			}
		}
	});
}

//! spec 096: at most one group is the default - marking a second one is refused, naming the current
static void RequireNoOtherDefault(CatalogBackend &catalog, const ReadFn &read, const string &name) {
	auto current = read("SELECT \"group\" FROM " + catalog.Tbl("resource_groups") +
	                    " WHERE \"is_default\" = true AND \"group\" <> " + Lit(name));
	if (current->RowCount() > 0) {
		auto other = current->Collection().GetValue(0, 0).ToString();
		throw BinderException("acl admin: resource group \"%s\" is already the default - ALTER RESOURCE GROUP %s DROP "
		                      "DEFAULT first (moving every principal without a group is a change made on purpose)",
		                      other, other);
	}
}

void PolicyStore::CatalogCreateResourceGroup(const string &name, const case_insensitive_map_t<int64_t> &limits,
                                             const string &comment, const string &is_default) {
	RequireCatalog(catalog, "acl_create_resource_group");
	vector<string> values {Lit(name)};
	for (auto limit : RESOURCE_LIMIT_NAMES) {
		auto it = limits.find(limit);
		values.push_back(it == limits.end() ? string("NULL") : std::to_string(it->second));
	}
	values.push_back(Lit(comment));
	catalog->WriteWithReads([&](const ReadFn &read, vector<string> &statements) {
		// a re-create replaces the limits and the comment; the roles bound to it stay bound, and it stays
		// the default (or not) unless the statement says DEFAULT (spec 096)
		string marked = is_default;
		if (marked.empty()) {
			auto was = read("SELECT \"is_default\" FROM " + catalog->Tbl("resource_groups") +
			                " WHERE \"group\" = " + Lit(name) + " AND \"is_default\" = true");
			marked = was->RowCount() > 0 ? "true" : "false";
		}
		if (marked == "true") {
			RequireNoOtherDefault(*catalog, read, name);
		}
		values.push_back(marked == "true" ? "true" : "NULL");
		statements.push_back("DELETE FROM " + catalog->Tbl("resource_groups") + " WHERE \"group\" = " + Lit(name));
		statements.push_back("INSERT INTO " + catalog->Tbl("resource_groups") +
		                     " (\"group\", \"window_start\", \"window_max\", \"batch_bytes\", \"max_result_rows\", "
		                     "\"queue_priority\", \"max_sessions\", \"comment\", \"is_default\") VALUES (" +
		                     StringUtil::Join(values, ", ") + ")");
	});
}

void PolicyStore::CatalogSetDefaultResourceGroup(const string &name, bool is_default) {
	RequireCatalog(catalog, "acl_alter_resource_group");
	catalog->WriteWithReads([&](const ReadFn &read, vector<string> &statements) {
		auto exists = read("SELECT 1 FROM " + catalog->Tbl("resource_groups") + " WHERE \"group\" = " + Lit(name));
		if (exists->RowCount() == 0) {
			throw BinderException("acl admin: resource group \"%s\" does not exist", name);
		}
		if (is_default) {
			RequireNoOtherDefault(*catalog, read, name);
		}
		statements.push_back("UPDATE " + catalog->Tbl("resource_groups") + " SET \"is_default\" = " +
		                     (is_default ? "true" : "NULL") + " WHERE \"group\" = " + Lit(name));
	});
}

void PolicyStore::CatalogDropResourceGroup(const string &name, bool if_exists) {
	RequireCatalog(catalog, "acl_drop_resource_group");
	catalog->WriteWithReads([&](const ReadFn &read, vector<string> &statements) {
		auto exists = read("SELECT 1 FROM " + catalog->Tbl("resource_groups") + " WHERE \"group\" = " + Lit(name));
		if (exists->RowCount() == 0) {
			if (if_exists) {
				return;
			}
			throw BinderException("acl admin: resource group \"%s\" does not exist", name);
		}
		// spec 096: its part of the cluster profile is its nodes' bootstrap - removed first, on purpose,
		// never orphaned (a scope nothing can write to again, revived by a group of the same name)
		auto items = read("SELECT \"kind\" || ' ' || \"name\" FROM " + catalog->Tbl("cluster_items") +
		                  " WHERE \"scope\" = " + Lit(name) + " ORDER BY 1");
		ResultRows item_rows(*items);
		if (item_rows.Count() > 0) {
			vector<string> named;
			for (idx_t i = 0; i < item_rows.Count(); i++) {
				named.push_back(item_rows.GetValue(0, i).ToString());
			}
			throw BinderException("acl admin: resource group \"%s\" has cluster profile items (%s) - remove them "
			                      "(ACL CLUSTER … IN GROUP %s) first",
			                      name, StringUtil::Join(named, ", "), name);
		}
		// its bindings go with it: a role bound to a group that is gone would be a row nothing reads
		statements.push_back("DELETE FROM " + catalog->Tbl("role_resource_groups") + " WHERE \"group\" = " + Lit(name));
		statements.push_back("DELETE FROM " + catalog->Tbl("resource_groups") + " WHERE \"group\" = " + Lit(name));
	});
}

void PolicyStore::CatalogBindResourceGroup(const string &role, const string &group, bool remove) {
	RequireCatalog(catalog, remove ? "acl_revoke_resource_group" : "acl_grant_resource_group");
	catalog->WriteWithReads([&](const ReadFn &read, vector<string> &statements) {
		if (!remove) {
			auto group_exists =
			    read("SELECT 1 FROM " + catalog->Tbl("resource_groups") + " WHERE \"group\" = " + Lit(group));
			if (group_exists->RowCount() == 0) {
				throw BinderException("acl admin: resource group \"%s\" does not exist", group);
			}
			auto role_exists = read("SELECT 1 FROM " + catalog->Tbl("roles") + " WHERE \"role\" = " + Lit(role));
			if (role_exists->RowCount() == 0) {
				throw BinderException("acl admin: role \"%s\" does not exist", role);
			}
		}
		statements.push_back("DELETE FROM " + catalog->Tbl("role_resource_groups") + " WHERE \"role\" = " + Lit(role) +
		                     " AND \"group\" = " + Lit(group));
		if (!remove) {
			statements.push_back("INSERT INTO " + catalog->Tbl("role_resource_groups") + " VALUES (" + Lit(role) +
			                     ", " + Lit(group) + ")");
		}
	});
}

void PolicyStore::CatalogWriteFunctionGrant(const string &role, const string &category,
                                            optional_ptr<const FunctionKey> key, bool allowed, bool remove) {
	RequireCatalog(catalog, "acl_grant_function");
	string where = " WHERE \"role\" = " + Lit(role) + " AND \"category\" = " + Lit(category) + " AND";
	string values = Lit(role) + ", " + Lit(category) + ", ";
	if (key) {
		where += KeyWhere(*key);
		values += KeyValues(*key);
	} else {
		where += " \"database\" = '' AND \"schema\" = '' AND \"name\" = '' AND \"kind\" = ''";
		values += "'', '', '', ''";
	}
	catalog->WriteWithReads([&](const ReadFn &read, vector<string> &statements) {
		if (!category.empty() && !remove) {
			auto exists =
			    read("SELECT 1 FROM " + catalog->Tbl("function_categories") + " WHERE \"category\" = " + Lit(category));
			if (exists->RowCount() == 0) {
				throw BinderException("acl admin: function category \"%s\" does not exist", category);
			}
		}
		statements.push_back("DELETE FROM " + catalog->Tbl("function_grants") + where);
		if (!remove) {
			statements.push_back("INSERT INTO " + catalog->Tbl("function_grants") + " VALUES (" + values + ", " +
			                     (allowed ? "true" : "false") + ")");
		}
	});
}

namespace {

//! ALTER targets must exist: read the single row, or fail with a specific message
unique_ptr<QueryResult> RequireRow(CatalogBackend &catalog, const string &sql, const string &what) {
	auto result = catalog.Query(sql);
	if (result->RowCount() == 0) {
		throw BinderException("acl admin: %s does not exist", what);
	}
	return result;
}

} // namespace

void PolicyStore::CatalogAlterRelation(const string &vcat, const string &vname, const string &field,
                                       const string &value, const vector<std::pair<string, string>> &columns,
                                       const case_insensitive_map_t<int8_t> &nullable_marks) {
	RequireCatalog(catalog, "acl_alter_relation");
	catalog->WriteWithReads([&](const ReadFn &read, vector<string> &statements) {
		auto current = read("SELECT \"form\", \"phys\", \"view_sql\", \"rls\" FROM " + catalog->Tbl("relations") +
		                    " WHERE \"vcat\" = " + Lit(vcat) + " AND \"vname\" = " + Lit(vname));
		if (current->RowCount() == 0) {
			throw BinderException("acl admin: relation \"%s.%s\" does not exist", vcat, vname);
		}
		auto form = current->Collection().GetValue(0, 0).ToString();
		// the statement kind must match what the object is: silently turning a masked/RLS table into
		// a view (or vice versa) would drop enforcement while the catalog still shows it
		bool target_is_view = form == "view";
		if (field != "types" && (field == "view") != target_is_view) {
			throw BinderException("acl admin: \"%s.%s\" is %s - use ALTER VIRTUAL %s", vcat, vname,
			                      target_is_view ? "a view" : "a table", target_is_view ? "VIEW" : "TABLE");
		}
		auto phys = current->Collection().GetValue(1, 0);
		auto view_sql = current->Collection().GetValue(2, 0);
		auto rls = current->Collection().GetValue(3, 0);
		string new_phys = phys.IsNull() ? string() : phys.ToString();
		string new_view = view_sql.IsNull() ? string() : view_sql.ToString();
		string new_rls = rls.IsNull() ? string() : rls.ToString();
		vector<std::pair<string, string>> new_columns;
		case_insensitive_map_t<int8_t> kept_marks = nullable_marks;
		if (field == "columns") {
			new_columns = columns;
			CompileDeclaredPaths(*catalog, new_phys, vname, new_columns);
		} else { // keep the current projection - and its nullability marks - when another property is set
			auto rows = read("SELECT \"name\", \"expr\", \"nullable\" FROM " + catalog->Tbl("relation_columns") +
			                 " WHERE \"vcat\" = " + Lit(vcat) + " AND \"vname\" = " + Lit(vname) + " ORDER BY \"pos\"");
			ResultRows rows_rows(*rows);
			for (idx_t row = 0; row < rows->RowCount(); row++) {
				auto expr = rows_rows.GetValue(1, row);
				auto name = rows_rows.GetValue(0, row).ToString();
				new_columns.emplace_back(name, expr.IsNull() ? string() : expr.ToString());
				auto nullable = rows_rows.GetValue(2, row);
				if (!nullable.IsNull()) {
					kept_marks[name] = nullable.GetValue<bool>() ? 1 : 0;
				}
			}
			// a view or a declared result keeps its marks in object_columns - carry those too, the
			// projection's own (when both state a name) winning
			auto declared = read("SELECT \"name\", \"nullable\" FROM " + catalog->Tbl("object_columns") +
			                     " WHERE \"vcat\" = " + Lit(vcat) + " AND \"vname\" = " + Lit(vname) +
			                     " AND \"kind\" = 'relation' AND \"nullable\" IS NOT NULL");
			ResultRows declared_rows(*declared);
			for (idx_t row = 0; row < declared->RowCount(); row++) {
				auto name = declared_rows.GetValue(0, row).ToString();
				if (kept_marks.find(name) == kept_marks.end()) {
					kept_marks[name] = declared_rows.GetValue(1, row).GetValue<bool>() ? 1 : 0;
				}
			}
		}
		if (field == "phys") {
			new_phys = value;
		} else if (field == "rls") {
			new_rls = value;
		} else if (field == "view") {
			new_view = value;
		} else if (field != "columns" && field != "types") {
			throw BinderException("acl admin: unknown relation property \"%s\"", field);
		}
		// the form follows the content, exactly as it does for ADD - through the same rule, so the same
		// list cannot give a writable relation one way and a read-only one the other
		string new_form =
		    !new_view.empty()
		        ? "view"
		        : (new_rls.empty() && (new_columns.empty() || RenameOnlyColumns(new_columns)) ? "alias" : "subquery");
		auto stored =
		    read("SELECT \"comment\", \"origin\", \"alias_types\", \"enum_types\" FROM " + catalog->Tbl("relations") +
		         " WHERE \"vcat\" = " + Lit(vcat) + " AND \"vname\" = " + Lit(vname));
		string comment, origin, alias_types, enum_types;
		if (stored->RowCount() > 0) {
			ResultRows kept(*stored);
			alias_types = kept.GetValue(2, 0).IsNull() ? string() : kept.GetValue(2, 0).ToString();
			enum_types = kept.GetValue(3, 0).IsNull() ? string() : kept.GetValue(3, 0).ToString();
			if (!kept.GetValue(0, 0).IsNull()) {
				comment = kept.GetValue(0, 0).ToString();
			}
			// editing a record an expansion produced does not take it out of the expansion: REFRESH
			// still leaves it alone (it never rewrites), and PRUNE still removes it if its source is
			// gone - which is right, because it would then point at nothing
			if (!kept.GetValue(1, 0).IsNull()) {
				origin = kept.GetValue(1, 0).ToString();
			}
		}
		if (field == "types") {
			// spec 099: SET TYPES (aliases = base|keep|default, enums = varchar|keep|default) - a key not
			// written keeps its value, `default` hands it back to the node's setting. The rewrite below
			// probes the source again, so this is also how the type facts are refreshed.
			for (auto &item : StringUtil::Split(value, ',')) {
				auto eq = item.find('=');
				auto key = StringUtil::Lower(item.substr(0, eq == string::npos ? item.size() : eq));
				auto setting = eq == string::npos ? string() : StringUtil::Lower(item.substr(eq + 1));
				StringUtil::Trim(key);
				StringUtil::Trim(setting);
				if (key == "aliases" && (setting == "base" || setting == "keep" || setting == "default")) {
					alias_types = setting == "default" ? string() : setting;
				} else if (key == "enums" && (setting == "varchar" || setting == "keep" || setting == "default")) {
					enum_types = setting == "default" ? string() : setting;
				} else {
					throw BinderException("acl admin: SET TYPES takes aliases = base|keep|default and enums = "
					                      "varchar|keep|default, got \"%s\"",
					                      item);
				}
			}
		}
		// ALTER keeps the stored schema policy: a declared result is re-declared explicitly, not here
		// spec 048: a redefinition must not silently drop the declared key - read and carry it
		string kept_pk;
		{
			auto key_rows = read("SELECT \"column\" FROM " + catalog->Tbl("keys") + " WHERE \"vcat\" = " + Lit(vcat) +
			                     " AND \"vname\" = " + Lit(vname) + " AND \"kind\" = 'relation' ORDER BY \"pos\"");
			ResultRows key_rows_rows(*key_rows);
			vector<string> parts;
			for (idx_t key_row = 0; key_row < key_rows->RowCount(); key_row++) {
				parts.push_back(key_rows_rows.GetValue(0, key_row).ToString());
			}
			kept_pk = StringUtil::Join(parts, ", ");
		}
		statements = RelationStatements(*catalog, vcat, vname, new_form, new_phys, new_view, new_rls, new_columns,
		                                comment, string(), origin, kept_pk, kept_marks, true, alias_types, enum_types);
	});
	NoteDefinitionLineage(vcat, vname, "ALTER");
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
	// redefining the body must not silently drop the declared shape (spec 048): the key and the
	// nullability marks are read and carried; the key lapses only if the new result loses its column
	string pk = ExistingKeyCsv(vcat, vname, kind);
	case_insensitive_map_t<int8_t> marks;
	auto declared = catalog->Query("SELECT \"name\", \"nullable\" FROM " + catalog->Tbl("object_columns") +
	                               " WHERE \"vcat\" = " + Lit(vcat) + " AND \"vname\" = " + Lit(vname) +
	                               " AND \"kind\" = " + Lit(kind) + " AND \"nullable\" IS NOT NULL");
	ResultRows declared_rows(*declared);
	for (idx_t row = 0; row < declared->RowCount(); row++) {
		marks[declared_rows.GetValue(0, row).ToString()] = declared_rows.GetValue(1, row).GetValue<bool>() ? 1 : 0;
	}
	CatalogAddFunction(vcat, vname, kind, form, is_alias ? definition : "", is_alias ? "" : definition, "", "", pk,
	                   marks, true);
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
	auto is_main_value = current->Collection().GetValue(0, 0);
	bool is_main = !is_main_value.IsNull() && is_main_value.GetValue<bool>();
	auto text = [&](idx_t column) {
		auto stored = current->Collection().GetValue(column, 0);
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
	CatalogGrant(role, vcat, caps, is_main, rls, columns, field == "columns");
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
	ResultRows grants_rows(*grants);
	vector<string> statements = {"DELETE FROM " + catalog->Tbl("admins") + " WHERE \"role\" = " + Lit(role)};
	for (idx_t row = 0; row < grants->RowCount(); row++) {
		auto caps_value = grants_rows.GetValue(1, row);
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
		                     " AND \"vcat\" = " + Lit(grants_rows.GetValue(0, row).ToString()));
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

namespace {

string LitOrNull(const string &value) {
	return value.empty() ? string("NULL") : Lit(value);
}

string IssuerValues(const IdentityIssuer &issuer) {
	return "(" + Lit(issuer.name) + ", " + LitOrNull(issuer.url) + ", " + LitOrNull(issuer.secret_service) + ", " +
	       LitOrNull(issuer.secret) + ")";
}

string ClientValues(const IdentityClient &client) {
	return "(" + Lit(client.name) + ", " + Lit(client.issuer) + ", " + LitOrNull(StoredList(client.audiences)) + ", " +
	       LitOrNull(StoredList(client.azp)) + ", " + LitOrNull(StoredConditions(client.conditions)) + ", " +
	       LitOrNull(StoredList(client.roles_from)) + ", " + LitOrNull(StoredList(client.roles_constant)) + ", " +
	       Lit(client.unmapped_as_role ? "as_role" : "ignore") + ", " + LitOrNull(StoredAttributes(client.attributes)) +
	       ", " + LitOrNull(StoredList(client.subject)) + ", " + LitOrNull(client.token_type) + ", " +
	       LitOrNull(client.client_id) + ", " + LitOrNull(StoredList(client.flows)) + ", " +
	       LitOrNull(client.secret_service) + ", " + LitOrNull(client.secret) + ", " +
	       (client.implicit ? "true" : "false") + ")";
}

string MappingValues(const IdentityMapping &mapping) {
	return "(" + Lit(mapping.scope_kind) + ", " + Lit(mapping.scope_name) + ", " + Lit(mapping.source) + ", " +
	       Lit(mapping.external_value) + ", " + Lit(mapping.role) + ")";
}

//! One table's difference as statements: a row that is gone is deleted by its key, a row that is new
//! (or changed) is inserted - a changed row is both
void DiffRows(CatalogBackend &catalog, const char *table, const vector<std::pair<string, string>> &old_rows,
              const vector<std::pair<string, string>> &new_rows, vector<string> &deletes, vector<string> &inserts) {
	std::multiset<string> had, kept;
	for (auto &row : old_rows) {
		had.insert(row.second);
	}
	for (auto &row : new_rows) {
		kept.insert(row.second);
	}
	for (auto &row : old_rows) {
		if (!kept.count(row.second)) {
			deletes.push_back("DELETE FROM " + catalog.Tbl(table) + " WHERE " + row.first);
		}
	}
	for (auto &row : new_rows) {
		if (!had.count(row.second)) {
			inserts.push_back("INSERT INTO " + catalog.Tbl(table) + " VALUES " + row.second);
		}
	}
}

} // namespace

void PolicyStore::CatalogEditIdentity(const std::function<void(IdentityModel &)> &apply) {
	RequireCatalog(catalog, "acl identity");
	if (catalog->FunctionMode()) {
		throw BinderException("acl catalog: the function-driver policy source is read-only");
	}
	catalog->WriteWithReads([&](const ReadFn &read, vector<string> &statements) {
		// read inside the write's transaction, so what is validated is what the write replaces
		auto issuers = read("SELECT \"name\", \"url\", \"secret_service\", \"secret\" FROM " + catalog->Tbl("issuers") +
		                    " ORDER BY \"name\"");
		auto clients = read("SELECT \"name\", \"issuer\", \"audiences\", \"azp\", \"requires\", \"roles_from\","
		                    " \"roles_constant\", \"unmapped\", \"attributes\", \"subject\", \"token_type\","
		                    " \"client_id\", \"flows\", \"secret_service\", \"secret\", \"implicit\" FROM " +
		                    catalog->Tbl("clients") + " ORDER BY \"issuer\", \"name\"");
		auto mappings = read("SELECT \"scope_kind\", \"scope_name\", \"source\", \"external_value\", \"role\" FROM " +
		                     catalog->Tbl("role_mappings"));
		auto before = CatalogBackend::IdentityFromRows(issuers.get(), clients.get(), mappings.get());
		auto after = before;
		apply(after);
		vector<std::pair<string, string>> old_issuers, new_issuers, old_clients, new_clients, old_maps, new_maps;
		for (auto &issuer : before.issuers) {
			old_issuers.emplace_back("\"name\" = " + Lit(issuer.name), IssuerValues(issuer));
		}
		for (auto &issuer : after.issuers) {
			new_issuers.emplace_back("\"name\" = " + Lit(issuer.name), IssuerValues(issuer));
		}
		for (auto &client : before.clients) {
			old_clients.emplace_back("\"name\" = " + Lit(client.name), ClientValues(client));
		}
		for (auto &client : after.clients) {
			new_clients.emplace_back("\"name\" = " + Lit(client.name), ClientValues(client));
		}
		auto mapping_key = [](const IdentityMapping &mapping) {
			return "\"scope_kind\" = " + Lit(mapping.scope_kind) + " AND \"scope_name\" = " + Lit(mapping.scope_name) +
			       " AND \"source\" = " + Lit(mapping.source) +
			       " AND \"external_value\" = " + Lit(mapping.external_value) + " AND \"role\" = " + Lit(mapping.role);
		};
		for (auto &mapping : before.mappings) {
			old_maps.emplace_back(mapping_key(mapping), MappingValues(mapping));
		}
		for (auto &mapping : after.mappings) {
			new_maps.emplace_back(mapping_key(mapping), MappingValues(mapping));
		}
		// every delete before any insert, so a changed row never meets its own old primary key
		vector<string> deletes, inserts;
		DiffRows(*catalog, "role_mappings", old_maps, new_maps, deletes, inserts);
		DiffRows(*catalog, "clients", old_clients, new_clients, deletes, inserts);
		DiffRows(*catalog, "issuers", old_issuers, new_issuers, deletes, inserts);
		statements.insert(statements.end(), deletes.begin(), deletes.end());
		statements.insert(statements.end(), inserts.begin(), inserts.end());
	});
}

void PolicyStore::CatalogSetObjectCaps(const string &role, const string &vcat, const string &vname,
                                       const string &caps_json, const string &rls, const string &columns) {
	RequireCatalog(catalog, "acl catalog");
	ValidateGrantColumns(*catalog, vcat, columns, vname);
	// spec 032: a capability that cannot apply to what it names is a misunderstanding, not a no-op, and
	// the refusal belongs here rather than in the pre-check - the legacy wrappers write a grant without
	// passing through that one.
	auto caps = acl_detail::ParseCaps(caps_json);
	if (caps.count("manage")) {
		throw BinderException("acl admin: `manage` is granted per catalog, not per object - administering the ACL is "
		                      "catalog-scoped (spec 009)");
	}
	string written_verb;
	for (auto verb : {"insert", "update", "delete", "merge"}) {
		if (written_verb.empty() && caps.count(verb)) {
			written_verb = verb;
		}
	}
	if (!written_verb.empty() && !CatalogObjectExists(vcat, vname, "relation")) {
		// a function is called rather than written, so a write verb on one would never be consulted
		for (auto kind : {"table", "scalar"}) {
			if (CatalogObjectExists(vcat, vname, kind)) {
				throw BinderException("acl admin: \"%s.%s\" is a function, which is called rather than written - "
				                      "`%s` on it would never be consulted (grant `select`)",
				                      vcat, vname, written_verb);
			}
		}
	}
	catalog->WriteWithReads([&](const ReadFn &read, vector<string> &statements) {
		// the grant's predicate is checked against the object it filters, here rather than at query
		// time (spec 021) - a predicate that cannot bind is a mistake, whoever eventually runs into it
		bool checked = false;
		if (!rls.empty()) {
			auto shape = read("SELECT \"form\", \"phys\", \"view_sql\" FROM " + catalog->Tbl("relations") +
			                  " WHERE \"vcat\" = " + Lit(vcat) + " AND \"vname\" = " + Lit(vname));
			if (shape->RowCount() > 0) {
				auto form = shape->Collection().GetValue(0, 0).IsNull() ? string()
				                                                        : shape->Collection().GetValue(0, 0).ToString();
				auto phys = shape->Collection().GetValue(1, 0).IsNull() ? string()
				                                                        : shape->Collection().GetValue(1, 0).ToString();
				auto view_sql = shape->Collection().GetValue(2, 0).IsNull()
				                    ? string()
				                    : shape->Collection().GetValue(2, 0).ToString();
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
		// spec 037: what the grant may say at all, and in whose order it is kept
		auto listed = NormaliseGrantColumns(*catalog, read, vcat, vname, columns);
		GrantProjectionStatements(*catalog, read, role, vcat, vname, listed, statements, true);
		statements.push_back("DELETE FROM " + catalog->Tbl("role_object_caps") + " WHERE \"role\" = " + Lit(role) +
		                     " AND \"vcat\" = " + Lit(vcat) + " AND \"vname\" = " + Lit(vname));
		statements.push_back("INSERT INTO " + catalog->Tbl("role_object_caps") +
		                     "(\"role\", \"vcat\", \"vname\", \"caps\", \"rls\", \"columns\", \"rls_checked\")"
		                     " VALUES (" +
		                     Lit(role) + ", " + Lit(vcat) + ", " + Lit(vname) + ", " + Lit(caps_json) + ", " +
		                     Lit(rls) + ", " + Lit(listed) + ", " +
		                     (rls.empty() ? "NULL" : (checked ? "true" : "false")) + ")");
	});
	NoteGrantLineage(vcat, vname); // spec 107
}

bool PolicyStore::CatalogObjectExists(const string &vcat, const string &vname, const string &kind) {
	RequireCatalog(catalog, "acl catalog");
	string sql;
	if (kind == "catalog") {
		sql = "SELECT 1 FROM " + catalog->Tbl("catalogs") + " WHERE \"vcat\" = " + Lit(vcat);
	} else if (kind == "role") {
		sql = "SELECT 1 FROM " + catalog->Tbl("roles") + " WHERE \"role\" = " + Lit(vname);
	} else if (kind == "issuer" || kind == "client") {
		// spec 095: an identity object - the model is the same in every mode, so the store answers
		auto model = Identity();
		return kind == "issuer" ? model->Issuer(vname) != nullptr : model->Client(vname) != nullptr;
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

void PolicyStore::CatalogRequireGrantTarget(const string &vcat, const string &vname, bool with_policy,
                                            const string &caps_json) {
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
	ResultRows result_rows(*result);
	if (result->RowCount() == 0) {
		throw BinderException("acl admin: object \"%s.%s\" does not exist", vcat, vname);
	}
	case_insensitive_set_t kinds;
	for (idx_t row = 0; row < result->RowCount(); row++) {
		kinds.insert(result_rows.GetValue(0, row).ToString());
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
