// The probe/bind validators of the catalog backend: what a definition is checked against where it
// is written (specs 026/027/048/065) - a predicate that binds, the columns a source exposes, a
// declaration's shape - so a stored policy never carries a name nothing judged. Split from
// acl_policy_catalog.cpp (plan 4.2).

#include "acl_policy_catalog.hpp"
#include "acl_rewriter.hpp"

namespace duckdb {
namespace acl {
namespace acl_detail {

bool CatalogBackend::ProbeSchema(const string &sql, bool expression, const vector<string> &param_types,
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

bool CatalogBackend::BareIdentifier(const string &expr) {
	string text = expr;
	StringUtil::Trim(text);
	if (text.empty()) {
		return true;
	}
	if (text.size() >= 2 && text.front() == '"' && text.back() == '"') {
		return text.find('"', 1) == text.size() - 1; // one quoted name, nothing after it
	}
	if (!isalpha(static_cast<unsigned char>(text[0])) && text[0] != '_') {
		return false;
	}
	for (auto ch : text) {
		if (!isalnum(static_cast<unsigned char>(ch)) && ch != '_') {
			return false;
		}
	}
	return true;
}

string CatalogBackend::PredicateError(const string &source, const string &rls, bool *checked) {
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

bool CatalogBackend::CatalogPredicateChecked(
    const std::function<unique_ptr<MaterializedQueryResult>(const string &)> &read, const string &vcat,
    const string &rls) {
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

bool CatalogBackend::ExposedColumns(const string &source, const vector<string> &declared, vector<string> &out) {
	if (!declared.empty()) {
		out = declared;
		return true;
	}
	auto instance = Db();
	Connection con(*instance);
	auto probe = con.Query("SELECT * FROM " + source + " WHERE false");
	if (probe->HasError()) {
		return false;
	}
	for (auto &name : probe->GetNames()) {
		out.push_back(name.GetIdentifierName());
	}
	return true;
}

string CatalogBackend::ProjectionSchema(const string &source, const string &column_csv,
                                        const case_insensitive_map_t<string> &own,
                                        vector<std::pair<string, string>> &out, bool *checked) {
	if (checked) {
		*checked = false;
	}
	vector<string> items;
	for (auto &column : ParseColumnList(column_csv)) {
		// the alias is an identifier and the bare source is one too - quoted, or a column whose name
		// is not a bare word could never be granted at all, since the probe would not parse
		if (!column.second.empty()) {
			items.push_back(column.second + " AS " + Ident(column.first)); // the grant masks it
			continue;
		}
		auto object = own.find(column.first);
		// a bare name is the object's column, which its own projection may have renamed
		items.push_back((object != own.end() && !object->second.empty() ? object->second : Ident(column.first)) +
		                " AS " + Ident(column.first));
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

bool CatalogBackend::ColumnBinds(const string &source, const string &column) {
	auto instance = Db();
	Connection con(*instance);
	auto base = con.Query("SELECT * FROM " + source + " WHERE false");
	if (base->HasError()) {
		return true;
	}
	auto quoted = "\"" + StringUtil::Replace(column, "\"", "\"\"") + "\"";
	return !con.Query("SELECT " + quoted + " FROM " + source + " WHERE false")->HasError();
}

vector<std::pair<string, string>> CatalogBackend::ParseDeclaration(const string &declaration) {
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

vector<string> CatalogBackend::DeclaredTypes(const string &declaration) {
	vector<string> types;
	for (auto &part : ParseDeclaration(declaration)) {
		types.push_back(part.second);
	}
	return types;
}

} // namespace acl_detail

} // namespace acl
} // namespace duckdb
