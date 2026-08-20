#include "acl_policy.hpp"

#include "duckdb/common/exception/binder_exception.hpp"
#include "duckdb/parser/parser.hpp"

namespace duckdb {
namespace acl {

case_insensitive_set_t DefaultDeniedFunctions() {
	return {// file / blob readers
	        "read_csv", "read_csv_auto", "read_parquet", "parquet_scan", "read_json", "read_json_auto",
	        "read_json_objects", "read_ndjson", "read_ndjson_objects", "read_text", "read_blob", "sniff_csv", "glob",
	        // spatial readers
	        "st_read", "st_readosm", "st_read_meta",
	        // external-source scanners / SQL passthrough (bypass the gateway's ACL)
	        "postgres_query", "postgres_scan", "postgres_scan_pushdown", "postgres_execute", "mysql_query",
	        "mysql_scan", "mysql_execute", "mssql_query", "mssql_scan", "mssql_execute", "sqlite_scan", "sqlite_query",
	        "iceberg_scan", "iceberg_metadata", "delta_scan", "query", "query_table",
	        // session / secret state
	        "getvariable", "which_secret", "current_setting", "current_query"};
}

unique_ptr<SelectStatement> PolicyStore::InstantiateSelect(const string &sql, const ParserOptions &options) {
	auto node = select_cache.GetCopy(sql, [&]() -> unique_ptr<QueryNode> {
		Parser parser(options);
		parser.ParseQuery(sql);
		if (parser.statements.size() != 1 || parser.statements[0]->type != StatementType::SELECT_STATEMENT) {
			throw BinderException("acl_rewrite: rewrite template is not a single SELECT");
		}
		return std::move(parser.statements[0]->Cast<SelectStatement>().node);
	});
	auto statement = make_uniq<SelectStatement>();
	statement->node = std::move(node);
	return statement;
}

unique_ptr<ParsedExpression> PolicyStore::InstantiateExpr(const string &expr, const ParserOptions &options) {
	return expr_cache.GetCopy(expr, [&]() -> unique_ptr<ParsedExpression> {
		auto expressions = Parser::ParseExpressionList(expr, options);
		if (expressions.size() != 1) {
			throw BinderException("acl_rewrite: scalar template must be a single expression");
		}
		return std::move(expressions[0]);
	});
}

bool PolicyStore::VerifyPrincipal(bool is_token, const string &value, Principal &out) {
	lock_guard<mutex> guard(lock);
	if (is_token) {
		auto entry = tokens.find(value);
		if (entry == tokens.end()) {
			return false;
		}
		out = entry->second;
		return true;
	}
	out.role = value;
	auto claims = role_claims.find(value);
	if (claims != role_claims.end()) {
		out.claims = claims->second;
	}
	return true;
}

bool PolicyStore::ResolveTable(const Principal &principal, const string &vname, TablePolicy &out) {
	return Resolve(tables, principal, vname, out);
}

bool PolicyStore::ResolveTableFunction(const Principal &principal, const string &vname, TablePolicy &out) {
	return Resolve(table_functions, principal, vname, out);
}

bool PolicyStore::ResolveScalarFunction(const Principal &principal, const string &vname, TablePolicy &out) {
	return Resolve(scalar_functions, principal, vname, out);
}

bool PolicyStore::FunctionAllowed(const QualifiedName &name) {
	lock_guard<mutex> guard(lock);
	return denied_functions.count(name.Name().GetIdentifierName()) == 0;
}

bool PolicyStore::Resolve(const case_insensitive_map_t<case_insensitive_map_t<TablePolicy>> &space,
                          const Principal &principal, const string &vname, TablePolicy &out) {
	lock_guard<mutex> guard(lock);
	auto role_entry = space.find(principal.role);
	if (role_entry == space.end()) {
		return false;
	}
	auto entry = role_entry->second.find(vname);
	if (entry == role_entry->second.end()) {
		return false;
	}
	out = entry->second;
	return true;
}

} // namespace acl
} // namespace duckdb
