#include "acl_policy.hpp"

#include "acl_token.hpp"
#include "duckdb/common/exception/binder_exception.hpp"
#include "duckdb/common/string_util.hpp"
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
	if (is_token) {
		string issuer;
		if (LooksLikeJwt(value, issuer)) {
			// the real path (spec 007): signature + claims against the issuer registry; throws on
			// failure, so a bad JWT can never fall back to the dev stub below
			VerifyJwtPrincipal(value, issuer, out);
		} else {
			lock_guard<mutex> guard(lock);
			auto entry = tokens.find(value); // dev stub for non-JWT tokens
			if (entry == tokens.end()) {
				return false;
			}
			out = entry->second;
		}
	} else {
		lock_guard<mutex> guard(lock);
		out.roles = {value};
		auto claims = role_claims.find(value);
		if (claims != role_claims.end()) {
			out.claims = claims->second;
		}
	}
	if (catalog) {
		// merge catalog-side default claims of the principal's roles (explicit claims win)
		CatalogLoadRoleClaims(out);
	}
	return true;
}

void PolicyStore::VerifyJwtPrincipal(const string &token, const string &issuer, Principal &out) {
	IssuerConfig config;
	if (!LookupIssuer(issuer, config)) {
		throw BinderException("acl_rewrite: token rejected: unknown issuer \"%s\"", issuer);
	}
	auto verified = VerifyJwt(token, config, JwtClockSkew());
	if (verified.raw_roles.empty() && verified.groups_overage) {
		throw BinderException("acl_rewrite: token rejected: groups overage - the groups claim was replaced "
		                      "by a Graph link; resolve groups at the gateway and use the ROLE form");
	}
	out.roles = MapExternalRoles(issuer, verified.raw_roles);
	if (out.roles.empty()) {
		throw BinderException("acl_rewrite: token rejected: no recognized roles");
	}
	out.claims = std::move(verified.claims);
	// role-default claims of the mapped roles (explicit token claims win); the catalog side is
	// merged by the caller via CatalogLoadRoleClaims
	lock_guard<mutex> guard(lock);
	for (auto &role : out.roles) {
		auto defaults = role_claims.find(role);
		if (defaults == role_claims.end()) {
			continue;
		}
		for (auto &claim : defaults->second) {
			if (!out.claims.count(claim.first)) {
				out.claims[claim.first] = claim.second;
			}
		}
	}
}

bool PolicyStore::LookupIssuer(const string &issuer, IssuerConfig &out) {
	// like every resolver: an enabled catalog is the only source (a stale memory entry must not
	// shadow the catalog registry)
	if (catalog) {
		return CatalogLookupIssuer(issuer, out);
	}
	lock_guard<mutex> guard(lock);
	auto entry = issuers.find(issuer);
	if (entry == issuers.end()) {
		return false;
	}
	out = entry->second;
	return true;
}

vector<string> PolicyStore::MapExternalRoles(const string &issuer, const vector<string> &raw_roles) {
	case_insensitive_map_t<vector<string>> mapped;
	case_insensitive_set_t known;
	if (catalog) {
		CatalogMapExternalRoles(issuer, raw_roles, mapped, known);
	}
	lock_guard<mutex> guard(lock);
	auto issuer_map = role_mappings.find(issuer);
	vector<string> roles;
	case_insensitive_set_t seen;
	auto add = [&](const string &role) {
		if (!seen.count(role)) {
			seen.insert(role);
			roles.push_back(role);
		}
	};
	for (auto &raw : raw_roles) {
		bool matched = false;
		if (issuer_map != role_mappings.end()) {
			auto entry = issuer_map->second.find(raw);
			if (entry != issuer_map->second.end()) {
				for (auto &role : entry->second) {
					add(role);
				}
				matched = true;
			}
		}
		auto catalog_entry = mapped.find(raw);
		if (catalog_entry != mapped.end()) {
			for (auto &role : catalog_entry->second) {
				add(role);
			}
			matched = true;
		}
		if (matched) {
			continue;
		}
		// unmapped: accept the raw value as an internal role only if that role is actually known -
		// unknown values are ignored (fail closed via the "no recognized roles" check)
		if (known.count(raw) || tables.count(raw) || table_functions.count(raw) || scalar_functions.count(raw) ||
		    role_claims.count(raw)) {
			add(raw);
		}
	}
	return roles;
}

void PolicyStore::DefineIssuer(IssuerConfig config) {
	if (catalog) {
		CatalogDefineIssuer(config);
		return;
	}
	lock_guard<mutex> guard(lock);
	issuers[config.issuer] = std::move(config);
}

namespace {

AdminScope ParseScope(const string &scope) {
	if (StringUtil::CIEquals(scope, "passthrough")) {
		return AdminScope::PASSTHROUGH;
	}
	if (StringUtil::CIEquals(scope, "manage")) {
		return AdminScope::MANAGE;
	}
	throw BinderException("acl admin: unknown admin scope \"%s\" (expected manage or passthrough)", scope);
}

} // namespace

void PolicyStore::GrantAdmin(const string &role, AdminScope scope) {
	if (catalog) {
		CatalogGrantAdmin(role, scope == AdminScope::PASSTHROUGH ? "passthrough" : "manage");
		return;
	}
	lock_guard<mutex> guard(lock);
	admin_scopes[role] = scope;
}

void PolicyStore::RevokeAdmin(const string &role) {
	if (catalog) {
		CatalogRevokeAdmin(role);
		return;
	}
	lock_guard<mutex> guard(lock);
	admin_scopes.erase(role);
}

AdminScope PolicyStore::AdminScopeOf(const Principal &principal, case_insensitive_set_t &catalogs_out) {
	auto strongest = AdminScope::NONE;
	auto consider = [&](AdminScope scope) {
		if (scope == AdminScope::MANAGE) {
			catalogs_out.insert(""); // a global manage scope: every catalog
		}
		if (scope > strongest) {
			strongest = scope;
		}
	};
	if (catalog) {
		// per-catalog management is a capability of the catalog grant, so a role manages as many
		// catalogs as it was granted; acl.admins carries only the global scopes
		CatalogManageCatalogs(principal, catalogs_out);
		if (!catalogs_out.empty()) {
			strongest = AdminScope::MANAGE;
		}
		case_insensitive_map_t<std::pair<string, string>> rows;
		CatalogAdminScopes(principal, rows);
		for (auto &row : rows) {
			consider(ParseScope(row.second.first));
		}
		return strongest;
	}
	lock_guard<mutex> guard(lock);
	for (auto &role : principal.roles) {
		auto entry = admin_scopes.find(role);
		if (entry != admin_scopes.end()) {
			consider(entry->second);
		}
	}
	return strongest;
}

bool PolicyStore::AnonymousAdminAllowed() {
	// the in-memory dev mode keeps the historical behavior; a real policy source means production,
	// where the gateway's own escape hatch must be turned on deliberately
	return !catalog || CatalogAnonymousAdminAllowed();
}

void PolicyStore::MapRole(const string &issuer, const string &source, const string &external_value,
                          const string &role) {
	if (catalog) {
		CatalogMapRole(issuer, source, external_value, role);
		return;
	}
	lock_guard<mutex> guard(lock);
	role_mappings[issuer][external_value].push_back(role);
}

bool PolicyStore::ResolveTable(const Principal &principal, const string &vname, TablePolicy &out) {
	if (catalog) {
		return CatalogResolveTable(principal, vname, out);
	}
	return Resolve(tables, principal, vname, out);
}

bool PolicyStore::ResolveTableFunction(const Principal &principal, const string &vname, TablePolicy &out) {
	if (catalog) {
		return CatalogResolveFunction(principal, vname, true, out);
	}
	return Resolve(table_functions, principal, vname, out);
}

bool PolicyStore::ResolveScalarFunction(const Principal &principal, const string &vname, TablePolicy &out) {
	if (catalog) {
		return CatalogResolveFunction(principal, vname, false, out);
	}
	return Resolve(scalar_functions, principal, vname, out);
}

bool PolicyStore::FunctionAllowed(const Principal &principal, const QualifiedName &name) {
	if (catalog) {
		bool allowed;
		if (CatalogFunctionGate(principal, name, allowed)) {
			return allowed;
		}
	}
	lock_guard<mutex> guard(lock);
	return denied_functions.count(name.Name().GetIdentifierName()) == 0;
}

bool PolicyStore::Resolve(const case_insensitive_map_t<case_insensitive_map_t<TablePolicy>> &space,
                          const Principal &principal, const string &vname, TablePolicy &out) {
	lock_guard<mutex> guard(lock);
	for (auto &role : principal.roles) {
		auto role_entry = space.find(role);
		if (role_entry == space.end()) {
			continue;
		}
		auto entry = role_entry->second.find(vname);
		if (entry != role_entry->second.end()) {
			out = entry->second;
			return true;
		}
	}
	return false;
}

} // namespace acl
} // namespace duckdb
