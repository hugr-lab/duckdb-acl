#include "acl_policy.hpp"

#include "acl_token.hpp"
#include "duckdb/common/exception/binder_exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/types/blob.hpp"

#include <chrono>
#include <random>
#include "duckdb/parser/parser.hpp"

namespace duckdb {
namespace acl {

const char *MetadataSurfaceOf(const string &name) {
	// The written name decides the shape (spec 035). These surfaces describe the same catalog, but
	// each answers with its own columns, and a client that selects a column by name - which is what a
	// program does - breaks on any other shape.
	static const case_insensitive_map_t<string> SURFACES = {
	    {"information_schema.tables", "tables"},
	    {"information_schema.columns", "columns"},
	    {"information_schema.schemata", "schemata"},
	    {"duckdb_tables", "duckdb_tables"},
	    {"duckdb_views", "duckdb_views"},
	    {"duckdb_columns", "duckdb_columns"},
	    {"duckdb_schemas", "duckdb_schemas"},
	    {"duckdb_databases", "databases"},
	};
	auto entry = SURFACES.find(name);
	return entry == SURFACES.end() ? nullptr : entry->second.c_str();
}

namespace {

//! Whether an expression is just a column reference: then `virtual = physical` renames rather than
//! computes. Anything else (NULL, amount * 2, a function call) has no physical column behind it, so
//! the relation cannot be written through.
bool IsPlainColumnReference(const string &expr) {
	if (expr.empty()) {
		return false;
	}
	for (auto c : expr) {
		if (!StringUtil::CharacterIsAlpha(c) && !StringUtil::CharacterIsDigit(c) && c != '_') {
			return false;
		}
	}
	if (StringUtil::CharacterIsDigit(expr[0])) {
		return false;
	}
	auto lowered = StringUtil::Lower(expr);
	return lowered != "null" && lowered != "true" && lowered != "false" && lowered != "default";
}

} // namespace

bool RenameOnlyColumns(const vector<std::pair<string, string>> &columns) {
	if (columns.empty()) {
		return false;
	}
	for (auto &column : columns) {
		if (!IsPlainColumnReference(column.second)) {
			return false;
		}
	}
	return true;
}

vector<string> SplitTopLevel(const string &text, char delimiter) {
	vector<string> parts;
	string current;
	idx_t depth = 0;
	for (idx_t pos = 0; pos < text.size(); pos++) {
		auto c = text[pos];
		if (c == '\'' || c == '"') {
			auto quote = c;
			current += c;
			for (pos++; pos < text.size(); pos++) {
				current += text[pos];
				if (text[pos] == quote) {
					// a doubled quote is an escaped one, not the end of the literal
					if (pos + 1 < text.size() && text[pos + 1] == quote) {
						current += text[++pos];
						continue;
					}
					break;
				}
			}
			continue;
		}
		if (c == '(') {
			depth++;
		} else if (c == ')' && depth > 0) {
			depth--;
		} else if (c == delimiter && depth == 0) {
			parts.push_back(current);
			current.clear();
			continue;
		}
		current += c;
	}
	parts.push_back(current);
	for (auto &part : parts) {
		StringUtil::Trim(part);
	}
	return parts;
}

case_insensitive_set_t DefaultDeniedFunctions() {
	return {
	    // file / blob readers
	    "read_csv", "read_csv_auto", "read_parquet", "parquet_scan", "read_json", "read_json_auto", "read_json_objects",
	    "read_ndjson", "read_ndjson_objects", "read_text", "read_blob", "sniff_csv", "glob",
	    // spatial readers
	    "st_read", "st_readosm", "st_read_meta",
	    // external-source scanners / SQL passthrough (bypass the gateway's ACL)
	    "postgres_query", "postgres_scan", "postgres_scan_pushdown", "postgres_execute", "mysql_query", "mysql_scan",
	    "mysql_execute", "mssql_query", "mssql_scan", "mssql_execute", "sqlite_scan", "sqlite_query", "iceberg_scan",
	    "iceberg_metadata", "delta_scan", "query", "query_table",
	    // session / secret state
	    "getvariable", "which_secret", "current_setting", "current_query",
	    // metadata surfaces: they enumerate every attached database, so under a principal they are
	    // a listing of the physical catalog the ACL exists to hide. Denied until spec 010 part 3
	    // replaces them with a listing filtered by the principal's grants - a denial keeps tooling
	    // blind, a leak keeps it informed about other people's tables.
	    "duckdb_databases", "duckdb_schemas", "duckdb_tables", "duckdb_views", "duckdb_columns", "duckdb_constraints",
	    "duckdb_indexes", "duckdb_functions", "duckdb_types", "duckdb_sequences", "duckdb_secrets", "duckdb_settings",
	    "duckdb_extensions", "duckdb_dependencies", "duckdb_temporary_files", "duckdb_memory", "duckdb_optimizers",
	    "duckdb_variables", "duckdb_log_contexts", "duckdb_logs", "pragma_database_size", "pragma_show",
	    "pragma_storage_info", "pragma_table_info", "pragma_metadata_info", "pragma_user_agent", "pragma_version",
	    "show_databases", "show_tables", "show_tables_expanded", "sql_auto_complete", "test_all_types",
	    // the quack door's own surface (spec 041): loading an extension extends the function
	    // surface, and this gate is a denylist - so its failure mode is the thing nobody named.
	    // Between them these read other sessions and their SQL, run arbitrary SQL against another
	    // server, cancel another principal's query, start and stop servers, and read a client's
	    // data stream by id.
	    "quack_active_connections", "quack_server_list", "quack_query", "quack_query_by_name", "quack_cancel",
	    "quack_serve", "quack_stop", "quack_clear_cache", "quack_identify", "quack_uri_parser", "quack_connection_id",
	    "quack_check_token", "quack_nop_authorization", "scan_data_from_quack_client", "whoami"};
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

namespace {

//! How often SessionOpen sweeps by itself. A constant rather than a setting: it trades a little
//! staleness for not walking the map on every arrival, and no deployment needs to tune that.
constexpr int64_t SWEEP_INTERVAL_SECONDS = 60;

//! Seconds since the epoch, for judging a session's `exp` the same way the verifier judged it.
int64_t NowSeconds() {
	return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
	    .count();
}

//! A handle a client cannot guess: 128 bits from the platform's entropy source, hex-encoded. Never
//! derived from the token, so holding one tells nothing about it (spec 040).
//!
//! `std::random_device` rather than duckdb's own utilities, deliberately: `RandomEngine` seeds from
//! the clock off Linux, and the encryption util refuses to generate randomness unless OpenSSL arrived
//! with httpfs (its mbedTLS fallback demands `force_mbedtls_unsafe`). On glibc, libc++ and MSVC the
//! device is the OS CSPRNG - `getrandom`, `arc4random` and `rand_s` respectively.
//!
//! The one implementation that was not is MinGW's before GCC 9.2, where it returned a fixed sequence.
//! That failure is silent and total, so it is checked for rather than assumed: two independent
//! devices agreeing on 64 bits means the device is deterministic, and a handle from it would be
//! guessable by anyone with the same toolchain. Refusing to mint beats minting that.
string MintHandle() {
	constexpr idx_t HANDLE_BYTES = 16;
	std::random_device source;
	{
		std::random_device other;
		if (source() == other() && source() == other()) {
			throw InternalException("acl: this build's std::random_device is deterministic, so a session handle "
			                        "would be guessable - refusing to mint one");
		}
	}
	data_t bytes[HANDLE_BYTES];
	for (idx_t i = 0; i < HANDLE_BYTES; i += 4) {
		auto word = static_cast<uint32_t>(source());
		for (idx_t byte = 0; byte < 4; byte++) {
			bytes[i + byte] = static_cast<data_t>((word >> (8 * byte)) & 0xFF);
		}
	}
	string handle(HANDLE_BYTES * 2, '\0');
	for (idx_t i = 0; i < HANDLE_BYTES; i++) {
		handle[2 * i] = Blob::HEX_TABLE[bytes[i] >> 4];
		handle[2 * i + 1] = Blob::HEX_TABLE[bytes[i] & 0x0F];
	}
	return handle;
}

} // namespace

string PolicyStore::SessionOpen(const string &token) {
	Principal principal;
	int64_t expires_at = 0;
	string issuer;
	if (LooksLikeJwt(token, issuer)) {
		// the real path: whatever refuses a token in the prefix refuses it here, and for the same
		// reason - a session must never be a way to get in with something a prefix would reject
		IssuerConfig config;
		if (!LookupIssuer(issuer, config)) {
			return string();
		}
		config.keys_json = ResolveIssuerKeys(config, JwtKid(token));
		JwtClaims verified;
		try {
			verified = VerifyJwt(token, config, JwtClockSkew());
		} catch (std::exception &) {
			return string(); // the door refuses; it does not learn why
		}
		principal.roles = MapExternalRoles(issuer, verified.raw_roles);
		if (principal.roles.empty()) {
			return string();
		}
		principal.claims = verified.claims;
		expires_at = verified.expires_at;
	} else if (!VerifyPrincipal(true, token, principal)) {
		return string(); // the dev stub, which carries no expiry
	}
	// Minted before the lock because it needs none, so that checking the cap and inserting happen in
	// ONE critical section: doing them in two let concurrent opens step over the cap between them.
	auto now = NowSeconds();
	auto cap = MaxSessions();
	auto skew = JwtClockSkew();
	auto idle_timeout = SessionIdleTimeout();
	auto handle = MintHandle();
	lock_guard<mutex> guard(lock);
	// Sweep before making room rather than after running out: at most once a minute on a quiet door,
	// and always when the map is at its cap, so the cost lands on arrivals and never on a reader.
	if (now - last_sweep >= SWEEP_INTERVAL_SECONDS || (cap > 0 && sessions.size() >= static_cast<idx_t>(cap))) {
		SweepLocked(now, skew, idle_timeout);
	}
	if (cap > 0 && sessions.size() >= static_cast<idx_t>(cap)) {
		// Refusing rather than evicting: making room by ending somebody else's session would let an
		// arriving stranger disconnect a working client, which is the worse of the two failures
		// (spec 044). A door turns this into "Authentication failed", which a client already handles.
		return string();
	}
	sessions[handle] = Session {std::move(principal), expires_at, now};
	return handle;
}

bool PolicyStore::SessionPrincipal(const string &handle, Principal &out, string &reason) {
	// Read before the lock, for the reason SweepLocked gives.
	auto now = NowSeconds();
	auto skew = JwtClockSkew();
	auto idle = SessionIdleTimeout();
	lock_guard<mutex> guard(lock);
	auto entry = sessions.find(handle);
	if (entry == sessions.end()) {
		reason = "unknown";
		return false;
	}
	if (entry->second.expires_at > 0 && entry->second.expires_at + skew < now) {
		sessions.erase(entry); // it can never come back, so do not keep it around
		reason = "expired";
		return false;
	}
	if (idle > 0 && entry->second.last_used + idle < now) {
		sessions.erase(entry);
		reason = "idle";
		return false;
	}
	entry->second.last_used = now;
	out = entry->second.principal;
	return true;
}

//! Caller holds the lock, and has read the two settings *before* taking it. Reading a setting goes
//! through the catalog to the DatabaseInstance; it executes no SQL today, but the parser override takes
//! this same lock on every unprefixed statement (spec 043), so anything that did would deadlock on a
//! non-recursive mutex. Passing them in removes the possibility rather than relying on it.
idx_t PolicyStore::SweepLocked(int64_t now, int64_t skew, int64_t idle) {
	idx_t removed = 0;
	for (auto entry = sessions.begin(); entry != sessions.end();) {
		bool expired = entry->second.expires_at > 0 && entry->second.expires_at + skew < now;
		// No `last_used > 0` guard: a session without a timestamp is a bug, and letting one live forever
		// is the wrong way to be wrong about it. Every session gets its stamp at SessionOpen.
		bool stale = idle > 0 && entry->second.last_used + idle < now;
		if (expired || stale) {
			entry = sessions.erase(entry);
			removed++;
			continue;
		}
		++entry;
	}
	// Unconditionally, not only when this pass removed something: SessionPrincipal erases a session it
	// finds dead and leaves its binding behind, so a connection whose session died on use would keep a
	// row here forever - the same unbounded growth this spec is about, one map to the left.
	for (auto binding = session_bindings.begin(); binding != session_bindings.end();) {
		binding = sessions.count(binding->second) == 0 ? session_bindings.erase(binding) : std::next(binding);
	}
	last_sweep = now;
	return removed;
}

idx_t PolicyStore::SessionSweep() {
	auto now = NowSeconds();
	auto skew = JwtClockSkew();
	auto idle = SessionIdleTimeout();
	lock_guard<mutex> guard(lock);
	return SweepLocked(now, skew, idle);
}

idx_t PolicyStore::SessionCount() {
	lock_guard<mutex> guard(lock);
	return sessions.size();
}

string PolicyStore::SessionSql(const string &handle, const string &sql) {
	Principal principal;
	string reason;
	if (!SessionPrincipal(handle, principal, reason)) {
		return string();
	}
	return "ACL SESSION '" + StringUtil::Replace(handle, "'", "''") + "' " + sql;
}

void PolicyStore::SetDoorOpen(bool open) {
	lock_guard<mutex> guard(lock);
	door_open = open;
}

bool PolicyStore::DoorOpen() {
	lock_guard<mutex> guard(lock);
	return door_open;
}

void PolicyStore::SessionClose(const string &handle) {
	lock_guard<mutex> guard(lock);
	sessions.erase(handle);
	for (auto entry = session_bindings.begin(); entry != session_bindings.end();) {
		entry = entry->second == handle ? session_bindings.erase(entry) : std::next(entry);
	}
}

void PolicyStore::SessionBind(const string &external_id, const string &handle) {
	lock_guard<mutex> guard(lock);
	// Ending what this replaces, rather than leaving it behind: a connection that authenticates again
	// used to orphan its previous session - unreachable, since the handle is never handed out twice and
	// the binding is gone, but permanent all the same (spec 044).
	auto previous = session_bindings.find(external_id);
	if (previous != session_bindings.end() && previous->second != handle) {
		sessions.erase(previous->second);
	}
	session_bindings[external_id] = handle;
}

idx_t PolicyStore::SessionCloseAll() {
	lock_guard<mutex> guard(lock);
	auto closed = sessions.size();
	sessions.clear();
	session_bindings.clear();
	return closed;
}

bool PolicyStore::SessionHandleFor(const string &external_id, string &handle) {
	lock_guard<mutex> guard(lock);
	auto entry = session_bindings.find(external_id);
	if (entry == session_bindings.end()) {
		return false;
	}
	handle = entry->second;
	return true;
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
	// the keys may come from a document rather than the row (spec 023); the token's kid decides
	// whether a cached one is still enough
	config.keys_json = ResolveIssuerKeys(config, JwtKid(token));
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

AdminScope ParseAdminScope(const string &scope) {
	if (StringUtil::CIEquals(scope, "passthrough")) {
		return AdminScope::PASSTHROUGH;
	}
	if (StringUtil::CIEquals(scope, "manage")) {
		return AdminScope::MANAGE;
	}
	throw BinderException("acl admin: unknown admin scope \"%s\" (expected manage or passthrough)", scope);
}

const char *AdminScopeName(AdminScope scope) {
	switch (scope) {
	case AdminScope::PASSTHROUGH:
		return "passthrough";
	case AdminScope::MANAGE:
		return "manage";
	default:
		throw BinderException("acl admin: an administration grant needs a scope");
	}
}

void PolicyStore::GrantAdmin(const string &role, AdminScope scope) {
	if (catalog) {
		CatalogGrantAdmin(role, AdminScopeName(scope));
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

PolicyStore::AdminRights PolicyStore::AdminRightsOf(const Principal &principal) {
	AdminRights rights;
	auto raise = [&](AdminScope scope) {
		if (scope > rights.scope) {
			rights.scope = scope;
		}
	};
	if (catalog) {
		// per-catalog management is a capability of the catalog grant, so a role manages as many
		// catalogs as it was granted; acl.admins carries the global scopes
		vector<std::pair<string, string>> rows;
		CatalogAdminRights(principal, rights.catalogs, rows);
		if (!rights.catalogs.empty()) {
			raise(AdminScope::MANAGE);
		}
		for (auto &row : rows) {
			auto scope = ParseAdminScope(row.first);
			if (scope == AdminScope::MANAGE && !row.second.empty()) {
				rights.catalogs.insert(row.second); // a catalog-scoped row, not a global one
				raise(AdminScope::MANAGE);
				continue;
			}
			if (scope == AdminScope::MANAGE) {
				rights.unrestricted_manage = true;
			}
			raise(scope);
		}
		return rights;
	}
	lock_guard<mutex> guard(lock);
	for (auto &role : principal.roles) {
		auto entry = admin_scopes.find(role);
		if (entry == admin_scopes.end()) {
			continue;
		}
		if (entry->second == AdminScope::MANAGE) {
			rights.unrestricted_manage = true; // the memory mode has no catalogs to scope to
		}
		raise(entry->second);
	}
	return rights;
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
	// The extension's own functions administer the ACL, so a principal's query may never call them:
	// otherwise one statement (`SELECT acl_grant_admin('me','passthrough')`) defeats the whole model.
	// They stay available in the native context (ACL ADMIN / ACL NATIVE), which is not rewritten, and
	// virtual names resolve before this seam, so a granted vfunc called acl_* still works.
	if (StringUtil::StartsWith(StringUtil::Lower(name.Name().GetIdentifierName()), "acl_")) {
		return false;
	}
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
