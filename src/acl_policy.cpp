#include "acl_policy.hpp"

#include "acl_audit_pipeline.hpp"
#include "acl_rewriter.hpp"
#include "acl_token.hpp"
#include "duckdb/common/error_data.hpp"
#include "duckdb/catalog/catalog_entry/duck_schema_entry.hpp"
#include "duckdb/catalog/duck_catalog.hpp"
#include "duckdb/common/exception/binder_exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/types/blob.hpp"
#include "duckdb/main/attached_database.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/client_data.hpp"
#include "duckdb/main/database.hpp"

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
	return {// file / blob readers
	        "read_csv", "read_csv_auto", "read_parquet", "parquet_scan", "read_json", "read_json_auto",
	        "read_json_objects", "read_ndjson", "read_ndjson_objects", "read_text", "read_blob", "sniff_csv", "glob",
	        // spatial readers
	        "st_read", "st_readosm", "st_read_meta",
	        // external-source scanners / SQL passthrough (bypass the gateway's ACL)
	        "postgres_query", "postgres_scan", "postgres_scan_pushdown", "postgres_execute", "mysql_query",
	        "mysql_scan", "mysql_execute", "mssql_query", "mssql_scan", "mssql_execute", "sqlite_scan", "sqlite_query",
	        "iceberg_scan", "iceberg_metadata", "delta_scan", "query", "query_table",
	        // spec 049: three raw pointers into a table. The ingest source - the door's own composed
	        // statement is exempted by Principal::arrow_ingest - and nobody else's.
	        "arrow_scan", "arrow_scan_dumb",
	        // session / secret state
	        "getvariable", "which_secret", "current_setting", "current_query",
	        // metadata surfaces: they enumerate every attached database, so under a principal they are
	        // a listing of the physical catalog the ACL exists to hide. Denied until spec 010 part 3
	        // replaces them with a listing filtered by the principal's grants - a denial keeps tooling
	        // blind, a leak keeps it informed about other people's tables.
	        "duckdb_databases", "duckdb_schemas", "duckdb_tables", "duckdb_views", "duckdb_columns",
	        "duckdb_constraints", "duckdb_indexes", "duckdb_functions", "duckdb_types", "duckdb_sequences",
	        "duckdb_secrets", "duckdb_settings", "duckdb_extensions", "duckdb_dependencies", "duckdb_temporary_files",
	        "duckdb_memory", "duckdb_optimizers", "duckdb_variables", "duckdb_log_contexts", "duckdb_logs",
	        "pragma_database_size", "pragma_show", "pragma_storage_info", "pragma_table_info", "pragma_metadata_info",
	        "pragma_user_agent", "pragma_version", "show_databases", "show_tables", "show_tables_expanded",
	        "sql_auto_complete", "test_all_types",
	        // the quack door's own surface (spec 041): loading an extension extends the function
	        // surface, and this gate is a denylist - so its failure mode is the thing nobody named.
	        // Between them these read other sessions and their SQL, run arbitrary SQL against another
	        // server, cancel another principal's query, start and stop servers, and read a client's
	        // data stream by id.
	        "quack_active_connections", "quack_server_list", "quack_query", "quack_query_by_name", "quack_cancel",
	        "quack_serve", "quack_stop", "quack_clear_cache", "quack_identify", "quack_uri_parser",
	        "quack_connection_id", "quack_check_token", "quack_nop_authorization", "scan_data_from_quack_client",
	        // spec 063: the embedded door registers the drain under an acl_ name; both are barred, so a
	        // principal cannot call it whether the server here is embedded or a co-loaded stock quack.
	        "acl_quack_scan_data", "whoami"};
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
string MintHandle() {
	return MintRandomHex(16);
}

//! One session lifecycle event (spec 069), at level `all`: opened, refused (with why), or closed
//! (with how and for how long). Nothing when the effective level does not record it. Safe under the
//! store's lock: emitting takes the audit queue's lock and reads two settings, nothing of the store's.
void SessionEvent(AuditPipeline *hooks, const Principal &principal, const string &door, const string &id,
                  int8_t session_level, const string &detail, const string &reason_code, const string &reason,
                  int64_t duration_us) {
	if (!hooks) {
		return;
	}
	// always emitted - the counters are a state of the node whatever the level - and recorded only
	// where the level says so: an opened/closed session is `all`, a refused one is a denial
	AuditEvent event;
	event.level = reason_code.empty() ? AuditLevel::ALL : AuditLevel::DENIED;
	event.recorded = hooks->Records(event.level, session_level);
	event.kind = "session";
	event.door = door;
	event.session = id;
	event.principal = principal;
	event.detail = detail;
	event.allowed = reason_code.empty();
	event.reason_code = reason_code;
	event.reason = AuditReasonText(reason_code, reason);
	event.duration_us = duration_us;
	hooks->Emit(std::move(event));
}

//! A JWT verification, counted by its result (spec 069): not an event - the session or statement
//! it was for is one - but a rate the node reports
void CountJwt(AuditPipeline *hooks, const char *result) {
	if (hooks) {
		hooks->Hooks().Counters().Add("acl.jwt.verifications", {{"result", result}});
	}
}

} // namespace

//! `std::random_device` rather than duckdb's own utilities, deliberately: `RandomEngine` seeds from
//! the clock off Linux, and the encryption util refuses to generate randomness unless OpenSSL arrived
//! with httpfs (its mbedTLS fallback demands `force_mbedtls_unsafe`). On glibc, libc++ and MSVC the
//! device is the OS CSPRNG - `getrandom`, `arc4random` and `rand_s` respectively.
//!
//! The one implementation that was not is MinGW's before GCC 9.2, where it returned a fixed sequence.
//! That failure is silent and total, so it is checked for rather than assumed: two independent
//! devices agreeing on 64 bits means the device is deterministic, and a credential from it would be
//! guessable by anyone with the same toolchain. Refusing to mint beats minting that.
string MintRandomHex(idx_t bytes) {
	std::random_device source;
	{
		std::random_device other;
		if (source() == other() && source() == other()) {
			throw InternalException("acl: this build's std::random_device is deterministic, so a credential minted "
			                        "from it would be guessable - refusing to mint one");
		}
	}
	string out(bytes * 2, '\0');
	idx_t i = 0;
	while (i < bytes) {
		auto word = static_cast<uint32_t>(source());
		for (idx_t byte = 0; byte < 4 && i < bytes; byte++, i++) {
			auto value = static_cast<data_t>((word >> (8 * byte)) & 0xFF);
			out[2 * i] = Blob::HEX_TABLE[value >> 4];
			out[2 * i + 1] = Blob::HEX_TABLE[value & 0x0F];
		}
	}
	return out;
}

string PolicyStore::SessionOpen(const string &token, const string &door) {
	// a refusal is a session event too (spec 069): the reason a client never learns is what the
	// operator's record carries
	auto refused = [&](const Principal &who, const char *code, const string &reason) {
		SessionEvent(audit.get(), who, door, "", -1, "refused", code, reason, -1);
		return string();
	};
	// Spec 066: a draining node seats nobody new. Refused before verifying anything - there is
	// nothing to decide with the result, and the drain path stays free of JWKS reads. Established
	// sessions never come back through here, so they keep working.
	if (draining.load(std::memory_order_relaxed)) {
		return refused(Principal(), "draining", "acl: node is draining - not accepting new sessions");
	}
	Principal principal;
	int64_t expires_at = 0;
	string issuer;
	if (LooksLikeJwt(token, issuer)) {
		// the real path: whatever refuses a token in the prefix refuses it here, and for the same
		// reason - a session must never be a way to get in with something a prefix would reject
		TakeDenyReason(); // a note a refusal nobody audited left on this thread must not name this one
		IssuerConfig config;
		if (!LookupIssuer(issuer, config)) {
			return refused(Principal(), "principal", "acl_rewrite: token rejected: unknown issuer \"" + issuer + "\"");
		}
		JwtClaims verified;
		try {
			config.keys_json = ResolveIssuerKeys(config, JwtKid(token));
			verified = VerifyJwt(token, config, JwtClockSkew());
		} catch (std::exception &ex) {
			// the door refuses; it does not learn why. The audit does: the keys' source, when that is
			// what failed (a note the read left), else the principal
			CountJwt(audit.get(), "failed");
			auto code = TakeDenyReason();
			return refused(Principal(), code.empty() ? "principal" : code.c_str(), ErrorData(ex).RawMessage());
		}
		CountJwt(audit.get(), "ok");
		principal.subject = verified.subject;
		principal.issuer = issuer;
		principal.roles = MapExternalRoles(issuer, verified.raw_roles);
		if (principal.roles.empty()) {
			return refused(principal, "principal", "acl_rewrite: token rejected: no recognized roles");
		}
		principal.claims = verified.claims;
		// The role-default claims, exactly as the ACL TOKEN path merges them (VerifyPrincipal): a
		// session is what `ACL SESSION` replays verbatim, so a claim the prefix path would carry and
		// the session lacked made the SAME token answer differently through a door than through a
		// gateway - an RLS predicate on a role default baked NULL and returned nothing (the 2026-09-03
		// review). Explicit token claims win, both here and there.
		MergeMemoryRoleDefaults(principal);
		if (catalog) {
			CatalogLoadRoleClaims(principal);
		}
		expires_at = verified.expires_at;
	} else if (!VerifyPrincipal(true, token, principal)) {
		return refused(Principal(), "principal", "acl_rewrite: token verification failed"); // the dev stub
	}
	// The session's own audit level (spec 069): the door's policy - the extended extension's rule
	// per role, user and door - answers once, here; no opinion means the instance's level applies.
	int8_t session_level = -1;
	AuditLevel chosen;
	if (audit && audit->LevelForSession(principal, door, chosen)) {
		session_level = static_cast<int8_t>(chosen);
	}
	// Minted before the lock because it needs none, so that checking the cap and inserting happen in
	// ONE critical section: doing them in two let concurrent opens step over the cap between them.
	auto now = NowSeconds();
	auto cap = MaxSessions();
	auto skew = JwtClockSkew();
	auto idle_timeout = SessionIdleTimeout();
	auto exp_binds = SessionExpEveryUse();
	auto handle = MintHandle();
	auto id = MintHandle().substr(0, 12);
	lock_guard<mutex> guard(lock);
	// Sweep before making room rather than after running out: at most once a minute on a quiet door,
	// and always when the map is at its cap, so the cost lands on arrivals and never on a reader.
	if (now - last_sweep >= SWEEP_INTERVAL_SECONDS || (cap > 0 && sessions.size() >= static_cast<idx_t>(cap))) {
		SweepLocked(now, skew, idle_timeout, exp_binds);
	}
	if (cap > 0 && sessions.size() >= static_cast<idx_t>(cap)) {
		// Refusing rather than evicting: making room by ending somebody else's session would let an
		// arriving stranger disconnect a working client, which is the worse of the two failures
		// (spec 044). A door turns this into "Authentication failed", which a client already handles.
		return refused(principal, "at_capacity",
		               "acl: at acl_max_sessions - a new session is refused, never an old one ended");
	}
	SessionEvent(audit.get(), principal, door, id, session_level, "opened", "", "", -1);
	Session session {std::move(principal), id, expires_at, now};
	session.door = door;
	session.opened_at = now;
	session.audit_level = session_level;
	sessions[handle] = std::move(session);
	return handle;
}

//! The close event of a session being removed (spec 069): how it ended, and for how long it lived.
//! Caller holds the lock; the event itself takes nothing of the store's.
void PolicyStore::SessionClosed(const Session &session, const char *how, int64_t now) {
	auto lived = session.opened_at > 0 ? (now - session.opened_at) * 1000000 : -1;
	SessionEvent(audit.get(), session.principal, session.door, session.id, session.audit_level, how, "", "", lived);
}

bool PolicyStore::SessionPrincipal(const string &handle, Principal &out, string &reason) {
	// Read before the lock, for the reason SweepLocked gives.
	auto now = NowSeconds();
	auto skew = JwtClockSkew();
	auto idle = SessionIdleTimeout();
	auto exp_binds = SessionExpEveryUse();
	lock_guard<mutex> guard(lock);
	auto entry = sessions.find(handle);
	if (entry == sessions.end()) {
		reason = "unknown";
		return false;
	}
	if (exp_binds && entry->second.expires_at > 0 && entry->second.expires_at + skew < now) {
		SessionClosed(entry->second, "expired", now);
		sessions.erase(entry); // it can never come back, so do not keep it around
		reason = "expired";
		return false;
	}
	if (idle > 0 && entry->second.last_used + idle < now) {
		SessionClosed(entry->second, "idle", now);
		sessions.erase(entry);
		reason = "idle";
		return false;
	}
	entry->second.last_used = now;
	out = entry->second.principal;
	return true;
}

bool PolicyStore::SessionAlive(const string &handle) {
	// The same three judgements as SessionPrincipal, minus every side effect: no bump - a periodic
	// sweep that touched the clock would keep every session it looks at alive forever - and no erase,
	// which stays the business of the paths that answer a caller.
	auto now = NowSeconds();
	auto skew = JwtClockSkew();
	auto idle = SessionIdleTimeout();
	auto exp_binds = SessionExpEveryUse();
	lock_guard<mutex> guard(lock);
	auto entry = sessions.find(handle);
	if (entry == sessions.end()) {
		return false;
	}
	if (exp_binds && entry->second.expires_at > 0 && entry->second.expires_at + skew < now) {
		return false;
	}
	if (idle > 0 && entry->second.last_used + idle < now) {
		return false;
	}
	return true;
}

string PolicyStore::SessionReason(const string &handle) {
	// Read-only, like SessionAlive: no bump, no erase - so a client that got NULL from SessionSql can
	// call this next and still learn the true reason rather than "unknown" (spec 054).
	auto now = NowSeconds();
	auto skew = JwtClockSkew();
	auto idle = SessionIdleTimeout();
	auto exp_binds = SessionExpEveryUse();
	lock_guard<mutex> guard(lock);
	auto entry = sessions.find(handle);
	if (entry == sessions.end()) {
		return "unknown";
	}
	if (exp_binds && entry->second.expires_at > 0 && entry->second.expires_at + skew < now) {
		return "expired";
	}
	if (idle > 0 && entry->second.last_used + idle < now) {
		return "idle";
	}
	return "live";
}

//! Caller holds the lock, and has read the two settings *before* taking it. Reading a setting goes
//! through the catalog to the DatabaseInstance; it executes no SQL today, but the parser override takes
//! this same lock on every unprefixed statement (spec 043), so anything that did would deadlock on a
//! non-recursive mutex. Passing them in removes the possibility rather than relying on it.
idx_t PolicyStore::SweepLocked(int64_t now, int64_t skew, int64_t idle, bool exp_binds) {
	idx_t removed = 0;
	for (auto entry = sessions.begin(); entry != sessions.end();) {
		bool expired = exp_binds && entry->second.expires_at > 0 && entry->second.expires_at + skew < now;
		// No `last_used > 0` guard: a session without a timestamp is a bug, and letting one live forever
		// is the wrong way to be wrong about it. Every session gets its stamp at SessionOpen.
		bool stale = idle > 0 && entry->second.last_used + idle < now;
		if (expired || stale) {
			SessionClosed(entry->second, expired ? "expired" : "idle", now);
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
	auto exp_binds = SessionExpEveryUse();
	lock_guard<mutex> guard(lock);
	return SweepLocked(now, skew, idle, exp_binds);
}

idx_t PolicyStore::SessionCount() {
	// The live total, not the map size: a dead session lingers until the next sweep now that resolving
	// one no longer erases it (spec 054), and "how many sessions are live right now" must not count
	// the not-yet-swept dead. Judged read-only, like SessionAlive.
	auto now = NowSeconds();
	auto skew = JwtClockSkew();
	auto idle = SessionIdleTimeout();
	auto exp_binds = SessionExpEveryUse();
	lock_guard<mutex> guard(lock);
	idx_t live = 0;
	for (auto &entry : sessions) {
		bool expired = exp_binds && entry.second.expires_at > 0 && entry.second.expires_at + skew < now;
		bool stale = idle > 0 && entry.second.last_used + idle < now;
		if (!expired && !stale) {
			live++;
		}
	}
	return live;
}

vector<PolicyStore::SessionInfo> PolicyStore::SessionList() {
	auto now = NowSeconds();
	lock_guard<mutex> guard(lock);
	vector<SessionInfo> out;
	out.reserve(sessions.size());
	for (auto &entry : sessions) {
		SessionInfo info;
		info.id = entry.second.id;
		info.subject = entry.second.principal.subject;
		info.roles = entry.second.principal.roles;
		info.expires_at = entry.second.expires_at;
		info.idle_seconds = now - entry.second.last_used;
		out.push_back(std::move(info));
	}
	return out;
}

bool PolicyStore::SessionKill(const string &id) {
	auto now = NowSeconds();
	lock_guard<mutex> guard(lock);
	for (auto entry = sessions.begin(); entry != sessions.end(); ++entry) {
		if (entry->second.id == id) {
			auto handle = entry->first;
			SessionClosed(entry->second, "killed", now);
			sessions.erase(entry);
			for (auto binding = session_bindings.begin(); binding != session_bindings.end();) {
				binding = binding->second == handle ? session_bindings.erase(binding) : std::next(binding);
			}
			return true;
		}
	}
	return false;
}

string PolicyStore::SessionSql(const string &handle, const string &sql) {
	return SessionSql(handle, sql, string(), string());
}

bool PolicyStore::SessionRefOf(const string &handle, SessionRef &out) {
	lock_guard<mutex> guard(lock);
	auto entry = sessions.find(handle);
	if (entry == sessions.end()) {
		return false;
	}
	out.id = entry->second.id;
	out.door = entry->second.door;
	out.audit_level = entry->second.audit_level;
	out.principal = entry->second.principal;
	return true;
}

void PolicyStore::AuditIngest(const string &handle, int64_t rows, const string &error) {
	if (!audit) {
		return;
	}
	SessionRef ref;
	SessionRefOf(handle, ref);
	AuditEvent event;
	event.kind = "ingest";
	event.door = ref.door;
	event.session = ref.id;
	event.principal = ref.principal;
	event.allowed = error.empty();
	event.rows = rows;
	event.level = event.allowed ? AuditLevel::DECISIONS : AuditLevel::DENIED;
	if (!event.allowed) {
		// Our own refusal carries our prefix - the rewriter's error() inside the written value, or
		// the door's load check - and names virtual objects only, so it is kept from the prefix on.
		// Anything else is the physical source refusing the write, and its text carries the row it
		// refused ("Duplicate key \"id: 7, ssn: ...\""): only the class of the error is kept.
		auto ours = error.find("acl_rewrite:");
		if (ours == string::npos) {
			ours = error.find("acl:");
		}
		if (ours != string::npos) {
			event.reason_code = "write_policy";
			event.reason = error.substr(ours);
		} else {
			event.reason_code = "source_error";
			auto colon = error.find(':');
			auto klass = colon == string::npos ? string("error") : error.substr(0, colon);
			event.reason = "acl: the source refused the write (" + TruncateUtf8(klass, 64) + ")";
		}
	}
	event.recorded = audit->Records(event.level, ref.audit_level);
	audit->Emit(std::move(event));
}

void PolicyStore::AuditDoor(const string &door, const string &detail, bool allowed, const string &reason_code,
                            const string &reason, const string &handle, const Principal *principal) {
	if (!audit) {
		return;
	}
	AuditEvent event;
	event.kind = "door";
	event.door = door;
	event.detail = detail;
	event.allowed = allowed;
	event.reason_code = reason_code;
	event.reason = AuditReasonText(reason_code, reason);
	int8_t session_level = -1;
	SessionRef ref;
	if (!handle.empty() && SessionRefOf(handle, ref)) {
		event.session = ref.id;
		event.principal = ref.principal;
		session_level = ref.audit_level;
	}
	if (principal) {
		event.principal = *principal;
	}
	event.level = allowed ? AuditLevel::ALL : AuditLevel::DENIED;
	event.recorded = audit->Records(event.level, session_level);
	audit->Emit(std::move(event));
}

void PolicyStore::AuditPolicy(const string &detail, const string &reason) {
	if (!audit) {
		return;
	}
	AuditEvent event;
	event.kind = "policy";
	event.detail = detail;
	event.allowed = detail != "source_error";
	if (!event.allowed) {
		event.reason_code = "source_error";
		event.reason = reason;
	}
	event.level = event.allowed ? AuditLevel::ALL : AuditLevel::DENIED;
	event.recorded = audit->Records(event.level, -1);
	audit->Emit(std::move(event));
}

void PolicyStore::AuditKeys(const string &issuer, bool ok, const string &error) {
	if (!audit) {
		return;
	}
	AuditEvent event;
	event.kind = "keys";
	event.objects.push_back(AuditObject {issuer, "keys"});
	event.detail = ok ? "refreshed" : "refresh_failed";
	event.allowed = ok;
	if (!ok) {
		event.reason_code = "source_error";
		event.reason = error;
	}
	event.level = ok ? AuditLevel::ALL : AuditLevel::DENIED;
	event.recorded = audit->Records(event.level, -1);
	audit->Emit(std::move(event));
}

shared_ptr<PolicyStore> PolicyStore::Of(DatabaseInstance &db) {
	auto handle = db.GetObjectCache().Get<PolicyStoreHandle>(PolicyStoreHandle::ObjectType());
	return handle ? handle->store.lock() : nullptr;
}

PolicyStoreHandle::~PolicyStoreHandle() {
	auto locked = store.lock();
	if (locked && locked->audit) {
		locked->audit->Stop(); // the instance is going: drain now, with the file system still whole
	}
}

void TraceFromContext(ClientContext &context, string &correlation_id, string &traceparent) {
	Value value;
	if (context.TryGetCurrentSetting("acl_correlation_id", value) && !value.IsNull()) {
		correlation_id = value.ToString();
	}
	if (context.TryGetCurrentSetting("acl_traceparent", value) && !value.IsNull()) {
		traceparent = value.ToString();
	}
}

string TruncateUtf8(const string &text, idx_t max_bytes) {
	if (text.size() <= max_bytes) {
		return text;
	}
	auto cut = max_bytes;
	// back off to the start of the character the cut would split (a continuation byte is 10xxxxxx)
	while (cut > 0 && (static_cast<unsigned char>(text[cut]) & 0xC0) == 0x80) {
		cut--;
	}
	return text.substr(0, cut);
}

string BoundTrace(const string &value) {
	string clean;
	clean.reserve(value.size());
	for (auto c : value) {
		if (static_cast<unsigned char>(c) >= 0x20 && c != 0x7f) {
			clean += c;
		}
	}
	return TruncateUtf8(clean, 128);
}

string TraceMarkers(const string &correlation_id, const string &traceparent) {
	// bounded, and quoted the way every other prefix value is: a trace names a request, it does not
	// carry a payload, and an id that could not fit a log line is not one
	auto marker = [](const char *keyword, const string &value) {
		return string(keyword) + " '" + StringUtil::Replace(BoundTrace(value), "'", "''") + "' ";
	};
	string out;
	if (!correlation_id.empty()) {
		out += marker("TRACE", correlation_id);
	}
	if (!traceparent.empty()) {
		out += marker("PARENT", traceparent);
	}
	return out;
}

vector<std::pair<string, int64_t>> PolicyStore::SessionCountsByDoor() {
	// the doors of the base are always listed, at zero when idle: a gauge that vanishes at zero is
	// one a dashboard cannot tell from a node that stopped reporting
	std::map<string, int64_t> counts {{"flight", 0}, {"quack", 0}, {"session", 0}};
	{
		lock_guard<mutex> guard(lock);
		for (auto &entry : sessions) {
			counts[entry.second.door]++;
		}
	}
	return vector<std::pair<string, int64_t>>(counts.begin(), counts.end());
}

bool PolicyStore::SetSessionTrace(const string &id, const string &name, const string &value) {
	lock_guard<mutex> guard(lock);
	for (auto &entry : sessions) {
		if (entry.second.id != id) {
			continue;
		}
		if (StringUtil::CIEquals(name, "acl_correlation_id")) {
			entry.second.correlation_id = BoundTrace(value);
		} else if (StringUtil::CIEquals(name, "acl_traceparent")) {
			entry.second.traceparent = BoundTrace(value);
		} else {
			return false;
		}
		return true;
	}
	return false;
}

string PolicyStore::SessionSql(const string &handle, const string &sql, const string &correlation_id,
                               const string &traceparent) {
	// Judge here rather than through SessionPrincipal, for one reason: SessionPrincipal *erases* a
	// dead session on read, which would leave a follow-up SessionReason nothing to report but
	// "unknown" (spec 054). This bumps the live session (using it keeps it alive - the idle rule of
	// spec 044) and leaves a dead one in place for SessionReason and the sweep; it never erases.
	auto now = NowSeconds();
	auto skew = JwtClockSkew();
	auto idle = SessionIdleTimeout();
	auto exp_binds = SessionExpEveryUse();
	lock_guard<mutex> guard(lock);
	auto entry = sessions.find(handle);
	if (entry == sessions.end()) {
		return string();
	}
	if (exp_binds && entry->second.expires_at > 0 && entry->second.expires_at + skew < now) {
		return string();
	}
	if (idle > 0 && entry->second.last_used + idle < now) {
		return string();
	}
	entry->second.last_used = now;
	// what the caller carries (a header, the composing connection's settings) wins; else what the
	// client SET on the session itself, wherever the composition is evaluated
	auto &cid = correlation_id.empty() ? entry->second.correlation_id : correlation_id;
	auto &tp = traceparent.empty() ? entry->second.traceparent : traceparent;
	return "ACL SESSION '" + StringUtil::Replace(handle, "'", "''") + "' " + TraceMarkers(cid, tp) + sql;
}

void PolicyStore::SetDoorOpen(bool open) {
	door_open.store(open);
}

bool PolicyStore::DoorOpen() {
	return door_open.load();
}

bool ClientSettingAllowed(const string &name) {
	// TimeZone and Calendar (ICU) decide how a TIMESTAMPTZ and a date part are RENDERED for this
	// client and nothing else: not what a name resolves to (search_path), not what is read
	// (file_search_path, enable_external_access), not what a statement may cost (threads, memory).
	// Everything outside this list stays refused; growing it is a spec, not a line. The two trace
	// settings (spec 069) name the request a session's statements belong to, and change nothing
	// about what a statement reads or costs.
	return StringUtil::CIEquals(name, "TimeZone") || StringUtil::CIEquals(name, "Calendar") ||
	       StringUtil::CIEquals(name, "acl_correlation_id") || StringUtil::CIEquals(name, "acl_traceparent");
}

bool PolicyStore::SetDraining(bool value) {
	return draining.exchange(value);
}

bool PolicyStore::Draining() const {
	return draining.load(std::memory_order_relaxed);
}

void PolicyStore::SessionClose(const string &handle) {
	auto now = NowSeconds();
	lock_guard<mutex> guard(lock);
	auto entry = sessions.find(handle);
	if (entry != sessions.end()) {
		SessionClosed(entry->second, "client", now);
		sessions.erase(entry);
	}
	for (auto binding = session_bindings.begin(); binding != session_bindings.end();) {
		binding = binding->second == handle ? session_bindings.erase(binding) : std::next(binding);
	}
}

void PolicyStore::SessionBind(const string &external_id, const string &handle) {
	auto now = NowSeconds();
	lock_guard<mutex> guard(lock);
	// Ending what this replaces, rather than leaving it behind: a connection that authenticates again
	// used to orphan its previous session - unreachable, since the handle is never handed out twice and
	// the binding is gone, but permanent all the same (spec 044).
	auto previous = session_bindings.find(external_id);
	if (previous != session_bindings.end() && previous->second != handle) {
		auto replaced = sessions.find(previous->second);
		if (replaced != sessions.end()) {
			SessionClosed(replaced->second, "client", now);
			sessions.erase(replaced);
		}
	}
	session_bindings[external_id] = handle;
}

idx_t PolicyStore::SessionCloseAll() {
	auto now = NowSeconds();
	lock_guard<mutex> guard(lock);
	auto closed = sessions.size();
	for (auto &entry : sessions) {
		SessionClosed(entry.second, "door_stopped", now);
	}
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

bool PolicyStore::SetSessionAuditLevel(const string &id, int8_t level) {
	lock_guard<mutex> guard(lock);
	for (auto &entry : sessions) {
		if (entry.second.id == id) {
			entry.second.audit_level = level;
			return true;
		}
	}
	return false;
}

int8_t PolicyStore::SessionAuditLevel(const string &handle) {
	lock_guard<mutex> guard(lock);
	auto entry = sessions.find(handle);
	return entry == sessions.end() ? -1 : entry->second.audit_level;
}

vector<std::pair<string, int64_t>> PolicyStore::JwksAges() {
	auto now = NowSeconds();
	lock_guard<mutex> guard(lock);
	vector<std::pair<string, int64_t>> out;
	for (auto &entry : jwks_cache) {
		out.emplace_back(entry.first, entry.second.fetched_at > 0 ? now - entry.second.fetched_at : -1);
	}
	return out;
}

bool PolicyStore::VerifyPrincipal(bool is_token, const string &value, Principal &out, bool ignore_exp) {
	if (is_token) {
		string issuer;
		if (LooksLikeJwt(value, issuer)) {
			// the real path (spec 007): signature + claims against the issuer registry; throws on
			// failure, so a bad JWT can never fall back to the dev stub below. Counted either way
			// (spec 069): a verification is not an event, but its rate is a state of the node.
			try {
				VerifyJwtPrincipal(value, issuer, out, ignore_exp);
			} catch (...) {
				CountJwt(audit.get(), "failed");
				throw;
			}
			CountJwt(audit.get(), "ok");
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

void PolicyStore::VerifyJwtPrincipal(const string &token, const string &issuer, Principal &out, bool ignore_exp) {
	IssuerConfig config;
	if (!LookupIssuer(issuer, config)) {
		throw BinderException("acl_rewrite: token rejected: unknown issuer \"%s\"", issuer);
	}
	// the keys may come from a document rather than the row (spec 023); the token's kid decides
	// whether a cached one is still enough
	config.keys_json = ResolveIssuerKeys(config, JwtKid(token));
	auto verified = VerifyJwt(token, config, JwtClockSkew(), ignore_exp);
	if (verified.raw_roles.empty() && verified.groups_overage) {
		throw BinderException("acl_rewrite: token rejected: groups overage - the groups claim was replaced "
		                      "by a Graph link; resolve groups at the gateway and use the ROLE form");
	}
	out.subject = verified.subject;
	out.issuer = issuer;
	out.roles = MapExternalRoles(issuer, verified.raw_roles);
	if (out.roles.empty()) {
		throw BinderException("acl_rewrite: token rejected: no recognized roles");
	}
	out.claims = std::move(verified.claims);
	// role-default claims of the mapped roles (explicit token claims win); the catalog side is
	// merged by the caller via CatalogLoadRoleClaims
	MergeMemoryRoleDefaults(out);
}

void PolicyStore::MergeMemoryRoleDefaults(Principal &out) {
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

vector<string> PolicyStore::ListIssuers() {
	// the discovery document's content (spec 062): issuer URLs only - public by nature, the same
	// class of fact OIDC discovery itself publishes
	vector<string> out;
	if (catalog) {
		CatalogListIssuers(out);
		return out;
	}
	lock_guard<mutex> guard(lock);
	for (auto &entry : issuers) {
		out.push_back(entry.second.issuer);
	}
	return out;
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

//! The exec-context seam (spec 050). Thread-local: the door sets it on the thread that calls
//! Prepare, the rewriter reads it on that same thread during the parse inside that Prepare, and it
//! is cleared before the exec lock is released - no other thread ever observes a value.
static thread_local ClientContext *temp_scan_context = nullptr;

void SetTempScanContext(ClientContext *context) {
	temp_scan_context = context;
}

ClientContext *TempScanContext() {
	return temp_scan_context;
}

//! Walk the connection's private temp catalog through the NO-context, NO-transaction overloads:
//! committed entries only, which is exactly right - a name only becomes resolvable once the
//! statement that created it has finished. A live Catalog::GetEntry here would throw "no active
//! transaction" (probed); this does not, because it never opens one.
static void ScanTempTables(ClientContext &context, const std::function<void(const string &)> &callback) {
	auto &temp_db = ClientData::Get(context).temporary_objects;
	if (!temp_db) {
		return;
	}
	auto &catalog = temp_db->GetCatalog().Cast<DuckCatalog>();
	catalog.ScanSchemas([&](SchemaCatalogEntry &schema_entry) {
		schema_entry.Cast<DuckSchemaEntry>().Scan(
		    CatalogType::TABLE_ENTRY, [&](CatalogEntry &entry) { callback(entry.name.GetIdentifierName()); });
	});
}

bool TempCatalogHas(ClientContext &context, const string &name) {
	bool found = false;
	ScanTempTables(context, [&](const string &entry) {
		if (StringUtil::CIEquals(entry, name)) {
			found = true;
		}
	});
	return found;
}

vector<string> TempCatalogNames(ClientContext &context) {
	vector<string> names;
	ScanTempTables(context, [&](const string &entry) { names.push_back(entry); });
	std::sort(names.begin(), names.end());
	return names;
}

bool PolicyStore::PrincipalMainCap(const Principal &principal, const string &capability) {
	if (catalog) {
		return CatalogPrincipalMainCap(principal, capability);
	}
	// memory mode has no catalog grants, so nothing explicit can sit on one - fail closed
	return false;
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
	auto lowered = StringUtil::Lower(name.Name().GetIdentifierName());
	if (StringUtil::StartsWith(lowered, "acl_")) {
		return false;
	}
	// spec 049: arrow_scan / arrow_scan_dumb turn three raw pointers into a table - memory-unsafe in a
	// principal's hands. The one ingest exemption is Principal::arrow_ingest, honored in the rewriter
	// before this seam is reached; here they are hard-denied AHEAD of the catalog gate, so an
	// acl_allow_function row can never re-open a pointer-dereference primitive (the review's finding).
	if (lowered == "arrow_scan" || lowered == "arrow_scan_dumb") {
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
