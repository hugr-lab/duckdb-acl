#include "acl_parser_override.hpp"

#include "acl_admin_sql.hpp"
#include "acl_audit_pipeline.hpp"
#include "acl_rewriter.hpp"
#include "acl_scan_util.hpp"
#include "duckdb/common/error_data.hpp"
#include "duckdb/common/exception/binder_exception.hpp"
#include "duckdb/common/exception/parser_exception.hpp"
#include "duckdb/common/helper.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/parser/expression/constant_expression.hpp"
#include "duckdb/parser/expression/function_expression.hpp"
#include "duckdb/parser/parser.hpp"
#include "duckdb/parser/parsed_data/create_info.hpp"
#include "duckdb/parser/query_node/select_node.hpp"
#include "duckdb/parser/statement/create_statement.hpp"
#include "duckdb/parser/statement/select_statement.hpp"
#include "duckdb/parser/tableref/emptytableref.hpp"

#include <algorithm>
#include <cstring>
#include <unordered_map>

namespace duckdb {
namespace acl {
namespace {

struct AclPrefix {
	enum class Kind { NONE, ROLE, TOKEN, SESSION, ADMIN, INGEST };
	//! What the remainder is, decided by the marker the CLIENT writes (the gateway only prepends the
	//! principal, so the client itself asks for anything beyond an ordinary query):
	//!   <sql>              -> QUERY:  rewritten inside the principal's virtual catalog
	//!   ACL <mgmt>         -> MANAGE: an ACL management statement (needs a manage/passthrough scope)
	//!   ACL NATIVE <sql>   -> NATIVE: plain SQL outside the virtual catalog (needs passthrough)
	//! `ACL ADMIN ...` is the gateway's own anonymous form of the same thing - NATIVE unless it
	//! carries a marker or a management statement.
	enum class Mode { QUERY, MANAGE, NATIVE };
	Kind kind = Kind::NONE;
	Mode mode = Mode::QUERY;
	bool marked = false; // an explicit `ACL [NATIVE]` marker was written
	string value;
	string rest;
	//! The statement's trace (spec 069): `TRACE '<correlation id>'` / `PARENT '<traceparent>'`,
	//! written after the principal by whoever composes the prefix, carried onto every event about it
	string correlation_id;
	string traceparent;
};

AclPrefix ParseAclPrefix(const string &query) {
	AclPrefix prefix;
	idx_t pos = 0;
	SkipWhitespace(query, pos);
	auto keyword = ReadWord(query, pos);
	if (!StringUtil::CIEquals(keyword, "acl")) {
		return prefix; // not our syntax
	}
	SkipWhitespace(query, pos);
	auto mode = ReadWord(query, pos);
	//! Read the client's marker off the remainder: `ACL [NATIVE]`
	auto read_marker = [&](idx_t &scan) {
		SkipWhitespace(query, scan);
		auto saved = scan;
		if (!StringUtil::CIEquals(ReadWord(query, scan), "acl")) {
			scan = saved;
			return AclPrefix::Mode::QUERY;
		}
		SkipWhitespace(query, scan);
		auto after_acl = scan;
		if (StringUtil::CIEquals(ReadWord(query, scan), "native")) {
			return AclPrefix::Mode::NATIVE;
		}
		scan = after_acl;
		return AclPrefix::Mode::MANAGE;
	};
	//! Read the trace markers off the remainder, in either order: `[TRACE '<id>'] [PARENT '<tp>']`
	auto read_trace = [&](idx_t &scan) {
		for (;;) {
			SkipWhitespace(query, scan);
			auto saved = scan;
			auto word = ReadWord(query, scan);
			bool trace = StringUtil::CIEquals(word, "trace");
			bool parent = StringUtil::CIEquals(word, "parent");
			if (!trace && !parent) {
				scan = saved;
				return;
			}
			SkipWhitespace(query, scan);
			if (scan >= query.size() || (query[scan] != '\'' && query[scan] != '"')) {
				throw ParserException("acl_rewrite: ACL %s requires a quoted value", trace ? "TRACE" : "PARENT");
			}
			(trace ? prefix.correlation_id : prefix.traceparent) = ReadQuoted(query, scan);
		}
	};
	if (StringUtil::CIEquals(mode, "admin")) {
		prefix.kind = AclPrefix::Kind::ADMIN;
		read_trace(pos);
		// the gateway's own hatch: native by default, management when marked (or written bare)
		auto marked = read_marker(pos);
		prefix.marked = marked != AclPrefix::Mode::QUERY;
		prefix.mode = prefix.marked ? marked : AclPrefix::Mode::NATIVE;
		prefix.rest = query.substr(pos);
		return prefix;
	}
	if (StringUtil::CIEquals(mode, "ingest")) {
		// spec 049: the door's own composition for its ingest INSERT - a session handle, then the
		// statement. No markers ride here: the remainder must be the INSERT itself, and an embedded
		// `ACL ...` is mid-statement garbage exactly as it is after any other prefix.
		SkipWhitespace(query, pos);
		if (pos >= query.size() || (query[pos] != '\'' && query[pos] != '"')) {
			throw ParserException("acl_rewrite: ACL INGEST requires a quoted session handle");
		}
		prefix.kind = AclPrefix::Kind::INGEST;
		prefix.value = ReadQuoted(query, pos);
		read_trace(pos);
		prefix.rest = query.substr(pos);
		return prefix;
	}
	bool is_role = StringUtil::CIEquals(mode, "role");
	bool is_token = StringUtil::CIEquals(mode, "token");
	// a session stands for a token a door already verified, so the handle rides where the token did
	// and everything after it - the markers, the batch - reads the same way (spec 040)
	bool is_session = StringUtil::CIEquals(mode, "session");
	if (!is_role && !is_token && !is_session) {
		return prefix; // "ACL <unknown>" -> leave for the native parser (NONE)
	}
	SkipWhitespace(query, pos);
	if (pos >= query.size() || (query[pos] != '\'' && query[pos] != '"')) {
		throw ParserException("acl_rewrite: ACL %s requires a quoted value", mode);
	}
	prefix.kind = is_role ? AclPrefix::Kind::ROLE : (is_session ? AclPrefix::Kind::SESSION : AclPrefix::Kind::TOKEN);
	prefix.value = ReadQuoted(query, pos);
	read_trace(pos);
	prefix.mode = read_marker(pos);
	prefix.marked = prefix.mode != AclPrefix::Mode::QUERY;
	prefix.rest = query.substr(pos);
	return prefix;
}

//===--------------------------------------------------------------------===//
// ACL ADMIN management grammar (spec 008)
//
// Recognized forms compile - with NO side effects at parse time - into synthesized
// `SELECT acl_<fn>(<constants>)` statements that run through the normal pipeline into the existing
// admin functions. Values travel as ConstantExpression nodes, never as SQL text. Anything that does
// not start with a management form stays the native ADMIN passthrough (`ACL ADMIN CREATE TABLE ...`
// is still plain DDL); a management form with a typo is an error, never a fallthrough.
//===--------------------------------------------------------------------===//

//! Token reader over the management text (words, dotted identifiers, quoted values)

//! True while this override is parsing the remainder of an ACL statement. The inner parse may run
//! other extensions' overrides (the native context does), and this keeps ours out of it: a nested
//! `ACL …` prefix must stay unparseable, or the inner parse would verify a second principal and the
//! outer one would rewrite what the inner one already produced.
bool &InAclParse() {
	static thread_local bool in_parse = false;
	return in_parse;
}

struct AclParseGuard {
	AclParseGuard() {
		InAclParse() = true;
	}
	~AclParseGuard() {
		InAclParse() = false;
	}
};

//! The principal a prefix stands for. A role is itself, a token is verified here, and a session is a
//! handle a door already exchanged a token for (spec 040) - so this is the one place that turns any
//! of the three into a principal, and the one place that refuses.
void ResolvePrincipal(PolicyStore &store, const AclPrefix &prefix, Principal &out) {
	if (prefix.kind == AclPrefix::Kind::SESSION || prefix.kind == AclPrefix::Kind::INGEST) {
		string reason;
		if (!store.SessionPrincipal(prefix.value, out, reason)) {
			NoteDenyReason(Reason::PRINCIPAL);
			throw BinderException("acl_rewrite: session %s", reason);
		}
		// a session is a connection of the client's own (spec 050), so a setting may live on it
		// (spec 068); the ingest prefix carries the door's composed INSERT and sets nothing
		out.session_connection = prefix.kind == AclPrefix::Kind::SESSION;
		return;
	}
	bool is_token = prefix.kind == AclPrefix::Kind::TOKEN;
	if (!store.VerifyPrincipal(is_token, prefix.value, out)) {
		NoteDenyReason(Reason::PRINCIPAL);
		throw BinderException("acl_rewrite: %s verification failed", is_token ? "token" : "role");
	}
}

//! The audit's view of one prefixed batch (spec 069): filled as the override learns who and what,
//! emitted once per statement decided - or once for the refusal that ended the batch, naming the
//! statement it stopped at and what had been decided up to it. Every event is emitted whatever the
//! level (the counters are a state of the node) and recorded only where the level says so.
struct StatementAudit {
	explicit StatementAudit(AuditPipeline *audit) : audit(audit) {
		TakeDenyReason(); // a stale note from a refusal nobody audited must not name this one
		proto.kind = "statement";
		proto.door = "gateway";
	}

	AuditPipeline *audit;
	AuditEvent proto; // what every event of the batch shares: door, session, principal, trace
	int8_t session_level = -1;
	AuditTrail trail;
	//! What the override was doing when an exception nobody noted escaped: it names the code
	Reason phase = Reason::PARSE;

	//! The batch runs under a session: its door, its ops id and its own level name the events
	void OnSession(PolicyStore &store, const string &handle) {
		PolicyStore::SessionRef ref;
		if (store.SessionRefOf(handle, ref)) {
			proto.door = ref.door;
			proto.session = ref.id;
			session_level = ref.audit_level;
		}
	}

	void Decided(const AuditTrail::Statement &stmt, bool allowed, const string &code, const string &reason) {
		if (!audit) {
			return;
		}
		AuditEvent event = proto;
		event.level = allowed ? AuditLevel::DECISIONS : AuditLevel::DENIED;
		event.recorded = audit->Records(event.level, session_level);
		event.statement = stmt.statement;
		event.objects = stmt.objects;
		event.rewrite_us = stmt.rewrite_us;
		event.allowed = allowed;
		event.reason_code = code;
		event.reason = reason;
		audit->Emit(std::move(event));
	}

	void Allowed() {
		for (auto &stmt : trail.statements) {
			Decided(stmt, true, string(), string());
		}
	}

	void Denied(const std::exception &ex) {
		auto code = TakeDenyReason();
		if (code.empty()) {
			code = ReasonCode(phase);
		}
		AuditTrail::Statement last;
		if (!trail.statements.empty()) {
			last = trail.statements.back();
		}
		ErrorData error(ex);
		Decided(last, false, code, error.RawMessage());
	}
};

//! The admin function a compiled management statement calls (`SELECT acl_<fn>(...)`), or ""
string MgmtCallName(SQLStatement &stmt) {
	if (stmt.type != StatementType::SELECT_STATEMENT) {
		return string();
	}
	auto &node = *stmt.Cast<SelectStatement>().node;
	if (node.type != QueryNodeType::SELECT_NODE) {
		return string();
	}
	auto &select = node.Cast<SelectNode>();
	if (select.select_list.size() != 1 || select.select_list[0]->GetExpressionClass() != ExpressionClass::FUNCTION) {
		return string();
	}
	return select.select_list[0]->Cast<FunctionExpression>().FunctionName().GetIdentifierName();
}

//! Is `name_lower` *called* anywhere in the query - the identifier followed by its open parenthesis?
//! Allocation-free, because every unprefixed statement passes through here, so it must not copy the
//! query to lowercase.
//!
//! The parenthesis is not pedantry: the resolver embeds the name it is looking up as a literal in its
//! own catalog SQL, so a bare occurrence says nothing about what the statement does. A call is what a
//! generated ingest statement always contains and a quoted name never is.
//! The table function a quack server generates to drain a client's streamed insert. Never a name a
//! client can author: it is on the denylist for a principal, and this statement is the server's own.
//! Two names: the embedded door (spec 063) drains through `acl_quack_scan_data`, but a stock quack
//! co-loaded and serving alongside still generates the original `scan_data_from_quack_client`. The
//! fence catches BOTH, so either server's unprefixed drain fails closed here.
constexpr const char *STREAM_SCAN = "acl_quack_scan_data";
constexpr const char *STREAM_SCAN_LEGACY = "scan_data_from_quack_client";

bool CallsFunctionNamed(const string &query, const char *name_lower, idx_t name_size) {
	if (query.size() < name_size) {
		return false;
	}
	auto end = query.end();
	auto ci_match = [](char a, char b) {
		return StringUtil::CharacterToLower(a) == b;
	};
	for (auto it = query.begin();;) {
		it = std::search(it, end, name_lower, name_lower + name_size, ci_match);
		if (it == end) {
			return false;
		}
		auto after = it + UnsafeNumericCast<int64_t>(name_size);
		if (after != end && *after == '"') {
			after++; // a quoted identifier is the same call: `"name"(...)`
		}
		while (after != end && StringUtil::CharacterIsSpace(*after)) {
			after++;
		}
		if (after != end && *after == '(') {
			return true;
		}
		++it;
	}
}

//! quack drains a client's streamed INSERT with a statement the *server* generates on the client's
//! own connection - `INSERT INTO <schema>.<table> SELECT * FROM scan_data_from_quack_client('<id>')`
//! - and generates it unprefixed, so it arrives here as an ordinary native statement and would run
//! with the operator's rights and no policy at all.
//!
//! Measured, not hypothesised (spec 041): where the published name resolves to a physical table of
//! matching width, a client bulk-inserted rows its own predicate forbids. The refusal lives here, at
//! the one place every unprefixed statement passes, rather than only in the probe quack authorizes
//! first - what actually writes is this statement, and it names this function every time.
//!
//! Spec 042 attaches the principal here instead of refusing, when it can be recovered; the refusal
//! below is what remains when it cannot.
bool DrainsQuackClientStream(const string &query) {
	return CallsFunctionNamed(query, STREAM_SCAN, strlen(STREAM_SCAN)) ||
	       CallsFunctionNamed(query, STREAM_SCAN_LEGACY, strlen(STREAM_SCAN_LEGACY));
}

//! The one stream id a generated ingest statement drains, or empty when the statement is not exactly
//! one such call with one quoted argument. Deliberately unforgiving: every shape we do not recognise
//! ends in a refusal, so reading this wrong costs a bulk load and never a policy.
string ExtractStreamIdFor(const string &query, const char *scan_name) {
	auto name_size = strlen(scan_name);
	auto ci_match = [](char a, char b) {
		return StringUtil::CharacterToLower(a) == b;
	};
	string found;
	idx_t pos = 0;
	while (pos < query.size()) {
		auto it = std::search(query.begin() + UnsafeNumericCast<int64_t>(pos), query.end(), scan_name,
		                      scan_name + name_size, ci_match);
		if (it == query.end()) {
			break;
		}
		auto at = UnsafeNumericCast<idx_t>(it - query.begin());
		auto scan = at + name_size;
		if (scan < query.size() && query[scan] == '"') {
			scan++; // `"name"(…)` is the same call, and the fence above reads it the same way
		}
		SkipWhitespace(query, scan);
		if (scan >= query.size() || query[scan] != '(') {
			pos = at + 1; // the name as ordinary text, not a call
			continue;
		}
		scan++;
		SkipWhitespace(query, scan);
		if (scan >= query.size() || query[scan] != '\'') {
			return string(); // a call whose argument we cannot read
		}
		auto value = ReadQuoted(query, scan);
		SkipWhitespace(query, scan);
		if (scan >= query.size() || query[scan] != ')') {
			return string(); // more than the single argument quack passes
		}
		if (!found.empty()) {
			return string(); // two streams in one statement is not a shape we know
		}
		found = value;
		pos = scan;
	}
	return found;
}

//! The stream id, from whichever drain name the statement uses (embedded or a co-loaded stock quack).
//! A statement that somehow named both would extract from neither cleanly, so the embedded name is
//! tried first and the legacy only when the embedded is absent.
string ExtractStreamId(const string &query) {
	auto id = ExtractStreamIdFor(query, STREAM_SCAN);
	if (!id.empty()) {
		return id;
	}
	return ExtractStreamIdFor(query, STREAM_SCAN_LEGACY);
}

//! Recover the principal a generated ingest statement belongs to and rewrite it as an ordinary
//! insert (spec 042). quack builds the stream id as `connection_id + ":" + uuid`, and
//! `acl_quack_authenticate` bound that connection id to a session - so the statement carries the key
//! to its own principal, and nothing has to be journalled ahead of time.
//!
//! Every step that does not succeed throws: the rewrite is the exception here and the refusal is the
//! rule, which is the opposite of how the rest of the override reads.
ParserOverrideResult DrainStreamUnderPrincipal(PolicyStore &store, const string &query, ParserOptions &options,
                                               StatementAudit &audit) {
	static constexpr const char *REFUSED = "acl: a streamed insert carries no principal, so it would be written "
	                                       "outside the policy";
	audit.phase = Reason::PRINCIPAL;
	auto stream_id = ExtractStreamId(query);
	if (stream_id.empty()) {
		throw BinderException("%s (its stream is not one this door opened)", REFUSED);
	}
	auto colon = stream_id.find(':');
	if (colon == string::npos || colon == 0) {
		throw BinderException("%s (its stream names no connection)", REFUSED);
	}
	auto connection_id = stream_id.substr(0, colon);
	string handle;
	if (!store.SessionHandleFor(connection_id, handle)) {
		throw BinderException("%s (its connection has no session)", REFUSED);
	}
	audit.OnSession(store, handle);
	Principal principal;
	string reason;
	if (!store.SessionPrincipal(handle, principal, reason)) {
		throw BinderException("%s (its session is %s)", REFUSED, reason.empty() ? "not usable" : reason.c_str());
	}
	// the one exemption this path carries, and it is bound to this exact stream: the principal may
	// read the source the server is filling for it, and no other
	principal.ingest_stream = stream_id;
	audit.proto.principal = principal;

	audit.phase = Reason::PARSE;
	vector<unique_ptr<SQLStatement>> statements;
	{
		AclParseGuard guard;
		ParserOptions inner = options;
		inner.parser_override_setting = AllowParserOverride::DEFAULT_OVERRIDE;
		Parser parser(inner);
		parser.ParseQuery(query);
		statements = std::move(parser.statements);
	}
	audit.phase = Reason::POLICY_ERROR;
	RewriteStatements(statements, principal, options, store, &audit.trail);
	return ParserOverrideResult(std::move(statements));
}

//! One prefixed batch, decided. Every refusal throws; the caller turns the outcome into the audit's
//! events, so this only has to say what it is doing (`audit.phase`) and whom it is doing it for.
ParserOverrideResult Prefixed(PolicyStore &store, const AclPrefix &prefix, ParserOptions &options,
                              StatementAudit &audit) {
	auto mode = prefix.mode;
	bool anonymous = prefix.kind == AclPrefix::Kind::ADMIN;
	if (anonymous && !prefix.marked && IsMgmtStart(prefix.rest)) {
		// the trusted gateway may write management statements unmarked; an explicit `ACL NATIVE`
		// means "plain SQL, do not interpret it" and must never be re-routed here
		mode = AclPrefix::Mode::MANAGE;
	}

	Principal principal;
	PolicyStore::AdminRights rights;
	rights.scope = AdminScope::PASSTHROUGH; // the anonymous hatch is god mode by definition
	rights.unrestricted_manage = true;
	if (anonymous) {
		audit.proto.door = "admin";
		audit.proto.detail = "anonymous";
		if (!store.AnonymousAdminAllowed()) {
			NoteDenyReason(Reason::MGMT_UNAUTHORIZED);
			throw BinderException("acl admin: a bare ACL ADMIN is disabled - authenticate the principal "
			                      "(ACL TOKEN '<jwt>' ACL ...) or SET GLOBAL acl_allow_anonymous_admin=true");
		}
	} else if (mode != AclPrefix::Mode::QUERY) {
		// leaving the virtual catalog - as management or as native SQL - is a granted capability
		audit.phase = Reason::PRINCIPAL;
		ResolvePrincipal(store, prefix, principal);
		audit.proto.principal = principal;
		rights = store.AdminRightsOf(principal);
		audit.proto.detail = rights.scope == AdminScope::PASSTHROUGH ? "passthrough" : "manage";
		if (rights.scope == AdminScope::NONE) {
			NoteDenyReason(Reason::MGMT_UNAUTHORIZED);
			throw BinderException("acl admin: the principal has no ACL administration scope");
		}
	}
	if (mode != AclPrefix::Mode::QUERY) {
		audit.proto.kind = "admin"; // management, or native SQL outside the virtual catalog
	}

	if (mode == AclPrefix::Mode::MANAGE) {
		// the management grammar (spec 008): compiled to admin-function calls, no native parse
		audit.phase = Reason::PARSE;
		auto statements = ParseMgmtBatch(prefix.rest);
		for (auto &stmt : statements) {
			audit.trail.statements.emplace_back();
			audit.trail.statements.back().statement = "manage";
			audit.trail.statements.back().objects.push_back(AuditObject {MgmtCallName(*stmt), "manage"});
		}
		audit.phase = Reason::MGMT_UNAUTHORIZED;
		AuthorizeMgmt(statements, rights);
		return ParserOverrideResult(std::move(statements));
	}
	if (mode == AclPrefix::Mode::NATIVE) {
		audit.trail.statements.emplace_back();
		audit.trail.statements.back().statement = "native";
		if (rights.scope != AdminScope::PASSTHROUGH) {
			// a manage scope administers the ACL; running SQL outside the virtual catalog is god mode
			NoteDenyReason(Reason::MGMT_UNAUTHORIZED);
			throw BinderException("acl admin: native SQL outside the virtual catalog requires a passthrough scope");
		}
	}

	// Re-parse the remainder. Foreign syntax reaches this parse two ways (spec 067), and both stay
	// safe by construction. A foreign parser_override runs only in the NATIVE context (the setting
	// below) - it may hand back arbitrary AST, and NATIVE rewrites nothing and requires passthrough,
	// so another extension's syntax is no more privileged there than the SQL it already allows. A
	// foreign parse_function (the PEG peeler) runs in EVERY context - `options` carries the
	// extension list and the compiled-grammar cache through - but what it claims becomes an opaque
	// ExtensionStatement planned by its own extension, which the rewriter's statement gate
	// default-denies in the virtual context: we cannot enumerate what we cannot see. When upstream
	// lands grammar-extension registration, extended-grammar statements arrive as ordinary AST the
	// rewriter walks node by node - unknown nodes denied - through this same call, unchanged.
	// `in_acl_parse` keeps *this* override out of its own inner parse, so a nested `ACL …` prefix
	// stays unparseable.
	audit.phase = Reason::PARSE;
	ParserOptions inner = options;
	if (mode != AclPrefix::Mode::NATIVE) {
		inner.parser_override_setting = AllowParserOverride::DEFAULT_OVERRIDE;
	}
	vector<unique_ptr<SQLStatement>> statements;
	{
		AclParseGuard guard;
		Parser parser(inner);
		parser.ParseQuery(prefix.rest);
		statements = std::move(parser.statements);
	}

	if (mode == AclPrefix::Mode::NATIVE) {
		return ParserOverrideResult(std::move(statements)); // no rewrite: the native context
	}

	audit.phase = Reason::PRINCIPAL;
	ResolvePrincipal(store, prefix, principal);
	audit.proto.principal = principal;

	if (prefix.kind == AclPrefix::Kind::INGEST) {
		audit.proto.detail = "ingest";
		// the ingest prefix carries the door's own composed statement and nothing else (spec 049):
		// one statement, of exactly two shapes - the append INSERT, or the CREATE TABLE that stages
		// into the session (spec 050) or creates/replaces in a granted home (spec 051). Anything
		// wider would hand the arrow_scan exemption to text the door never wrote.
		bool insert_form = statements.size() == 1 && statements[0]->type == StatementType::INSERT_STATEMENT;
		bool create_form = false;
		if (statements.size() == 1 && statements[0]->type == StatementType::CREATE_STATEMENT) {
			auto &info = statements[0]->Cast<CreateStatement>().info;
			create_form = info && info->type == CatalogType::TABLE_ENTRY;
		}
		if (!insert_form && !create_form) {
			NoteDenyReason(Reason::STATEMENT_TYPE);
			throw BinderException(
			    "acl_rewrite: the ingest prefix carries exactly one INSERT or CREATE TABLE statement");
		}
		principal.arrow_ingest = true;
	}
	audit.phase = Reason::POLICY_ERROR; // an unnoted failure under the rewrite is the policy's
	RewriteStatements(statements, principal, options, store, &audit.trail);
	return ParserOverrideResult(std::move(statements));
}

ParserOverrideResult AclParserOverride(ParserExtensionInfo *info, const string &query, ParserOptions &options) {
	if (InAclParse()) {
		return ParserOverrideResult(); // our own inner parse: decline, and let the others try
	}
	auto &store = *info->Cast<AclParserInfo>().store;
	auto prefix = ParseAclPrefix(query);
	if (prefix.kind == AclPrefix::Kind::NONE) {
		// The one thing we do to a statement nobody prefixed - and only while a door of ours is open.
		// The refusal exists because a client *we serve* caused the statement; with no door open, a
		// plain quack server's ingest is its own business, and taking it would mean anyone who merely
		// loads this extension loses quack's bulk loading (spec 043, found by the throughput benchmark,
		// whose un-ACL'd baseline could not load at all).
		if (store.DoorOpen() && DrainsQuackClientStream(query)) {
			StatementAudit audit(store.audit.get());
			audit.proto.detail = "drain";
			try {
				auto result = DrainStreamUnderPrincipal(store, query, options, audit);
				audit.Allowed();
				return result;
			} catch (std::exception &ex) {
				audit.Denied(ex);
				throw;
			}
		}
		return ParserOverrideResult(); // fall through to the native parser
	}

	// the decision is audited whatever happens to it (spec 069): one event per statement decided, or
	// one for the refusal - the events are emitted here, after the decision, never on its path
	StatementAudit audit(store.audit.get());
	audit.proto.correlation_id = prefix.correlation_id;
	audit.proto.traceparent = prefix.traceparent;
	if (prefix.kind == AclPrefix::Kind::SESSION || prefix.kind == AclPrefix::Kind::INGEST) {
		audit.OnSession(store, prefix.value); // known before anything is judged: a parse error names it too
	}
	try {
		auto result = Prefixed(store, prefix, options, audit);
		audit.Allowed();
		return result;
	} catch (std::exception &ex) {
		audit.Denied(ex);
		throw;
	}
}

} // namespace

void RegisterAclParser(DBConfig &config, shared_ptr<PolicyStore> store) {
	ParserExtension extension;
	extension.parser_override = AclParserOverride;
	extension.parser_info = make_shared_ptr<AclParserInfo>(std::move(store));
	ParserExtension::Register(config, extension);
}

} // namespace acl
} // namespace duckdb
