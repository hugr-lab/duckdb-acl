// The AST rewriter (specs/001): resolves virtual names to their replacement form (RENAME or
// SUBQUERY), bakes claim constants, substitutes virtual-function arguments, gates functions and
// capabilities - all before bind. Every denial throws, so a recognized ACL prefix never falls back
// to the native parser (FALLBACK would silently re-parse it).

#pragma once

#include "acl_audit.hpp"
#include "acl_policy.hpp"

namespace duckdb {
class SQLStatement;

namespace acl {

//! The bounded taxonomy every refusal names (spec 069): the one dimension a denial counter carries,
//! beside the free text a client reads. Grows by a spec, never by a message.
enum class Reason : uint8_t {
	NO_ACCESS,
	CAPABILITY,
	READ_ONLY,
	FUNCTION_DENIED,
	STATEMENT_TYPE,
	UNCHECKED_PREDICATE,
	SETTING_DENIED,
	PARSE,
	PRINCIPAL,
	MGMT_UNAUTHORIZED,
	DDL_HOME,
	DRAINING,
	AT_CAPACITY,
	SOURCE_ERROR,
	UNAVAILABLE,
	WRITE_POLICY,
	POLICY_ERROR
};
const char *ReasonCode(Reason reason);

//! Note the reason of the refusal about to be thrown. Thread-local, so a refusal thrown anywhere
//! under the rewrite names its code without the exception carrying it: the override that catches
//! the exception takes it back once, and a code nobody noted falls to the phase the override was in.
void NoteDenyReason(Reason reason);
//! The reason noted since the last take, cleared; empty when nothing was noted.
string TakeDenyReason();

//! What the rewrite of one batch decided, per statement (spec 069): the class, every object it
//! touched with the capability the decision needed, and what the decision cost. The entry of the
//! statement being rewritten is the last one, so a refusal thrown mid-walk leaves what was decided
//! up to it.
struct AuditTrail {
	struct Statement {
		string statement;
		vector<AuditObject> objects;
		int64_t rewrite_us = -1;
	};
	vector<Statement> statements;
};

//! Rewrite every statement of one ACL batch in place, under one verified principal
void RewriteStatements(vector<unique_ptr<SQLStatement>> &statements, const Principal &principal,
                       const ParserOptions &options, PolicyStore &store, AuditTrail *trail = nullptr);

//! Rewrite a policy template into a bindable form by baking every marker to NULL: used at write time
//! to derive the column names and types of a query-defined object (spec 010). `expression` picks the
//! shape - a full SELECT (views, table-function macros) or a single expression (scalar macros).
//! `param_types` types the NULLs a probe substitutes for acl_arg(n) - an untyped NULL binds to the
//! wrong type whenever the result depends on an argument, so a declared signature makes the probe
//! meaningful (and a declared RETURNS makes it unnecessary).
string BakeTemplateForProbe(const string &sql, const ParserOptions &options, bool expression,
                            const vector<string> &param_types);

//! The (qualifier, column) pairs an expression names. Every reference must be qualified: without a
//! side we cannot tell whose column it is, and a reference is only visible when its columns are.
vector<std::pair<string, string>> QualifiedColumnRefs(const string &expression, const ParserOptions &options);

} // namespace acl
} // namespace duckdb
