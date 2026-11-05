//===----------------------------------------------------------------------===//
// acl_admin_sql.hpp — the ACL management grammar (spec 008) and its authorization gate
//
// `ACL ADMIN CREATE VIRTUAL CATALOG ...`, `GRANT CATALOG ... TO ROLE ...`, `ALTER ...`, `DROP ...`
// and the rest compile, with no parse-time side effects, into calls of the acl_* admin functions - the
// families spec 150 moved by the grammar's rules (acl_mgmt_grammar.cpp), the rest here from their text;
// AuthorizeMgmt (acl_platform.hpp) then judges every compiled call against the principal's rights
// (spec 009 / 117) before anything runs. The parser override (acl_parser_override.cpp) is the only caller:
// it recognises the `ACL <management>` marker after a principal and hands the text here.
//===----------------------------------------------------------------------===//
#pragma once

#include "acl_grammar.hpp"
#include "acl_policy.hpp"

#include "duckdb/common/types/value.hpp"
#include "duckdb/parser/parser_options.hpp"

namespace duckdb {
class SQLStatement;

namespace acl {
class AclGrammarCache;

//! `SELECT <function>(<args>)` - what every management form compiles to (the authorizer judges the call), and the
//! call ATTACH … LINEAGE adds (spec 112 §9)
unique_ptr<SQLStatement> MakeAdminCall(const string &function, const vector<Value> &args);

//! Compile a management batch (statements separated by `;`) into admin-function calls. Parse-time
//! only: nothing is written until the statements execute. A statement that does not read is refused (a
//! ParserException from the tokenizer, a BinderException from a form).
//! `current_session` is the ops id of the session the batch runs under ('' off a session): what
//! `PROFILE SESSION CURRENT` names (spec 074 slice 3).
//! spec 150, stage 3: the batch is read by `grammar`'s management rules, a family no rule reads yet by the compiler.
vector<unique_ptr<SQLStatement>> ParseMgmtBatch(const string &text, const string &current_session,
                                                AclGrammarCache &grammar, const ParserOptions &options);

//! spec 082: whether text opens with `GRANT SECRET` / `REVOKE SECRET` - the node's secrets service,
//! not the ACL: judged by the `secrets` capability, never by an administration scope.
bool IsSecretsStart(const string &text);
bool IsSecretsStart(const vector<vector<HeadToken>> &heads); // the same, on heads read once
//! Compile a batch of GRANT / REVOKE SECRET statements (nothing else may be in it) into the service
//! catalog's own calls; the catalog is the one each statement names or the one attached
//! (PolicyStore::SecretService).
//! spec 150 3g-2a: the statements are read by the management grammar's rules (`grammar`, `options` as
//! ParseMgmtBatch's).
vector<unique_ptr<SQLStatement>> ParseSecretsBatch(const string &text, PolicyStore &store, AclGrammarCache &grammar,
                                                   const ParserOptions &options);

//! spec 117: a statement after the first that starts with its own `ACL` prefix - refused with a message of its
//! own (a second prefix inside a batch is text, never a prefix)
void RefuseRepeatedPrefix(const string &text);
void RefuseRepeatedPrefix(const vector<vector<HeadToken>> &heads); // the same, on heads read once
//! spec 117: whether any statement of the batch opens with a management form - each judged by its head on duckdb's
//! tokens (spec 150 stage 3g-1: a comment between the words is gone, `;` ends a statement as duckdb ends it)
bool BatchHasMgmtStatement(const string &text);
bool BatchHasMgmtStatement(const vector<vector<HeadToken>> &heads); // the same, on heads read once
//! spec 117: whether every statement of the batch opens with a management form
bool BatchIsAllMgmt(const string &text);
//! spec 117: whether the batch's first statement - past what opens it but says nothing (whitespace,
//! comments) - opens with a management form: what decides a batch is management
bool StartsWithMgmt(const string &text);
bool StartsWithMgmt(const vector<vector<HeadToken>> &heads); // the same, on heads read once
//! A client's statement text (a door's - spec 111 runs a management statement where Flight SQL runs a command) as the
//! override will read it behind the door's prefix: duckdb's normalized text (a Unicode space is a space), the markers a
//! client writes itself, its `ACL` marker (management unless NATIVE follows), else the first statement's head.
//! `rest`: the normalized text past those markers, for the door's other judgments of the client's statement
bool ClientTextIsMgmt(const string &query, string &rest);

// The authorization gate (spec 009) moved to acl_platform.hpp (spec 117): AuthorizeMgmt is the one
// authorizer of the grammar and of a direct platform.<op>(…) call alike.

} // namespace acl
} // namespace duckdb
