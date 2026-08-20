// The AST rewriter (specs/001): resolves virtual names to their replacement form (RENAME or
// SUBQUERY), bakes claim constants, substitutes virtual-function arguments, gates functions and
// capabilities - all before bind. Every denial throws, so a recognized ACL prefix never falls back
// to the native parser (FALLBACK would silently re-parse it).

#pragma once

#include "acl_policy.hpp"

namespace duckdb {
class SQLStatement;

namespace acl {

//! Rewrite every statement of one ACL batch in place, under one verified principal
void RewriteStatements(vector<unique_ptr<SQLStatement>> &statements, const Principal &principal,
                       const ParserOptions &options, PolicyStore &store);

//! Rewrite a policy template into a bindable form by baking every marker to NULL: used at write time
//! to derive the column names and types of a query-defined object (spec 010). `expression` picks the
//! shape - a full SELECT (views, table-function macros) or a single expression (scalar macros).
//! `param_types` types the NULLs a probe substitutes for acl_arg(n) - an untyped NULL binds to the
//! wrong type whenever the result depends on an argument, so a declared signature makes the probe
//! meaningful (and a declared RETURNS makes it unnecessary).
string BakeTemplateForProbe(const string &sql, const ParserOptions &options, bool expression,
                            const vector<string> &param_types);

} // namespace acl
} // namespace duckdb
