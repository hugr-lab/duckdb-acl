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

} // namespace acl
} // namespace duckdb
