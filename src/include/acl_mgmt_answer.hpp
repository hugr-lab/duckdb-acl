//===----------------------------------------------------------------------===//
// acl_mgmt_answer.hpp — what a management statement answers (spec 179)
//
// Every compiled management statement and every top-level `platform.<op>(…)` call answers the same two columns,
// `ok BOOLEAN` and `message VARCHAR` (a STRUCT answer keeps its own fields after them). The call is wrapped once
// every authorizer has judged it: `SELECT __acl_answer.* FROM (SELECT acl_answer('<fn>', <fn>(<args>), <args>…) AS
// __acl_answer)`. acl_answer reads the
// call's value - false, a count, a text - into the pair and adds what the platform part notes about the write
// (`NodeTraits::management_note`). A direct `acl_*` call answers as before.
//===----------------------------------------------------------------------===//
#pragma once

#include "acl_policy.hpp"

#include "duckdb/common/types/value.hpp"

namespace duckdb {
class ExtensionLoader;
class SQLStatement;

namespace acl {

//! Wrap each compiled scalar call of `statements` (`SELECT acl_<fn>(…)`) into its answer; a table call (CHECK, a
//! platform read) answers its rows and is left alone. The statement keeps its text, location and parameters.
void AnswerManagement(vector<unique_ptr<SQLStatement>> &statements);

//! The answer of a call `function` whose value is `value` (its arguments `args`, `note` the platform part's note):
//! `{ok, message, <a STRUCT value's other fields>}`. Pure: the function's own words for a false, a count or a text.
Value ManagementAnswer(const string &function, const Value &value, const LogicalType &type, const string &note);

//! acl_answer(function, value, args…): registered with the admin functions, in the never set by its prefix
void RegisterAclAnswer(ExtensionLoader &loader, const shared_ptr<PolicyStore> &store);

} // namespace acl
} // namespace duckdb
