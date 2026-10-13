//===----------------------------------------------------------------------===//
// acl_sql_text.hpp
//
// Checks on stored SQL read as text, never bound (binding would load a source's catalog). Spec 125
// moved them out of the cluster file: the cluster's DETACH and the platform's exposures (spec 120.2)
// both ask them.
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb/common/common.hpp"

namespace duckdb {
namespace acl {

//! spec 118: a view's or a macro's SQL names `source` as a qualifier - `source.` or `"source".`, any
//! case, word-bounded. Over-reading by design: a false hit blocks a DETACH, and FORCE answers it.
bool SqlNamesSource(const string &sql, const string &source);

} // namespace acl
} // namespace duckdb
