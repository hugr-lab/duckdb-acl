//! spec 099: what type a column is exposed as. An extension's alias type (`MSSQL_VARCHAR(20)`) means
//! nothing to a client without that extension - a quack client binds the server's DDL and fails its
//! whole ATTACH on one unknown type - so by default it is read as its base type; an ENUM's labels are
//! visible to whoever sees the column, so it may be read as VARCHAR. Both are casts the rewriter puts
//! at the source (`TablePolicy::casts`), and every listing describes the same exposed type through
//! `acl_exposed_type`, so the description and the data agree.
#pragma once

#include "acl_policy.hpp"
#include "duckdb/main/extension/extension_loader.hpp"

namespace duckdb {
namespace acl {

//! `type` with every extension alias replaced by its base type (`strip_alias`; JSON is a built-in's
//! name and stays) and every ENUM by VARCHAR (`enums_to_varchar`), at any depth of a STRUCT / LIST /
//! MAP / ARRAY / UNION. A type nothing changes comes back as it was.
LogicalType ExposedType(const LogicalType &type, bool strip_alias, bool enums_to_varchar);

//! The node's settings, `acl_alias_types` = base and `acl_enum_types` = varchar.
bool NodeStripsAliases(DatabaseInstance &db);
bool NodeEnumsToVarchar(DatabaseInstance &db);

//! acl_exposed_type(type_text, strip_alias, enums_to_varchar) - the listings' spelling of
//! ExposedType. Binds the text as a type, so it is never a principal's (the acl_* never set).
void RegisterAclTypes(ExtensionLoader &loader, const shared_ptr<PolicyStore> &store);

} // namespace acl
} // namespace duckdb
