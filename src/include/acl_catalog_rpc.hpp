//===----------------------------------------------------------------------===//
//                         duckdb-acl
//
// acl_catalog_rpc.hpp
//
// The statements behind Flight SQL's catalog RPCs (spec 046).
//
// A door does not know what a role may see. It knows how to turn a protocol command into a `SELECT`
// over the principal's own surfaces - `information_schema.tables`, `.schemata`, `.columns`,
// `acl_references()` - which the rewriter answers under an `ACL SESSION` prefix like any other
// statement. There is therefore exactly one implementation of "what may this role see", and it is not
// here.
//
// This file carries no Arrow: it is compiled into every build, door or not, so the composition can be
// tested without a server (and without a build that links Arrow at all).
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb/common/types/value.hpp"
#include "duckdb/common/vector.hpp"
#include "duckdb/common/string.hpp"

namespace duckdb {
namespace acl {

//! A composed statement and the values its `$n` placeholders take, in order. Filter patterns are
//! bound rather than quoted into the text - the door writes this statement, so the only parameters in
//! it are its own, and a pattern never reaches the parser as SQL.
struct CatalogQuery {
	string sql;
	vector<Value> parameters;
};

//! Which listing a command needs. COLUMNS is not an RPC of its own - it is what `GetTables` asks for
//! when `include_schema` is set, in one statement rather than one per table.
enum class CatalogListing : uint8_t { CATALOGS, DB_SCHEMAS, TABLES, TABLE_TYPES, COLUMNS };

//! The filters a Flight SQL catalog command may carry. Flight's semantics are followed as written,
//! including the corner: an *absent* catalog means no filter, while an empty string means "objects
//! with no catalog" - which correctly matches nothing here, since every object has one.
struct CatalogFilter {
	bool has_catalog = false;
	string catalog;
	bool has_db_schema_pattern = false;
	string db_schema_pattern;
	bool has_table_pattern = false;
	string table_pattern;
	vector<string> table_types;
};

//! Which end of a reference the named table is. IMPORTED: the table holds the referencing columns
//! (spec 022's `from` end). EXPORTED: the table is referenced (the `to` end). CROSS: both ends named.
enum class KeyListing : uint8_t { IMPORTED, EXPORTED, CROSS };

//! A table as Flight names one. `schema` empty means the catalog's main schema.
struct CatalogTableRef {
	bool has_catalog = false;
	string catalog;
	string schema;
	string table;
};

CatalogQuery BuildCatalogListing(CatalogListing listing, const CatalogFilter &filter);
CatalogQuery BuildKeyListing(KeyListing listing, const CatalogTableRef &table, const CatalogTableRef &second);

} // namespace acl
} // namespace duckdb
