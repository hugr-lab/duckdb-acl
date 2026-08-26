//! The Arrow half of spec 046: run a composed catalog statement under a session and shape the rows
//! into the protocol's fixed schema. Declared separately from the server class so the door's file
//! stays about the door.
#pragma once

#include "acl_catalog_rpc.hpp"
#include "acl_policy.hpp"
#include "duckdb/main/database.hpp"

#include <arrow/flight/sql/server.h>

namespace duckdb {
class ClientContext;
class MaterializedQueryResult;

namespace acl {

arrow::Result<unique_ptr<MaterializedQueryResult>> RunCatalogQuery(PolicyStore &store, DatabaseInstance &db,
                                                                   const string &handle, const CatalogQuery &query);

arrow::Result<std::shared_ptr<arrow::RecordBatch>>
BatchFrom(const std::shared_ptr<arrow::Schema> &schema, MaterializedQueryResult &result, const vector<string> *extra);

arrow::Result<std::shared_ptr<arrow::RecordBatch>> EmptyBatch(const std::shared_ptr<arrow::Schema> &schema);

arrow::Result<vector<string>> SchemasFor(ClientContext &context, MaterializedQueryResult &tables,
                                         MaterializedQueryResult &columns);

//! The parameter rows a client bound to a prepared statement, read back as duckdb values (spec 047).
//! The batches are exposed as an ArrowArrayStream and read through `arrow_scan` - duckdb's own
//! conversion, the same mechanism its in-tree ADBC layer uses - so no second Arrow-to-duckdb type
//! mapping exists in this codebase.
arrow::Result<vector<vector<Value>>> ParamRowsFrom(DatabaseInstance &db, arrow::flight::FlightMessageReader &reader);

CatalogFilter FilterFrom(const arrow::flight::sql::GetTables &command);
CatalogFilter FilterFrom(const arrow::flight::sql::GetDbSchemas &command);
CatalogTableRef TableRefFrom(const arrow::flight::sql::TableRef &table);

} // namespace acl
} // namespace duckdb
