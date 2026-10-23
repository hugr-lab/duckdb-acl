//! The Arrow half of spec 046: run a composed catalog statement under a session and shape the rows
//! into the protocol's fixed schema. Declared separately from the server class so the door's file
//! stays about the door.
#pragma once

#include "acl_catalog_rpc.hpp"
#include "acl_policy.hpp"
#include "acl_profile.hpp"
#include "duckdb/main/database.hpp"

#include <arrow/flight/sql/server.h>
#include <functional>

namespace duckdb {
class ClientContext;
class Connection;
class QueryResult;

namespace acl {

arrow::Result<unique_ptr<QueryResult>> RunCatalogQuery(PolicyStore &store, Connection &con, const string &handle,
                                                       const CatalogQuery &query);

arrow::Result<std::shared_ptr<arrow::RecordBatch>> BatchFrom(const std::shared_ptr<arrow::Schema> &schema,
                                                             QueryResult &result, const vector<string> *extra,
                                                             idx_t trailing = 0);

arrow::Result<std::shared_ptr<arrow::RecordBatch>> EmptyBatch(const std::shared_ptr<arrow::Schema> &schema);

//! include_schema's serialized schema per object (spec 046): `tables` the DESCRIBED_TABLES listing, `columns` the
//! COLUMNS one, `tags` the objects' (PolicyStore::ObjectTags) - a column's comment rides as REMARKS, the object's as
//! `duckdb:comment` on the schema, tags as `duckdb:tag:<key>` on both (spec 143)
arrow::Result<vector<string>> SchemasFor(ClientContext &context, QueryResult &tables, QueryResult &columns,
                                         const std::map<std::tuple<string, string, string>, Value> &tags);

//! spec 143: a comment (under `comment_key`) and tags (`duckdb:tag:<key>` each) as Arrow metadata; empty when
//! there is neither
std::shared_ptr<const arrow::KeyValueMetadata> DescribedMetadata(const string &comment_key, const Value &comment,
                                                                 const Value &tags);

//! spec 143: a result schema with its columns' origins (the rewriter's, read off the statement): Flight SQL's
//! CATALOG_NAME / SCHEMA_NAME / TABLE_NAME - the virtual names - and the column's comment as `duckdb:comment`
//! (never REMARKS on a result: arrow-java makes it the column's label) and its tags; the object's comment and tags
//! on the schema when every column is one object's. `describe` answers an origin's object as the principal's
//! listing describes it (null: names only). Origins that do not fit the fields leave the schema as it is.
arrow::Result<std::shared_ptr<arrow::Schema>>
WithOrigins(const std::shared_ptr<arrow::Schema> &schema, const vector<ResultOrigin> &origins,
            const std::function<shared_ptr<const PolicyStore::ObjectDescription>(const ResultOrigin &)> &describe);

//! spec 115: each field carries duckdb's type text as Flight SQL's `ARROW:FLIGHT:SQL:TYPE_NAME` (and a
//! DECIMAL its precision and scale) - what a JDBC driver's getColumns / a tool's tree shows instead of
//! a generic JAVA_OBJECT / ARRAY. `type_texts[i]` is the text to show (empty = the type's own ToString)
arrow::Result<std::shared_ptr<arrow::Schema>> WithTypeNames(const std::shared_ptr<arrow::Schema> &schema,
                                                            const vector<LogicalType> &types,
                                                            const vector<string> &type_texts);

//! The parameter rows a client bound to a prepared statement, read back as duckdb values (spec 047).
//! The batches are exposed as an ArrowArrayStream and read through `arrow_scan` - duckdb's own
//! conversion, the same mechanism its in-tree ADBC layer uses - so no second Arrow-to-duckdb type
//! mapping exists in this codebase.
arrow::Result<vector<vector<Value>>> ParamRowsFrom(DatabaseInstance &db, arrow::flight::FlightMessageReader &reader,
                                                   idx_t max_rows);

//! spec 115: GetXdbcTypeInfo - the types a principal may name (the system catalog's, spec 099), one row
//! each, in Flight SQL's fixed schema; `data_type` narrows to one xdbc code. Static per build.
arrow::Result<std::shared_ptr<arrow::RecordBatch>> XdbcTypeInfoBatch(std::optional<int> data_type);

CatalogFilter FilterFrom(const arrow::flight::sql::GetTables &command);
CatalogFilter FilterFrom(const arrow::flight::sql::GetDbSchemas &command);
CatalogTableRef TableRefFrom(const arrow::flight::sql::TableRef &table);

} // namespace acl
} // namespace duckdb
