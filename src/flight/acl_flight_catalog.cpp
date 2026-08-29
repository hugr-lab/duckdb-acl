//===----------------------------------------------------------------------===//
// The Flight SQL catalog RPCs (spec 046) - the Arrow half.
//
// The statements live in `src/acl_catalog_rpc.cpp`, which links no Arrow and is compiled into every
// build. What is here is the glue: run one of those statements under the caller's session, and turn
// the rows into the *protocol's* schema.
//
// The batches are built with Arrow's own builders rather than by importing duckdb's Arrow export and
// declaring the protocol's schema over it. Importing would be less code and would quietly depend on
// two instance settings - `arrow_large_buffer_size` turns `utf8` into `large_utf8`, and
// `produce_arrow_string_view` turns it into `string_view` - so a client's catalog tree would depend on
// how the server was configured for something else entirely. Building explicitly costs a row loop over
// a listing of tens of rows and removes the question.
//===----------------------------------------------------------------------===//

#include "acl_flight_catalog.hpp"

#include "acl_catalog_rpc.hpp"
#include "duckdb/common/arrow/arrow_converter.hpp"
#include "duckdb/common/types.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/common/arrow/arrow_wrapper.hpp"
#include "duckdb/function/table/arrow.hpp"
#include "duckdb/common/error_data.hpp"
#include "duckdb/main/connection.hpp"

#include <arrow/array/builder_binary.h>
#include <arrow/array/builder_primitive.h>
#include <arrow/c/bridge.h>
#include <arrow/ipc/writer.h>
#include <arrow/record_batch.h>
#include <arrow/table.h>

namespace duckdb {
namespace acl {

namespace flight = arrow::flight;
namespace flightsql = arrow::flight::sql;

namespace {

//! Every column a catalog answer can carry, appended one row at a time. The protocol's schemas use
//! four types between them; anything else is a mistake worth failing on rather than guessing at.
struct ColumnBuilder {
	explicit ColumnBuilder(const std::shared_ptr<arrow::DataType> &type) : id(type->id()) {
		switch (id) {
		case arrow::Type::STRING:
			strings = std::make_unique<arrow::StringBuilder>();
			break;
		case arrow::Type::BINARY:
			binaries = std::make_unique<arrow::BinaryBuilder>();
			break;
		case arrow::Type::INT32:
			int32s = std::make_unique<arrow::Int32Builder>();
			break;
		case arrow::Type::UINT8:
			uint8s = std::make_unique<arrow::UInt8Builder>();
			break;
		default:
			throw InternalException("acl: a catalog answer cannot carry %s", type->ToString());
		}
	}

	arrow::Status Append(const Value &value) {
		if (value.IsNull()) {
			return AppendNull();
		}
		switch (id) {
		case arrow::Type::STRING:
			return strings->Append(value.ToString());
		case arrow::Type::BINARY:
			return binaries->Append(value.ToString());
		case arrow::Type::INT32:
			return int32s->Append(value.GetValue<int32_t>());
		case arrow::Type::UINT8:
			return uint8s->Append(value.GetValue<uint8_t>());
		default:
			return arrow::Status::Invalid("acl: unreachable column type");
		}
	}

	arrow::Status AppendBinary(const string &bytes) {
		return binaries->Append(bytes);
	}

	arrow::Status AppendNull() {
		switch (id) {
		case arrow::Type::STRING:
			return strings->AppendNull();
		case arrow::Type::BINARY:
			return binaries->AppendNull();
		case arrow::Type::INT32:
			return int32s->AppendNull();
		default:
			return uint8s->AppendNull();
		}
	}

	arrow::Result<std::shared_ptr<arrow::Array>> Finish() {
		std::shared_ptr<arrow::Array> array;
		switch (id) {
		case arrow::Type::STRING:
			ARROW_RETURN_NOT_OK(strings->Finish(&array));
			break;
		case arrow::Type::BINARY:
			ARROW_RETURN_NOT_OK(binaries->Finish(&array));
			break;
		case arrow::Type::INT32:
			ARROW_RETURN_NOT_OK(int32s->Finish(&array));
			break;
		default:
			ARROW_RETURN_NOT_OK(uint8s->Finish(&array));
			break;
		}
		return array;
	}

	arrow::Type::type id;
	std::unique_ptr<arrow::StringBuilder> strings;
	std::unique_ptr<arrow::BinaryBuilder> binaries;
	std::unique_ptr<arrow::Int32Builder> int32s;
	std::unique_ptr<arrow::UInt8Builder> uint8s;
};

} // namespace

//! One statement, composed and run under the caller's session. The session is judged on every use
//! (spec 040), so an expired one refuses here rather than returning a stale answer.
arrow::Result<unique_ptr<MaterializedQueryResult>> RunCatalogQuery(PolicyStore &store, DatabaseInstance &db,
                                                                   const string &handle, const CatalogQuery &query) {
	auto prefixed = store.SessionSql(handle, query.sql);
	if (prefixed.empty()) {
		return arrow::Status::Invalid("acl: this session is no longer usable - reconnect");
	}
	Connection con(db);
	auto prepared = con.Prepare(prefixed);
	if (prepared->HasError()) {
		return arrow::Status::Invalid("acl: " + prepared->GetError());
	}
	vector<Value> parameters = query.parameters;
	// `allow_stream_result` defaults to *true*, and a streaming result cast to a materialized one is
	// undefined behaviour rather than a wrong answer - it segfaulted the server on the first catalog
	// fetch. A catalog answer is small and is read twice on the include_schema path (the rows, then
	// the per-table schemas), so materialized is what this wants; it is asked for explicitly, and
	// checked rather than assumed.
	auto result = prepared->Execute(parameters, false);
	if (result->HasError()) {
		return arrow::Status::Invalid("acl: " + result->GetError());
	}
	if (result->GetResultType() != QueryResultType::MATERIALIZED_RESULT) {
		return arrow::Status::Invalid("acl: a catalog answer must be materialized");
	}
	return unique_ptr<MaterializedQueryResult>(static_cast<MaterializedQueryResult *>(result.release()));
}

//! Rows into the protocol's shape, by position: the composed statement produces the schema's columns
//! in the schema's order, and `extra` - the serialized per-table schema of `include_schema` - is
//! appended after them when the shape has one.
arrow::Result<std::shared_ptr<arrow::RecordBatch>>
BatchFrom(const std::shared_ptr<arrow::Schema> &schema, MaterializedQueryResult &result, const vector<string> *extra) {
	auto sql_columns = static_cast<idx_t>(schema->num_fields()) - (extra ? 1 : 0);
	if (result.ColumnCount() != sql_columns) {
		return arrow::Status::Invalid("acl: catalog statement produced " + std::to_string(result.ColumnCount()) +
		                              " columns, the protocol wants " + std::to_string(sql_columns));
	}
	vector<unique_ptr<ColumnBuilder>> builders;
	for (int field = 0; field < schema->num_fields(); field++) {
		builders.push_back(make_uniq<ColumnBuilder>(schema->field(field)->type()));
	}
	idx_t rows = 0;
	for (idx_t row = 0; row < result.RowCount(); row++) {
		for (idx_t column = 0; column < sql_columns; column++) {
			ARROW_RETURN_NOT_OK(builders[column]->Append(result.GetValue(column, row)));
		}
		if (extra) {
			ARROW_RETURN_NOT_OK(builders[sql_columns]->AppendBinary((*extra)[row]));
		}
		rows++;
	}
	std::vector<std::shared_ptr<arrow::Array>> arrays;
	for (auto &builder : builders) {
		ARROW_ASSIGN_OR_RAISE(auto array, builder->Finish());
		arrays.push_back(std::move(array));
	}
	return arrow::RecordBatch::Make(schema, static_cast<int64_t>(rows), std::move(arrays));
}

//! A shape with no rows in it - what `GetPrimaryKeys` answers with, and what any listing degrades to.
arrow::Result<std::shared_ptr<arrow::RecordBatch>> EmptyBatch(const std::shared_ptr<arrow::Schema> &schema) {
	std::vector<std::shared_ptr<arrow::Array>> arrays;
	for (int field = 0; field < schema->num_fields(); field++) {
		ColumnBuilder builder(schema->field(field)->type());
		ARROW_ASSIGN_OR_RAISE(auto array, builder.Finish());
		arrays.push_back(std::move(array));
	}
	return arrow::RecordBatch::Make(schema, 0, std::move(arrays));
}

//! The serialized Arrow schema of each table in `tables`, in its order.
//!
//! Built from the columns listing rather than by preparing `SELECT * FROM <name> LIMIT 0` per table:
//! that would be N+1, it would bind each view's SQL against its physical sources at the moment a
//! client opens its sidebar, and it could never describe a table function at all. The `data_type`
//! strings are parsed by duckdb's own `TransformStringToLogicalType` - the inverse of the
//! `ToString()` that produced them - so no type mapping is re-implemented here.
arrow::Result<vector<string>> SchemasFor(ClientContext &context, MaterializedQueryResult &tables,
                                         MaterializedQueryResult &columns) {
	// (catalog, schema, name) -> the row range in `columns`, which the statement returned in order
	std::map<std::tuple<string, string, string>, vector<idx_t>> by_object;
	for (idx_t row = 0; row < columns.RowCount(); row++) {
		auto key = std::make_tuple(columns.GetValue(0, row).ToString(), columns.GetValue(1, row).ToString(),
		                           columns.GetValue(2, row).ToString());
		by_object[key].push_back(row);
	}

	// Two passes, and the split is deliberate. Parsing a type name resolves it against the catalog -
	// a user-defined type is a catalog entry - so it needs a transaction, and one transaction covers
	// every table: the schemas a client is handed then describe one consistent view rather than a
	// per-table sample. The Arrow half runs *outside* it, where a failure can be returned as a Status.
	// An earlier cut did both inside and reached for ValueOrDie(), which on failure aborts the whole
	// process - one client's sidebar taking the instance down. Nothing here is worth that.
	struct ParsedTableSchema {
		vector<string> names;
		vector<LogicalType> types;
		vector<bool> non_nullable;
	};
	vector<ParsedTableSchema> parsed;
	context.RunFunctionInTransaction([&]() {
		for (idx_t row = 0; row < tables.RowCount(); row++) {
			auto key = std::make_tuple(tables.GetValue(0, row).ToString(), tables.GetValue(1, row).ToString(),
			                           tables.GetValue(2, row).ToString());
			vector<string> names;
			vector<LogicalType> types;
			vector<bool> non_nullable;
			// A table with no rows in the columns listing gets an empty schema, and that is the honest
			// answer rather than a gap to paper over: it is exactly what information_schema.columns
			// says about it, so the two Flight answers agree with each other and with SQL. The case
			// itself - an object a role can list but not read - is a listing-level matter, tracked as
			// such (spec 038's follow-up), and fixing it there fixes it here.
			auto found = by_object.find(key);
			if (found != by_object.end()) {
				for (auto column_row : found->second) {
					names.push_back(columns.GetValue(3, column_row).ToString());
					types.push_back(TransformStringToLogicalType(columns.GetValue(4, column_row).ToString(), context));
					auto nullable = columns.GetValue(5, column_row);
					non_nullable.push_back(!nullable.IsNull() && nullable.ToString() == "NO");
				}
			}
			parsed.push_back(ParsedTableSchema {std::move(names), std::move(types), std::move(non_nullable)});
		}
	});

	vector<string> serialized;
	auto properties = context.GetClientProperties();
	for (auto &entry : parsed) {
		ArrowSchema exported;
		ArrowConverter::ToArrowSchema(&exported, entry.types, entry.names, properties);
		ARROW_ASSIGN_OR_RAISE(auto schema, arrow::ImportSchema(&exported));
		// duckdb's converter marks every field nullable (it has nowhere to learn otherwise);
		// a declared NOT NULL is the door's to carry into the promise (spec 048)
		for (idx_t field = 0; field < entry.non_nullable.size(); field++) {
			if (entry.non_nullable[field]) {
				ARROW_ASSIGN_OR_RAISE(schema,
				                      schema->SetField(NumericCast<int>(field),
				                                       schema->field(NumericCast<int>(field))->WithNullable(false)));
			}
		}
		ARROW_ASSIGN_OR_RAISE(auto buffer, arrow::ipc::SerializeSchema(*schema));
		serialized.push_back(buffer->ToString());
	}
	return serialized;
}

namespace {

//! The two adapters `arrow_scan` wants around a C stream. Produce moves the stream into duckdb's
//! wrapper - called once per scan, and the source is spent after it; GetSchema hands out the fresh
//! copy the C ABI contract already makes ours to own.
unique_ptr<ArrowArrayStreamWrapper> ParamStreamProduce(uintptr_t stream_ptr, ArrowStreamParameters &) {
	auto stream = reinterpret_cast<ArrowArrayStream *>(stream_ptr);
	auto wrapper = make_uniq<ArrowArrayStreamWrapper>();
	wrapper->arrow_array_stream = *stream;
	stream->release = nullptr;
	return wrapper;
}

void ParamStreamGetSchema(ArrowArrayStream *stream, ArrowSchema &schema) {
	stream->get_schema(stream, &schema);
}

} // namespace

arrow::Result<vector<vector<Value>>> ParamRowsFrom(DatabaseInstance &db, flight::FlightMessageReader &reader,
                                                   idx_t max_rows) {
	// Collect the client's batches - refusing *while reading*, not after they sit in RAM: a bound
	// enforced post-materialization is no bound at all against a multi-gigabyte "parameter" stream.
	std::vector<std::shared_ptr<arrow::RecordBatch>> batches;
	int64_t total_rows = 0;
	while (true) {
		ARROW_ASSIGN_OR_RAISE(auto chunk, reader.Next());
		if (!chunk.data) {
			break;
		}
		total_rows += chunk.data->num_rows();
		if (total_rows > static_cast<int64_t>(max_rows)) {
			return arrow::Status::Invalid("acl: too many parameter rows bound - batch data belongs to ingest");
		}
		batches.push_back(std::move(chunk.data));
	}
	ARROW_ASSIGN_OR_RAISE(auto schema, reader.GetSchema());
	ARROW_ASSIGN_OR_RAISE(auto table, arrow::Table::FromRecordBatches(schema, std::move(batches)));
	auto batch_reader = std::make_shared<arrow::TableBatchReader>(*table);
	ArrowArrayStream stream;
	ARROW_RETURN_NOT_OK(arrow::ExportRecordBatchReader(batch_reader, &stream));

	vector<vector<Value>> rows;
	try {
		Connection con(db);
		auto result =
		    con.TableFunction("arrow_scan", {Value::POINTER(reinterpret_cast<uintptr_t>(&stream)),
		                                     Value::POINTER(reinterpret_cast<uintptr_t>(ParamStreamProduce)),
		                                     Value::POINTER(reinterpret_cast<uintptr_t>(ParamStreamGetSchema))})
		        ->Execute();
		if (result->HasError()) {
			if (stream.release) {
				stream.release(&stream);
			}
			return arrow::Status::Invalid("acl: reading bound parameters: " + result->GetError());
		}
		while (true) {
			auto chunk = result->Fetch();
			if (!chunk || chunk->size() == 0) {
				break;
			}
			for (idx_t row = 0; row < chunk->size(); row++) {
				vector<Value> values;
				for (idx_t col = 0; col < chunk->ColumnCount(); col++) {
					values.push_back(chunk->GetValue(col, row));
				}
				rows.push_back(std::move(values));
			}
		}
	} catch (std::exception &ex) {
		if (stream.release) {
			stream.release(&stream);
		}
		return arrow::Status::Invalid("acl: reading bound parameters: " + ErrorData(ex).Message());
	}
	if (stream.release) {
		stream.release(&stream);
	}
	return rows;
}

CatalogFilter FilterFrom(const flightsql::GetTables &command) {
	CatalogFilter filter;
	if (command.catalog.has_value()) {
		filter.has_catalog = true;
		filter.catalog = *command.catalog;
	}
	if (command.db_schema_filter_pattern.has_value()) {
		filter.has_db_schema_pattern = true;
		filter.db_schema_pattern = *command.db_schema_filter_pattern;
	}
	if (command.table_name_filter_pattern.has_value()) {
		filter.has_table_pattern = true;
		filter.table_pattern = *command.table_name_filter_pattern;
	}
	for (auto &type : command.table_types) {
		filter.table_types.push_back(type);
	}
	return filter;
}

CatalogFilter FilterFrom(const flightsql::GetDbSchemas &command) {
	CatalogFilter filter;
	if (command.catalog.has_value()) {
		filter.has_catalog = true;
		filter.catalog = *command.catalog;
	}
	if (command.db_schema_filter_pattern.has_value()) {
		filter.has_db_schema_pattern = true;
		filter.db_schema_pattern = *command.db_schema_filter_pattern;
	}
	return filter;
}

CatalogTableRef TableRefFrom(const flightsql::TableRef &table) {
	CatalogTableRef ref;
	if (table.catalog.has_value()) {
		ref.has_catalog = true;
		ref.catalog = *table.catalog;
	}
	if (table.db_schema.has_value()) {
		ref.schema = *table.db_schema;
	}
	ref.table = table.table;
	return ref;
}

} // namespace acl
} // namespace duckdb
