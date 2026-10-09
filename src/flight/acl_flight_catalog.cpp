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

#include "acl_result_rows.hpp"
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
#include <arrow/array/builder_nested.h>
#include <arrow/array/builder_primitive.h>
#include <arrow/c/bridge.h>
#include <arrow/flight/sql/column_metadata.h>
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
arrow::Result<unique_ptr<QueryResult>> RunCatalogQuery(PolicyStore &store, Connection &con, const string &handle,
                                                       const CatalogQuery &query) {
	auto prefixed = store.SessionSql(handle, query.sql);
	if (prefixed.empty()) {
		return arrow::Status::Invalid("acl: this session is no longer usable - reconnect");
	}
	auto prepared = con.Prepare(prefixed);
	if (prepared->HasError()) {
		return arrow::Status::Invalid("acl: " + prepared->GetError());
	}
	vector<Value> parameters = query.parameters;
	// Execute runs the statement to completion and retains its rows: a catalog answer is small and is
	// read twice on the include_schema path (the rows, then the per-table schemas)
	auto result = prepared->Execute(parameters);
	if (result->HasError()) {
		return arrow::Status::Invalid("acl: " + result->GetError());
	}
	return result;
}

//! Rows into the protocol's shape, by position: the composed statement produces the schema's columns
//! in the schema's order, and `extra` - the serialized per-table schema of `include_schema` - is
//! appended after them when the shape has one.
arrow::Result<std::shared_ptr<arrow::RecordBatch>> BatchFrom(const std::shared_ptr<arrow::Schema> &schema,
                                                             QueryResult &result, const vector<string> *extra) {
	auto sql_columns = static_cast<idx_t>(schema->num_fields()) - (extra ? 1 : 0);
	if (result.ColumnCount() != sql_columns) {
		return arrow::Status::Invalid("acl: catalog statement produced " + std::to_string(result.ColumnCount()) +
		                              " columns, the protocol wants " + std::to_string(sql_columns));
	}
	ResultRows result_rows(result);
	vector<unique_ptr<ColumnBuilder>> builders;
	for (int field = 0; field < schema->num_fields(); field++) {
		builders.push_back(make_uniq<ColumnBuilder>(schema->field(field)->type()));
	}
	idx_t rows = 0;
	for (idx_t row = 0; row < result.RowCount(); row++) {
		for (idx_t column = 0; column < sql_columns; column++) {
			ARROW_RETURN_NOT_OK(builders[column]->Append(result_rows.GetValue(column, row)));
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
arrow::Result<std::shared_ptr<arrow::RecordBatch>> XdbcTypeInfoBatch(std::optional<int> data_type) {
	// xdbc codes are JDBC's java.sql.Types (Flight SQL's XdbcDataType)
	struct TypeRow {
		const char *name;
		int32_t code;
		int32_t size; // max characters / precision; 0 = none
		const char *prefix;
		const char *suffix;
		const char *params; // create params, comma-separated; "" = none
		bool case_sensitive;
		int32_t searchable; // 0 none, 1 char (LIKE only), 2 basic, 3 full
		bool is_unsigned;
		int32_t radix;
	};
	static const TypeRow ROWS[] = {
	    {"BOOLEAN", -7, 1, nullptr, nullptr, "", false, 2, false, 0},
	    {"TINYINT", -6, 3, nullptr, nullptr, "", false, 2, false, 10},
	    {"SMALLINT", 5, 5, nullptr, nullptr, "", false, 2, false, 10},
	    {"INTEGER", 4, 10, nullptr, nullptr, "", false, 2, false, 10},
	    {"BIGINT", -5, 19, nullptr, nullptr, "", false, 2, false, 10},
	    {"HUGEINT", 2, 39, nullptr, nullptr, "", false, 2, false, 10},
	    {"UTINYINT", -6, 3, nullptr, nullptr, "", false, 2, true, 10},
	    {"USMALLINT", 5, 5, nullptr, nullptr, "", false, 2, true, 10},
	    {"UINTEGER", 4, 10, nullptr, nullptr, "", false, 2, true, 10},
	    {"UBIGINT", -5, 20, nullptr, nullptr, "", false, 2, true, 10},
	    {"UHUGEINT", 2, 39, nullptr, nullptr, "", false, 2, true, 10},
	    {"FLOAT", 7, 24, nullptr, nullptr, "", false, 2, false, 2},
	    {"DOUBLE", 8, 53, nullptr, nullptr, "", false, 2, false, 2},
	    {"DECIMAL", 3, 38, nullptr, nullptr, "precision,scale", false, 2, false, 10},
	    {"VARCHAR", 12, 0, "'", "'", "", true, 3, false, 0},
	    {"BLOB", -3, 0, "'", "'::BLOB", "", false, 2, false, 0},
	    {"DATE", 91, 10, "DATE '", "'", "", false, 2, false, 0},
	    {"TIME", 92, 15, "TIME '", "'", "", false, 2, false, 0},
	    {"TIMESTAMP", 93, 26, "TIMESTAMP '", "'", "", false, 2, false, 0},
	    {"TIMESTAMP WITH TIME ZONE", 2014, 32, "TIMESTAMPTZ '", "'", "", false, 2, false, 0},
	    {"INTERVAL", 1111, 0, "INTERVAL '", "'", "", false, 2, false, 0},
	    {"UUID", 1, 36, "'", "'::UUID", "", false, 2, false, 0},
	    {"JSON", 12, 0, "'", "'::JSON", "", true, 3, false, 0},
	    {"BIT", -7, 0, "'", "'::BIT", "", false, 2, false, 0},
	    {"LIST", 2003, 0, nullptr, nullptr, "element type", false, 0, false, 0},
	    {"ARRAY", 2003, 0, nullptr, nullptr, "element type,size", false, 0, false, 0},
	    {"STRUCT", 2002, 0, nullptr, nullptr, "fields", false, 0, false, 0},
	    {"MAP", 1111, 0, nullptr, nullptr, "key type,value type", false, 0, false, 0},
	    {"UNION", 1111, 0, nullptr, nullptr, "members", false, 0, false, 0},
	};
	auto &schema = arrow::flight::sql::SqlSchema::GetXdbcTypeInfoSchema();
	arrow::StringBuilder type_name, prefix, suffix, local_name;
	arrow::Int32Builder code, size, nullable, searchable, min_scale, max_scale, sql_code, subcode, radix, interval;
	arrow::BooleanBuilder case_sensitive, is_unsigned, fixed, auto_increment;
	auto params_values = std::make_shared<arrow::StringBuilder>();
	arrow::ListBuilder params(arrow::default_memory_pool(), params_values,
	                          arrow::list(arrow::field("item", arrow::utf8(), false)));
	for (auto &row : ROWS) {
		if (data_type && *data_type != row.code) {
			continue;
		}
		ARROW_RETURN_NOT_OK(type_name.Append(row.name));
		ARROW_RETURN_NOT_OK(code.Append(row.code));
		ARROW_RETURN_NOT_OK(row.size ? size.Append(row.size) : size.AppendNull());
		ARROW_RETURN_NOT_OK(row.prefix ? prefix.Append(row.prefix) : prefix.AppendNull());
		ARROW_RETURN_NOT_OK(row.suffix ? suffix.Append(row.suffix) : suffix.AppendNull());
		ARROW_RETURN_NOT_OK(params.Append());
		if (*row.params) { // duckdb's Split("") is {""}: a type with no params has an empty list
			for (auto &param : StringUtil::Split(row.params, ",")) {
				ARROW_RETURN_NOT_OK(params_values->Append(param));
			}
		}
		ARROW_RETURN_NOT_OK(nullable.Append(1)); // columnNullable
		ARROW_RETURN_NOT_OK(case_sensitive.Append(row.case_sensitive));
		ARROW_RETURN_NOT_OK(searchable.Append(row.searchable));
		ARROW_RETURN_NOT_OK(row.radix ? is_unsigned.Append(row.is_unsigned) : is_unsigned.AppendNull());
		ARROW_RETURN_NOT_OK(fixed.Append(string(row.name) == "DECIMAL"));
		ARROW_RETURN_NOT_OK(auto_increment.Append(false));
		ARROW_RETURN_NOT_OK(local_name.Append(row.name));
		ARROW_RETURN_NOT_OK(string(row.name) == "DECIMAL" ? min_scale.Append(0) : min_scale.AppendNull());
		ARROW_RETURN_NOT_OK(string(row.name) == "DECIMAL" ? max_scale.Append(38) : max_scale.AppendNull());
		ARROW_RETURN_NOT_OK(sql_code.Append(row.code));
		ARROW_RETURN_NOT_OK(subcode.AppendNull());
		ARROW_RETURN_NOT_OK(row.radix ? radix.Append(row.radix) : radix.AppendNull());
		ARROW_RETURN_NOT_OK(interval.AppendNull());
	}
	std::vector<std::shared_ptr<arrow::Array>> columns(19);
	ARROW_RETURN_NOT_OK(type_name.Finish(&columns[0]));
	ARROW_RETURN_NOT_OK(code.Finish(&columns[1]));
	ARROW_RETURN_NOT_OK(size.Finish(&columns[2]));
	ARROW_RETURN_NOT_OK(prefix.Finish(&columns[3]));
	ARROW_RETURN_NOT_OK(suffix.Finish(&columns[4]));
	ARROW_RETURN_NOT_OK(params.Finish(&columns[5]));
	ARROW_RETURN_NOT_OK(nullable.Finish(&columns[6]));
	ARROW_RETURN_NOT_OK(case_sensitive.Finish(&columns[7]));
	ARROW_RETURN_NOT_OK(searchable.Finish(&columns[8]));
	ARROW_RETURN_NOT_OK(is_unsigned.Finish(&columns[9]));
	ARROW_RETURN_NOT_OK(fixed.Finish(&columns[10]));
	ARROW_RETURN_NOT_OK(auto_increment.Finish(&columns[11]));
	ARROW_RETURN_NOT_OK(local_name.Finish(&columns[12]));
	ARROW_RETURN_NOT_OK(min_scale.Finish(&columns[13]));
	ARROW_RETURN_NOT_OK(max_scale.Finish(&columns[14]));
	ARROW_RETURN_NOT_OK(sql_code.Finish(&columns[15]));
	ARROW_RETURN_NOT_OK(subcode.Finish(&columns[16]));
	ARROW_RETURN_NOT_OK(radix.Finish(&columns[17]));
	ARROW_RETURN_NOT_OK(interval.Finish(&columns[18]));
	auto rows = columns[0]->length();
	return arrow::RecordBatch::Make(schema, rows, std::move(columns));
}

arrow::Result<std::shared_ptr<arrow::Schema>> WithTypeNames(const std::shared_ptr<arrow::Schema> &schema,
                                                            const vector<LogicalType> &types,
                                                            const vector<string> &type_texts) {
	auto out = schema;
	for (idx_t i = 0; i < types.size() && i < idx_t(out->num_fields()); i++) {
		auto text = i < type_texts.size() && !type_texts[i].empty() ? type_texts[i] : types[i].ToString();
		auto builder = arrow::flight::sql::ColumnMetadata::Builder();
		builder.TypeName(text);
		if (types[i].id() == LogicalTypeId::DECIMAL) {
			builder.Precision(int32_t(DecimalType::GetWidth(types[i])));
			builder.Scale(int32_t(DecimalType::GetScale(types[i])));
		}
		auto field = out->field(NumericCast<int>(i));
		// merged, never replaced: duckdb's converter may already carry an extension type's metadata
		ARROW_ASSIGN_OR_RAISE(
		    out, out->SetField(NumericCast<int>(i), field->WithMergedMetadata(builder.Build().metadata_map())));
	}
	return out;
}

arrow::Result<vector<string>> SchemasFor(ClientContext &context, QueryResult &tables, QueryResult &columns) {
	ResultRows table_rows(tables);
	ResultRows column_rows(columns);
	// (catalog, schema, name) -> the row range in `columns`, which the statement returned in order
	std::map<std::tuple<string, string, string>, vector<idx_t>> by_object;
	for (idx_t row = 0; row < columns.RowCount(); row++) {
		auto key = std::make_tuple(column_rows.GetValue(0, row).ToString(), column_rows.GetValue(1, row).ToString(),
		                           column_rows.GetValue(2, row).ToString());
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
		vector<string> texts; // the listing's own type text (spec 115)
	};
	vector<ParsedTableSchema> parsed;
	context.RunFunctionInTransaction([&]() {
		for (idx_t row = 0; row < tables.RowCount(); row++) {
			auto key = std::make_tuple(table_rows.GetValue(0, row).ToString(), table_rows.GetValue(1, row).ToString(),
			                           table_rows.GetValue(2, row).ToString());
			vector<string> names;
			vector<LogicalType> types;
			vector<bool> non_nullable;
			vector<string> texts;
			// A table with no rows in the columns listing gets an empty schema, and that is the honest
			// answer rather than a gap to paper over: it is exactly what information_schema.columns
			// says about it, so the two Flight answers agree with each other and with SQL. The case
			// itself - an object a role can list but not read - is a listing-level matter, tracked as
			// such (spec 038's follow-up), and fixing it there fixes it here.
			auto found = by_object.find(key);
			if (found != by_object.end()) {
				for (auto column_row : found->second) {
					names.push_back(column_rows.GetValue(3, column_row).ToString());
					texts.push_back(column_rows.GetValue(4, column_row).ToString());
					types.push_back(TransformStringToLogicalType(texts.back(), context));
					auto nullable = column_rows.GetValue(5, column_row);
					non_nullable.push_back(!nullable.IsNull() && nullable.ToString() == "NO");
				}
			}
			parsed.push_back(
			    ParsedTableSchema {std::move(names), std::move(types), std::move(non_nullable), std::move(texts)});
		}
	});

	vector<string> serialized;
	auto properties = context.GetClientProperties();
	for (auto &entry : parsed) {
		ArrowSchema exported;
		ArrowConverter::ToArrowSchema(&exported, entry.types, entry.names, properties);
		ARROW_ASSIGN_OR_RAISE(auto imported, arrow::ImportSchema(&exported));
		ARROW_ASSIGN_OR_RAISE(auto schema, WithTypeNames(imported, entry.types, entry.texts));
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

//! What `arrow_scan` wants around a C stream (duckdb #25726: process-local bind input on the ref).
//! Produce moves the stream into duckdb's wrapper - called once per scan, and the source is spent
//! after it; GetSchema hands out the fresh copy the C ABI contract already makes ours to own.
struct ParamScanFactory : public ArrowScanFactory {
	explicit ParamScanFactory(ArrowArrayStream &stream_p) : stream(stream_p) {
	}
	void GetSchema(ArrowSchema &schema) override {
		stream.get_schema(&stream, &schema);
	}
	unique_ptr<ArrowArrayStreamWrapper> ProduceStream(ArrowStreamParameters &) override {
		auto wrapper = make_uniq<ArrowArrayStreamWrapper>();
		wrapper->arrow_array_stream = stream;
		stream.release = nullptr;
		return wrapper;
	}
	ArrowArrayStream &stream;
};

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
	if (schema->num_fields() == 0) {
		// a statement without parameters, executed through DoPut: Arrow's JDBC sends a batch with no
		// columns (spec 111 announces a prepared DML as an update, so every parameterless one comes
		// this way) - no parameters, and the statement runs once
		return vector<vector<Value>>();
	}
	ARROW_ASSIGN_OR_RAISE(auto table, arrow::Table::FromRecordBatches(schema, batches));
	auto batch_reader = std::make_shared<arrow::TableBatchReader>(*table);
	ArrowArrayStream stream;
	ARROW_RETURN_NOT_OK(arrow::ExportRecordBatchReader(batch_reader, &stream));

	vector<vector<Value>> rows;
	try {
		Connection con(db);
		auto result = con.TableFunction("arrow_scan", vector<Value>(), named_parameter_map_t(),
		                                make_shared_ptr<ParamScanFactory>(stream))
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
