//===----------------------------------------------------------------------===//
// acl_result_rows.hpp
//
// The rows of a materialized QueryResult, built once. Since duckdb's ResultFormat (the 2026-09-30
// pin) a result has no GetValue of its own, and ColumnDataCollection::GetValue builds every row of
// the collection on each call - a loop over rows through it is quadratic. Build a ResultRows once,
// then read cells from it.
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb/common/types/column/column_data_collection.hpp"
#include "duckdb/main/query_result.hpp"

namespace duckdb {
namespace acl {

class ResultRows {
public:
	explicit ResultRows(QueryResult &result) : rows(result.Collection().GetRows()) {
	}

	Value GetValue(idx_t column, idx_t row) const {
		return rows.GetValue(column, row);
	}
	idx_t Count() const {
		return rows.size();
	}

private:
	ColumnDataRowCollection rows;
};

} // namespace acl
} // namespace duckdb
