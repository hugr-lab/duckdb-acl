//===----------------------------------------------------------------------===//
// acl_lineage_walker.hpp - spec 107: the edges of a bound logical plan
//
// The walker goes bottom-up over a bound plan (before the optimizer, as the pre-optimize hook and the
// lineage worker's shadow bind see it) and maps every ColumnBinding to the source fields it was made
// from, with OpenLineage's transformation:
//   - a column reference: DIRECT/IDENTITY; an expression: DIRECT/TRANSFORMATION; an aggregate:
//     DIRECT/AGGREGATION;
//   - join / filter / group / sort keys: INDIRECT edges to the whole target; a window's partition
//     and order keys: INDIRECT/WINDOW on the field it computes; a CASE condition:
//     INDIRECT/CONDITIONAL on the field it decides.
// struct_extract / struct_extract_at with a constant key, and list_transform(l, x -> x.f), extend
// a field path (spec 102's spelling: `address.city`, `items[].price`).
//
// What a LogicalGet IS - a physical table, a virtual object behind a shadow, a function - is the
// caller's to say (LineageWalkOptions::classify): the walker only knows bindings. It never reads a
// value: constants are dropped, never copied into an edge.
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb/common/common.hpp"
#include "duckdb/common/types.hpp"

#include <functional>

namespace duckdb {

class LogicalOperator;
class LogicalGet;

namespace acl {

//! A dataset the walk found, as the caller classified it.
struct LineageDatasetKey {
	string kind;    // physical / virtual / function / file
	string catalog; // physical: the attached database; virtual: the virtual catalog
	string schema;
	string name;
	bool operator==(const LineageDatasetKey &other) const {
		return kind == other.kind && catalog == other.catalog && schema == other.schema && name == other.name;
	}
};

//! One source of a target field (or of the whole target).
struct LineageContribution {
	idx_t dataset = DConstants::INVALID_INDEX; // into LineageWalk::datasets
	string field;                              // a field path; empty = the source taken whole
	string type;                               // DIRECT / INDIRECT
	string subtype;                            // IDENTITY / TRANSFORMATION / AGGREGATION / JOIN / ...
	bool masking = false;
	bool operator==(const LineageContribution &other) const {
		return dataset == other.dataset && field == other.field && type == other.type && subtype == other.subtype &&
		       masking == other.masking;
	}
};

//! A target field and what it is made of.
struct LineageOutput {
	string name;
	//! spec 112 §7: the field's type as the walked plan has it (INVALID = unknown)
	LogicalType type = LogicalType::INVALID;
	vector<LineageContribution> sources;
};

struct LineageWalk {
	vector<LineageDatasetKey> datasets;
	//! The fields of the walked root (a query's result), or of the DML / CTAS target.
	vector<LineageOutput> outputs;
	//! INDIRECT edges to the whole target: filter / join / group / sort keys.
	vector<LineageContribution> whole_target;
	//! The DML or CTAS target, when the root writes; `has_target` false for a query.
	bool has_target = false;
	LineageDatasetKey target;
	string target_operation;  // INSERT / UPDATE / DELETE / MERGE / CREATE_TABLE_AS
	bool approximate = false; // an operator or expression the walker could not follow exactly
	bool truncated = false;   // the edge cap was reached
	idx_t EdgeCount() const;
	idx_t DatasetIndex(const LineageDatasetKey &key);
};

struct LineageWalkOptions {
	//! Says what a LogicalGet reads; false = unknown (the walk marks itself approximate and treats it as
	//! a function dataset named after the function).
	std::function<bool(LogicalGet &get, LineageDatasetKey &out)> classify;
	//! The names of the root's result columns, when the caller knows them (a bound statement's names);
	//! otherwise the walker names them from the expressions' aliases or `col<i>`.
	vector<string> output_names;
	idx_t max_edges = 4096;
};

//! Walk a bound plan; never throws for an operator it does not know (it marks the walk approximate).
LineageWalk WalkLineage(LogicalOperator &root, const LineageWalkOptions &options);

} // namespace acl
} // namespace duckdb
