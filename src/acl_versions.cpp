#include "acl_versions.hpp"

#include "duckdb/common/string_util.hpp"
#include "duckdb/parser/expression/between_expression.hpp"
#include "duckdb/parser/parsed_expression_iterator.hpp"
#include "duckdb/parser/parser.hpp"
#include "duckdb/parser/query_node/select_node.hpp"
#include "duckdb/parser/statement/select_statement.hpp"
#include "duckdb/parser/tableref/basetableref.hpp"

namespace duckdb {
namespace acl {

namespace {

constexpr const char *VERSIONS_TABLE = "__acl_versions";

const char *const WHAT_TO_WRITE =
    "VERSIONS CURRENT, VERSIONS ANY, VERSIONS AT (VERSION => <n>), VERSIONS AT (TIMESTAMP => "
    "<t>) or VERSIONS BETWEEN <t1> AND <t2> - each value a constant";

[[noreturn]] void Refuse(const string &why) {
	throw BinderException("acl admin: %s - a grant's versions are %s", why, WHAT_TO_WRITE);
}

bool StartsWithWord(const string &text, const char *word) {
	auto length = strlen(word);
	return text.size() > length && StringUtil::CIEquals(text.substr(0, length), word) &&
	       !StringUtil::CharacterIsAlphaNumeric(text[length]) && text[length] != '_';
}

//! The one SELECT node `sql` parses into, nullptr when it is anything else
unique_ptr<SelectNode> ParseSelectNode(const string &sql) {
	Parser parser(ParserOptions::Builtin());
	try {
		parser.ParseQuery(sql);
	} catch (std::exception &) {
		return nullptr;
	}
	if (parser.statements.size() != 1 || parser.statements[0]->type != StatementType::SELECT_STATEMENT) {
		return nullptr;
	}
	auto &select = parser.statements[0]->Cast<SelectStatement>();
	if (!select.node || select.node->type != QueryNodeType::SELECT_NODE) {
		return nullptr;
	}
	auto node = unique_ptr_cast<QueryNode, SelectNode>(std::move(select.node));
	if (node->select_list.size() != 1) {
		return nullptr;
	}
	// nothing but the one item and the FROM: a node rebuilt of only those prints the same (a GROUP BY ALL, a WINDOW,
	// a clause of any kind would not)
	SelectNode bare;
	bare.select_list.push_back(node->select_list[0]->Copy());
	if (node->from_table) {
		bare.from_table = node->from_table->Copy();
	}
	if (bare.ToString() != node->ToString()) {
		return nullptr;
	}
	return node;
}

//! `AT (…)` read as duckdb reads a table's AT clause, nullptr when the text holds anything more
unique_ptr<AtClause> ParseAt(const string &text) {
	auto node = ParseSelectNode(string("SELECT 1 FROM ") + VERSIONS_TABLE + " " + text);
	if (!node || !node->from_table || node->from_table->type != TableReferenceType::BASE_TABLE) {
		return nullptr;
	}
	auto &base = node->from_table->Cast<BaseTableRef>();
	if (!base.alias.empty() || !base.column_name_alias.empty() || base.sample || !base.at_clause ||
	    !base.at_clause->ExpressionMutable()) {
		return nullptr;
	}
	return std::move(base.at_clause);
}

//! `BETWEEN a AND b` read as duckdb reads a BETWEEN's bounds, nullptr when the text holds anything more
unique_ptr<BetweenExpression> ParseBetween(const string &text) {
	auto node = ParseSelectNode("SELECT NULL " + text);
	if (!node || (node->from_table && node->from_table->type != TableReferenceType::EMPTY_FROM)) {
		return nullptr;
	}
	auto &item = node->select_list[0];
	if (item->GetExpressionType() != ExpressionType::COMPARE_BETWEEN || !item->GetAlias().empty()) {
		return nullptr;
	}
	auto between = unique_ptr_cast<ParsedExpression, BetweenExpression>(std::move(item));
	if (between->InputMutable()->GetExpressionClass() != ExpressionClass::CONSTANT) {
		return nullptr;
	}
	return between;
}

string Quoted(const string &value) {
	return Value(value).ToSQLString();
}

string UnitOf(AtClause &at) {
	return StringUtil::Upper(at.Unit().GetIdentifierName());
}

} // namespace

bool ConstantOnly(const ParsedExpression &expr) {
	switch (expr.GetExpressionClass()) {
	case ExpressionClass::CONSTANT:
		return true;
	case ExpressionClass::CAST: {
		bool only = true;
		ParsedExpressionIterator::EnumerateChildren(
		    expr, [&](const ParsedExpression &child) { only = only && ConstantOnly(child); });
		return only;
	}
	default:
		return false;
	}
}

bool HasParameter(const ParsedExpression &expr) {
	if (expr.GetExpressionClass() == ExpressionClass::PARAMETER) {
		return true;
	}
	bool found = false;
	ParsedExpressionIterator::EnumerateChildren(
	    expr, [&](const ParsedExpression &child) { found = found || HasParameter(child); });
	return found;
}

VersionLimit ReadVersions(const string &stored) {
	VersionLimit limit;
	auto text = stored;
	StringUtil::Trim(text);
	if (text.empty() || StringUtil::CIEquals(text, "ANY")) {
		return limit;
	}
	if (StringUtil::CIEquals(text, "CURRENT")) {
		limit.kind = VersionLimit::Kind::CURRENT;
		return limit;
	}
	// what is read is spliced into a principal's statement: only what a writer of ours stores - constants
	if (StartsWithWord(text, "AT")) {
		limit.at = ParseAt(text);
		if (limit.at && ConstantOnly(*limit.at->ExpressionMutable())) {
			limit.kind = VersionLimit::Kind::AT;
			return limit;
		}
	} else if (StartsWithWord(text, "BETWEEN")) {
		auto between = ParseBetween(text);
		if (between && ConstantOnly(*between->LowerBoundMutable()) && ConstantOnly(*between->UpperBoundMutable())) {
			limit.kind = VersionLimit::Kind::BETWEEN;
			limit.lo = std::move(between->LowerBoundMutable());
			limit.hi = std::move(between->UpperBoundMutable());
			return limit;
		}
	}
	// a stored row no build of ours wrote: no version at all, rather than every one
	throw BinderException("acl: a grant's stored versions \"%s\" do not read as a VERSIONS clause", stored);
}

string NormalizeVersions(const string &written, const std::function<string(const string &)> &evaluate) {
	auto text = written;
	StringUtil::Trim(text);
	if (text.empty()) {
		return string();
	}
	if (StringUtil::CIEquals(text, "ANY") || StringUtil::CIEquals(text, "CURRENT")) {
		return StringUtil::Upper(text);
	}
	auto run = [&](ParsedExpression &expr, const string &sql) {
		try {
			return evaluate(sql);
		} catch (std::exception &) {
			Refuse("\"" + expr.ToString() + "\" is no value of that kind");
		}
	};
	// a VERSION is an integer as written (never a rounded 1.9 or a TRUE); a TIMESTAMP a finite instant, stored in UTC
	// - the same instant reads the same whatever time zone wrote it, so two roles' grants of it unite
	auto value = [&](ParsedExpression &expr, bool version) {
		if (!ConstantOnly(expr)) {
			Refuse("\"" + expr.ToString() + "\" is not a constant");
		}
		auto sql = "(" + expr.ToString() + ")";
		string result;
		if (version) {
			auto type = run(expr, "typeof(" + sql + ")");
			if (type != "TINYINT" && type != "SMALLINT" && type != "INTEGER" && type != "BIGINT" &&
			    type != "UTINYINT" && type != "USMALLINT" && type != "UINTEGER" && type != "UBIGINT" &&
			    type != "HUGEINT" && type != "UHUGEINT" && type != "\"NULL\"") {
				Refuse("\"" + expr.ToString() + "\" is no version number - a VERSION is an integer");
			}
			result = run(expr, "CAST(" + sql + " AS BIGINT)");
		} else {
			auto instant = "CAST(" + sql + " AS TIMESTAMPTZ)";
			if (run(expr, "coalesce(isfinite(" + instant + "), true)") != "true") {
				Refuse("\"" + expr.ToString() + "\" is no instant - a TIMESTAMP is finite");
			}
			// the instant's microseconds since the epoch, printed as UTC wall time (a TIMESTAMP without an offset
			// is the node's zone, UTC without ICU)
			result = run(expr, "strftime(make_timestamp(epoch_us(" + instant + ")), '%Y-%m-%d %H:%M:%S.%f') || '+00'");
		}
		if (result.empty()) {
			Refuse("\"" + expr.ToString() + "\" is NULL");
		}
		return result;
	};
	if (StartsWithWord(text, "AT")) {
		auto at = ParseAt(text);
		if (!at) {
			Refuse("\"" + written + "\" does not read as AT (<unit> => <value>)");
		}
		auto unit = UnitOf(*at);
		if (unit == "VERSION") {
			return "AT (VERSION => " + value(*at->ExpressionMutable(), true) + ")";
		}
		if (unit == "TIMESTAMP") {
			return "AT (TIMESTAMP => TIMESTAMPTZ " + Quoted(value(*at->ExpressionMutable(), false)) + ")";
		}
		Refuse("AT names a VERSION or a TIMESTAMP, not " + unit);
	}
	if (StartsWithWord(text, "BETWEEN")) {
		auto between = ParseBetween(text);
		if (!between) {
			Refuse("\"" + written + "\" does not read as BETWEEN <t1> AND <t2>");
		}
		auto lo = value(*between->LowerBoundMutable(), false);
		auto hi = value(*between->UpperBoundMutable(), false);
		auto lo_sql = "TIMESTAMPTZ " + Quoted(lo);
		auto hi_sql = "TIMESTAMPTZ " + Quoted(hi);
		if (evaluate(lo_sql + " <= " + hi_sql) != "true") {
			Refuse("the window BETWEEN " + lo + " AND " + hi + " is empty - its start is after its end");
		}
		return "BETWEEN " + lo_sql + " AND " + hi_sql;
	}
	Refuse("\"" + written + "\" is no VERSIONS clause");
}

string UniteVersions(const vector<string> &stored, bool &differ) {
	differ = false;
	string united;
	bool first = true;
	for (auto &one : stored) {
		auto text = one;
		StringUtil::Trim(text);
		if (text.empty() || StringUtil::CIEquals(text, "ANY")) {
			return string(); // one role reads every version: the union does
		}
		if (first) {
			united = text;
			first = false;
		} else if (united != text) {
			differ = true;
		}
	}
	return differ ? string() : united;
}

} // namespace acl
} // namespace duckdb
