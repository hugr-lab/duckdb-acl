// Foreign syntax under the ACL prefix (spec 067): duckdb's PEG parser hands a statement it cannot
// parse to parse_function extensions (the token peeler), and what such an extension claims becomes
// an opaque ExtensionStatement, planned by the extension itself. This binary registers a toy peeler
// (modeled on duckdb's own loadable_extension_demo) and pins the three-way contract:
//
//   bare            -> the peeler works on an instance with acl loaded (the override declines,
//                      the peel loop proceeds) - loading acl must not cost anyone foreign syntax;
//   under a prefix  -> REFUSED, fail-closed: an ExtensionStatement is planned by its extension, so
//                      the rewriter can neither enumerate nor rewrite what it reads - the statement
//                      gate's default-deny is the only honest answer (design/005);
//   under ACL NATIVE-> works: passthrough runs outside the virtual catalog by definition, so a
//                      foreign extension's syntax is no more privileged there than the SQL it
//                      already allows (design/005 path 1).
//
// A grammar-extension API (rules + transforms producing ordinary AST) is not landed upstream yet;
// when it lands, statements built from extended grammar arrive as AST the rewriter walks node by
// node - ordinary nodes rewritten, unknown ones denied - and this file gains the parallel case.

#include "acl_test_util.hpp"

#include "duckdb/common/string_util.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/parser/parser_extension.hpp"

using namespace duckdb;
using namespace acl_test;

namespace {

//! The toy: `honk honk honk` is three identifiers in a row - a PEG syntax hole - and the peeler
//! claims the run, planning a table function that answers one row per honk.
class HonkFunction : public TableFunction {
public:
	HonkFunction() {
		name = "honk";
		arguments.push_back(LogicalType::BIGINT);
		bind = HonkBind;
		init_global = HonkInit;
		function = HonkFunc;
	}

	struct HonkBindData : public TableFunctionData {
		explicit HonkBindData(idx_t honks) : honks(honks) {
		}
		idx_t honks;
	};

	struct HonkGlobalData : public GlobalTableFunctionState {
		idx_t offset = 0;
	};

	static duckdb::unique_ptr<FunctionData> HonkBind(ClientContext &context, TableFunctionBindInput &input,
	                                                 vector<LogicalType> &return_types, vector<Identifier> &names) {
		names.emplace_back("honk");
		return_types.emplace_back(LogicalType::VARCHAR);
		return make_uniq<HonkBindData>(NumericCast<idx_t>(BigIntValue::Get(input.inputs[0])));
	}

	static duckdb::unique_ptr<GlobalTableFunctionState> HonkInit(ClientContext &context,
	                                                             TableFunctionInitInput &input) {
		return make_uniq<HonkGlobalData>();
	}

	static void HonkFunc(ClientContext &context, TableFunctionInput &data_p, DataChunk &output) {
		auto &bind_data = data_p.bind_data->Cast<HonkBindData>();
		auto &data = data_p.global_state->Cast<HonkGlobalData>();
		idx_t count = 0;
		auto &honk_col = output.data[0];
		while (data.offset < bind_data.honks && count < STANDARD_VECTOR_SIZE) {
			honk_col.Append(Value("honk!"));
			data.offset++;
			count++;
		}
		output.SetChildCardinality(count);
	}
};

struct HonkParseData : public ParserExtensionParseData {
	explicit HonkParseData(idx_t honks) : honks(honks) {
	}
	idx_t honks;

	duckdb::unique_ptr<ParserExtensionParseData> Copy() const override {
		return make_uniq<HonkParseData>(honks);
	}
	string ToString() const override {
		return "HONK x" + std::to_string(honks);
	}
};

class HonkExtension : public ParserExtension {
public:
	HonkExtension() {
		parse_function = HonkParse;
		plan_function = HonkPlan;
	}

	static ParserExtensionParseResult HonkParse(ParserExtensionInfo *info, const vector<SimpleToken> &tokens) {
		idx_t honks = 0;
		while (honks < tokens.size() && StringUtil::CIEquals(tokens[honks].text, "honk")) {
			honks++;
		}
		if (honks == 0) {
			return ParserExtensionParseResult(); // not our input
		}
		// a proper TopLevelStatement ends at ';' or end-of-input; anything else is not ours
		const auto next_type = tokens[honks].type;
		if (next_type != TokenType::TERMINATOR && next_type != TokenType::END_OF_INPUT &&
		    next_type != TokenType::END_OF_INPUT_AUTOCOMPLETE) {
			return ParserExtensionParseResult();
		}
		auto result = ParserExtensionParseResult(make_uniq<HonkParseData>(honks));
		result.consumed_tokens = NumericCast<int64_t>(honks + 1); // the terminator too
		return result;
	}

	static ParserExtensionPlanResult HonkPlan(ParserExtensionInfo *info, ClientContext &context,
	                                          duckdb::unique_ptr<ParserExtensionParseData> parse_data) {
		auto &honk_data = parse_data->Cast<HonkParseData>();
		ParserExtensionPlanResult result;
		result.function = HonkFunction();
		result.parameters.push_back(Value::BIGINT(NumericCast<int64_t>(honk_data.honks)));
		result.requires_valid_transaction = false;
		result.return_type = StatementReturnType::QUERY_RESULT;
		return result;
	}
};

void Run() {
	DBConfig config;
	// the toy is registered the way any co-loaded extension would register itself
	ParserExtension::Register(config, HonkExtension());
	DuckDB db(nullptr, &config);
	Connection con(db);
	// statically linked: the generated extension loader publishes 'acl' on the config
	Exec(con, "LOAD acl");

	Exec(con, "ATTACH ':memory:' AS phys");
	Exec(con, "CREATE TABLE phys.main.orders_physical(id INT, tenant VARCHAR)");
	Exec(con, "SELECT acl_grant_table('analyst','orders','phys.main.orders_physical','id','','select')");
	Exec(con, "SELECT acl_define_token('tok','analyst','tenant=acme')");

	Scenario("foreign syntax parses bare: loading acl costs nobody the peeler", [&] {
		auto rows = con.Query("honk honk honk");
		if (CheckOk(*rows, "the toy statement answers")) {
			Check(rows->RowCount() == 3 && rows->GetValue(0, 0).ToString() == "honk!",
			      "...one row per honk: " + std::to_string(rows->RowCount()));
		}
	});

	Scenario("a peeled statement in a batch: the peel resumes after the claimed tokens", [&] {
		auto rows = con.Query("honk honk; SELECT 42");
		Check(!rows->HasError(), "the mixed batch parses: " + (rows->HasError() ? rows->GetError() : ""));
	});

	Scenario("under the prefix it is refused, fail-closed", [&] {
		auto refused = con.Query("ACL TOKEN 'tok' honk honk honk");
		Check(refused->HasError() && refused->GetError().find("not permitted under ACL") != string::npos,
		      "an ExtensionStatement is planned by its extension, so the rewriter cannot see what it "
		      "reads - denied: " +
		          (refused->HasError() ? refused->GetError() : "it passed"));
	});

	Scenario("ACL NATIVE without passthrough stays refused - foreign syntax changes nothing", [&] {
		auto refused = con.Query("ACL TOKEN 'tok' ACL NATIVE honk honk honk");
		// the refusal fires even earlier than the passthrough gate: leaving the virtual catalog at
		// all is a granted capability (spec 009), and this principal holds none
		Check(refused->HasError() && refused->GetError().find("administration scope") != string::npos,
		      "NATIVE is gated on the scope, not on the syntax: " +
		          (refused->HasError() ? refused->GetError() : "it passed"));
	});

	Scenario("under ACL NATIVE with passthrough it works - design/005 path 1", [&] {
		Exec(con, "SELECT acl_grant_admin('analyst','passthrough')");
		auto rows = con.Query("ACL TOKEN 'tok' ACL NATIVE honk honk honk");
		if (CheckOk(*rows, "the toy statement answers through NATIVE")) {
			Check(rows->RowCount() == 3, "...all three honks: " + std::to_string(rows->RowCount()));
		}
		// and the virtual context still refuses the same principal - NATIVE is the only door
		auto still = con.Query("ACL TOKEN 'tok' honk honk honk");
		Check(still->HasError(), "the virtual context still refuses it for the same principal");
	});
}

} // namespace

int main() {
	return RunMain("foreign parser syntax under the ACL prefix (spec 067)", Run);
}
