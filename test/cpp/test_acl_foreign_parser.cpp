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
// Spec 132: duckdb's grammar extensions (rules + transforms, opted into per connection by
// active_grammar_extensions) are the fourth row. Our inner parse uses the connection's grammar, so a
// statement an extension builds from ordinary AST is walked under the prefix like any other - virtual
// names resolved, the grant's RLS applied, a hidden name refused - while one that yields an
// ExtensionStatement is denied as a peeler's is. The grammar is the connection owner's to choose: a
// principal's SET of active_grammar_extensions is refused under every prefix.

#include "acl_test_util.hpp"

#include "duckdb/common/string_util.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/parser/expression/star_expression.hpp"
#include "duckdb/parser/grammar_extension.hpp"
#include "duckdb/parser/parser_extension.hpp"
#include "duckdb/parser/peg/parsed_grammar.hpp"
#include "duckdb/parser/peg/transformer/peg_transformer.hpp"
#include "duckdb/parser/query_node/select_node.hpp"
#include "duckdb/parser/statement/extension_statement.hpp"
#include "duckdb/parser/statement/select_statement.hpp"

using namespace duckdb;
using namespace acl_test;

namespace {

//! The toy: `honk honk honk` is three identifiers in a row - a PEG syntax hole - and the peeler
//! claims the run, planning a table function that answers one row per honk.
class HonkFunction : public TableFunction {
public:
	HonkFunction() {
		name = "honk";
		GetSignature().AddParameter("honks", LogicalType::BIGINT);
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

//! Spec 132, ordinary AST: `FROM t |> WHERE p` is `SELECT * FROM t WHERE p` - the first stage of duckdb's pipe
//! syntax demo, built from the core transforms of FromClause and WhereClause
arena_ptr<TransformResultValue> FinalizePipeWhere(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	auto select_node = make_uniq<SelectNode>();
	select_node->select_list.push_back(make_uniq<StarExpression>());
	select_node->from_table = transformer.Transform<duckdb::unique_ptr<TableRef>>(list.GetChild(0));
	select_node->where_clause = transformer.Transform<duckdb::unique_ptr<ParsedExpression>>(list.GetChild(2));
	auto statement = make_uniq<SelectStatement>();
	statement->node = std::move(select_node);
	return transformer.MakeResult<duckdb::unique_ptr<SelectStatement>>(std::move(statement));
}

arena_ptr<TransformProcess> StartPipeWhere(PEGTransformer &transformer, ParseResult &parse_result) {
	return transformer.MakeProcess<FinalizeTransformProcess>(transformer, parse_result, FinalizePipeWhere);
}

class PipeWhereGrammar final : public GrammarExtension {
public:
	PipeWhereGrammar() : GrammarExtension("acl_test_pipe_where", "FROM t |> WHERE p (spec 132's test)") {
	}
	vector<GrammarChange> GetChanges() const override {
		return {GrammarChange::AddRule("PipeWhereAtom <- FromClause '|>' WhereClause", StartPipeWhere),
		        GrammarChange::PrependChoice("SelectAtom", "PipeWhereAtom")};
	}
};

//! Spec 132, opaque: the statement `HONKING` is the toy peeler's ExtensionStatement, reached through the grammar
arena_ptr<TransformResultValue> FinalizeHonking(PEGTransformer &transformer, ParseResult &) {
	duckdb::unique_ptr<SQLStatement> statement =
	    make_uniq<ExtensionStatement>(HonkExtension(), make_uniq<HonkParseData>(1));
	return transformer.MakeResult<duckdb::unique_ptr<SQLStatement>>(std::move(statement));
}

arena_ptr<TransformProcess> StartHonking(PEGTransformer &transformer, ParseResult &parse_result) {
	return transformer.MakeProcess<FinalizeTransformProcess>(transformer, parse_result, FinalizeHonking);
}

class HonkingGrammar final : public GrammarExtension {
public:
	HonkingGrammar() : GrammarExtension("acl_test_honking", "HONKING as an ExtensionStatement (spec 132's test)") {
	}
	vector<GrammarChange> GetChanges() const override {
		return {GrammarChange::AddRule("HonkingStatement <- 'HONKING'", StartHonking),
		        GrammarChange::AddChoice("Statement", "HonkingStatement")};
	}
};

std::string OpenSession(Connection &con) {
	auto result = con.Query("SELECT acl_session_open('tok')");
	if (result->HasError() || result->RowCount() == 0) {
		return std::string();
	}
	auto value = result->Collection().GetValue(0, 0);
	return value.IsNull() ? std::string() : value.ToString();
}

bool Refused(QueryResult &result, const std::string &needle, const std::string &what) {
	return Check(result.HasError() && result.GetError().find(needle) != string::npos,
	             what + ": " + (result.HasError() ? result.GetError() : "it passed"));
}

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
			Check(rows->RowCount() == 3 && rows->Collection().GetValue(0, 0).ToString() == "honk!",
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

	// spec 132: the grammar extensions, registered as a co-loaded extension's Load would, and opted into by this
	// connection - its owner's choice
	GrammarExtension::Register(*db.instance, make_shared_ptr<PipeWhereGrammar>());
	GrammarExtension::Register(*db.instance, make_shared_ptr<HonkingGrammar>());
	Exec(con, "INSERT INTO phys.main.orders_physical VALUES (1, 'acme'), (2, 'globex'), (3, 'acme')");
	Exec(con, "SELECT acl_grant_table('analyst','orders_rls','phys.main.orders_physical','id, tenant',"
	          "'tenant = acl_claim(''tenant'')','select')");
	Exec(con, "SET active_grammar_extensions = ['acl_test_pipe_where', 'acl_test_honking']");

	Scenario("spec 132: the extended grammar parses bare", [&] {
		auto rows = con.Query("FROM phys.main.orders_physical |> WHERE id > 1");
		if (CheckOk(*rows, "the pipe statement answers")) {
			Check(rows->RowCount() == 2, "...two rows past id 1: " + std::to_string(rows->RowCount()));
		}
		auto honks = con.Query("HONKING");
		if (CheckOk(*honks, "the grammar's ExtensionStatement answers bare")) {
			Check(honks->RowCount() == 1, "...one honk: " + std::to_string(honks->RowCount()));
		}
	});

	Scenario("spec 132: under the prefix the extended grammar's AST is walked like any SELECT", [&] {
		auto rows = con.Query("ACL TOKEN 'tok' FROM orders_rls |> WHERE id > 1");
		if (CheckOk(*rows, "the pipe statement answers under the prefix")) {
			// globex's row 2 is outside the slice: the grant's RLS applied to what the grammar built
			Check(rows->RowCount() == 1 && rows->Collection().GetValue(0, 0).ToString() == "3",
			      "...only acme's row past id 1: " + std::to_string(rows->RowCount()));
		}
		auto projected = con.Query("ACL TOKEN 'tok' FROM orders |> WHERE id > 0");
		if (CheckOk(*projected, "the virtual name resolves in the grammar's FROM")) {
			Check(projected->ColumnCount() == 1,
			      "...and the grant's projection holds: " + std::to_string(projected->ColumnCount()) + " columns");
		}
		auto hidden_column = con.Query("ACL TOKEN 'tok' FROM orders |> WHERE tenant = 'acme'");
		Refused(*hidden_column, "\"tenant\"", "a column the grant hides is not there for the grammar's WHERE either");
		auto physical = con.Query("ACL TOKEN 'tok' FROM phys.main.orders_physical |> WHERE id > 0");
		Refused(*physical, "phys", "a physical name stays unreachable through the grammar");
	});

	Scenario("spec 132: a grammar that yields an ExtensionStatement is denied like a peeler", [&] {
		auto refused = con.Query("ACL TOKEN 'tok' HONKING");
		Refused(*refused, "not permitted under ACL", "an opaque statement from the grammar");
	});

	Scenario("spec 132: the grammar is the connection owner's - a principal cannot change it", [&] {
		auto by_token = con.Query("ACL TOKEN 'tok' SET active_grammar_extensions = []");
		Refused(*by_token, "SET \"active_grammar_extensions\" is not permitted under ACL", "SET under ACL TOKEN");
		auto by_role = con.Query("ACL ROLE \"analyst\" SET active_grammar_extensions = []");
		Refused(*by_role, "SET \"active_grammar_extensions\" is not permitted under ACL", "SET under ACL ROLE");
		// a dialect (DialectExtension) is chosen the same way, per connection - refused alike (spec 067's concern)
		auto dialect = con.Query("ACL TOKEN 'tok' SET current_dialect = 'duckdb'");
		Refused(*dialect, "SET \"current_dialect\" is not permitted under ACL", "SET current_dialect under ACL TOKEN");
		auto handle = OpenSession(con);
		if (Check(!handle.empty(), "a session opens for the token")) {
			// a session of the client's own may set TimeZone (spec 068) - and nothing else
			auto by_session = con.Query("ACL SESSION '" + handle + "' SET active_grammar_extensions = []");
			Refused(*by_session, "SET \"active_grammar_extensions\" is not permitted under ACL",
			        "SET under ACL SESSION");
			auto session_dialect = con.Query("ACL SESSION '" + handle + "' SET current_dialect = 'duckdb'");
			Refused(*session_dialect, "SET \"current_dialect\" is not permitted under ACL",
			        "SET current_dialect under ACL SESSION");
			auto local = con.Query("ACL SESSION '" + handle + "' SET TimeZone = 'UTC'");
			Check(!local->HasError(),
			      "...while the spec 068 allowlist still holds: " + (local->HasError() ? local->GetError() : string()));
			Exec(con, "SELECT acl_session_close('" + handle + "')");
		}
		auto active = con.Query("SELECT current_setting('active_grammar_extensions')::VARCHAR");
		Check(!active->HasError() &&
		          active->Collection().GetValue(0, 0).ToString().find("acl_test_pipe_where") != string::npos,
		      "the connection's grammar is unchanged");
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
		// spec 132: break-glass keeps the connection's grammar - both of its statements run there
		auto piped = con.Query("ACL TOKEN 'tok' ACL NATIVE FROM phys.main.orders_physical |> WHERE id > 1");
		if (CheckOk(*piped, "the pipe statement runs through NATIVE")) {
			Check(piped->RowCount() == 2, "...on the physical table, unconfined: " + std::to_string(piped->RowCount()));
		}
		auto honking = con.Query("ACL TOKEN 'tok' ACL NATIVE HONKING");
		CheckOk(*honking, "the grammar's ExtensionStatement runs through NATIVE");
	});
}

} // namespace

int main() {
	return RunMain("foreign parser syntax under the ACL prefix (spec 067)", Run);
}
