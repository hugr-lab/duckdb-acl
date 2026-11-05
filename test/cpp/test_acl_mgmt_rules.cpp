// spec 150 stage 3g-3: a linked module's management statements are rules (RegisterMgmtRules, acl_mgmt_rules.hpp) -
// read on duckdb's tokens beside acl's own, its values checked against their tokens, a form the rules do not read
// refused in the module's words, the compiled call judged by the one authorizer. A toy module registers here what
// hugr-node registers for CLUSTER. Build + run via `GEN=ninja make test-cpp`.

#include "acl_test_util.hpp"

#include "acl_mgmt_rules.hpp"

using namespace duckdb;
using namespace acl_test;

namespace {

// AclToyStatement <- 'TOYKILL' AclToyTarget AclToyNote?: the toy's statement, compiled to acl_session_kill(id) - the
// id a quoted value, or a word and its note joined (so the reading shows in the compiled call)
arena_ptr<TransformResultValue> FinalizeToy(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	acl::MgmtCall call(transformer, "acl_session_kill");
	auto &target = acl::MgmtCall::Part(list.GetChild(1));
	if (target.Name() == "AclToyWord") {
		auto value = acl::MgmtCall::Word(target.Cast<ListParseResult>().GetChild(1));
		auto &note = list.Child<OptionalParseResult>(2);
		if (note.HasResult()) {
			auto &clause = acl::MgmtCall::Part(note.GetResult()).Cast<ListParseResult>();
			value += "/" + call.NameValue(clause.GetChild(1), "a note");
		}
		call.Arg(Value(value));
	} else {
		call.Arg(Value(call.Quoted(target, "a session id")));
	}
	return call.Result();
}

void RegisterToy() {
	vector<GrammarChange> rules;
	rules.push_back(
	    GrammarChange::AddRule("AclToyStatement <- 'TOYKILL' AclToyTarget AclToyNote?", acl::MgmtStart<FinalizeToy>));
	rules.push_back(GrammarChange::AddRule("AclToyTarget <- AclToyWord / AclQuotedValue"));
	rules.push_back(GrammarChange::AddRule("AclToyWord <- 'WORD' AclWordToken"));
	rules.push_back(GrammarChange::AddRule("AclToyNote <- 'NOTE' AclNameValue"));
	acl::RegisterMgmtRules("toykill", "AclToyStatement", std::move(rules),
	                       "TOYKILL expects '<id>' or WORD <word> [NOTE <name>]");
}

//! The statement the override compiles the text to
std::string Compiled(Connection &con, const std::string &text) {
	try {
		auto statements = con.ExtractStatements(text);
		std::string out;
		for (auto &statement : statements) {
			out += (out.empty() ? "" : "; ") + statement->ToString();
		}
		return out;
	} catch (std::exception &ex) {
		return std::string("error: ") + ErrorData(ex).Message();
	}
}

bool Has(const std::string &text, const std::string &needle) {
	return text.find(needle) != std::string::npos;
}

} // namespace

int main(int argc, char *argv[]) {
	// at load, before the first statement is read: the management grammar is compiled then
	RegisterToy();
	DBConfig config;
	DuckDB db(nullptr, &config);
	Connection con(db);
	// statically linked: the generated extension loader publishes 'acl' on the config
	Exec(con, "LOAD acl");
	Exec(con, "SET GLOBAL acl_allow_anonymous_admin=true");
	Exec(con, "SELECT acl_define_role('nobody', '')");

	Scenario("the module's statement is read by its rules and compiled to its call", [&] {
		auto quoted = Compiled(con, "ACL ADMIN TOYKILL '0000'");
		Check(Has(quoted, "acl_session_kill('0000')"), "a quoted id: " + quoted);
		auto spaced = Compiled(con, "ACL ADMIN toykill /* a comment */ WORD 4GB NOTE \"a.b\"");
		Check(Has(spaced, "acl_session_kill('4GB/a.b')"), "a word and a note, as duckdb's tokens read them: " + spaced);
		auto dotted = Compiled(con, "ACL ADMIN TOYKILL WORD x NOTE a.b");
		Check(Has(dotted, "acl_session_kill('x/a.b')"), "a dotted name judged whole: " + dotted);
		auto ran = con.Query("ACL ADMIN TOYKILL '0000'");
		Check(!ran->HasError() && ran->RowCount() == 1 && !ran->Collection().GetValue(0, 0).GetValue<bool>(),
		      "it runs: no such session - " + (ran->HasError() ? ran->GetError() : std::string("ok")));
		auto batch = Compiled(con, "ACL ADMIN TOYKILL '1'; TOYKILL '2'");
		Check(Has(batch, "acl_session_kill('1')") && Has(batch, "acl_session_kill('2')"),
		      "a batch of the module's statements: " + batch);
	});

	Scenario("its values are checked against their tokens", [&] {
		auto escape = Compiled(con, "ACL ADMIN TOYKILL E'0000'");
		Check(Has(escape, "error:"), "an escape string is no plain literal: " + escape);
		auto joined = Compiled(con, "ACL ADMIN TOYKILL '00'\n'00'");
		Check(Has(joined, "error:"), "a string joined across a line break is no plain literal: " + joined);
	});

	Scenario("a statement its rules do not read is refused in the module's words", [&] {
		auto unread = Compiled(con, "ACL ADMIN TOYKILL 123 456");
		Check(Has(unread, "TOYKILL expects '<id>' or WORD <word> [NOTE <name>]"), "the module's usage: " + unread);
		auto open = Compiled(con, "ACL ADMIN TOYKILL 'never closed");
		Check(Has(open, "unterminated"), "an unterminated string is the tokenizer's: " + open);
	});

	Scenario("the compiled call is judged by the one authorizer", [&] {
		auto refused = con.Query("ACL ROLE \"nobody\" TOYKILL '0000'");
		Check(refused->HasError() && Has(refused->GetError(), "administration scope"),
		      "a role with no scope: " + (refused->HasError() ? refused->GetError() : std::string("it ran")));
		auto mixed = con.Query("ACL ADMIN TOYKILL '0000'; SELECT 1");
		Check(mixed->HasError(), "a batch mixing it with a query is refused: " +
		                             (mixed->HasError() ? mixed->GetError() : std::string("it ran")));
	});

	Scenario("a statement with another head is untouched", [&] {
		auto plain = con.Query("SELECT 'TOYKILL' AS word");
		Check(!plain->HasError() && plain->Collection().GetValue(0, 0).ToString() == "TOYKILL", "a plain SELECT");
	});

	std::cout << (failures == 0 ? "PASS" : "FAIL") << "\n";
	return failures == 0 ? 0 : 1;
}
