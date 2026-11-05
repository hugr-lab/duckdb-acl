// spec 150 stage 3g-3: a linked module's management statements are rules (RegisterMgmtRules, acl_mgmt_rules.hpp) -
// read on duckdb's tokens beside acl's own, its values checked against their tokens, a form the rules do not read
// refused in the module's words, the compiled call judged by the one authorizer - and a registration that would
// change acl's own statements, or plain SQL, refused at load. A toy module registers here what hugr-node registers for
// CLUSTER. Build + run via `GEN=ninja make test-cpp`.

#include "acl_test_util.hpp"

#include "acl_admin_scanner.hpp"
#include "acl_admin_sql.hpp"
#include "acl_mgmt_rules.hpp"
#include "duckdb/parser/peg/matcher.hpp"

using namespace duckdb;
using namespace acl_test;

namespace {

using acl::MgmtCall;

//! TOYKILL '<id>' | WORD <word> [NOTE <name>] | NUMBER <n> | VALUE <value> | LIST <name>, … | NAMED <ident> [COMMENT
//! '…']
//! - compiled to acl_session_kill(id), the id what the form read (so the reading shows in the compiled call)
arena_ptr<TransformResultValue> FinalizeToy(PEGTransformer &transformer, ParseResult &parse_result) {
	auto &list = parse_result.Cast<ListParseResult>();
	MgmtCall call(transformer, "acl_session_kill");
	auto &target = MgmtCall::Part(list.GetChild(1));
	string value;
	if (target.Name() == "AclToykillWord") {
		auto &form = target.Cast<ListParseResult>();
		value = MgmtCall::Word(form.GetChild(1));
		if (auto note = MgmtCall::Optional(form.GetChild(2))) {
			value += "/" + call.NameValue(note->Cast<ListParseResult>().GetChild(1), "a note");
		}
	} else if (target.Name() == "AclToykillNumber") {
		// a module that reads a number as a quoted value: refused, never an internal error
		value = call.Quoted(target.Cast<ListParseResult>().GetChild(1), "a session id");
	} else if (target.Name() == "AclToykillValue") {
		value = call.Text(target.Cast<ListParseResult>().GetChild(1), "a value");
	} else if (target.Name() == "AclToykillList") {
		auto &form = target.Cast<ListParseResult>();
		value = call.NameValue(form.GetChild(1), "a name");
		for (auto &more : MgmtCall::Each(form.GetChild(2))) {
			value += "+" + call.NameValue(MgmtCall::Part(more.get()).Cast<ListParseResult>().GetChild(1), "a name");
		}
	} else if (target.Name() == "AclToykillScoped") {
		auto &form = target.Cast<ListParseResult>();
		value = call.Quoted(form.GetChild(1), "a session id");
		if (auto group = MgmtCall::Optional(form.GetChild(2))) {
			value += "@" + call.NameValue(group->Cast<ListParseResult>().GetChild(2), "a group");
		}
	} else if (target.Name() == "AclToykillItems") {
		value = "items";
		for (auto &item : MgmtCall::Each(target.Cast<ListParseResult>().GetChild(1))) {
			value += ":" + call.Quoted(MgmtCall::Part(item.get()).Cast<ListParseResult>().GetChild(1), "an item");
		}
	} else if (target.Name() == "AclToykillNamed") {
		auto &form = target.Cast<ListParseResult>();
		value = call.Name(form.GetChild(1), "a name");
		if (auto comment = MgmtCall::Optional(form.GetChild(2))) {
			value += "#" + call.Quoted(comment->Cast<ListParseResult>().GetChild(1), "a comment");
		}
	} else {
		value = call.Quoted(target, "a session id");
	}
	call.Arg(Value(value));
	return call.Result();
}

// TOYBAD '<value>': a call the platform's table does not know
arena_ptr<TransformResultValue> FinalizeToyBad(PEGTransformer &transformer, ParseResult &parse_result) {
	MgmtCall call(transformer, "acl_not_a_platform_function");
	call.Arg(Value(call.Quoted(parse_result.Cast<ListParseResult>().GetChild(1), "a value")));
	return call.Result();
}

// a rule headed by acl's words, registered under another keyword
arena_ptr<TransformResultValue> FinalizeToyHijack(PEGTransformer &transformer, ParseResult &parse_result) {
	MgmtCall call(transformer, "acl_session_kill");
	call.Arg(Value(MgmtCall::Word(parse_result.Cast<ListParseResult>().GetChild(2))));
	return call.Result();
}

unique_ptr<SQLStatement> OldSeam(acl::AdminScanner &) {
	return nullptr;
}

//! A module's matcher that takes any token - a `;` too (duckdb's own passthrough stops there)
class GreedyTokenMatcher : public AtomicMatcher {
public:
	GreedyTokenMatcher() : AtomicMatcher(MatcherType::CUSTOM) {
	}
	MatcherResult MatchAtomic(MatchState &state) const override {
		auto current = state.token_iterator.Current();
		if (!current || current->type == TokenType::END_OF_INPUT ||
		    current->type == TokenType::END_OF_INPUT_AUTOCOMPLETE) {
			return MatcherResult::Failure();
		}
		auto text = current->text;
		auto offset = current->offset;
		auto length = current->length;
		state.token_iterator.Advance();
		state.UpdateMaxTokenIndex();
		return state.AllocateParseResult<TokenParseResult>(std::move(text), offset, length);
	}
	SuggestionType AddSuggestionInternal(MatchState &state) const override {
		return SuggestionType::MANDATORY;
	}
	string ToString() const override {
		return "GreedyToken";
	}
};

// TOYSEMI <anything>: compiled to acl_session_kill('semi') - its matcher would read past a `;`
arena_ptr<TransformResultValue> FinalizeToySemi(PEGTransformer &transformer, ParseResult &) {
	MgmtCall call(transformer, "acl_session_kill");
	call.Arg(Value("semi"));
	return call.Result();
}

void RegisterToy() {
	vector<GrammarChange> rules;
	rules.push_back(
	    GrammarChange::AddRule("AclToykillStatement <- 'TOYKILL' AclToykillTarget", acl::MgmtStart<FinalizeToy>));
	rules.push_back(GrammarChange::AddRule("AclToykillTarget <- AclToykillWord / AclToykillNumber / AclToykillValue / "
	                                       "AclToykillList / AclToykillScoped / AclToykillItems / AclToykillNamed / "
	                                       "AclQuotedValue"));
	// an optional and a repetition behind helper rules of their own (CLUSTER's shared IN GROUP)
	rules.push_back(GrammarChange::AddRule("AclToykillGroup <- 'IN' 'GROUP' AclNameValue"));
	rules.push_back(GrammarChange::AddRule("AclToykillScope <- AclToykillGroup?"));
	rules.push_back(GrammarChange::AddRule("AclToykillScoped <- 'SCOPED' AclQuotedValue AclToykillScope"));
	rules.push_back(GrammarChange::AddRule("AclToykillItem <- ',' AclQuotedValue"));
	rules.push_back(GrammarChange::AddRule("AclToykillItemList <- AclToykillItem*"));
	rules.push_back(GrammarChange::AddRule("AclToykillItems <- 'ITEMS' AclToykillItemList"));
	rules.push_back(GrammarChange::AddRule("AclToykillWord <- 'WORD' AclWordToken AclToykillNote?"));
	rules.push_back(GrammarChange::AddRule("AclToykillNote <- 'NOTE' AclNameValue"));
	rules.push_back(GrammarChange::AddRule("AclToykillNumber <- 'NUMBER' NumberLiteral"));
	rules.push_back(GrammarChange::AddRule("AclToykillValue <- 'VALUE' AclValue"));
	rules.push_back(GrammarChange::AddRule("AclToykillMore <- ',' AclNameValue"));
	rules.push_back(GrammarChange::AddRule("AclToykillList <- 'LIST' AclNameValue AclToykillMore*"));
	rules.push_back(GrammarChange::AddRule("AclToykillNamed <- 'NAMED' AclName AclComment?"));
	acl::RegisterMgmtRules("toykill", {{"AclToykillStatement", {"word"}, "write TOYKILL WORD <word> [NOTE <name>]"}},
	                       std::move(rules), "TOYKILL expects '<id>' or WORD <word> [NOTE <name>]");
	vector<GrammarChange> bad;
	bad.push_back(
	    GrammarChange::AddRule("AclToybadStatement <- 'TOYBAD' AclQuotedValue", acl::MgmtStart<FinalizeToyBad>));
	acl::RegisterMgmtRules("toybad", {{"AclToybadStatement", {}, ""}}, std::move(bad), "TOYBAD expects '<value>'");
	vector<GrammarChange> semi;
	semi.push_back(
	    GrammarChange::AddRule("AclToysemiStatement <- 'TOYSEMI' AclToysemiToken+", acl::MgmtStart<FinalizeToySemi>));
	semi.push_back(GrammarChange::AddRule("AclToysemiToken <- Identifier"));
	semi.push_back(
	    GrammarChange::AddTerminalRuleOverride("AclToysemiToken", [](const PEGKeywordHelper &) -> unique_ptr<Matcher> {
		    return make_uniq<GreedyTokenMatcher>();
	    }));
	acl::RegisterMgmtRules("toysemi", {{"AclToysemiStatement", {}, ""}}, std::move(semi), "TOYSEMI expects anything");
}

//! Why a registration is refused ('' when it is not)
std::string Refusal(const std::string &keyword, const std::string &statement, vector<GrammarChange> changes) {
	try {
		acl::RegisterMgmtRules(keyword, {{statement, {}, ""}}, std::move(changes), "usage");
		return std::string();
	} catch (std::exception &ex) {
		return ErrorData(ex).Message();
	}
}

vector<GrammarChange> One(const std::string &rule) {
	vector<GrammarChange> changes;
	changes.push_back(GrammarChange::AddRule(rule, acl::MgmtStart<FinalizeToyBad>));
	return changes;
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

std::string ErrorOf(QueryResult &result) {
	return result.HasError() ? result.GetError() : std::string("it ran");
}

} // namespace

int main(int argc, char *argv[]) {
	Scenario("a registration that would change acl's statements or plain SQL is refused at load", [&] {
		Check(Has(Refusal("select", "AclSelectStatement", One("AclSelectStatement <- 'SELECT' AclQuotedValue")),
		          "heads acl's or duckdb's own statements"),
		      "a keyword duckdb's statements begin with");
		Check(Has(Refusal("kill", "AclKillStatement", One("AclKillStatement <- 'KILL' AclQuotedValue")),
		          "heads acl's or duckdb's own statements"),
		      "a keyword acl's statements begin with");
		Check(Has(Refusal("analyse", "AclAnalyseStatement", One("AclAnalyseStatement <- 'ANALYSE' AclQuotedValue")),
		          "heads acl's or duckdb's own statements"),
		      "duckdb's ANALYSE (ANALYZE's other spelling)");
		Check(Has(Refusal("to y", "AclToyStatement", One("AclToyStatement <- 'TO' AclQuotedValue")), "one plain word"),
		      "a keyword that is no word");
		Check(Has(Refusal("toy_x", "AclToy_xStatement", One("AclToyxStatement <- 'TOYX' AclQuotedValue")),
		          "one plain word"),
		      "a keyword with an underscore (no rule name holds one)");
		vector<GrammarChange> hijack;
		hijack.push_back(GrammarChange::AddRule("AclToyhlStatement <- 'KILL' 'SESSION' AclWordToken",
		                                        acl::MgmtStart<FinalizeToyHijack>));
		Check(Has(Refusal("toyhl", "AclToyhlStatement", std::move(hijack)), "begins with its keyword"),
		      "a form headed by acl's words (KILL SESSION)");
		vector<GrammarChange> twice;
		twice.push_back(
		    GrammarChange::AddRule("AclToytStatement <- 'TOYT' AclQuotedValue", acl::MgmtStart<FinalizeToyBad>));
		twice.push_back(
		    GrammarChange::AddRule("AclToytOther <- 'TOYT' 'X' AclQuotedValue", acl::MgmtStart<FinalizeToyBad>));
		try {
			acl::RegisterMgmtRules("toyt", {{"AclToytStatement", {"a"}, "u1"}, {"AclToytOther", {"A"}, "u2"}},
			                       std::move(twice), "usage");
			Check(false, "a verb two forms name");
		} catch (std::exception &ex) {
			Check(Has(ErrorData(ex).Message(), "is two forms'"), "a verb two forms name");
		}
		vector<GrammarChange> replace;
		replace.push_back(GrammarChange::ReplaceRule("AclQuotedValue <- StringLiteral"));
		replace.push_back(
		    GrammarChange::AddRule("AclToyrStatement <- 'TOYR' AclQuotedValue", acl::MgmtStart<FinalizeToyBad>));
		Check(Has(Refusal("toyr", "AclToyrStatement", std::move(replace)), "a module adds rules"),
		      "a change of acl's rules (ReplaceRule)");
		Check(Has(Refusal("toys", "AclToysElsewhere", One("AclToysStatement <- 'TOYS' AclQuotedValue")),
		          "a form's statement is one of the rules it adds"),
		      "a statement that is not among its rules");
		Check(Has(Refusal("toyc", "AclName", One("AclName <- Identifier")), "its rules are named AclToyc"),
		      "a rule outside the module's names (acl's own AclName)");
		auto undefined = Refusal("toyu", "AclToyuStatement", One("AclToyuStatement <- 'TOYU' AclNoSuchRule"));
		Check(Has(undefined, "do not compile"), "a rule that names no rule: " + undefined);
		acl::RegisterMgmtGrammar("toyold", OldSeam);
		Check(Has(Refusal("toyold", "AclToyoldStatement", One("AclToyoldStatement <- 'TOYOLD' AclQuotedValue")),
		          "older seam"),
		      "a keyword registered through the older seam");
	});

	// at load, before the first statement is read: the management grammar is compiled then
	RegisterToy();
	Check(Refusal("toybad", "AclToybadStatement", One("AclToybadStatement <- 'TOYBAD' AclQuotedValue")).empty(),
	      "the module's load again is a no-op");
	Check(Has(Refusal("toybad", "AclToybadOther", One("AclToybadOther <- 'TOYBAD' AclQuotedValue")),
	          "registered already, with other forms"),
	      "the keyword again with other forms");
	try {
		acl::RegisterMgmtGrammar("toykill", OldSeam);
		Check(false, "the older seam for a keyword its rules read");
	} catch (std::exception &ex) {
		Check(Has(ErrorData(ex).Message(), "read by its rules"), "the older seam for a keyword its rules read");
	}

	DBConfig config;
	DuckDB db(nullptr, &config);
	Connection con(db);
	// statically linked: the generated extension loader publishes 'acl' on the config
	Exec(con, "LOAD acl");
	Exec(con, "SET GLOBAL acl_allow_anonymous_admin=true");
	Exec(con, "SELECT acl_define_role('nobody', '')");
	Exec(con, "SELECT acl_define_role('pol', '')");
	Exec(con, "ACL ADMIN GRANT ADMIN policy TO ROLE pol");

	Scenario("the module's statement is read by its rules and compiled to its call", [&] {
		auto quoted = Compiled(con, "ACL ADMIN TOYKILL '0000'");
		Check(Has(quoted, "acl_session_kill('0000')"), "a quoted id: " + quoted);
		auto spaced = Compiled(con, "ACL ADMIN toykill /* a comment */ WORD 4GB NOTE \"a.b\"");
		Check(Has(spaced, "acl_session_kill('4GB/a.b')"), "a word and a note, as duckdb's tokens read them: " + spaced);
		auto dotted = Compiled(con, "ACL ADMIN TOYKILL WORD x NOTE a.b");
		Check(Has(dotted, "acl_session_kill('x/a.b')"), "a dotted name judged whole: " + dotted);
		for (auto &entry : vector<std::pair<std::string, std::string>> {
		         {"-0.5", "'-0.5'"}, {"7", "'7'"}, {"4GB", "'4GB'"}, {"'x y'", "'x y'"}, {"v1.0", "'v1.0'"}}) {
			auto read = Compiled(con, "ACL ADMIN TOYKILL VALUE " + entry.first);
			Check(Has(read, "acl_session_kill(" + entry.second + ")"), "AclValue " + entry.first + ": " + read);
		}
		auto each = Compiled(con, "ACL ADMIN TOYKILL LIST a, \"b c\", d.e");
		Check(Has(each, "acl_session_kill('a+b c+d.e')"), "a repetition read in order: " + each);
		auto scoped = Compiled(con, "ACL ADMIN TOYKILL SCOPED 'a' IN GROUP g");
		Check(Has(scoped, "acl_session_kill('a@g')"), "an optional behind a helper rule, present: " + scoped);
		auto unscoped = Compiled(con, "ACL ADMIN TOYKILL SCOPED 'a'");
		Check(Has(unscoped, "acl_session_kill('a')"), "...and absent: " + unscoped);
		auto items = Compiled(con, "ACL ADMIN TOYKILL ITEMS , 'a' , 'b'");
		Check(Has(items, "acl_session_kill('items:a:b')"), "a repetition behind a helper rule: " + items);
		auto none = Compiled(con, "ACL ADMIN TOYKILL ITEMS");
		Check(Has(none, "acl_session_kill('items')"), "...and none of it: " + none);
		auto named = Compiled(con, "ACL ADMIN TOYKILL NAMED \"Q\"\"x\" COMMENT 'c'");
		Check(Has(named, "acl_session_kill('Q\"x#c')"), "AclName and AclComment: " + named);
		auto ran = con.Query("ACL ADMIN TOYKILL '0000'");
		Check(!ran->HasError() && ran->RowCount() == 1 && !ran->Collection().GetValue(0, 0).GetValue<bool>(),
		      "it runs: no such session - " + (ran->HasError() ? ran->GetError() : std::string("ok")));
		auto batch = Compiled(con, "ACL ADMIN TOYKILL '1'; TOYKILL '2'");
		Check(Has(batch, "acl_session_kill('1')") && Has(batch, "acl_session_kill('2')"),
		      "a batch of the module's statements: " + batch);
		auto with_acl = Compiled(con, "ACL ADMIN KILL SESSION 'a'; TOYKILL 'b'");
		Check(Has(with_acl, "acl_session_kill('a')") && Has(with_acl, "acl_session_kill('b')"),
		      "acl's statement and the module's in one batch: " + with_acl);
		auto acl_own = Compiled(con, "ACL ADMIN KILL SESSION 'x'");
		Check(Has(acl_own, "acl_session_kill('x')"),
		      "acl's own statement, after the refused registrations: " + acl_own);
	});

	Scenario("its values are checked against their tokens", [&] {
		auto escape = Compiled(con, "ACL ADMIN TOYKILL E'0000'");
		Check(Has(escape, "expected a session id, quoted"), "an escape string is no plain literal: " + escape);
		auto joined = Compiled(con, "ACL ADMIN TOYKILL '00'\n'00'");
		Check(Has(joined, "expected a session id, quoted"), "a string joined across a line break: " + joined);
		auto number = Compiled(con, "ACL ADMIN TOYKILL NUMBER 7");
		Check(Has(number, "no quoted value is"), "a quoted reader on a number is refused, not internal: " + number);
	});

	Scenario("a statement its rules do not read is refused in the module's words", [&] {
		auto unread = Compiled(con, "ACL ADMIN TOYKILL 123 456");
		Check(Has(unread, "TOYKILL expects '<id>' or WORD <word> [NOTE <name>]"), "the module's usage: " + unread);
		auto verb = Compiled(con, "ACL ADMIN TOYKILL WORD x y z");
		Check(Has(verb, "write TOYKILL WORD <word> [NOTE <name>]"), "the form's own usage, by its verb: " + verb);
		auto commented = Compiled(con, "ACL ADMIN TOYKILL /* c */ WORD x y z");
		Check(Has(commented, "write TOYKILL WORD <word> [NOTE <name>]"), "the verb after a comment: " + commented);
		auto open = Compiled(con, "ACL ADMIN TOYKILL 'never closed");
		Check(Has(open, "unterminated"), "an unterminated string is the tokenizer's: " + open);
		auto empty = Compiled(con, "ACL ADMIN KILL SESSION 'a'; TOYKILL \"\"");
		Check(Has(empty, "zero-length delimited identifier"), "the tokenizer's refusal wins: " + empty);
	});

	Scenario("a module reads one statement, headed by its keyword", [&] {
		auto own = Compiled(con, "ACL ADMIN KILL SESSION 123");
		Check(Has(own, "write KILL SESSION '<id>'"), "acl's KILL SESSION is acl's, refused in its words: " + own);
		auto semi = Compiled(con, "ACL ADMIN TOYSEMI a; KILL SESSION 'b'");
		Check(Has(semi, "reads past a ';'"), "a module's matcher that reads past a `;`: " + semi);
		auto alone = Compiled(con, "ACL ADMIN TOYSEMI a b");
		Check(Has(alone, "acl_session_kill('semi')"), "...while one statement reads: " + alone);
	});

	Scenario("the compiled call is judged by the one authorizer", [&] {
		auto refused = con.Query("ACL ROLE \"nobody\" TOYKILL '0000'");
		Check(refused->HasError() && Has(refused->GetError(), "administration scope"),
		      "a role with no scope: " + ErrorOf(*refused));
		auto policy = con.Query("ACL ROLE \"pol\" TOYKILL '0000'");
		Check(policy->HasError() && Has(policy->GetError(), "operate bundle"),
		      "the policy bundle is not the operation's right: " + ErrorOf(*policy));
		auto unknown = con.Query("ACL ADMIN TOYBAD 'x'");
		Check(unknown->HasError() && Has(unknown->GetError(), "cannot authorize the management call"),
		      "a call the platform's table does not know: " + ErrorOf(*unknown));
		auto mixed = con.Query("ACL ADMIN TOYKILL '0000'; SELECT 1");
		Check(mixed->HasError() && Has(mixed->GetError(), "mixing management statements and queries"),
		      "a batch mixing it with a query: " + ErrorOf(*mixed));
	});

	Scenario("the door and the batch tell its statement from a query", [&] {
		std::string rest;
		Check(acl::ClientTextIsMgmt("TOYKILL '0'", rest), "the Flight door runs it as a command");
		Check(!acl::ClientTextIsMgmt("SELECT 'TOYKILL'", rest), "a query that holds the word is no command");
		auto query = con.Query("ACL ROLE \"nobody\" SELECT 'TOYKILL' AS word");
		Check(!query->HasError() && query->Collection().GetValue(0, 0).ToString() == "TOYKILL",
		      "under a principal, a query with the word runs as a query: " + ErrorOf(*query));
	});

	Scenario("a registration after the grammar was compiled is refused; another instance reads the module", [&] {
		Check(Has(Refusal("toylate", "AclToylateStatement", One("AclToylateStatement <- 'TOYLATE' AclQuotedValue")),
		          "after the first management statement"),
		      "a late registration");
		// hugr-node's test runner: many databases in one process, the module registering at each load
		Check(Refusal("toybad", "AclToybadStatement", One("AclToybadStatement <- 'TOYBAD' AclQuotedValue")).empty(),
		      "the module's load again, after the grammar was compiled, is a no-op");
		DuckDB second(nullptr, &config);
		Connection other(second);
		Exec(other, "LOAD acl");
		auto compiled = Compiled(other, "ACL ADMIN TOYKILL '7'");
		Check(Has(compiled, "acl_session_kill('7')"), "a second instance: " + compiled);
	});

	std::cout << (failures == 0 ? "PASS" : "FAIL") << "\n";
	return failures == 0 ? 0 : 1;
}
