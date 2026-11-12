//===----------------------------------------------------------------------===//
// acl_grammar.hpp
//
// Spec 150: our grammar as rules of duckdb's PEG parser. Stage 2: the ACL prefix's head -
// `ACL <ROLE|TOKEN|SESSION|INGEST> '<value>' | ACL ADMIN`, its markers (TRACE, PARENT, LINEAGE …) and
// the client's mode marker (`ACL`, `ACL NATIVE`) - is read by a rule, which passes the rest of the
// statement through as tokens and says where it starts. The rest is then parsed as its own text, the
// way each mode parses it, by the standard parser with the connection's grammar extensions. The
// rules are compiled inside the override (the connection's extensions, ours behind them) and also
// registered as the grammar extension `acl` - for completion only.
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb.hpp"
#include "duckdb/parser/parser_options.hpp"

namespace duckdb {
class CompiledGrammar;
class GrammarExtension;

namespace acl {

//! What the prefix rule read off a text's head
struct GrammarPrefix {
	enum class Kind : uint8_t { ROLE, TOKEN, SESSION, INGEST, ADMIN };
	enum class MarkerKind : uint8_t { TRACE, PARENT, LINEAGE_PARENT, LINEAGE_ROOT, LINEAGE_JOB };
	//! how many marker kinds there are - LINEAGE_JOB is the last
	static constexpr uint8_t MARKER_KINDS = static_cast<uint8_t>(MarkerKind::LINEAGE_JOB) + 1;
	//! a marker, in the order written
	struct Marker {
		MarkerKind kind;
		string value;
	};
	Kind kind = Kind::ROLE;
	//! the principal's value, as written inside its quotes (none for ADMIN)
	string value;
	vector<Marker> markers;
	//! how many times LINEAGE was written (more than once is refused by the reader)
	idx_t lineage_written = 0;
	//! the client's mode marker: `ACL` after the head, and whether `NATIVE` follows it
	bool mode_written = false;
	bool native = false;
	//! where the rest starts: past the head and the whitespace after it
	idx_t rest_start = 0;
};

//! spec 150, stage 3: a management statement as the grammar read it - a call of an acl_* function a rule compiled, or
//! (`unread`: no rule reads it) the statement's own text, refused in its form's words
struct MgmtParsed {
	bool unread = false;
	//! unread: the statement as written, its first token to its last
	string text;
	//! unread: why a name in it may not read (spec 150 4a) - a keyword or a leading digit the rules read no name in,
	//! with the quoting that reads it; '' when the parse stopped at nothing so
	string hint;
	//! a rule's: the acl_* function and its arguments
	string function;
	vector<Value> args;
	//! the first argument is the session the batch runs under (`PROFILE SESSION CURRENT`)
	bool current_session = false;
	//! the call is a table function, read in FROM (`CHECK VIRTUAL CATALOG`)
	bool table_call = false;
	//! spec 082: `GRANT | REVOKE SECRET` - the secrets service's call, not an acl_* one: `function` is grant_secret /
	//! revoke_secret, `args` the secret's name, the principal (`role:r` / `group:g`) and the service named ('' none)
	bool secrets = false;
	//! arguments written as a list or a body, as text the compiler's readers take as they always did (a list becomes a
	//! rule in stage 4): a columns list for UnquoteColumnsList, the rest as is (a group's limits are a rule since
	//! spec 150 4b, a client's lists since 4c, a role's claims since 4d)
	enum class TextKind : uint8_t { COLUMNS, TEXT };
	struct TextArg {
		idx_t arg;
		string text;
		TextKind kind;
	};
	vector<TextArg> texts;
};

//! A marker's words as a client writes them: `TRACE`, `LINEAGE JOB`, ...
const char *MarkerWords(GrammarPrefix::MarkerKind kind);

//! spec 150, stage 3g-1: one token of a statement's head as duckdb's tokenizer reads it (comments are gone): a bare
//! word (lower-cased), a quoted name (`"…"` or a backtick one), a number written with a leading digit (`1x` is the
//! tokenizer's number then word: a name to our rules), a single-quoted string, or anything else
struct HeadToken {
	enum class Kind : uint8_t { WORD, QUOTED_NAME, NUMBER, STRING, OTHER };
	Kind kind = Kind::OTHER;
	string word;
	//! the token as written, where it starts in the text read, and its place in its statement
	string text;
	idx_t offset = 0;
	idx_t index = 0;
	//! a string or a quoted name the text ends inside
	bool unterminated = false;
	bool IsWord(const char *keyword) const {
		return kind == Kind::WORD && word == keyword;
	}
};
//! A batch's statements, as duckdb's tokenizer ends them (`;` outside a literal or a comment), each by its first
//! `count` tokens - what decides whose statement it is (the management grammar's or duckdb's) - and, past them, its
//! last `tail` (what ends it: `ATTACH … LINEAGE '<x>'`; a token's `index` says where a gap is). Never throws: a text
//! that ends inside a block comment has the heads before it, one ending inside a string or a quoted name has that
//! token last (`unterminated`), and its own reader refuses either; `open`, when given, says whether it does (a
//! comment never becomes a token, so no head shows one)
vector<vector<HeadToken>> ReadStatementHeads(const string &text, idx_t count, bool *open = nullptr, idx_t tail = 0);
//! spec 150 3g-3: whether `word` heads a linked module's statements (RegisterMgmtRules, acl_mgmt_rules.hpp), and how
//! the module says what a statement with that `verb` (the word after it) is when its rules do not read one
bool MgmtRulesKeyword(const string &word, string *usage = nullptr, const string &verb = string());

//! The grammars the override compiles, one per set of the caller's grammar extensions
class AclGrammarCache {
public:
	AclGrammarCache();
	~AclGrammarCache();

	//! Reads `query`'s ACL prefix head. False when the text has none of ours (it does not start with
	//! `ACL <kind>`) - the override leaves it. Throws a ParserException for a head the rule refuses.
	bool ReadPrefix(const string &query, const ParserOptions &options, GrammarPrefix &out);

	//! spec 150, stage 3: a management batch's statements, each by its rule or as text. Throws a ParserException for a
	//! text the grammar refuses.
	vector<MgmtParsed> ReadManagement(const string &text, const ParserOptions &options);
	//! A management batch's statements as duckdb's tokenizer ends them, for a batch it refuses to read whole (a `""`
	//! in one statement): each statement's text, first token to last. Throws a ParserException when the text ends
	//! inside a comment, a string or a quoted name - what it hides is never run without it
	vector<string> SplitManagement(const string &text);

	//! The rules as a grammar extension, registered so a connection may switch them on for completion
	//! (`SET active_grammar_extensions = ['acl']`); the override never depends on it being on
	shared_ptr<GrammarExtension> Extension() const;

private:
	shared_ptr<CompiledGrammar> ManagementGrammar();
	struct Impl;
	unique_ptr<Impl> impl;
};

} // namespace acl
} // namespace duckdb
