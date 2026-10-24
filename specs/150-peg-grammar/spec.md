# Spec 150: our grammar on the PEG parser - no statement text parsed by hand

- **Status**: accepted; stages 1 and 2 implemented, stage 3 in progress (3a, 3b, 3c part 1 built), stage 4 to come
- **Date**: 2026-10-23
- **Author**: hugr lab (the owner, 2026-10-23: "отдельная спека с переделкой всей нашей семантики (грамматики) в
  рерайтере на peg парсер ... вообще не будем разбирать текст запроса вручную")

## Summary

Today our own code parses the ACL prefix, its markers and the management statements from the statement's text. That
is about 3,800 lines: the override's scanner (`acl_parser_override.cpp`), `acl_admin_scanner.hpp`, the
`acl_admin_sql.cpp` compiler and `ATTACH … LINEAGE` (`acl_attach_lineage.hpp`). The policy texts a statement carries (an
RLS, a mask, a column list) are split by hand (`ParseColumnList`, `SplitTopLevel`) and later pasted into SQL.

duckdb 2.0's parser is PEG, and grammar extensions (duckdb #24919) let an extension add rules with transforms into the
AST. This spec moves our grammar there: the standard parser parses the whole text once, an expression position is the
engine's own `Expression` rule, and the rewriter receives trees, never text.

## Problem

Two readers of one text can disagree. The scanner decides where the prefix ends, which marker is which and where a
statement starts; duckdb's parser then reads the rest. Each place where the two read quoting, comments, dollar quotes
or separators differently is a place where what we decided and what runs could differ. Spec 148 found the same class
inside policy texts: a gate that judged an expression list missed a `FROM` written after a mask. A hand parser also
accepts what no rule says (spec 148's tails), splits list and struct literals at their commas (`ParseColumnList`), and
gives no positions or completion for `ACL …` (spec 067's deferred CLI completion).

## Design

**What moves**

- **The prefix and its markers**: `ACL ROLE "r" | TOKEN '…' | SESSION '…' | ADMIN | NATIVE`, `TRACE` / `PARENT`,
  `LINEAGE PARENT | ROOT | JOB`, `INGEST`, and the batch split (`SplitBatchText`, `StartsWithMgmt`).
- **The management statements** (`acl_admin_sql.cpp`): `CREATE | ALTER | DROP VIRTUAL …`, `GRANT | DENY | REVOKE …`,
  issuers / clients / mappings, resource groups, references, categories, operate (`KILL SESSION`, `DRAIN NODE`, …),
  view-as, `USE`, `ATTACH … LINEAGE`. hugr-node's registered grammar (`RegisterMgmtGrammar`, spec 126) moves with
  them: its registration point becomes rules plus their transforms.
- **Policy texts**: `COLUMNS (…)` and `RLS (…)` become rules (`Expression`, spec 102's paths), so a list or struct
  literal is never split at its commas. Spec 148's check becomes "parses as the rule", and the function forms, which
  take text, are judged by the same rules.

**Where it runs.** `parser_override` stays the seam. duckdb offers it the whole text first (`ParseIterator::Peek`),
before any statement runs. The override parses with a grammar compiled by us: the connection's active grammar
extensions plus ours (`CompiledGrammar::Create(vector<reference<GrammarExtension>>)`; `ParserOptions` carries the
`context` and the `compiled_grammar`).

The grammar is also registered with duckdb as `acl` (the owner, 2026-10-23: so a CLI session completes `ACL …`), and
the override never depends on it: it compiles the connection's grammar extensions with ours behind them, once per set
(a connection that switched `acl` on gets the same grammar). Not switched on, nothing changes for a bare statement
(spec 067's first row). Switched on, `sql_auto_complete` offers `ACL`, then `ROLE`, then the statements; a prefixed text that reaches
duckdb's own parser - the override set to `DEFAULT` - parses to our statement and is refused at bind (acl's parser
extension plans nothing). Spec 132's grammar extensions keep working under the prefix: the inner statements are parsed
by the same compiled grammar, which includes them.

**A connection with a grammar of its own choosing.** `CONNECT` binds a connection to a remote catalog and forwards its
statements there; it is the connection owner's native mode (the owner, 2026-10-23), refused under every prefix
(`statement type CONNECT is not permitted under ACL`, also `DISCONNECT`). A prefix on a CONNECT-ed connection, or under
a dialect (`current_dialect`, refused under a prefix since spec 132), is refused from stage 2 on: nothing of ours can
be added to their grammars, and nothing there runs as a principal.

**What the rules yield (stage 2, the owner's choice of 2026-10-24).** The prefix rule reads the HEAD -
`ACL ROLE|TOKEN|SESSION|INGEST '<value>' | ACL ADMIN`, the markers (`TRACE`, `PARENT`, `LINEAGE PARENT|ROOT|JOB`, in
any order) and the client's mode marker (`ACL`, `ACL NATIVE`) - and passes the rest of its statement through as
tokens: `AclTail <- AclTailToken+`, the token matched by duckdb's own `PassthroughTokenMatcher` (the mechanism of its
passthrough dialect) as a terminal override. The override parses ONE top-level statement on duckdb's tokens; the
transform yields an `ExtensionStatement` carrying what the head says and where the rest starts. The rest is then parsed
as its own text, the way its mode parses it - a query by the standard parser with the connection's grammar extensions
(their syntax under `ACL ROLE` is confined or refused exactly as spec 132 says), `ACL NATIVE` as duckdb's own SQL
(other extensions' parsers included - break-glass), management by today's compiler until stage 3. Two calls, not one:
the rest parsed as its own text keeps every error position right and keeps the prefix - a token, a session handle -
out of duckdb's query text; stage 1 parsed the statement inside the rule, and its positions counted from the whole text
(no generic walker could shift them all, spec 139). A management rule (stage 3) yields the compiled call it compiles to
today, so the authorizer and the admin functions do not change.

**Each value is one plain literal.** duckdb's tokenizer joins string literals across a line break (`'ana'` then
`'lyst'` on the next line is `'analyst'`) - a client writing after a gateway's `ACL ROLE 'ana'` would finish its role's
name. Every value in the head must be its own token, written as the value in its quotes (`WrittenPlainly`): no joined
string, no `E'…'`, no bare name, never empty. Comments anywhere in the head are comments now (the scanner read none).

**Batches.** A prefix covers a statement list, as today:

- one prefix;
- every statement is decided and rewritten before any runs;
- the same refusals: a second prefix, management mixed with queries, and `USE` without a session of the client's own.

What a batch answers stays duckdb's: the first row-returning result, then the chain. The quack door answers as native
quack does (the same collector), and Flight refuses a batch at Prepare. Owner, 2026-10-23: keep both.

**Stages**

1. A prototype: the prefix `ACL ROLE "r" <statements>` as a rule beside the scanner, behind a setting. It answers the
   open questions below and measures the parse; the owner decides the shape.
2. The prefix and its markers move; the scanner goes. Built (below).
3. The management statements move, one statement family per PR; the compiled calls stay unchanged.
4. Policy texts become rules and stored rows are emitted from trees; `ParseColumnList` / `SplitTopLevel` go.

**Stage 1, the prototype (2026-10-23, #259)** - the role prefix as a rule taking the statement inside it, behind
`acl_peg_prefix`, beside the scanner. Measured with the rule on by default: the whole suite and `make test-cpp` pass;
5,000 prefixed statements 1.04-1.06 s against the scanner's 1.02-1.12 s; the grammar compiles once per set of the
caller's extensions, about 2 ms; a rule's keyword reserves nothing (`SELECT acl FROM acl`). Its reviews found what
stage 2 is built on: a comment inside the prefix made the two readers disagree (an internal error a principal could
reach), the statement inside the rule had its positions counted from the whole text, and an implicit PIVOT's entries
and the statement's parameters must be taken by the rule. Found building it: a helper rule without a transform cannot
be transformed (descend to `StringLiteral` / `Identifier`); a token rule (`QuotedIdentifier`) cannot be named from a
rule.

**Stage 2 (2026-10-24)** - `ReadAclPrefix` (acl_parser_override.cpp) over `AclGrammarCache::ReadPrefix`
(acl_grammar.cpp): a text not starting with the word ACL is never tokenized; `ACL <unknown>` is left to duckdb's
parser, as before; the scanner's rules are kept (each marker once, a lineage parent a run reference, INGEST with no
mode marker, ADMIN native unless marked) and the rest starts where the scanner left it, past the head and its
whitespace. A text duckdb's tokenizer refuses past the head (an unterminated string, `""`) is read up to the refusal:
the head reads, and the rest reports its own error where its mode parses it, as before (under `ACL NATIVE` other
extensions' parsers still get it; the audit still names the session). An error of the rest's parse is drawn against
the rest - duckdb drew it under the whole text with the rest's offset, the caret in the prefix and the prefix, a token
or a door's session handle, echoed back (pre-existing, found by the review, fixed); a compiler's own segment error
loses its position instead; the head's own syntax error never quotes the text. A marker word whose value does not read
(`TRACE SELECT`, `LINEAGE JOB SELECT`) gets the client's words, not the rest's syntax error. Cost: 5,000 prefixed
statements 1.04-1.06 s (the scanner's 1.02-1.12 s): the text is tokenized for the head and again for the rest. The
management statements and the batch's checks (`SplitBatchText`, `StartsWithMgmt`, `RefuseRepeatedPrefix`) stay read by
hand until stage 3; `ACL ROLE "r" ; ACL ROLE "x" …` ends as a syntax error, not as "one ACL prefix per batch".
A client's `ROOT` / `PARENT` right after a door's `LINEAGE JOB` joins that LINEAGE marker, as it did. Any other error
leaving the override drops a position of its own (it would be drawn under the whole text); with `errors_as_json` the
positions stay, unrendered, counted in the client's own text. One error is not ours to draw: duckdb validates the
whole text as UTF-8 before any override runs, and draws a failure under it, the prefix included - a gateway validates
before it composes (security.md's checklist); the doors refuse such bytes before they compose. The scanner, the
stage 1 path and `acl_peg_prefix` are gone. The registered `acl` grammar (completion) has
`AclTail <- Statement`, so the CLI offers the statements after the prefix. A prefix in a position where duckdb's
grammar takes a `Statement` - `PREPARE p AS ACL ROLE …`, a CTE body, a CTAS - parses to our statement (on a connection
with `acl` on) and is refused by duckdb's own transforms or by the plan function.

**Stage 3 - the management statements, one family per PR.** The batch after `ACL <prefix> ACL` (or `ACL ADMIN`) is
read by a grammar of its own (acl_mgmt_grammar.cpp, compiled once by `AclGrammarCache`, never registered): duckdb's
rules for what a statement holds, ours for the statements - `Statement <- AclMgmtStatement`, its alternatives the
families' rules and, last, `AclMgmtLegacy <- AclTailToken+`: a statement of a family that has not moved yet passes
through as tokens and goes, as its own text, to the management compiler (`CompileMgmtText`). A rule yields the acl_*
call it always compiled to (`MgmtParsed` -> `MakeAdminCall`), so the authorizer and the admin functions do not change.
A moved family's text form stays only as a refusal in the form's own words ("write KILL SESSION '<id>'"): what does
not read as its rule falls to it, and only the rule accepts - never two readers. A form a rule began with more after
it before its `;` (PEG keeps the rule that matched, so the statement fails there) goes the same way: its tokens up to
the `;`, as text, to the compiler - the batch's other statements are not blamed. duckdb's grammar splits the batch (a
`;` inside parentheses now ends a statement - none of ours holds one; `SplitBatchText` reads comments as the
tokenizer does, a line comment ending at either line break, block comments nested); a text the tokenizer refuses is
read piece by piece - the pieces it reads by their rules, the refused one by the compiler in its own words (a moved
form refused there says the tokenizer's: an unterminated string), and a batch no piece of which holds the refusal (an
unterminated comment the split drops) is refused whole - never run without it. Values a rule reads are checked against their
tokens - one plain quoted literal (an empty `''` passes, as it did: the function judges it; `""` is a zero-length
identifier the tokenizer refuses), a level a bare word. hugr-node's registered forms
(`RegisterMgmtGrammar`, spec 126) take the legacy path unchanged. The text checks that tell a management batch from
native SQL (`IsMgmtStart`, `StartsWithMgmt`, `BatchHasMgmtStatement`, `SplitBatchText`, `RefuseRepeatedPrefix`) stay
until the last PR of the stage, which judges the batch by its parse and drops `AdminScanner`.

- 3a (built): the grammar, the legacy path, and the operations of a node - `KILL SESSION '<id>'`,
  `SET SESSION '<id>' AUDIT LEVEL …|DEFAULT`, `PROFILE SESSION CURRENT|'<id>' ON|ALL|SAMPLED|OFF`, `DRAIN NODE`,
  `RESUME NODE`, `MIGRATE POLICY CATALOG <db>[.<schema>]`. Newly accepted: comments inside these forms; a quoted
  level stays refused, as it was; a SQL keyword as a database name must be quoted now (the refusal says so); an inline body's trailing comment is no longer part of a legacy statement's text. A rule's checks run over
  the batch before the compiler's statements, so a later statement's error may be the one reported.
- 3b (built): roles, admin scopes, role mappings, view-as - `CREATE [OR REPLACE] ROLE [IF NOT EXISTS] r [CLAIMS
  (…) | '…']`, `ALTER ROLE r SET COMMENT | CLAIMS`, `DROP ROLE [IF EXISTS] r`, `GRANT ADMIN s TO ROLE r`, `REVOKE ADMIN
  [s] FROM ROLE r`, `[DROP] MAP GROUP | CLAIM '<v>' FROM CLIENT | ISSUER n TO ROLE r`, `SET SESSION VIEW AS ROLE r`,
  `RESET SESSION VIEW AS`. The compiler's values on duckdb's tokens: a matcher of ours (`AclTokenMatcher`) reads a word
  (ASCII letters, digits, `_` - a keyword too: `CREATE ROLE select` works as it did; the tokenizer splits a word at a
  leading digit, `9abc` is `9` `abc`, so a word is the run of word tokens with nothing between them, as the scanner
  read it), a double-quoted name, or a list's item; `Ident` is `AclName`, `NameValue` `AclNameValue` (quoted either
  way, or words joined by `.` - the tokenizer reads a number through its dots, `v2.0.1` is `v2` `.0.1`, so one matcher
  takes the tokens of word characters and dots that touch or meet at a dot and judges the name whole, every part a
  word), a parenthesised claims list is passed to the compiler's `ClaimsListToCsv` as written with each comment a
  space (the span as is read `(a = 'x' -- , b = 'y'⏎)` as two claims; the tokens joined by a space would have split
  `custom:tenant` and `-1`, which the reader keeps as written). A claim's value is not yet checked to
  be a plain literal (`(a = 'x' ACL ROLE 'boss')` stores what the compiler made of it, as before): stage 4's rule for
  the list does. Changed: a moved form's `""` is the tokenizer's zero-length identifier (`ALTER ROLE r SET COMMENT ""`
  cleared the comment, `SET SESSION VIEW AS ROLE ""` reset the mode; `''` / `RESET` do), `REVOKE ADMIN`'s scope and
  `FROM` are told apart by the rule, never by peeking (`REVOKE ADMIN from FROM ROLE r` is an unknown scope); newly
  accepted: a comment anywhere inside these forms, spaces or a comment around a name's dot (`kc . x` is `kc.x`), `if`
  as a role name (`DROP ROLE if`), a comment inside a claims list (read as a space). Refused inside a claims list: a
  value written `E'…'` or `$$…$$` and a backtick name - the compiler's reader knows `'…'` and `"…"` only, so it split
  `(region = $$a, tenant = 'globex', b = $$)` into three claims where the tokenizer reads one value (the scanner's
  `Parens` accepted that too) - and a text the tokens do not tile (after a lone `$` duckdb's tokenizer places the next
  token at the `$`).
- 3c: the virtual catalog's objects, in two PRs. Part 1 (built): `CREATE [OR REPLACE] VIRTUAL CATALOG | REFERENCE |
  SCHEMA | VIEW | SCALAR | TABLE FUNCTION | TABLE …` and the spec-008 `ADD VIEW | SCHEMA | SCALAR | TABLE FUNCTION |
  TABLE` forms. The compiler's `Path` is our matcher's `AclPathToken` (`Kind::PATH`): the dotted name's run of tokens
  with a double-quoted name a part of its own, judged whole into spec 116's canonical key (an empty part, `a"b"`,
  `"a"b` refused); `PathName` is `AclPathName <- StringLiteral / AclPathToken` (the single-quoted legacy whole path
  read with the key rules); `List` is `AclList <- AclParenList / AclQuotedValue`, a parenthesised one as written with
  each comment a space (`TokensText`, refused unless the tokens tile it - the lone `$` of 3b); a body is `AclBody <-
  AclTailToken+`: one plain quoted token is its value, anything else the text from its first token to its last as
  written (the comments inside it kept). A columns list goes to `UnquoteColumnsList` and a
  claims list to `ClaimsListToCsv` as before (`MgmtParsed::texts`). Changed: a comment is accepted after `VIRTUAL` /
  `ADD` (before it the text check that tells management from native SQL still misses it - 3g), and a list's comment
  is a space - `RLS (a > 0 -- note⏎)` left an open comment in the stored predicate, which spec 148 refused, and a
  column list stored a column named `/* hidden */ b`; a body's comments before its first token and after its last are
  not stored; spaces or a comment before a path's dot are accepted (after one they always were); a `""` value
  (`COMMENT ""`, `RLS ""`, a body `AS ""`) is the tokenizer's zero-length identifier, as in 3b (`''` is the empty
  text); a `;` ends a body wherever it stands outside a literal (the scanner kept one inside parentheses: such a body
  was never one statement), while a `$$…$$` string in a body is one token (the scanner did not know it); a name the
  scanner took as a keyword is a name (`CREATE VIRTUAL CATALOG if`, `CREATE VIRTUAL TABLE function.t`). A body
  written quoted is still the whole body: `AS 'SELECT 1' COMMENT 'x'` is refused, never stored as the view's SQL.
  A list our readers split (columns, keys, pairs, parameters, a result's columns - `SplitTopLevel` knows `'…'` with
  `''` and `"…"` only) refuses a literal it would split otherwise than the tokenizer reads it - a `$$…$$` string, an
  `E'…'` one with a backslash, a backtick name: `COLUMNS (a, $$x, b, y$$)` was three columns to the reader where the
  tokenizer reads one literal; an RLS predicate (SQL, duckdb's parser reads it) takes any. A comment between two
  strings duckdb joins (`'a' -- c⏎'b'` is `'ab'`: a quoted string of any prefix, then a plain one with
  `preceded_by_newline` and no `preceded_by_block_comment` - its StringLiteralMatcher's rule, `JoinsStrings`) is a
  line break, a space elsewhere (a declared column's name and type stay apart); a claims list's is always a space. A batch holding a
  dollar-quoted string nobody closed is refused whole: duckdb's tokenizer keeps it as one literal to the end of the
  text (`MatcherToken::unterminated`), so `AS SELECT $x$ AS a; DROP ROLE r` stored the DROP as the view's SQL - and
  never ran it - while the batch answered success; and a statement the tokenizer refuses (a `""`) is compiled from
  its text only when it holds no `;` - the batch's split and duckdb's tokenizer may disagree on where a statement
  ends (`ALTER VIRTUAL VIEW … SET AS SELECT (1 AS ""; DROP ROLE r)`, or `$1$; …; $1$`, which the split took for a
  quote, did the same through the compiler's `Rest`) - both found in review.
  Part 2: `ALTER | DROP VIRTUAL …`, `DROP RELATION | REFERENCE`, `COMMENT ON VIRTUAL`, `CHECK`,
  `REPAIR`, `ANALYZE VIRTUAL`.
- 3d: grants (`GRANT | REVOKE CATALOG | SCHEMA | TABLE | VIEW | OBJECT`, `ALTER GRANT`, CAPS / RLS / COLUMNS clauses).
- 3e: issuers and clients (spec 095).
- 3f: function categories and grants, platform grants, sources, resource groups.
- 3g: `GRANT | REVOKE SECRET`, `USE [SCHEMA]`, `ATTACH … LINEAGE`, the batch's classification by its parse;
  `AdminScanner` and `SplitBatchText` go; `RegisterMgmtGrammar` becomes rules (hugr-node re-pins).

**Open questions**

1. Stored policy rows are text by contract (read back and pasted). Either parse them with the rule at read and emit
   the tree, or keep spec 148's check.

## Enforcement & security

- **One reader.** The head is read by duckdb's tokenizer and our rule; the rest starts at a token boundary the rule
  found and is parsed by duckdb's parser. No hand scanner reads where the prefix ends, so there is no second reading
  to disagree with. Each value is one plain literal - a string continuation cannot extend a principal's name.
- **Fail closed.**
  - The override still claims every text (`STRICT`), and a parse that fails is a refusal, as now.
  - With the override off (`DEFAULT`), an `ACL …` text is a parse error on a connection that has not switched `acl`
    on, as today, and on one that has it parses to our statement, which is refused at bind: acl's parser extension
    plans nothing.
  - Our statement never leaves the override unrewritten.
  - A rule never yields a statement the rewriter has not seen.
- **Nothing widens.** Every refusal the scanner made is kept: a second prefix, a mixed batch, `USE` without a
  session, foreign syntax under the prefix (spec 067's three rows and spec 132's fourth), each marker once. Newly
  refused: an empty value, a value that is not one plain literal, a marker written twice whatever its first value (the
  review found `TRACE '' TRACE 'x'` accepted mid-stage), a prefix on a CONNECT-ed connection or under a dialect; a mode
  marker after INGEST is refused in its own words now, where it was the rest's parse error.
- **The golden rule holds.** A rule adds no parameters; a client's `$1` / `?` stays the only parameter.

## Testing

- Every existing grammar test passes unchanged at each stage, since the grammar is the same language.
- The batch behaviour is pinned: the gateway answers the first row-returning result (`acl_prefix_grammar.test`), the
  quack door answers as native quack and refuses the batch when one statement is refused (`test_acl_quack_embed`),
  Flight refuses a batch at Prepare (`test/e2e/flight/adbc_client.py`).
- `acl_prefix_grammar.test`: every kind, the markers in any order and quoted either way, each value one plain literal,
  the rest's text and error positions, the empty prefix and a separator after it; `acl_prefix_completion.test`.
- Negative tests cover what the hand parser accepted and the rules refuse.
- Stage 1 ran the whole suite with the rule on by default beside the scanner; stage 2 runs it with the rule alone.

## Alternatives considered

- **Keep the scanner and harden it.** The disagreement class stays, and every new form needs both readers kept in
  step.
- **One call: the statement inside the prefix rule** (stage 1's form). The AST is the same - duckdb's parser with the
  connection's grammar extensions builds it either way - but the statement's positions count from the whole text while
  its text must stay cut (the prefix carries a token or a session handle), `ACL NATIVE` would lose other extensions'
  own parsers, and management text has no rule until stage 3.
- **Depend on the registered grammar** (switched on per connection by `active_grammar_extensions`). A connection owner
  could switch it off, and every door and gateway connection would have to set it. The override compiles ours in, and
  the registration is for completion only.

## Follow-ups

The DDL follow-ups (`SELECT acl_register_* / acl_rename_relation / acl_drop_relation(…)`) are answered to the client as
a result:

- the column header names the physical object, and a view's carries the rewritten body;
- on quack, the follow-up takes the batch's answer from the client's own SELECT.

Owner, 2026-10-23: this is fixed after 150, as its own spec.
