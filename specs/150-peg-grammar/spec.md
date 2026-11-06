# Spec 150: our grammar on the PEG parser - no statement text parsed by hand

- **Status**: accepted; stages 1-3 implemented (stage 3: 3a-3g), stage 4 in progress (4a implemented)
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
4. Policy texts become rules where they are written (the owner, 2026-11-06: stored rows stay the text as written,
   see Decided); the statement's list readers on `AdminScanner` go.

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
`;` inside parentheses now ends a statement - none of ours holds one; since 3g-1 the batch's classification reads the
same tokens, `ReadStatementHeads`); a text the tokenizer refuses is
read piece by piece - the pieces it reads by their rules, the refused one by the compiler in its own words (a moved
form refused there says the tokenizer's: an unterminated string), and a batch no piece of which holds the refusal (an
unterminated comment the split drops) is refused whole - never run without it. Values a rule reads are checked against their
tokens - one plain quoted literal (an empty `''` passes, as it did: the function judges it; `""` is a zero-length
identifier the tokenizer refuses), a level a bare word. hugr-node's registered forms
(`RegisterMgmtGrammar`, spec 126) take the legacy path unchanged. The text checks that tell a management batch from
native SQL read the batch's heads on duckdb's tokens since 3g-1 (`IsMgmtStart` and `SplitBatchText` gone); 3g-3 drops
`AdminScanner`.

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
  never ran it - while the batch answered success; and the statement-by-statement reading of a batch the tokenizer
  refuses (a `""`) did the same through the compiler's `Rest` (`ALTER VIRTUAL VIEW … SET AS SELECT (1 AS ""; DROP
  ROLE r)`, `$1$; …; $1$`) - both found in review; part 2 reads such a batch by duckdb's own statement ends.
  Part 2 (built): `ALTER VIRTUAL CATALOG | REFERENCE | VIEW | TABLE | SCALAR | TABLE FUNCTION | SCHEMA …`,
  `COMMENT ON VIRTUAL …`, `CHECK VIRTUAL CATALOG` (a table call, `MgmtParsed::table_call`), `REPAIR VIRTUAL TABLE`,
  `ANALYZE VIRTUAL …`, `DROP RELATION | [VIRTUAL] REFERENCE`, `DROP VIRTUAL CATALOG | SCHEMA | TABLE | VIEW | SCALAR |
  TABLE FUNCTION` - one `ObjectChangeInto` for every SET / DROP change of a view, a table and a function, part 1's
  paths, lists and bodies. Changed as in part 1 (comments, `""`, the lists' literal rule - REMAP's list too, as a
  columns list); a scalar's PRIMARY KEY is refused in its own words (the scanner said `expected alias` / `expected
  set`); a physical path may be the legacy single-quoted string in `ALTER VIRTUAL SCHEMA … SET PHYS`, `ADD SCHEMA`
  and `ADD TABLE` too, as the notation always said; a table function's COMMENT ON / ANALYZE form is a rule of its own
  and a kind is read only before a path, so `TABLE function.x` and `ANALYZE VIRTUAL table.t` name catalogs
  `function` / `table` (the scanner refused them; `CHECK` writes such repairs). A batch duckdb's tokenizer refuses
  whole (a `""` in one statement) is read statement by statement as THAT tokenizer ends them - `SplitMgmtStatements`,
  its tokenizer run with a behavior that throws nothing (`SplitTokenizerBehavior`), the text ending inside a comment,
  a string or a quoted name refused - never by `SplitBatchText`, whose own reading of quotes and comments (`$1$`, a
  backtick name, `E'\''`) hid an open comment and let the statements it hides run (found in review, four times, on
  that path: a `;` inside parentheses, `$1$`, an open comment, an opener inside what it took for a quote); part 1's
  "no `;` in a refused piece" guard is gone with it. A statement no rule reads yet goes to the compiler as its text,
  whose scanner knows `'…'`, `"…"` and whitespace only: once it compiles, a comment inside it, a `$$…$$` string, an
  `E'…'` one with a backslash or a backtick name refuses it (`MgmtParsed::unreadable`, `LegacyUnreadable`) -
  `GRANT CATALOG c TO ROLE r WITH (select, /*, manage, */ insert)` stored `manage` (found in review; a statement
  that does not compile keeps its own refusal; comments before, between and after statements are untouched). A body
  is read as what it is before anything of the batch runs (`JudgeBody`: a view's SQL and a table function's template
  one statement, a scalar's template an expression list, duckdb's parser): a body a `;` cut (`AS SELECT [1; …`,
  `CASE … ; … END`) does not parse and is refused, and an unparseable body is never stored (it used to be, under an
  operator, and failed at its first read).
  Found in the same review and left to the family that moves the form (each a fix with its test there): 3d - the WITH
  list's JSON is built without escaping (`\u006danage` stores manage), `ParseCaps` reads a key up to a NUL and counts
  a duplicate key true if any is (both fixed in 3d); 3e - `CLAIM MAP`'s JSON without escaping and split on `=>` inside
  quotes (fixed in 3e); 3b's
  `ClaimsListToCsv` splits at an `=` inside a quoted name (stage 4's rule); 3g - `UseSchemaAsSet`'s own comment
  reader (`--` ends at `\n` only, `/* */` not nested).
- 3d (built): grants - `GRANT CATALOG c TO ROLE r` / `GRANT SCHEMA c.p …` / `GRANT TABLE | VIEW | OBJECT c.n …` with
  their clauses in any order, each once (`WITH (…)` / `CAPS '<json>'` one kind, `RLS`, `COLUMNS`, a catalog's `MAIN`;
  a schema's `INTO <phys>` | `VIRTUAL ONLY` and `COMMENT` after them, its `RLS` / `COLUMNS` refused unless empty -
  separators only are empty), `REVOKE CATALOG | SCHEMA | TABLE | VIEW | OBJECT … FROM ROLE r`, `ALTER GRANT CATALOG c
  TO ROLE r SET CAPS | RLS | COLUMNS '<text>' | MAIN <word>`. A grant on a view of the platform catalog (`GRANT |
  REVOKE VIEW platform.x`, spec 117, `PlatformObjectName`) is a point grant the compiler still reads: its transform
  answers legacy data with the statement's span (`PlatformViewGrant`; a call since 3f); another name of platform's
  stays an object grant, refused as the reserved catalog. Fixed with the move (3c's review, 3d's): `WITH (…)` is a list of names
  (`AclCapsList`: a word or a double-quoted name, lower-cased, the same twice one, `JsonQuote`d - `CapsListToJson`
  pasted the text between the commas, so `\u006danage` stored manage); `ParseCaps(json, strict)` where caps are WRITTEN
  (a grant, `ALTER GRANT SET CAPS`, `check_grant`, the function forms) refuses an escape in the JSON (a name is a word
  and needs none - an escaped one read as a word here and as text to the listings' match) and a name that is not a word (ASCII letters, digits, `_`: a NUL it read up
  to, a `"` a rewrite pasted, a character the listings' regex folded) and a name written twice (names compare
  case-insensitively; it counts any true, a JSON reader takes the last); `REVOKE ADMIN` rebuilds the caps as JSON
  (`JsonQuote` - it pasted each name, so a stored `\u006danage` came back as manage and the role stayed an administrator;
  found in 3d's review) and so does the legacy csv wrapper (`CapsCsvToJson`, each name once, as `CapsJson` the
  platform call's list); a quoted COLUMNS list holding a comment, a `$$…$$` string, an `E'…'` one with a backslash or
  a backtick name or a `;` is refused (its reader would split it otherwise than written: `'a /*, tenant, */'` read
  only `tenant`), and so is a quoted claims list. A refused grant leaves no catalog grant behind: the role's grant on
  the catalog (an empty one when it has none) is written in the schema / object grant's own transaction
  (`EnsureGrantSql`) - the separate ensure before it was left by any later refusal, and an empty grant moved a role's
  short names to that catalog or gave it a second main one (found in 3d's re-review). A stored row keeps its reading and its rewrites stay unjudged (`ALTER GRANT SET RLS`, `REPAIR … AND
  MASKS`): nothing is taken back by itself. Changed: a comment in an RLS / COLUMNS list reads as a space (spec 148
  refused the open comment), a clause written twice is refused (the last won, so `RLS (tenant = 'x') … RLS ()` read
  as a filter and granted every row), a `WITH` item that is no word (`'insert'`, `select insert`) is refused, the
  catalog / schema / object refusals are the form's usage, `""` is the tokenizer's (`''` the empty text).
- 3e (built): issuers and clients (spec 095) - `CREATE [OR REPLACE] ISSUER [IF NOT EXISTS] <name | '<url>'>` with
  `URL`, its `FROM SECRET s [IN c]` and the implicit client's clauses (the short form), `CREATE [OR REPLACE] CLIENT
  [IF NOT EXISTS] c ISSUER i` with a client's (`AUDIENCES`, `AZP`, `REQUIRE (…)`, `ROLES FROM | CONSTANT`, `ROLE
  CLAIM`, `UNMAPPED IGNORE | AS ROLE`, `ATTRIBUTES (…)`, `CLAIM MAP`, `SUBJECT`, `TOKEN TYPE`, `FLOWS`, `CLIENT ID`,
  its own `FROM SECRET`, the short form's `CLIENT FROM SECRET`), `ALTER ISSUER i SET … | DROP [CLIENT] FROM SECRET`,
  `ALTER CLIENT c SET … | DROP FROM SECRET`, `DROP ISSUER | CLIENT [IF EXISTS] n`; `KEYS` / `ALGS` / `CLIENT SECRET`
  are read with their values and refused in their own words (never written into the policy). The spec JSON is built
  in the transform; a parenthesised list inside it (`AUDIENCES (…)` and the other value lists, `REQUIRE`,
  `ATTRIBUTES`, `CLAIM MAP`) is a marker the list's reading replaces once the tokens are known
  (`MgmtParsed::TextArg::splice`, a control character no JSON value holds raw) - the compiler's readers
  (`ListItemsJson`, `RequireJson`, `AttributesJson`, `ClaimMapToJson`) on the list as written, each comment a space,
  the lists' literal rule. Fixed with the move (3c's review): `ClaimMapToJson` quotes each side as JSON and splits at
  an `=>` outside quotes - it pasted the sides, so `('x' => 'a", "groups": "tenant')` stored a second, hidden
  attribute (`tenant` from `groups`, what RLS reads through `acl_claim`), and `('a=>b' => 'c')` split inside the
  quotes. Changed: each clause once, by what it writes - `ROLE CLAIM` / `ROLES FROM` (both `roles_from`) and
  `ATTRIBUTES` / `CLAIM MAP` (both the attributes) are one clause each (a repeated one wrote its key twice into the
  spec JSON and the last took effect: `ATTRIBUTES (tenant = CONSTANT 'acme') CLAIM MAP (tid => tenant)` read
  `tenant` from the token); comments inside these forms after their first words (one after `CREATE` / `ALTER` /
  `DROP` is 3g's classification); `""` the tokenizer's; an item continued on the next line refused where the
  list's reader takes its items as literals - these lists and 3b's claims lists (duckdb joins `'rol'⏎'es'`, the
  reader stored `rol'⏎'es`); a mask or a REMAP item is SQL, read by duckdb, joined. Two literals with no separator
  (`('a' 'b')`, a claims list's missing comma) are still read as one item, wrongly and closed - the lists as rules
  (stage 4); the function forms take a spec JSON as written (a key twice, `attributes` with `claim_map` - the last
  wins), never read by an authorizer. 3e's review also found two
  holes of spec 117's authorizer (a name written in another case, a batch mapping and granting manage together) -
  spec 152's.
- 3f (built): function categories and grants (spec 072: `CREATE | ALTER … ADD | DROP (…) | SET COMMENT | DROP [IF
  EXISTS] FUNCTION CATEGORY`, `GRANT | DENY | REVOKE FUNCTION [CATEGORY] … TO | FROM ROLE r | ALL ROLES`), the platform
  catalog's point grants (spec 117: `GRANT | DENY | REVOKE FUNCTION platform.<f>`, `DENY VIEW platform.<v>`, and `GRANT
  | REVOKE VIEW platform.<v>` through the object grant's rule, whose role is now `ROLE r | ALL ROLES` - ALL ROLES
  refused where read), sources (spec 118.3: `GRANT | REVOKE SOURCE <db>[.<schema>]`), resource groups (spec 085: `CREATE
  [OR REPLACE] RESOURCE GROUP g [WITH] [(limits)] [DEFAULT] [COMMENT '…']`, `ALTER … SET (limits) | SET COMMENT | SET
  DEFAULT | DROP DEFAULT`, `DROP [IF EXISTS]`, `GRANT | REVOKE RESOURCE GROUP g TO | FROM ROLE r`). A function spec is
  its path's key, a one-part name no bare word could be (`"||"`, `"IS DISTINCT FROM"`) in double quotes, then `TABLE` /
  `SCALAR` as written - what `ParseFunctionSpec` reads, as the compiler's `FunctionSpecText` wrote it; a platform
  function takes no kind (refused). The limits are `TextKind::LIMITS`, read by the compiler's `ResourceLimitsJson`, and
  a value list: a string continued on the next line refused. Fixed with the move (3f's reviews): a function spec is read
  as duckdb reads a qualified name - `ParseFunctionSpec` reads its parts with `QualifiedName::ParseComponents` (a word
  or a double-quoted name, `""` a quote), a kind only as a last word after any space outside quotes, an unquoted part
  plain (a space only - no apostrophe, parenthesis, tab, line break or control character), a part never empty nor with
  an edge space, a trailing dot refused; the rule writes each part double-quoted. The old reader cut text: a space in a
  qualified name's last part ended the name at a kind word (`system.main."read_csv TABLE"` stored the table function
  read_csv, as the compiler's `Dotted` did), a quote was kept in a part, an edge space trimmed, a trailing dot dropped -
  and a category's member with a quoted part (`DROP (system.main."lower")`, what the DBeaver editor writes) dropped
  nothing, silently; `category` alone is refused (a category's forgotten name read as a grant of a function `category`);
  `ALL ROLES` on an object grant and a platform grant refused where read (the call refused it after the batch's earlier
  statements ran); a limit written twice refused (the last won). Changed: comments inside the forms after their first
  words (one after `DENY` / `CREATE` / `ALTER` / `DROP` is 3g's classification); `""` the tokenizer's; a quoted part
  touching the next word (`"lower"TABLE`) refused; DEFAULT / COMMENT each once and the platform grant's clause or kind
  refusals are the old refusals in new words. After 3f no family of this repository is the compiler's - the legacy path
  (`AclMgmtLegacy`, `CompileMgmtText`, `LegacyUnreadable`) serves hugr-node's registered forms until 3g, and its tests
  are hugr-node's.
- 3g, in three PRs (the owner, 2026-11-04):
  - 3g-1 (built): the batch's classification on duckdb's tokens - `ReadStatementHeads` (acl_mgmt_grammar.cpp:
    `CompiledGrammar::DefaultGrammar()`'s tokenizer, never throwing, the statements as it ends them) hands each
    statement's first tokens (a word, a quoted name, a digit-led number, a plain string, other) to `IsMgmtHead`, the decision table
    `IsMgmtStart` read off the text; `StartsWithMgmt` / `BatchHasMgmtStatement` / `BatchIsAllMgmt` /
    `RefuseRepeatedPrefix` / `IsSecretsStart` read the heads, and `SplitBatchText` / `IsMgmtStart` / `CommentEnd`
    go. Changed: a comment between a form's first words is gone (`CREATE /* c */ ROLE`, `DENY -- …⏎FUNCTION` were
    sent to duckdb as native SQL), a quoted name after `ANALYZE VIRTUAL` is ours, a `;` ends a statement where
    duckdb ends one - inside parentheses too, and not inside a `$1$…$1$` duckdb does not read as a string (a
    query batch with a management statement after such a `;` is the mixed batch refused), an `E'…\'…'` string or a
    backtick name holding a `'` no longer misleads the split (it refused such a query as mixed); the first statement
    after the prefix is judged for a second `ACL` too (`ACL ROLE "r" ; ACL …`, `ACL ROLE "r" ACL ACL …`). Fixed by
    the reviews: a digit-led name (`FUNCTION CATEGORY 1x`, the tokenizer's number then word) is a name;
    `DROP FUNCTION category CASCADE | RESTRICT` is duckdb's DROP of a macro (the scan read it as ours, dropping the
    category `cascade` - a category of that name is dropped quoted); the Flight door's command detection
    (`ClientTextIsMgmt`) reads the client's text as the override does behind the door's prefix - duckdb's normalized
    text (a Unicode space is a space), the markers a client writes itself as the prefix rule reads them (`TRACE |
    PARENT <value>`, `LINEAGE` then its repeated parts, a value '…' or "…"), its `ACL` marker (management unless
    NATIVE follows: it compiles or is refused at Prepare), an empty statement - and its other checks (a platform
    call, a client's SET / CREATE / DROP / ALTER) read the text past those markers - so a
    management statement the door missed (`REVOKE<NBSP>CATALOG …`, `ACL/* x */REVOKE …`) no longer ran only at DoGet, lost by
    a client that never fetched (spec 111); a GRANT / REVOKE SECRET batch's statements are checked where its
    scanner stands (the heads of the whole rest per statement made it quadratic) - a comment in it is refused
    until 3g-2.
  - 3g-2, in parts (one PR each):
    - 3g-2a (built): `GRANT | REVOKE SECRET n TO | FROM ROLE | GROUP p [FROM | IN c]` (spec 082) are rules
      (`AclGrantSecret` / `AclRevokeSecret`, `MgmtParsed::secrets` - the service's call, not an acl_* one);
      `ParseSecretsBatch` reads the batch by them and `CompileSecretsStatement` builds the service's table call as
      before; the hand reader (`ParseSecretsStatement`, `SecretsName`, `AdminScanner::AtSemicolon`) goes. Changed:
      a comment between the words is a space (and a Unicode space or a zero-width one separates words, as everywhere
      duckdb's tokenizer reads - `r<ZWSP>in<ZWSP>ternal` is the principal `r` and the service `ternal`); the secret's
      name and the principal are NameValues (dotted words too), the service one name (`StringLiteral / AclName` - a word, `"…"` or `'…'`; a
      dotted one quoted, `IN "a.b"`); `""` is the tokenizer's refusal, `''` refused for each (it named the attached service, or sent
      `role:`); a literal not written plainly (`E'…'`, `$$…$$`, a backtick name, a continued string, a non-ASCII bare
      word) is refused - in the rules' words for the name and the principal, in the form's for the service; a statement of a secrets batch that is not a secrets one is the batch's
      refusal (`… holds GRANT / REVOKE SECRET statements only` - the compiler never runs there), a GRANT / REVOKE
      SECRET not read as its rule its form's (`RefuseSecretsForm`); one inside a management batch, read or not, goes
      in a batch of its own.
    - 3g-2b (built): `USE [SCHEMA]` (spec 114, `UseSchemaAsSet`) - sugar over duckdb's USE in a query batch (and the
      Flight door's command check), compiled to `SET acl_use_schema` / `SET schema` - is read on duckdb's tokens
      (`ReadStatementHeads`; `HeadToken` carries each token's text and whether it is unterminated, and the reader says
      whether the text ends inside a comment): one statement, `USE`, `SCHEMA` unless a `.` follows it (`USE
      schema.x` is duckdb's USE of the catalog `schema`), then parts - a word (a digit-led one: the tokenizer's
      number then word, written together) or a `"…"` as written - joined by `.` with any space around it. A number
      token holding a dot (`.2024`, `2024_01.`, `1.e5` - the tokenizer reads a dot next to digits into a number; digits,
      `_` and an exponent's `e`, never a sign) is split at its dots, so a digit-led part stands anywhere in the path
      (`raw.2024`, `mart.out.2024`, `mart.2024_01`, `out.1e5`); a signed number (`1e-5`) is no part. The hand scanner goes. `Prefixed` reads the batch's heads once (the classification's
      checks take them, `UseSchemaAsSet` runs only for a batch that is one USE). Changed: a text ending inside a
      comment is left to duckdb, which refuses it (the reader dropped the open comment, compiling what came before
      it); `;;` after the USE, a word holding `$` and the comment forms duckdb reads otherwise than the scan (`--`
      ended by `\r`, nested `/* */`) now read as duckdb reads them; a backtick name stays duckdb's.
    - 3g-2c (built): `ATTACH … LINEAGE '<x>'` (spec 112 §9, `acl_attach_lineage.hpp`) - sugar over duckdb's ATTACH,
      compiled to the native ATTACH and `acl_lineage_source(alias, x)` - is read on duckdb's tokens: the batch's
      statements as the tokenizer ends them (`ReadStatementHeads(text, 1, &open, 2)` - each by its first token and
      its last two, a token's `index` its place), the marker an ATTACH's last two tokens - the word `LINEAGE` and one
      plain closed `'…'` literal - and each statement's text its first token to its last; the runtime's
      `AttachLineageIdentity` reads the same way. The hand splitter goes (`MayCarryAttachLineage`, a substring test,
      stays the fast path). Changed, each now as duckdb reads it: a `$$…$$` / `$tag$…$tag$` string and a backtick
      name are one token (a `;` or the marker's words inside them split or marked the batch); a `--` comment ends at
      `\r` (the splitter ran on to `\n`, dropping a statement or missing a marker); a nested `/* /* */ */` is one
      comment (the splitter ran an ATTACH inside it); words the tokenizer joins (a control or non-ASCII byte beside
      `LINEAGE`) are one; an unterminated `'…''` is no identity (the splitter took it as closed); a text ending inside
      a block comment is the native parser's, which refuses it, and one ending inside a literal or a name is split as
      read, its own parse refusing it - nothing of the batch runs either way (the splitter ran what came before an
      open comment). A statement's text no longer carries the comments around it (a view's SQL is re-rendered, a
      note's hash is its own `query`). Review fixes: the identity, read trimmed once (the parse,
      the call and the hook read one value), is judged at parse as `acl_lineage_source` judges it
      (`LineageIdentityRefusal`, one judgment for both), so a refused one attaches nothing (the ATTACH used to run
      first); the call is built as an AST (`MakeAdminCall`, declared in acl_admin_sql.hpp), never SQL text; a statement
      parsed on its own reports its error where it is in the batch (`ParseSegment`: `position` and `location`; under
      `ACL NATIVE` drawn against the rest); and under a dialect or CONNECT the sugar is off (the connection owner's
      grammar reads the text by its own tokenizer - as a prefix there is refused, nothing of ours is added to it).
      Known: a native `ATTACH DATABASE lineage '<path>'` (a typed literal of a user type `lineage`) reads as the
      marker, as it did; a grammar extension's rule that reads a `;` splits otherwise than the statements here
      (refused, nothing runs - the connection owner's grammar on an operator's path); the runtime's hook reads an
      ATTACH's text on the default tokens whatever the connection's grammar (judged where the plan is made, a dialect
      set earlier in the batch would drop what the parse declared), so a dialect's own ATTACH whose text reads so
      there names its NAMESPACE event by that literal - lineage naming only.
  - 3g-3: a linked module registers rules (`RegisterMgmtGrammar` becomes rules - hugr-node's CLUSTER forms),
    `AdminScanner` and the compiler go, hugr-node re-pins. In three steps, so neither repository is ever left
    without its forms:
    - 3g-3a (built): the seam - `RegisterMgmtRules(keyword, forms, changes, usage)` and `MgmtCall`
      (`acl_mgmt_rules.hpp`, public: a module includes it). A module's statement forms (`MgmtStatementForm`: the rule,
      the verbs after the keyword it covers, its usage) are compiled into the management grammar beside acl's own -
      each an alternative ahead of `AclMgmtLegacy`; the shared rules a module may name are listed in the header and
      kept (AclQuotedValue, AclNameValue, AclName, AclWordToken, AclDottedToken, AclComment, and the new AclValue /
      AclSignedNumber). Its transform builds the acl_* call through `MgmtCall` (`Quoted` / `NameValue` / `Name` /
      `Text` checked against their tokens as acl's are, and refusing a part they do not read; `Word`, `Keyword`,
      `Part`, `Optional`, `Each`; `MgmtStart<F>` beside it); a ParserException from it is the module's refusal, never
      "not read". The keyword makes a statement management (`IsMgmtHead`, `MgmtRulesKeyword`), and one the rules do
      not read reaches the compiler, which refuses it with the usage of the form its verb names, else the keyword's
      (a tokenizer refusal wins, as for acl's moved forms). A module reads only the statements headed by its keyword
      (`module_keyword`, checked against the statement's first token), one statement (a `;` its matcher read past is
      refused). Refused at registration - at load, never at the first statement: a keyword that is not one word of
      letters or heads acl's or duckdb's statements (or the prefix's markers), a change that is not a new rule (or a
      terminal override of one), a rule not named `Acl<Keyword>…`, a form whose statement it does not add or whose
      rule does not begin with the keyword's literal, a verb two forms name, the keyword again with other forms, the
      keyword on both seams, a registration after an instance compiled its management grammar, and rules that do not
      compile (a trial compile with the candidate, before it is registered). `Optional` / `Each` read through the
      helper rules around an optional or a repetition (CLUSTER's shared `IN GROUP`). Test
      `test_acl_mgmt_rules.cpp` (a toy module: its forms, readers, refusals, the authorizer, Flight's command
      detection, a second instance).
    - 3g-3b (built, hugr-node spec 020, hugr-node #21): hugr-node re-pins and writes its CLUSTER forms as rules (an
      option list and DEPENDS ON read by rules, not split as text).
    - 3g-3c (built): every management statement is a rule - the compiler (`CompileMgmtText`, `ParseMgmtStatement` on
      `AdminScanner`), the legacy alternative (`AclMgmtLegacy`) and the old seam (`RegisterMgmtGrammar`) go. A
      statement no rule reads (the batch reader's ParserException, statement by statement) is refused in its form's own
      words by `RefuseUnreadStatement`, chosen by its head on duckdb's tokens (`HeadWords` over `ReadStatementHeads`)
      as the compiler chose them - a module's by its usage, a tokenizer refusal still first. `AdminScanner` stays as
      the readers of a statement's lists (REQUIRE / ATTRIBUTES, a column list, a claim map, limits - handed their text
      by the rules): they become rules with stage 4, as do their checks (`JudgeListText`, `ScannerUnreadable`, once
      `JudgeLegacyText`); its members only the statement compiler used go. The batch reader stops at the first
      statement no rule reads (the batch is refused there: reading on cost a failed match - duckdb renders the batch's
      tokens for each - per statement after it, 32,000 of them 20 s); under the `ACL` marker a CREATE / ALTER / DROP
      that is no management statement says so (`CREATE TABLE is no management statement`). A differential against the
      compiler over 4,658 malformed statements lost no refusal - the words differ where a comment stood between the
      head's words (now the form's own), for `CREATE OR <noun>` and a non-ASCII letter glued to a word. hugr-node
      re-pins onto it next.
- Spec 151 comes between stage 3 and stage 4 (the owner, 2026-11-04); stage 4 also takes the bare non-ASCII words the
  rules refuse since 3b (`CREATE ROLE größe` - a word is ASCII to `IsWord` / `IsDottedText`; quoted works).

**Stage 4 - policy texts read by rules where they are written, one family per PR** (the owner's decisions of
2026-11-06 in Decided below):

- 4a (built): a NAME in a management statement - a catalog, schema, object, role, issuer, client, group, secret, a
  path's parts - is read exactly as duckdb reads an identifier (`IdentifierMatcher`'s rule, `DuckdbIdentifier` in
  the rules' matcher with duckdb's literal table and identifier mask): `"…"` or a backtick name quoted; bare, a word
  that does not start with a digit, its first character one duckdb's tokenizer keeps in a word (a letter, `_`, any
  byte past ASCII), a keyword only when duckdb lets it name a column (`user`, `schema` bare; a reserved word -
  `select`, `default` - and a word only a function or a type may be - `full`, `left`, `join` - quoted); after a dot
  any word; a function's path (`AclFunctionPath`: GRANT / DENY / REVOKE FUNCTION, ALIAS OF) reads its one part as
  duckdb's `FunctionName` does (`left`, `glob` bare). No check of ours on top (Decided 3): `CREATE ROLE größe`,
  `CREATE VIRTUAL CATALOG продажи` read bare, and so does whatever duckdb itself keeps in a bare identifier (an
  invisible character too - duckdb turns U+00A0, U+2000-U+200B, U+202F, U+205F, U+2060, U+3000 and U+FEFF outside
  quotes into a space first). A name is taken as written: a connection's `preserve_identifier_case` folds duckdb's
  identifiers, never a management statement's (a role compares exactly, and a node's policy must not depend on the
  connection that wrote it). Newly refused bare, as duckdb refuses them: such a keyword (`CREATE ROLE "full"`, the
  legacy wrappers' catalog `"default"`) and a leading digit (`ISSUER "v1.2"`, `objects."9t"`) - what is stored
  under such a name keeps working, only its statement quotes it, and the refusal says so (`NameHint`: the token the
  parse stopped at, `… - full is an SQL keyword: a name spelled so is written in double quotes ("full")`). A name
  that is a value (an issuer, client, group, secret, `AclNameValue`) keeps stage 3's reading of bare words joined by
  dots as one name (`kc.local`), never a word, a dot and a quoted part (`a."b"` is no name); a backtick one is a
  quoted one there too. A VALUE (a scope, a level, a setting's value, a capability) stays the scanner's word
  (`true`, `v1.0`, `4GB`; a capability a word or a quoted one - `select` is a keyword). A name offered back to paste
  is quoted as duckdb's writer quotes it (`NamePath::ToGrammar` = `KeywordHelper::RequiresQuotes`, capitals allowed:
  `c."old"`, `"größe"`; the same in a message that suggests a statement). Found by its reviews: `REVOKE CATALOG …
  FROM ROLE <a name that only looks like the role's>` answered success and left the grant - EVERY revoke of nothing
  is refused now (`ThrowNothingToRevoke`: catalog, schema, resource group, function, function category, platform's
  point grants and sources, `REVOKE ADMIN` without a scope; REVOKE TABLE and a scoped REVOKE ADMIN were already);
  whether a column expression is a plain rename (`RenameOnlyColumns`) and a key column (`BareIdentifier`) are
  duckdb's parser's reading (`PlainColumnName`: one token of the text the parser reads, one column reference of one
  part, no alias - `x = größe` stays a writable rename, `x = (b)`, `x = "b"` and `` x = `b` `` stay read-only; duckdb's
  special values `current_date`, `user` parse as column references and stay renames, as before 4a); the listings'
  by-name test reads a word as duckdb's tokenizer does (no ASCII punctuation but `_`, `$` not first). Look-alikes
  (Cyrillic `а`, a modifier letter like `ʼ`, a decomposed `ö`) are different names - every rights check compares
  names exactly, so one never reaches another's rights; a GRANT or DENY to a role nobody defined is accepted (a role
  may come from claims alone); security.md says what an operator should look for. hugr-node's rules use the same
  matchers; the DBeaver plugin's composer quotes the same words (acl-clients).
- 4b: resource group limits as rules (`ResourceLimitsJson` and `TextKind::LIMITS` go).
- 4c: a client's REQUIRE / ATTRIBUTES / claim map and the ITEMS lists as rules (`AdminScanner` goes - its words are
  ASCII, so `REQUIRE (größe = 'x')` is refused until then while `ROLES FROM (größe)` reads).
- 4d: a role's claims list as rules, and one reader of a list's text for the quoted form and the function forms.
- 4e: a grant's column list: a mask read by duckdb's `Expression` rule (`[ ]`, `{ }`, `MAP`, lambdas as duckdb
  takes them), and the stored list split on duckdb's tokens instead of `SplitTopLevel`'s counter (a top-level comma,
  the first top-level `=`) - both sides lex as duckdb does; a differential test pins that the rule's items are what
  the stored text reads back as. The other readers of a stored list follow (`acl_platform_list`, the lineage tags,
  the listings' copy of `ParseFieldPath`), and `ParseFieldPath`'s bare word is duckdb's identifier, as 4a's.
- 4f: a relation's column list (`AS`, the NULL marks) the same way; `UnquoteColumnsList`, `JudgeListText`,
  `ScannerUnreadable` go.

**Hand-written readers left outside stage 4** (the owner, 2026-11-06: reuse duckdb's grammar wherever it applies -
an inventory of `src/`, each with its verdict; the REPLACE ones are the next work after stage 4):

| Reader | Text | Verdict |
|---|---|---|
| `KeyStatements` (acl_catalog_admin.cpp) | `PRIMARY KEY (…)`, split on `,` | replace: a rule (a quoted key column holding a comma is split) |
| SET TYPES (acl_catalog_admin.cpp) | `aliases = …, enums = …` | replace: a rule |
| `ParseDeclaration` / `DeclaredTypes`, `StripDeclarationNullability` | RETURNS TABLE, parameter types | replace: duckdb's `ParseColumnList` (a `,` split breaks `DECIMAL(10, 2)`, `STRUCT(…)`) |
| `SplitParams` (acl_principal_functions.cpp) | a stored macro's parameters | replace: read once at write (a `CREATE MACRO` probe) |
| REFERENCE arguments / `ON` pairs (`SplitPair`) | `param => col`, `a = b` | replace: rules |
| category members (`SplitTopLevel`), the function spec's kind word | `[db.schema.]name [TABLE]` | replace in the statement form (a rule); the function form keeps `QualifiedName::ParseComponents` |
| `SplitIdentifierPath` (acl_rewriter.cpp) | a USE value | replace: `QualifiedName::ParseComponents` |
| `ExtractStreamIdFor` (acl_parser_override.cpp) | a drain's raw INSERT | replace: the constant from the AST parsed right after |
| `GetTableNames` output cut at ` as ` (acl_catalog_admin.cpp) | a body's table names | replace: `BodyTables` (the AST walk) |
| `SplitProjectionItem` (lineage) | our own `expr AS "name"` | replace: carry the pairs |
| `TextNamesPolicyStore`, `SqlNamesSource` | view / macro bodies | keep: they over-read on purpose, string literals too (`query_table('acl.admins')`) |
| `ParseFieldPath` | `a.b`, `items[].x` | keep (duckdb has no `[]` path); its word reads as duckdb's identifier in 4e |
| the first-word ACL check, `MayCarryAttachLineage`, `CallsFunctionNamed` | every query | keep: prefilters before the real read on tokens |
| keys (`NamePath`), JWT, base64, URLs, `\x1f` serializations, JSON | not SQL | keep |

**Decided**

1. Stored policy rows are text by contract (read back and pasted). The owner, 2026-11-06: the rules read a policy
   text where it is WRITTEN (the statement's lists, the function forms' text arguments); the stored row stays the
   text as written - no parse at read, no row emitted from a tree - and spec 148's check stays. So the read side keeps
   reading the stored text (`ParseColumnList`) - split on duckdb's tokens since 4e (decision 2); a write-side rule
   and it must split one list alike, which stage 4's tests pin.
2. A mask with a list / struct literal (`COLUMNS (tags = ['a', 'b'])`, `{'k': 1}`) works as in duckdb (the owner,
   2026-11-06: "что бы работало так же") - by duckdb's own grammar and tokenizer, not a second hand-written one.
3. A name in a management statement is read exactly as duckdb reads an identifier (the owner, 2026-11-06: "Ровно
   как duckdb") - no check of ours on top. It replaces the same day's "Unicode letters and digits only", which
   refused what duckdb reads (a format character, a decomposed spelling) and read what duckdb refuses (`full`, `9t`).

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
