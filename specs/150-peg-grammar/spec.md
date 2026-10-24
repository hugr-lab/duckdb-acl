# Spec 150: our grammar on the PEG parser - no statement text parsed by hand

- **Status**: accepted; stages 1 and 2 implemented, 3 and 4 to come
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
