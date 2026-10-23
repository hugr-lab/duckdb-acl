# Spec 150: our grammar on the PEG parser - no statement text parsed by hand

- **Status**: draft (stage 1, the prototype, in progress)
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
the override never depends on it: it adds the rules itself when the connection has not switched them on, and uses
the connection's grammar as is when it has. Not switched on, nothing changes for a bare statement (spec 067's first
row). Switched on, `sql_auto_complete` offers `ACL`, then `ROLE`, then the statements; a prefixed text that reaches
duckdb's own parser - the override set to `DEFAULT` - parses to our statement and is refused at bind (acl's parser
extension plans nothing). Spec 132's grammar extensions keep working under the prefix: the inner statements are parsed
by the same compiled grammar, which includes them.

**A connection with a grammar of its own choosing.** `CONNECT` binds a connection to a remote catalog and forwards its
statements there; it is the connection owner's native mode (the owner, 2026-10-23), refused under every prefix
(`statement type CONNECT is not permitted under ACL`, also `DISCONNECT`). A prefix on a CONNECT-ed connection, or under
a dialect (`current_dialect`, refused under a prefix since spec 132), is refused from stage 2 on: nothing of ours can
be added to their grammars, and nothing there runs as a principal. Stage 1 leaves both to the scanner.

**What the rules yield.** A rule's transform (`std::function<arena_ptr<TransformProcess>(PEGTransformer &,
ParseResult &)>`) returns typed results. duckdb parses a text one top-level statement at a time, so the prefix rule
is a choice of `Statement` and yields one statement of ours, an `ExtensionStatement` of acl's parser extension. It
carries the principal, the markers and the statement behind them; the statements after it in the batch are the
prefix's too, and a second prefix among them is refused. The override verifies the principal and rewrites the statements, as it does today
from the scanner's output. A management rule yields the compiled call it compiles to today, so the authorizer and the
admin functions do not change.

**Batches.** A prefix covers a statement list, as today:

- one prefix;
- every statement is decided and rewritten before any runs;
- the same refusals: a second prefix, management mixed with queries, and `USE` without a session of the client's own.

What a batch answers stays duckdb's: the first row-returning result, then the chain. The quack door answers as native
quack does (the same collector), and Flight refuses a batch at Prepare. Owner, 2026-10-23: keep both.

**Stages**

1. A prototype: the prefix `ACL ROLE "r" <statements>` as a rule beside the scanner, behind a setting. It answers the
   open questions below and measures the parse; the owner decides the shape.
2. The prefix and its markers move; the scanner goes.
3. The management statements move, one statement family per PR; the compiled calls stay unchanged.
4. Policy texts become rules and stored rows are emitted from trees; `ParseColumnList` / `SplitTopLevel` go.

**Stage 1, measured (2026-10-23)** - `acl_grammar.{hpp,cpp}`, behind `acl_peg_prefix` (GLOBAL, off):
`AclPrefixedStatement <- 'ACL' 'ROLE' AclPrincipalValue AclTraceMarker* Statement`, prepended to `Statement`, taken
by the override for a role prefix in query mode (LINEAGE, the `ACL [NATIVE]` markers, `USE SCHEMA` and management
stay the scanner's in this stage; the scanner's text checks still run first).

- With the rule on by default, the whole sqllogictest suite (129 files) and `make test-cpp` (29) pass. Two PIVOT files
  failed at first: the rule must take the statement's pivot entries itself and clear them, or the top level wraps
  the prefix in them again. The role and the markers never differed from the scanner's.
- `acl` stays a name: a rule keyword that is no keyword of duckdb's reserves nothing (`SELECT acl FROM acl`).
- Cost: 5,000 prefixed statements 1.04-1.06 s against the scanner's 1.02-1.12 s - no difference past noise; the
  first statement compiles the grammar, about 2 ms, once per set of the caller's grammar extensions.
- Found in building it: a helper rule without a transform cannot be transformed (the transform descends to the base
  rules - `StringLiteral`, `Identifier`); a token rule (`QuotedIdentifier`) cannot be named from a rule (it is a
  regex), so "quoted only" is judged on the token in stage 2; the inner statement's text, a CREATE's `sql` and the
  named parameters are set by the rule's caller, not by duckdb, for a statement inside a rule.
- Completion: with `SET active_grammar_extensions = ['acl']`, `sql_auto_complete('AC')` offers `ACL`, `'ACL '` offers
  `role`, and after the prefix the statements; a rule's keywords are suggested unless the rule suppresses them.

**Open questions**

1. Errors and completion: the parser's error positions and suggestions for `ACL …`.
2. Stored policy rows are text by contract (read back and pasted). Either parse them with the rule at read and emit
   the tree, or keep spec 148's check.

## Enforcement & security

- **One reader.** The text is parsed once, by duckdb's parser with our rules. The prefix, the markers and the
  statements are the parse tree's, so there is no second reading to disagree with.
- **Fail closed.**
  - The override still claims every text (`STRICT`), and a parse that fails is a refusal, as now.
  - The grammar is active only inside the override. With the override off (`DEFAULT`), an `ACL …` text is a parse
    error, as today.
  - Our statement never leaves the override unrewritten. If one ever reached the binder, it would fail there: acl's
    parser extension plans nothing.
  - A rule never yields a statement the rewriter has not seen.
- **Nothing widens.** Every refusal the scanner makes is kept: a second prefix, a mixed batch, `USE` without a
  session, foreign syntax under the prefix (spec 067's three rows and spec 132's fourth). The tests pin them before the
  scanner goes.
- **The golden rule holds.** A rule adds no parameters; a client's `$1` / `?` stays the only parameter.

## Testing

- Every existing grammar test passes unchanged at each stage, since the grammar is the same language.
- Before stage 2, tests pin the batch behaviour: the gateway answers the first row-returning result, the quack door
  answers as native quack, and Flight refuses a batch.
- Negative tests cover what the hand parser accepted and the rules refuse.
- The prototype is compared statement by statement with the scanner over the suite's prefixed statements.

## Alternatives considered

- **Keep the scanner and harden it.** The disagreement class stays, and every new form needs both readers kept in
  step.
- **Register the grammar and switch it on per connection** (`active_grammar_extensions`). A connection owner could
  switch it off, and every door and gateway connection would have to set it. Compiling it inside the override needs
  neither.

## Follow-ups

The DDL follow-ups (`SELECT acl_register_* / acl_rename_relation / acl_drop_relation(…)`) are answered to the client as
a result:

- the column header names the physical object, and a view's carries the rewritten body;
- on quack, the follow-up takes the batch's answer from the client's own SELECT.

Owner, 2026-10-23: this is fixed after 150, as its own spec.
