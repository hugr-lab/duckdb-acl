# Spec 132: grammar extensions under the ACL - what the API gives us

- **Status**: implemented (uses 1 and 2, accepted by the owner 2026-10-15; 3 and 4 are follow-ups)
- **Date**: 2026-10-15
- **Author**: the agent, at the owner's ask ("давай откроем и посмотрим что полезного мы получим от грамматики")

## Summary

duckdb has had an extension-facing grammar API since 2026-09-04 (#24919, `79469d161a6`). It reached our pins at
eb0d9df, so spec 067's condition for reopening was met then; our pin checks missed it until the 7304f7b bump
(spec 131).

An extension registers a `GrammarExtension`. Its changes (new rules, edited choices, transforms) produce **ordinary
AST**. A connection opts in with `SET active_grammar_extensions = [...]`, and the setting is per connection only.

This spec records what that means for acl. It proposes two things for now, both tests and documentation of what is
already true. Two larger uses wait.

## What the API is (at 7304f7b)

- **Registration**: `GrammarExtension::Register(db, extension)`, from Load. A name is unique, and nothing unregisters.
- **Changes**: `GetChanges()` returns `GrammarChange`s, applied in order to the default grammar.
  - A change can add a rule, add or prepend a choice, remove or replace one, or replace a whole rule or its
    transform.
  - A terminal can be overridden only if it is new: the built-in ones (identifier, string literal) cannot.
  - No core rule is protected.
- **Transforms**: a transform builds the AST, reusing the core transforms (`transformer.Transform<T>(child)`).
  - At the statement level the result is a `unique_ptr<SQLStatement>` of an existing class. That includes
    `ExtensionStatement`, `MultiStatement` and `PassthroughStatement`.
  - There are no new statement types or node kinds.
  - The grammar still yields one statement per top-level statement.
- **Activation**: `active_grammar_extensions` is per connection. `SET GLOBAL` throws, and a registered extension
  changes nothing until a connection lists it.
  - Precedence on a connection: a CONNECT grammar, then `current_dialect`, then the active list, then the default.
  - Compiled grammars are cached per instance, keyed by the ordered list (16 entries, LRU) and immutable. One
    connection's choice never reaches another.
- **Order in `Parser::ParseQuery`**:
  1. The `parser_override`s run first on the raw string. That is ours, so we still see and can replace everything.
  2. Then PEG with the connection's grammar.
  3. On a parse error, the peelers.
- **Our inner parse** copies the caller's `ParserOptions` (`acl_parser_override.cpp`), `compiled_grammar` included.
  The remainder after the prefix therefore parses with the connection's grammar.
  - The duckdb CLI activates its own `shell` grammar at open, so under a prefix a bare `tbl` is already
    `SELECT * FROM tbl`, walked like any SELECT.
  - Templates and stored bodies parse with `ParserOptions::Builtin()`, the default grammar.
- **Stability**: no "experimental" marker, but the transform contract changed three times in six weeks (59533c8
  09-03, ddd8d5d 09-24, d84515a 10-12). Transforms also depend on core rule names and child positions, which this
  bump edited.

## What it gives acl

| # | use | what it takes | value | proposal |
| --- | --- | --- | --- | --- |
| 1 | **Foreign syntax we can confine.** A grammar extension active on the connection produces ordinary AST, and our inner parse uses that grammar. Under a prefix, the AST is walked and gated like any statement. A peeler's opaque `ExtensionStatement` stays denied (spec 067). | tests | other extensions' syntax works under the ACL, confined, not refused | **now**: a fourth row in spec 067's contract, pinned by tests |
| 2 | **Who chooses a principal's grammar.** The connection's owner (gateway, door, operator) chooses it, never the principal: the setting is per connection, and `SET` under a prefix is refused except `TimeZone` / `Calendar` (spec 068). | tests, a line in the docs | the meaning of a principal's SQL is not the principal's to change | **now**: refused under every prefix, by test |
| 3 | **Completion for `ACL …` in the duckdb CLI.** A completion-only `acl` grammar extension (`['shell','acl']`). The override still parses `ACL` text before PEG runs. | a second description of the management grammar, kept in step with the scanner | the CLI's `sql_auto_complete` only; DBeaver and JDBC complete on their own | **later**, if CLI completion is wanted |
| 4 | **The prefix and the management grammar as PEG rules.** The override would parse with a grammar of its own (`CompiledGrammar::Create` with our extension, cached by us), replacing the hand-written scanner (`acl_admin_scanner.hpp`). | a rewrite of a working scanner, against an API still moving | error positions; one grammar for parsing and completion | **after v2.0.0**. The override stays the gate either way: activation is per connection and can be RESET |

## Enforcement & security

- **An active grammar can change what ordinary SQL means.** duckdb's own test makes `SELECT 1` return 7 through
  `SetTransformProcess("AdditiveExpression")`. Only the connection's owner can activate one, and whatever it produces
  is AST that we walk or deny.
- **A principal cannot activate one.** The setting is LOCAL, and SET under any prefix is refused but the spec 068
  allowlist. The tests in #2 pin this for `ACL ROLE`, `ACL TOKEN` and `ACL SESSION`.
- **A CONNECT-ed connection** parses into `PassthroughStatement`, which the statement gate denies (fail closed).
- **Not proposed: pinning a principal's inner parse to the default grammar.** The grammar is the connection owner's
  choice, and a pin would break the extensions a deployment relies on (the CLI's `shell` grammar, for one).
  `ACL NATIVE` keeps the connection's grammar too, as break-glass does today.
- **To review when this is built**: the judgments we derive from statement **text** rather than AST, which an active
  grammar could make diverge:
  - the profile note's text hash (spec 074);
  - the client's text in Flight's command test (spec 111, 114);
  - `SplitBatchText` (spec 117).

## Testing (the "now" part)

`test/cpp/test_acl_foreign_parser.cpp` registers a small grammar extension in the test's database: a statement rule
whose transform builds a `SELECT * FROM <table>`, and a second rule that yields an `ExtensionStatement`.

- **Bare**: the rule works.
- **Under `ACL ROLE`**:
  - the produced SELECT is rewritten: a virtual name resolves and a grant's RLS applies;
  - a table the role cannot see is refused;
  - the `ExtensionStatement` rule is denied.
- **The setting**: `SET active_grammar_extensions = [...]` is refused under `ACL ROLE`, `ACL TOKEN` and
  `ACL SESSION`, and so is `SET current_dialect` (a `DialectExtension` is chosen the same way).
- **Under `ACL NATIVE`** with passthrough: both rules work.

Spec 067 gets an addendum: the API exists, and its contract gains the fourth row.

## As built

- **Code**: no change; uses 1 and 2 were already true, and the tests pin them.
- **`test/cpp/test_acl_foreign_parser.cpp`** registers two grammar extensions, `acl_test_pipe_where` and
  `acl_test_honking`, and activates them on the connection.
  - `ACL TOKEN 'tok' FROM orders_rls |> WHERE id > 1` answers acme's row 3 only: the grant's RLS applied to what the
    grammar built.
  - `FROM orders |> …` keeps the grant's one column. A hidden column (`Referenced column "tenant" not found`) and the
    physical name (`no access to object`) are refused.
  - `HONKING` is denied as `statement type EXTENSION`.
  - Both `SET`s are refused under TOKEN, ROLE and SESSION, while the session's `SET TimeZone` still passes.
  - Under `ACL NATIVE` with passthrough, both statements run.
- **Build**: the Makefile adds `third_party/utf8proc/include` to the C++ tests' include path, because the PEG headers
  need it.
- **Docs**: `security.md` describes grammar extensions under the prefix, and spec 067 has an addendum.

## Alternatives considered

- **Wait for v2.0.0 for all of it.** Uses 1 and 2 cost only tests, and they pin a promise that is already true
  today.

## Follow-ups

- The pin-bump check looks for the API's presence (`GrammarExtension::Register`), not only a change in
  `GetMatcher`.
- Uses 3 and 4, as above.
