# Spec 067: The PEG world — foreign syntax under the prefix, and where our parsing stands

- **Status**: implemented
- **Date**: 2026-09-03
- **Author**: hugr-lab

## Summary

DuckDB's PEG parser is no longer the future — at the commit we track (and on live `main`) it *is*
the parser, and the extension surface around it has settled into three mechanisms: `parser_override`
(ours — sees every query string, pre-parse), the **token peeler** (`parse_function` — called with
the token tail when PEG fails on a statement; what it claims becomes an opaque `ExtensionStatement`
planned by its own extension), and grammar-extension registration (rules + transforms producing
ordinary AST — built upstream, **not yet exposed to extensions**). This spec records where that
leaves our three concerns — surviving future versions, letting other syntax-extending extensions
work under the ACL prefix, and the cost of our own parsing — and pins the foreign-syntax semantics
with tests, because they were true but nowhere written down as a promise.

## Problem

Three questions, asked together as "the PEG story":

1. **Does our foundation survive the parser transition?** Everything we enforce rides on
   `parser_override` receiving every query string and returning real `SQLStatement`s.
2. **Does another extension's syntax work inside the ACL prefix?** A gateway prefixes *everything*,
   so syntax the prefix cannot carry is syntax the deployment loses (design/005: duckpgq's
   `GRAPH_TABLE` was the motivating case).
3. **Is our parsing paying anything it does not have to?**

None of this was covered by tests: the answers were facts about the code, one stale comment, and two
local research notes (design/011, design/014).

## Design — what is true, now pinned

### 1. The foundation stands (and is load-bearing upstream)

The PEG parser is duckdb's parser at our pin; the whole suite, the doors and the distribution matrix
already run on it. `parser_override` is intact in the contract, runs *before* the PEG parse on the
whole string, and upstream plans to ship the legacy PG parser through the very same seam — it is
load-bearing for them, not a compatibility shim for us. STRICT semantics (spec 017) are unchanged.
Nothing to port today; the tracked pin (memory: bump it periodically, run everything) is the early
warning if the contract moves before 2.0.

### 2. Foreign syntax: a three-way contract, one per trust level

Our override re-parses the prefix remainder with the caller's own `ParserOptions` — the extension
list and the compiled-grammar cache ride through. That makes the semantics *per mechanism*:

- **Bare (no prefix)**: loading acl costs nobody anything. Our override declines what it does not
  recognize, the peel loop proceeds, a co-loaded extension's peeler works — including mid-batch
  (`honk honk; SELECT 42` peels and resumes).
- **Inside the prefix (the virtual context)**: a peeler's claim becomes an `ExtensionStatement` —
  planned by *its* extension, opaque to us. The rewriter's statement gate default-denies it:
  `statement type EXTENSION is not permitted under ACL`. This is not a limitation to apologize for;
  an AST we cannot enumerate is an AST we cannot confine, and refusing it is the only honest answer
  (design/005's reasoning, now enforced by test).
- **Under `ACL NATIVE` (passthrough)**: works. Foreign parser_overrides are deliberately left on
  there (design/005 path 1, implemented since), and the peeler needs no enabling at all. NATIVE
  rewrites nothing and requires a granted passthrough scope, so foreign syntax is exactly as
  privileged as the plain SQL that scope already runs — and the gate fires on the *scope*, never on
  the syntax (a principal without one is refused before the parse matters).

### 3. Grammar extensions: the door we are waiting on, ready-shaped

Upstream has built rule overrides, a versioned parser cache and grammar invalidation — and still
constructs the default grammar internally: **no extension-facing registration exists** (re-verified
2026-09-03; the `add_parser_change_extension_api` cherry-pick of 2026-08-31 is internal plumbing).
When it lands:

- statements built from extended grammar arrive as **ordinary AST**, which the rewriter walks node
  by node — known nodes rewritten, unknown nodes denied — through the very same inner parse,
  unchanged: the fail-closed default extends to grammar extensions by construction;
- our own prefix becomes a grammar rule (`AclStatement <- 'ACL' … Statement`, proven by the
  design/014 spike), the ~200-line hand scanner is deleted, parse errors improve — its own spec;
- the versioned cache means our inner parse picks up an instance's extended grammar automatically
  (`options.parser_cache` passes through).

The sharpened upstream question (design/011/QUESTION.md: the registration API's form, and the
multi-statement transform contract whose current shape silently drops a batch tail) is ready to
post; posting it is the lever for all of the above.

### Parsing cost, measured against what it could be

One parse per statement (ours adds a prefix scan of the head, not a re-parse); the inner parse
shares the instance's compiled grammar through `options.parser_cache` (no recompilation, ever);
rewrite templates are parsed once and copied (`TemplateCache`). The one real economy waiting —
deleting the hand scanner — is the grammar port above. Nothing else worth optimizing was found.

## Enforcement & security

- **Default-deny is the whole mechanism**: the statement-type gate refuses `EXTENSION_STATEMENT` in
  the virtual context (it cannot be enumerated), the node/table-ref gates refuse unknown AST forms —
  so both today's peeler and tomorrow's grammar extensions fail closed with no new code.
- **`in_acl_parse` self-refusal**: our override declines its own inner parse, so a nested
  `ACL … ACL …` prefix stays text (pinned in acl_admin_scopes.test).
- **NATIVE adds no authority**: foreign syntax there is gated on the passthrough scope, which
  already means "runs arbitrary SQL outside the virtual catalog".
- **Golden rule untouched**: no parsing change; this spec pins semantics and refreshes one comment.

## Testing

`test/cpp/test_acl_foreign_parser.cpp` — a toy peeler extension (`honk honk honk`, modeled on
duckdb's own loadable_extension_demo) registered the way any co-loaded extension registers itself:

- bare toy statement answers (3 rows), and a mixed batch peels and resumes;
- under `ACL TOKEN … ` it is refused with `statement type EXTENSION is not permitted under ACL`;
- `ACL NATIVE` without an admin scope is refused on the scope, never the syntax;
- with `passthrough` the same statement answers through NATIVE — and the virtual context still
  refuses it for the same principal.

Existing pins that complete the picture: nested prefix (acl_admin_scopes.test), the CONNECT gate
(acl_statement_gate.test), the full suite + distribution matrix running on the PEG parser.

## Alternatives considered

- **Enable foreign parser_overrides in the virtual context too**: rejected (design/005) — an
  override hands back arbitrary AST, and letting foreign AST into the rewrite path is how a
  reference gets missed. The peeler needs no such enabling and is safe by its opacity.
- **Port the prefix to a grammar rule now, against internal APIs**: rejected — the spike needed
  `#define private public`; nothing extension-facing exists to build on. Wait for the hook.
- **A per-extension allowlist for ExtensionStatements under the prefix**: rejected — an opaque
  statement is unconfinable regardless of who produced it; trust belongs to the scope (NATIVE), not
  to the extension.

## Follow-ups

- **Post the upstream question** (design/011/QUESTION.md) — the gate to the grammar port.
- **The grammar port itself** (prefix-as-rule, hand scanner deleted) — its own spec, when the
  registration API lands.
- **design/005 paths 2–3** (a property graph as a virtual-catalog object; a reference-enumeration
  contract for foreign AST) — unlocked, not obsoleted, by grammar extensions: extended grammar that
  produces *custom* nodes still needs enumeration to pass the gate.
- `DialectExtension` appeared in the same registration surface upstream — watch what it becomes
  (QUESTION.md already asks; an opt-in dialect that can bypass rewriting would concern us).
