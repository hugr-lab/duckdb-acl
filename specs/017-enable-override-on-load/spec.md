# Spec 017: the extension enables its own parser override

- **Status**: implemented
- **Date**: 2026-08-20
- **Author**: hugr-lab

## Summary

Every bit of enforcement lives behind the parser override, and duckdb skips overrides entirely while
`allow_parser_override_extension` sits at its default — so loading the extension without that `SET`
leaves it inert. The extension now turns the setting on when it loads (as duckpgq does), and the
admin entry points refuse to configure a policy that cannot be enforced.

## Problem

```sql
LOAD acl;
SELECT acl_use_db('aclcat', 'acl', true);      -- works
SELECT acl_grant_catalog('analyst', 'sales');  -- works
ACL ROLE "analyst" SELECT * FROM orders;       -- Parser Error: syntax error at or near "ROLE"
```

The split is sharp and worth naming: the `acl_*` functions are ordinary scalar functions and keep
working, so **policy can be configured** — while nothing can be **enforced**, because no `ACL …`
statement parses. `Parser::ParseQuery` skips every extension whose `parser_override` is set when the
setting is `DEFAULT`, which is the shipped default.

The failure is loud (a gateway that prefixes every query gets parse errors, not silent
unrestricted access), but it is a footgun with no upside.

## Design

- **Enable on load.** `LoadInternal` sets `allow_parser_override_extension` to `STRICT` unless the
  value was already changed from `DEFAULT` before loading — an explicit choice is left alone.
- **`STRICT`, not `FALLBACK`.** For this extension the two are identical: a denial is *thrown*, never
  returned (see below), so no mode can discard it. The difference is for the neighbours — a
  co-loaded extension that does use the error channel (duckpgq) keeps its own parse errors under
  `STRICT` and loses them under `FALLBACK`, and the setting is global, one value per instance, so
  whoever loads last decides for everyone.
- **The admin entry points check.** `acl_use_db` / `acl_use_functions` refuse with a clear message
  when the setting is `DEFAULT`: they are the only `acl_*` path duckdb still runs in that state, so
  they are the only place where "you are configuring a policy that will not be enforced" can be said.

### Why denials are thrown rather than returned

`ParserOverrideResult` has an error channel (`DISPLAY_EXTENSION_ERROR`), and it is tempting to route
policy denials through it. One reading of `Parser::ParseQuery` settles it — the loop over overrides
does this per extension under `STRICT`:

```cpp
if (result.type == DISPLAY_EXTENSION_ERROR) { has_strict_extension_error = true; … }
else                                        { has_strict_extension_error = false; }
```

A **later** extension that behaves perfectly well — looks at the query, sees syntax that is not its
own, returns `DISPLAY_ORIGINAL_ERROR` — thereby **clears our error**. No conflict, no misbehaviour:
the last extension in registration order decides whether anyone reported anything. With any other
override extension loaded after us, a denial routed through the result channel would reach the user
as "syntax error at or near ACL" instead of its reason. Under `FALLBACK` it is not surfaced at all,
so the channel would also need a per-mode branch.

(A later extension returning `PARSE_SUCCESSFUL` would discard it too, but that case is two grammars
claiming the same text — a conflict with no sensible resolution from either side, and not something
to design against.)

A thrown exception leaves `ParseQuery` in every mode and cannot be cleared by anyone. Refusals are
security output; they do not get a channel a neighbour can mute. The `else`-reset looks like a duckdb
bug rather than an intent — worth reporting upstream, and worth revisiting this if it is fixed.

### Sharing the parser with another override extension

Concretely, with `acl` loaded first and duckpgq second (both want `STRICT`, so the value agrees):

- **a prefixed query** is claimed by us and returned as `PARSE_SUCCESSFUL`, so the loop ends before
  duckpgq is asked — and a **denial throws**, which leaves `ParseQuery` immediately. This is exactly
  the arrangement in which a *returned* denial would have been cleared by duckpgq's polite decline,
  so the decision above is not hypothetical;
- **the query after our prefix is re-parsed with overrides disabled** (`inner.parser_override_setting
  = DEFAULT_OVERRIDE`), so another extension's syntax never reaches us: `ACL ROLE "x" SELECT … FROM
  GRAPH_TABLE(…)` fails as a plain syntax error rather than arriving in our rewriter as a table
  reference we do not know. Loud, and it keeps a foreign AST out of the rewrite path;
- **an unprefixed PGQ query** is declined by us and parsed by duckpgq, and runs without the ACL —
  the same property every unprefixed query has, and the same reason only the gateway may connect.

The deployment consequence is worth stating: a second override extension does not weaken the ACL for
prefixed queries, but its syntax is available **only outside** the ACL. A gateway that prefixes
everything cannot use it.

## Enforcement & security

Nothing about what is enforced changes; this is about the switch that decides whether anything is
enforced at all. The deployment invariant is unchanged and unchanged-able by this setting: an
unprefixed query runs natively and unrestricted in every mode, which is why only the gateway may
connect (CLAUDE.md).

## Testing

`test/sql/acl_override_setting.test`: the setting is `STRICT` right after `require acl`, and an
`ACL …` statement parses and enforces without any `SET` of our own; turning it back to `DEFAULT`
makes `ACL …` a parse error (loud, not silent) and makes `acl_use_db` refuse with the reason; turning
it on again restores enforcement. The other suites keep their explicit `SET … 'fallback'`, which
still works — an explicit value is never overridden.

## Alternatives considered

- **Leaving it to the gateway** (what we did): one more startup step, and a silently inert extension
  if it is missed.
- **`FALLBACK`**: identical for us, worse for a co-loaded extension that uses the error channel.
- **Refusing to load** when the setting is `DEFAULT`: an extension that cannot be loaded also cannot
  be configured, and the value can be changed after loading anyway.
