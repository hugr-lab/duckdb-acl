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
policy denials through it. Reading how the parser consumes it settles the question — in
`Parser::ParseQuery` the loop over overrides does:

- a **later** extension returning `PARSE_SUCCESSFUL` returns immediately, and our error is gone;
- a later extension returning `DISPLAY_ORIGINAL_ERROR` ("not mine") explicitly **resets**
  `has_strict_extension_error` — our denial evaporates because some unrelated extension is loaded;
- under `FALLBACK` the returned error is not surfaced at all.

So a returned denial can be destroyed by an extension that has nothing to do with us, and the user
would see "syntax error at or near ACL" instead of the reason. A thrown exception propagates out of
`ParseQuery` in every mode and cannot be overwritten by anyone. Refusals are security output; they do
not get a channel that another extension can mute.

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
