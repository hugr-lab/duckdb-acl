# Spec 148: a policy expression is one expression

- **Status**: accepted (the owner, 2026-10-23: "да давай")
- **Date**: 2026-10-23
- **Author**: hugr lab (found by spec 147's review)

## Summary

A grant's or a relation's RLS, mask and computed column are SQL text the node later splices into statements: the read
(`REPLACE (<mask> AS c)`, `<expr> AS c`, `WHERE <rls>`), spec 026's projection probe, spec 027's predicate probe, spec
122's check, `acl_check_catalog`. At write they are judged as expressions - the author's function gate, the source
gate, the policy-store check - by `ParseExpressionList`, which parses `SELECT <text>` and keeps the select list: a
`FROM`, `WHERE`, comment or second statement written after the expression is dropped there, and stays in the stored
text. This spec refuses such text where it is written: a policy expression is exactly one expression, nothing after
it.

## Problem

`acl_grant_object('r', 'c', 'f', '{"select": true}', '', 'c0 = j AS m FROM read_csv(''/etc/x'') j --, c2')` is
accepted by every check: the mask's select list is `j AS m`, the FROM is never seen. What then runs it:

- spec 147's first cut of the functions listing spliced the text into a DESCRIBE - the node read the file while
  binding (fixed there: the listing binds the printed parse, in the read's shape);
- spec 026's probe splices it into `SELECT * FROM (SELECT ... <mask> AS c ... FROM <source>) WHERE false` - the table
  function binds (and reads its file's header) before the shape is refused;
- the read refuses it (the statement no longer parses) - fail closed, but by accident of the text around it.

## Design

- `OneExpression(text, problem)` (acl_catalog_validation.cpp, declared in acl_policy_catalog.hpp) judges the text with
  the same parser that reads it where it is spliced, never a second lexer:
  1. **Alone.** `SELECT <text>` is one SelectNode with one select item, no alias, no FROM, and no other clause.
  2. **With a known tail right after it.** `SELECT <text> AS __acl_a, 1 AS __acl_b FROM __acl_t WHERE true` keeps
     exactly that structure, and its first item prints as the text alone does.

  What the text does to the text around it shows as a tail that is no longer the one written: a comment left open,
  an unbalanced parenthesis, a clause or a second statement. Text that does not parse is refused too. A comment
  closed inside the text hides nothing and is allowed.

  The two parses are compared as trees, in place (`Equals`). A copy of a star's EXCLUDE / REPLACE / RENAME sets
  prints them in another order (review). A parameter (`?`, `$1`) is refused too, by the golden rule. It is read
  from the statement's own map, so it is found at any depth - the re-review reproduced a prepared read binding the
  client's `$1` into a policy through a subquery.
- **Refused where it is written** (`RequireOneExpression`): `RequirePolicyFreeExpressions` (every writer of an RLS and
  a column list: relations, catalog and object grants, ALTER ... SET), a scalar function's template, and a
  reference's join expression. A REMAP item is refused by `ItemBinds`.
- **Never pasted by a probe.** `ItemBinds`, `ProjectionSchema` (spec 026) and `PredicateError` (spec 027) judge the
  text first. So do the probes that re-read stored text (`StoredExpressionsOk`, verdicts kept per text):
  - an ALTER of another field (`RelationStatements`);
  - `ExposedTypes`;
  - ANALYZE's re-derivation;
  - the check's path test;
  - the lineage definition walk.

  A row stored before this spec, or past it by the operator's own SQL into the policy tables, is
  `acl_check_catalog`'s `mask_broken` / `rls_broken` with the reason. It is never run and never rewritten (nothing
  rolls back by itself).
- **The read refuses such a policy** (`RequireStoredExpressions` in `LookupRelation`, `LookupSchemaAlias` and
  `FunctionPolicyFrom`, reason `policy_error`). The review found two shapes where the read did not reliably fail: a
  declared list's projection, and an RLS at the end of a statement.
- **A column's name is emitted as a name.** The read quoted it only when it renamed: a declared column named `odd
  name` read under a grant was pasted bare (review).
- The memory store's writers (`acl_grant_table`, a scalar template) judge the same text, and a name it pastes as written
  must be one column reference (`RequireColumnName`).

## Enforcement & security

- The write-time gates (the author's function gate, spec 117's `AuthorizeBodies`, spec 118.3's source gate, the
  policy-store check) judge `ParseExpressionList(text)`, the select list. What they did not see can no longer be
  stored.
- Probes that splice text (`SELECT ... <text> ... FROM <source>`) bound a table function written after a mask - as
  the node, with the author's gate skipped - before the shape was refused. Now the text is judged before any probe.
- Legitimate expressions are untouched: a string holding `--` or `/*`, a subquery, CASE, a lambda, a cast.

## Testing

`acl_one_expression.test`:
- Refused at write:
  - a catalog grant's mask with a FROM after it, a `--` comment, an open `/*` comment, a second statement, an alias, or
    an unbalanced parenthesis;
  - its RLS with a FROM after it;
  - an object grant's mask and RLS;
  - a relation's computed column and RLS;
  - a REMAP item;
  - a scalar template.
- Allowed and read: a comment closed inside the text, a string holding comment marks, CASE, a subquery in the RLS,
  and a lambda.
- A row written straight into the policy tables is reported by `acl_check_catalog` with spec 148's reason, and
  refuses the read.
- A star's EXCLUDE / RENAME inside a subquery of the RLS passes and reads.
- A parameter in an RLS or a mask is refused.
- A declared column named with a space reads under a grant.
- The memory store refuses a tail.

`acl_catalog_scale.test` (spec 147): its injected mask is now refused at write.

## Alternatives considered

- **Store the normalized parse** (`ToString()` of the select list): this would rewrite the operator's text silently,
  and drop the tail instead of saying so.
- **Judge the text in each read's shape only**: there are several shapes (REPLACE, select item, WHERE, the probes'),
  and one rule at write covers them all.

## Follow-ups

- The next spec moves our whole grammar onto the PEG parser (the owner, 2026-10-23: "вообще не будем разбирать текст
  запроса вручную"):
  - the prefix, the markers and the management statements become grammar-extension rules over the standard parser;
  - an expression position is the engine's `Expression` rule;
  - this spec's text check becomes "the text parses as the rule".
- Older, noted by the review: `ParseColumnList` splits a list or struct literal at its commas (`[a, b]`,
  `{'a': x}`). A comment before an item becomes part of its name. A `""` inside a quoted name swallows the next items
  (`"we""ird", s` is one column). The PEG spec removes the hand splitter.
