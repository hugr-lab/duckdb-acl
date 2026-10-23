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

- `OneExpression(text, problem)` (acl_catalog_validation.cpp, declared in acl_policy_catalog.hpp):
  1. no comment token (`Parser::Tokenize`, `SIMPLIFIED_TOKEN_COMMENT`), since a comment hides what follows it wherever
     the text is placed;
  2. `SELECT <text>` parses to exactly one statement: a SelectNode with one select item, no alias, an empty FROM, no
     WHERE / GROUP BY / HAVING / QUALIFY / SAMPLE / modifiers / CTE.

  Text that does not parse alone is refused too: an unbalanced parenthesis could close the statement it is spliced
  into.
- **Refused where it is written** (`RequireOneExpression`): `RequirePolicyFreeExpressions` (every writer of an RLS and
  a column list: relations, catalog and object grants, ALTER ... SET), a scalar function's template, and a
  reference's join expression. A REMAP item is refused by `ItemBinds`.
- **Never spliced by a probe**: `ItemBinds`, `ProjectionSchema` (spec 026) and `PredicateError` (spec 027) judge the
  text first. A row stored before this spec, or past it by the operator's own SQL into the policy tables, is
  `acl_check_catalog`'s `mask_broken` / `rls_broken` / `definition_broken` with the reason. It is never run and never
  rewritten (nothing rolls back by itself).
- The read is unchanged. Such a text never parsed there.

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
  - a catalog grant's mask with a FROM after it, a `--` or `/* */` comment, a second statement, an alias, or an
    unbalanced parenthesis;
  - its RLS with a FROM after it;
  - an object grant's mask and RLS;
  - a relation's computed column and RLS;
  - a REMAP item;
  - a scalar template.
- Allowed and read: a string holding comment marks, CASE, a subquery in the RLS, a lambda.
- A row written straight into the policy tables is reported by `acl_check_catalog` with spec 148's reason.

`acl_catalog_scale.test` (spec 147): its injected mask is now refused at write.

## Alternatives considered

- **Store the normalized parse** (`ToString()` of the select list): this would rewrite the operator's text silently,
  and drop the tail instead of saying so.
- **Judge the text in each read's shape only**: there are several shapes (REPLACE, select item, WHERE, the probes'),
  and one rule at write covers them all.
