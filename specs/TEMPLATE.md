# Spec NNNN: <feature name>

- **Status**: draft | accepted | implemented | superseded by NNNN
- **Date**: YYYY-MM-DD
- **Author**: <who>

## Summary

One paragraph: what this feature is and why, in plain language.

## Problem

What is missing or wrong today, and who is affected. Concrete examples of queries/policies that don't
work yet, or attack surface that is not closed.

## Design

The chosen approach. Cover, as applicable:

- **Syntax / API** — new SQL surface, admin functions, or `ACL` input changes.
- **Resolution / rewrite** — how the AST is walked and rewritten; RENAME vs SUBQUERY; markers
  (`acl_arg`/`acl_claim`); which node types are touched.
- **Data structures** — additions to `PolicyStore` / policy shape.
- **Interaction** — how it composes with existing features (RLS, masking, gating, caching, parameters).

## Enforcement & security

Why this is safe. Cover fail-closed behavior, the parameter golden rule (no rewriter-added params),
what happens on an unknown/denied name, and any trust assumptions (admin-supplied text is trusted).

## Testing

How it is proven. List the sqllogictest cases (and any C++ tests) and the key expected results.

## Alternatives considered

Options rejected and why (briefly).

## Follow-ups

Anything intentionally left out of scope, and what a production build changes.
