# Spec 180: a grant's MASK and VERSIONS as one literal

- **Status**: implemented
- **Date**: 2026-11-21
- **Author**: Claude (the owner's decision of 2026-11-21: read the person's text with duckdb's tokenizer, not a
  client's own scanner)

## Summary

`MASK` and `VERSIONS` take one literal beside their own forms, as `RLS` already does: `MASK '<column> AS <expression>,
…'` and `VERSIONS '<clause>'`. The node reads the literal with the readers it reads the clauses with - duckdb's
parser (`ReadMasks`, `NormalizeVersions` / `ReadVersions`) - so a client that composes a grant from a form passes the
person's text as a value, never as SQL of its statement.

## Problem

The console's grant editor (hugr-platform spec 007 stage 2c) composes a grant on its server from a form: names as
quoted identifiers, the row filter as a literal (`RLS '<filter>'`). A mask's expression and a versions clause had no
literal form, so the server placed the person's text in the statement. To keep it inside its clause (one statement, the
one previewed) the server ran a scanner of its own over the text - quotes, parentheses, `;`, comments - which read
some texts otherwise than duckdb's tokenizer does: four review rounds found `E'\''`, `$$'$$`, backtick names and
`1E'…'` taking the rest of the text out of the clause. A hand-written reader of SQL is what the project avoids (the
owner, 2026-11-06: duckdb's grammar and tokenizer, not our own).

## Design

- **Grammar** (acl_mgmt_grammar.cpp): `AclMaskClause <- 'MASK' AclList` (was `AclParenList`) - `AclList <-
  AclParenList / AclQuotedValue`, the rule `RLS` reads; `AclVersionsSpec <- AclVersionsBetween / AtClause /
  AclVersionsWord / AclQuotedValue`.
- **Transform**: a mask literal goes to `acl_grant_object`'s `masks` argument as its text (`ListInto`, as an RLS
  literal goes to `rls`) - the argument the parenthesised items always reached, read by `ReadMasks` (duckdb's
  `Expression` per item, the column a name) and stored cast to the column's type. A versions literal goes to the
  `versions` argument as its text, normalized by the writer as a function call's versions are (constants evaluated
  where written). An empty `MASK ''` is no mask, as `MASK ()`; an empty `VERSIONS ''` is refused (on an object grant
  no clause inherits the catalog grant's, which `''` would not say).
- **One plain literal**, as every quoted value of the grammar (`WrittenPlainly`): no string joined across a line
  break, no `E'…'`, no `$$…$$` - what is stored is what is visibly written.
- **Nothing else changes**: the writers, the stored forms and the views are those of specs 158 and 167; the
  parenthesised forms stay.

## Enforcement & security

- The literal is a value: whatever it holds - a `;`, a closing parenthesis, another clause's words - is text the
  writer reads as the items or the clause it must be, and refuses otherwise (`MASK 'ssn AS 1); DROP ROLE r; --'` is
  one malformed mask, never a batch).
- A comment inside a mask literal is refused by the mask's reader (the parenthesised form reads a comment as a space,
  as every list does).
- The same judgments as the inline forms: a mask's author's function gate (spec 117), its tables stored whole (spec
  160), one expression per item (spec 148); a versions clause's constants evaluated where written (spec 167).

## Tests

- `test/sql/acl_grant_literal_clauses.test`: a mask literal stores what the parenthesised items store and the role
  reads it masked; two items with COLUMNS beside them; an empty literal; a literal holding a second statement and one
  that is no mask list refused, the batch not run; a versions literal (`'AT (VERSION => 2)'`, `'any'`) normalized as the
  clause; a literal with another clause's words and one that is no clause refused; a catalog grant's versions literal;
  `E'…'`, `$$…$$` and a string joined across a line break refused for both clauses; `VERSIONS ''` refused; a comment
  in a mask literal refused; a catalog's and a schema's grant refuse a mask literal; a principal author's function gate
  (spec 117) and the tables written whole (spec 160) through a literal.
- **Found by its review, fixed**: a versions literal skipped the plain-literal check (a string joined across a line
  break was stored as one word); `VERSIONS ''` silently meant "unstated"; the form's usage did not name the literals.

## Alternatives

- **The client asks the node to tokenize** (a function answering duckdb's tokens): a round trip per edit and a new
  never-set function, and the client would still assemble SQL from the person's text.
- **Keep the client's scanner**: refused - it reads SQL by hand, and reviews kept finding forms it reads otherwise.
