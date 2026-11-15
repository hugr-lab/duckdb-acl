# Spec 166: an argument is carried under its own name

- **Status**: implemented
- **Date**: 2026-11-15
- **Author**: hugr lab (spec 163's BACKLOG item)

## Summary

An argument that spec 163 evaluates beside a call, in `(VALUES (…)) AS __acl_args(…)`, is now carried in a column named
the way duckdb names the argument: a column reference by its column, any other expression by its text. A template's
or a macro's item that reads the argument is therefore named as if the argument were spliced in. An error about its
value names the caller's column.

## Problem

Spec 163 named every carrier column `__acl_arg_<n>`. duckdb names an item that only reads a column after that column,
so the names leaked into what a principal sees:

- **Result columns:** `SELECT f.* FROM s, raw(s.key) f` over a template `SELECT acl_arg(1) FROM …` answered a column
  `__acl_arg_1`. The same held for an alias of a table macro `SELECT k FROM …`. duckdb itself, and the spliced form
  before spec 163, name it `key`.
- **Errors:** an error about the argument's value named the carrier, for example "when casting from source column
  __acl_arg_1".

Spec 155's scrub does not know these names. Naming the carrier after the argument removes them at the source instead
of scrubbing them later.

## Design

`CarrierNames(function)` (acl_rewriter.cpp) gives each argument, as the client wrote it, `GetName()`: the name duckdb
gives an expression with no alias. The names are taken before the arguments are rewritten (`RewriteFunctionArgs`) and
passed to the sites that build the carrier (the template, a table macro's alias, a scalar template, a scalar macro's
alias). A rewritten argument's text names physical tables, a grant's predicate and a scalar's template: the review
found that the first version, which named the rewritten arguments, showed them in a result's names and in errors.
The rules:

- a column reference gets its column's name (`key`);
- any other expression gets its text (`(s."key" || 'y')`);
- a name met twice takes duckdb's suffix for a repeated result name (`key`, `key_1`);
- an empty name falls back to `__acl_arg_<n>`.

The carrier `ArgumentsRef` builds and the references a template's `acl_arg(n)` or an alias's argument become use these
names. Every reference is qualified by `__acl_args`, so a name shared with a column of the template's own source
cannot be ambiguous. The names are derived from the arguments alone, so equal calls stay equal expressions (spec 163's
reason for one alias).

## Enforcement & security

No change to what is read: the carrier is the same VALUES row in the caller's scope, read by the same qualified
references.

## Testing

`test/sql/acl_carrier_names.test`:
- **Result names:** a template item and a macro alias item read with a column argument are named after the column,
  and one read with an expression argument is named after the expression's text. Before the fix both were
  `__acl_arg_1`.
- **Repeated names:** the same argument passed twice is named `key`, `key_1`, as duckdb names it.
- **A caller's column named like a carrier:** `__acl_arg_2` keeps its name and its value.
- **Errors:** a conversion error about the argument's value names the caller's column `key`.
- **As written:** an argument that reads a virtual table under an RLS grant, or calls a virtual scalar, names the item
  and an error by the client's text (`(SELECT (max(o.amount) + s."key") FROM orders AS o)`, `lookup(s."key")`), never
  the physical table, the predicate or the template - for a template, a macro alias, a scalar template, and a
  principal's own view read by another role.
