# Spec 163: a call's arguments are the caller's

- **Status**: implemented
- **Date**: 2026-11-13
- **Author**: hugr lab (found by spec 159's review)

## Summary

A virtual table function or scalar is a template over the physical catalog, and `acl_arg(n)` marks where its n-th
argument goes. An argument that names something of the caller's query is now evaluated in the caller's scope, and the
template reads its value. Before, the argument's expression was spliced into the template, and its names bound to the
template's own physical source first.

## Problem

`CREATE VIRTUAL TABLE FUNCTION c.hf(p) AS 'SELECT id, pub, acl_arg(1) AS echo FROM phys.main.h'` read
`hf(secret)` as `SELECT id, pub, secret AS echo FROM phys.main.h`. The name `secret` bound to the source's column,
which no grant gave the caller. The same held for a scalar template with a subquery,
`(SELECT pub FROM phys.main.h WHERE id = acl_arg(1))`: its argument was evaluated inside that subquery.

## Design

**Which arguments are spliced.** `Spliceable` is an allowlist. Constants, casts, operators, comparisons, CASE, and the
system catalog's plain scalar functions over those are spliced into the template as written; so are parameters for a
call evaluated where it stands. Everything else names something of the caller's query and is read beside the call:

- a column or a positional reference (`#n`);
- an aggregate or a window (the function's type comes from duckdb's own `duckdb_functions()`, read once:
  `SystemScalarFunction`);
- a subquery, a lambda or a star.

Spec 159's closed calls are this allowlist without parameters.

**How it is read.** The arguments are evaluated in `(VALUES (<arg 1>, …)) AS __acl_args(__acl_arg_1, …)`
(`ArgumentsRef`). `acl_arg(n)` in the template becomes `__acl_args.__acl_arg_n`. In `VALUES`, an aggregate or a window
refuses ("cannot contain …") instead of being evaluated over no row. The name is the same for every call, so the same
call is the same expression (`GROUP BY lookup(id)`).

- **A table function** whose arguments are not spliced becomes
  `(SELECT __acl_call.* FROM (VALUES …) AS __acl_args(…), (<template>) AS __acl_call)` (`CallWithArguments`). A
  correlated call (`FROM t, f(t.x)`) keeps its plan.
- **An alias of a table macro or a scalar macro** outside the system catalog reads its arguments the same way. duckdb
  binds a macro's arguments inside its body.
- **A scalar template** that may bind a name of its own becomes `(SELECT <template> FROM (VALUES …) AS
  __acl_args(…))`. A template may bind a name if it has a subquery, a lambda (its parameter is the template's name),
  or a call of a function that is not the system catalog's (a macro). Such a template is evaluated over one row, so
  one that aggregates or windows refuses a non-spliced argument ("takes constants only here").
- **A scalar template without these** keeps splicing: there is no name of its own to bind.

**Builtins are the system's.** A virtual function's builtin is the system catalog's: an alias target, and each call a
scalar template makes, written bare or `main.<name>`, is written `system.main.<name>` (`QualifySystemCall`). A macro
of the same name in the default database would otherwise stand in for it. A system macro (`pg_get_viewdef`, …) reads a
table in its body, so it counts as a macro, not as a plain scalar.

**The call's column alias list** (`f(…) AS a(c1, …)`) now goes on the outermost reference, around the grant's
wrapper (spec 011). Inside it, the wrapper's own names had read the caller's columns.

**Costs.** A subquery argument loses the filter pushdown the splice gave (a non-correlated `f((SELECT max(k) FROM
t))`), and a correlated scalar template with a subquery gains a delim join. Lambda and star arguments, and a window
or an aggregate, refuse ("INSERT statement cannot contain …", duckdb's VALUES wording). A wrapped scalar call inside a
caller's lambda refuses (duckdb takes no subquery in a lambda). An error about an argument's value can name the carrier
(`__acl_arg_1`).

## Enforcement & security

A name in an argument resolves in the caller's query, or refuses there. Neither the template's own source nor a
macro's body can bind it.

## Testing

`test/sql/acl_call_arguments_scope.test`:

- **Refused:**
  - a column of the template's source as an argument: through a table function, a scalar template, an alias of a
    table macro or a scalar macro, and a template calling a macro;
  - a positional reference;
  - a window in an argument;
  - an aggregating template with a column argument.
- **Works:**
  - a correlated call, constants, a macro alias over the caller's column;
  - a lambda template, which reads its own parameter;
  - `GROUP BY` over a call;
  - a column alias list with the grant's RLS.
- **Builtins:** a default-database macro named like a builtin (`lower`, `range`) never stands in for an alias or a
  template's call; `ALIAS OF main.lower` keeps its plan (usable in a caller's lambda); a one-column table function's
  column keeps the call's alias; a system macro's argument is the caller's.
- **`lookup(id)`** reads the caller's `id`. Before, it bound to the template source's own `id` and answered more than
  one row.

## Alternatives considered

- **Refusing column arguments.** A correlated call is the point of a table function's arguments.
- **Qualifying the template's own names.** It needs a scope-aware walk of every template, and the argument's names
  would still be in the template's scope.
