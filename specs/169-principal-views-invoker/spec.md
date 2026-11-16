# Spec 169: a principal's view reads under its reader's grants

- **Status**: accepted (the owner, 2026-11-16: "a mask is the reader's")
- **Date**: 2026-11-16
- **Author**: duckdb-acl
- **Supersedes**: spec 018's "the body is resolved with its author's rights", spec 162 (the policy reads hoisted to a
  principal view's root) and spec 165 (a call's probe kept in a principal view's body)

## Summary

A view a principal creates (spec 018 / 113: `CREATE VIEW` in a home its role may create in) is stored as its query,
in virtual names. Each read rewrites that query under the **reader's** grants, the same way it would rewrite the
query had the reader written it. Its author's rights are judged once, where the view is created, and are never read
again.

## Problem

Spec 018 stored the body resolved with its author's policy: the author's projection, row filter and masks, with the
claim markers left standing so that each reader read their own tenant. Spec 158 makes masks and markers the reader's
(the owner: "we define the mask for the role that will read the data"). A body that holds the author's policy and
the reader's markers mixes two principals' rights:

- an author's mask written `CASE WHEN acl_has_role('hr') THEN ssn ELSE '***' END` shows `ssn` to an `hr` reader
  through the view, whatever the reader's own grant on the table says - access neither grant gives;
- the author's row filter with the reader's claims is a slice neither role was granted;
- each reader of the view reads with the author's reach (a strong grant, spec 018's own warning).

## Design

**Stored.** `relations.query` (schema v26, `min_reader` 26: an older build would read the view with its author's
policy) holds the view's query as written, every relation it names qualified to its canonical virtual key
(`c.sales.orders`, spec 116) where the author resolved it - so the session's `USE` and the author's MAIN catalog are
not the reader's. `view_sql` keeps the author's resolution, as before; it is now the view's **shape** only: what the
write-time probes bind (the columns, the types of spec 099, a grant's RLS / MASK over the view, ANALYZE, the check,
the definition lineage), never what a read executes.

**Created.** As before (spec 113): the home, `create`, REPLACE priced as `drop`. The author's rewrite of the body is
still run - it is the check that the author may read everything the body names and call every function it calls, and
it gives `view_sql`. In addition:

- the relations of the body are qualified in its text (`QualifiedBodyTables`' text replacement, spec 160, with the
  rewriter's own resolution in place of the binder's);
- a call to a virtual function must name its catalog (`c.f(…)`, `c.s.f(…)`): a bare one resolves in the reader's
  MAIN catalog, which may not be the author's - refused where written;
- a session temp table cannot be named (it is the author's connection's);
- the body is one SELECT, reading only: a data-modifying CTE (`WITH x AS (INSERT … RETURNING …)`) and a parameter
  are refused (review);
- the author's own reads are bound alone before the record is written (spec 159's guards, the markers NULL), so a
  policy name the author's source lost refuses the create;
- the composed read of a statement's principal views is bounded at 4 MiB (a view read twice per level doubles per
  level).

**Read.** Resolving the view gives its `query`. The rewriter parses it (one SELECT, else refused) and rewrites it as
part of the reader's statement - the reader's grants, masks, row filters, markers, function gate, types - with each
name read as the canonical key it stores (a name that resolves to another object for the reader refuses: `the view
reads c.sales.orders, which this principal cannot read`). The rewritten query then takes the place of the view's
SQL: the reader's own grant on the view (its RLS, `COLUMNS`, `MASK`, spec 158) wraps it as for any view, and spec
159 binds it alone. A view that reads a view nests the same way; a view reached again inside itself is refused, and
so is a nesting deeper than 16.

**Reading needs both grants.** `select` on the view (as before) and the reader's own rights on what the view reads.
A principal's view no longer publishes its author's reach; an operator's virtual view (`CREATE VIRTUAL VIEW`, its
SQL physical) still does - that is the operator's decision, written with the operator's rights.

**Removed.** Spec 162's hoisted reads and spec 165's probes in a principal's body (a read is now rewritten in the
reader's statement, where spec 159 / 164 bind it alone), and with them the reserved `__acl_read_` / `__acl_probe_`
prefixes.

**The shape and the reader.** The listings describe the view as its author's resolution probed it. A reader whose
own grants hide a column the view names cannot read the view (the column is not found where it binds - refused, not
narrowed); a mask of the reader's keeps the column's type (spec 158), so the shape holds for every reader who may
read the view.

## Enforcement & security

- A reader reads through a principal's view exactly what the reader may read directly: the same rewrite, the same
  gates, the same guards.
- The author's rights decide only whether the view may be created; a later change of the author's grants changes
  nothing a reader reads.
- A stored `query` is data, parsed by duckdb's parser at each read, and refused unless it is one SELECT.
- Views created before v26 have no `query`. One stored by specs 162 / 165 (a `__acl_read_` / `__acl_probe_` CTE in
  its body) is refused where read and named by `acl_check_catalog` (`view_recreate`): its probes are gone and it holds
  its author's policy (review). One stored before spec 162 cannot be told from an administrator's view written
  through a principal, and is read as stored - its author creates it again (no backward compatibility before the
  release; such views exist only in development catalogs of the last weeks).

## Known limits

- A view's query runs with its reader's data: a function with an effect outside the node (a URL read, a log) that
  both the author and the reader may call carries the reader's values where the author's query sends them. The
  default categories grant no such function; an operator who grants one to a role that creates views grants this too.
- `platform.effective_rights` reports a role's rights on the view itself, not on what the view reads.

- The listings describe the view by its author's shape. A column duckdb names after its expression's text (a table
  function's column named by its argument, spec 166) is named after the stored query's text when read, its relations
  qualified (`… FROM c.orders AS o` where the author wrote `orders`), while the listing shows the author's spelling.
- A principal's view over a table function: the call's arguments are the reader's to evaluate, like any query of the
  reader's (spec 163).

## Found by the reviews (fixed with tests)

- **A CTE's scope** (older than this spec, `acl_cte_scope.test`): the rewriter put every CTE name of a WITH in scope
  before it rewrote any CTE's definition, while duckdb's binder sees a CTE only after its own definition (a recursive
  CTE's right side excepted). A self or forward reference was skipped as a CTE and bound by duckdb to the default
  database's table or a file - past the gate, and through a principal's view for its readers. The scope now follows
  the binder's; a name a view's query names that no policy answers is refused at create.
- **A recursive CTE's `USING KEY` targets** (older than this spec): expressions duckdb binds, walked by neither
  duckdb's iterator nor the rewriter - now gated like any expression.
- **`recurring.<name>`** (a compatibility review against duckdb's binder): a recursive CTE's right side reads
  itself under that name too (duckdb binds a name by its last two parts); the rewriter refused it as a catalog name -
  now read as the CTE there, and only there. The review found the rest of the scope rule equal to the binder's. Two
  differences stay, both failing closed: a CTE nothing references is still gated (duckdb never binds it), and a
  DELETE / UPDATE / MERGE target named like a CTE resolves as the virtual object (duckdb refuses it).
- The shape is replaced only where it occurs once (a mask holding its text is refused); a refusal inside a nested view
  names the outermost view; the rewriter's state is restored on a refusal.

## Testing

`test/sql/acl_principal_view_invoker.test`:

- a view an author creates over a table both roles read differently: each reader reads its own rows, columns and
  masks - an author's grant never shows through;
- the owner's case: a mask on the reader's grant `CASE WHEN acl_has_role('hr') …` and an author holding `hr`;
- a reader without a grant on the table the view reads is refused; with `select` on the view alone too;
- a reader whose grant hides a column the view names is refused;
- a view over a view (nested) and a view reaching itself through another (refused);
- the stored `query` qualified (a session's `USE`, a schema-qualified name, a bare name of the MAIN catalog);
- a bare virtual function call refused at create; a qualified one read under the reader's function grants;
- the listing's columns of the view (the author's shape).

Specs 162's and 165's tests move to the reader's statement (the same refusals, now from the reader's guards).

## Alternatives considered

- **Keep the author's resolution and bake the markers by the author** (spec 018 as written, markers frozen): one
  principal's rights throughout, but the view then shows the author's tenant to every reader - what spec 018 rejected.
- **Store only the author's resolution and re-resolve its physical names for the reader.** The physical text has
  lost which virtual object each read came from (a subquery, an alias, a mask): it cannot be read back as the
  author's query.
