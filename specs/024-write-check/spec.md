# Spec 024: the grant's predicate confines what is written

- **Status**: implemented
- **Date**: 2026-08-21
- **Author**: hugr-lab

## Summary

A grant's predicate decided which rows a principal could *reach*. It now also decides what those rows
may *become*: a write that would leave a row outside the principal's own slice is refused where the
value is written, instead of landing there silently.

## Problem

The predicate was AND-ed into the `WHERE` of a read or a write, which bounds what a statement can
touch and says nothing about what it writes. So a role granted `RLS (tenant = acl_claim('tenant'))`
with `insert` and `update` could:

```sql
ACL ROLE "r" INSERT INTO orders VALUES (2, 'globex', 20);   -- a row it cannot read back
ACL ROLE "r" UPDATE orders SET tenant = 'globex' WHERE id = 1;   -- its own row, handed away
```

The second is the worse one: the row is reachable (it satisfied the predicate when the statement
started), and the statement moves it out of the principal's view entirely.

Spec 011 named this and offered the *value column* as the answer — an injection that assigns the
column. That works, but it is a different thing: it **overrides** what the writer supplied rather than
**checking** it, and it only helps where an administrator remembered to add one. A predicate on a
column with no injection let everything through. PostgreSQL splits the same question in two: `USING`
decides what you may touch, `WITH CHECK` what the result must satisfy. We had only the first half.

## Design

**The check travels with the value.** DuckDB's `error()` raises from an expression, and a `CASE` is
evaluated per row, so the row that violates the grant refuses itself where it is written:

```sql
CASE WHEN <predicate over the new row> THEN <value> ELSE error('… cannot be written') END
```

One written value carries the guard; the rest are untouched. A violating row fails the whole statement
rather than being dropped from it — silently writing part of a batch would be worse than either
outcome.

**`INSERT`: the row must be judgeable.** The predicate reads columns; if the insert does not supply
one of them, there is nothing to judge, and the row would land on a default nobody chose. So an insert
under a predicate must name its columns, and must supply every column the predicate reads — or be
given one by an injection, which counts. Both refusals name the column.

**`UPDATE`: the predicate is evaluated over the row that will exist.** Columns the `SET` assigns take
their new expressions; the rest keep their own values. That substitution is what turns "which rows may
be touched" into "what they may become".

**A `SET` that touches nothing the predicate reads gets no guard at all.** The new row then satisfies
the predicate exactly when the old one did, which the `WHERE` (or a `MERGE`'s `ON`) already
guaranteed. That is not only cheaper — see below.

**`MERGE`** gets both halves: its `UPDATE` branch is checked like an update, its `INSERT` branch like
an insert. The predicate is bound to the target's alias first, exactly as spec 020 binds the `USING`
half, so a same-named column on the source cannot capture it.

### Why the "touches a predicate column" rule is load-bearing

Measured, not assumed: with a `WHEN NOT MATCHED BY SOURCE` branch present, DuckDB evaluates the
`WHEN MATCHED` branch's `SET` expression **for rows that branch does not apply to**. Without that
branch it does not. A guard on such an expression would then fire on a row the statement was never
going to write.

Skipping the guard when the `SET` cannot change the answer avoids that for every ordinary merge. What
remains: a merge that *does* assign a predicate column while a `WHEN NOT MATCHED BY SOURCE` branch is
present may be refused even if no row would have been written. That is an over-refusal of a statement
that was trying to move rows across the predicate, which is the shape we refuse anyway.

## Enforcement & security

- **This closes a write path, not a read path.** Nothing became readable; rows that used to escape the
  slice now cannot be created there. A deployment relying on the old behaviour was relying on a role
  being able to write rows it could not read.
- **Injections keep overriding.** A grant that assigns a column still assigns it — the writer's value
  is dropped and the row satisfies the predicate by construction, so the check never fires. The two
  mechanisms compose: assign what you want forced, check what you want the writer to get right.
- **A grant with no predicate is untouched**, and so is `DELETE`: removing a row the principal could
  reach leaves nothing to judge.
- The refusal is an `Invalid Input Error` from `error()` rather than a binder error, because it is a
  property of the row, not of the statement — a statement that violates the grant for *some* rows is
  refused only when those rows exist.

## Testing

`test/sql/acl_write_check.test` (56 assertions): an insert outside the slice refused and one inside it
written; an insert that does not name its columns, and one that omits a column the predicate reads,
each refused with that reason; a multi-row insert with one violator writing nothing; an update moving
its own row out refused while an update within the slice works; a `MERGE` refused on both its update
and its insert branch and accepted when the row stays inside; the merge insert branch required to
supply what the predicate reads; an injected value still overriding a supplied one and satisfying the
predicate without the writer naming it; and a grant with no predicate unaffected.

## Alternatives considered

- **Filter the violating rows out** (`WHERE <predicate>` on the source). Silent data loss: the writer
  is told the statement succeeded and half the rows are gone. Worse than either refusing or allowing.
- **Check after the write, in a second statement.** Cannot be made atomic through the rewriter, and it
  would report a violation after the fact.
- **Require an injection for every column a predicate reads.** It would close the hole by construction,
  but it forces the value instead of checking it — a grant that wants "write anything in your own
  tenant" cannot be expressed that way.

## Follow-ups

- **`RETURNING` on a refused row**: the statement fails before returning anything, which is right, but
  the message names the grant rather than the row. A row identifier in the message would help an
  operator, and would leak the row to the principal — deliberately not done.
- The over-refusal noted above (a merge assigning a predicate column beside a `NOT MATCHED BY SOURCE`
  branch) could be closed if DuckDB stops evaluating a branch's expressions for rows outside it.
