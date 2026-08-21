# Spec 039: maintenance — telling an admin what the catalog can no longer do

- **Status**: draft
- **Date**: 2026-08-21
- **Author**: hugr-lab

## Summary

A virtual catalog describes objects in sources it does not own. When a source changes underneath —
a column dropped, a table renamed, a schema gone — the catalog keeps saying what used to be true, and
nobody is told: the principal discovers it as a binder error that leaks the source's naming, and the
listing quietly describes a narrower object than the one that fails. This adds a **maintenance
surface**: `acl_check_catalog()` reports what no longer holds, and repair stays explicit and
admin-driven, because the obvious automatic repair is the one thing we have already refused to do.

## Problem

Probed on the current build. An object that renames its columns
(`COLUMNS (id = pk, tenant = internal_tenant, ssn = ssn_raw)`), then `ssn_raw` dropped from the
source:

```text
ACL ROLE "r" SELECT * FROM orders;
Binder Error: Referenced column "ssn_raw" not found in FROM clause!
Candidate bindings: "internal_tenant"
```

Three things are wrong at once:

1. **Nobody told the admin.** The catalog was written when the source had that column; nothing since
   has asked whether it still does. The first report comes from a principal's failed query.
2. **The error leaks the source's naming.** `ssn_raw` and `internal_tenant` are physical names the
   virtual catalog exists to hide, and they reach a principal who was only ever shown `id, tenant,
   ssn`.
3. **The listing and the read disagree.** While the read fails outright, `duckdb_columns()` narrows to
   `id, tenant` — it joins the physical columns, so the vanished one simply drops out. The metadata
   describes an object no query can return.

The reverse direction is fine and should stay that way: a column *added* to a source becomes visible
through a plain alias or a schema alias, which is what "live" means.

## Design

**Repair is not automatic, and that is a decision rather than an omission.** The obvious self-heal —
drop the vanished column from the object's list — also drops any mask that was on it. That is exactly
the "silently skipped protection" spec 038 refuses a mask over; doing it during a background refresh
would be the same failure with less visibility. An admin repairs, having been told what the repair
costs.

**`acl_check_catalog([vcat])` — read-only, admin-scoped, one row per finding.** It walks the virtual
catalog and asks the source, rather than the policy, whether each claim still holds:

| what it checks | how |
| --- | --- |
| the object's source binds at all | `SELECT * FROM <source> WHERE false` |
| every column the object declares still exists | the source's own column list |
| every grant's column list still names columns the object has | the grant chain, per role |
| every grant predicate still binds | the spec 021 check, re-run |
| a reference's ends and columns still exist | spec 022's visibility rule, re-checked |

The shape of a row: catalog, object, kind, what failed, the detail (which column, which grant, which
role), and — the part that makes it actionable — **what a repair would cost**: the masks that would
be lost, the grants that would narrow, the references that would disappear.

**Repair is explicit, and names what it gives up.** A companion `acl_repair_relation(vcat, vname,
mode)` where the mode says what the admin chose — drop the vanished columns from the object's list,
or drop the object. It refuses to run while it would silently remove a mask unless the caller says so,
because the whole reason repair is manual is that the choice belongs to someone who knows the policy.

**The listing tells the truth while an object is broken.** Rather than narrowing silently, the
metadata surfaces should mark the object as not resolvable — which is the same data the check needs,
computed in the same place. That also closes a follow-up shared with specs 037 and 038: an object
nobody can read should not be described as if they could.

**Where it sits.** `acl_refresh_schema_objects` already exists and mutates (re-reads an expansion's
source). This is the diagnostic half of the same family: check first, then a chosen repair. Both are
`manage`-scoped, both work per catalog, and neither is on any read path.

## Enforcement & security

- **Read-only by default and admin-scoped.** A check reveals what a source no longer has, which is
  information about the source, not about a principal's data — but it is still an admin's business,
  so it needs `manage` on the catalog (spec 009), the same as any other administration.
- **Repair only ever narrows.** Every mode removes something — a column, an object. Nothing a repair
  does can expose a column that was not already exposed.
- **The check is not a probe on a read path.** It runs when an admin asks, so the resolver keeps its
  "no schema probe at resolution" property (spec 038).

## Testing

`test/sql/acl_maintenance.test` (planned):

- an object whose source lost a column: the check names the object, the column and the grants that
  reference it; the read still fails and the listing marks the object broken rather than narrowing;
- an object whose source is gone entirely;
- a grant whose column list no longer matches, and one whose predicate no longer binds;
- a reference whose column vanished;
- a healthy catalog reports nothing;
- repair with the mask-losing mode: refused without the acknowledgement, applied with it, and the
  grants it narrowed reported;
- a column *added* to a source is not a finding — the live direction stays live.

## Alternatives considered

- **Heal during `acl_refresh_schema`.** Same act, less visible: a mask disappears and nobody is told.
- **Probe at resolution so the error is ours.** Ruled out in spec 038 — a query per resolution and a
  cache that goes stale exactly when an alias is meant to be live.
- **Refuse to start / refuse the catalog while anything is broken.** Too blunt: one object with a
  vanished column would take the whole catalog down for every role.

## Follow-ups

- **The read-time error still leaks the source's naming** until something knows the columns before
  bind. `ClientContextState::OnPlanningError` is a candidate hook — it sees the statement and the
  error and could replace it — and it is worth investigating on its own, since the same channel
  carries every other binder error a principal can provoke.
- Whether `acl_refresh_schema_objects` re-probes an object's own column list is unverified; it does
  not re-probe grant projections (spec 026 follow-up), which this check should cover regardless.
- A scheduled or startup-time check (report at `acl_use_db`, or a setting) — useful for an operator,
  but it belongs after the surface exists and after someone has an opinion about noise.
