# Feature specs

We keep one **lightweight spec per feature** here. This is deliberately *not* full spec-kit — no
plan/tasks/constitution machinery, no generated branches. Just a short, honest document per feature so
design decisions are written down and reviewable.

## Layout

Each feature is a numbered folder holding its `spec.md` (plus any feature-local assets):

```text
specs/
  TEMPLATE.md
  001-parser-override-ast-rewrite/
    spec.md
  002-<slug>/
    spec.md
```

## Process

1. **Write a spec first** (or alongside the work): create `specs/NNN-slug/spec.md` from `TEMPLATE.md`,
   where `NNN` is the next zero-padded number and `slug` is a short kebab-case name. Fill in the problem,
   the design, enforcement/security considerations, and how it will be tested.
2. **Implement with tests.** Prefer sqllogictest (`test/sql/acl.test`); add C++ tests only where SQL
   cannot express it (e.g. parameter binding).
3. **Keep the spec current.** When the design shifts during implementation, update the spec. Set
   `Status: implemented` when it lands; reference the spec in the commit/PR.
4. **Supersede, don't rewrite history.** If a later feature reverses a decision, add a new spec and mark
   the old one `Status: superseded by NNN`.

## What a spec is (and isn't)

- **Is**: the problem, the chosen design and why, the security/enforcement implications, the tests that
  prove it, and the alternatives considered.
- **Isn't**: a task list, an implementation diary, or API reference docs (those live in the code and
  `README.md`).

Deeper research and thinking-out-loud lives in a local, un-committed `design/` folder (gitignored) —
specs are the shareable distillation of that work.

## Index

| Spec | Title | Status |
| --- | --- | --- |
| [001](001-parser-override-ast-rewrite/spec.md) | parser_override + AST rewrite (core model) | implemented |
| [002](002-cpp-invariant-tests/spec.md) | standalone C++ invariant tests (params, isolation) | implemented |
| [003](003-select-capability-read-gate/spec.md) | the 'select' capability gates the read path | implemented |
| [004](004-code-structure/spec.md) | code structure and namespaces | implemented |
| [005](005-integration-env/spec.md) | integration environment, real-database scenarios, CI/CD | implemented |
| [006](006-catalog-policy-store/spec.md) | catalog-backed policy store (virtual catalogs, phase 1) | implemented |
| [007](007-jwt-verification/spec.md) | offline JWT verification (issuers, role mappings, EntraID) | implemented |
| [008](008-function-driver-admin-sql/spec.md) | function-driver policy source + ACL ADMIN management SQL | implemented |
| [009](009-admin-scopes/spec.md) | ACL administration scopes (god mode by grant) | implemented |
| [010](010-catalog-ops-surface/spec.md) | operating the virtual catalog — DROP, metadata, introspection | in progress |
| [011](011-grant-policy/spec.md) | per-grant policy — one object, different slices per role | implemented |
| [012](012-function-select-gate/spec.md) | the `select` capability gates virtual function calls | implemented |
| [013](013-unified-ddl-syntax/spec.md) | one DDL syntax for the virtual catalog | implemented |
| [014](014-virtual-schemas/spec.md) | virtual schemas as objects — alias, expansion, refresh | implemented |
| [015](015-schema-grants/spec.md) | schema-level grants and materialised caps inheritance | implemented |
| [016](016-ddl-through-acl/spec.md) | DDL through the ACL — `create`, `drop`, and where the object lands | implemented |
| [017](017-enable-override-on-load/spec.md) | the extension enables its own parser override | implemented |
| [018](018-create-view-through-acl/spec.md) | a role may create a view — `CREATE VIEW` through the ACL | implemented |
| [019](019-dml-target-qualification/spec.md) | a write may qualify its columns by the name the principal used | implemented |
| [020](020-multi-relation-writes/spec.md) | writing with a second relation in scope | implemented |
| [021](021-grant-predicate-validation/spec.md) | a predicate is checked where it is written | implemented |
| [022](022-object-references/spec.md) | references — declared join paths between objects | implemented |
| [023](023-jwks-from-a-document/spec.md) | an issuer's keys read from a document | implemented |
| [024](024-write-check/spec.md) | the grant's predicate confines what is written | implemented |
| [025](025-show-and-describe/spec.md) | `DESCRIBE`, `SUMMARIZE` and `SHOW TABLES` under a principal | implemented |
| [026](026-grant-projection-columns/spec.md) | a grant's projection is probed where it is written | implemented |
| [027](027-validation-completeness/spec.md) | a skipped write-time check is remembered, and taken again | implemented |
| [028](028-dml-in-a-cte/spec.md) | a DML statement inside a `WITH` | implemented |
| [029](029-columns-always-restrict/spec.md) | a column list is a projection, whatever it is made of | implemented |
