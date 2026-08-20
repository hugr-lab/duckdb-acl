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
