# Feature specs

We keep one **lightweight spec per feature** here. This is deliberately *not* full spec-kit — no
plan/tasks/constitution machinery, no generated branches. Just a short, honest document per feature so
design decisions are written down and reviewable.

## Process

1. **Write a spec first** (or alongside the work): copy `TEMPLATE.md` to `NNNN-slug.md`, where `NNNN`
   is the next zero-padded number and `slug` is a short kebab-case name. Fill in the problem, the design,
   enforcement/security considerations, and how it will be tested.
2. **Implement with tests.** Prefer sqllogictest (`test/sql/acl.test`); add C++ tests only where SQL
   cannot express it (e.g. parameter binding).
3. **Keep the spec current.** When the design shifts during implementation, update the spec. Set
   `Status: implemented` when it lands; reference the spec in the commit/PR.
4. **Supersede, don't rewrite history.** If a later feature reverses a decision, add a new spec and mark
   the old one `Status: superseded by NNNN`.

## What a spec is (and isn't)

- **Is**: the problem, the chosen design and why, the security/enforcement implications, the tests that
  prove it, and the alternatives considered.
- **Isn't**: a task list, an implementation diary, or API reference docs (those live in
  [../DESIGN.md](../DESIGN.md) and the code).

## Index

| Spec | Title | Status |
| --- | --- | --- |
| [0001](0001-parser-override-ast-rewrite.md) | parser_override + AST rewrite (core model) | implemented |

Deeper background and the running research notes from the PoC phase live in
[../research/](../research/); the canonical architecture is [../DESIGN.md](../DESIGN.md).
