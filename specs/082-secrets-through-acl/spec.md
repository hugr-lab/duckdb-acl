# Spec 082: secrets through the ACL - the node's secrets service, under an explicit capability

- **Status**: implemented
- **Date**: 2026-09-23
- **Requested by**: tresor spec 009 ("duckdb-acl's side")
- **Decisions (owner, 2026-09-23)**:
  - an explicit capability `secrets`;
  - the service catalog's functions are admitted through a category the operator grants;
  - a local `CREATE SECRET` stays refused.

## Problem

tresor keeps a node's secrets in an external service and attaches it as a catalog of type `tresor`.
Under tresor spec 009 an administrator manages the service through an acl node: create, drop, and grant
use to roles and groups. Under a principal, acl refused all of it:

- `CREATE SECRET`: "only tables and views can be created through the ACL";
- the grants had no syntax.

A principal must also never create a secret in the node's own secret manager. A temporary secret there
would serve every later statement on the node, whoever's it is.

## Design

**Capability.** `secrets` sits on the principal's MAIN catalog grant. It is explicit-only, like `temp`
and `explain`: never in the unstated default, and never implied by a `manage` or `passthrough` scope.
The anonymous `ACL ADMIN` form is the gateway's own and passes.

**The catalog.** `PolicyStore::SecretService(named)` chooses it:

- the catalog the statement names, if the name is an attached catalog of type `tresor` (read from
  `DatabaseManager::GetDatabases()` through the instance the store keeps since load);
- otherwise the single one attached.

It refuses with text that says what to write when:

- a named storage is not a secrets service (`memory`, `local_file`, a data catalog), reason
  `unavailable`;
- no service is attached (`unavailable`). The node keeps working, it just does not manage secrets;
- several are attached and none is named (`statement_type`).

**GRANT / REVOKE SECRET** (`acl_admin_sql.cpp`).

- They follow the principal with the `ACL` marker, or come unmarked after `ACL ADMIN`, where
  `IsMgmtStart` already routes `GRANT`.
- `Prefixed` intercepts them ahead of the admin-scope check, requires `secrets`, and compiles:
  - `GRANT SECRET n TO ROLE r [FROM c]` → `SELECT * FROM c.main.grant_secret('n', 'role:r', ['use'])`;
  - `REVOKE SECRET n FROM GROUP g [IN c]` → `... revoke_secret('n', 'group:g')`.
- A grant goes to a ROLE or a GROUP, never to one user. The batch is read whole before any service is
  chosen, and it holds nothing else.
- Audit records statement `secrets` and object `grant_secret` / `revoke_secret` with capability
  `secrets`.

**CREATE / DROP SECRET** (the rewriter).

- They require `secrets`. `TEMPORARY` and `TRANSACTION` persistence is refused.
- `storage_type` / `secret_storage` is set to the chosen service.
- The parameters (TYPE, PROVIDER, SCOPE, the options) must be constants: literals, casts of them, and
  `list_value` / `array_value` / `struct_pack` / `row` / `map` / unary minus over them.
  - duckdb's `ConstantBinder` refuses columns and subqueries but evaluates function calls on the node,
    so `SECRET getenv('...')` would put the node's environment into the service.
  - The refusal text never quotes the parameter. A debugging run that did put a literal into a deny
    reason was caught by the test below: a reason reaches the audit event as written.
- The decision notes `<service>.<secret name>` with capability `secrets`.

**Direct calls** (`corp.whoami()`, `corp.main.secrets()`) belong to the function gate, spec 072:

- **Category.** The operator puts what a role may call into a category. Nothing is seeded, since a
  seed cannot know the catalog's name.
- **Never set.** `whoami` is never callable only as the system catalog's (quack's): `FunctionNeverCallable(name,
  database)` / `FunctionNeverOnlyInSystem`. The rule is judged on the key the name resolves to, so
  `corp.main.whoami` can be categorized and `system.main.whoami` cannot.
- **Resolver.** It reads `x.f` as database `x`, schema `main`, when no member has schema `x`. That is
  duckdb's own reading, and before this change `corp.whoami()` was unresolvable.

## Enforcement & security

- **No local secrets.** A principal's secret lands only in the service. The node's own manager (memory,
  local_file, transaction) is refused, so no secret serves another principal's statements.
- **Two gates.** acl requires `secrets`. The service manages only for its administrators (tresor spec
  009), and under a session it acts with the session user's grant (spec 078).
- **Evaluation.** Parameters are constants, so nothing is evaluated on the node on the principal's
  behalf.
- **No secret value on any event.** A statement event carries the service and the name. Refusal texts
  quote no parameter, and the profile carries no literal (spec 074).

## Tests

- **`test/sql/acl_secrets.test`** (no service):
  - the capability is refused for a plain role and for a `manage` admin;
  - "no secrets service" is reported for every form;
  - `TEMPORARY` is refused, as are `IN memory` / `IN local_file` / `FROM phys`;
  - non-constant parameters (`getenv`, `current_setting`, a call inside a list) are refused;
  - `TO USER` is refused, as is a mixed batch;
  - the anonymous form is gated by `acl_allow_anonymous_admin`;
  - the node's secret manager stays empty.
- **`test/cpp/test_acl_secrets.cpp`**: a fake service with the shape tresor attaches (a DuckCatalog of
  type `tresor` with the service's table functions, and a persistent storage named after it):
  - GRANT and REVOKE compile to the exact calls, and a batch runs each call;
  - CREATE and DROP (plain, and `PERSISTENT … IN`) land in the service and never in `local_file` (the
    test has its own `secret_directory`);
  - no value, key id or scope appears on any audit or profile event;
  - with two services, an unnamed statement is refused and `FROM` / `IN` choose;
  - a direct `corp.whoami()` is refused without the category, admitted with it, and refused for another
    role; `system.main.whoami` stays never, both called and categorized.
- Tresor's side against real acl is tresor's CI (`test/acl/actor.sql`).

## Alternatives

- **The management scope instead of a capability.** Rejected: administering the ACL and holding the
  node's secrets are different trusts (the owner's decision).
- **Compiling the calls into acl functions that run the service's calls.** Rejected: that duplicates
  the service's surface. The compiled calls are the service's own, so its refusal reaches the client
  as it is.
- **Walking the parameters through the function gate instead of requiring constants.** Rejected: no
  secret parameter needs a function, and the constant rule is a smaller surface.
