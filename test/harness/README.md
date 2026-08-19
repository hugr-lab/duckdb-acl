# Test harness

An end-to-end demonstration of the `acl` extension acting as the enforcement layer behind a gateway.

```sh
make                 # build duckdb + the extension (from the repo root)
test/harness/run.sh  # loads the built extension and runs demo.sql
```

`demo.sql` attaches a physical database, registers policy via the admin stub functions, enables the
parser override (`SET allow_parser_override_extension='fallback'`), and then runs `ACL ROLE` / `ACL
TOKEN` queries that show:

- row-level security and column masking on a read-only relation,
- denial of a direct physical name and of a data-reading function,
- a virtual scalar function expanding with the baked claim,
- DML succeeding on a writable RENAME relation and being refused on a read-only one.

Override the binary/extension paths with `DUCKDB_BIN` and `ACL_EXT` if your build lives elsewhere.

For the automated regression suite, use `make test` (runs `test/sql/acl.test`).
