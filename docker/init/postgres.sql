-- Physical schema for the acl integration scenarios (specs/005). Mirrors the unit fixtures of
-- test/sql/acl.test: orders (tenant-scoped) and employees (masked columns). Sandboxed roles never
-- name these objects directly - the acl extension maps virtual names onto them.

CREATE TABLE orders (
    id INT PRIMARY KEY,
    tenant VARCHAR(32) NOT NULL,
    amount INT NOT NULL
);

INSERT INTO orders VALUES (1, 'acme', 100), (2, 'globex', 200), (3, 'acme', 300);

CREATE TABLE employees (
    id INT PRIMARY KEY,
    name VARCHAR(64) NOT NULL,
    salary INT NOT NULL,
    ssn VARCHAR(16) NOT NULL
);

INSERT INTO employees VALUES (1, 'alice', 100, 'aaa'), (2, 'bob', 200, 'bbb');

-- a scratch table the writable-RENAME scenario inserts into (kept separate so reruns stay simple)
CREATE TABLE audit_log (
    id INT PRIMARY KEY,
    note VARCHAR(64) NOT NULL
);

-- a separate database for the DuckLake catalog, so lake metadata stays out of the fixture schema
CREATE DATABASE ducklake_catalog;
