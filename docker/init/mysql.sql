-- Physical schema for the acl integration scenarios (specs/005), MySQL flavor. Same shape as
-- postgres.sql; the duckdb-side scenarios skip automatically while mysql_scanner is disabled at
-- the duckdb submodule pin (see extension_config.cmake).

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

CREATE TABLE audit_log (
    id INT PRIMARY KEY,
    note VARCHAR(64) NOT NULL
);
