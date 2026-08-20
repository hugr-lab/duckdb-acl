-- Physical schema for the acl integration scenarios (specs/005), SQL Server flavor - same shape as
-- postgres.sql, laid out like mssql-extension's docker/init/init.sql (TestDB + dbo schema). The
-- duckdb-side scenarios are deferred until a SQL Server scanner builds against the duckdb commit we
-- track (hugr-lab/mssql-extension targets stable releases); the environment is ready for them.

USE master;
GO

IF NOT EXISTS (SELECT name FROM sys.databases WHERE name = 'acltest')
BEGIN
    CREATE DATABASE acltest;
    PRINT 'acltest created';
END
GO

USE acltest;
GO

IF OBJECT_ID('dbo.orders', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.orders (
        id INT PRIMARY KEY,
        tenant NVARCHAR(32) NOT NULL,
        amount INT NOT NULL
    );
    INSERT INTO dbo.orders VALUES (1, 'acme', 100), (2, 'globex', 200), (3, 'acme', 300);
END
GO

IF OBJECT_ID('dbo.employees', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.employees (
        id INT PRIMARY KEY,
        name NVARCHAR(64) NOT NULL,
        salary INT NOT NULL,
        ssn NVARCHAR(16) NOT NULL
    );
    INSERT INTO dbo.employees VALUES (1, 'alice', 100, 'aaa'), (2, 'bob', 200, 'bbb');
END
GO

IF OBJECT_ID('dbo.audit_log', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.audit_log (
        id INT PRIMARY KEY,
        note NVARCHAR(64) NOT NULL
    );
END
GO
