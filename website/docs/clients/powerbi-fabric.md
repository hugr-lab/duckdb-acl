# Power BI and Microsoft Fabric

## Fabric notebooks - works with what exists

A Fabric notebook takes an Entra token from its environment and connects over ADBC:

```python
token = notebookutils.credentials.getToken("<audience of the app registration>")
# then exactly as in adbc.md, with "Bearer " + token
```

The node verifies the Entra token like any issuer: keys by the tenant's OIDC discovery
(`https://login.microsoftonline.com/<tenant>/v2.0`), RS256, a client with the app registration's
audience, app roles / groups mapped to ACL roles. No acquisition code anywhere - the platform's
workload identity is the acquiring layer.

## Power BI - planned

A custom connector (`.mez`) over the Arrow Flight SQL ODBC/ADBC driver, with OAuth done by Power
BI's own connector runtime (browser sign-in, secure storage, silent refresh). The connector exposes
exactly the auth kinds the deployment permits - OAuth / UsernamePassword / Key - which is the
admin's flow menu in Power BI's idiom. Tracked in design/016 §3d.
