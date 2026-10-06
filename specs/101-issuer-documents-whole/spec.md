# Spec 101: an issuer's documents are read whole

- **Status**: implemented
- **Date**: 2026-10-06
- **Found by**: tresor's live Microsoft Entra ID check (2026-10-06): every Entra token was refused.

## Problem

The node reads an issuer's discovery document and its JWKS through duckdb's filesystem
(`read_text`, spec 023/095), so an https IdP is read by httpfs. httpfs sizes its ranged reads by a
HEAD, and refuses a GET that delivers another size. Entra's HEAD answers another page than its GET -
`200`, `text/html`, `Content-Length: 24541` - while the GET is the ~1.7k JSON, uncompressed (checked
with curl against the common tenant's v2 discovery; tresor's correction):

```
token rejected: issuer "https://login.microsoftonline.com/<tenant>/v2.0" could not read
".../v2.0/.well-known/openid-configuration": HTTP Error: The size reported by HEAD ... was 24644
bytes, but the full GET downloaded 1964 bytes. You can try to resolve this by enabling SET force_download=true
```

The operator's workaround, `SET GLOBAL force_download = true`, changes every remote read of the node
(the narrower `SET GLOBAL force_download_threshold = 1048576` - small documents whole, lake files still
ranged - is what tresor's docs recommend for a node without this spec).
A session-level SET does not help: the read runs on the store's own connection.

## Design

`PolicyStore::ReadDocumentText` sets `force_download = true` at SESSION scope on its own connection
before it reads a remote location (`scheme://`, not `file://`). The document is downloaded whole, in
one GET; nothing else on the node changes. A local location never sets it, so reading a fixture can
never autoload httpfs for nothing. A remote location without httpfs fails at the read, as before.

These documents are a few KB, so a ranged read gains nothing.

## Testing

- `test/e2e/flight/fake_idp.py` answers HEAD the way Entra does: an HTML page of 24541 bytes, while the
  GET serves the JSON. `test/e2e/flight/auth.sh` (in `make test-flight`) fails without the fix ("the load
  report is unavailable": the bearer's issuer cannot be read) and passes with it.
- Live, by hand: an Entra v2 issuer and a token naming it now reach key selection ("no usable RS256
  key" for a made-up kid), where before they stopped at the read.

## Alternatives

- Read through `HTTPUtil` directly. This was rejected: it duplicates what the filesystem gives us
  (location allowlist, `file://` fixtures, secrets for the proxy and TLS settings).
