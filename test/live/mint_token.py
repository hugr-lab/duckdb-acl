#!/usr/bin/env python3
"""Mint an HS256 token for the live node's demo issuer (spec 057).

    test/live/mint_token.py <role>[,role2,...] [tenant] [subject]

Examples:
    test/live/mint_token.py analyst acme
    test/live/mint_token.py viewer globex u-someone
    test/live/mint_token.py analyst,auditor acme

The secret is the demo fixture's ("acl-test-hs256-secret") - matching the issuer bootstrap.sql
defines. Edit bootstrap.sql to add roles/grants, mint a token here, paste it into the tool.
Demo-only: real deployments use a real issuer and RS256/ES256 (spec 007).
"""
import base64
import hashlib
import hmac
import json
import sys


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


roles = (sys.argv[1] if len(sys.argv) > 1 else "analyst").split(",")
tenant = sys.argv[2] if len(sys.argv) > 2 else "acme"
subject = sys.argv[3] if len(sys.argv) > 3 else f"u-{tenant}"

head = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
body = b64(json.dumps({"iss": "https://issuer.test/s", "aud": "api://acl-test",
                       "exp": 4102444800, "sub": subject, "roles": roles,
                       "tid": tenant}).encode())
sig = b64(hmac.new(b"acl-test-hs256-secret", f"{head}.{body}".encode(), hashlib.sha256).digest())
print(f"{head}.{body}.{sig}")
