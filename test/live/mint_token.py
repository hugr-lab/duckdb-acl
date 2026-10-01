#!/usr/bin/env python3
"""Mint an RS256 token for the live node's demo issuer (specs 057, 095).

    test/live/mint_token.py <role>[,role2,...] [tenant] [subject]

Examples:
    test/live/mint_token.py analyst acme
    test/live/mint_token.py viewer globex u-someone
    test/live/mint_token.py analyst,auditor acme

The key is the committed fixture key; the demo issuer (test/idp/s) publishes it through its discovery
document, which the node reads from the repository (bootstrap.sql). Edit bootstrap.sql to add
roles/grants, mint a token here, paste it into the tool. Demo-only: a real deployment's issuer is its
IdP, found the same way - by discovery (spec 095).
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts"))
import idp_fixtures  # noqa: E402


roles = (sys.argv[1] if len(sys.argv) > 1 else "analyst").split(",")
tenant = sys.argv[2] if len(sys.argv) > 2 else "acme"
subject = sys.argv[3] if len(sys.argv) > 3 else f"u-{tenant}"

print(idp_fixtures.sign({"alg": "RS256", "typ": "JWT", "kid": "test-key"},
                        {"iss": "test/idp/s", "aud": "api://acl-test", "exp": 4102444800, "sub": subject,
                         "roles": roles, "tid": tenant}))
