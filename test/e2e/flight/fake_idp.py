#!/usr/bin/env python3
"""A fake OIDC IdP for the auth e2e (spec 064): discovery + a password grant.

Answers /.well-known/openid-configuration, /jwks and /token. alice/wonder (and bob/builder, whose
'bob:builder' is 11 bytes: base64 with padding, spec 089) earns an RS256 token signed with the
committed fixture key; the door finds the key itself, through this discovery's jwks_uri (spec 095),
like it does with a real IdP. A wrong password is invalid_grant; the user 'noropc' models an IdP that
has the password flow off (unsupported_grant_type). Stdlib and the openssl CLI only - the point is
that nothing here shares code with the door.
"""
import base64
import json
import os
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

BASE = sys.argv[1]          # the issuer URL the door was configured with, e.g. http://localhost:32795
PORT = int(sys.argv[2])
ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."))
KEY = os.path.join(ROOT, "test", "scripts", "fixtures", "rs256_key.pem")
JWKS = json.load(open(os.path.join(ROOT, "test", "idp", "rs", "jwks.json")))


def b64url(raw: bytes) -> bytes:
    return base64.urlsafe_b64encode(raw).rstrip(b"=")


def mint(sub: str) -> str:
    header = b64url(json.dumps({"alg": "RS256", "typ": "JWT", "kid": "test-key"}).encode())
    claims = b64url(json.dumps({
        "iss": BASE, "aud": "api://acl-test", "exp": int(time.time()) + 3600,
        "sub": sub, "roles": ["analyst"], "tid": "acme",
    }).encode())
    signing = header + b"." + claims
    sig = b64url(subprocess.run(["openssl", "dgst", "-sha256", "-sign", KEY], input=signing,
                                capture_output=True, check=True).stdout)
    return (signing + b"." + sig).decode()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _json(self, code, body):
        payload = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    # spec 101: like Microsoft Entra ID, a HEAD answers another page (HTML, ~24.5k) than the GET's JSON -
    # httpfs sizes its ranged read by the HEAD and refuses the mismatch, so the node must read the
    # discovery document and the JWKS whole
    def do_HEAD(self):
        if self.path in ("/.well-known/openid-configuration", "/jwks"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", "24541")
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self):
        if self.path == "/.well-known/openid-configuration":
            self._json(200, {
                "issuer": BASE,
                "token_endpoint": BASE + "/token",
                "device_authorization_endpoint": BASE + "/device",
                "jwks_uri": BASE + "/jwks",
                "id_token_signing_alg_values_supported": ["RS256"],
            })
        elif self.path == "/jwks":
            self._json(200, JWKS)
        else:
            self._json(404, {"error": "not_found"})

    def do_POST(self):
        if self.path != "/token":
            self._json(404, {"error": "not_found"})
            return
        length = int(self.headers.get("Content-Length", "0"))
        form = parse_qs(self.rfile.read(length).decode())
        grant = form.get("grant_type", [""])[0]
        user = form.get("username", [""])[0]
        password = form.get("password", [""])[0]
        if grant != "password":
            self._json(400, {"error": "unsupported_grant_type"})
        elif user == "noropc":
            # the IdP with ROPC switched off: the door must surface exactly this refusal
            self._json(400, {"error": "unsupported_grant_type"})
        elif (user, password) in (("alice", "wonder"), ("bob", "builder")):
            self._json(200, {"access_token": mint(user), "token_type": "Bearer", "expires_in": 3600})
        else:
            self._json(400, {"error": "invalid_grant"})


HTTPServer(("localhost", PORT), Handler).serve_forever()
