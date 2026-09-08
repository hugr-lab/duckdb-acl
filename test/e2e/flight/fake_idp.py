#!/usr/bin/env python3
"""A fake OIDC IdP for the auth e2e (spec 064): discovery + a password grant.

Answers /.well-known/openid-configuration and /token. alice/wonder earns an HS256
token signed with the same oct key the door's issuer trusts; a wrong password is
invalid_grant; the user 'noropc' models an IdP that has the password flow off
(unsupported_grant_type). Stdlib only - the point is that nothing here shares
code with the door.
"""
import base64
import hashlib
import hmac
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

BASE = sys.argv[1]          # the issuer URL the door was configured with, e.g. http://localhost:32795
PORT = int(sys.argv[2])
SECRET = b"acl-test-hs256-secret"  # base64url: YWNsLXRlc3QtaHMyNTYtc2VjcmV0


def b64url(raw: bytes) -> bytes:
    return base64.urlsafe_b64encode(raw).rstrip(b"=")


def mint(sub: str) -> str:
    header = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    claims = b64url(json.dumps({
        "iss": BASE, "aud": "api://acl-test", "exp": int(time.time()) + 3600,
        "sub": sub, "roles": ["analyst"], "tid": "acme",
    }).encode())
    signing = header + b"." + claims
    sig = b64url(hmac.new(SECRET, signing, hashlib.sha256).digest())
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

    def do_GET(self):
        if self.path == "/.well-known/openid-configuration":
            self._json(200, {
                "issuer": BASE,
                "token_endpoint": BASE + "/token",
                "device_authorization_endpoint": BASE + "/device",
            })
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
        elif user == "alice" and password == "wonder":
            self._json(200, {"access_token": mint("alice"), "token_type": "Bearer", "expires_in": 3600})
        else:
            self._json(400, {"error": "invalid_grant"})


HTTPServer(("localhost", PORT), Handler).serve_forever()
