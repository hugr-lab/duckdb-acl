#!/usr/bin/env python3
# The test IdPs of spec 095. A token is verified against its issuer's OIDC discovery, so every issuer
# a test defines has a discovery document and a JWKS under test/idp/<name>/ - read through duckdb's
# own filesystem, relative to the repository root (where the test runners start), and admitted by
# `SET GLOBAL acl_jwks_locations = 'test/idp/'`. The keys are the committed fixture keys of
# gen_jwt_fixtures.py (RS256 kid test-key, ES256 kid test-ec).
#
#   python3 test/scripts/idp_fixtures.py fixtures            # (re)write test/idp/<name>/ for NAMES
#   python3 test/scripts/idp_fixtures.py mint '<payload>' [rs|es] [kid]
#   python3 test/scripts/idp_fixtures.py remint <file>...    # spec 095's one-time move of test tokens
#
# remint rewrites every JWT literal in the files: an `iss` of https://issuer.test/<x> (and the two
# other demo issuers) becomes test/idp/<x>, and the token is signed again - RS256 for RS256 and HS256
# tokens (an HS256 key now lives only in a secrets service, which a sqllogictest has none of), ES256
# for ES256. A token whose signature did not verify before stays a token whose signature does not.

import base64
import hashlib
import hmac
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, HERE)
import gen_jwt_fixtures as g  # noqa: E402

IDP = os.path.join(ROOT, "test", "idp")
NAMES = ["s", "rs", "hs", "order", "shapes", "file", "cat", "inline", "gone", "d", "demo", "a", "b", "c",
         "two", "other"]
JWT = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")
ISS_MAP = {
    "https://issuer.demo": "test/idp/demo",
    "https://evil.test": "test/idp/evil",
    "https://evil.example": "test/idp/evil",
}


def b64d(segment):
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def jwks():
    n, e = g.der_ints(g.pem_body(g.PUB), 2)
    ec_spki = g.pem_body(g.ECPUB)
    point = ec_spki[ec_spki.index(b"\x00\x04") + 2:]
    return {"keys": [
        {"kty": "RSA", "kid": "test-key", "alg": "RS256", "use": "sig", "n": g.b64url(n), "e": g.b64url(e)},
        {"kty": "EC", "crv": "P-256", "kid": "test-ec", "alg": "ES256", "use": "sig",
         "x": g.b64url(point[:32]), "y": g.b64url(point[32:64])},
    ]}


def fixtures():
    keys = jwks()
    for name in NAMES:
        base = "test/idp/" + name
        os.makedirs(os.path.join(IDP, name, ".well-known"), exist_ok=True)
        with open(os.path.join(IDP, name, ".well-known", "openid-configuration"), "w") as f:
            json.dump({"issuer": base, "jwks_uri": base + "/jwks.json",
                       "id_token_signing_alg_values_supported": ["RS256", "ES256"]}, f, indent=1)
            f.write("\n")
        with open(os.path.join(IDP, name, "jwks.json"), "w") as f:
            json.dump(keys, f, indent=1)
            f.write("\n")
    print("wrote %d issuers under %s" % (len(NAMES), IDP))


def sign(header, payload):
    body = g.signing_input(header, payload)
    if header["alg"] == "RS256":
        sig = subprocess.run(["openssl", "dgst", "-sha256", "-sign", g.KEY], input=body, capture_output=True,
                             check=True).stdout
        return body.decode() + "." + g.b64url(sig)
    der = subprocess.run(["openssl", "dgst", "-sha256", "-sign", g.ECKEY], input=body, capture_output=True,
                         check=True).stdout
    r, s = g.der_ints(der, 2)
    return body.decode() + "." + g.b64url(r.rjust(32, b"\x00") + s.rjust(32, b"\x00"))


def verifies(token):
    head, payload, sig = token.split(".")
    header = json.loads(b64d(head))
    data = (head + "." + payload).encode()
    try:
        signature = b64d(sig)
    except ValueError:
        return False  # a signature that is not even base64url: deliberately broken
    alg = header.get("alg")
    if alg == "HS256":
        return hmac.compare_digest(hmac.new(g.HS_SECRET, data, hashlib.sha256).digest(), signature)
    if alg == "RS256":
        path = os.path.join(ROOT, "build", ".remint_sig")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(signature)
        done = subprocess.run(["openssl", "dgst", "-sha256", "-verify", g.PUB, "-signature", path], input=data,
                              capture_output=True)
        return done.returncode == 0
    return True  # ES256: the fixtures only ever carry valid ones


def new_iss(iss):
    if iss in ISS_MAP:
        return ISS_MAP[iss]
    if iss and iss.startswith("https://issuer.test/"):
        return "test/idp/" + iss[len("https://issuer.test/"):]
    return iss


def remint_token(token):
    head, payload, sig = token.split(".")
    header = json.loads(b64d(head))
    claims = json.loads(b64d(payload))
    iss = new_iss(claims.get("iss"))
    if iss == claims.get("iss") and header.get("alg") != "HS256":
        return token
    valid = verifies(token)
    claims["iss"] = iss
    alg = "ES256" if header.get("alg") == "ES256" else "RS256"
    fresh = {"alg": alg, "typ": header.get("typ", "JWT"), "kid": "test-ec" if alg == "ES256" else "test-key"}
    minted = sign(fresh, claims)
    if not valid:
        # it was refused for its signature: keep it refused for that, with a signature of the right size
        h, p, s = minted.split(".")
        try:
            b64d(sig)
            raw = bytearray(b64d(s))
            raw[0] ^= 0xFF
            minted = h + "." + p + "." + g.b64url(bytes(raw))
        except ValueError:
            minted = h + "." + p + "." + sig  # malformed before, malformed after
    return minted


def remint(paths):
    for path in paths:
        text = open(path).read()
        seen = {}

        def swap(match):
            token = match.group(0)
            if token not in seen:
                seen[token] = remint_token(token)
            return seen[token]

        updated = JWT.sub(swap, text)
        if updated != text:
            with open(path, "w") as f:
                f.write(updated)
            print("%s: %d token(s)" % (path, sum(1 for k, v in seen.items() if k != v)))


def main(argv):
    if len(argv) < 2:
        print(__doc__ or "usage: idp_fixtures.py fixtures | mint <payload> [rs|es] | remint <file>...")
        return 2
    if argv[1] == "fixtures":
        fixtures()
    elif argv[1] == "mint":
        alg = "ES256" if len(argv) > 3 and argv[3] == "es" else "RS256"
        kid = argv[4] if len(argv) > 4 else ("test-ec" if alg == "ES256" else "test-key")
        print(sign({"alg": alg, "typ": "JWT", "kid": kid}, json.loads(argv[2])))
    elif argv[1] == "remint":
        remint(argv[2:])
    else:
        print("unknown command " + argv[1])
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
