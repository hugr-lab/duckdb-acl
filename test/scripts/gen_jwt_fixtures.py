#!/usr/bin/env python3
# Generates the JWT fixtures baked into test/sql/acl_jwt.test (spec 007). Deterministic apart from
# the RSA keypair, which is generated once into test/scripts/fixtures/ and committed - the tokens
# only verify against exactly that key, so regenerate tokens and test constants together:
#   python3 test/scripts/gen_jwt_fixtures.py
# Requires the openssl CLI (RS256 signatures); HS256 is pure python.

import base64
import hashlib
import hmac
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "fixtures")
KEY = os.path.join(FIXTURES, "rs256_key.pem")
PUB = os.path.join(FIXTURES, "rs256_pub.pem")
ECKEY = os.path.join(FIXTURES, "es256_key.pem")
ECPUB = os.path.join(FIXTURES, "es256_pub.pem")

HS_SECRET = b"acl-test-hs256-secret"
FUTURE = 4102444800  # 2100-01-01, far-future exp for stable tests
PAST = 946684800     # 2000-01-01, long-expired

ISS_RS = "https://issuer.test/rs"
ISS_HS = "https://issuer.test/hs"
AUD = "api://acl-test"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def signing_input(header: dict, payload: dict) -> bytes:
    return (b64url(json.dumps(header, separators=(",", ":")).encode()) + "." +
            b64url(json.dumps(payload, separators=(",", ":")).encode())).encode()


def rs256(payload: dict, kid: str = "test-key") -> str:
    header = {"alg": "RS256", "typ": "JWT", "kid": kid}
    body = signing_input(header, payload)
    sig = subprocess.run(["openssl", "dgst", "-sha256", "-sign", KEY],
                         input=body, capture_output=True, check=True).stdout
    return body.decode() + "." + b64url(sig)


def der_ints(der: bytes, count: int):
    """Minimal ASN.1 walk: return the first `count` INTEGER values found depth-first."""
    out = []

    def walk(buf):
        i = 0
        while i < len(buf) and len(out) < count:
            tag = buf[i]
            length = buf[i + 1]
            i += 2
            if length & 0x80:
                nbytes = length & 0x7F
                length = int.from_bytes(buf[i:i + nbytes], "big")
                i += nbytes
            body = buf[i:i + length]
            if tag == 0x02:  # INTEGER
                out.append(body.lstrip(b"\x00"))
            elif tag in (0x30, 0x31):  # SEQUENCE/SET
                walk(body)
            elif tag == 0x03:  # BIT STRING (skip the unused-bits byte)
                walk(body[1:])
            i += length
    walk(der)
    return out


def pem_body(path: str) -> bytes:
    lines = [l for l in open(path).read().splitlines() if not l.startswith("-")]
    return base64.b64decode("".join(lines))


def es256(payload: dict, kid: str = "test-ec") -> str:
    header = {"alg": "ES256", "typ": "JWT", "kid": kid}
    body = signing_input(header, payload)
    der_sig = subprocess.run(["openssl", "dgst", "-sha256", "-sign", ECKEY],
                             input=body, capture_output=True, check=True).stdout
    r, s = der_ints(der_sig, 2)  # JOSE wants raw r||s, 32 bytes each
    raw = r.rjust(32, b"\x00") + s.rjust(32, b"\x00")
    return body.decode() + "." + b64url(raw)


def hs256(payload: dict) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    body = signing_input(header, payload)
    sig = hmac.new(HS_SECRET, body, hashlib.sha256).digest()
    return body.decode() + "." + b64url(sig)


def main():
    os.makedirs(FIXTURES, exist_ok=True)
    if not os.path.exists(KEY):
        subprocess.run(["openssl", "genrsa", "-out", KEY, "2048"], check=True, capture_output=True)
        subprocess.run(["openssl", "rsa", "-in", KEY, "-pubout", "-out", PUB], check=True,
                       capture_output=True)
    if not os.path.exists(ECKEY):
        subprocess.run(["openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout",
                        "-out", ECKEY], check=True, capture_output=True)
        subprocess.run(["openssl", "ec", "-in", ECKEY, "-pubout", "-out", ECPUB], check=True,
                       capture_output=True)
    pub_pem = open(PUB).read().strip()
    # JWKS forms: RSA n/e from the SPKI DER, EC x/y from the uncompressed point
    n, e = der_ints(pem_body(PUB), 2)
    ec_spki = pem_body(ECPUB)
    point = ec_spki[ec_spki.index(b"\x00\x04") + 2:]  # BIT STRING pad + uncompressed marker
    jwks = {"keys": [
        {"kty": "RSA", "kid": "test-key", "alg": "RS256", "n": b64url(n), "e": b64url(e)},
        {"kty": "EC", "crv": "P-256", "kid": "test-ec", "alg": "ES256",
         "x": b64url(point[:32]), "y": b64url(point[32:64])},
    ]}

    tokens = {
        # the happy path: role claim as an array, extra claims mapped via claim_map
        "rs_valid": rs256({"iss": ISS_RS, "aud": AUD, "exp": FUTURE, "sub": "u1",
                           "roles": ["analyst"], "tid": "acme"}),
        # nested role-claim path + two roles (multi-role union)
        "rs_two_roles": rs256({"iss": ISS_RS, "aud": AUD, "exp": FUTURE, "sub": "u2",
                               "roles": ["analyst", "auditor"], "tid": "acme"}),
        # EntraID-style: GUID groups mapped to roles
        "rs_groups": rs256({"iss": ISS_RS, "aud": AUD, "exp": FUTURE, "sub": "u3",
                            "groups": ["9f3a0000-0000-0000-0000-00000000beef"], "tid": "globex"}),
        # groups overage marker (no groups claim, only the Graph link) -> explicit refusal
        "rs_overage": rs256({"iss": ISS_RS, "aud": AUD, "exp": FUTURE, "sub": "u4", "tid": "acme",
                             "_claim_names": {"groups": "src1"},
                             "_claim_sources": {"src1": {"endpoint": "https://graph.test/x"}}}),
        # negatives
        "rs_expired": rs256({"iss": ISS_RS, "aud": AUD, "exp": PAST, "sub": "u5",
                             "roles": ["analyst"], "tid": "acme"}),
        "rs_wrong_aud": rs256({"iss": ISS_RS, "aud": "api://other", "exp": FUTURE, "sub": "u6",
                               "roles": ["analyst"], "tid": "acme"}),
        "rs_unknown_role": rs256({"iss": ISS_RS, "aud": AUD, "exp": FUTURE, "sub": "u7",
                                  "roles": ["nobody"], "tid": "acme"}),
        # HS256 issuer (dev mode)
        "hs_valid": hs256({"iss": ISS_HS, "aud": AUD, "exp": FUTURE, "sub": "u8",
                           "roles": ["analyst"], "tid": "acme"}),
        # ES256 (p256-m verify; key delivered as JWKS x/y)
        "es_valid": es256({"iss": ISS_RS, "aud": AUD, "exp": FUTURE, "sub": "u9",
                           "roles": ["analyst"], "tid": "acme"}),
    }
    # a token signed by the right key but tampered afterwards: the payload stays valid JSON (so the
    # token still parses as a JWT), only a claim value changes - the signature must catch it
    valid = tokens["rs_valid"]
    head, payload, sig = valid.split(".")
    decoded = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)).decode()
    tampered = b64url(decoded.replace('"tid":"acme"', '"tid":"evil"').encode())
    tokens["rs_tampered"] = head + "." + tampered + "." + sig

    out = {"pub_pem": pub_pem, "jwks": jwks, "hs_secret": HS_SECRET.decode(), "iss_rs": ISS_RS,
           "iss_hs": ISS_HS, "aud": AUD, "tokens": tokens}
    path = os.path.join(FIXTURES, "jwt_fixtures.json")
    with open(path, "w") as f:
        json.dump(out, f, indent=1)
    print(f"wrote {path}")
    for name, token in tokens.items():
        print(f"-- {name}:\n{token}")


if __name__ == "__main__":
    sys.exit(main())
