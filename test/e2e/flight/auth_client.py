#!/usr/bin/env python3
"""The auth e2e's client half (spec 064): discovery over the Handshake, then the password handshake.

Usage: auth_client.py <uri> <check> [args...] [--tls-roots cert.pem]
Checks:
  discover                 print the discovery JSON the door answers to the 'discover-auth' payload
  password <user> <pass> <sql>   authenticate with BasicAuth, run sql under the earned bearer, print rows
  bearer <jwt> <sql>       plain bearer call (the path that must stay unaffected)
"""
import sys

import pyarrow.flight as fl

args = sys.argv[1:]
tls_roots = None
if "--tls-roots" in args:
    i = args.index("--tls-roots")
    with open(args[i + 1], "rb") as f:
        tls_roots = f.read()
    args = args[:i] + args[i + 2:]

uri, check = args[0], args[1]
kwargs = {"tls_root_certs": tls_roots} if tls_roots else {}
client = fl.FlightClient(uri, **kwargs)


def run(sql, headers):
    # the one command the raw client needs, encoded by hand as client.py does: a Flight SQL
    # CommandStatementQuery inside a google.protobuf.Any, packed into a command descriptor
    def any_wrap(type_url, msg):
        out = b"\x0a" + varint(len(type_url)) + type_url.encode() + b"\x12" + varint(len(msg)) + msg
        return out

    def varint(n):
        out = b""
        while True:
            bit = n & 0x7F
            n >>= 7
            out += bytes([bit | (0x80 if n else 0)])
            if not n:
                return out

    query = b"\x0a" + varint(len(sql.encode())) + sql.encode()
    cmd = any_wrap("type.googleapis.com/arrow.flight.protocol.sql.CommandStatementQuery", query)
    desc = fl.FlightDescriptor.for_command(cmd)
    opts = fl.FlightCallOptions(headers=headers)
    info = client.get_flight_info(desc, opts)
    table = client.do_get(info.endpoints[0].ticket, opts).read_all()
    return table.to_pydict()


if check == "discover":
    class Discover(fl.ClientAuthHandler):
        def authenticate(self, outgoing, incoming):
            outgoing.write(b"discover-auth")
            self.doc = incoming.read()

        def get_token(self):
            return b""

    handler = Discover()
    client.authenticate(handler)
    print(handler.doc.decode())
elif check == "password":
    user, password, sql = args[2], args[3], args[4]
    pair = client.authenticate_basic_token(user, password)
    print(run(sql, [pair]))
elif check == "bearer":
    jwt, sql = args[2], args[3]
    print(run(sql, [(b"authorization", b"Bearer " + jwt.encode())]))
else:
    sys.exit("unknown check: " + check)
