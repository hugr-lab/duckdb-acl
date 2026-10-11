#!/usr/bin/env python3
"""Spec 120.3: a statement prepared before SET SESSION VIEW AS is not executed inside the mode.

    python3 view_as_client.py <uri> <token> <query>

On ONE Flight session (its cookie kept in memory): prepare <query>, enter the view-as mode as role
`analyst`, execute the earlier statement, leave the mode. Prints `refused` when the execution was refused,
else the rows it answered.
"""
import os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
# the protocol helpers of client.py (everything above its command line)
exec(open(os.path.join(HERE, "client.py")).read().split("uri, ask = sys.argv")[0])
from pyarrow import flight


class MemoryJar(flight.ClientMiddleware):
    cookie = ""

    def sending_headers(self):
        return {"cookie": MemoryJar.cookie} if MemoryJar.cookie else {}

    def received_headers(self, headers):
        for key, values in headers.items():
            if key.lower() == "set-cookie":
                for item in values if isinstance(values, list) else [values]:
                    if "acl_flight_session_id" in item:
                        MemoryJar.cookie = item.split(";")[0].strip()

    def call_completed(self, exception):
        pass


class MemoryJarFactory(flight.ClientMiddlewareFactory):
    def start_call(self, info):
        return MemoryJar()


def fields_of(payload):
    out, at = {}, 0
    while at < len(payload):
        key, at = read_varint(payload, at)
        number, wire = key >> 3, key & 7
        if wire == 2:
            length, at = read_varint(payload, at)
            out[number] = payload[at:at + length]
            at += length
        else:
            _, at = read_varint(payload, at)
    return out


uri, token, query = sys.argv[1], sys.argv[2], sys.argv[3]
client = flight.FlightClient(uri, middleware=[MemoryJarFactory()])
options = flight.FlightCallOptions(headers=[(b"authorization", f"Bearer {token}".encode())])


def run(sql):
    info = client.get_flight_info(flight.FlightDescriptor.for_command(statement_query(sql)), options)
    return client.do_get(info.endpoints[0].ticket, options).read_all().to_pydict()


run("SELECT 1 AS warm")  # the session's cookie, from the second call on
request = command("ActionCreatePreparedStatementRequest", text(1, query))
result = list(client.do_action(flight.Action("CreatePreparedStatement", request), options))
handle = fields_of(fields_of(result[0].body.to_pybytes())[2]).get(1, b"")
run("SET SESSION VIEW AS ROLE 'analyst'")
try:
    descriptor = flight.FlightDescriptor.for_command(command("CommandPreparedStatementQuery", field(1, handle)))
    info = client.get_flight_info(descriptor, options)
    print(client.do_get(info.endpoints[0].ticket, options).read_all().to_pydict())
except Exception:
    print("refused")
finally:
    run("RESET SESSION VIEW AS")
