#!/usr/bin/env python3
"""Spec 120.3 addendum: a statement prepared IN the view-as mode is not run once the viewer lost the right.

    python3 view_as_lost_client.py <uri> <token> <query> <ready-file> <go-file>

On ONE Flight session: enter the mode as `analyst` (SET only - no header), prepare <query>, execute it once (it
answers), write <ready-file>, wait for <go-file> (the caller takes the right away meanwhile), execute it again.
Prints `first ok` / `first refused`, then `refused` or the rows of the second execution.
"""
import os, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
exec(open(os.path.join(HERE, "view_as_client.py")).read().split("uri, token, query = sys.argv")[0])

uri, token, query, ready, go = sys.argv[1:6]
client = flight.FlightClient(uri, middleware=[MemoryJarFactory()])
options = flight.FlightCallOptions(headers=[(b"authorization", f"Bearer {token}".encode())])


def run(sql):
    info = client.get_flight_info(flight.FlightDescriptor.for_command(statement_query(sql)), options)
    return client.do_get(info.endpoints[0].ticket, options).read_all().to_pydict()


def execute(handle):
    descriptor = flight.FlightDescriptor.for_command(command("CommandPreparedStatementQuery", field(1, handle)))
    info = client.get_flight_info(descriptor, options)
    return client.do_get(info.endpoints[0].ticket, options).read_all().to_pydict()


run("SELECT 1 AS warm")
run("SET SESSION VIEW AS ROLE 'analyst'")
request = command("ActionCreatePreparedStatementRequest", text(1, query))
result = list(client.do_action(flight.Action("CreatePreparedStatement", request), options))
handle = fields_of(fields_of(result[0].body.to_pybytes())[2]).get(1, b"")
try:
    execute(handle)
    print("first ok")
except Exception as e:
    print("first refused", e)
open(ready, "w").close()
for _ in range(300):
    if os.path.exists(go):
        break
    time.sleep(0.1)
try:
    print(execute(handle))
except Exception as e:
    print("refused" if "can no longer be kept" in str(e) else f"other: {e}")
