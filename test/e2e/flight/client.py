import sys
from pyarrow import flight

TOKEN = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci50ZXN0L3MiLCJhdWQiOiJhcGk6Ly9hY2wt"
         "dGVzdCIsImV4cCI6NDEwMjQ0NDgwMCwic3ViIjoidS1hY21lIiwicm9sZXMiOlsiYW5hbHlzdCJdLCJ0aWQiOiJhY21lIn0."
         "vzPJbHXAXfczhZwQp183JaaBLlSRSipNsSqwxoIFfng")

def varint(n):
    out = b""
    while True:
        b_ = n & 0x7F
        n >>= 7
        out += bytes([b_ | (0x80 if n else 0)])
        if not n:
            return out

def statement_query(sql: str) -> bytes:
    """An Any-wrapped CommandStatementQuery, encoded by hand - pyarrow ships Flight but not Flight SQL."""
    inner = b"\x0a" + varint(len(sql)) + sql.encode()
    url = b"type.googleapis.com/arrow.flight.protocol.sql.CommandStatementQuery"
    return b"\x0a" + varint(len(url)) + url + b"\x12" + varint(len(inner)) + inner

uri, sql = sys.argv[1], sys.argv[2]
token = sys.argv[3] if len(sys.argv) > 3 else TOKEN
client = flight.connect(uri)
options = flight.FlightCallOptions(headers=[(b"authorization", f"Bearer {token}".encode())])
info = client.get_flight_info(flight.FlightDescriptor.for_command(statement_query(sql)), options)
table = client.do_get(info.endpoints[0].ticket, options).read_all()
print(table.to_pydict())
