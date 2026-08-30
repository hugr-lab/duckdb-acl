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

def field(number: int, payload: bytes) -> bytes:
    """One length-delimited protobuf field."""
    return bytes([(number << 3) | 2]) + varint(len(payload)) + payload


def text(number: int, value: str) -> bytes:
    return field(number, value.encode())


def flag(number: int, value: bool) -> bytes:
    return bytes([(number << 3) | 0]) + varint(1 if value else 0)


def command(name: str, inner: bytes) -> bytes:
    """An Any-wrapped Flight SQL command, encoded by hand - pyarrow ships Flight but not Flight SQL.

    That is a feature of this test rather than a shortcut: nothing about the exchange is taken on
    trust from a library that shares our assumptions, and a field number we got wrong shows up as a
    filter that did not filter rather than as a silent agreement between two halves of ourselves.

    The numbers below are checked twice over: the assertions in run.sh fail if a filter does not
    filter, and they match `format/FlightSql.proto`, which arrow's vcpkg build leaves in
    `vcpkg/buildtrees/arrow/src/*/` if you want to read it.
    """
    url = f"type.googleapis.com/arrow.flight.protocol.sql.{name}".encode()
    return field(1, url) + field(2, inner)


def statement_query(sql: str) -> bytes:
    return command("CommandStatementQuery", text(1, sql))


def enum_field(number: int, value: int) -> bytes:
    return bytes([(number << 3) | 0]) + varint(value)


def do_ingest(client, options, spec: str) -> int:
    """Bulk ingestion via DoPut(CommandStatementIngest) - spec 049. `spec` is
    `<table>:<mode>:<cols>:<rows>` with rows `v,v,..;v,v,..`; ints stay ints, the rest are strings.
    Field numbers from FlightSql.proto: table_definition_options=1 (if_not_exist=1, if_exists=2),
    table=2, temporary=5. Modes: append (not_exist=FAIL, exists=APPEND), create (CREATE, FAIL),
    replace (FAIL, REPLACE), temp (append + temporary)."""
    import pyarrow as pa
    table_name, mode, cols, rows = spec.split(":", 3)
    tdo = {"append": (2, 2), "create": (1, 1), "replace": (2, 3), "temp": (2, 2)}[mode]
    payload = field(1, enum_field(1, tdo[0]) + enum_field(2, tdo[1])) + text(2, table_name)
    if mode == "temp":
        payload += flag(5, True)
    names = cols.split(",")
    parsed = [[int(v) if v.lstrip("-").isdigit() else v for v in row.split(",")]
              for row in rows.split(";")]
    data = pa.table({name: [row[i] for row in parsed] for i, name in enumerate(names)})
    descriptor = flight.FlightDescriptor.for_command(command("CommandStatementIngest", payload))
    writer, reader = client.do_put(descriptor, data.schema, options)
    writer.write_table(data)
    writer.done_writing()
    buf = reader.read()
    writer.close()
    if buf is None:
        return -1
    payload = buf.to_pybytes()
    at = 0
    while at < len(payload):
        tag = payload[at]
        at += 1
        if tag >> 3 == 1 and tag & 7 == 0:
            value, at = read_varint(payload, at)
            return value
        value, at = read_varint(payload, at)  # skip an unexpected field
    return -1


def read_varint(payload: bytes, at: int):
    shift, out = 0, 0
    while True:
        byte = payload[at]
        out |= (byte & 0x7F) << shift
        at += 1
        if not byte & 0x80:
            return out, at
        shift += 7


def do_update(client, options, sql: str) -> int:
    """Text DML via DoPut(CommandStatementUpdate) - the wire JDBC's executeUpdate speaks (spec 048).
    The count comes back as a DoPutUpdateResult{record_count=1} in the writer's metadata."""
    import pyarrow as pa
    descriptor = flight.FlightDescriptor.for_command(command("CommandStatementUpdate", text(1, sql)))
    writer, reader = client.do_put(descriptor, pa.schema([]), options)
    writer.done_writing()
    buf = reader.read()
    writer.close()
    if buf is None:
        return -1
    payload = buf.to_pybytes()
    at = 0
    while at < len(payload):
        tag = payload[at]
        at += 1
        if tag >> 3 == 1 and tag & 7 == 0:
            value, at = read_varint(payload, at)
            return value
        value, at = read_varint(payload, at)  # skip an unexpected field
    return -1


def catalog_command(spec: str) -> bytes:
    """`@name` or `@name:arg` - the catalog RPCs, in the terms the protocol uses."""
    name, _, argument = spec[1:].partition(":")
    if name == "catalogs":
        return command("CommandGetCatalogs", b"")
    if name == "types":
        return command("CommandGetTableTypes", b"")
    if name == "schemas":
        # optional string catalog = 1; optional string db_schema_filter_pattern = 2
        return command("CommandGetDbSchemas", text(2, argument) if argument else b"")
    if name == "tables":
        # optional catalog = 1, db_schema pattern = 2, table pattern = 3, types = 4, include_schema = 5
        return command("CommandGetTables", (text(3, argument) if argument else b"") + flag(5, False))
    if name == "tables_schema":
        return command("CommandGetTables", (text(3, argument) if argument else b"") + flag(5, True))
    if name == "table_types_filter":
        return command("CommandGetTables", text(4, argument) + flag(5, False))
    # the key RPCs name a table: optional catalog = 1, optional db_schema = 2, string table = 3
    if name in ("pk", "imported", "exported"):
        message = {"pk": "CommandGetPrimaryKeys", "imported": "CommandGetImportedKeys",
                   "exported": "CommandGetExportedKeys"}[name]
        return command(message, text(3, argument))
    if name == "cross":
        pk_table, fk_table = argument.split(",")
        # pk_catalog = 1, pk_db_schema = 2, pk_table = 3, fk_catalog = 4, fk_db_schema = 5, fk_table = 6
        return command("CommandGetCrossReference", text(3, pk_table) + text(6, fk_table))
    raise SystemExit(f"unknown catalog command: {spec}")


import os


class CookieJar(flight.ClientMiddleware):
    """Persist the door's session cookie across processes (spec 050): each `ask` is a fresh process,
    and only a client that RETURNS the cookie keeps its connection-long session - which is what the
    reuse check exercises."""
    def __init__(self, path):
        self.path = path
    def sending_headers(self):
        try:
            cookie = open(self.path).read().strip()
        except OSError:
            cookie = ""
        return {"cookie": cookie} if cookie else {}
    def received_headers(self, headers):
        for key, values in headers.items():
            if key.lower() == "set-cookie":
                for item in (values if isinstance(values, list) else [values]):
                    if "acl_flight_session_id" in item:
                        open(self.path, "w").write(item.split(";")[0].strip())
    def call_completed(self, exception):
        pass


class CookieJarFactory(flight.ClientMiddlewareFactory):
    def __init__(self, path):
        self.path = path
    def start_call(self, info):
        return CookieJar(self.path)


uri, ask = sys.argv[1], sys.argv[2]
token = sys.argv[3] if len(sys.argv) > 3 else TOKEN
_jar = os.environ.get("ACL_COOKIE_JAR")
client = flight.FlightClient(uri, middleware=[CookieJarFactory(_jar)]) if _jar else flight.connect(uri)
# "-" means: send no credentials at all. The door must refuse that, and it is worth being able to ask.
headers = [] if token == "-" else [(b"authorization", f"Bearer {token}".encode())]
options = flight.FlightCallOptions(headers=headers)
if ask.startswith("@update:"):
    print({"count": do_update(client, options, ask[len("@update:"):])})
    raise SystemExit(0)
if ask.startswith("@ingest:"):
    print({"count": do_ingest(client, options, ask[len("@ingest:"):])})
    raise SystemExit(0)
descriptor = catalog_command(ask) if ask.startswith("@") else statement_query(ask)
info = client.get_flight_info(flight.FlightDescriptor.for_command(descriptor), options)
reader = client.do_get(info.endpoints[0].ticket, options)
table = reader.read_all()
data = table.to_pydict()
# `table_schema` is a serialized IPC schema, which is bytes nobody can read in a shell assertion.
# Unpack it into the column names and types it describes, which is the thing worth asserting on.
if "table_schema" in data:
    import pyarrow as pa
    unpacked = []
    for blob in data["table_schema"]:
        schema = pa.ipc.read_schema(pa.BufferReader(blob))
        unpacked.append([f"{f.name}:{f.type}" + ("" if f.nullable else " NOT NULL") for f in schema])
    data["table_schema"] = unpacked
print(data)
