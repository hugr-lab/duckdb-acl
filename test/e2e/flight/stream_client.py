"""The streaming client of spec 070's e2e (test/e2e/flight/stream.sh): a third-party pyarrow Flight
client that pulls a result the way a driver does, and stops the way a client stops.

  stream_client.py <uri> first <sql>       time to the first batch, then cancel the read
  stream_client.py <uri> consume <sql>     read it all, chunk by chunk; prints the row count (and the
                                           error that ended it, with the rows received before)
  stream_client.py <uri> supersede <sql>   read one batch, keep the stream open, run `SELECT 1` on the
                                           same session (a cookie), print how long that waited
  stream_client.py <uri> killed <sql>      read one batch, pause (stream.sh kills the session), then
                                           drain to the error that ends the stream
  stream_client.py <uri> ingest <table>    stream batches into <table> forever - stream.sh kills it

Every mode prints one dict on the last line; a refusal prints {"error": "..."}.
"""
import os
import signal
import sys
import time

import pyarrow as pa
import pyarrow.flight as flight

# a client that hangs (a stream the server never ends, a cap not in force and 200M rows to read) must
# fail the run, not hold it: one deadline for the whole process, whatever the mode
signal.alarm(int(os.environ.get("ACL_STREAM_DEADLINE", "120")))

TOKEN = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
         "eyJpc3MiOiJodHRwczovL2lzc3Vlci50ZXN0L3MiLCJhdWQiOiJhcGk6Ly9hY2wtdGVzdCIsImV4cCI6NDEwMjQ0NDgwMCwic3ViIjoidSIsInJvbGVzIjpbImFuYWx5c3QiXSwidGlkIjoiYWNtZSJ9."
         "c_RJ0X6_Gj5O5Z273KOaB9e11XFXVgQkEbtTCayEzJc")


def varint(n):
    out = b""
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out += bytes([b | 0x80])
        else:
            return out + bytes([b])


def field(number, payload):
    return varint((number << 3) | 2) + varint(len(payload)) + payload


def text(number, value):
    return field(number, value.encode())


def command(name, inner):
    any_msg = text(1, "type.googleapis.com/arrow.flight.protocol.sql." + name) + field(2, inner)
    return any_msg


def statement_query(sql):
    return command("CommandStatementQuery", text(1, sql))


class CookieJar(flight.ClientMiddleware):
    """One session across the calls of this process (spec 050): the door's cookie, returned."""
    def __init__(self, jar):
        self.jar = jar
    def sending_headers(self):
        return {"cookie": self.jar["cookie"]} if self.jar.get("cookie") else {}
    def received_headers(self, headers):
        for key, values in headers.items():
            if key.lower() == "set-cookie":
                for item in (values if isinstance(values, list) else [values]):
                    if "acl_flight_session_id" in item:
                        self.jar["cookie"] = item.split(";")[0].strip()
    def call_completed(self, exception):
        pass


class CookieJarFactory(flight.ClientMiddlewareFactory):
    def __init__(self, jar):
        self.jar = jar
    def start_call(self, info):
        return CookieJar(self.jar)


def main():
    uri, mode, arg = sys.argv[1], sys.argv[2], sys.argv[3]
    token = os.environ.get("ACL_STREAM_TOKEN", TOKEN)
    jar = {}
    client = flight.FlightClient(uri, middleware=[CookieJarFactory(jar)])
    options = flight.FlightCallOptions(headers=[(b"authorization", f"Bearer {token}".encode())])

    def open_stream(sql):
        info = client.get_flight_info(flight.FlightDescriptor.for_command(statement_query(sql)), options)
        return client.do_get(info.endpoints[0].ticket, options)

    try:
        if mode == "first":
            started = time.monotonic()
            reader = open_stream(arg)
            chunk = reader.read_chunk()
            first_ms = int((time.monotonic() - started) * 1000)
            rows = chunk.data.num_rows
            # the client stops here: a driver's LIMIT, a closed cursor, a user who saw enough
            reader.cancel()
            print({"first_ms": first_ms, "rows": rows})
        elif mode == "consume":
            # chunk by chunk, so what arrived before a mid-stream refusal (the cap) is counted too
            reader = open_stream(arg)
            rows = 0
            try:
                while True:
                    rows += reader.read_chunk().data.num_rows
            except StopIteration:
                print({"rows": rows})
            except Exception as ex:  # noqa: BLE001 - the assertion is about the text
                print({"rows": rows, "error": str(ex)})
        elif mode == "killed":
            # read one batch, then pause while stream.sh kills the session from the server side; the
            # next pull must say the session ended, not hand over another batch
            open_stream("SELECT 1 AS warm").read_all()
            reader = open_stream(arg)
            held = reader.read_chunk().data.num_rows
            sys.stdout.write("held\n")
            sys.stdout.flush()
            time.sleep(float(os.environ.get("ACL_STREAM_PAUSE", "3")))
            # gRPC had already sent batches ahead of the one read - as many as its flow-control window
            # held while we paused, which on a fast runner is a lot - so drain until the end arrives
            # or a deadline passes, never for a fixed number of batches: a budget in batches makes the
            # assertion depend on how much the transport happened to buffer, and that is a coin toss.
            more = 0
            deadline = time.monotonic() + float(os.environ.get("ACL_STREAM_DRAIN", "30"))
            try:
                while time.monotonic() < deadline:
                    more += reader.read_chunk().data.num_rows
                print({"held": held, "more": more, "error": "the stream did not end"})
            except Exception as ex:  # noqa: BLE001
                print({"held": held, "more": more, "error": str(ex)})
        elif mode == "supersede":
            # a session is a connection from the SECOND call on (spec 050: the cookie arrives with the
            # first answer): warm up, so the stream and the probe below share one connection
            open_stream("SELECT 1 AS warm").read_all()
            reader = open_stream(arg)
            chunk = reader.read_chunk()
            held = chunk.data.num_rows
            # the stream stays open and unpulled; the session's next statement must still run
            started = time.monotonic()
            probe = open_stream("SELECT 1 AS ok").read_all().to_pydict()
            waited_ms = int((time.monotonic() - started) * 1000)
            print({"held": held, "ok": probe.get("ok"), "waited_ms": waited_ms})
        elif mode == "ingest":
            # CommandStatementIngest (spec 049): table_definition_options=1 {if_not_exist=1: FAIL(2),
            # if_exists=2: APPEND(2)}, table=2 - the shape client.py's do_ingest composes
            payload = field(1, varint((1 << 3) | 0) + varint(2) + varint((2 << 3) | 0) + varint(2)) + text(2, arg)
            descriptor = flight.FlightDescriptor.for_command(command("CommandStatementIngest", payload))
            schema = pa.schema([("id", pa.int64()), ("tenant", pa.string()), ("amount", pa.int64()),
                                ("customer_id", pa.int64())])
            writer, reader = client.do_put(descriptor, schema, options)
            base = 5000000
            sent = 0
            while True:  # until stream.sh kills this process
                batch = pa.table({"id": list(range(base + sent, base + sent + 10000)),
                                  "tenant": ["acme"] * 10000, "amount": [1] * 10000,
                                  "customer_id": [0] * 10000}, schema=schema)
                writer.write_table(batch)
                sent += 10000
                sys.stdout.write(f"sent {sent}\n")
                sys.stdout.flush()
                time.sleep(0.2)
        else:
            raise SystemExit(f"unknown mode {mode}")
    except Exception as ex:  # noqa: BLE001 - the assertion is about the text
        print({"error": str(ex)})


if __name__ == "__main__":
    main()
