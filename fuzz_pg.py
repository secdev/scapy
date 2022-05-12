from scapy.all import *
from scapy.contrib.postgres import *

sock=socket.socket()
sock.connect(("127.0.0.1",5432))

o = {
    b'user': b'postgres',
    # b'database': b'postgres\xfe',
    b'application_name': b'psql',
    b'client_encoding': b'UTF8'
}

result = bytes()
for k, v in o.items():
    result += k + b'\0' + v + b'\0'

mystream=StreamSocket(sock)

test_packets = [
    Startup(options=result),
    Query(query=RandString()),
    Describe(statement=RandString()),
    Close(statement=RandString()),
    Execute(portal="foo"),
    Flush(),
    Parse(destination="foo", query="baz", num_param_dtypes=3, params=[1,2,3]),
    Parse(destination="fig", query="bar", num_param_dtypes=2, params=[1,2,]),
    CancelRequest(process_id=11234, secret=123455),
    Terminate(),
]

for p in test_packets:
    resp = mystream.sr1(p, timeout=2)
    if resp:
        PostgresBackend(resp.load).show2()
