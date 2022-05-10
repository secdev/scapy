from scapy.all import *
from scapy.contrib.postgres import *

sock=socket.socket()
sock.connect(("192.168.86.244",5432))

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
init_packet = Startup(options=result)
init_packet.show2()
r = mystream.sr1(init_packet)
PostgresBackend(r.load).show2()

fuzz_payload = Query(query=RandString())
fuzz_payload.show2()
r = mystream.sr1(fuzz_payload)
r_backend = PostgresBackend(r.load)
r_backend.show2()

