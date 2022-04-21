from scapy.compat import raw
from scapy.contrib.postgres import AuthenticationRequest, BasePacket, Startup, ErrorResponse
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.sendrecv import srp1, sendp
import random

o = {
    b'user': b'postgres',
    # b'database': b'postgres\xfe',
    b'application_name': b'psql',
    b'client_encoding': b'UTF8'
}

result = bytes()
for k, v in o.items():
    result += k + b'\0' + v + b'\0'

sport = random.randint(1024,65535)
dest = Ether()/IP(dst='192.168.86.237')

syn = TCP(sport=sport, dport=5432, flags='S', seq=0)
synack = srp1(dest/syn)

my_ack = synack.seq + 1
# ACK
ack = TCP(sport=sport, dport=5432, flags='A', seq=1, ack=my_ack)
sendp(dest/ack)

startup = TCP(sport=sport, dport=5432, flags='PA', seq=1, ack=my_ack)/Startup(options=result)

r = srp1(dest/startup)

auth_response = BasePacket(r.payload.payload.payload.load)

auth_response.show()

sendp(dest/TCP(sport=sport, dport=5432, flags='F'))