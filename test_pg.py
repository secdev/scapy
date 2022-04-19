from scapy.contrib.postgres import BasePacket, Startup
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp, srp1
from scapy.utils import hexdump


o = {
    'user': 'anthonyshaw',
    'database': 'anthonyshaw',
    'application_name': 'psql',
    'client_encoding': 'UTF8'
}

result = bytes()
for k, v in o.items():
    result += k.encode(encoding='ascii') + b'\0' + v.encode(encoding='ascii') + b'\0'


packet = Ether()/IP(dst='192.168.86.227')/TCP(dport=5432, flags='S')/Startup(options=result)
hexdump(packet)

srp1(packet)

