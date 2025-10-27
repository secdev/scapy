from scapy.all import *
import time

# Test sending & sniffing without root
pkt = IP(dst="127.0.0.1")/UDP(dport=55555)/Raw(load=b"Hello NonRoot")
s = conf.L3socket(port=55555)
s.send(pkt)

pkts = sniff(count=1, timeout=2)
for p in pkts:
    print(p.summary())
