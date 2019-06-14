# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Gabriel Potter
# This program is published under a GPLv2 license


# https://github.com/secdev/scapy/issues/1791

from common import *

# Router IP
dest = conf.route.route("0.0.0.0")[2]

send_tcp = True
send_icmp = False

pkts = []
for i in range(1,50):
    a = IP(dst=dest) / TCP(flags="S", seq=i, sport=65000, dport=55556)
    b = IP(dst=dest)/ICMP()
    if send_tcp:
        pkts.append(a)
    if send_icmp:
        pkts.append(b)

ans, unans = sr(pkts, filter="host {0}".format(dest), inter=0, timeout=1, prebuild=True)

print("scapy version: {}".format(conf.version))

average = 0

for pkt in ans:
    sent = pkt[0]
    received = pkt[1]
    res = (received.time - sent.sent_time)
    average += res
    print("%s %s : %s" % (received.time, sent.sent_time, res))

print("AVERAGE RESPONSE TIME: %ss" % (average / len(ans)))
