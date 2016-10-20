
# scapy.contrib.description = CARP
# scapy.contrib.status = loads

import struct, hmac, hashlib

from scapy.packet import *
from scapy.layers.inet import IP
from scapy.fields import BitField, ByteField, XShortField, IntField, XIntField
from scapy.utils import checksum, inet_aton

class CARP(Packet):
    name = "CARP"
    fields_desc = [ BitField("version", 4, 4),
        BitField("type", 4, 4),
        ByteField("vhid", 1),
        ByteField("advskew", 0),
        ByteField("authlen", 0),
        ByteField("demotion", 0),
        ByteField("advbase", 0),
        XShortField("chksum", 0),
        XIntField("counter1", 0),
        XIntField("counter2", 0),
        XIntField("hmac1", 0),
        XIntField("hmac2", 0),
        XIntField("hmac3", 0),
        XIntField("hmac4", 0),
        XIntField("hmac5", 0)
    ]

    def post_build(self, pkt, pay):
        if self.chksum == None:
            pkt = pkt[:6] + struct.pack("!H", checksum(pkt)) + pkt[8:]

        return pkt

def build_hmac_sha1(pkt, pw = '\0' * 20, ip4l=None, ip6l=None):
    if ip4l is None:
        ip4l = []
    if ip6l is None:
        ip6l = []
    if not pkt.haslayer(CARP):
        return None 

    p = pkt[CARP]
    h = hmac.new(pw, digestmod = hashlib.sha1)
    # XXX: this is a dirty hack. it needs to pack version and type into a single 8bit field
    h.update('\x21')
    # XXX: mac addy if different from special link layer. comes before vhid
    h.update(struct.pack('!B', p.vhid))

    sl = []
    for i in ip4l:
        # sort ips from smallest to largest
        sl.append(inet_aton(i))
    sl.sort()

    for i in sl:
        h.update(i)

    # XXX: do ip6l sorting

    return h.digest()

"""
XXX: Usually CARP is multicast to 224.0.0.18 but because of virtual setup, it'll 
be unicast between nodes. Uncomment the following line for normal use
bind_layers(IP, CARP, proto=112, dst='224.0.0.18')
"""
bind_layers(IP, CARP, proto=112)
