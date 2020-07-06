
"""
L2F (Cisco Layer Two Forwarding (Protocol))

[RFC 2341]
"""

import struct

from scapy.packet import Packet, bind_layers, bind_bottom_up
from scapy.fields import BitEnumField, ConditionalField, FlagsField, \
    PadField, ShortField, BitField, ByteField, IntField, StrLenField
from scapy.layers.inet import UDP
from scapy.layers.ppp import PPP


class L2F(Packet):
    name = "L2F"
    fields_desc = [
        BitField("F", 0, 1),
        BitField("K", 0, 1),
        BitField("P", 0, 1),
        BitField("S", 0, 1),
        BitField("reserved", 0, 8),
        BitField("C", 0, 1),
        BitField("version", 1, 3),
        ByteField("protocol", 0),
        ConditionalField(ByteField("sequence", 1), lambda pkt: pkt.S ==1),
        ShortField("MID", 0),
        ShortField("client_ID", 0),
        ShortField("length", 0),
        ConditionalField(ShortField("offset", 1), lambda pkt: pkt.F == 1),
        ConditionalField(IntField("key", 1), lambda pkt : pkt.K == 1),
        StrLenField("payload",0, length_from=lambda x:x.length),
        ConditionalField(ShortField("checksum", 1), lambda pkt: pkt.C == 1)]

        # def post_build(self, pkt, pay):
        # if self.len is None:
        #     tmp_len = len(pkt) + len(pay)
        #     pkt = pkt[:2] + struct.pack("!H", tmp_len) + pkt[4:]
        # return pkt + pay

bind_bottom_up(PPP, L2F, dport=1701)
bind_bottom_up(UDP, L2F, sport=1701)
bind_layers(UDP, L2F, dport=1701, sport=1701)
bind_layers(L2F, PPP,)
