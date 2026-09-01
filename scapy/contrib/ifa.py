# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) 2024 Jingfei Hu <hujf@clounix.com>

# scapy.contrib.description = Inband Flow Analyzer Protocol (IFA)
# scapy.contrib.status = loads

'''
Inband Flow Analyzer Protocol (IFA)

References:
https://datatracker.ietf.org/doc/html/draft-kumar-ippm-ifa-08
'''

import struct
import socket
from scapy.data import IP_PROTOS
from scapy.layers.l2 import Ether, GRE
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.vxlan import VXLAN
from scapy.contrib.geneve import GENEVE
from scapy.packet import Packet, bind_layers
from scapy.fields import BitField, BitEnumField, FlagsField, \
    ByteField, ByteEnumField, ShortField, IntField, PacketListField

IPPROTO_IFA = 131
IP_PROTOS[IPPROTO_IFA] = 'IFA'

_ifa_flags = [
    'C',    # Checksum
    'TA',   # Turn Around
    'I',    # Inband
    'TS',   # Tail Stamp
    'MF',   # Metadata Fragment
    'R',    # Reserved
    'R',    # Reserved
    'R',    # Reserved
]

_ifa_action = [
    'R',    # Reserved
    'R',    # Reserved
    'R',    # Reserved
    'R',    # Reserved
    'R',    # Reserved
    'R',    # Reserved
    'C',    # Color bit to mark the packet
    'L',    # Loss bit to measure packet loss
]

_ifa_speed = {
    0: '10Gbps',
    1: '25Gbps',
    2: '40Gbps',
    3: '50Gbps',
    4: '100Gbps',
    5: '200Gbps',
    6: '400Gbps',
}


class IFA(Packet):
    name = 'IFA'
    fields_desc = [
        BitField('ver', 3, 4),
        BitField('gns', 0, 4),
        ByteEnumField("nexthdr", 0, IP_PROTOS),
        FlagsField("flags", 0, 8, _ifa_flags),
        ByteField('maxlen', 255),
    ]


class IFAMd(Packet):
    name = 'IFAMd'
    fields_desc = [
        BitField('lns', 0, 4),
        BitField('device_id', 0, 20),
        ByteField('ttl', 0),
        BitEnumField('speed', 0, 4, _ifa_speed),
        BitField('ecn', 0, 2),
        BitField('qid', 0, 6),
        BitField('rx_sec', 0, 20),
        ShortField('dport', 0),
        ShortField('sport', 0),
        IntField('rx_nsec', 0),
        IntField('latency', 0),
        IntField('qbytes', 0),
        ShortField('rsvd0', 0),
        ShortField('qcells', 0),
        IntField('rsvd1', 0),
    ]

    def extract_padding(self, s):
        return "", s


class IFAMdHdr(Packet):
    name = 'IFAMdHdr'
    fields_desc = [
        ByteField('request', 0),
        FlagsField("action", 0, 8, _ifa_action),
        ByteField('hoplmt', 128),
        ByteField('curlen', 0),
        PacketListField("mdstack", None, IFAMd,
                        length_from=lambda pkt: pkt.curlen * 4)
    ]

    def post_build(self, p, pay):
        mdlen = (len(p) - 4) // 4
        if self.curlen != mdlen:
            p = p[:3] + struct.pack("!B", mdlen) + p[4:]
        return p + pay

    def guess_payload_class(self, payload):
        if isinstance(self.underlayer, UDP):
            if self.underlayer.dport in [4789, 4790]:
                return VXLAN
            elif self.underlayer.dport == 6081:
                return GENEVE
        elif isinstance(self.underlayer, GRE):
            if self.underlayer.proto == 0x6558:
                return Ether
            if self.underlayer.proto == 0x0800:
                return IP
            if self.underlayer.proto == 0x86dd:
                return IPv6
        return Packet.guess_payload_class(self, payload)


bind_layers(IP, IFA, proto=IPPROTO_IFA)
bind_layers(IPv6, IFA, nh=IPPROTO_IFA)
bind_layers(IFA, TCP, nexthdr=socket.IPPROTO_TCP)
bind_layers(IFA, UDP, nexthdr=socket.IPPROTO_UDP)
bind_layers(IFA, GRE, nexthdr=socket.IPPROTO_GRE)
