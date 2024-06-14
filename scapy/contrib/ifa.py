# scapy.contrib.description = Inband Flow Analyzer Protocol (IFA)
# scapy.contrib.status = loads

'''
Inband Flow Analyzer Protocol (IFA)

References:
https://datatracker.ietf.org/doc/html/draft-kumar-ippm-ifa-07

Example Packet Format:
IFAoIPv4UDP   = Ether/IP/IFA/UDP/IFAMetaHdr/IFAMetaHop/.../IFAMetaHop/Payload
IFAoIPv4TCP   = Ether/IP/IFA/TCP/IFAMetaHdr/IFAMetaHop/.../IFAMetaHop/Payload
IFAoIPv4VxLAN = Ether/IP/IFA/UDP/IFAMetaHdr/IFAMetaHop/.../IFAMetaHop/VXLAN/Ether/IP/TCP/Payload    # noqa: E501
IFAoIPv4GRE   = Ether/IP/IFA/GRE/IFAMetaHdr/IFAMetaHop/.../IFAMetaHop/Ether/IP/TCP/Payload  # noqa: E501
IFAoIPv6UDP   = Ether/IPv6/IFA/UDP/IFAMetaHdr/IFAMetaHop/.../IFAMetaHop/Payload
IFAoIPv6TCP   = Ether/IPv6/IFA/TCP/IFAMetaHdr/IFAMetaHop/.../IFAMetaHop/Payload
IFAoIPv6VxLAN = Ether/IPv6/IFA/UDP/IFAMetaHdr/IFAMetaHop/.../IFAMetaHop/VXLAN/Ether/IP/TCP/Payload    # noqa: E501
IFAoIPv6GRE   = Ether/IPv6/IFA/GRE/IFAMetaHdr/IFAMetaHop/.../IFAMetaHop/Ether/IP/TCP/Payload  # noqa: E501
'''

import struct
import socket
from scapy.packet import Packet, bind_layers
from scapy.fields import (
    BitField,
    FlagsField,
    ByteField,
    ShortField,
    IntField,
    PacketListField
)
from scapy.layers.l2 import GRE
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.vxlan import VXLAN

IPPROTO_IFA = 131

_IFA_SHIM_FLAGS = [
    "fragment",
    "tail_stamp",
    "inband",
    "turn_around",
    "checksum"
]


class IFA(Packet):
    name = 'IFA'
    fields_desc = [
        BitField('ver', 2, 4),
        BitField('gns', 0, 4),
        ByteField('next_protocol', 0),
        BitField('reserved', 0, 3),
        FlagsField("flags", 0, 5, _IFA_SHIM_FLAGS),
        ByteField('max_len', 255),
    ]


class IFAMetaHop(Packet):
    name = 'IFAMetaHop'
    fields_desc = [
        BitField('lns', 0, 4),
        BitField('device_id', 0, 20),
        ByteField('ip_ttl', 0),
        BitField('eport_speed', 0, 4),
        BitField('congestion', 0, 2),
        BitField('queue_id', 0, 6),
        BitField('rx_ts_s', 0, 20),
        ShortField('egr_port', 0),
        ShortField('igr_port', 0),
        IntField('rx_ts_ns', 0),
        IntField('residence', 0),
        IntField('que_bytes', 0),
        ShortField('reserved0', 0),
        ShortField('que_cells', 0),
        IntField('reserved1', 0),
    ]

    def extract_padding(self, s):
        return "", s


class IFAMetaHdr(Packet):
    name = 'IFAMetaHdr'
    fields_desc = [
        ByteField('request', 0),
        ByteField('action', 0),
        ByteField('hop_limit', 128),
        ByteField('cur_len', 0),
        PacketListField("meta_hops", None, IFAMetaHop,
                        length_from=lambda pkt: pkt.cur_len * 4)
    ]

    def post_build(self, p, pay):
        meta_hops_len = (len(p) - 4) // 4
        if self.cur_len != meta_hops_len:
            p = p[:3] + struct.pack("!B", meta_hops_len) + p[4:]
        return p + pay

    def guess_payload_class(self, payload):
        ifa_hdr = self.underlayer.underlayer
        if isinstance(ifa_hdr, IFA):
            if (ifa_hdr.next_protocol == socket.IPPROTO_UDP) and (self.underlayer.dport == 4789):  # noqa: E501
                return VXLAN
            elif (ifa_hdr.next_protocol == socket.IPPROTO_GRE):
                gre_hdr = self.underlayer
                from scapy.layers.l2 import (LLC, Dot1Q, Dot1AD, Ether, ARP, GRErouting)
                if (gre_hdr.proto == 122):
                    return LLC
                elif (gre_hdr.proto == 33024):
                    return Dot1Q
                elif (gre_hdr.proto == 0x88a8):
                    return Dot1AD
                elif (gre_hdr.proto == 0x6558):
                    return Ether
                elif (gre_hdr.proto == 2054):
                    return ARP
                elif (gre_hdr.routing_present == 1):
                    return GRErouting
        return Packet.guess_payload_class(self, payload)


bind_layers(IP, IFA, proto=IPPROTO_IFA)
bind_layers(IPv6, IFA, nh=IPPROTO_IFA)
bind_layers(IFA, TCP, next_protocol=socket.IPPROTO_TCP)
bind_layers(IFA, UDP, next_protocol=socket.IPPROTO_UDP)
bind_layers(IFA, GRE, next_protocol=socket.IPPROTO_GRE)
