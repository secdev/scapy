# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information

# scapy.contrib.description = Protocol Independent Multicast (PIM)
# scapy.contrib.status = loads
"""
References:
  - https://tools.ietf.org/html/rfc4601
  - https://www.iana.org/assignments/pim-parameters/pim-parameters.xhtml
"""
import struct
from scapy.packet import Packet, bind_layers
from scapy.fields import BitFieldLenField, BitField, BitEnumField, ByteField, \
    ShortField, XShortField, IPField, IP6Field, PacketListField, \
    IntField, FieldLenField, BoundStrLenField, MultipleTypeField
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6, in6_chksum, _IPv6ExtHdr
from scapy.utils import checksum
from scapy.compat import orb
from scapy.config import conf
from scapy.volatile import RandInt


PIM_TYPE = {
    0: "Hello",
    1: "Register",
    2: "Register-Stop",
    3: "Join/Prune",
    4: "Bootstrap",
    5: "Assert",
    6: "Graft",
    7: "Graft-Ack",
    8: "Candidate-RP-Advertisement"
}


class PIMv2Hdr(Packet):
    name = "Protocol Independent Multicast Version 2 Header"
    fields_desc = [BitField("version", 2, 4),
                   BitEnumField("type", 0, 4, PIM_TYPE),
                   ByteField("reserved", 0),
                   XShortField("chksum", None)]

    def post_build(self, p, pay):
        """
        Called implicitly before a packet is sent to compute and
         place PIM checksum.

        Parameters:
          self    The instantiation of an PIMv2Hdr class
          p       The PIMv2Hdr message in hex in network byte order
          pay     Additional payload for the PIMv2Hdr message
        """
        p += pay
        if self.chksum is None:
            if isinstance(self.underlayer, IP):
                ck = checksum(p)
                # ck = in4_chksum(103, self.underlayer, p)
                # According to RFC768 if the result checksum is 0, it should be set to 0xFFFF  # noqa: E501
                if ck == 0:
                    ck = 0xFFFF
                p = p[:2] + struct.pack("!H", ck) + p[4:]

            elif isinstance(self.underlayer, IPv6) or isinstance(self.underlayer, _IPv6ExtHdr):  # noqa: E501
                ck = in6_chksum(103, self.underlayer, p)  # noqa: E501
                # According to RFC2460 if the result checksum is 0, it should be set to 0xFFFF  # noqa: E501
                if ck == 0:
                    ck = 0xFFFF
                p = p[:2] + struct.pack("!H", ck) + p[4:]

        return p


def _guess_pim_tlv_class(h_classes, default_key, pkt, **kargs):
    cls = conf.raw_layer
    if len(pkt) >= 2:
        tlvtype = orb(pkt[1])
        cls = h_classes.get(tlvtype, default_key)
    return cls(pkt, **kargs)


class _PIMGenericTlvBase(Packet):
    fields_desc = [ByteField("type", 0),
                   FieldLenField("length", None, length_of="value", fmt="B"),
                   BoundStrLenField("value", "",
                                    length_from=lambda pkt: pkt.length)]

    def guess_payload_class(self, p):
        return conf.padding_layer

    def extract_padding(self, s):
        return "", s


##################################
# PIMv2 Hello
##################################
class _PIMv2GenericHello(_PIMGenericTlvBase):
    name = "PIMv2 Generic Hello"


def _guess_pimv2_hello_class(p, **kargs):
    return _guess_pim_tlv_class(PIMv2_HELLO_CLASSES, None, p, **kargs)


class _PIMv2HelloListField(PacketListField):
    def __init__(self):
        PacketListField.__init__(self, "option", [], _guess_pimv2_hello_class)


class PIMv2Hello(Packet):
    name = "PIMv2 Hello Options"
    fields_desc = [
        _PIMv2HelloListField()
    ]


class PIMv2HelloHoldtime(_PIMv2GenericHello):
    name = "PIMv2 Hello Options : Holdtime"
    fields_desc = [
        ShortField("type", 1),
        FieldLenField("length", None, length_of="holdtime", fmt="!H"),
        ShortField("holdtime", 105)
    ]


class PIMv2HelloLANPruneDelayValue(_PIMv2GenericHello):
    name = "PIMv2 Hello Options : LAN Prune Delay Value"
    fields_desc = [
        BitField("t", 0, 1),
        BitField("propagation_delay", 500, 15),
        ShortField("override_interval", 2500),
    ]


class PIMv2HelloLANPruneDelay(_PIMv2GenericHello):
    name = "PIMv2 Hello Options : LAN Prune Delay"
    fields_desc = [
        ShortField("type", 2),
        FieldLenField("length", None, length_of="value", fmt="!H"),
        PacketListField("value", PIMv2HelloLANPruneDelayValue(),
                        PIMv2HelloLANPruneDelayValue,
                        length_from=lambda pkt: pkt.length)
    ]


class PIMv2HelloDRPriority(_PIMv2GenericHello):
    name = "PIMv2 Hello Options : DR Priority"
    fields_desc = [
        ShortField("type", 19),
        FieldLenField("length", None, length_of="dr_priority", fmt="!H"),
        IntField("dr_priority", 1)
    ]


class PIMv2HelloGenerationID(_PIMv2GenericHello):
    name = "PIMv2 Hello Options : Generation ID"
    fields_desc = [
        ShortField("type", 20),
        FieldLenField(
            "length", None, length_of="generation_id", fmt="!H"
        ),
        IntField("generation_id", RandInt())
    ]


class PIMv2HelloStateRefreshValue(_PIMv2GenericHello):
    name = "PIMv2 Hello Options : State-Refresh Value"
    fields_desc = [ByteField("version", 1),
                   ByteField("interval", 0),
                   ShortField("reserved", 0)]


class PIMv2HelloStateRefresh(_PIMv2GenericHello):
    name = "PIMv2 Hello Options : State-Refresh"
    fields_desc = [
        ShortField("type", 21),
        FieldLenField(
            "length", None, length_of="value", fmt="!H"
        ),
        PacketListField("value", PIMv2HelloStateRefreshValue(),
                        PIMv2HelloStateRefreshValue)
    ]


class PIMv2HelloAddrListValue(_PIMv2GenericHello):
    name = "PIMv2 Hello Options : Address List Value"
    fields_desc = [
        ByteField("addr_family", 1),
        ByteField("encoding_type", 0),
        IP6Field("prefix", "::"),
    ]


class PIMv2HelloAddrList(_PIMv2GenericHello):
    name = "PIMv2 Hello Options : Address List"
    fields_desc = [
        ShortField("type", 24),
        FieldLenField(
            "length", None, length_of="value" , fmt="!H"
        ),
        PacketListField("value", PIMv2HelloAddrListValue(),
                        PIMv2HelloAddrListValue)
    ]


PIMv2_HELLO_CLASSES = {
    1: PIMv2HelloHoldtime,
    2: PIMv2HelloLANPruneDelay,
    19: PIMv2HelloDRPriority,
    20: PIMv2HelloGenerationID,
    21: PIMv2HelloStateRefresh,
    24: PIMv2HelloAddrList,
    None: _PIMv2GenericHello,
}


##################################
# PIMv2 Join/Prune
##################################
class PIMv2JoinPruneAddrsBase(_PIMGenericTlvBase):
    fields_desc = [
        ByteField("addr_family", 1),
        ByteField("encoding_type", 0),
        BitField("rsrvd", 0, 5),
        BitField("sparse", 0, 1),
        BitField("wildcard", 0, 1),
        BitField("rpt", 1, 1),
        ByteField("mask_len", 32),
        MultipleTypeField(
            [(IP6Field("src_ip", "::"),
              lambda pkt: pkt.addr_family == 2)],
            IPField("src_ip", "0.0.0.0")
        ),

    ]


class PIMv2JoinAddrs(PIMv2JoinPruneAddrsBase):
    name = "PIMv2 Join: Source Address"


class PIMv2PruneAddrs(PIMv2JoinPruneAddrsBase):
    name = "PIMv2 Prune: Source Address"


class PIMv2GroupAddrs(_PIMGenericTlvBase):
    name = "PIMv2 Join/Prune: Multicast Group Address"
    fields_desc = [
        ByteField("addr_family", 1),
        ByteField("encoding_type", 0),
        BitField("bidirection", 0, 1),
        BitField("reserved", 0, 6),
        BitField("admin_scope_zone", 0, 1),
        ByteField("mask_len", 32),
        MultipleTypeField(
            [(IP6Field("gaddr", "::"),
              lambda pkt: pkt.addr_family == 2)],
            IPField("gaddr", "0.0.0.0")
        ),
        BitFieldLenField("num_joins", None, size=16, count_of="join_ips"),
        BitFieldLenField("num_prunes", None, size=16, count_of="prune_ips"),
        PacketListField("join_ips", [], PIMv2JoinAddrs,
                        count_from=lambda x: x.num_joins),
        PacketListField("prune_ips", [], PIMv2PruneAddrs,
                        count_from=lambda x: x.num_prunes),
    ]


class PIMv2JoinPrune(_PIMGenericTlvBase):
    name = "PIMv2 Join/Prune Options"
    fields_desc = [
        ByteField("up_addr_family", 1),
        ByteField("up_encoding_type", 0),
        MultipleTypeField(
            [(IP6Field("up_neighbor_ip", "::"),
              lambda pkt: pkt.up_addr_family == 2)],
            IPField("up_neighbor_ip", "0.0.0.0")
        ),
        ByteField("reserved", 0),
        FieldLenField("num_group", None, count_of="jp_ips", fmt="B"),
        ShortField("holdtime", 210),
        PacketListField("jp_ips", [], PIMv2GroupAddrs,
                        count_from=lambda pkt: pkt.num_group)
    ]


bind_layers(IP, PIMv2Hdr, proto=103)
bind_layers(IPv6, PIMv2Hdr, nh=103)
bind_layers(PIMv2Hdr, PIMv2Hello, type=0)
bind_layers(PIMv2Hdr, PIMv2JoinPrune, type=3)
