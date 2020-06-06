# This file is part of Scapy.
# See http://www.secdev.org/projects/scapy for more information.
#
# Scapy is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# Scapy is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Scapy.  If not, see <http://www.gnu.org/licenses/>.
#
# Copyright (C) 2020 Rahul Jadhav <nyrahul@gmail.com>

# RFC 6550
# scapy.contrib.description = Routing Protocol for LLNs (RPL)
# scapy.contrib.status = loads

"""
RPL
===

RFC 6550 - Routing Protocol for Low-Power and Lossy Networks (RPL)
draft-ietf-roll-efficient-npdao-17 - Efficient Route Invalidation

+----------------------------------------------------------------------+
| RPL Options : Pad1 PadN TIO RIO PIO Tgt TgtDesc DODAGConfig DAGMC ...|
+----------------------------------------------------------------------+
| RPL Msgs : DIS DIO DAO DAOACK DCO DCOACK                             |
+----------------------------------------------------------------------+
| ICMPv6 : type 155 RPL                                                |
+----------------------------------------------------------------------+

"""


from scapy.packet import Packet, bind_layers
from scapy.fields import ByteEnumField, ByteField, IP6Field, ShortField, \
    BitField, BitEnumField, FieldLenField, StrLenField, IntField, \
    ConditionalField
from scapy.layers.inet6 import ICMPv6RPL, icmp6ndraprefs, _IP6PrefixField


# https://www.iana.org/assignments/rpl/rpl.xhtml#mop
RPLMOP = {0: "No Downward routes",
          1: "Non-Storing",
          2: "Storing with no multicast support",
          3: "Storing with multicast support",
          4: "P2P Route Discovery"}


# https://www.iana.org/assignments/rpl/rpl.xhtml#control-message-options
RPLOPTSSTR = {0: "Pad1",
              1: "PadN",
              2: "DAG Metric Container",
              3: "Routing Information",
              4: "DODAG Configuration",
              5: "RPL Target",
              6: "Transit Information",
              7: "Solicited Information",
              8: "Prefix Information Option",
              9: "Target Descriptor",
              10: "P2P Route Discovery"}


class _RPLGuessOption(Packet):
    name = "Dummy RPL Option class"


class RPLOptRIO(_RPLGuessOption):
    """
    Control Option: Routing Information Option (RIO)
    """
    name = "Routing Information"
    fields_desc = [ByteEnumField("otype", 3, RPLOPTSSTR),
                   FieldLenField("len", None, length_of="prefix", fmt="B",
                                 adjust=lambda pkt, x: x + 6),
                   ByteField("plen", None),
                   BitField("res1", 0, 3),
                   BitEnumField("prf", 0, 2, icmp6ndraprefs),
                   BitField("res2", 0, 3),
                   IntField("rtlifetime", 0xffffffff),
                   _IP6PrefixField("prefix", None)]


class RPLOptDODAGConfig(_RPLGuessOption):
    """
    Control Option: DODAG Configuration
    """
    name = "DODAG Configuration"
    fields_desc = [ByteEnumField("otype", 4, RPLOPTSSTR),
                   ByteField("len", 14),
                   BitField("flags", 0, 4),
                   BitField("A", 0, 1),
                   BitField("PCS", 0, 3),
                   ByteField("DIOIntDoubl", 20),
                   ByteField("DIOIntMin", 3),
                   ByteField("DIORedun", 10),
                   ShortField("MaxRankIncrease", 0),
                   ShortField("MinRankIncrease", 256),
                   ShortField("OCP", 1),
                   ByteField("reserved", 0),
                   ByteField("DefLifetime", 0xff),
                   ShortField("LifetimeUnit", 0xffff)]


class RPLOptTgt(_RPLGuessOption):
    """
    Control Option: RPL Target
    """
    name = "RPL Target"
    fields_desc = [ByteEnumField("otype", 5, RPLOPTSSTR),
                   FieldLenField("len", None, length_of="prefix", fmt="B",
                                 adjust=lambda pkt, x: x + 2),
                   ByteField("flags", 0),
                   ByteField("plen", 0),
                   _IP6PrefixField("prefix", None)]


class RPLOptTIO(_RPLGuessOption):
    """
    Control Option: Transit Information Option (TIO)
    """
    name = "Transit Information"
    fields_desc = [ByteEnumField("otype", 6, RPLOPTSSTR),
                   FieldLenField("len", None, length_of="parentaddr", fmt="B",
                                 adjust=lambda pkt, x: x + 4),
                   BitField("E", 0, 1),
                   BitField("flags", 0, 7),
                   ByteField("pathcontrol", 0),
                   ByteField("pathseq", 0),
                   ByteField("pathlifetime", 0xff),
                   _IP6PrefixField("parentaddr", None)]


class RPLOptSolInfo(_RPLGuessOption):
    """
    Control Option: Solicited Information
    """
    name = "Solicited Information"
    fields_desc = [ByteEnumField("otype", 7, RPLOPTSSTR),
                   ByteField("len", 19),
                   ByteField("RPLInstanceID", 0),
                   BitField("V", 0, 1),
                   BitField("I", 0, 1),
                   BitField("D", 0, 1),
                   BitField("flags", 0, 5),
                   IP6Field("dodagid", "::1"),
                   ByteField("ver", 0)]


class RPLOptPIO(_RPLGuessOption):
    """
    Control Option: Prefix Information Option (PIO)
    """
    name = "Prefix Information"
    fields_desc = [ByteEnumField("otype", 8, RPLOPTSSTR),
                   ByteField("len", 30),
                   ByteField("plen", 64),
                   BitField("L", 0, 1),
                   BitField("A", 0, 1),
                   BitField("R", 0, 1),
                   BitField("reserved1", 0, 5),
                   IntField("validlifetime", 0xffffffff),
                   IntField("preflifetime", 0xffffffff),
                   IntField("reserved2", 0),
                   IP6Field("prefix", "::1")]


class RPLOptTgtDesc(_RPLGuessOption):
    """
    Control Option: RPL Target Descriptor
    """
    name = "RPL Target Descriptor"
    fields_desc = [ByteEnumField("otype", 9, RPLOPTSSTR),
                   ByteField("len", 4),
                   IntField("descriptor", 0)]


class RPLOptPad1(_RPLGuessOption):
    """
    Control Option: Pad 1 byte
    """
    name = "Pad1"
    fields_desc = [ByteEnumField("otype", 0x00, RPLOPTSSTR)]


class RPLOptPadN(_RPLGuessOption):
    """
    Control Option: Pad N bytes
    """
    name = "PadN"
    fields_desc = [ByteEnumField("otype", 0x01, RPLOPTSSTR),
                   FieldLenField("optlen", None, length_of="optdata", fmt="B"),
                   StrLenField("optdata", "",
                               length_from=lambda pkt: pkt.optlen)]


# https://www.iana.org/assignments/rpl/rpl.xhtml#control-message-options
RPLOPTS = {0: RPLOptPad1,
           1: RPLOptPadN,
           # 2: RPLOptDAGMC, defined in rpl_metrics.py
           3: RPLOptRIO,
           4: RPLOptDODAGConfig,
           5: RPLOptTgt,
           6: RPLOptTIO,
           7: RPLOptSolInfo,
           8: RPLOptPIO,
           9: RPLOptTgtDesc}


# RPL Control Message Handling


class _RPLGuessMsgType(Packet):
    name = "Dummy RPL Message class"

    def guess_payload_class(self, payload):
        if isinstance(payload, str):
            otype = ord(payload[0])
        else:
            otype = payload[0]
        return RPLOPTS.get(otype)


class RPLDIS(_RPLGuessMsgType, _RPLGuessOption):
    """
    Control Message: DODAG Information Solicitation (DIS)
    """
    name = "DODAG Information Solicitation"
    fields_desc = [ByteField("flags", 0),
                   ByteField("reserved", 0)]


class RPLDIO(_RPLGuessMsgType, _RPLGuessOption):
    """
    Control Message: DODAG Information Object (DIO)
    """
    name = "DODAG Information Object"
    fields_desc = [ByteField("RPLInstanceID", 50),
                   ByteField("ver", 0),
                   ShortField("rank", 1),
                   BitField("G", 1, 1),
                   BitField("unused1", 0, 1),
                   BitEnumField("mop", 1, 3, RPLMOP),
                   BitField("prf", 0, 3),
                   ByteField("dtsn", 240),
                   ByteField("flags", 0),
                   ByteField("reserved", 0),
                   IP6Field("dodagid", "::1")]


class RPLDAO(_RPLGuessMsgType, _RPLGuessOption):
    """
    Control Message: Destination Advertisement Object (DAO)
    """
    name = "Destination Advertisement Object"
    fields_desc = [ByteField("RPLInstanceID", 50),
                   BitField("K", 0, 1),
                   BitField("D", 0, 1),
                   BitField("flags", 0, 6),
                   ByteField("reserved", 0),
                   ByteField("daoseq", 1),
                   ConditionalField(IP6Field("dodagid", None),
                                    lambda pkt: pkt.D == 1)]


class RPLDAOACK(_RPLGuessMsgType, _RPLGuessOption):
    """
    Control Message: Destination Advertisement Object Acknowledgement (DAOACK)
    """
    name = "Destination Advertisement Object Acknowledgement"
    fields_desc = [ByteField("RPLInstanceID", 50),
                   BitField("D", 0, 1),
                   BitField("reserved", 0, 7),
                   ByteField("daoseq", 1),
                   ByteField("status", 0),
                   ConditionalField(IP6Field("dodagid", None),
                                    lambda pkt: pkt.D == 1)]


# https://datatracker.ietf.org/doc/draft-ietf-roll-efficient-npdao/
class RPLDCO(_RPLGuessMsgType, _RPLGuessOption):
    """
    Control Message: Destination Cleanup Object (DCO)
    """
    name = "Destination Cleanup Object"
    fields_desc = [ByteField("RPLInstanceID", 50),
                   BitField("K", 0, 1),
                   BitField("D", 0, 1),
                   BitField("flags", 0, 6),
                   ByteField("status", 0),
                   ByteField("dcoseq", 1),
                   ConditionalField(IP6Field("dodagid", None),
                                    lambda pkt: pkt.D == 1)]


# https://datatracker.ietf.org/doc/draft-ietf-roll-efficient-npdao/
class RPLDCOACK(_RPLGuessMsgType, _RPLGuessOption):
    """
    Control Message: Destination Cleanup Object Acknowledgement (DCOACK)
    """
    name = "Destination Cleanup Object Acknowledgement"
    fields_desc = [ByteField("RPLInstanceID", 50),
                   BitField("D", 0, 1),
                   BitField("flags", 0, 7),
                   ByteField("dcoseq", 1),
                   ByteField("status", 0),
                   ConditionalField(IP6Field("dodagid", None),
                                    lambda pkt: pkt.D == 1)]


# https://www.iana.org/assignments/rpl/rpl.xhtml#control-codes
bind_layers(ICMPv6RPL, RPLDIS, code=0)
bind_layers(ICMPv6RPL, RPLDIO, code=1)
bind_layers(ICMPv6RPL, RPLDAO, code=2)
bind_layers(ICMPv6RPL, RPLDAOACK, code=3)
bind_layers(ICMPv6RPL, RPLDCO, code=7)
bind_layers(ICMPv6RPL, RPLDCOACK, code=8)
