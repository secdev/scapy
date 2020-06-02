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
RFC 6550 - Routing Protocol for Low-Power and Lossy Networks (RPL)
draft-ietf-roll-efficient-npdao-17 - Efficient Route Invalidation
"""

from scapy.packet import Packet, bind_layers
from scapy.fields import ByteEnumField, ByteField, IP6Field, ShortField, \
    BitField, BitEnumField, FieldLenField, StrLenField, IntField
from scapy.layers.inet6 import RPL, icmp6ndraprefs, _IP6PrefixField


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
    name = "Dummy RPL Option class that implements guess_payload_class()"


class OptRIO(_RPLGuessOption):
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


class OptDODAGConfig(_RPLGuessOption):
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


class OptTgt(_RPLGuessOption):
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


class OptTIO(_RPLGuessOption):
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


class OptSolInfo(_RPLGuessOption):
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


class OptPIO(_RPLGuessOption):
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


class OptTgtDesc(_RPLGuessOption):
    """
    Control Option: RPL Target Descriptor
    """
    name = "RPL Target Descriptor"
    fields_desc = [ByteEnumField("otype", 9, RPLOPTSSTR),
                   ByteField("len", 4),
                   IntField("descriptor", 0)]


class Pad1(_RPLGuessOption):
    """
    Control Option: Pad 1 byte
    """
    name = "Pad1"
    fields_desc = [ByteEnumField("otype", 0x00, RPLOPTSSTR)]


class PadN(_RPLGuessOption):
    """
    Control Option: Pad N bytes
    """
    name = "PadN"
    fields_desc = [ByteEnumField("otype", 0x01, RPLOPTSSTR),
                   FieldLenField("optlen", None, length_of="optdata", fmt="B"),
                   StrLenField("optdata", "",
                               length_from=lambda pkt: pkt.optlen)]


# RPL Control Message Handling


class DIS(_RPLGuessOption, Packet):
    """
    Control Message: DODAG Information Solicitation (DIS)
    """
    name = "DODAG Information Solicitation"
    fields_desc = [ByteField("flags", 0),
                   ByteField("reserved", 0)]


class DIO(_RPLGuessOption, Packet):
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


class _OptDODAGIDField(IP6Field):
    """
    Handle Optional DODAG ID field in DAO
    """
    def getfield(self, pkt, s):
        if pkt.D == 0:
            return s, None
        return s[16:], self.m2i(pkt, s[:16])

    def addfield(self, pkt, s, val):
        if pkt.D == 1:
            return s + self.i2m(pkt, val)
        if val:
            print("RPL DAO 'D' flag is not set but dodagid is given.")
        return s


class DAO(_RPLGuessOption, Packet):
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
                   _OptDODAGIDField("dodagid", None)]


class DAOACK(_RPLGuessOption, Packet):
    """
    Control Message: Destination Advertisement Object Acknowledgement (DAOACK)
    """
    name = "Destination Advertisement Object Acknowledgement"
    fields_desc = [ByteField("RPLInstanceID", 50),
                   BitField("D", 0, 1),
                   BitField("reserved", 0, 7),
                   ByteField("daoseq", 1),
                   ByteField("status", 0),
                   _OptDODAGIDField("dodagid", None)]


# https://datatracker.ietf.org/doc/draft-ietf-roll-efficient-npdao/
class DCO(_RPLGuessOption, Packet):
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
                   _OptDODAGIDField("dodagid", None)]


# https://datatracker.ietf.org/doc/draft-ietf-roll-efficient-npdao/
class DCOACK(_RPLGuessOption, Packet):
    """
    Control Message: Destination Cleanup Object Acknowledgement (DCOACK)
    """
    name = "Destination Cleanup Object Acknowledgement"
    fields_desc = [ByteField("RPLInstanceID", 50),
                   BitField("D", 0, 1),
                   BitField("flags", 0, 7),
                   ByteField("dcoseq", 1),
                   ByteField("status", 0),
                   _OptDODAGIDField("dodagid", None)]


# https://www.iana.org/assignments/rpl/rpl.xhtml#control-codes
bind_layers(RPL, DIS, code=0)
bind_layers(RPL, DIO, code=1)
bind_layers(RPL, DAO, code=2)
bind_layers(RPL, DAOACK, code=3)
bind_layers(RPL, DCO, code=7)
bind_layers(RPL, DCOACK, code=8)


# https://www.iana.org/assignments/rpl/rpl.xhtml#control-message-options
for msg in [DIS, DIO, DAO, DAOACK, DCO, DCOACK]:
    bind_layers(msg, Pad1, otype=0)
    bind_layers(msg, PadN, otype=1)
    # OptDAGMC, otype=2 defined in rpl_metric.py
    bind_layers(msg, OptRIO, otype=3)
    bind_layers(msg, OptDODAGConfig, otype=4)
    bind_layers(msg, OptTgt, otype=5)
    bind_layers(msg, OptTIO, otype=6)
    bind_layers(msg, OptSolInfo, otype=7)
    bind_layers(msg, OptPIO, otype=8)
    bind_layers(msg, OptTgtDesc, otype=9)
