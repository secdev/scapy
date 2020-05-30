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

from scapy.packet import Packet
from scapy.fields import ByteEnumField, ByteField, IP6Field, ShortField, \
    XShortField, BitField, BitEnumField, FieldLenField, StrLenField, IntField
from scapy.layers.inet6 import icmp6rplcodes, RPL, icmp6ndraprefs, \
    _IP6PrefixField


# https://www.iana.org/assignments/rpl/rpl.xhtml#mop
rplmop = {0: "No Downward routes",
          1: "Non-Storing",
          2: "Storing with no multicast support",
          3: "Storing with multicast support",
          4: "P2P Route Discovery"}


# https://www.iana.org/assignments/rpl/rpl.xhtml#control-message-options
rploptsstr = {0: "Pad1",
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


rplopts = {
}


class RPLGuessOption:
    name = "Dummy RPL Option class that implements guess_payload_class()"

    def guess_payload_class(self, p):
        if len(p) > 0:
            return rplopts.get(ord(p[0]))


class OptRIO(Packet):
    name = "Routing Information"
    fields_desc = [ByteEnumField("otype", 3, rploptsstr),
                   FieldLenField("len", None, length_of="prefix", fmt="B",
                                 adjust=lambda pkt, x: x + 6),
                   ByteField("plen", None),
                   BitField("res1", 0, 3),
                   BitEnumField("prf", 0, 2, icmp6ndraprefs),
                   BitField("res2", 0, 3),
                   IntField("rtlifetime", 0xffffffff),
                   _IP6PrefixField("prefix", None)]


class OptDODAGConfig(Packet):
    name = "DODAG Configuration"
    fields_desc = [ByteEnumField("otype", 4, rploptsstr),
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


class OptTgt(Packet):
    name = "RPL Target"
    fields_desc = [ByteEnumField("otype", 5, rploptsstr),
                   FieldLenField("len", None, length_of="prefix", fmt="B",
                                 adjust=lambda pkt, x: x + 2),
                   ByteField("flags", 0),
                   ByteField("plen", None),
                   _IP6PrefixField("prefix", None)]


class OptTIO(Packet):
    name = "Transit Information"
    fields_desc = [ByteEnumField("otype", 6, rploptsstr),
                   FieldLenField("len", None, length_of="parentaddr", fmt="B",
                                 adjust=lambda pkt, x: x + 4),
                   BitField("E", 0, 1),
                   BitField("flags", 0, 7),
                   ByteField("pathcontrol", 0),
                   ByteField("pathseq", 0),
                   ByteField("pathlifetime", 0xff),
                   _IP6PrefixField("parentaddr", None)]


class OptSolInfo(Packet):
    name = "Solicited Information"
    fields_desc = [ByteEnumField("otype", 7, rploptsstr),
                   ByteField("len", 19),
                   ByteField("RPLInstanceID", 0),
                   BitField("V", 0, 1),
                   BitField("I", 0, 1),
                   BitField("D", 0, 1),
                   BitField("flags", 0, 5),
                   IP6Field("dodagid", "::1"),
                   ByteField("ver", 0)]


class OptPIO(Packet):
    name = "Prefix Information"
    fields_desc = [ByteEnumField("otype", 8, rploptsstr),
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


class OptTgtDesc(Packet):
    name = "RPL Target Descriptor"
    fields_desc = [ByteEnumField("otype", 9, rploptsstr),
                   ByteField("len", 4),
                   IntField("descriptor", 0)]


class Pad1(Packet):
    name = "Pad1"
    fields_desc = [ByteEnumField("otype", 0x00, rploptsstr)]

    def alignment_delta(self, curpos):  # No alignment requirement
        return 0

    def extract_padding(self, p):
        return b"", p


class PadN(Packet):
    name = "PadN"
    fields_desc = [ByteEnumField("otype", 0x01, rploptsstr),
                   FieldLenField("optlen", None, length_of="optdata", fmt="B"),
                   StrLenField("optdata", "",
                               length_from=lambda pkt: pkt.optlen)]

    def alignment_delta(self, curpos):  # No alignment requirement
        return 0

    def extract_padding(self, p):
        return b"", p


# RPL Control Message Handling


class DIS(RPLGuessOption, Packet):
    name = "DODAG Information Solicitation"
    fields_desc = [XShortField("cksum", None),
                   # DIS Base Object
                   ByteField("flags", 0),
                   ByteField("reserved", 0)]


class DIO(RPLGuessOption, Packet):
    name = "DODAG Information Object"
    fields_desc = [XShortField("cksum", None),
                   # DIO Base Object
                   ByteField("RPLInstanceID", 50),
                   ByteField("ver", 0),
                   ShortField("rank", 1),
                   BitField("G", 1, 1),
                   BitField("unused1", 0, 1),
                   BitEnumField("mop", 1, 3, rplmop),
                   BitField("prf", 0, 3),
                   ByteField("dtsn", 240),
                   ByteField("flags", 0),
                   ByteField("reserved", 0),
                   IP6Field("dodagid", "::1")]
    overload_fields = {RPL: {"code": 1}}


class _OptDODAGIDField(IP6Field):
    def addfield(self, pkt, s, val):
        if pkt.D == 1:
            return s + self.i2m(pkt, val)
        if val:
            print("RPL DAO 'D' flag is not set but dodagid is given.")
        return s


class DAO(RPLGuessOption, Packet):
    name = "Destination Advertisement Object"
    fields_desc = [XShortField("cksum", None),
                   # Base Object
                   ByteField("RPLInstanceID", 50),
                   BitField("K", 0, 1),
                   BitField("D", 0, 1),
                   BitField("flags", 0, 6),
                   ByteField("reserved", 0),
                   ByteField("daoseq", 1),
                   _OptDODAGIDField("dodagid", None)]
    overload_fields = {RPL: {"code": 2}}


class DAOACK(RPLGuessOption, Packet):
    name = "Destination Advertisement Object Acknowledgement"
    fields_desc = [XShortField("cksum", None),
                   # Base Object
                   ByteField("RPLInstanceID", 50),
                   BitField("D", 0, 1),
                   BitField("reserved", 0, 7),
                   ByteField("daoseq", 1),
                   ByteField("status", 0),
                   _OptDODAGIDField("dodagid", None)]
    overload_fields = {RPL: {"code": 3}}


# https://datatracker.ietf.org/doc/draft-ietf-roll-efficient-npdao/
class DCO(RPLGuessOption, Packet):
    name = "Destination Cleanup Object"
    fields_desc = [XShortField("cksum", None),
                   # Base Object
                   ByteField("RPLInstanceID", 50),
                   BitField("K", 0, 1),
                   BitField("D", 0, 1),
                   BitField("flags", 0, 6),
                   ByteField("status", 0),
                   ByteField("dcoseq", 1),
                   _OptDODAGIDField("dodagid", None)]
    overload_fields = {RPL: {"code": 7}}


# https://datatracker.ietf.org/doc/draft-ietf-roll-efficient-npdao/
class DCOACK(RPLGuessOption, Packet):
    name = "Destination Cleanup Object Acknowledgement"
    fields_desc = [XShortField("cksum", None),
                   # Base Object
                   ByteField("RPLInstanceID", 50),
                   BitField("D", 0, 1),
                   BitField("flags", 0, 7),
                   ByteField("dcoseq", 1),
                   ByteField("status", 0),
                   _OptDODAGIDField("dodagid", None)]
    overload_fields = {RPL: {"code": 8}}


# https://www.iana.org/assignments/rpl/rpl.xhtml#control-codes
icmp6rplcodes.update({0: DIS,
                      1: DIO,
                      2: DAO,
                      3: DAOACK,
                      # 4: "P2P-DRO",
                      # 5: "P2P-DRO-ACK",
                      # 6: "Measurement",
                      7: DCO,
                      8: DCOACK})


# https://www.iana.org/assignments/rpl/rpl.xhtml#control-message-options
rplopts.update({0: Pad1,
                1: PadN,
                # 2: OptDAGMC # Handled in rpl_metrics.py
                3: OptRIO,  # Routing Information
                4: OptDODAGConfig,  # DODAG Configuration
                5: OptTgt,  # RPL Target
                6: OptTIO,  # Transit Information
                7: OptSolInfo,  # Solicited Information
                8: OptPIO,  # Prefix Information Option
                9: OptTgtDesc})  # Target Descriptor
