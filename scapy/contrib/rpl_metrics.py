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

# RFC 6551
# scapy.contrib.description = Routing Metrics used for Path Calc in LLNs
# scapy.contrib.status = loads

import struct
from scapy.compat import orb
from scapy.packet import Packet
from scapy.fields import ByteEnumField, ByteField, ShortField, BitField, \
    BitEnumField, FieldLenField, StrLenField, IntField
from scapy.layers.inet6 import _PhantomAutoPadField, _OptionsField
from scapy.contrib.rpl import rploptsstr, rplopts


class _DAGMetricContainer(Packet):
    name = 'Dummy DAG Metric container'

    def post_build(self, p, pay):
        p += pay
        tmp_len = self.len
        if self.len is None:
            tmp_len = len(p) - 2
        p = p[:1] + struct.pack("B", tmp_len) + p[2:]
        return p


_dagmcobjtypes = {1: "Node State and Attributes",
                  2: "Node Energy",
                  3: "Hop Count",
                  4: "Link Throughput",
                  5: "Link Latency",
                  6: "Link Quality Level",
                  7: "Link ETX",
                  8: "Link Color"}


class DAGMCObjUnknown(Packet):
    name = 'Unknown DAGMC Object Option'
    fields_desc = [ByteEnumField("otype", 3, _dagmcobjtypes),
                   FieldLenField("olen", None, length_of="odata", fmt="B"),
                   StrLenField("odata", "",
                               length_from=lambda pkt: pkt.olen)]

    @classmethod
    def dispatch_hook(cls, _pkt=None, *_, **kargs):
        if _pkt:
            o = orb(_pkt[0])  # Option type
            if o in dagmcobjcls:
                return dagmcobjcls[o]
        return cls


aggroutmetric = {0: "additive",
                 1: "maximum",
                 2: "minimum",
                 3: "multiplicative"}  # RFC 6551


class DAGMCObj(Packet):
    name = 'Dummy DAG MC Object'

    def post_build(self, p, pay):
        p += pay
        tmp_len = self.len
        if self.len is None:
            tmp_len = len(p) - 4
        p = p[:3] + struct.pack("B", tmp_len) + p[4:]
        return p


class NSA(DAGMCObj):
    name = "Node State and Attributes"
    fields_desc = [ByteEnumField("otype", 1, _dagmcobjtypes),
                   BitField("resflags", 0, 5),
                   BitField("P", 0, 1),
                   BitField("C", 0, 1),
                   BitField("O", 0, 1),
                   BitField("R", 0, 1),
                   BitEnumField("A", 0, 3, aggroutmetric),
                   BitField("prec", 0, 4),
                   ByteField("len", None),
                   # NSA Object Body Format
                   ByteField("res", 0),
                   BitField("flags", 0, 6),
                   BitField("A", 0, 1),
                   BitField("O", 0, 1)]


class NodeEnergy(DAGMCObj):
    name = "Node Energy"
    fields_desc = [ByteEnumField("otype", 2, _dagmcobjtypes),
                   BitField("resflags", 0, 5),
                   BitField("P", 0, 1),
                   BitField("C", 0, 1),
                   BitField("O", 0, 1),
                   BitField("R", 0, 1),
                   BitEnumField("A", 0, 3, aggroutmetric),
                   BitField("prec", 0, 4),
                   ByteField("len", None),
                   # NE Sub-Object Format
                   BitField("flags", 0, 4),
                   BitField("I", 0, 1),
                   BitField("T", 0, 2),
                   BitField("E", 0, 1),
                   ByteField("E_E", 0)]


class HopCount(DAGMCObj):
    name = "Hop Count"
    fields_desc = [ByteEnumField("otype", 3, _dagmcobjtypes),
                   BitField("resflags", 0, 5),
                   BitField("P", 0, 1),
                   BitField("C", 0, 1),
                   BitField("O", 0, 1),
                   BitField("R", 0, 1),
                   BitEnumField("A", 0, 3, aggroutmetric),
                   BitField("prec", 0, 4),
                   ByteField("len", None),
                   # Sub-Object Format
                   BitField("res", 0, 4),
                   BitField("flags", 0, 4),
                   ByteField("HopCount", 1)]


class LinkThroughput(DAGMCObj):
    name = "Link Throughput"
    fields_desc = [ByteEnumField("otype", 4, _dagmcobjtypes),
                   BitField("resflags", 0, 5),
                   BitField("P", 0, 1),
                   BitField("C", 0, 1),
                   BitField("O", 0, 1),
                   BitField("R", 0, 1),
                   BitEnumField("A", 0, 3, aggroutmetric),
                   BitField("prec", 0, 4),
                   ByteField("len", None),
                   # Sub-Object Format
                   IntField("Throughput", 1)]


class LinkLatency(DAGMCObj):
    name = "Link Latency"
    fields_desc = [ByteEnumField("otype", 5, _dagmcobjtypes),
                   BitField("resflags", 0, 5),
                   BitField("P", 0, 1),
                   BitField("C", 0, 1),
                   BitField("O", 0, 1),
                   BitField("R", 0, 1),
                   BitEnumField("A", 0, 3, aggroutmetric),
                   BitField("prec", 0, 4),
                   ByteField("len", None),
                   # NE Sub-Object Format
                   IntField("Latency", 1)]


class LinkQualityLevel(DAGMCObj):
    name = "Link Quality Level"
    fields_desc = [ByteEnumField("otype", 6, _dagmcobjtypes),
                   BitField("resflags", 0, 5),
                   BitField("P", 0, 1),
                   BitField("C", 0, 1),
                   BitField("O", 0, 1),
                   BitField("R", 0, 1),
                   BitEnumField("A", 0, 3, aggroutmetric),
                   BitField("prec", 0, 4),
                   ByteField("len", None),
                   # Sub-Object Format
                   ByteField("res", 0),
                   BitField("val", 0, 3),
                   BitField("counter", 0, 5)]


class LinkETX(DAGMCObj):
    name = "Link ETX"
    fields_desc = [ByteEnumField("otype", 7, _dagmcobjtypes),
                   BitField("resflags", 0, 5),
                   BitField("P", 0, 1),
                   BitField("C", 0, 1),
                   BitField("O", 0, 1),
                   BitField("R", 0, 1),
                   BitEnumField("A", 0, 3, aggroutmetric),
                   BitField("prec", 0, 4),
                   ByteField("len", None),
                   # Sub-Object Format
                   ShortField("ETX", 1)]


# Note: Wireshark shows warning decoding LinkColor.
# This seems to be wireshark issue!
class LinkColor(DAGMCObj):
    name = "Link Color"
    fields_desc = [ByteEnumField("otype", 8, _dagmcobjtypes),
                   BitField("resflags", 0, 5),
                   BitField("P", 0, 1),
                   BitField("C", 0, 1),
                   BitField("O", 0, 1),
                   BitField("R", 0, 1),
                   BitEnumField("A", 0, 3, aggroutmetric),
                   BitField("prec", 0, 4),
                   ByteField("len", None),
                   # Sub-Object Format
                   ByteField("res", 0),
                   BitField("color", 1, 10),
                   BitField("counter", 1, 6)]


dagmcobjcls = {1: NSA,
               2: NodeEnergy,
               3: HopCount,
               4: LinkThroughput,
               5: LinkLatency,
               6: LinkQualityLevel,
               7: LinkETX,
               8: LinkColor}


class OptDAGMC(_DAGMetricContainer):
    name = "DAG Metric Container"
    fields_desc = [ByteEnumField("otype", 2, rploptsstr),
                   ByteField("len", None),
                   _PhantomAutoPadField("autopad", 0),
                   _OptionsField("options", [], DAGMCObjUnknown, 8,
                                 length_from=lambda pkt: 8 * pkt.len)]


# https://www.iana.org/assignments/rpl/rpl.xhtml#control-message-options
rplopts.update({2: OptDAGMC})
