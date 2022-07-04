# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) 2020 Rahul Jadhav <nyrahul@gmail.com>

# scapy.contrib.description = Routing Metrics used for Path Calc in LLNs
# scapy.contrib.status = loads

"""
RFC 6551 - Routing Metrics Used for Path Calculation in LLNs

+----------------------------+
| Metrics & Constraint Types |
+----------------------------+
| DAGMC Option               |
+----------------------------+
| RPL-DIO                    |
+----------------------------+
"""

import struct
from scapy.compat import orb
from scapy.packet import Packet
from scapy.fields import ByteEnumField, ByteField, ShortField, BitField, \
    BitEnumField, FieldLenField, StrLenField, IntField
from scapy.layers.inet6 import _PhantomAutoPadField, _OptionsField
from scapy.contrib.rpl import RPLOPTSSTR, RPLOPTS


class _DAGMetricContainer(Packet):
    name = 'Dummy DAG Metric container'

    def post_build(self, pkt, pay):
        pkt += pay
        tmp_len = self.len
        if self.len is None:
            tmp_len = len(pkt) - 2
        pkt = pkt[:1] + struct.pack("B", tmp_len) + pkt[2:]
        return pkt


DAGMC_OBJTYPE = {1: "Node State and Attributes",
                 2: "Node Energy",
                 3: "Hop Count",
                 4: "Link Throughput",
                 5: "Link Latency",
                 6: "Link Quality Level",
                 7: "Link ETX",
                 8: "Link Color"}


class DAGMCObjUnknown(Packet):
    """
    Dummy unknown metric/constraint
    """
    name = 'Unknown DAGMC Object Option'
    fields_desc = [ByteEnumField("otype", 3, DAGMC_OBJTYPE),
                   FieldLenField("olen", None, length_of="odata", fmt="B"),
                   StrLenField("odata", "",
                               length_from=lambda pkt: pkt.olen)]

    @classmethod
    def dispatch_hook(cls, _pkt=None, *_, **kargs):
        """
        Dispatch hook for DAGMC sub-fields
        """
        if _pkt:
            opt_type = orb(_pkt[0])  # Option type
            if opt_type in DAGMC_CLS:
                return DAGMC_CLS[opt_type]
        return cls


AGG_RTMETRIC = {0: "additive",
                1: "maximum",
                2: "minimum",
                3: "multiplicative"}  # RFC 6551


class DAGMCObj(Packet):
    """
    Set the length field in DAG Metric Constraint Control Option
    """
    name = 'Dummy DAG MC Object'
    # RFC 6551 - 2.1
    fields_desc = [ByteEnumField("otype", 0, DAGMC_OBJTYPE),
                   BitField("resflags", 0, 5),
                   BitField("P", 0, 1),
                   BitField("C", 0, 1),
                   BitField("O", 0, 1),
                   BitField("R", 0, 1),
                   BitEnumField("A", 0, 3, AGG_RTMETRIC),
                   BitField("prec", 0, 4),
                   ByteField("len", None)]

    def post_build(self, pkt, pay):
        pkt += pay
        tmp_len = self.len
        if self.len is None:
            tmp_len = len(pkt) - 4
        pkt = pkt[:3] + struct.pack("B", tmp_len) + pkt[4:]
        return pkt


class RPLDAGMCNSA(DAGMCObj):
    """
    DAG Metric: Node State and Attributes
    """
    name = "Node State and Attributes"
    otype = 1
    # RFC 6551 - 3.1
    fields_desc = DAGMCObj.fields_desc + [
        # NSA Object Body Format
        ByteField("res", 0),
        BitField("flags", 0, 6),
        BitField("Agg", 0, 1),  # A
        BitField("Overload", 0, 1),  # O
    ]


class RPLDAGMCNodeEnergy(DAGMCObj):
    """
    DAG Metric: Node Energy
    """
    name = "Node Energy"
    otype = 2
    # RFC 6551 - 3.2
    fields_desc = DAGMCObj.fields_desc + [
        # NE Sub-Object Format
        BitField("flags", 0, 4),
        BitField("I", 0, 1),
        BitField("T", 0, 2),
        BitField("E", 0, 1),
        ByteField("E_E", 0)
    ]


class RPLDAGMCHopCount(DAGMCObj):
    """
    DAG Metric: Hop Count
    """
    name = "Hop Count"
    otype = 3
    # RFC 6551 - 3.3
    fields_desc = DAGMCObj.fields_desc + [
        # Sub-Object Format
        BitField("res", 0, 4),
        BitField("flags", 0, 4),
        ByteField("HopCount", 1)
    ]


class RPLDAGMCLinkThroughput(DAGMCObj):
    """
    DAG Metric: Link Throughput
    """
    name = "Link Throughput"
    otype = 4
    # RFC 6551 - 4.1
    fields_desc = DAGMCObj.fields_desc + [
        # Sub-Object Format
        IntField("Throughput", 1)
    ]


class RPLDAGMCLinkLatency(DAGMCObj):
    """
    DAG Metric: Link Latency
    """
    name = "Link Latency"
    otype = 5
    # RFC 6551 - 4.2
    fields_desc = DAGMCObj.fields_desc + [
        # NE Sub-Object Format
        IntField("Latency", 1)
    ]


class RPLDAGMCLinkQualityLevel(DAGMCObj):
    """
    DAG Metric: Link Quality Level (LQL)
    """
    name = "Link Quality Level"
    otype = 6
    # RFC 6551 - 4.3.1
    fields_desc = DAGMCObj.fields_desc + [
        # Sub-Object Format
        ByteField("res", 0),
        BitField("val", 0, 3),
        BitField("counter", 0, 5)
    ]


class RPLDAGMCLinkETX(DAGMCObj):
    """
    DAG Metric: Link ETX
    """
    name = "Link ETX"
    otype = 7
    # RFC 6551 - 4.3.2
    fields_desc = DAGMCObj.fields_desc + [
        # Sub-Object Format
        ShortField("ETX", 1)
    ]


# Note: Wireshark shows warning decoding LinkColor.
# This seems to be wireshark issue!
class RPLDAGMCLinkColor(DAGMCObj):
    """
    DAG Metric: Link Color
    """
    name = "Link Color"
    otype = 8
    # RFC 6551 - 4.4.1
    fields_desc = DAGMCObj.fields_desc + [
        # Sub-Object Format
        ByteField("res", 0),
        BitField("color", 1, 10),
        BitField("counter", 1, 6)
    ]


DAGMC_CLS = {1: RPLDAGMCNSA,
             2: RPLDAGMCNodeEnergy,
             3: RPLDAGMCHopCount,
             4: RPLDAGMCLinkThroughput,
             5: RPLDAGMCLinkLatency,
             6: RPLDAGMCLinkQualityLevel,
             7: RPLDAGMCLinkETX,
             8: RPLDAGMCLinkColor}


class RPLOptDAGMC(_DAGMetricContainer):
    """
    Control Option: DAG Metric Container
    """
    name = "DAG Metric Container"
    fields_desc = [ByteEnumField("otype", 2, RPLOPTSSTR),
                   ByteField("len", None),
                   _PhantomAutoPadField("autopad", 0),
                   _OptionsField("options", [], DAGMCObjUnknown, 8,
                                 length_from=lambda pkt: 8 * pkt.len)]


# https://www.iana.org/assignments/rpl/rpl.xhtml#control-message-options
RPLOPTS.update({2: RPLOptDAGMC})
