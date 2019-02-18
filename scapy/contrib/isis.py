# This file is part of Scapy
# Scapy is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# any later version.
#
# Scapy is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Scapy. If not, see <http://www.gnu.org/licenses/>.

# scapy.contrib.description = Intermediate System to Intermediate System (ISIS)
# scapy.contrib.status = loads

"""
    IS-IS Scapy Extension
    ~~~~~~~~~~~~~~~~~~~~~

    :copyright: 2014-2016 BENOCS GmbH, Berlin (Germany)
    :author:    Marcel Patzlaff, mpatzlaff@benocs.com
                Michal Kaliszan, mkaliszan@benocs.com
    :license:   GPLv2

        This module is free software; you can redistribute it and/or
        modify it under the terms of the GNU General Public License
        as published by the Free Software Foundation; either version 2
        of the License, or (at your option) any later version.

        This module is distributed in the hope that it will be useful,
        but WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
        GNU General Public License for more details.

    :description:

        This module provides Scapy layers for the Intermediate System
        to Intermediate System routing protocol as defined in RFC 1195.

        Currently it (partially) supports the packaging/encoding
        requirements of the following RFCs:
         * RFC 1195 (only the TCP/IP related part)
         * RFC 3358 (optional checksums)
         * RFC 5301 (dynamic hostname extension)
         * RFC 5302 (domain-wide prefix distribution)
         * RFC 5303 (three-way handshake)
         * RFC 5304 (cryptographic authentication)
         * RFC 5308 (routing IPv6 with IS-IS)

    :TODO:

        - packet relations (requests, responses)
        - support for recent RFCs:
          * RFC 5305 (traffic engineering)
          * RFC 5307 (support for G-MPLS)
          * RFC 5310 (generic cryptographic authentication)
          * RFC 5316 (inter-AS MPLS and G-MPLS TE)

"""

from __future__ import absolute_import
import struct
import random

from scapy.config import conf
from scapy.fields import BitField, BitFieldLenField, BoundStrLenField, \
    ByteEnumField, ByteField, ConditionalField, Field, FieldLenField, \
    FieldListField, FlagsField, IEEEFloatField, IP6PrefixField, IPField, \
    IPPrefixField, IntField, LongField, MACField, PacketListField, \
    ShortField, ThreeBytesField, XIntField, XShortField
from scapy.packet import bind_layers, Packet
from scapy.layers.clns import network_layer_protocol_ids, register_cln_protocol
from scapy.layers.inet6 import IP6ListField, IP6Field
from scapy.utils import fletcher16_checkbytes
from scapy.volatile import RandString, RandByte
from scapy.modules.six.moves import range
from scapy.compat import orb, hex_bytes

EXT_VERSION = "v0.0.2"


#######################################################################
#   ISIS Utilities + Fields                                           #
#######################################################################
def isis_area2str(area):
    return b"".join(hex_bytes(x) for x in area.split("."))


def isis_str2area(s):
    if len(s) == 0:
        return ""

    numbytes = len(s[1:])
    fmt = "%02X" + (".%02X%02X" * (numbytes // 2)) + ("" if (numbytes % 2) == 0 else ".%02X")  # noqa: E501
    return fmt % tuple(orb(x) for x in s)


def isis_sysid2str(sysid):
    return b"".join(hex_bytes(x) for x in sysid.split("."))


def isis_str2sysid(s):
    return ("%02X%02X." * 3)[:-1] % tuple(orb(x) for x in s)


def isis_nodeid2str(nodeid):
    return isis_sysid2str(nodeid[:-3]) + hex_bytes(nodeid[-2:])


def isis_str2nodeid(s):
    return "%s.%02X" % (isis_str2sysid(s[:-1]), orb(s[-1]))


def isis_lspid2str(lspid):
    return isis_nodeid2str(lspid[:-3]) + hex_bytes(lspid[-2:])


def isis_str2lspid(s):
    return "%s-%02X" % (isis_str2nodeid(s[:-1]), orb(s[-1]))


class _ISIS_IdFieldBase(Field):
    __slots__ = ["to_str", "to_id", "length"]

    def __init__(self, name, default, length, to_str, to_id):
        self.to_str = to_str
        self.to_id = to_id
        self.length = length
        Field.__init__(self, name, default, "%is" % length)

    def i2m(self, pkt, x):
        if x is None:
            return b"\0" * self.length

        return self.to_str(x)

    def m2i(self, pkt, x):
        return self.to_id(x)

    def any2i(self, pkt, x):
        if isinstance(x, str) and len(x) == self.length:
            return self.m2i(pkt, x)

        return x


class _ISIS_RandId(RandString):
    def __init__(self, template):
        self.bytecount = template.count("*")
        self.format = template.replace("*", "%02X")

    def _fix(self):
        if self.bytecount == 0:
            return ""

        val = ()

        for _ in range(self.bytecount):
            val += (RandByte(),)

        return self.format % val


class _ISIS_RandAreaId(_ISIS_RandId):
    def __init__(self, bytecount=None):
        self.bytecount = random.randint(1, 13) if bytecount is None else bytecount  # noqa: E501
        self.format = "%02X" + (".%02X%02X" * ((self.bytecount - 1) // 2)) + ("" if ((self.bytecount - 1) % 2) == 0 else ".%02X")  # noqa: E501


class ISIS_AreaIdField(Field):
    __slots__ = ["length_from"]

    def __init__(self, name, default, length_from):
        Field.__init__(self, name, default)
        self.length_from = length_from

    def i2m(self, pkt, x):
        return isis_area2str(x)

    def m2i(self, pkt, x):
        return isis_str2area(x)

    def i2len(self, pkt, x):
        if x is None:
            return 0
        tmp_len = len(x)
        # l/5 is the number of dots in the Area ID
        return (tmp_len - (tmp_len // 5)) // 2

    def addfield(self, pkt, s, val):
        sval = self.i2m(pkt, val)
        return s + struct.pack("!%is" % len(sval), sval)

    def getfield(self, pkt, s):
        numbytes = self.length_from(pkt)
        return s[numbytes:], self.m2i(pkt, struct.unpack("!%is" % numbytes, s[:numbytes])[0])  # noqa: E501

    def randval(self):
        return _ISIS_RandAreaId()


class ISIS_SystemIdField(_ISIS_IdFieldBase):
    def __init__(self, name, default):
        _ISIS_IdFieldBase.__init__(self, name, default, 6, isis_sysid2str, isis_str2sysid)  # noqa: E501

    def randval(self):
        return _ISIS_RandId("**.**.**")


class ISIS_NodeIdField(_ISIS_IdFieldBase):
    def __init__(self, name, default):
        _ISIS_IdFieldBase.__init__(self, name, default, 7, isis_nodeid2str, isis_str2nodeid)  # noqa: E501

    def randval(self):
        return _ISIS_RandId("**.**.**.*")


class ISIS_LspIdField(_ISIS_IdFieldBase):
    def __init__(self, name, default):
        _ISIS_IdFieldBase.__init__(self, name, default, 8, isis_lspid2str, isis_str2lspid)  # noqa: E501

    def randval(self):
        return _ISIS_RandId("**.**.**.*-*")


class ISIS_CircuitTypeField(FlagsField):
    def __init__(self, name="circuittype", default=2, size=8,
                 names=None):
        if names is None:
            names = ["L1", "L2", "r0", "r1", "r2", "r3", "r4", "r5"]
        FlagsField.__init__(self, name, default, size, names)


def _ISIS_GuessTlvClass_Helper(tlv_classes, defaultname, p, **kargs):
    cls = conf.raw_layer
    if len(p) >= 2:
        tlvtype = orb(p[0])
        clsname = tlv_classes.get(tlvtype, defaultname)
        cls = globals()[clsname]

    return cls(p, **kargs)


class _ISIS_GenericTlv_Base(Packet):
    fields_desc = [ByteField("type", 0),
                   FieldLenField("len", None, length_of="val", fmt="B"),
                   BoundStrLenField("val", "", length_from=lambda pkt: pkt.len)]  # noqa: E501

    def guess_payload_class(self, p):
        return conf.padding_layer


class ISIS_GenericTlv(_ISIS_GenericTlv_Base):
    name = "ISIS Generic TLV"


class ISIS_GenericSubTlv(_ISIS_GenericTlv_Base):
    name = "ISIS Generic Sub-TLV"


#######################################################################
#   ISIS Sub-TLVs for TLVs 22, 23, 141, 222, 223                      #
#######################################################################
_isis_subtlv_classes_1 = {
    3: "ISIS_AdministrativeGroupSubTlv",
    4: "ISIS_LinkLocalRemoteIdentifiersSubTlv",
    6: "ISIS_IPv4InterfaceAddressSubTlv",
    8: "ISIS_IPv4NeighborAddressSubTlv",
    9: "ISIS_MaximumLinkBandwidthSubTlv",
    10: "ISIS_MaximumReservableLinkBandwidthSubTlv",
    11: "ISIS_UnreservedBandwidthSubTlv",
    12: "ISIS_IPv6InterfaceAddressSubTlv",
    13: "ISIS_IPv6NeighborAddressSubTlv",
    18: "ISIS_TEDefaultMetricSubTlv"
}

_isis_subtlv_names_1 = {
    3: "Administrative Group (Color)",
    4: "Link Local/Remote Identifiers",
    6: "IPv4 Interface Address",
    8: "IPv4 Neighbor Address",
    9: "Maximum Link Bandwidth",
    10: "Maximum Reservable Link Bandwidth",
    11: "Unreserved Bandwidth",
    12: "IPv6 Interface Address",
    13: "IPv6 Neighbor Address",
    18: "TE Default Metric"
}


def _ISIS_GuessSubTlvClass_1(p, **kargs):
    return _ISIS_GuessTlvClass_Helper(_isis_subtlv_classes_1, "ISIS_GenericSubTlv", p, **kargs)  # noqa: E501


class ISIS_IPv4InterfaceAddressSubTlv(ISIS_GenericSubTlv):
    name = "ISIS IPv4 Interface Address (S)"
    fields_desc = [ByteEnumField("type", 6, _isis_subtlv_names_1),
                   FieldLenField("len", None, length_of="address", fmt="B"),
                   IPField("address", "0.0.0.0")]


class ISIS_IPv4NeighborAddressSubTlv(ISIS_GenericSubTlv):
    name = "ISIS IPv4 Neighbor Address (S)"
    fields_desc = [ByteEnumField("type", 8, _isis_subtlv_names_1),
                   FieldLenField("len", None, length_of="address", fmt="B"),
                   IPField("address", "0.0.0.0")]


class ISIS_LinkLocalRemoteIdentifiersSubTlv(ISIS_GenericSubTlv):
    name = "ISIS Link Local/Remote Identifiers (S)"
    fields_desc = [ByteEnumField("type", 4, _isis_subtlv_names_1),
                   FieldLenField("len", 8, fmt="B"),
                   IntField("localid", "0"),
                   IntField("remoteid", "0")]


class ISIS_IPv6InterfaceAddressSubTlv(ISIS_GenericSubTlv):
    name = "ISIS IPv6 Interface Address (S)"
    fields_desc = [ByteEnumField("type", 12, _isis_subtlv_names_1),
                   FieldLenField("len", None, length_of="address", fmt="B"),
                   IP6Field("address", "::")]


class ISIS_IPv6NeighborAddressSubTlv(ISIS_GenericSubTlv):
    name = "ISIS IPv6 Neighbor Address (S)"
    fields_desc = [ByteEnumField("type", 13, _isis_subtlv_names_1),
                   FieldLenField("len", None, length_of="address", fmt="B"),
                   IP6Field("address", "::")]


class ISIS_AdministrativeGroupSubTlv(ISIS_GenericSubTlv):
    name = "Administrative Group SubTLV (Color)"
    fields_desc = [ByteEnumField("code", 3, _isis_subtlv_names_1),
                   FieldLenField("len", None, length_of="admingroup", fmt="B"),
                   IPField("admingroup", "0.0.0.1")]


class ISIS_MaximumLinkBandwidthSubTlv(ISIS_GenericSubTlv):
    name = "Maximum Link Bandwidth SubTLV"
    fields_desc = [ByteEnumField("type", 9, _isis_subtlv_names_1),
                   FieldLenField("len", None, length_of="maxbw", fmt="B"),
                   IEEEFloatField("maxbw", 1000)]  # in B/s


class ISIS_MaximumReservableLinkBandwidthSubTlv(ISIS_GenericSubTlv):
    name = "Maximum Reservable Link Bandwidth SubTLV"
    fields_desc = [ByteEnumField("type", 10, _isis_subtlv_names_1),
                   FieldLenField("len", None, length_of="maxrsvbw", fmt="B"),
                   IEEEFloatField("maxrsvbw", 1000)]  # in B/s


class ISIS_UnreservedBandwidthSubTlv(ISIS_GenericSubTlv):
    name = "Unreserved Bandwidth SubTLV"
    fields_desc = [ByteEnumField("type", 11, _isis_subtlv_names_1),
                   FieldLenField("len", None, length_of="unrsvbw", fmt="B"),
                   FieldListField("unrsvbw", [1000, 1000, 1000, 1000, 1000, 1000, 1000, 1000], IEEEFloatField("", 1000), count_from=lambda pkt: pkt.len / 4)]  # in B/s  # noqa: E501


class ISIS_TEDefaultMetricSubTlv(ISIS_GenericSubTlv):
    name = "TE Default Metric SubTLV"
    fields_desc = [ByteEnumField("type", 18, _isis_subtlv_names_1),
                   FieldLenField("len", None, length_of="temetric", adjust=lambda pkt, x:x - 1, fmt="B"),  # noqa: E501
                   ThreeBytesField("temetric", 1000)]


#######################################################################
#   ISIS Sub-TLVs for TLVs 135, 235, 236, and 237                     #
#######################################################################
_isis_subtlv_classes_2 = {
    1: "ISIS_32bitAdministrativeTagSubTlv",
    2: "ISIS_64bitAdministrativeTagSubTlv"
}

_isis_subtlv_names_2 = {
    1: "32-bit Administrative Tag",
    2: "64-bit Administrative Tag"
}


def _ISIS_GuessSubTlvClass_2(p, **kargs):
    return _ISIS_GuessTlvClass_Helper(_isis_subtlv_classes_2, "ISIS_GenericSubTlv", p, **kargs)  # noqa: E501


class ISIS_32bitAdministrativeTagSubTlv(ISIS_GenericSubTlv):
    name = "ISIS 32-bit Administrative Tag (S)"
    fields_desc = [ByteEnumField("type", 1, _isis_subtlv_names_2),
                   FieldLenField("len", None, length_of="tags", fmt="B"),
                   FieldListField("tags", [], IntField("", 0), count_from=lambda pkt: pkt.len // 4)]  # noqa: E501


class ISIS_64bitAdministrativeTagSubTlv(ISIS_GenericSubTlv):
    name = "ISIS 64-bit Administrative Tag (S)"
    fields_desc = [ByteEnumField("type", 2, _isis_subtlv_names_2),
                   FieldLenField("len", None, length_of="tags", fmt="B"),
                   FieldListField("tags", [], LongField("", 0), count_from=lambda pkt: pkt.len // 8)]  # noqa: E501


#######################################################################
#   ISIS TLVs                                                         #
#######################################################################
_isis_tlv_classes = {
    1: "ISIS_AreaTlv",
    2: "ISIS_IsReachabilityTlv",
    6: "ISIS_IsNeighbourTlv",
    8: "ISIS_PaddingTlv",
    9: "ISIS_LspEntryTlv",
    10: "ISIS_AuthenticationTlv",
    12: "ISIS_ChecksumTlv",
    14: "ISIS_BufferSizeTlv",
    22: "ISIS_ExtendedIsReachabilityTlv",
    128: "ISIS_InternalIpReachabilityTlv",
    129: "ISIS_ProtocolsSupportedTlv",
    130: "ISIS_ExternalIpReachabilityTlv",
    132: "ISIS_IpInterfaceAddressTlv",
    135: "ISIS_ExtendedIpReachabilityTlv",
    137: "ISIS_DynamicHostnameTlv",
    232: "ISIS_Ipv6InterfaceAddressTlv",
    236: "ISIS_Ipv6ReachabilityTlv",
    240: "ISIS_P2PAdjacencyStateTlv"
}

_isis_tlv_names = {
    1: "Area TLV",
    2: "IS Reachability TLV",
    6: "IS Neighbour TLV",
    7: "Instance Identifier TLV",
    8: "Padding TLV",
    9: "LSP Entries TLV",
    10: "Authentication TLV",
    12: "Optional Checksum TLV",
    13: "Purge Originator Identification TLV",
    14: "LSP Buffer Size TLV",
    22: "Extended IS-Reachability TLV",
    23: "IS Neighbour Attribute TLV",
    24: "IS Alias ID",
    128: "IP Internal Reachability TLV",
    129: "Protocols Supported TLV",
    130: "IP External Reachability TLV",
    131: "Inter-Domain Routing Protocol Information TLV",
    132: "IP Interface Address TLV",
    134: "Traffic Engineering Router ID TLV",
    135: "Extended IP Reachability TLV",
    137: "Dynamic Hostname TLV",
    138: "GMPLS Shared Risk Link Group TLV",
    139: "IPv6 Shared Risk Link Group TLV",
    140: "IPv6 Traffic Engineering Router ID TLV",
    141: "Inter-AS Reachability Information TLV",
    142: "Group Address TLV",
    143: "Multi-Topology-Aware Port Capability TLV",
    144: "Multi-Topology Capability TLV",
    145: "TRILL Neighbour TLV",
    147: "MAC-Reachability TLV",
    148: "BFD-Enabled TLV",
    211: "Restart TLV",
    222: "Multi-Topology Intermediate Systems TLV",
    223: "Multi-Topology IS Neighbour Attributes TLV",
    229: "Multi-Topology TLV",
    232: "IPv6 Interface Address TLV",
    233: "IPv6 Global Interface Address TLV",
    235: "Multi-Topology IPv4 Reachability TLV",
    236: "IPv6 Reachability TLV",
    237: "Multi-Topology IPv6 Reachability TLV",
    240: "Point-to-Point Three-Way Adjacency TLV",
    242: "IS-IS Router Capability TLV",
    251: "Generic Information TLV"
}


def _ISIS_GuessTlvClass(p, **kargs):
    return _ISIS_GuessTlvClass_Helper(_isis_tlv_classes, "ISIS_GenericTlv", p, **kargs)  # noqa: E501


class ISIS_AreaEntry(Packet):
    name = "ISIS Area Entry"
    fields_desc = [FieldLenField("arealen", None, length_of="areaid", fmt="B"),
                   ISIS_AreaIdField("areaid", "49", length_from=lambda pkt: pkt.arealen)]  # noqa: E501

    def extract_padding(self, s):
        return "", s


class ISIS_AreaTlv(ISIS_GenericTlv):
    name = "ISIS Area TLV"
    fields_desc = [ByteEnumField("type", 1, _isis_tlv_names),
                   FieldLenField("len", None, length_of="areas", fmt="B"),
                   PacketListField("areas", [], ISIS_AreaEntry, length_from=lambda x: x.len)]  # noqa: E501


class ISIS_AuthenticationTlv(ISIS_GenericTlv):
    name = "ISIS Authentication TLV"
    fields_desc = [ByteEnumField("type", 10, _isis_tlv_names),
                   FieldLenField("len", None, length_of="password", adjust=lambda pkt, x: x + 1, fmt="B"),  # noqa: E501
                   ByteEnumField("authtype", 1, {1: "Plain", 17: "HMAC-MD5"}),
                   BoundStrLenField("password", "", maxlen=254, length_from=lambda pkt: pkt.len - 1)]  # noqa: E501


class ISIS_BufferSizeTlv(ISIS_GenericTlv):
    name = "ISIS Buffer Size TLV"
    fields_desc = [ByteEnumField("type", 14, _isis_tlv_names),
                   ByteField("len", 2),
                   ShortField("lspbuffersize", 1497)]


class ISIS_ChecksumTlv(ISIS_GenericTlv):
    name = "ISIS Optional Checksum TLV"
    fields_desc = [ByteEnumField("type", 12, _isis_tlv_names),
                   ByteField("len", 2),
                   XShortField("checksum", None)]


class ISIS_DynamicHostnameTlv(ISIS_GenericTlv):
    name = "ISIS Dynamic Hostname TLV"
    fields_desc = [ByteEnumField("type", 137, _isis_tlv_names),
                   FieldLenField("len", None, length_of="hostname", fmt="B"),
                   BoundStrLenField("hostname", "", length_from=lambda pkt: pkt.len)]  # noqa: E501


class ISIS_ExtendedIpPrefix(Packet):
    name = "ISIS Extended IP Prefix"
    fields_desc = [
        IntField("metric", 1),
        BitField("updown", 0, 1),
        BitField("subtlvindicator", 0, 1),
        BitFieldLenField("pfxlen", None, 6, length_of="pfx"),
        IPPrefixField("pfx", None, wordbytes=1, length_from=lambda x: x.pfxlen),  # noqa: E501
        ConditionalField(FieldLenField("subtlvslen", None, length_of="subtlvs", fmt="B"), lambda pkt: pkt.subtlvindicator == 1),  # noqa: E501
        ConditionalField(PacketListField("subtlvs", [], _ISIS_GuessSubTlvClass_2, length_from=lambda x: x.subtlvslen), lambda pkt: pkt.subtlvindicator == 1)  # noqa: E501
    ]

    def extract_padding(self, s):
        return "", s


class ISIS_TERouterIDTlv(ISIS_GenericTlv):
    name = "ISIS TE Router ID TLV"
    fields_desc = [ByteEnumField("type", 134, _isis_tlv_names),
                   FieldLenField("len", None, length_of="routerid", fmt="B"),
                   IPField("routerid", "0.0.0.0")]


class ISIS_ExtendedIpReachabilityTlv(ISIS_GenericTlv):
    name = "ISIS Extended IP Reachability TLV"
    fields_desc = [ByteEnumField("type", 135, _isis_tlv_names),
                   FieldLenField("len", None, length_of="pfxs", fmt="B"),
                   PacketListField("pfxs", [], ISIS_ExtendedIpPrefix, length_from=lambda pkt: pkt.len)]  # noqa: E501


class ISIS_ExtendedIsNeighbourEntry(Packet):
    name = "ISIS Extended IS Neighbour Entry"
    fields_desc = [
        ISIS_NodeIdField("neighbourid", "0102.0304.0506.07"),
        ThreeBytesField("metric", 1),
        FieldLenField("subtlvslen", None, length_of="subtlvs", fmt="B"),
        PacketListField("subtlvs", [], _ISIS_GuessSubTlvClass_1, length_from=lambda x: x.subtlvslen)  # noqa: E501
    ]

    def extract_padding(self, s):
        return "", s


class ISIS_ExtendedIsReachabilityTlv(ISIS_GenericTlv):
    name = "ISIS Extended IS Reachability TLV"
    fields_desc = [ByteEnumField("type", 22, _isis_tlv_names),
                   FieldLenField("len", None, length_of="neighbours", fmt="B"),
                   PacketListField("neighbours", [], ISIS_ExtendedIsNeighbourEntry, length_from=lambda x: x.len)]  # noqa: E501


class ISIS_IpInterfaceAddressTlv(ISIS_GenericTlv):
    name = "ISIS IP Interface Address TLV"
    fields_desc = [ByteEnumField("type", 132, _isis_tlv_names),
                   FieldLenField("len", None, length_of="addresses", fmt="B"),
                   FieldListField("addresses", [], IPField("", "0.0.0.0"), count_from=lambda pkt: pkt.len // 4)]  # noqa: E501


class ISIS_Ipv6InterfaceAddressTlv(ISIS_GenericTlv):
    name = "ISIS IPv6 Interface Address TLV"
    fields_desc = [
        ByteEnumField("type", 232, _isis_tlv_names),
        FieldLenField("len", None, length_of="addresses", fmt="B"),
        IP6ListField("addresses", [], count_from=lambda pkt: pkt.len // 16)
    ]


class ISIS_Ipv6Prefix(Packet):
    name = "ISIS IPv6 Prefix"
    fields_desc = [
        IntField("metric", 1),
        BitField("updown", 0, 1),
        BitField("external", 0, 1),
        BitField("subtlvindicator", 0, 1),
        BitField("reserved", 0, 5),
        FieldLenField("pfxlen", None, length_of="pfx", fmt="B"),
        IP6PrefixField("pfx", None, wordbytes=1, length_from=lambda x: x.pfxlen),  # noqa: E501
        ConditionalField(FieldLenField("subtlvslen", None, length_of="subtlvs", fmt="B"), lambda pkt: pkt.subtlvindicator == 1),  # noqa: E501
        ConditionalField(PacketListField("subtlvs", [], _ISIS_GuessSubTlvClass_2, length_from=lambda x: x.subtlvslen), lambda pkt: pkt.subtlvindicator == 1)  # noqa: E501
    ]

    def extract_padding(self, s):
        return "", s


class ISIS_Ipv6ReachabilityTlv(ISIS_GenericTlv):
    name = "ISIS IPv6 Reachability TLV"
    fields_desc = [ByteEnumField("type", 236, _isis_tlv_names),
                   FieldLenField("len", None, length_of="pfxs", fmt="B"),
                   PacketListField("pfxs", [], ISIS_Ipv6Prefix, length_from=lambda pkt: pkt.len)]  # noqa: E501


class ISIS_IsNeighbourTlv(ISIS_GenericTlv):
    name = "ISIS IS Neighbour TLV"
    fields_desc = [ByteEnumField("type", 6, _isis_tlv_names),
                   FieldLenField("len", None, length_of="neighbours", fmt="B"),
                   FieldListField("neighbours", [], MACField("", "00.00.00.00.00.00"), count_from=lambda pkt: pkt.len // 6)]  # noqa: E501


class ISIS_LspEntry(Packet):
    name = "ISIS LSP Entry"
    fields_desc = [ShortField("lifetime", 1200),
                   ISIS_LspIdField("lspid", "0102.0304.0506.07-08"),
                   XIntField("seqnum", 0x00000001),
                   XShortField("checksum", None)]

    def extract_padding(self, s):
        return "", s


class ISIS_LspEntryTlv(ISIS_GenericTlv):
    name = "ISIS LSP Entry TLV"
    fields_desc = [
        ByteEnumField("type", 9, _isis_tlv_names),
        FieldLenField("len", None, length_of="entries", fmt="B"),
        PacketListField("entries", [], ISIS_LspEntry, count_from=lambda pkt: pkt.len // 16)  # noqa: E501
    ]


class _AdjacencyStateTlvLenField(Field):
    def i2m(self, pkt, x):
        if pkt.neighbourextlocalcircuitid is not None:
            return 15

        if pkt.neighboursystemid is not None:
            return 11

        if pkt.extlocalcircuitid is not None:
            return 5

        return 1


class ISIS_P2PAdjacencyStateTlv(ISIS_GenericTlv):
    name = "ISIS P2P Adjacency State TLV"
    fields_desc = [ByteEnumField("type", 240, _isis_tlv_names),
                   _AdjacencyStateTlvLenField("len", None, fmt="B"),
                   ByteEnumField("state", "Down", {0x2: "Down", 0x1: "Initialising", 0x0: "Up"}),  # noqa: E501
                   ConditionalField(IntField("extlocalcircuitid", None), lambda pkt: pkt.len >= 5),  # noqa: E501
                   ConditionalField(ISIS_SystemIdField("neighboursystemid", None), lambda pkt: pkt.len >= 11),  # noqa: E501
                   ConditionalField(IntField("neighbourextlocalcircuitid", None), lambda pkt: pkt.len == 15)]  # noqa: E501


# TODO dynamically allocate sufficient size
class ISIS_PaddingTlv(ISIS_GenericTlv):
    name = "ISIS Padding TLV"
    fields_desc = [
        ByteEnumField("type", 8, _isis_tlv_names),
        FieldLenField("len", None, length_of="padding", fmt="B"),
        BoundStrLenField("padding", "", length_from=lambda pkt: pkt.len)
    ]


class ISIS_ProtocolsSupportedTlv(ISIS_GenericTlv):
    name = "ISIS Protocols Supported TLV"
    fields_desc = [
        ByteEnumField("type", 129, _isis_tlv_names),
        FieldLenField("len", None, count_of="nlpids", fmt="B"),
        FieldListField("nlpids", [], ByteEnumField("", "IPv4", network_layer_protocol_ids), count_from=lambda pkt: pkt.len)  # noqa: E501
    ]


#######################################################################
#   ISIS Old-Style TLVs                                               #
#######################################################################

class ISIS_IpReachabilityEntry(Packet):
    name = "ISIS IP Reachability"
    fields_desc = [ByteField("defmetric", 1),
                   ByteField("delmetric", 0x80),
                   ByteField("expmetric", 0x80),
                   ByteField("errmetric", 0x80),
                   IPField("ipaddress", "0.0.0.0"),
                   IPField("subnetmask", "255.255.255.255")]

    def extract_padding(self, s):
        return "", s


class ISIS_InternalIpReachabilityTlv(ISIS_GenericTlv):
    name = "ISIS Internal IP Reachability TLV"
    fields_desc = [
        ByteEnumField("type", 128, _isis_tlv_names),
        FieldLenField("len", None, length_of="entries", fmt="B"),
        PacketListField("entries", [], ISIS_IpReachabilityEntry, count_from=lambda x: x.len // 12)  # noqa: E501
    ]


class ISIS_ExternalIpReachabilityTlv(ISIS_GenericTlv):
    name = "ISIS External IP Reachability TLV"
    fields_desc = [
        ByteEnumField("type", 130, _isis_tlv_names),
        FieldLenField("len", None, length_of="entries", fmt="B"),
        PacketListField("entries", [], ISIS_IpReachabilityEntry, count_from=lambda x: x.len // 12)  # noqa: E501
    ]


class ISIS_IsReachabilityEntry(Packet):
    name = "ISIS IS Reachability"
    fields_desc = [ByteField("defmetric", 1),
                   ByteField("delmetric", 0x80),
                   ByteField("expmetric", 0x80),
                   ByteField("errmetric", 0x80),
                   ISIS_NodeIdField("neighbourid", "0102.0304.0506.07")]

    def extract_padding(self, s):
        return "", s


class ISIS_IsReachabilityTlv(ISIS_GenericTlv):
    name = "ISIS IS Reachability TLV"
    fields_desc = [
        ByteEnumField("type", 2, _isis_tlv_names),
        FieldLenField("len", None, fmt="B", length_of="neighbours", adjust=lambda pkt, x: x + 1),  # noqa: E501
        ByteField("virtual", 0),
        PacketListField("neighbours", [], ISIS_IsReachabilityEntry, count_from=lambda x: (x.len - 1) // 11)  # noqa: E501
    ]


#######################################################################
#   ISIS PDU Packets                                                  #
#######################################################################
_isis_pdu_names = {
    15: "L1 LAN Hello",
    16: "L2 LAN Hello",
    17: "P2P Hello",
    18: "L1 LSP",
    20: "L2 LSP",
    24: "L1 CSNP",
    25: "L2 CSNP",
    26: "L1 PSNP",
    27: "L2 PSNP"
}


class ISIS_CommonHdr(Packet):
    name = "ISIS Common Header"
    fields_desc = [
        ByteEnumField("nlpid", 0x83, network_layer_protocol_ids),
        ByteField("hdrlen", None),
        ByteField("version", 1),
        ByteField("idlen", 0),
        ByteEnumField("pdutype", None, _isis_pdu_names),
        ByteField("pduversion", 1),
        ByteField("hdrreserved", 0),
        ByteField("maxareaaddr", 0)
    ]

    def post_build(self, pkt, pay):
        # calculating checksum if requested
        pdu = pkt + pay
        checksumInfo = self[1].checksum_info(self.hdrlen)

        if checksumInfo is not None:
            (cbegin, cpos) = checksumInfo
            checkbytes = fletcher16_checkbytes(pdu[cbegin:], (cpos - cbegin))
            pdu = pdu[:cpos] + checkbytes + pdu[cpos + 2:]

        return pdu


class _ISIS_PduBase(Packet):
    def checksum_info(self, hdrlen):
        checksumPosition = hdrlen
        for tlv in self.tlvs:
            if isinstance(tlv, ISIS_ChecksumTlv):
                checksumPosition += 2
                return (0, checksumPosition)
            else:
                checksumPosition += len(tlv)

        return None

    def guess_payload_class(self, p):
        return conf.padding_layer


class _ISIS_PduLengthField(FieldLenField):
    def __init__(self):
        FieldLenField.__init__(self, "pdulength", None, length_of="tlvs", adjust=lambda pkt, x: x + pkt.underlayer.hdrlen)  # noqa: E501


class _ISIS_TlvListField(PacketListField):
    def __init__(self):
        PacketListField.__init__(self, "tlvs", [], _ISIS_GuessTlvClass, length_from=lambda pkt: pkt.pdulength - pkt.underlayer.hdrlen)  # noqa: E501


class _ISIS_LAN_HelloBase(_ISIS_PduBase):
    fields_desc = [
        ISIS_CircuitTypeField(),
        ISIS_SystemIdField("sourceid", "0102.0304.0506"),
        ShortField("holdingtime", 30),
        _ISIS_PduLengthField(),
        ByteField("priority", 1),
        ISIS_NodeIdField("lanid", "0000.0000.0000.00"),
        _ISIS_TlvListField()
    ]


class ISIS_L1_LAN_Hello(_ISIS_LAN_HelloBase):
    name = "ISIS L1 LAN Hello PDU"


class ISIS_L2_LAN_Hello(_ISIS_LAN_HelloBase):
    name = "ISIS L2 LAN Hello PDU"


class ISIS_P2P_Hello(_ISIS_PduBase):
    name = "ISIS Point-to-Point Hello PDU"

    fields_desc = [
        ISIS_CircuitTypeField(),
        ISIS_SystemIdField("sourceid", "0102.0304.0506"),
        ShortField("holdingtime", 30),
        _ISIS_PduLengthField(),
        ByteField("localcircuitid", 0),
        _ISIS_TlvListField()
    ]


class _ISIS_LSP_Base(_ISIS_PduBase):
    fields_desc = [
        _ISIS_PduLengthField(),
        ShortField("lifetime", 1199),
        ISIS_LspIdField("lspid", "0102.0304.0506.00-00"),
        XIntField("seqnum", 0x00000001),
        XShortField("checksum", None),
        FlagsField("typeblock", 0x03, 8, ["L1", "L2", "OL", "ADef", "ADel", "AExp", "AErr", "P"]),  # noqa: E501
        _ISIS_TlvListField()
    ]

    def checksum_info(self, hdrlen):
        if self.checksum is not None:
            return None

        return (12, 24)


def _lsp_answers(lsp, other, clsname):
    # TODO
    return 0


class ISIS_L1_LSP(_ISIS_LSP_Base):
    name = "ISIS L1 Link State PDU"

    def answers(self, other):
        return _lsp_answers(self, other, "ISIS_L1_PSNP")


class ISIS_L2_LSP(_ISIS_LSP_Base):
    name = "ISIS L2 Link State PDU"

    def answers(self, other):
        return _lsp_answers(self, other, "ISIS_L2_PSNP")


class _ISIS_CSNP_Base(_ISIS_PduBase):
    fields_desc = [
        _ISIS_PduLengthField(),
        ISIS_NodeIdField("sourceid", "0102.0304.0506.00"),
        ISIS_LspIdField("startlspid", "0000.0000.0000.00-00"),
        ISIS_LspIdField("endlspid", "FFFF.FFFF.FFFF.FF-FF"),
        _ISIS_TlvListField()
    ]


def _snp_answers(snp, other, clsname):
    # TODO
    return 0


class ISIS_L1_CSNP(_ISIS_CSNP_Base):
    name = "ISIS L1 Complete Sequence Number Packet"

    def answers(self, other):
        return _snp_answers(self, other, "ISIS_L1_LSP")


class ISIS_L2_CSNP(_ISIS_CSNP_Base):
    name = "ISIS L2 Complete Sequence Number Packet"

    def answers(self, other):
        return _snp_answers(self, other, "ISIS_L2_LSP")


class _ISIS_PSNP_Base(_ISIS_PduBase):
    fields_desc = [
        _ISIS_PduLengthField(),
        ISIS_NodeIdField("sourceid", "0102.0304.0506.00"),
        _ISIS_TlvListField()
    ]


class ISIS_L1_PSNP(_ISIS_PSNP_Base):
    name = "ISIS L1 Partial Sequence Number Packet"

    def answers(self, other):
        return _snp_answers(self, other, "ISIS_L1_LSP")


class ISIS_L2_PSNP(_ISIS_PSNP_Base):
    name = "ISIS L2 Partial Sequence Number Packet"

    def answers(self, other):
        return _snp_answers(self, other, "ISIS_L2_LSP")


register_cln_protocol(0x83, ISIS_CommonHdr)
bind_layers(ISIS_CommonHdr, ISIS_L1_LAN_Hello, hdrlen=27, pdutype=15)
bind_layers(ISIS_CommonHdr, ISIS_L2_LAN_Hello, hdrlen=27, pdutype=16)
bind_layers(ISIS_CommonHdr, ISIS_P2P_Hello, hdrlen=20, pdutype=17)
bind_layers(ISIS_CommonHdr, ISIS_L1_LSP, hdrlen=27, pdutype=18)
bind_layers(ISIS_CommonHdr, ISIS_L2_LSP, hdrlen=27, pdutype=20)
bind_layers(ISIS_CommonHdr, ISIS_L1_CSNP, hdrlen=33, pdutype=24)
bind_layers(ISIS_CommonHdr, ISIS_L2_CSNP, hdrlen=33, pdutype=25)
bind_layers(ISIS_CommonHdr, ISIS_L1_PSNP, hdrlen=17, pdutype=26)
bind_layers(ISIS_CommonHdr, ISIS_L2_PSNP, hdrlen=17, pdutype=27)
