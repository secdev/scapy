# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>

# Netflow V5 appended by spaceB0x and Guillaume Valadon
# Netflow V9/10 appended by Gabriel Potter

"""
Cisco NetFlow protocol v1, v5, v9 and v10 (IPFix)

HowTo dissect NetflowV9/10 (IPFix) packets

# From a pcap / list of packets

Using sniff and sessions::

    >>> sniff(offline=open("my_great_pcap.pcap", "rb"), session=NetflowSession)

Using the netflowv9_defragment/ipfix_defragment commands:

- get a list of packets containing NetflowV9/10 packets
- call `netflowv9_defragment(plist)` to defragment the list

(ipfix_defragment is an alias for netflowv9_defragment)

# Live / on-the-flow / other: use NetflowSession::

    >>> sniff(session=NetflowSession, prn=[...])

"""

import dataclasses
import socket
import struct

from collections import Counter

from scapy.config import conf
from scapy.data import IP_PROTOS
from scapy.error import warning, Scapy_Exception
from scapy.fields import (
    BitEnumField,
    BitField,
    ByteEnumField,
    ByteField,
    ConditionalField,
    Field,
    FieldLenField,
    FlagsField,
    IPField,
    IntField,
    LongField,
    MACField,
    PacketListField,
    SecondsIntField,
    ShortEnumField,
    ShortField,
    StrField,
    StrFixedLenField,
    StrLenField,
    ThreeBytesField,
    UTCTimeField,
    XByteField,
    XShortField,
)
from scapy.packet import Packet, bind_layers, bind_bottom_up
from scapy.plist import PacketList
from scapy.sessions import IPSession

from scapy.layers.inet import UDP
from scapy.layers.inet6 import IP6Field

# Typing imports
from typing import (
    Any,
    Dict,
    Optional,
)


class NetflowHeader(Packet):
    name = "Netflow Header"
    fields_desc = [ShortField("version", 1)]


for port in [2055, 2056, 9995, 9996, 6343]:  # Classic NetFlow ports
    bind_bottom_up(UDP, NetflowHeader, dport=port)
    bind_bottom_up(UDP, NetflowHeader, sport=port)
# However, we'll default to 2055, classic among classics :)
bind_layers(UDP, NetflowHeader, dport=2055, sport=2055)

###########################################
# Netflow Version 1
###########################################


class NetflowHeaderV1(Packet):
    name = "Netflow Header v1"
    fields_desc = [ShortField("count", None),
                   IntField("sysUptime", 0),
                   UTCTimeField("unixSecs", 0),
                   UTCTimeField("unixNanoSeconds", 0, use_nano=True)]

    def post_build(self, pkt, pay):
        if self.count is None:
            count = len(self.layers()) - 1
            pkt = struct.pack("!H", count) + pkt[2:]
        return pkt + pay


class NetflowRecordV1(Packet):
    name = "Netflow Record v1"
    fields_desc = [IPField("ipsrc", "0.0.0.0"),
                   IPField("ipdst", "0.0.0.0"),
                   IPField("nexthop", "0.0.0.0"),
                   ShortField("inputIfIndex", 0),
                   ShortField("outpuIfIndex", 0),
                   IntField("dpkts", 0),
                   IntField("dbytes", 0),
                   IntField("starttime", 0),
                   IntField("endtime", 0),
                   ShortField("srcport", 0),
                   ShortField("dstport", 0),
                   ShortField("padding", 0),
                   ByteField("proto", 0),
                   ByteField("tos", 0),
                   IntField("padding1", 0),
                   IntField("padding2", 0)]


bind_layers(NetflowHeader, NetflowHeaderV1, version=1)
bind_layers(NetflowHeaderV1, NetflowRecordV1)
bind_layers(NetflowRecordV1, NetflowRecordV1)


#########################################
# Netflow Version 5
#########################################


class NetflowHeaderV5(Packet):
    name = "Netflow Header v5"
    fields_desc = [ShortField("count", None),
                   IntField("sysUptime", 0),
                   UTCTimeField("unixSecs", 0),
                   UTCTimeField("unixNanoSeconds", 0, use_nano=True),
                   IntField("flowSequence", 0),
                   ByteField("engineType", 0),
                   ByteField("engineID", 0),
                   ShortField("samplingInterval", 0)]

    def post_build(self, pkt, pay):
        if self.count is None:
            count = len(self.layers()) - 1
            pkt = struct.pack("!H", count) + pkt[2:]
        return pkt + pay


class NetflowRecordV5(Packet):
    name = "Netflow Record v5"
    fields_desc = [IPField("src", "127.0.0.1"),
                   IPField("dst", "127.0.0.1"),
                   IPField("nexthop", "0.0.0.0"),
                   ShortField("input", 0),
                   ShortField("output", 0),
                   IntField("dpkts", 1),
                   IntField("dOctets", 60),
                   IntField("first", 0),
                   IntField("last", 0),
                   ShortField("srcport", 0),
                   ShortField("dstport", 0),
                   ByteField("pad1", 0),
                   FlagsField("tcpFlags", 0x2, 8, "FSRPAUEC"),
                   ByteEnumField("prot", socket.IPPROTO_TCP, IP_PROTOS),
                   ByteField("tos", 0),
                   ShortField("src_as", 0),
                   ShortField("dst_as", 0),
                   ByteField("src_mask", 0),
                   ByteField("dst_mask", 0),
                   ShortField("pad2", 0)]


bind_layers(NetflowHeader, NetflowHeaderV5, version=5)
bind_layers(NetflowHeaderV5, NetflowRecordV5)
bind_layers(NetflowRecordV5, NetflowRecordV5)

#########################################
# Netflow Version 9/10
#########################################

# NetflowV9 RFC
# https://www.ietf.org/rfc/rfc3954.txt

# IPFix RFC
# https://tools.ietf.org/html/rfc5101
# https://tools.ietf.org/html/rfc5655


@dataclasses.dataclass
class _N910F:
    name: str
    length: int = 0
    field: Field = None
    kwargs: Dict[str, Any] = dataclasses.field(default_factory=dict)


# NetflowV9 Ready-made fields

class ShortOrInt(IntField):
    def getfield(self, pkt, x):
        if len(x) == 2:
            Field.__init__(self, self.name, self.default, fmt="!H")
        return Field.getfield(self, pkt, x)


class _AdjustableNetflowField(IntField, LongField):
    """Fields that can receive a length kwarg, even though they normally can't.
    Netflow usage only."""
    def __init__(self, name, default, length):
        if length == 4:
            IntField.__init__(self, name, default)
            return
        elif length == 8:
            LongField.__init__(self, name, default)
            return
        LongField.__init__(self, name, default)


class N9SecondsIntField(SecondsIntField, _AdjustableNetflowField):
    """Defines dateTimeSeconds (without EPOCH: just seconds)"""
    def __init__(self, name, default, *args, **kargs):
        length = kargs.pop("length", 8)
        SecondsIntField.__init__(self, name, default, *args, **kargs)
        _AdjustableNetflowField.__init__(
            self, name, default, length
        )


class N9UTCTimeField(UTCTimeField, _AdjustableNetflowField):
    """Defines dateTimeSeconds (EPOCH)"""
    def __init__(self, name, default, *args, **kargs):
        length = kargs.pop("length", 8)
        UTCTimeField.__init__(self, name, default, *args, **kargs)
        _AdjustableNetflowField.__init__(
            self, name, default, length
        )

# TODO: There are hundreds of entries to add to the following list :(
# it's thus incomplete.
# https://www.iana.org/assignments/ipfix/ipfix.xml
# ==> feel free to contribute :D

# XXX: we should probably switch the names below to IANA normalized ones.

# This is v9_v10_template_types (with names from the rfc for the first 79)
# https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-netflow.c  # noqa: E501
# (it has all values external to the RFC)


NTOP_BASE = 57472
NetflowV910TemplateFields = {
    1: _N910F("IN_BYTES", length=4),
    2: _N910F("IN_PKTS", length=4),
    3: _N910F("FLOWS", length=4),
    4: _N910F("PROTOCOL", length=1,
              field=ByteEnumField, kwargs={"enum": IP_PROTOS}),
    5: _N910F("TOS", length=1,
              field=XByteField),
    6: _N910F("TCP_FLAGS", length=1,
              field=ByteField),
    7: _N910F("L4_SRC_PORT", length=2,
              field=ShortField),
    8: _N910F("IPV4_SRC_ADDR", length=4,
              field=IPField),
    9: _N910F("SRC_MASK", length=1,
              field=ByteField),
    10: _N910F("INPUT_SNMP"),
    11: _N910F("L4_DST_PORT", length=2,
               field=ShortField),
    12: _N910F("IPV4_DST_ADDR", length=4,
               field=IPField),
    13: _N910F("DST_MASK", length=1,
               field=ByteField),
    14: _N910F("OUTPUT_SNMP"),
    15: _N910F("IPV4_NEXT_HOP", length=4,
               field=IPField),
    16: _N910F("SRC_AS", length=2,
               field=ShortOrInt),
    17: _N910F("DST_AS", length=2,
               field=ShortOrInt),
    18: _N910F("BGP_IPV4_NEXT_HOP", length=4,
               field=IPField),
    19: _N910F("MUL_DST_PKTS", length=4),
    20: _N910F("MUL_DST_BYTES", length=4),
    21: _N910F("LAST_SWITCHED", length=4,
               field=SecondsIntField,
               kwargs={"use_msec": True}),
    22: _N910F("FIRST_SWITCHED", length=4,
               field=SecondsIntField,
               kwargs={"use_msec": True}),
    23: _N910F("OUT_BYTES", length=4),
    24: _N910F("OUT_PKTS", length=4),
    25: _N910F("IP_LENGTH_MINIMUM"),
    26: _N910F("IP_LENGTH_MAXIMUM"),
    27: _N910F("IPV6_SRC_ADDR", length=16,
               field=IP6Field),
    28: _N910F("IPV6_DST_ADDR", length=16,
               field=IP6Field),
    29: _N910F("IPV6_SRC_MASK", length=1,
               field=ByteField),
    30: _N910F("IPV6_DST_MASK", length=1,
               field=ByteField),
    31: _N910F("IPV6_FLOW_LABEL", length=3,
               field=ThreeBytesField),
    32: _N910F("ICMP_TYPE", length=2,
               field=XShortField),
    33: _N910F("MUL_IGMP_TYPE", length=1,
               field=ByteField),
    34: _N910F("SAMPLING_INTERVAL", length=4,
               field=IntField),
    35: _N910F("SAMPLING_ALGORITHM", length=1,
               field=XByteField),
    36: _N910F("FLOW_ACTIVE_TIMEOUT", length=2,
               field=ShortField),
    37: _N910F("FLOW_INACTIVE_TIMEOUT", length=2,
               field=ShortField),
    38: _N910F("ENGINE_TYPE", length=1,
               field=ByteField),
    39: _N910F("ENGINE_ID", length=1,
               field=ByteField),
    40: _N910F("TOTAL_BYTES_EXP", length=4),
    41: _N910F("TOTAL_PKTS_EXP", length=4),
    42: _N910F("TOTAL_FLOWS_EXP", length=4),
    43: _N910F("IPV4_ROUTER_SC"),
    44: _N910F("IP_SRC_PREFIX"),
    45: _N910F("IP_DST_PREFIX"),
    46: _N910F("MPLS_TOP_LABEL_TYPE", length=1,
               field=ByteEnumField,
               kwargs={"enum": {
                   0x00: "UNKNOWN",
                   0x01: "TE-MIDPT",
                   0x02: "ATOM",
                   0x03: "VPN",
                   0x04: "BGP",
                   0x05: "LDP",
               }}),
    47: _N910F("MPLS_TOP_LABEL_IP_ADDR", length=4,
               field=IPField),
    48: _N910F("FLOW_SAMPLER_ID", length=4),  # from ERRATA
    49: _N910F("FLOW_SAMPLER_MODE", length=1,
               field=ByteField),
    50: _N910F("FLOW_SAMPLER_RANDOM_INTERVAL", length=4,
               field=IntField),
    51: _N910F("FLOW_CLASS"),
    52: _N910F("MIN_TTL"),
    53: _N910F("MAX_TTL"),
    54: _N910F("IPV4_IDENT"),
    55: _N910F("DST_TOS", length=1,
               field=XByteField),
    56: _N910F("SRC_MAC", length=6,
               field=MACField),
    57: _N910F("DST_MAC", length=6,
               field=MACField),
    58: _N910F("SRC_VLAN", length=2,
               field=ShortField),
    59: _N910F("DST_VLAN", length=2,
               field=ShortField),
    60: _N910F("IP_PROTOCOL_VERSION", length=1,
               field=ByteField),
    61: _N910F("DIRECTION", length=1,
               field=ByteEnumField,
               kwargs={"enum": {0x00: "Ingress flow", 0x01: "Egress flow"}}),
    62: _N910F("IPV6_NEXT_HOP", length=16,
               field=IP6Field),
    63: _N910F("BGP_IPV6_NEXT_HOP", length=16,
               field=IP6Field),
    64: _N910F("IPV6_OPTION_HEADERS", length=4),
    70: _N910F("MPLS_LABEL_1", length=3),
    71: _N910F("MPLS_LABEL_2", length=3),
    72: _N910F("MPLS_LABEL_3", length=3),
    73: _N910F("MPLS_LABEL_4", length=3),
    74: _N910F("MPLS_LABEL_5", length=3),
    75: _N910F("MPLS_LABEL_6", length=3),
    76: _N910F("MPLS_LABEL_7", length=3),
    77: _N910F("MPLS_LABEL_8", length=3),
    78: _N910F("MPLS_LABEL_9", length=3),
    79: _N910F("MPLS_LABEL_10", length=3),
    80: _N910F("DESTINATION_MAC"),
    81: _N910F("SOURCE_MAC"),
    82: _N910F("IF_NAME"),
    83: _N910F("IF_DESC"),
    84: _N910F("SAMPLER_NAME"),
    85: _N910F("BYTES_TOTAL"),
    86: _N910F("PACKETS_TOTAL"),
    88: _N910F("FRAGMENT_OFFSET"),
    89: _N910F("FORWARDING_STATUS"),
    90: _N910F("VPN_ROUTE_DISTINGUISHER"),
    91: _N910F("mplsTopLabelPrefixLength"),
    92: _N910F("SRC_TRAFFIC_INDEX"),
    93: _N910F("DST_TRAFFIC_INDEX"),
    94: _N910F("APPLICATION_DESC"),
    95: _N910F("APPLICATION_ID"),
    96: _N910F("APPLICATION_NAME"),
    98: _N910F("postIpDiffServCodePoint"),
    99: _N910F("multicastReplicationFactor"),
    101: _N910F("classificationEngineId"),
    128: _N910F("DST_AS_PEER"),
    129: _N910F("SRC_AS_PEER"),
    130: _N910F("exporterIPv4Address", length=4,
                field=IPField),
    131: _N910F("exporterIPv6Address", length=16,
                field=IP6Field),
    132: _N910F("DROPPED_BYTES"),
    133: _N910F("DROPPED_PACKETS"),
    134: _N910F("DROPPED_BYTES_TOTAL"),
    135: _N910F("DROPPED_PACKETS_TOTAL"),
    136: _N910F("flowEndReason"),
    137: _N910F("commonPropertiesId"),
    138: _N910F("observationPointId"),
    139: _N910F("icmpTypeCodeIPv6"),
    140: _N910F("MPLS_TOP_LABEL_IPv6_ADDRESS"),
    141: _N910F("lineCardId"),
    142: _N910F("portId"),
    143: _N910F("meteringProcessId"),
    144: _N910F("FLOW_EXPORTER"),
    145: _N910F("templateId"),
    146: _N910F("wlanChannelId"),
    147: _N910F("wlanSSID"),
    148: _N910F("flowId"),
    149: _N910F("observationDomainId"),
    150: _N910F("flowStartSeconds", length=8,
                field=N9UTCTimeField),
    151: _N910F("flowEndSeconds", length=8,
                field=N9UTCTimeField),
    152: _N910F("flowStartMilliseconds", length=8,
                field=N9UTCTimeField,
                kwargs={"use_msec": True}),
    153: _N910F("flowEndMilliseconds", length=8,
                field=N9UTCTimeField,
                kwargs={"use_msec": True}),
    154: _N910F("flowStartMicroseconds", length=8,
                field=N9UTCTimeField,
                kwargs={"use_micro": True}),
    155: _N910F("flowEndMicroseconds", length=8,
                field=N9UTCTimeField,
                kwargs={"use_micro": True}),
    156: _N910F("flowStartNanoseconds", length=8,
                field=N9UTCTimeField,
                kwargs={"use_nano": True}),
    157: _N910F("flowEndNanoseconds", length=8,
                field=N9UTCTimeField,
                kwargs={"use_nano": True}),
    158: _N910F("flowStartDeltaMicroseconds", length=8,
                field=N9SecondsIntField,
                kwargs={"use_micro": True}),
    159: _N910F("flowEndDeltaMicroseconds", length=8,
                field=N9SecondsIntField,
                kwargs={"use_micro": True}),
    160: _N910F("systemInitTimeMilliseconds", length=8,
                field=N9UTCTimeField,
                kwargs={"use_msec": True}),
    161: _N910F("flowDurationMilliseconds", length=8,
                field=N9SecondsIntField,
                kwargs={"use_msec": True}),
    162: _N910F("flowDurationMicroseconds", length=8,
                field=N9SecondsIntField,
                kwargs={"use_micro": True}),
    163: _N910F("observedFlowTotalCount"),
    164: _N910F("ignoredPacketTotalCount"),
    165: _N910F("ignoredOctetTotalCount"),
    166: _N910F("notSentFlowTotalCount"),
    167: _N910F("notSentPacketTotalCount"),
    168: _N910F("notSentOctetTotalCount"),
    169: _N910F("destinationIPv6Prefix"),
    170: _N910F("sourceIPv6Prefix"),
    171: _N910F("postOctetTotalCount"),
    172: _N910F("postPacketTotalCount"),
    173: _N910F("flowKeyIndicator"),
    174: _N910F("postMCastPacketTotalCount"),
    175: _N910F("postMCastOctetTotalCount"),
    176: _N910F("ICMP_IPv4_TYPE"),
    177: _N910F("ICMP_IPv4_CODE"),
    178: _N910F("ICMP_IPv6_TYPE"),
    179: _N910F("ICMP_IPv6_CODE"),
    180: _N910F("UDP_SRC_PORT"),
    181: _N910F("UDP_DST_PORT"),
    182: _N910F("TCP_SRC_PORT"),
    183: _N910F("TCP_DST_PORT"),
    184: _N910F("TCP_SEQ_NUM"),
    185: _N910F("TCP_ACK_NUM"),
    186: _N910F("TCP_WINDOW_SIZE"),
    187: _N910F("TCP_URGENT_PTR"),
    188: _N910F("TCP_HEADER_LEN"),
    189: _N910F("IP_HEADER_LEN"),
    190: _N910F("IP_TOTAL_LEN"),
    191: _N910F("payloadLengthIPv6"),
    192: _N910F("IP_TTL"),
    193: _N910F("nextHeaderIPv6"),
    194: _N910F("mplsPayloadLength"),
    195: _N910F("IP_DSCP", length=1,
                field=XByteField),
    196: _N910F("IP_PRECEDENCE"),
    197: _N910F("IP_FRAGMENT_FLAGS"),
    198: _N910F("DELTA_BYTES_SQUARED"),
    199: _N910F("TOTAL_BYTES_SQUARED"),
    200: _N910F("MPLS_TOP_LABEL_TTL"),
    201: _N910F("MPLS_LABEL_STACK_OCTETS"),
    202: _N910F("MPLS_LABEL_STACK_DEPTH"),
    203: _N910F("MPLS_TOP_LABEL_EXP"),
    204: _N910F("IP_PAYLOAD_LENGTH"),
    205: _N910F("UDP_LENGTH"),
    206: _N910F("IS_MULTICAST"),
    207: _N910F("IP_HEADER_WORDS"),
    208: _N910F("IP_OPTION_MAP"),
    209: _N910F("TCP_OPTION_MAP"),
    210: _N910F("paddingOctets"),
    211: _N910F("collectorIPv4Address", length=4,
                field=IPField),
    212: _N910F("collectorIPv6Address", length=16,
                field=IP6Field),
    213: _N910F("collectorInterface"),
    214: _N910F("collectorProtocolVersion"),
    215: _N910F("collectorTransportProtocol"),
    216: _N910F("collectorTransportPort"),
    217: _N910F("exporterTransportPort"),
    218: _N910F("tcpSynTotalCount"),
    219: _N910F("tcpFinTotalCount"),
    220: _N910F("tcpRstTotalCount"),
    221: _N910F("tcpPshTotalCount"),
    222: _N910F("tcpAckTotalCount"),
    223: _N910F("tcpUrgTotalCount"),
    224: _N910F("ipTotalLength"),
    225: _N910F("postNATSourceIPv4Address", length=4,
                field=IPField),
    226: _N910F("postNATDestinationIPv4Address", length=4,
                field=IPField),
    227: _N910F("postNAPTSourceTransportPort"),
    228: _N910F("postNAPTDestinationTransportPort"),
    229: _N910F("natOriginatingAddressRealm"),
    230: _N910F("natEvent"),
    231: _N910F("initiatorOctets"),
    232: _N910F("responderOctets"),
    233: _N910F("firewallEvent"),
    234: _N910F("ingressVRFID"),
    235: _N910F("egressVRFID"),
    236: _N910F("VRFname"),
    237: _N910F("postMplsTopLabelExp"),
    238: _N910F("tcpWindowScale"),
    239: _N910F("biflowDirection"),
    240: _N910F("ethernetHeaderLength"),
    241: _N910F("ethernetPayloadLength"),
    242: _N910F("ethernetTotalLength"),
    243: _N910F("dot1qVlanId"),
    244: _N910F("dot1qPriority"),
    245: _N910F("dot1qCustomerVlanId"),
    246: _N910F("dot1qCustomerPriority"),
    247: _N910F("metroEvcId"),
    248: _N910F("metroEvcType"),
    249: _N910F("pseudoWireId"),
    250: _N910F("pseudoWireType"),
    251: _N910F("pseudoWireControlWord"),
    252: _N910F("ingressPhysicalInterface"),
    253: _N910F("egressPhysicalInterface"),
    254: _N910F("postDot1qVlanId"),
    255: _N910F("postDot1qCustomerVlanId"),
    256: _N910F("ethernetType"),
    257: _N910F("postIpPrecedence"),
    258: _N910F("collectionTimeMilliseconds", length=8,
                field=N9SecondsIntField,
                kwargs={"use_msec": True}),
    259: _N910F("exportSctpStreamId"),
    260: _N910F("maxExportSeconds", length=8,
                field=N9SecondsIntField),
    261: _N910F("maxFlowEndSeconds", length=8,
                field=N9SecondsIntField),
    262: _N910F("messageMD5Checksum"),
    263: _N910F("messageScope"),
    264: _N910F("minExportSeconds", length=8,
                field=N9SecondsIntField),
    265: _N910F("minFlowStartSeconds", length=8,
                field=N9SecondsIntField),
    266: _N910F("opaqueOctets"),
    267: _N910F("sessionScope"),
    268: _N910F("maxFlowEndMicroseconds", length=8,
                field=N9UTCTimeField,
                kwargs={"use_micro": True}),
    269: _N910F("maxFlowEndMilliseconds", length=8,
                field=N9UTCTimeField,
                kwargs={"use_msec": True}),
    270: _N910F("maxFlowEndNanoseconds", length=8,
                field=N9UTCTimeField,
                kwargs={"use_nano": True}),
    271: _N910F("minFlowStartMicroseconds", length=8,
                field=N9UTCTimeField,
                kwargs={"use_micro": True}),
    272: _N910F("minFlowStartMilliseconds", length=8,
                field=N9UTCTimeField,
                kwargs={"use_msec": True}),
    273: _N910F("minFlowStartNanoseconds", length=8,
                field=N9UTCTimeField,
                kwargs={"use_nano": True}),
    274: _N910F("collectorCertificate"),
    275: _N910F("exporterCertificate"),
    276: _N910F("dataRecordsReliability"),
    277: _N910F("observationPointType"),
    278: _N910F("newConnectionDeltaCount"),
    279: _N910F("connectionSumDurationSeconds", length=8,
                field=N9SecondsIntField),
    280: _N910F("connectionTransactionId"),
    281: _N910F("postNATSourceIPv6Address", length=16,
                field=IP6Field),
    282: _N910F("postNATDestinationIPv6Address", length=16,
                field=IP6Field),
    283: _N910F("natPoolId"),
    284: _N910F("natPoolName"),
    285: _N910F("anonymizationFlags"),
    286: _N910F("anonymizationTechnique"),
    287: _N910F("informationElementIndex"),
    288: _N910F("p2pTechnology"),
    289: _N910F("tunnelTechnology"),
    290: _N910F("encryptedTechnology"),
    291: _N910F("basicList"),
    292: _N910F("subTemplateList"),
    293: _N910F("subTemplateMultiList"),
    294: _N910F("bgpValidityState"),
    295: _N910F("IPSecSPI"),
    296: _N910F("greKey"),
    297: _N910F("natType"),
    298: _N910F("initiatorPackets"),
    299: _N910F("responderPackets"),
    300: _N910F("observationDomainName"),
    301: _N910F("selectionSequenceId"),
    302: _N910F("selectorId"),
    303: _N910F("informationElementId"),
    304: _N910F("selectorAlgorithm"),
    305: _N910F("samplingPacketInterval"),
    306: _N910F("samplingPacketSpace"),
    307: _N910F("samplingTimeInterval"),
    308: _N910F("samplingTimeSpace"),
    309: _N910F("samplingSize"),
    310: _N910F("samplingPopulation"),
    311: _N910F("samplingProbability"),
    312: _N910F("dataLinkFrameSize"),
    313: _N910F("IP_SECTION_HEADER"),
    314: _N910F("IP_SECTION_PAYLOAD"),
    315: _N910F("dataLinkFrameSection"),
    316: _N910F("mplsLabelStackSection"),
    317: _N910F("mplsPayloadPacketSection"),
    318: _N910F("selectorIdTotalPktsObserved"),
    319: _N910F("selectorIdTotalPktsSelected"),
    320: _N910F("absoluteError"),
    321: _N910F("relativeError"),
    322: _N910F("observationTimeSeconds", length=8,
                field=N9UTCTimeField),
    323: _N910F("observationTimeMilliseconds", length=8,
                field=N9UTCTimeField,
                kwargs={"use_msec": True}),
    324: _N910F("observationTimeMicroseconds", length=8,
                field=N9UTCTimeField,
                kwargs={"use_micro": True}),
    325: _N910F("observationTimeNanoseconds", length=8,
                field=N9UTCTimeField,
                kwargs={"use_nano": True}),
    326: _N910F("digestHashValue"),
    327: _N910F("hashIPPayloadOffset"),
    328: _N910F("hashIPPayloadSize"),
    329: _N910F("hashOutputRangeMin"),
    330: _N910F("hashOutputRangeMax"),
    331: _N910F("hashSelectedRangeMin"),
    332: _N910F("hashSelectedRangeMax"),
    333: _N910F("hashDigestOutput"),
    334: _N910F("hashInitialiserValue"),
    335: _N910F("selectorName"),
    336: _N910F("upperCILimit"),
    337: _N910F("lowerCILimit"),
    338: _N910F("confidenceLevel"),
    339: _N910F("informationElementDataType"),
    340: _N910F("informationElementDescription"),
    341: _N910F("informationElementName"),
    342: _N910F("informationElementRangeBegin"),
    343: _N910F("informationElementRangeEnd"),
    344: _N910F("informationElementSemantics"),
    345: _N910F("informationElementUnits"),
    346: _N910F("privateEnterpriseNumber"),
    347: _N910F("virtualStationInterfaceId"),
    348: _N910F("virtualStationInterfaceName"),
    349: _N910F("virtualStationUUID"),
    350: _N910F("virtualStationName"),
    351: _N910F("layer2SegmentId"),
    352: _N910F("layer2OctetDeltaCount"),
    353: _N910F("layer2OctetTotalCount"),
    354: _N910F("ingressUnicastPacketTotalCount"),
    355: _N910F("ingressMulticastPacketTotalCount"),
    356: _N910F("ingressBroadcastPacketTotalCount"),
    357: _N910F("egressUnicastPacketTotalCount"),
    358: _N910F("egressBroadcastPacketTotalCount"),
    359: _N910F("monitoringIntervalStartMilliSeconds"),
    360: _N910F("monitoringIntervalEndMilliSeconds"),
    361: _N910F("portRangeStart"),
    362: _N910F("portRangeEnd"),
    363: _N910F("portRangeStepSize"),
    364: _N910F("portRangeNumPorts"),
    365: _N910F("staMacAddress", length=6,
                field=MACField),
    366: _N910F("staIPv4Address", length=4,
                field=IPField),
    367: _N910F("wtpMacAddress", length=6,
                field=MACField),
    368: _N910F("ingressInterfaceType"),
    369: _N910F("egressInterfaceType"),
    370: _N910F("rtpSequenceNumber"),
    371: _N910F("userName"),
    372: _N910F("applicationCategoryName"),
    373: _N910F("applicationSubCategoryName"),
    374: _N910F("applicationGroupName"),
    375: _N910F("originalFlowsPresent"),
    376: _N910F("originalFlowsInitiated"),
    377: _N910F("originalFlowsCompleted"),
    378: _N910F("distinctCountOfSourceIPAddress"),
    379: _N910F("distinctCountOfDestinationIPAddress"),
    380: _N910F("distinctCountOfSourceIPv4Address", length=4,
                field=IPField),
    381: _N910F("distinctCountOfDestinationIPv4Address", length=4,
                field=IPField),
    382: _N910F("distinctCountOfSourceIPv6Address", length=16,
                field=IP6Field),
    383: _N910F("distinctCountOfDestinationIPv6Address", length=16,
                field=IP6Field),
    384: _N910F("valueDistributionMethod"),
    385: _N910F("rfc3550JitterMilliseconds"),
    386: _N910F("rfc3550JitterMicroseconds"),
    387: _N910F("rfc3550JitterNanoseconds"),
    388: _N910F("dot1qDEI"),
    389: _N910F("dot1qCustomerDEI"),
    390: _N910F("flowSelectorAlgorithm"),
    391: _N910F("flowSelectedOctetDeltaCount"),
    392: _N910F("flowSelectedPacketDeltaCount"),
    393: _N910F("flowSelectedFlowDeltaCount"),
    394: _N910F("selectorIDTotalFlowsObserved"),
    395: _N910F("selectorIDTotalFlowsSelected"),
    396: _N910F("samplingFlowInterval"),
    397: _N910F("samplingFlowSpacing"),
    398: _N910F("flowSamplingTimeInterval"),
    399: _N910F("flowSamplingTimeSpacing"),
    400: _N910F("hashFlowDomain"),
    401: _N910F("transportOctetDeltaCount"),
    402: _N910F("transportPacketDeltaCount"),
    403: _N910F("originalExporterIPv4Address", length=4,
                field=IPField),
    404: _N910F("originalExporterIPv6Address", length=16,
                field=IP6Field),
    405: _N910F("originalObservationDomainId"),
    406: _N910F("intermediateProcessId"),
    407: _N910F("ignoredDataRecordTotalCount"),
    408: _N910F("dataLinkFrameType"),
    409: _N910F("sectionOffset"),
    410: _N910F("sectionExportedOctets"),
    411: _N910F("dot1qServiceInstanceTag"),
    412: _N910F("dot1qServiceInstanceId"),
    413: _N910F("dot1qServiceInstancePriority"),
    414: _N910F("dot1qCustomerSourceMacAddress", length=6,
                field=MACField),
    415: _N910F("dot1qCustomerDestinationMacAddress", length=6,
                field=MACField),
    416: _N910F("deprecated [dup of layer2OctetDeltaCount]"),
    417: _N910F("postLayer2OctetDeltaCount"),
    418: _N910F("postMCastLayer2OctetDeltaCount"),
    419: _N910F("deprecated [dup of layer2OctetTotalCount"),
    420: _N910F("postLayer2OctetTotalCount"),
    421: _N910F("postMCastLayer2OctetTotalCount"),
    422: _N910F("minimumLayer2TotalLength"),
    423: _N910F("maximumLayer2TotalLength"),
    424: _N910F("droppedLayer2OctetDeltaCount"),
    425: _N910F("droppedLayer2OctetTotalCount"),
    426: _N910F("ignoredLayer2OctetTotalCount"),
    427: _N910F("notSentLayer2OctetTotalCount"),
    428: _N910F("layer2OctetDeltaSumOfSquares"),
    429: _N910F("layer2OctetTotalSumOfSquares"),
    430: _N910F("layer2FrameDeltaCount"),
    431: _N910F("layer2FrameTotalCount"),
    432: _N910F("pseudoWireDestinationIPv4Address", length=4,
                field=IPField),
    433: _N910F("ignoredLayer2FrameTotalCount"),
    434: _N910F("mibObjectValueInteger"),
    435: _N910F("mibObjectValueOctetString"),
    436: _N910F("mibObjectValueOID"),
    437: _N910F("mibObjectValueBits"),
    438: _N910F("mibObjectValueIPAddress"),
    439: _N910F("mibObjectValueCounter"),
    440: _N910F("mibObjectValueGauge"),
    441: _N910F("mibObjectValueTimeTicks"),
    442: _N910F("mibObjectValueUnsigned"),
    443: _N910F("mibObjectValueTable"),
    444: _N910F("mibObjectValueRow"),
    445: _N910F("mibObjectIdentifier"),
    446: _N910F("mibSubIdentifier"),
    447: _N910F("mibIndexIndicator"),
    448: _N910F("mibCaptureTimeSemantics"),
    449: _N910F("mibContextEngineID"),
    450: _N910F("mibContextName"),
    451: _N910F("mibObjectName"),
    452: _N910F("mibObjectDescription"),
    453: _N910F("mibObjectSyntax"),
    454: _N910F("mibModuleName"),
    455: _N910F("mobileIMSI"),
    456: _N910F("mobileMSISDN"),
    457: _N910F("httpStatusCode"),
    458: _N910F("sourceTransportPortsLimit"),
    459: _N910F("httpRequestMethod"),
    460: _N910F("httpRequestHost"),
    461: _N910F("httpRequestTarget"),
    462: _N910F("httpMessageVersion"),
    463: _N910F("natInstanceID"),
    464: _N910F("internalAddressRealm"),
    465: _N910F("externalAddressRealm"),
    466: _N910F("natQuotaExceededEvent"),
    467: _N910F("natThresholdEvent"),
    468: _N910F("httpUserAgent"),
    469: _N910F("httpContentType"),
    470: _N910F("httpReasonPhrase"),
    471: _N910F("maxSessionEntries"),
    472: _N910F("maxBIBEntries"),
    473: _N910F("maxEntriesPerUser"),
    474: _N910F("maxSubscribers"),
    475: _N910F("maxFragmentsPendingReassembly"),
    476: _N910F("addressPoolHighThreshold"),
    477: _N910F("addressPoolLowThreshold"),
    478: _N910F("addressPortMappingHighThreshold"),
    479: _N910F("addressPortMappingLowThreshold"),
    480: _N910F("addressPortMappingPerUserHighThreshold"),
    481: _N910F("globalAddressMappingHighThreshold"),

    # Ericsson NAT Logging
    24628: _N910F("NAT_LOG_FIELD_IDX_CONTEXT_ID"),
    24629: _N910F("NAT_LOG_FIELD_IDX_CONTEXT_NAME"),
    24630: _N910F("NAT_LOG_FIELD_IDX_ASSIGN_TS_SEC"),
    24631: _N910F("NAT_LOG_FIELD_IDX_UNASSIGN_TS_SEC"),
    24632: _N910F("NAT_LOG_FIELD_IDX_IPV4_INT_ADDR", length=4,
                  field=IPField),
    24633: _N910F("NAT_LOG_FIELD_IDX_IPV4_EXT_ADDR", length=4,
                  field=IPField),
    24634: _N910F("NAT_LOG_FIELD_IDX_EXT_PORT_FIRST"),
    24635: _N910F("NAT_LOG_FIELD_IDX_EXT_PORT_LAST"),
    # Cisco ASA5500 Series NetFlow
    33000: _N910F("INGRESS_ACL_ID"),
    33001: _N910F("EGRESS_ACL_ID"),
    33002: _N910F("FW_EXT_EVENT"),
    # Cisco TrustSec
    34000: _N910F("SGT_SOURCE_TAG"),
    34001: _N910F("SGT_DESTINATION_TAG"),
    34002: _N910F("SGT_SOURCE_NAME"),
    34003: _N910F("SGT_DESTINATION_NAME"),
    # medianet performance monitor
    37000: _N910F("PACKETS_DROPPED"),
    37003: _N910F("BYTE_RATE"),
    37004: _N910F("APPLICATION_MEDIA_BYTES"),
    37006: _N910F("APPLICATION_MEDIA_BYTE_RATE"),
    37007: _N910F("APPLICATION_MEDIA_PACKETS"),
    37009: _N910F("APPLICATION_MEDIA_PACKET_RATE"),
    37011: _N910F("APPLICATION_MEDIA_EVENT"),
    37012: _N910F("MONITOR_EVENT"),
    37013: _N910F("TIMESTAMP_INTERVAL"),
    37014: _N910F("TRANSPORT_PACKETS_EXPECTED"),
    37016: _N910F("TRANSPORT_ROUND_TRIP_TIME"),
    37017: _N910F("TRANSPORT_EVENT_PACKET_LOSS"),
    37019: _N910F("TRANSPORT_PACKETS_LOST"),
    37021: _N910F("TRANSPORT_PACKETS_LOST_RATE"),
    37022: _N910F("TRANSPORT_RTP_SSRC"),
    37023: _N910F("TRANSPORT_RTP_JITTER_MEAN"),
    37024: _N910F("TRANSPORT_RTP_JITTER_MIN"),
    37025: _N910F("TRANSPORT_RTP_JITTER_MAX"),
    37041: _N910F("TRANSPORT_RTP_PAYLOAD_TYPE"),
    37071: _N910F("TRANSPORT_BYTES_OUT_OF_ORDER"),
    37074: _N910F("TRANSPORT_PACKETS_OUT_OF_ORDER"),
    37083: _N910F("TRANSPORT_TCP_WINDOWS_SIZE_MIN"),
    37084: _N910F("TRANSPORT_TCP_WINDOWS_SIZE_MAX"),
    37085: _N910F("TRANSPORT_TCP_WINDOWS_SIZE_MEAN"),
    37086: _N910F("TRANSPORT_TCP_MAXIMUM_SEGMENT_SIZE"),
    # Cisco ASA 5500
    40000: _N910F("AAA_USERNAME"),
    40001: _N910F("XLATE_SRC_ADDR_IPV4", length=4,
                  field=IPField),
    40002: _N910F("XLATE_DST_ADDR_IPV4", length=4,
                  field=IPField),
    40003: _N910F("XLATE_SRC_PORT"),
    40004: _N910F("XLATE_DST_PORT"),
    40005: _N910F("FW_EVENT"),
    # v9 nTop extensions
    80 + NTOP_BASE: _N910F("SRC_FRAGMENTS"),
    81 + NTOP_BASE: _N910F("DST_FRAGMENTS"),
    82 + NTOP_BASE: _N910F("SRC_TO_DST_MAX_THROUGHPUT"),
    83 + NTOP_BASE: _N910F("SRC_TO_DST_MIN_THROUGHPUT"),
    84 + NTOP_BASE: _N910F("SRC_TO_DST_AVG_THROUGHPUT"),
    85 + NTOP_BASE: _N910F("SRC_TO_SRC_MAX_THROUGHPUT"),
    86 + NTOP_BASE: _N910F("SRC_TO_SRC_MIN_THROUGHPUT"),
    87 + NTOP_BASE: _N910F("SRC_TO_SRC_AVG_THROUGHPUT"),
    88 + NTOP_BASE: _N910F("NUM_PKTS_UP_TO_128_BYTES"),
    89 + NTOP_BASE: _N910F("NUM_PKTS_128_TO_256_BYTES"),
    90 + NTOP_BASE: _N910F("NUM_PKTS_256_TO_512_BYTES"),
    91 + NTOP_BASE: _N910F("NUM_PKTS_512_TO_1024_BYTES"),
    92 + NTOP_BASE: _N910F("NUM_PKTS_1024_TO_1514_BYTES"),
    93 + NTOP_BASE: _N910F("NUM_PKTS_OVER_1514_BYTES"),
    98 + NTOP_BASE: _N910F("CUMULATIVE_ICMP_TYPE"),
    101 + NTOP_BASE: _N910F("SRC_IP_COUNTRY"),
    102 + NTOP_BASE: _N910F("SRC_IP_CITY"),
    103 + NTOP_BASE: _N910F("DST_IP_COUNTRY"),
    104 + NTOP_BASE: _N910F("DST_IP_CITY"),
    105 + NTOP_BASE: _N910F("FLOW_PROTO_PORT"),
    106 + NTOP_BASE: _N910F("UPSTREAM_TUNNEL_ID"),
    107 + NTOP_BASE: _N910F("LONGEST_FLOW_PKT"),
    108 + NTOP_BASE: _N910F("SHORTEST_FLOW_PKT"),
    109 + NTOP_BASE: _N910F("RETRANSMITTED_IN_PKTS"),
    110 + NTOP_BASE: _N910F("RETRANSMITTED_OUT_PKTS"),
    111 + NTOP_BASE: _N910F("OOORDER_IN_PKTS"),
    112 + NTOP_BASE: _N910F("OOORDER_OUT_PKTS"),
    113 + NTOP_BASE: _N910F("UNTUNNELED_PROTOCOL"),
    114 + NTOP_BASE: _N910F("UNTUNNELED_IPV4_SRC_ADDR", length=4,
                            field=IPField),
    115 + NTOP_BASE: _N910F("UNTUNNELED_L4_SRC_PORT"),
    116 + NTOP_BASE: _N910F("UNTUNNELED_IPV4_DST_ADDR", length=4,
                            field=IPField),
    117 + NTOP_BASE: _N910F("UNTUNNELED_L4_DST_PORT"),
    118 + NTOP_BASE: _N910F("L7_PROTO"),
    119 + NTOP_BASE: _N910F("L7_PROTO_NAME"),
    120 + NTOP_BASE: _N910F("DOWNSTREAM_TUNNEL_ID"),
    121 + NTOP_BASE: _N910F("FLOW_USER_NAME"),
    122 + NTOP_BASE: _N910F("FLOW_SERVER_NAME"),
    123 + NTOP_BASE: _N910F("CLIENT_NW_LATENCY_MS"),
    124 + NTOP_BASE: _N910F("SERVER_NW_LATENCY_MS"),
    125 + NTOP_BASE: _N910F("APPL_LATENCY_MS"),
    126 + NTOP_BASE: _N910F("PLUGIN_NAME"),
    127 + NTOP_BASE: _N910F("RETRANSMITTED_IN_BYTES"),
    128 + NTOP_BASE: _N910F("RETRANSMITTED_OUT_BYTES"),
    130 + NTOP_BASE: _N910F("SIP_CALL_ID"),
    131 + NTOP_BASE: _N910F("SIP_CALLING_PARTY"),
    132 + NTOP_BASE: _N910F("SIP_CALLED_PARTY"),
    133 + NTOP_BASE: _N910F("SIP_RTP_CODECS"),
    134 + NTOP_BASE: _N910F("SIP_INVITE_TIME"),
    135 + NTOP_BASE: _N910F("SIP_TRYING_TIME"),
    136 + NTOP_BASE: _N910F("SIP_RINGING_TIME"),
    137 + NTOP_BASE: _N910F("SIP_INVITE_OK_TIME"),
    138 + NTOP_BASE: _N910F("SIP_INVITE_FAILURE_TIME"),
    139 + NTOP_BASE: _N910F("SIP_BYE_TIME"),
    140 + NTOP_BASE: _N910F("SIP_BYE_OK_TIME"),
    141 + NTOP_BASE: _N910F("SIP_CANCEL_TIME"),
    142 + NTOP_BASE: _N910F("SIP_CANCEL_OK_TIME"),
    143 + NTOP_BASE: _N910F("SIP_RTP_IPV4_SRC_ADDR", length=4,
                            field=IPField),
    144 + NTOP_BASE: _N910F("SIP_RTP_L4_SRC_PORT"),
    145 + NTOP_BASE: _N910F("SIP_RTP_IPV4_DST_ADDR", length=4,
                            field=IPField),
    146 + NTOP_BASE: _N910F("SIP_RTP_L4_DST_PORT"),
    147 + NTOP_BASE: _N910F("SIP_RESPONSE_CODE"),
    148 + NTOP_BASE: _N910F("SIP_REASON_CAUSE"),
    150 + NTOP_BASE: _N910F("RTP_FIRST_SEQ"),
    151 + NTOP_BASE: _N910F("RTP_FIRST_TS"),
    152 + NTOP_BASE: _N910F("RTP_LAST_SEQ"),
    153 + NTOP_BASE: _N910F("RTP_LAST_TS"),
    154 + NTOP_BASE: _N910F("RTP_IN_JITTER"),
    155 + NTOP_BASE: _N910F("RTP_OUT_JITTER"),
    156 + NTOP_BASE: _N910F("RTP_IN_PKT_LOST"),
    157 + NTOP_BASE: _N910F("RTP_OUT_PKT_LOST"),
    158 + NTOP_BASE: _N910F("RTP_OUT_PAYLOAD_TYPE"),
    159 + NTOP_BASE: _N910F("RTP_IN_MAX_DELTA"),
    160 + NTOP_BASE: _N910F("RTP_OUT_MAX_DELTA"),
    161 + NTOP_BASE: _N910F("RTP_IN_PAYLOAD_TYPE"),
    168 + NTOP_BASE: _N910F("SRC_PROC_PID"),
    169 + NTOP_BASE: _N910F("SRC_PROC_NAME"),
    180 + NTOP_BASE: _N910F("HTTP_URL"),
    181 + NTOP_BASE: _N910F("HTTP_RET_CODE"),
    182 + NTOP_BASE: _N910F("HTTP_REFERER"),
    183 + NTOP_BASE: _N910F("HTTP_UA"),
    184 + NTOP_BASE: _N910F("HTTP_MIME"),
    185 + NTOP_BASE: _N910F("SMTP_MAIL_FROM"),
    186 + NTOP_BASE: _N910F("SMTP_RCPT_TO"),
    187 + NTOP_BASE: _N910F("HTTP_HOST"),
    188 + NTOP_BASE: _N910F("SSL_SERVER_NAME"),
    189 + NTOP_BASE: _N910F("BITTORRENT_HASH"),
    195 + NTOP_BASE: _N910F("MYSQL_SRV_VERSION"),
    196 + NTOP_BASE: _N910F("MYSQL_USERNAME"),
    197 + NTOP_BASE: _N910F("MYSQL_DB"),
    198 + NTOP_BASE: _N910F("MYSQL_QUERY"),
    199 + NTOP_BASE: _N910F("MYSQL_RESPONSE"),
    200 + NTOP_BASE: _N910F("ORACLE_USERNAME"),
    201 + NTOP_BASE: _N910F("ORACLE_QUERY"),
    202 + NTOP_BASE: _N910F("ORACLE_RSP_CODE"),
    203 + NTOP_BASE: _N910F("ORACLE_RSP_STRING"),
    204 + NTOP_BASE: _N910F("ORACLE_QUERY_DURATION"),
    205 + NTOP_BASE: _N910F("DNS_QUERY"),
    206 + NTOP_BASE: _N910F("DNS_QUERY_ID"),
    207 + NTOP_BASE: _N910F("DNS_QUERY_TYPE"),
    208 + NTOP_BASE: _N910F("DNS_RET_CODE"),
    209 + NTOP_BASE: _N910F("DNS_NUM_ANSWERS"),
    210 + NTOP_BASE: _N910F("POP_USER"),
    220 + NTOP_BASE: _N910F("GTPV1_REQ_MSG_TYPE"),
    221 + NTOP_BASE: _N910F("GTPV1_RSP_MSG_TYPE"),
    222 + NTOP_BASE: _N910F("GTPV1_C2S_TEID_DATA"),
    223 + NTOP_BASE: _N910F("GTPV1_C2S_TEID_CTRL"),
    224 + NTOP_BASE: _N910F("GTPV1_S2C_TEID_DATA"),
    225 + NTOP_BASE: _N910F("GTPV1_S2C_TEID_CTRL"),
    226 + NTOP_BASE: _N910F("GTPV1_END_USER_IP"),
    227 + NTOP_BASE: _N910F("GTPV1_END_USER_IMSI"),
    228 + NTOP_BASE: _N910F("GTPV1_END_USER_MSISDN"),
    229 + NTOP_BASE: _N910F("GTPV1_END_USER_IMEI"),
    230 + NTOP_BASE: _N910F("GTPV1_APN_NAME"),
    231 + NTOP_BASE: _N910F("GTPV1_RAI_MCC"),
    232 + NTOP_BASE: _N910F("GTPV1_RAI_MNC"),
    233 + NTOP_BASE: _N910F("GTPV1_ULI_CELL_LAC"),
    234 + NTOP_BASE: _N910F("GTPV1_ULI_CELL_CI"),
    235 + NTOP_BASE: _N910F("GTPV1_ULI_SAC"),
    236 + NTOP_BASE: _N910F("GTPV1_RAT_TYPE"),
    240 + NTOP_BASE: _N910F("RADIUS_REQ_MSG_TYPE"),
    241 + NTOP_BASE: _N910F("RADIUS_RSP_MSG_TYPE"),
    242 + NTOP_BASE: _N910F("RADIUS_USER_NAME"),
    243 + NTOP_BASE: _N910F("RADIUS_CALLING_STATION_ID"),
    244 + NTOP_BASE: _N910F("RADIUS_CALLED_STATION_ID"),
    245 + NTOP_BASE: _N910F("RADIUS_NAS_IP_ADDR"),
    246 + NTOP_BASE: _N910F("RADIUS_NAS_IDENTIFIER"),
    247 + NTOP_BASE: _N910F("RADIUS_USER_IMSI"),
    248 + NTOP_BASE: _N910F("RADIUS_USER_IMEI"),
    249 + NTOP_BASE: _N910F("RADIUS_FRAMED_IP_ADDR"),
    250 + NTOP_BASE: _N910F("RADIUS_ACCT_SESSION_ID"),
    251 + NTOP_BASE: _N910F("RADIUS_ACCT_STATUS_TYPE"),
    252 + NTOP_BASE: _N910F("RADIUS_ACCT_IN_OCTETS"),
    253 + NTOP_BASE: _N910F("RADIUS_ACCT_OUT_OCTETS"),
    254 + NTOP_BASE: _N910F("RADIUS_ACCT_IN_PKTS"),
    255 + NTOP_BASE: _N910F("RADIUS_ACCT_OUT_PKTS"),
    260 + NTOP_BASE: _N910F("IMAP_LOGIN"),
    270 + NTOP_BASE: _N910F("GTPV2_REQ_MSG_TYPE"),
    271 + NTOP_BASE: _N910F("GTPV2_RSP_MSG_TYPE"),
    272 + NTOP_BASE: _N910F("GTPV2_C2S_S1U_GTPU_TEID"),
    273 + NTOP_BASE: _N910F("GTPV2_C2S_S1U_GTPU_IP"),
    274 + NTOP_BASE: _N910F("GTPV2_S2C_S1U_GTPU_TEID"),
    275 + NTOP_BASE: _N910F("GTPV2_S2C_S1U_GTPU_IP"),
    276 + NTOP_BASE: _N910F("GTPV2_END_USER_IMSI"),
    277 + NTOP_BASE: _N910F("GTPV2_END_USER_MSISDN"),
    278 + NTOP_BASE: _N910F("GTPV2_APN_NAME"),
    279 + NTOP_BASE: _N910F("GTPV2_ULI_MCC"),
    280 + NTOP_BASE: _N910F("GTPV2_ULI_MNC"),
    281 + NTOP_BASE: _N910F("GTPV2_ULI_CELL_TAC"),
    282 + NTOP_BASE: _N910F("GTPV2_ULI_CELL_ID"),
    283 + NTOP_BASE: _N910F("GTPV2_RAT_TYPE"),
    284 + NTOP_BASE: _N910F("GTPV2_PDN_IP"),
    285 + NTOP_BASE: _N910F("GTPV2_END_USER_IMEI"),
    290 + NTOP_BASE: _N910F("SRC_AS_PATH_1"),
    291 + NTOP_BASE: _N910F("SRC_AS_PATH_2"),
    292 + NTOP_BASE: _N910F("SRC_AS_PATH_3"),
    293 + NTOP_BASE: _N910F("SRC_AS_PATH_4"),
    294 + NTOP_BASE: _N910F("SRC_AS_PATH_5"),
    295 + NTOP_BASE: _N910F("SRC_AS_PATH_6"),
    296 + NTOP_BASE: _N910F("SRC_AS_PATH_7"),
    297 + NTOP_BASE: _N910F("SRC_AS_PATH_8"),
    298 + NTOP_BASE: _N910F("SRC_AS_PATH_9"),
    299 + NTOP_BASE: _N910F("SRC_AS_PATH_10"),
    300 + NTOP_BASE: _N910F("DST_AS_PATH_1"),
    301 + NTOP_BASE: _N910F("DST_AS_PATH_2"),
    302 + NTOP_BASE: _N910F("DST_AS_PATH_3"),
    303 + NTOP_BASE: _N910F("DST_AS_PATH_4"),
    304 + NTOP_BASE: _N910F("DST_AS_PATH_5"),
    305 + NTOP_BASE: _N910F("DST_AS_PATH_6"),
    306 + NTOP_BASE: _N910F("DST_AS_PATH_7"),
    307 + NTOP_BASE: _N910F("DST_AS_PATH_8"),
    308 + NTOP_BASE: _N910F("DST_AS_PATH_9"),
    309 + NTOP_BASE: _N910F("DST_AS_PATH_10"),
    320 + NTOP_BASE: _N910F("MYSQL_APPL_LATENCY_USEC"),
    321 + NTOP_BASE: _N910F("GTPV0_REQ_MSG_TYPE"),
    322 + NTOP_BASE: _N910F("GTPV0_RSP_MSG_TYPE"),
    323 + NTOP_BASE: _N910F("GTPV0_TID"),
    324 + NTOP_BASE: _N910F("GTPV0_END_USER_IP"),
    325 + NTOP_BASE: _N910F("GTPV0_END_USER_MSISDN"),
    326 + NTOP_BASE: _N910F("GTPV0_APN_NAME"),
    327 + NTOP_BASE: _N910F("GTPV0_RAI_MCC"),
    328 + NTOP_BASE: _N910F("GTPV0_RAI_MNC"),
    329 + NTOP_BASE: _N910F("GTPV0_RAI_CELL_LAC"),
    330 + NTOP_BASE: _N910F("GTPV0_RAI_CELL_RAC"),
    331 + NTOP_BASE: _N910F("GTPV0_RESPONSE_CAUSE"),
    332 + NTOP_BASE: _N910F("GTPV1_RESPONSE_CAUSE"),
    333 + NTOP_BASE: _N910F("GTPV2_RESPONSE_CAUSE"),
    334 + NTOP_BASE: _N910F("NUM_PKTS_TTL_5_32"),
    335 + NTOP_BASE: _N910F("NUM_PKTS_TTL_32_64"),
    336 + NTOP_BASE: _N910F("NUM_PKTS_TTL_64_96"),
    337 + NTOP_BASE: _N910F("NUM_PKTS_TTL_96_128"),
    338 + NTOP_BASE: _N910F("NUM_PKTS_TTL_128_160"),
    339 + NTOP_BASE: _N910F("NUM_PKTS_TTL_160_192"),
    340 + NTOP_BASE: _N910F("NUM_PKTS_TTL_192_224"),
    341 + NTOP_BASE: _N910F("NUM_PKTS_TTL_224_255"),
    342 + NTOP_BASE: _N910F("GTPV1_RAI_LAC"),
    343 + NTOP_BASE: _N910F("GTPV1_RAI_RAC"),
    344 + NTOP_BASE: _N910F("GTPV1_ULI_MCC"),
    345 + NTOP_BASE: _N910F("GTPV1_ULI_MNC"),
    346 + NTOP_BASE: _N910F("NUM_PKTS_TTL_2_5"),
    347 + NTOP_BASE: _N910F("NUM_PKTS_TTL_EQ_1"),
    348 + NTOP_BASE: _N910F("RTP_SIP_CALL_ID"),
    349 + NTOP_BASE: _N910F("IN_SRC_OSI_SAP"),
    350 + NTOP_BASE: _N910F("OUT_DST_OSI_SAP"),
    351 + NTOP_BASE: _N910F("WHOIS_DAS_DOMAIN"),
    352 + NTOP_BASE: _N910F("DNS_TTL_ANSWER"),
    353 + NTOP_BASE: _N910F("DHCP_CLIENT_MAC", length=6,
                            field=MACField),
    354 + NTOP_BASE: _N910F("DHCP_CLIENT_IP", length=4,
                            field=IPField),
    355 + NTOP_BASE: _N910F("DHCP_CLIENT_NAME"),
    356 + NTOP_BASE: _N910F("FTP_LOGIN"),
    357 + NTOP_BASE: _N910F("FTP_PASSWORD"),
    358 + NTOP_BASE: _N910F("FTP_COMMAND"),
    359 + NTOP_BASE: _N910F("FTP_COMMAND_RET_CODE"),
    360 + NTOP_BASE: _N910F("HTTP_METHOD"),
    361 + NTOP_BASE: _N910F("HTTP_SITE"),
    362 + NTOP_BASE: _N910F("SIP_C_IP"),
    363 + NTOP_BASE: _N910F("SIP_CALL_STATE"),
    364 + NTOP_BASE: _N910F("EPP_REGISTRAR_NAME"),
    365 + NTOP_BASE: _N910F("EPP_CMD"),
    366 + NTOP_BASE: _N910F("EPP_CMD_ARGS"),
    367 + NTOP_BASE: _N910F("EPP_RSP_CODE"),
    368 + NTOP_BASE: _N910F("EPP_REASON_STR"),
    369 + NTOP_BASE: _N910F("EPP_SERVER_NAME"),
    370 + NTOP_BASE: _N910F("RTP_IN_MOS"),
    371 + NTOP_BASE: _N910F("RTP_IN_R_FACTOR"),
    372 + NTOP_BASE: _N910F("SRC_PROC_USER_NAME"),
    373 + NTOP_BASE: _N910F("SRC_FATHER_PROC_PID"),
    374 + NTOP_BASE: _N910F("SRC_FATHER_PROC_NAME"),
    375 + NTOP_BASE: _N910F("DST_PROC_PID"),
    376 + NTOP_BASE: _N910F("DST_PROC_NAME"),
    377 + NTOP_BASE: _N910F("DST_PROC_USER_NAME"),
    378 + NTOP_BASE: _N910F("DST_FATHER_PROC_PID"),
    379 + NTOP_BASE: _N910F("DST_FATHER_PROC_NAME"),
    380 + NTOP_BASE: _N910F("RTP_RTT"),
    381 + NTOP_BASE: _N910F("RTP_IN_TRANSIT"),
    382 + NTOP_BASE: _N910F("RTP_OUT_TRANSIT"),
    383 + NTOP_BASE: _N910F("SRC_PROC_ACTUAL_MEMORY"),
    384 + NTOP_BASE: _N910F("SRC_PROC_PEAK_MEMORY"),
    385 + NTOP_BASE: _N910F("SRC_PROC_AVERAGE_CPU_LOAD"),
    386 + NTOP_BASE: _N910F("SRC_PROC_NUM_PAGE_FAULTS"),
    387 + NTOP_BASE: _N910F("DST_PROC_ACTUAL_MEMORY"),
    388 + NTOP_BASE: _N910F("DST_PROC_PEAK_MEMORY"),
    389 + NTOP_BASE: _N910F("DST_PROC_AVERAGE_CPU_LOAD"),
    390 + NTOP_BASE: _N910F("DST_PROC_NUM_PAGE_FAULTS"),
    391 + NTOP_BASE: _N910F("DURATION_IN"),
    392 + NTOP_BASE: _N910F("DURATION_OUT"),
    393 + NTOP_BASE: _N910F("SRC_PROC_PCTG_IOWAIT"),
    394 + NTOP_BASE: _N910F("DST_PROC_PCTG_IOWAIT"),
    395 + NTOP_BASE: _N910F("RTP_DTMF_TONES"),
    396 + NTOP_BASE: _N910F("UNTUNNELED_IPV6_SRC_ADDR", length=16,
                            field=IP6Field),
    397 + NTOP_BASE: _N910F("UNTUNNELED_IPV6_DST_ADDR", length=16,
                            field=IP6Field),
    398 + NTOP_BASE: _N910F("DNS_RESPONSE"),
    399 + NTOP_BASE: _N910F("DIAMETER_REQ_MSG_TYPE"),
    400 + NTOP_BASE: _N910F("DIAMETER_RSP_MSG_TYPE"),
    401 + NTOP_BASE: _N910F("DIAMETER_REQ_ORIGIN_HOST"),
    402 + NTOP_BASE: _N910F("DIAMETER_RSP_ORIGIN_HOST"),
    403 + NTOP_BASE: _N910F("DIAMETER_REQ_USER_NAME"),
    404 + NTOP_BASE: _N910F("DIAMETER_RSP_RESULT_CODE"),
    405 + NTOP_BASE: _N910F("DIAMETER_EXP_RES_VENDOR_ID"),
    406 + NTOP_BASE: _N910F("DIAMETER_EXP_RES_RESULT_CODE"),
    407 + NTOP_BASE: _N910F("S1AP_ENB_UE_S1AP_ID"),
    408 + NTOP_BASE: _N910F("S1AP_MME_UE_S1AP_ID"),
    409 + NTOP_BASE: _N910F("S1AP_MSG_EMM_TYPE_MME_TO_ENB"),
    410 + NTOP_BASE: _N910F("S1AP_MSG_ESM_TYPE_MME_TO_ENB"),
    411 + NTOP_BASE: _N910F("S1AP_MSG_EMM_TYPE_ENB_TO_MME"),
    412 + NTOP_BASE: _N910F("S1AP_MSG_ESM_TYPE_ENB_TO_MME"),
    413 + NTOP_BASE: _N910F("S1AP_CAUSE_ENB_TO_MME"),
    414 + NTOP_BASE: _N910F("S1AP_DETAILED_CAUSE_ENB_TO_MME"),
    415 + NTOP_BASE: _N910F("TCP_WIN_MIN_IN"),
    416 + NTOP_BASE: _N910F("TCP_WIN_MAX_IN"),
    417 + NTOP_BASE: _N910F("TCP_WIN_MSS_IN"),
    418 + NTOP_BASE: _N910F("TCP_WIN_SCALE_IN"),
    419 + NTOP_BASE: _N910F("TCP_WIN_MIN_OUT"),
    420 + NTOP_BASE: _N910F("TCP_WIN_MAX_OUT"),
    421 + NTOP_BASE: _N910F("TCP_WIN_MSS_OUT"),
    422 + NTOP_BASE: _N910F("TCP_WIN_SCALE_OUT"),
    423 + NTOP_BASE: _N910F("DHCP_REMOTE_ID"),
    424 + NTOP_BASE: _N910F("DHCP_SUBSCRIBER_ID"),
    425 + NTOP_BASE: _N910F("SRC_PROC_UID"),
    426 + NTOP_BASE: _N910F("DST_PROC_UID"),
    427 + NTOP_BASE: _N910F("APPLICATION_NAME"),
    428 + NTOP_BASE: _N910F("USER_NAME"),
    429 + NTOP_BASE: _N910F("DHCP_MESSAGE_TYPE"),
    430 + NTOP_BASE: _N910F("RTP_IN_PKT_DROP"),
    431 + NTOP_BASE: _N910F("RTP_OUT_PKT_DROP"),
    432 + NTOP_BASE: _N910F("RTP_OUT_MOS"),
    433 + NTOP_BASE: _N910F("RTP_OUT_R_FACTOR"),
    434 + NTOP_BASE: _N910F("RTP_MOS"),
    435 + NTOP_BASE: _N910F("GTPV2_S5_S8_GTPC_TEID"),
    436 + NTOP_BASE: _N910F("RTP_R_FACTOR"),
    437 + NTOP_BASE: _N910F("RTP_SSRC"),
    438 + NTOP_BASE: _N910F("PAYLOAD_HASH"),
    439 + NTOP_BASE: _N910F("GTPV2_C2S_S5_S8_GTPU_TEID"),
    440 + NTOP_BASE: _N910F("GTPV2_S2C_S5_S8_GTPU_TEID"),
    441 + NTOP_BASE: _N910F("GTPV2_C2S_S5_S8_GTPU_IP"),
    442 + NTOP_BASE: _N910F("GTPV2_S2C_S5_S8_GTPU_IP"),
    443 + NTOP_BASE: _N910F("SRC_AS_MAP"),
    444 + NTOP_BASE: _N910F("DST_AS_MAP"),
    445 + NTOP_BASE: _N910F("DIAMETER_HOP_BY_HOP_ID"),
    446 + NTOP_BASE: _N910F("UPSTREAM_SESSION_ID"),
    447 + NTOP_BASE: _N910F("DOWNSTREAM_SESSION_ID"),
    448 + NTOP_BASE: _N910F("SRC_IP_LONG"),
    449 + NTOP_BASE: _N910F("SRC_IP_LAT"),
    450 + NTOP_BASE: _N910F("DST_IP_LONG"),
    451 + NTOP_BASE: _N910F("DST_IP_LAT"),
    452 + NTOP_BASE: _N910F("DIAMETER_CLR_CANCEL_TYPE"),
    453 + NTOP_BASE: _N910F("DIAMETER_CLR_FLAGS"),
    454 + NTOP_BASE: _N910F("GTPV2_C2S_S5_S8_GTPC_IP"),
    455 + NTOP_BASE: _N910F("GTPV2_S2C_S5_S8_GTPC_IP"),
    456 + NTOP_BASE: _N910F("GTPV2_C2S_S5_S8_SGW_GTPU_TEID"),
    457 + NTOP_BASE: _N910F("GTPV2_S2C_S5_S8_SGW_GTPU_TEID"),
    458 + NTOP_BASE: _N910F("GTPV2_C2S_S5_S8_SGW_GTPU_IP"),
    459 + NTOP_BASE: _N910F("GTPV2_S2C_S5_S8_SGW_GTPU_IP"),
    460 + NTOP_BASE: _N910F("HTTP_X_FORWARDED_FOR"),
    461 + NTOP_BASE: _N910F("HTTP_VIA"),
    462 + NTOP_BASE: _N910F("SSDP_HOST"),
    463 + NTOP_BASE: _N910F("SSDP_USN"),
    464 + NTOP_BASE: _N910F("NETBIOS_QUERY_NAME"),
    465 + NTOP_BASE: _N910F("NETBIOS_QUERY_TYPE"),
    466 + NTOP_BASE: _N910F("NETBIOS_RESPONSE"),
    467 + NTOP_BASE: _N910F("NETBIOS_QUERY_OS"),
    468 + NTOP_BASE: _N910F("SSDP_SERVER"),
    469 + NTOP_BASE: _N910F("SSDP_TYPE"),
    470 + NTOP_BASE: _N910F("SSDP_METHOD"),
    471 + NTOP_BASE: _N910F("NPROBE_IPV4_ADDRESS", length=4,
                            field=IPField),
}
NetflowV910TemplateFieldTypes = {
    k: v.name for k, v in NetflowV910TemplateFields.items()
}

ScopeFieldTypes = {
    1: "System",
    2: "Interface",
    3: "Line card",
    4: "Cache",
    5: "Template",
}


class NetflowHeaderV9(Packet):
    name = "Netflow Header V9"
    fields_desc = [ShortField("count", None),
                   IntField("sysUptime", 0),
                   UTCTimeField("unixSecs", None),
                   IntField("packageSequence", 0),
                   IntField("SourceID", 0)]

    def post_build(self, pkt, pay):

        def count_by_layer(layer):
            if type(layer) == NetflowFlowsetV9:
                return len(layer.templates)
            elif type(layer) == NetflowDataflowsetV9:
                return len(layer.records)
            elif type(layer) == NetflowOptionsFlowsetV9:
                return 1
            else:
                return 0

        if self.count is None:
            # https://www.rfc-editor.org/rfc/rfc3954#section-5.1
            count = sum(
                sum(count_by_layer(self.getlayer(layer_cls, nth))
                    for nth in range(1, n + 1))
                for layer_cls, n in Counter(self.layers()).items()
            )
            pkt = struct.pack("!H", count) + pkt[2:]
        return pkt + pay


# https://tools.ietf.org/html/rfc5655#appendix-B.1.1
class NetflowHeaderV10(Packet):
    """IPFix (Netflow V10) Header"""
    name = "IPFix (Netflow V10) Header"
    fields_desc = [ShortField("length", None),
                   UTCTimeField("ExportTime", 0),
                   IntField("flowSequence", 0),
                   IntField("ObservationDomainID", 0)]

    def post_build(self, pkt, pay):
        if self.length is None:
            length = len(pkt) + len(pay)
            pkt = struct.pack("!H", length) + pkt[2:]
        return pkt + pay


class NetflowTemplateFieldV9(Packet):
    name = "Netflow Flowset Template Field V9/10"
    fields_desc = [BitField("enterpriseBit", 0, 1),
                   BitEnumField("fieldType", None, 15,
                                NetflowV910TemplateFieldTypes),
                   ShortField("fieldLength", None),
                   ConditionalField(IntField("enterpriseNumber", 0),
                                    lambda p: p.enterpriseBit)]

    def __init__(self, *args, **kwargs):
        Packet.__init__(self, *args, **kwargs)
        if (self.fieldType is not None and
                self.fieldLength is None and
                self.fieldType in NetflowV910TemplateFields):
            self.fieldLength = NetflowV910TemplateFields[
                self.fieldType
            ].length or None

    def default_payload_class(self, p):
        return conf.padding_layer


class NetflowTemplateV9(Packet):
    name = "Netflow Flowset Template V9/10"
    fields_desc = [ShortField("templateID", 255),
                   FieldLenField("fieldCount", None, count_of="template_fields"),  # noqa: E501
                   PacketListField("template_fields", [], NetflowTemplateFieldV9,  # noqa: E501
                                   count_from=lambda pkt: pkt.fieldCount)]

    def default_payload_class(self, p):
        return conf.padding_layer


class NetflowFlowsetV9(Packet):
    name = "Netflow FlowSet V9/10"
    fields_desc = [ShortField("flowSetID", 0),
                   FieldLenField("length", None, length_of="templates",
                                 adjust=lambda pkt, x:x + 4),
                   PacketListField("templates", [], NetflowTemplateV9,
                                   length_from=lambda pkt: pkt.length - 4)]


class _CustomStrFixedLenField(StrFixedLenField):
    def i2repr(self, pkt, v):
        return repr(v)


def _GenNetflowRecordV9(cls, lengths_list):
    """Internal function used to generate the Records from
    their template.
    """
    _fields_desc = []
    for j, k in lengths_list:
        _f_type = None
        _f_kwargs = {}
        if k in NetflowV910TemplateFields:
            _f = NetflowV910TemplateFields[k]
            _f_type = _f.field
            _f_kwargs = _f.kwargs

        if _f_type:
            if issubclass(_f_type, _AdjustableNetflowField):
                _f_kwargs["length"] = j
            print(k, _f_kwargs)
            _fields_desc.append(
                _f_type(
                    NetflowV910TemplateFieldTypes.get(k, "unknown_data"),
                    0, **_f_kwargs
                )
            )
        else:
            _fields_desc.append(
                _CustomStrFixedLenField(
                    NetflowV910TemplateFieldTypes.get(k, "unknown_data"),
                    b"", length=j
                )
            )

    # This will act exactly like a NetflowRecordV9, but has custom fields
    class NetflowRecordV9I(cls):
        fields_desc = _fields_desc
        match_subclass = True
    NetflowRecordV9I.name = cls.name
    NetflowRecordV9I.__name__ = cls.__name__
    return NetflowRecordV9I


def GetNetflowRecordV9(flowset, templateID=None):
    """
    Get a NetflowRecordV9/10 for a specific NetflowFlowsetV9/10.

    Have a look at the online doc for examples.
    """
    definitions = {}
    for ntv9 in flowset.templates:
        llist = []
        for tmpl in ntv9.template_fields:
            llist.append((tmpl.fieldLength, tmpl.fieldType))
        if llist:
            cls = _GenNetflowRecordV9(NetflowRecordV9, llist)
            definitions[ntv9.templateID] = cls
    if not definitions:
        raise Scapy_Exception(
            "No template IDs detected"
        )
    if len(definitions) > 1:
        if templateID is None:
            raise Scapy_Exception(
                "Multiple possible templates ! Specify templateID=.."
            )
        return definitions[templateID]
    else:
        return list(definitions.values())[0]


class NetflowRecordV9(Packet):
    name = "Netflow DataFlowset Record V9/10"
    fields_desc = [StrField("fieldValue", "")]

    def default_payload_class(self, p):
        return conf.padding_layer


class NetflowDataflowsetV9(Packet):
    name = "Netflow DataFlowSet V9/10"
    fields_desc = [ShortField("templateID", 255),
                   ShortField("length", None),
                   PacketListField(
                       "records", [],
                       NetflowRecordV9,
                       length_from=lambda pkt: pkt.length - 4)]

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt:
            # https://tools.ietf.org/html/rfc5655#appendix-B.1.2
            # NetflowV9
            if _pkt[:2] == b"\x00\x00":
                return NetflowFlowsetV9
            if _pkt[:2] == b"\x00\x01":
                return NetflowOptionsFlowsetV9
            # IPFix
            if _pkt[:2] == b"\x00\x02":
                return NetflowFlowsetV9
            if _pkt[:2] == b"\x00\x03":
                return NetflowOptionsFlowset10
        return cls

    def post_build(self, pkt, pay):
        if self.length is None:
            # Padding is optional, let's apply it on build
            length = len(pkt)
            pad = (-length) % 4
            pkt = pkt[:2] + struct.pack("!H", length + pad) + pkt[4:]
            pkt += b"\x00" * pad
        return pkt + pay


def _netflowv9_defragment_packet(pkt, definitions, definitions_opts, ignored):
    """Used internally to process a single packet during defragmenting"""
    # Dataflowset definitions
    if NetflowFlowsetV9 in pkt:
        current = pkt
        while NetflowFlowsetV9 in current:
            current = current[NetflowFlowsetV9]
            for ntv9 in current.templates:
                llist = []
                for tmpl in ntv9.template_fields:
                    llist.append((tmpl.fieldLength, tmpl.fieldType))
                if llist:
                    tot_len = sum(x[0] for x in llist)
                    cls = _GenNetflowRecordV9(NetflowRecordV9, llist)
                    definitions[ntv9.templateID] = (tot_len, cls)
            current = current.payload
    # Options definitions
    if NetflowOptionsFlowsetV9 in pkt:
        current = pkt
        while NetflowOptionsFlowsetV9 in current:
            current = current[NetflowOptionsFlowsetV9]
            # Load scopes
            llist = []
            for scope in current.scopes:
                llist.append((
                    scope.scopeFieldlength,
                    scope.scopeFieldType
                ))
            scope_tot_len = sum(x[0] for x in llist)
            scope_cls = _GenNetflowRecordV9(
                NetflowOptionsRecordScopeV9,
                llist
            )
            # Load options
            llist = []
            for opt in current.options:
                llist.append((
                    opt.optionFieldlength,
                    opt.optionFieldType
                ))
            option_tot_len = sum(x[0] for x in llist)
            option_cls = _GenNetflowRecordV9(
                NetflowOptionsRecordOptionV9,
                llist
            )
            # Storage
            definitions_opts[current.templateID] = (
                scope_tot_len, scope_cls,
                option_tot_len, option_cls
            )
            current = current.payload
    # Dissect flowsets
    if NetflowDataflowsetV9 in pkt:
        current = pkt
        while NetflowDataflowsetV9 in current:
            datafl = current[NetflowDataflowsetV9]
            tid = datafl.templateID
            if tid not in definitions and tid not in definitions_opts:
                ignored.add(tid)
                return
            # All data is stored in one record, awaiting to be split
            # If fieldValue is available, the record has not been
            # defragmented: pop it
            try:
                data = datafl.records[0].fieldValue
                datafl.records.pop(0)
            except (IndexError, AttributeError):
                return
            res = []
            # Flowset record
            # Now, according to the flow/option data,
            # let's re-dissect NetflowDataflowsetV9
            if tid in definitions:
                tot_len, cls = definitions[tid]
                while len(data) >= tot_len:
                    res.append(cls(data[:tot_len]))
                    data = data[tot_len:]
                # Inject dissected data
                datafl.records = res
                if data:
                    if len(data) <= 4:
                        datafl.add_payload(conf.padding_layer(data))
                    else:
                        datafl.do_dissect_payload(data)
            # Options
            elif tid in definitions_opts:
                (scope_len, scope_cls,
                    option_len, option_cls) = definitions_opts[tid]
                # Dissect scopes
                if scope_len:
                    res.append(scope_cls(data[:scope_len]))
                if option_len:
                    res.append(
                        option_cls(data[scope_len:scope_len + option_len])
                    )
                if len(data) > scope_len + option_len:
                    res.append(
                        conf.padding_layer(data[scope_len + option_len:])
                    )
                # Inject dissected data
                datafl.records = res
                datafl.name = "Netflow DataFlowSet V9/10 - OPTIONS"
            current = datafl.payload


def netflowv9_defragment(plist, verb=1):
    """Process all NetflowV9/10 Packets to match IDs of the DataFlowsets
    with the Headers

    params:
     - plist: the list of mixed NetflowV9/10 packets.
     - verb: verbose print (0/1)
    """
    if not isinstance(plist, (PacketList, list)):
        plist = [plist]
    # We need the whole packet to be dissected to access field def in
    # NetflowFlowsetV9 or NetflowOptionsFlowsetV9/10
    definitions = {}
    definitions_opts = {}
    ignored = set()
    # Iterate through initial list
    for pkt in plist:
        _netflowv9_defragment_packet(pkt,
                                     definitions,
                                     definitions_opts,
                                     ignored)
    if conf.verb >= 1 and ignored:
        warning("Ignored templateIDs (missing): %s" % list(ignored))
    return plist


def ipfix_defragment(*args, **kwargs):
    """Alias for netflowv9_defragment"""
    return netflowv9_defragment(*args, **kwargs)


class NetflowSession(IPSession):
    """Session used to defragment NetflowV9/10 packets on the flow.
    See help(scapy.layers.netflow) for more infos.
    """
    def __init__(self, *args, **kwargs):
        self.definitions = {}
        self.definitions_opts = {}
        self.ignored = set()
        super(NetflowSession, self).__init__(*args, **kwargs)

    def process(self, pkt: Packet) -> Optional[Packet]:
        pkt = super(NetflowSession, self).process(pkt)
        if not pkt:
            return
        _netflowv9_defragment_packet(pkt,
                                     self.definitions,
                                     self.definitions_opts,
                                     self.ignored)
        return pkt


class NetflowOptionsRecordScopeV9(NetflowRecordV9):
    name = "Netflow Options Template Record V9/10 - Scope"


class NetflowOptionsRecordOptionV9(NetflowRecordV9):
    name = "Netflow Options Template Record V9/10 - Option"


# Aka Set
class NetflowOptionsFlowsetOptionV9(Packet):
    name = "Netflow Options Template FlowSet V9/10 - Option"
    fields_desc = [BitField("enterpriseBit", 0, 1),
                   BitEnumField("optionFieldType", None, 15,
                                NetflowV910TemplateFieldTypes),
                   ShortField("optionFieldlength", 0),
                   ConditionalField(ShortField("enterpriseNumber", 0),
                                    lambda p: p.enterpriseBit)]

    def default_payload_class(self, p):
        return conf.padding_layer


# Aka Set
class NetflowOptionsFlowsetScopeV9(Packet):
    name = "Netflow Options Template FlowSet V9/10 - Scope"
    fields_desc = [ShortEnumField("scopeFieldType", None, ScopeFieldTypes),
                   ShortField("scopeFieldlength", 0)]

    def default_payload_class(self, p):
        return conf.padding_layer


class NetflowOptionsFlowsetV9(Packet):
    name = "Netflow Options Template FlowSet V9"
    fields_desc = [ShortField("flowSetID", 1),
                   ShortField("length", None),
                   ShortField("templateID", 255),
                   FieldLenField("option_scope_length", None,
                                 length_of="scopes"),
                   FieldLenField("option_field_length", None,
                                 length_of="options"),
                   # We can't use PadField as we have 2 PacketListField
                   PacketListField(
                       "scopes", [],
                       NetflowOptionsFlowsetScopeV9,
                       length_from=lambda pkt: pkt.option_scope_length),
                   PacketListField(
                       "options", [],
                       NetflowOptionsFlowsetOptionV9,
                       length_from=lambda pkt: pkt.option_field_length),
                   StrLenField("pad", None, length_from=lambda pkt: (
                       pkt.length - pkt.option_scope_length -
                       pkt.option_field_length - 10))]

    def default_payload_class(self, p):
        return conf.padding_layer

    def post_build(self, pkt, pay):
        if self.pad is None:
            # Padding 4-bytes with b"\x00"
            start = 10 + self.option_scope_length + self.option_field_length
            pkt = pkt[:start] + (-len(pkt) % 4) * b"\x00"
        if self.length is None:
            pkt = pkt[:2] + struct.pack("!H", len(pkt)) + pkt[4:]
        return pkt + pay


# https://tools.ietf.org/html/rfc5101#section-3.4.2.2
class NetflowOptionsFlowset10(NetflowOptionsFlowsetV9):
    """Netflow V10 (IPFix) Options Template FlowSet"""
    name = "Netflow V10 (IPFix) Options Template FlowSet"
    fields_desc = [ShortField("flowSetID", 3),
                   ShortField("length", None),
                   ShortField("templateID", 255),
                   # Slightly different counting than in its NetflowV9
                   # counterpart: we count the total, and among them which
                   # ones are scopes. Also, it's count, not length
                   FieldLenField("field_count", None,
                                 count_of="options",
                                 adjust=lambda pkt, x: (
                                     x + pkt.get_field(
                                         "scope_field_count").i2m(pkt, None))),
                   FieldLenField("scope_field_count", None,
                                 count_of="scopes"),
                   # We can't use PadField as we have 2 PacketListField
                   PacketListField(
                       "scopes", [],
                       NetflowOptionsFlowsetScopeV9,
                       count_from=lambda pkt: pkt.scope_field_count),
                   PacketListField(
                       "options", [],
                       NetflowOptionsFlowsetOptionV9,
                       count_from=lambda pkt: (
                           pkt.field_count - pkt.scope_field_count
                       )),
                   StrLenField("pad", None, length_from=lambda pkt: (
                       pkt.length - (pkt.scope_field_count * 4) - 10))]

    def post_build(self, pkt, pay):
        if self.length is None:
            pkt = pkt[:2] + struct.pack("!H", len(pkt)) + pkt[4:]
        if self.pad is None:
            # Padding 4-bytes with b"\x00"
            start = 10 + self.scope_field_count * 4
            pkt = pkt[:start] + (-len(pkt) % 4) * b"\x00"
        return pkt + pay


bind_layers(NetflowHeader, NetflowHeaderV9, version=9)
bind_layers(NetflowHeaderV9, NetflowDataflowsetV9)
bind_layers(NetflowDataflowsetV9, NetflowDataflowsetV9)
bind_layers(NetflowOptionsFlowsetV9, NetflowDataflowsetV9)
bind_layers(NetflowFlowsetV9, NetflowDataflowsetV9)

# Apart from the first header, IPFix and NetflowV9 have the same format
# (except the Options Template)
# https://tools.ietf.org/html/rfc5655#appendix-B.1.2
bind_layers(NetflowHeader, NetflowHeaderV10, version=10)
bind_layers(NetflowHeaderV10, NetflowDataflowsetV9)
