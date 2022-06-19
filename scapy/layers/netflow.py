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

import socket
import struct

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
from scapy.sessions import IPSession, DefaultSession

from scapy.layers.inet import UDP
from scapy.layers.inet6 import IP6Field


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

# This is v9_v10_template_types (with names from the rfc for the first 79)
# https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-netflow.c  # noqa: E501
# (it has all values external to the RFC)
NTOP_BASE = 57472
NetflowV910TemplateFieldTypes = {
    1: "IN_BYTES",
    2: "IN_PKTS",
    3: "FLOWS",
    4: "PROTOCOL",
    5: "TOS",
    6: "TCP_FLAGS",
    7: "L4_SRC_PORT",
    8: "IPV4_SRC_ADDR",
    9: "SRC_MASK",
    10: "INPUT_SNMP",
    11: "L4_DST_PORT",
    12: "IPV4_DST_ADDR",
    13: "DST_MASK",
    14: "OUTPUT_SNMP",
    15: "IPV4_NEXT_HOP",
    16: "SRC_AS",
    17: "DST_AS",
    18: "BGP_IPV4_NEXT_HOP",
    19: "MUL_DST_PKTS",
    20: "MUL_DST_BYTES",
    21: "LAST_SWITCHED",
    22: "FIRST_SWITCHED",
    23: "OUT_BYTES",
    24: "OUT_PKTS",
    25: "IP_LENGTH_MINIMUM",
    26: "IP_LENGTH_MAXIMUM",
    27: "IPV6_SRC_ADDR",
    28: "IPV6_DST_ADDR",
    29: "IPV6_SRC_MASK",
    30: "IPV6_DST_MASK",
    31: "IPV6_FLOW_LABEL",
    32: "ICMP_TYPE",
    33: "MUL_IGMP_TYPE",
    34: "SAMPLING_INTERVAL",
    35: "SAMPLING_ALGORITHM",
    36: "FLOW_ACTIVE_TIMEOUT",
    37: "FLOW_INACTIVE_TIMEOUT",
    38: "ENGINE_TYPE",
    39: "ENGINE_ID",
    40: "TOTAL_BYTES_EXP",
    41: "TOTAL_PKTS_EXP",
    42: "TOTAL_FLOWS_EXP",
    43: "IPV4_ROUTER_SC",
    44: "IP_SRC_PREFIX",
    45: "IP_DST_PREFIX",
    46: "MPLS_TOP_LABEL_TYPE",
    47: "MPLS_TOP_LABEL_IP_ADDR",
    48: "FLOW_SAMPLER_ID",
    49: "FLOW_SAMPLER_MODE",
    50: "FLOW_SAMPLER_RANDOM_INTERVAL",
    51: "FLOW_CLASS",
    52: "IP TTL MINIMUM",
    53: "IP TTL MAXIMUM",
    54: "IPv4 ID",
    55: "DST_TOS",
    56: "SRC_MAC",
    57: "DST_MAC",
    58: "SRC_VLAN",
    59: "DST_VLAN",
    60: "IP_PROTOCOL_VERSION",
    61: "DIRECTION",
    62: "IPV6_NEXT_HOP",
    63: "BGP_IPV6_NEXT_HOP",
    64: "IPV6_OPTION_HEADERS",
    70: "MPLS_LABEL_1",
    71: "MPLS_LABEL_2",
    72: "MPLS_LABEL_3",
    73: "MPLS_LABEL_4",
    74: "MPLS_LABEL_5",
    75: "MPLS_LABEL_6",
    76: "MPLS_LABEL_7",
    77: "MPLS_LABEL_8",
    78: "MPLS_LABEL_9",
    79: "MPLS_LABEL_10",
    80: "DESTINATION_MAC",
    81: "SOURCE_MAC",
    82: "IF_NAME",
    83: "IF_DESC",
    84: "SAMPLER_NAME",
    85: "BYTES_TOTAL",
    86: "PACKETS_TOTAL",
    88: "FRAGMENT_OFFSET",
    89: "FORWARDING_STATUS",
    90: "VPN_ROUTE_DISTINGUISHER",
    91: "mplsTopLabelPrefixLength",
    92: "SRC_TRAFFIC_INDEX",
    93: "DST_TRAFFIC_INDEX",
    94: "APPLICATION_DESC",
    95: "APPLICATION_ID",
    96: "APPLICATION_NAME",
    98: "postIpDiffServCodePoint",
    99: "multicastReplicationFactor",
    101: "classificationEngineId",
    128: "DST_AS_PEER",
    129: "SRC_AS_PEER",
    130: "exporterIPv4Address",
    131: "exporterIPv6Address",
    132: "DROPPED_BYTES",
    133: "DROPPED_PACKETS",
    134: "DROPPED_BYTES_TOTAL",
    135: "DROPPED_PACKETS_TOTAL",
    136: "flowEndReason",
    137: "commonPropertiesId",
    138: "observationPointId",
    139: "icmpTypeCodeIPv6",
    140: "MPLS_TOP_LABEL_IPv6_ADDRESS",
    141: "lineCardId",
    142: "portId",
    143: "meteringProcessId",
    144: "FLOW_EXPORTER",
    145: "templateId",
    146: "wlanChannelId",
    147: "wlanSSID",
    148: "flowId",
    149: "observationDomainId",
    150: "flowStartSeconds",
    151: "flowEndSeconds",
    152: "flowStartMilliseconds",
    153: "flowEndMilliseconds",
    154: "flowStartMicroseconds",
    155: "flowEndMicroseconds",
    156: "flowStartNanoseconds",
    157: "flowEndNanoseconds",
    158: "flowStartDeltaMicroseconds",
    159: "flowEndDeltaMicroseconds",
    160: "systemInitTimeMilliseconds",
    161: "flowDurationMilliseconds",
    162: "flowDurationMicroseconds",
    163: "observedFlowTotalCount",
    164: "ignoredPacketTotalCount",
    165: "ignoredOctetTotalCount",
    166: "notSentFlowTotalCount",
    167: "notSentPacketTotalCount",
    168: "notSentOctetTotalCount",
    169: "destinationIPv6Prefix",
    170: "sourceIPv6Prefix",
    171: "postOctetTotalCount",
    172: "postPacketTotalCount",
    173: "flowKeyIndicator",
    174: "postMCastPacketTotalCount",
    175: "postMCastOctetTotalCount",
    176: "ICMP_IPv4_TYPE",
    177: "ICMP_IPv4_CODE",
    178: "ICMP_IPv6_TYPE",
    179: "ICMP_IPv6_CODE",
    180: "UDP_SRC_PORT",
    181: "UDP_DST_PORT",
    182: "TCP_SRC_PORT",
    183: "TCP_DST_PORT",
    184: "TCP_SEQ_NUM",
    185: "TCP_ACK_NUM",
    186: "TCP_WINDOW_SIZE",
    187: "TCP_URGENT_PTR",
    188: "TCP_HEADER_LEN",
    189: "IP_HEADER_LEN",
    190: "IP_TOTAL_LEN",
    191: "payloadLengthIPv6",
    192: "IP_TTL",
    193: "nextHeaderIPv6",
    194: "mplsPayloadLength",
    195: "IP_DSCP",
    196: "IP_PRECEDENCE",
    197: "IP_FRAGMENT_FLAGS",
    198: "DELTA_BYTES_SQUARED",
    199: "TOTAL_BYTES_SQUARED",
    200: "MPLS_TOP_LABEL_TTL",
    201: "MPLS_LABEL_STACK_OCTETS",
    202: "MPLS_LABEL_STACK_DEPTH",
    203: "MPLS_TOP_LABEL_EXP",
    204: "IP_PAYLOAD_LENGTH",
    205: "UDP_LENGTH",
    206: "IS_MULTICAST",
    207: "IP_HEADER_WORDS",
    208: "IP_OPTION_MAP",
    209: "TCP_OPTION_MAP",
    210: "paddingOctets",
    211: "collectorIPv4Address",
    212: "collectorIPv6Address",
    213: "collectorInterface",
    214: "collectorProtocolVersion",
    215: "collectorTransportProtocol",
    216: "collectorTransportPort",
    217: "exporterTransportPort",
    218: "tcpSynTotalCount",
    219: "tcpFinTotalCount",
    220: "tcpRstTotalCount",
    221: "tcpPshTotalCount",
    222: "tcpAckTotalCount",
    223: "tcpUrgTotalCount",
    224: "ipTotalLength",
    225: "postNATSourceIPv4Address",
    226: "postNATDestinationIPv4Address",
    227: "postNAPTSourceTransportPort",
    228: "postNAPTDestinationTransportPort",
    229: "natOriginatingAddressRealm",
    230: "natEvent",
    231: "initiatorOctets",
    232: "responderOctets",
    233: "firewallEvent",
    234: "ingressVRFID",
    235: "egressVRFID",
    236: "VRFname",
    237: "postMplsTopLabelExp",
    238: "tcpWindowScale",
    239: "biflowDirection",
    240: "ethernetHeaderLength",
    241: "ethernetPayloadLength",
    242: "ethernetTotalLength",
    243: "dot1qVlanId",
    244: "dot1qPriority",
    245: "dot1qCustomerVlanId",
    246: "dot1qCustomerPriority",
    247: "metroEvcId",
    248: "metroEvcType",
    249: "pseudoWireId",
    250: "pseudoWireType",
    251: "pseudoWireControlWord",
    252: "ingressPhysicalInterface",
    253: "egressPhysicalInterface",
    254: "postDot1qVlanId",
    255: "postDot1qCustomerVlanId",
    256: "ethernetType",
    257: "postIpPrecedence",
    258: "collectionTimeMilliseconds",
    259: "exportSctpStreamId",
    260: "maxExportSeconds",
    261: "maxFlowEndSeconds",
    262: "messageMD5Checksum",
    263: "messageScope",
    264: "minExportSeconds",
    265: "minFlowStartSeconds",
    266: "opaqueOctets",
    267: "sessionScope",
    268: "maxFlowEndMicroseconds",
    269: "maxFlowEndMilliseconds",
    270: "maxFlowEndNanoseconds",
    271: "minFlowStartMicroseconds",
    272: "minFlowStartMilliseconds",
    273: "minFlowStartNanoseconds",
    274: "collectorCertificate",
    275: "exporterCertificate",
    276: "dataRecordsReliability",
    277: "observationPointType",
    278: "newConnectionDeltaCount",
    279: "connectionSumDurationSeconds",
    280: "connectionTransactionId",
    281: "postNATSourceIPv6Address",
    282: "postNATDestinationIPv6Address",
    283: "natPoolId",
    284: "natPoolName",
    285: "anonymizationFlags",
    286: "anonymizationTechnique",
    287: "informationElementIndex",
    288: "p2pTechnology",
    289: "tunnelTechnology",
    290: "encryptedTechnology",
    291: "basicList",
    292: "subTemplateList",
    293: "subTemplateMultiList",
    294: "bgpValidityState",
    295: "IPSecSPI",
    296: "greKey",
    297: "natType",
    298: "initiatorPackets",
    299: "responderPackets",
    300: "observationDomainName",
    301: "selectionSequenceId",
    302: "selectorId",
    303: "informationElementId",
    304: "selectorAlgorithm",
    305: "samplingPacketInterval",
    306: "samplingPacketSpace",
    307: "samplingTimeInterval",
    308: "samplingTimeSpace",
    309: "samplingSize",
    310: "samplingPopulation",
    311: "samplingProbability",
    312: "dataLinkFrameSize",
    313: "IP_SECTION HEADER",
    314: "IP_SECTION PAYLOAD",
    315: "dataLinkFrameSection",
    316: "mplsLabelStackSection",
    317: "mplsPayloadPacketSection",
    318: "selectorIdTotalPktsObserved",
    319: "selectorIdTotalPktsSelected",
    320: "absoluteError",
    321: "relativeError",
    322: "observationTimeSeconds",
    323: "observationTimeMilliseconds",
    324: "observationTimeMicroseconds",
    325: "observationTimeNanoseconds",
    326: "digestHashValue",
    327: "hashIPPayloadOffset",
    328: "hashIPPayloadSize",
    329: "hashOutputRangeMin",
    330: "hashOutputRangeMax",
    331: "hashSelectedRangeMin",
    332: "hashSelectedRangeMax",
    333: "hashDigestOutput",
    334: "hashInitialiserValue",
    335: "selectorName",
    336: "upperCILimit",
    337: "lowerCILimit",
    338: "confidenceLevel",
    339: "informationElementDataType",
    340: "informationElementDescription",
    341: "informationElementName",
    342: "informationElementRangeBegin",
    343: "informationElementRangeEnd",
    344: "informationElementSemantics",
    345: "informationElementUnits",
    346: "privateEnterpriseNumber",
    347: "virtualStationInterfaceId",
    348: "virtualStationInterfaceName",
    349: "virtualStationUUID",
    350: "virtualStationName",
    351: "layer2SegmentId",
    352: "layer2OctetDeltaCount",
    353: "layer2OctetTotalCount",
    354: "ingressUnicastPacketTotalCount",
    355: "ingressMulticastPacketTotalCount",
    356: "ingressBroadcastPacketTotalCount",
    357: "egressUnicastPacketTotalCount",
    358: "egressBroadcastPacketTotalCount",
    359: "monitoringIntervalStartMilliSeconds",
    360: "monitoringIntervalEndMilliSeconds",
    361: "portRangeStart",
    362: "portRangeEnd",
    363: "portRangeStepSize",
    364: "portRangeNumPorts",
    365: "staMacAddress",
    366: "staIPv4Address",
    367: "wtpMacAddress",
    368: "ingressInterfaceType",
    369: "egressInterfaceType",
    370: "rtpSequenceNumber",
    371: "userName",
    372: "applicationCategoryName",
    373: "applicationSubCategoryName",
    374: "applicationGroupName",
    375: "originalFlowsPresent",
    376: "originalFlowsInitiated",
    377: "originalFlowsCompleted",
    378: "distinctCountOfSourceIPAddress",
    379: "distinctCountOfDestinationIPAddress",
    380: "distinctCountOfSourceIPv4Address",
    381: "distinctCountOfDestinationIPv4Address",
    382: "distinctCountOfSourceIPv6Address",
    383: "distinctCountOfDestinationIPv6Address",
    384: "valueDistributionMethod",
    385: "rfc3550JitterMilliseconds",
    386: "rfc3550JitterMicroseconds",
    387: "rfc3550JitterNanoseconds",
    388: "dot1qDEI",
    389: "dot1qCustomerDEI",
    390: "flowSelectorAlgorithm",
    391: "flowSelectedOctetDeltaCount",
    392: "flowSelectedPacketDeltaCount",
    393: "flowSelectedFlowDeltaCount",
    394: "selectorIDTotalFlowsObserved",
    395: "selectorIDTotalFlowsSelected",
    396: "samplingFlowInterval",
    397: "samplingFlowSpacing",
    398: "flowSamplingTimeInterval",
    399: "flowSamplingTimeSpacing",
    400: "hashFlowDomain",
    401: "transportOctetDeltaCount",
    402: "transportPacketDeltaCount",
    403: "originalExporterIPv4Address",
    404: "originalExporterIPv6Address",
    405: "originalObservationDomainId",
    406: "intermediateProcessId",
    407: "ignoredDataRecordTotalCount",
    408: "dataLinkFrameType",
    409: "sectionOffset",
    410: "sectionExportedOctets",
    411: "dot1qServiceInstanceTag",
    412: "dot1qServiceInstanceId",
    413: "dot1qServiceInstancePriority",
    414: "dot1qCustomerSourceMacAddress",
    415: "dot1qCustomerDestinationMacAddress",
    416: "deprecated [dup of layer2OctetDeltaCount]",
    417: "postLayer2OctetDeltaCount",
    418: "postMCastLayer2OctetDeltaCount",
    419: "deprecated [dup of layer2OctetTotalCount",
    420: "postLayer2OctetTotalCount",
    421: "postMCastLayer2OctetTotalCount",
    422: "minimumLayer2TotalLength",
    423: "maximumLayer2TotalLength",
    424: "droppedLayer2OctetDeltaCount",
    425: "droppedLayer2OctetTotalCount",
    426: "ignoredLayer2OctetTotalCount",
    427: "notSentLayer2OctetTotalCount",
    428: "layer2OctetDeltaSumOfSquares",
    429: "layer2OctetTotalSumOfSquares",
    430: "layer2FrameDeltaCount",
    431: "layer2FrameTotalCount",
    432: "pseudoWireDestinationIPv4Address",
    433: "ignoredLayer2FrameTotalCount",
    434: "mibObjectValueInteger",
    435: "mibObjectValueOctetString",
    436: "mibObjectValueOID",
    437: "mibObjectValueBits",
    438: "mibObjectValueIPAddress",
    439: "mibObjectValueCounter",
    440: "mibObjectValueGauge",
    441: "mibObjectValueTimeTicks",
    442: "mibObjectValueUnsigned",
    443: "mibObjectValueTable",
    444: "mibObjectValueRow",
    445: "mibObjectIdentifier",
    446: "mibSubIdentifier",
    447: "mibIndexIndicator",
    448: "mibCaptureTimeSemantics",
    449: "mibContextEngineID",
    450: "mibContextName",
    451: "mibObjectName",
    452: "mibObjectDescription",
    453: "mibObjectSyntax",
    454: "mibModuleName",
    455: "mobileIMSI",
    456: "mobileMSISDN",
    457: "httpStatusCode",
    458: "sourceTransportPortsLimit",
    459: "httpRequestMethod",
    460: "httpRequestHost",
    461: "httpRequestTarget",
    462: "httpMessageVersion",
    463: "natInstanceID",
    464: "internalAddressRealm",
    465: "externalAddressRealm",
    466: "natQuotaExceededEvent",
    467: "natThresholdEvent",
    468: "httpUserAgent",
    469: "httpContentType",
    470: "httpReasonPhrase",
    471: "maxSessionEntries",
    472: "maxBIBEntries",
    473: "maxEntriesPerUser",
    474: "maxSubscribers",
    475: "maxFragmentsPendingReassembly",
    476: "addressPoolHighThreshold",
    477: "addressPoolLowThreshold",
    478: "addressPortMappingHighThreshold",
    479: "addressPortMappingLowThreshold",
    480: "addressPortMappingPerUserHighThreshold",
    481: "globalAddressMappingHighThreshold",

    # Ericsson NAT Logging
    24628: "NAT_LOG_FIELD_IDX_CONTEXT_ID",
    24629: "NAT_LOG_FIELD_IDX_CONTEXT_NAME",
    24630: "NAT_LOG_FIELD_IDX_ASSIGN_TS_SEC",
    24631: "NAT_LOG_FIELD_IDX_UNASSIGN_TS_SEC",
    24632: "NAT_LOG_FIELD_IDX_IPV4_INT_ADDR",
    24633: "NAT_LOG_FIELD_IDX_IPV4_EXT_ADDR",
    24634: "NAT_LOG_FIELD_IDX_EXT_PORT_FIRST",
    24635: "NAT_LOG_FIELD_IDX_EXT_PORT_LAST",
    # Cisco ASA5500 Series NetFlow
    33000: "INGRESS_ACL_ID",
    33001: "EGRESS_ACL_ID",
    33002: "FW_EXT_EVENT",
    # Cisco TrustSec
    34000: "SGT_SOURCE_TAG",
    34001: "SGT_DESTINATION_TAG",
    34002: "SGT_SOURCE_NAME",
    34003: "SGT_DESTINATION_NAME",
    # medianet performance monitor
    37000: "PACKETS_DROPPED",
    37003: "BYTE_RATE",
    37004: "APPLICATION_MEDIA_BYTES",
    37006: "APPLICATION_MEDIA_BYTE_RATE",
    37007: "APPLICATION_MEDIA_PACKETS",
    37009: "APPLICATION_MEDIA_PACKET_RATE",
    37011: "APPLICATION_MEDIA_EVENT",
    37012: "MONITOR_EVENT",
    37013: "TIMESTAMP_INTERVAL",
    37014: "TRANSPORT_PACKETS_EXPECTED",
    37016: "TRANSPORT_ROUND_TRIP_TIME",
    37017: "TRANSPORT_EVENT_PACKET_LOSS",
    37019: "TRANSPORT_PACKETS_LOST",
    37021: "TRANSPORT_PACKETS_LOST_RATE",
    37022: "TRANSPORT_RTP_SSRC",
    37023: "TRANSPORT_RTP_JITTER_MEAN",
    37024: "TRANSPORT_RTP_JITTER_MIN",
    37025: "TRANSPORT_RTP_JITTER_MAX",
    37041: "TRANSPORT_RTP_PAYLOAD_TYPE",
    37071: "TRANSPORT_BYTES_OUT_OF_ORDER",
    37074: "TRANSPORT_PACKETS_OUT_OF_ORDER",
    37083: "TRANSPORT_TCP_WINDOWS_SIZE_MIN",
    37084: "TRANSPORT_TCP_WINDOWS_SIZE_MAX",
    37085: "TRANSPORT_TCP_WINDOWS_SIZE_MEAN",
    37086: "TRANSPORT_TCP_MAXIMUM_SEGMENT_SIZE",
    # Cisco ASA 5500
    40000: "AAA_USERNAME",
    40001: "XLATE_SRC_ADDR_IPV4",
    40002: "XLATE_DST_ADDR_IPV4",
    40003: "XLATE_SRC_PORT",
    40004: "XLATE_DST_PORT",
    40005: "FW_EVENT",
    # v9 nTop extensions
    80 + NTOP_BASE: "SRC_FRAGMENTS",
    81 + NTOP_BASE: "DST_FRAGMENTS",
    82 + NTOP_BASE: "SRC_TO_DST_MAX_THROUGHPUT",
    83 + NTOP_BASE: "SRC_TO_DST_MIN_THROUGHPUT",
    84 + NTOP_BASE: "SRC_TO_DST_AVG_THROUGHPUT",
    85 + NTOP_BASE: "SRC_TO_SRC_MAX_THROUGHPUT",
    86 + NTOP_BASE: "SRC_TO_SRC_MIN_THROUGHPUT",
    87 + NTOP_BASE: "SRC_TO_SRC_AVG_THROUGHPUT",
    88 + NTOP_BASE: "NUM_PKTS_UP_TO_128_BYTES",
    89 + NTOP_BASE: "NUM_PKTS_128_TO_256_BYTES",
    90 + NTOP_BASE: "NUM_PKTS_256_TO_512_BYTES",
    91 + NTOP_BASE: "NUM_PKTS_512_TO_1024_BYTES",
    92 + NTOP_BASE: "NUM_PKTS_1024_TO_1514_BYTES",
    93 + NTOP_BASE: "NUM_PKTS_OVER_1514_BYTES",
    98 + NTOP_BASE: "CUMULATIVE_ICMP_TYPE",
    101 + NTOP_BASE: "SRC_IP_COUNTRY",
    102 + NTOP_BASE: "SRC_IP_CITY",
    103 + NTOP_BASE: "DST_IP_COUNTRY",
    104 + NTOP_BASE: "DST_IP_CITY",
    105 + NTOP_BASE: "FLOW_PROTO_PORT",
    106 + NTOP_BASE: "UPSTREAM_TUNNEL_ID",
    107 + NTOP_BASE: "LONGEST_FLOW_PKT",
    108 + NTOP_BASE: "SHORTEST_FLOW_PKT",
    109 + NTOP_BASE: "RETRANSMITTED_IN_PKTS",
    110 + NTOP_BASE: "RETRANSMITTED_OUT_PKTS",
    111 + NTOP_BASE: "OOORDER_IN_PKTS",
    112 + NTOP_BASE: "OOORDER_OUT_PKTS",
    113 + NTOP_BASE: "UNTUNNELED_PROTOCOL",
    114 + NTOP_BASE: "UNTUNNELED_IPV4_SRC_ADDR",
    115 + NTOP_BASE: "UNTUNNELED_L4_SRC_PORT",
    116 + NTOP_BASE: "UNTUNNELED_IPV4_DST_ADDR",
    117 + NTOP_BASE: "UNTUNNELED_L4_DST_PORT",
    118 + NTOP_BASE: "L7_PROTO",
    119 + NTOP_BASE: "L7_PROTO_NAME",
    120 + NTOP_BASE: "DOWNSTREAM_TUNNEL_ID",
    121 + NTOP_BASE: "FLOW_USER_NAME",
    122 + NTOP_BASE: "FLOW_SERVER_NAME",
    123 + NTOP_BASE: "CLIENT_NW_LATENCY_MS",
    124 + NTOP_BASE: "SERVER_NW_LATENCY_MS",
    125 + NTOP_BASE: "APPL_LATENCY_MS",
    126 + NTOP_BASE: "PLUGIN_NAME",
    127 + NTOP_BASE: "RETRANSMITTED_IN_BYTES",
    128 + NTOP_BASE: "RETRANSMITTED_OUT_BYTES",
    130 + NTOP_BASE: "SIP_CALL_ID",
    131 + NTOP_BASE: "SIP_CALLING_PARTY",
    132 + NTOP_BASE: "SIP_CALLED_PARTY",
    133 + NTOP_BASE: "SIP_RTP_CODECS",
    134 + NTOP_BASE: "SIP_INVITE_TIME",
    135 + NTOP_BASE: "SIP_TRYING_TIME",
    136 + NTOP_BASE: "SIP_RINGING_TIME",
    137 + NTOP_BASE: "SIP_INVITE_OK_TIME",
    138 + NTOP_BASE: "SIP_INVITE_FAILURE_TIME",
    139 + NTOP_BASE: "SIP_BYE_TIME",
    140 + NTOP_BASE: "SIP_BYE_OK_TIME",
    141 + NTOP_BASE: "SIP_CANCEL_TIME",
    142 + NTOP_BASE: "SIP_CANCEL_OK_TIME",
    143 + NTOP_BASE: "SIP_RTP_IPV4_SRC_ADDR",
    144 + NTOP_BASE: "SIP_RTP_L4_SRC_PORT",
    145 + NTOP_BASE: "SIP_RTP_IPV4_DST_ADDR",
    146 + NTOP_BASE: "SIP_RTP_L4_DST_PORT",
    147 + NTOP_BASE: "SIP_RESPONSE_CODE",
    148 + NTOP_BASE: "SIP_REASON_CAUSE",
    150 + NTOP_BASE: "RTP_FIRST_SEQ",
    151 + NTOP_BASE: "RTP_FIRST_TS",
    152 + NTOP_BASE: "RTP_LAST_SEQ",
    153 + NTOP_BASE: "RTP_LAST_TS",
    154 + NTOP_BASE: "RTP_IN_JITTER",
    155 + NTOP_BASE: "RTP_OUT_JITTER",
    156 + NTOP_BASE: "RTP_IN_PKT_LOST",
    157 + NTOP_BASE: "RTP_OUT_PKT_LOST",
    158 + NTOP_BASE: "RTP_OUT_PAYLOAD_TYPE",
    159 + NTOP_BASE: "RTP_IN_MAX_DELTA",
    160 + NTOP_BASE: "RTP_OUT_MAX_DELTA",
    161 + NTOP_BASE: "RTP_IN_PAYLOAD_TYPE",
    168 + NTOP_BASE: "SRC_PROC_PID",
    169 + NTOP_BASE: "SRC_PROC_NAME",
    180 + NTOP_BASE: "HTTP_URL",
    181 + NTOP_BASE: "HTTP_RET_CODE",
    182 + NTOP_BASE: "HTTP_REFERER",
    183 + NTOP_BASE: "HTTP_UA",
    184 + NTOP_BASE: "HTTP_MIME",
    185 + NTOP_BASE: "SMTP_MAIL_FROM",
    186 + NTOP_BASE: "SMTP_RCPT_TO",
    187 + NTOP_BASE: "HTTP_HOST",
    188 + NTOP_BASE: "SSL_SERVER_NAME",
    189 + NTOP_BASE: "BITTORRENT_HASH",
    195 + NTOP_BASE: "MYSQL_SRV_VERSION",
    196 + NTOP_BASE: "MYSQL_USERNAME",
    197 + NTOP_BASE: "MYSQL_DB",
    198 + NTOP_BASE: "MYSQL_QUERY",
    199 + NTOP_BASE: "MYSQL_RESPONSE",
    200 + NTOP_BASE: "ORACLE_USERNAME",
    201 + NTOP_BASE: "ORACLE_QUERY",
    202 + NTOP_BASE: "ORACLE_RSP_CODE",
    203 + NTOP_BASE: "ORACLE_RSP_STRING",
    204 + NTOP_BASE: "ORACLE_QUERY_DURATION",
    205 + NTOP_BASE: "DNS_QUERY",
    206 + NTOP_BASE: "DNS_QUERY_ID",
    207 + NTOP_BASE: "DNS_QUERY_TYPE",
    208 + NTOP_BASE: "DNS_RET_CODE",
    209 + NTOP_BASE: "DNS_NUM_ANSWERS",
    210 + NTOP_BASE: "POP_USER",
    220 + NTOP_BASE: "GTPV1_REQ_MSG_TYPE",
    221 + NTOP_BASE: "GTPV1_RSP_MSG_TYPE",
    222 + NTOP_BASE: "GTPV1_C2S_TEID_DATA",
    223 + NTOP_BASE: "GTPV1_C2S_TEID_CTRL",
    224 + NTOP_BASE: "GTPV1_S2C_TEID_DATA",
    225 + NTOP_BASE: "GTPV1_S2C_TEID_CTRL",
    226 + NTOP_BASE: "GTPV1_END_USER_IP",
    227 + NTOP_BASE: "GTPV1_END_USER_IMSI",
    228 + NTOP_BASE: "GTPV1_END_USER_MSISDN",
    229 + NTOP_BASE: "GTPV1_END_USER_IMEI",
    230 + NTOP_BASE: "GTPV1_APN_NAME",
    231 + NTOP_BASE: "GTPV1_RAI_MCC",
    232 + NTOP_BASE: "GTPV1_RAI_MNC",
    233 + NTOP_BASE: "GTPV1_ULI_CELL_LAC",
    234 + NTOP_BASE: "GTPV1_ULI_CELL_CI",
    235 + NTOP_BASE: "GTPV1_ULI_SAC",
    236 + NTOP_BASE: "GTPV1_RAT_TYPE",
    240 + NTOP_BASE: "RADIUS_REQ_MSG_TYPE",
    241 + NTOP_BASE: "RADIUS_RSP_MSG_TYPE",
    242 + NTOP_BASE: "RADIUS_USER_NAME",
    243 + NTOP_BASE: "RADIUS_CALLING_STATION_ID",
    244 + NTOP_BASE: "RADIUS_CALLED_STATION_ID",
    245 + NTOP_BASE: "RADIUS_NAS_IP_ADDR",
    246 + NTOP_BASE: "RADIUS_NAS_IDENTIFIER",
    247 + NTOP_BASE: "RADIUS_USER_IMSI",
    248 + NTOP_BASE: "RADIUS_USER_IMEI",
    249 + NTOP_BASE: "RADIUS_FRAMED_IP_ADDR",
    250 + NTOP_BASE: "RADIUS_ACCT_SESSION_ID",
    251 + NTOP_BASE: "RADIUS_ACCT_STATUS_TYPE",
    252 + NTOP_BASE: "RADIUS_ACCT_IN_OCTETS",
    253 + NTOP_BASE: "RADIUS_ACCT_OUT_OCTETS",
    254 + NTOP_BASE: "RADIUS_ACCT_IN_PKTS",
    255 + NTOP_BASE: "RADIUS_ACCT_OUT_PKTS",
    260 + NTOP_BASE: "IMAP_LOGIN",
    270 + NTOP_BASE: "GTPV2_REQ_MSG_TYPE",
    271 + NTOP_BASE: "GTPV2_RSP_MSG_TYPE",
    272 + NTOP_BASE: "GTPV2_C2S_S1U_GTPU_TEID",
    273 + NTOP_BASE: "GTPV2_C2S_S1U_GTPU_IP",
    274 + NTOP_BASE: "GTPV2_S2C_S1U_GTPU_TEID",
    275 + NTOP_BASE: "GTPV2_S2C_S1U_GTPU_IP",
    276 + NTOP_BASE: "GTPV2_END_USER_IMSI",
    277 + NTOP_BASE: "GTPV2_END_USER_MSISDN",
    278 + NTOP_BASE: "GTPV2_APN_NAME",
    279 + NTOP_BASE: "GTPV2_ULI_MCC",
    280 + NTOP_BASE: "GTPV2_ULI_MNC",
    281 + NTOP_BASE: "GTPV2_ULI_CELL_TAC",
    282 + NTOP_BASE: "GTPV2_ULI_CELL_ID",
    283 + NTOP_BASE: "GTPV2_RAT_TYPE",
    284 + NTOP_BASE: "GTPV2_PDN_IP",
    285 + NTOP_BASE: "GTPV2_END_USER_IMEI",
    290 + NTOP_BASE: "SRC_AS_PATH_1",
    291 + NTOP_BASE: "SRC_AS_PATH_2",
    292 + NTOP_BASE: "SRC_AS_PATH_3",
    293 + NTOP_BASE: "SRC_AS_PATH_4",
    294 + NTOP_BASE: "SRC_AS_PATH_5",
    295 + NTOP_BASE: "SRC_AS_PATH_6",
    296 + NTOP_BASE: "SRC_AS_PATH_7",
    297 + NTOP_BASE: "SRC_AS_PATH_8",
    298 + NTOP_BASE: "SRC_AS_PATH_9",
    299 + NTOP_BASE: "SRC_AS_PATH_10",
    300 + NTOP_BASE: "DST_AS_PATH_1",
    301 + NTOP_BASE: "DST_AS_PATH_2",
    302 + NTOP_BASE: "DST_AS_PATH_3",
    303 + NTOP_BASE: "DST_AS_PATH_4",
    304 + NTOP_BASE: "DST_AS_PATH_5",
    305 + NTOP_BASE: "DST_AS_PATH_6",
    306 + NTOP_BASE: "DST_AS_PATH_7",
    307 + NTOP_BASE: "DST_AS_PATH_8",
    308 + NTOP_BASE: "DST_AS_PATH_9",
    309 + NTOP_BASE: "DST_AS_PATH_10",
    320 + NTOP_BASE: "MYSQL_APPL_LATENCY_USEC",
    321 + NTOP_BASE: "GTPV0_REQ_MSG_TYPE",
    322 + NTOP_BASE: "GTPV0_RSP_MSG_TYPE",
    323 + NTOP_BASE: "GTPV0_TID",
    324 + NTOP_BASE: "GTPV0_END_USER_IP",
    325 + NTOP_BASE: "GTPV0_END_USER_MSISDN",
    326 + NTOP_BASE: "GTPV0_APN_NAME",
    327 + NTOP_BASE: "GTPV0_RAI_MCC",
    328 + NTOP_BASE: "GTPV0_RAI_MNC",
    329 + NTOP_BASE: "GTPV0_RAI_CELL_LAC",
    330 + NTOP_BASE: "GTPV0_RAI_CELL_RAC",
    331 + NTOP_BASE: "GTPV0_RESPONSE_CAUSE",
    332 + NTOP_BASE: "GTPV1_RESPONSE_CAUSE",
    333 + NTOP_BASE: "GTPV2_RESPONSE_CAUSE",
    334 + NTOP_BASE: "NUM_PKTS_TTL_5_32",
    335 + NTOP_BASE: "NUM_PKTS_TTL_32_64",
    336 + NTOP_BASE: "NUM_PKTS_TTL_64_96",
    337 + NTOP_BASE: "NUM_PKTS_TTL_96_128",
    338 + NTOP_BASE: "NUM_PKTS_TTL_128_160",
    339 + NTOP_BASE: "NUM_PKTS_TTL_160_192",
    340 + NTOP_BASE: "NUM_PKTS_TTL_192_224",
    341 + NTOP_BASE: "NUM_PKTS_TTL_224_255",
    342 + NTOP_BASE: "GTPV1_RAI_LAC",
    343 + NTOP_BASE: "GTPV1_RAI_RAC",
    344 + NTOP_BASE: "GTPV1_ULI_MCC",
    345 + NTOP_BASE: "GTPV1_ULI_MNC",
    346 + NTOP_BASE: "NUM_PKTS_TTL_2_5",
    347 + NTOP_BASE: "NUM_PKTS_TTL_EQ_1",
    348 + NTOP_BASE: "RTP_SIP_CALL_ID",
    349 + NTOP_BASE: "IN_SRC_OSI_SAP",
    350 + NTOP_BASE: "OUT_DST_OSI_SAP",
    351 + NTOP_BASE: "WHOIS_DAS_DOMAIN",
    352 + NTOP_BASE: "DNS_TTL_ANSWER",
    353 + NTOP_BASE: "DHCP_CLIENT_MAC",
    354 + NTOP_BASE: "DHCP_CLIENT_IP",
    355 + NTOP_BASE: "DHCP_CLIENT_NAME",
    356 + NTOP_BASE: "FTP_LOGIN",
    357 + NTOP_BASE: "FTP_PASSWORD",
    358 + NTOP_BASE: "FTP_COMMAND",
    359 + NTOP_BASE: "FTP_COMMAND_RET_CODE",
    360 + NTOP_BASE: "HTTP_METHOD",
    361 + NTOP_BASE: "HTTP_SITE",
    362 + NTOP_BASE: "SIP_C_IP",
    363 + NTOP_BASE: "SIP_CALL_STATE",
    364 + NTOP_BASE: "EPP_REGISTRAR_NAME",
    365 + NTOP_BASE: "EPP_CMD",
    366 + NTOP_BASE: "EPP_CMD_ARGS",
    367 + NTOP_BASE: "EPP_RSP_CODE",
    368 + NTOP_BASE: "EPP_REASON_STR",
    369 + NTOP_BASE: "EPP_SERVER_NAME",
    370 + NTOP_BASE: "RTP_IN_MOS",
    371 + NTOP_BASE: "RTP_IN_R_FACTOR",
    372 + NTOP_BASE: "SRC_PROC_USER_NAME",
    373 + NTOP_BASE: "SRC_FATHER_PROC_PID",
    374 + NTOP_BASE: "SRC_FATHER_PROC_NAME",
    375 + NTOP_BASE: "DST_PROC_PID",
    376 + NTOP_BASE: "DST_PROC_NAME",
    377 + NTOP_BASE: "DST_PROC_USER_NAME",
    378 + NTOP_BASE: "DST_FATHER_PROC_PID",
    379 + NTOP_BASE: "DST_FATHER_PROC_NAME",
    380 + NTOP_BASE: "RTP_RTT",
    381 + NTOP_BASE: "RTP_IN_TRANSIT",
    382 + NTOP_BASE: "RTP_OUT_TRANSIT",
    383 + NTOP_BASE: "SRC_PROC_ACTUAL_MEMORY",
    384 + NTOP_BASE: "SRC_PROC_PEAK_MEMORY",
    385 + NTOP_BASE: "SRC_PROC_AVERAGE_CPU_LOAD",
    386 + NTOP_BASE: "SRC_PROC_NUM_PAGE_FAULTS",
    387 + NTOP_BASE: "DST_PROC_ACTUAL_MEMORY",
    388 + NTOP_BASE: "DST_PROC_PEAK_MEMORY",
    389 + NTOP_BASE: "DST_PROC_AVERAGE_CPU_LOAD",
    390 + NTOP_BASE: "DST_PROC_NUM_PAGE_FAULTS",
    391 + NTOP_BASE: "DURATION_IN",
    392 + NTOP_BASE: "DURATION_OUT",
    393 + NTOP_BASE: "SRC_PROC_PCTG_IOWAIT",
    394 + NTOP_BASE: "DST_PROC_PCTG_IOWAIT",
    395 + NTOP_BASE: "RTP_DTMF_TONES",
    396 + NTOP_BASE: "UNTUNNELED_IPV6_SRC_ADDR",
    397 + NTOP_BASE: "UNTUNNELED_IPV6_DST_ADDR",
    398 + NTOP_BASE: "DNS_RESPONSE",
    399 + NTOP_BASE: "DIAMETER_REQ_MSG_TYPE",
    400 + NTOP_BASE: "DIAMETER_RSP_MSG_TYPE",
    401 + NTOP_BASE: "DIAMETER_REQ_ORIGIN_HOST",
    402 + NTOP_BASE: "DIAMETER_RSP_ORIGIN_HOST",
    403 + NTOP_BASE: "DIAMETER_REQ_USER_NAME",
    404 + NTOP_BASE: "DIAMETER_RSP_RESULT_CODE",
    405 + NTOP_BASE: "DIAMETER_EXP_RES_VENDOR_ID",
    406 + NTOP_BASE: "DIAMETER_EXP_RES_RESULT_CODE",
    407 + NTOP_BASE: "S1AP_ENB_UE_S1AP_ID",
    408 + NTOP_BASE: "S1AP_MME_UE_S1AP_ID",
    409 + NTOP_BASE: "S1AP_MSG_EMM_TYPE_MME_TO_ENB",
    410 + NTOP_BASE: "S1AP_MSG_ESM_TYPE_MME_TO_ENB",
    411 + NTOP_BASE: "S1AP_MSG_EMM_TYPE_ENB_TO_MME",
    412 + NTOP_BASE: "S1AP_MSG_ESM_TYPE_ENB_TO_MME",
    413 + NTOP_BASE: "S1AP_CAUSE_ENB_TO_MME",
    414 + NTOP_BASE: "S1AP_DETAILED_CAUSE_ENB_TO_MME",
    415 + NTOP_BASE: "TCP_WIN_MIN_IN",
    416 + NTOP_BASE: "TCP_WIN_MAX_IN",
    417 + NTOP_BASE: "TCP_WIN_MSS_IN",
    418 + NTOP_BASE: "TCP_WIN_SCALE_IN",
    419 + NTOP_BASE: "TCP_WIN_MIN_OUT",
    420 + NTOP_BASE: "TCP_WIN_MAX_OUT",
    421 + NTOP_BASE: "TCP_WIN_MSS_OUT",
    422 + NTOP_BASE: "TCP_WIN_SCALE_OUT",
    423 + NTOP_BASE: "DHCP_REMOTE_ID",
    424 + NTOP_BASE: "DHCP_SUBSCRIBER_ID",
    425 + NTOP_BASE: "SRC_PROC_UID",
    426 + NTOP_BASE: "DST_PROC_UID",
    427 + NTOP_BASE: "APPLICATION_NAME",
    428 + NTOP_BASE: "USER_NAME",
    429 + NTOP_BASE: "DHCP_MESSAGE_TYPE",
    430 + NTOP_BASE: "RTP_IN_PKT_DROP",
    431 + NTOP_BASE: "RTP_OUT_PKT_DROP",
    432 + NTOP_BASE: "RTP_OUT_MOS",
    433 + NTOP_BASE: "RTP_OUT_R_FACTOR",
    434 + NTOP_BASE: "RTP_MOS",
    435 + NTOP_BASE: "GTPV2_S5_S8_GTPC_TEID",
    436 + NTOP_BASE: "RTP_R_FACTOR",
    437 + NTOP_BASE: "RTP_SSRC",
    438 + NTOP_BASE: "PAYLOAD_HASH",
    439 + NTOP_BASE: "GTPV2_C2S_S5_S8_GTPU_TEID",
    440 + NTOP_BASE: "GTPV2_S2C_S5_S8_GTPU_TEID",
    441 + NTOP_BASE: "GTPV2_C2S_S5_S8_GTPU_IP",
    442 + NTOP_BASE: "GTPV2_S2C_S5_S8_GTPU_IP",
    443 + NTOP_BASE: "SRC_AS_MAP",
    444 + NTOP_BASE: "DST_AS_MAP",
    445 + NTOP_BASE: "DIAMETER_HOP_BY_HOP_ID",
    446 + NTOP_BASE: "UPSTREAM_SESSION_ID",
    447 + NTOP_BASE: "DOWNSTREAM_SESSION_ID",
    448 + NTOP_BASE: "SRC_IP_LONG",
    449 + NTOP_BASE: "SRC_IP_LAT",
    450 + NTOP_BASE: "DST_IP_LONG",
    451 + NTOP_BASE: "DST_IP_LAT",
    452 + NTOP_BASE: "DIAMETER_CLR_CANCEL_TYPE",
    453 + NTOP_BASE: "DIAMETER_CLR_FLAGS",
    454 + NTOP_BASE: "GTPV2_C2S_S5_S8_GTPC_IP",
    455 + NTOP_BASE: "GTPV2_S2C_S5_S8_GTPC_IP",
    456 + NTOP_BASE: "GTPV2_C2S_S5_S8_SGW_GTPU_TEID",
    457 + NTOP_BASE: "GTPV2_S2C_S5_S8_SGW_GTPU_TEID",
    458 + NTOP_BASE: "GTPV2_C2S_S5_S8_SGW_GTPU_IP",
    459 + NTOP_BASE: "GTPV2_S2C_S5_S8_SGW_GTPU_IP",
    460 + NTOP_BASE: "HTTP_X_FORWARDED_FOR",
    461 + NTOP_BASE: "HTTP_VIA",
    462 + NTOP_BASE: "SSDP_HOST",
    463 + NTOP_BASE: "SSDP_USN",
    464 + NTOP_BASE: "NETBIOS_QUERY_NAME",
    465 + NTOP_BASE: "NETBIOS_QUERY_TYPE",
    466 + NTOP_BASE: "NETBIOS_RESPONSE",
    467 + NTOP_BASE: "NETBIOS_QUERY_OS",
    468 + NTOP_BASE: "SSDP_SERVER",
    469 + NTOP_BASE: "SSDP_TYPE",
    470 + NTOP_BASE: "SSDP_METHOD",
    471 + NTOP_BASE: "NPROBE_IPV4_ADDRESS",
}

ScopeFieldTypes = {
    1: "System",
    2: "Interface",
    3: "Line card",
    4: "Cache",
    5: "Template",
}

NetflowV9TemplateFieldDefaultLengths = {
    1: 4,
    2: 4,
    3: 4,
    4: 1,
    5: 1,
    6: 1,
    7: 2,
    8: 4,
    9: 1,
    10: 2,
    11: 2,
    12: 4,
    13: 1,
    14: 2,
    15: 4,
    16: 2,
    17: 2,
    18: 4,
    19: 4,
    20: 4,
    21: 4,
    22: 4,
    23: 4,
    24: 4,
    27: 16,
    28: 16,
    29: 1,
    30: 1,
    31: 3,
    32: 2,
    33: 1,
    34: 4,
    35: 1,
    36: 2,
    37: 2,
    38: 1,
    39: 1,
    40: 4,
    41: 4,
    42: 4,
    46: 1,
    47: 4,
    48: 4,  # from ERRATA
    49: 1,
    50: 4,
    55: 1,
    56: 6,
    57: 6,
    58: 2,
    59: 2,
    60: 1,
    61: 1,
    62: 16,
    63: 16,
    64: 4,
    70: 3,
    71: 3,
    72: 3,
    73: 3,
    74: 3,
    75: 3,
    76: 3,
    77: 3,
    78: 3,
    79: 3,
}

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


# TODO: There are hundreds of entries to add to the following :(
# https://tools.ietf.org/html/rfc5655
# ==> feel free to contribute :D
NetflowV9TemplateFieldDecoders = {
    # Only contains fields that have a fixed length
    # ID: Field,
    # or
    # ID: (Field, [*optional_parameters]),
    4: (ByteEnumField, [IP_PROTOS]),  # PROTOCOL
    5: XByteField,  # TOS
    6: ByteField,  # TCP_FLAGS
    7: ShortField,  # L4_SRC_PORT
    8: IPField,  # IPV4_SRC_ADDR
    9: ByteField,  # SRC_MASK
    11: ShortField,  # L4_DST_PORT
    12: IPField,  # IPV4_DST_PORT
    13: ByteField,  # DST_MASK
    15: IPField,  # IPv4_NEXT_HOP
    16: ShortOrInt,  # SRC_AS
    17: ShortOrInt,  # DST_AS
    18: IPField,  # BGP_IPv4_NEXT_HOP
    21: (SecondsIntField, [True]),  # LAST_SWITCHED
    22: (SecondsIntField, [True]),  # FIRST_SWITCHED
    27: IP6Field,  # IPV6_SRC_ADDR
    28: IP6Field,  # IPV6_DST_ADDR
    29: ByteField,  # IPV6_SRC_MASK
    30: ByteField,  # IPV6_DST_MASK
    31: ThreeBytesField,  # IPV6_FLOW_LABEL
    32: XShortField,  # ICMP_TYPE
    33: ByteField,  # MUL_IGMP_TYPE
    34: IntField,  # SAMPLING_INTERVAL
    35: XByteField,  # SAMPLING_ALGORITHM
    36: ShortField,  # FLOW_ACTIVE_TIMEOUT
    37: ShortField,  # FLOW_ACTIVE_TIMEOUT
    38: ByteField,  # ENGINE_TYPE
    39: ByteField,  # ENGINE_ID
    46: (ByteEnumField, [{0x00: "UNKNOWN", 0x01: "TE-MIDPT", 0x02: "ATOM", 0x03: "VPN", 0x04: "BGP", 0x05: "LDP"}]),  # MPLS_TOP_LABEL_TYPE  # noqa: E501
    47: IPField,  # MPLS_TOP_LABEL_IP_ADDR
    48: ByteField,  # FLOW_SAMPLER_ID
    49: ByteField,  # FLOW_SAMPLER_MODE
    50: IntField,  # FLOW_SAMPLER_RANDOM_INTERVAL
    55: XByteField,  # DST_TOS
    56: MACField,  # SRC_MAC
    57: MACField,  # DST_MAC
    58: ShortField,  # SRC_VLAN
    59: ShortField,  # DST_VLAN
    60: ByteField,  # IP_PROTOCOL_VERSION
    61: (ByteEnumField, [{0x00: "Ingress flow", 0x01: "Egress flow"}]),  # DIRECTION  # noqa: E501
    62: IP6Field,  # IPV6_NEXT_HOP
    63: IP6Field,  # BGP_IPV6_NEXT_HOP
    130: IPField,  # exporterIPv4Address
    131: IP6Field,  # exporterIPv6Address
    150: N9UTCTimeField,  # flowStartSeconds
    151: N9UTCTimeField,  # flowEndSeconds
    152: (N9UTCTimeField, [True]),  # flowStartMilliseconds
    153: (N9UTCTimeField, [True]),  # flowEndMilliseconds
    154: (N9UTCTimeField, [False, True]),  # flowStartMicroseconds
    155: (N9UTCTimeField, [False, True]),  # flowEndMicroseconds
    156: (N9UTCTimeField, [False, False, True]),  # flowStartNanoseconds
    157: (N9UTCTimeField, [False, False, True]),  # flowEndNanoseconds
    158: (N9SecondsIntField, [False, True]),  # flowStartDeltaMicroseconds
    159: (N9SecondsIntField, [False, True]),  # flowEndDeltaMicroseconds
    160: (N9UTCTimeField, [True]),  # systemInitTimeMilliseconds
    161: (N9SecondsIntField, [True]),  # flowDurationMilliseconds
    162: (N9SecondsIntField, [False, True]),  # flowDurationMicroseconds
    211: IPField,  # collectorIPv4Address
    212: IP6Field,  # collectorIPv6Address
    225: IPField,  # postNATSourceIPv4Address
    226: IPField,  # postNATDestinationIPv4Address
    258: (N9SecondsIntField, [True]),  # collectionTimeMilliseconds
    260: N9SecondsIntField,  # maxExportSeconds
    261: N9SecondsIntField,  # maxFlowEndSeconds
    264: N9SecondsIntField,  # minExportSeconds
    265: N9SecondsIntField,  # minFlowStartSeconds
    268: (N9UTCTimeField, [False, True]),  # maxFlowEndMicroseconds
    269: (N9UTCTimeField, [True]),  # maxFlowEndMilliseconds
    270: (N9UTCTimeField, [False, False, True]),  # maxFlowEndNanoseconds
    271: (N9UTCTimeField, [False, True]),  # minFlowStartMicroseconds
    272: (N9UTCTimeField, [True]),  # minFlowStartMilliseconds
    273: (N9UTCTimeField, [False, False, True]),  # minFlowStartNanoseconds
    279: N9SecondsIntField,  # connectionSumDurationSeconds
    281: IP6Field,  # postNATSourceIPv6Address
    282: IP6Field,  # postNATDestinationIPv6Address
    322: N9UTCTimeField,  # observationTimeSeconds
    323: (N9UTCTimeField, [True]),  # observationTimeMilliseconds
    324: (N9UTCTimeField, [False, True]),  # observationTimeMicroseconds
    325: (N9UTCTimeField, [False, False, True]),  # observationTimeNanoseconds
    365: MACField,  # staMacAddress
    366: IPField,  # staIPv4Address
    367: MACField,  # wtpMacAddress
    380: IPField,  # distinctCountOfSourceIPv4Address
    381: IPField,  # distinctCountOfDestinationIPv4Address
    382: IP6Field,  # distinctCountOfSourceIPv6Address
    383: IP6Field,  # distinctCountOfDestinationIPv6Address
    403: IPField,  # originalExporterIPv4Address
    404: IP6Field,  # originalExporterIPv6Address
    414: MACField,  # dot1qCustomerSourceMacAddress
    415: MACField,  # dot1qCustomerDestinationMacAddress
    432: IPField,  # pseudoWireDestinationIPv4Address
    24632: IPField,  # NAT_LOG_FIELD_IDX_IPV4_INT_ADDR
    24633: IPField,  # NAT_LOG_FIELD_IDX_IPV4_EXT_ADDR
    40001: IPField,  # XLATE_SRC_ADDR_IPV4
    40002: IPField,  # XLATE_DST_ADDR_IPV4
    114 + NTOP_BASE: IPField,  # UNTUNNELED_IPV4_SRC_ADDR
    116 + NTOP_BASE: IPField,  # UNTUNNELED_IPV4_DST_ADDR
    143 + NTOP_BASE: IPField,  # SIP_RTP_IPV4_SRC_ADDR
    145 + NTOP_BASE: IPField,  # SIP_RTP_IPV4_DST_ADDR
    353 + NTOP_BASE: MACField,  # DHCP_CLIENT_MAC
    396 + NTOP_BASE: IP6Field,  # UNTUNNELED_IPV6_SRC_ADDR
    397 + NTOP_BASE: IP6Field,  # UNTUNNELED_IPV6_DST_ADDR
    471 + NTOP_BASE: IPField,  # NPROBE_IPV4_ADDRESS
}


class NetflowHeaderV9(Packet):
    name = "Netflow Header V9"
    fields_desc = [ShortField("count", None),
                   IntField("sysUptime", 0),
                   UTCTimeField("unixSecs", None),
                   IntField("packageSequence", 0),
                   IntField("SourceID", 0)]

    def post_build(self, pkt, pay):
        if self.count is None:
            count = sum(1 for x in self.layers() if x in [
                NetflowFlowsetV9,
                NetflowDataflowsetV9,
                NetflowOptionsFlowsetV9]
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
                self.fieldType in NetflowV9TemplateFieldDefaultLengths):
            self.fieldLength = NetflowV9TemplateFieldDefaultLengths[
                self.fieldType
            ]

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
        _f_data = NetflowV9TemplateFieldDecoders.get(k, None)
        _f_type, _f_args = (
            _f_data if isinstance(_f_data, tuple) else (_f_data, [])
        )
        _f_kwargs = {}
        if _f_type:
            if issubclass(_f_type, _AdjustableNetflowField):
                _f_kwargs["length"] = j
            _fields_desc.append(
                _f_type(
                    NetflowV910TemplateFieldTypes.get(k, "unknown_data"),
                    0, *_f_args, **_f_kwargs
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
        IPSession.__init__(self, *args, **kwargs)
        self.definitions = {}
        self.definitions_opts = {}
        self.ignored = set()

    def _process_packet(self, pkt):
        _netflowv9_defragment_packet(pkt,
                                     self.definitions,
                                     self.definitions_opts,
                                     self.ignored)
        return pkt

    def on_packet_received(self, pkt):
        # First, defragment IP if necessary
        pkt = self._ip_process_packet(pkt)
        # Now handle NetflowV9 defragmentation
        pkt = self._process_packet(pkt)
        DefaultSession.on_packet_received(self, pkt)


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
        if self.length is None:
            pkt = pkt[:2] + struct.pack("!H", len(pkt)) + pkt[4:]
        if self.pad is None:
            # Padding 4-bytes with b"\x00"
            start = 10 + self.option_scope_length + self.option_field_length
            pkt = pkt[:start] + (-len(pkt) % 4) * b"\x00"
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
