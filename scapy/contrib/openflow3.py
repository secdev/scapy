# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

# Copyright (C) 2014 Maxence Tury <maxence.tury@ssi.gouv.fr>
# OpenFlow is an open standard used in SDN deployments.
# Based on OpenFlow v1.3.4
# Specifications can be retrieved from https://www.opennetworking.org/

# scapy.contrib.description = OpenFlow v1.3
# scapy.contrib.status = loads

from __future__ import absolute_import
import copy
import struct


from scapy.compat import orb, raw
from scapy.config import conf
from scapy.fields import BitEnumField, BitField, ByteEnumField, ByteField, \
    FieldLenField, FlagsField, IntEnumField, IntField, IPField, \
    LongField, MACField, PacketField, PacketListField, ShortEnumField, \
    ShortField, StrFixedLenField, X3BytesField, XBitField, XByteField, \
    XIntField, XShortField, PacketLenField
from scapy.layers.l2 import Ether
from scapy.layers.inet import TCP
from scapy.packet import Packet, Padding, Raw

from scapy.contrib.openflow import _ofp_header, _ofp_header_item, \
    OFPacketField, OpenFlow, _UnknownOpenFlow

#####################################################
#                 Predefined values                 #
#####################################################

ofp_port_no = {0xfffffff8: "IN_PORT",
               0xfffffff9: "TABLE",
               0xfffffffa: "NORMAL",
               0xfffffffb: "FLOOD",
               0xfffffffc: "ALL",
               0xfffffffd: "CONTROLLER",
               0xfffffffe: "LOCAL",
               0xffffffff: "ANY"}

ofp_group = {0xffffff00: "MAX",
             0xfffffffc: "ALL",
             0xffffffff: "ANY"}

ofp_table = {0xfe: "MAX",
             0xff: "ALL"}

ofp_queue = {0xffffffff: "ALL"}

ofp_meter = {0xffff0000: "MAX",
             0xfffffffd: "SLOWPATH",
             0xfffffffe: "CONTROLLER",
             0xffffffff: "ALL"}

ofp_buffer = {0xffffffff: "NO_BUFFER"}

ofp_max_len = {0xffff: "NO_BUFFER"}


#####################################################
#                 Common structures                 #
#####################################################

# The following structures will be used in different types
# of OpenFlow messages: ports, matches/OXMs, actions,
# instructions, buckets, queues, meter bands.


#                  Hello elements                   #


ofp_hello_elem_types = {1: "OFPHET_VERSIONBITMAP"}


class OFPHET(_ofp_header):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and len(_pkt) >= 2:
            t = struct.unpack("!H", _pkt[:2])[0]
            return ofp_hello_elem_cls.get(t, Raw)
        return Raw

    def extract_padding(self, s):
        return b"", s


class OFPHETVersionBitmap(_ofp_header):
    name = "OFPHET_VERSIONBITMAP"
    fields_desc = [ShortEnumField("type", 1, ofp_hello_elem_types),
                   ShortField("len", 8),
                   FlagsField("bitmap", 0, 32, ["Type 0",
                                                "OFv1.0",
                                                "OFv1.1",
                                                "OFv1.2",
                                                "OFv1.3",
                                                "OFv1.4",
                                                "OFv1.5"])]


ofp_hello_elem_cls = {1: OFPHETVersionBitmap}


#                       Ports                       #

ofp_port_config = ["PORT_DOWN",
                   "NO_STP",        # undefined in v1.3
                   "NO_RECV",
                   "NO_RECV_STP",   # undefined in v1.3
                   "NO_FLOOD",      # undefined in v1.3
                   "NO_FWD",
                   "NO_PACKET_IN"]

ofp_port_state = ["LINK_DOWN",
                  "BLOCKED",
                  "LIVE"]

ofp_port_features = ["10MB_HD",
                     "10MB_FD",
                     "100MB_HD",
                     "100MB_FD",
                     "1GB_HD",
                     "1GB_FD",
                     "10GB_FD",
                     "40GB_FD",
                     "100GB_FD",
                     "1TB_FD",
                     "OTHER",
                     "COPPER",
                     "FIBER",
                     "AUTONEG",
                     "PAUSE",
                     "PAUSE_ASYM"]


class OFPPort(Packet):
    name = "OFP_PHY_PORT"
    fields_desc = [IntEnumField("port_no", 0, ofp_port_no),
                   XIntField("pad1", 0),
                   MACField("hw_addr", "0"),
                   XShortField("pad2", 0),
                   StrFixedLenField("port_name", "", 16),
                   FlagsField("config", 0, 32, ofp_port_config),
                   FlagsField("state", 0, 32, ofp_port_state),
                   FlagsField("curr", 0, 32, ofp_port_features),
                   FlagsField("advertised", 0, 32, ofp_port_features),
                   FlagsField("supported", 0, 32, ofp_port_features),
                   FlagsField("peer", 0, 32, ofp_port_features),
                   IntField("curr_speed", 0),
                   IntField("max_speed", 0)]

    def extract_padding(self, s):
        return b"", s


#                   Matches & OXMs                  #

ofp_oxm_classes = {0: "OFPXMC_NXM_0",
                   1: "OFPXMC_NXM_1",
                   0x8000: "OFPXMC_OPENFLOW_BASIC",
                   0xffff: "OFPXMC_EXPERIMENTER"}

ofp_oxm_names = {0: "OFB_IN_PORT",
                 1: "OFB_IN_PHY_PORT",
                 2: "OFB_METADATA",
                 3: "OFB_ETH_DST",
                 4: "OFB_ETH_SRC",
                 5: "OFB_ETH_TYPE",
                 6: "OFB_VLAN_VID",
                 7: "OFB_VLAN_PCP",
                 8: "OFB_IP_DSCP",
                 9: "OFB_IP_ECN",
                 10: "OFB_IP_PROTO",
                 11: "OFB_IPV4_SRC",
                 12: "OFB_IPV4_DST",
                 13: "OFB_TCP_SRC",
                 14: "OFB_TCP_DST",
                 15: "OFB_UDP_SRC",
                 16: "OFB_UDP_DST",
                 17: "OFB_SCTP_SRC",
                 18: "OFB_SCTP_DST",
                 19: "OFB_ICMPV4_TYPE",
                 20: "OFB_ICMPV4_CODE",
                 21: "OFB_ARP_OP",
                 22: "OFB_ARP_SPA",
                 23: "OFB_ARP_TPA",
                 24: "OFB_ARP_SHA",
                 25: "OFB_ARP_THA",
                 26: "OFB_IPV6_SRC",
                 27: "OFB_IPV6_DST",
                 28: "OFB_IPV6_FLABEL",
                 29: "OFB_ICMPV6_TYPE",
                 30: "OFB_ICMPV6_CODE",
                 31: "OFB_IPV6_ND_TARGET",
                 32: "OFB_IPV6_ND_SLL",
                 33: "OFB_IPV6_ND_TLL",
                 34: "OFB_MPLS_LABEL",
                 35: "OFB_MPLS_TC",
                 36: "OFB_MPLS_BOS",
                 37: "OFB_PBB_ISID",
                 38: "OFB_TUNNEL_ID",
                 39: "OFB_IPV6_EXTHDR"}

ofp_oxm_constr = {0: ["OFBInPort", "in_port", 4],
                  1: ["OFBInPhyPort", "in_phy_port", 4],
                  2: ["OFBMetadata", "metadata", 8],
                  3: ["OFBEthDst", "eth_dst", 6],
                  4: ["OFBEthSrc", "eth_src", 6],
                  5: ["OFBEthType", "eth_type", 2],
                  6: ["OFBVLANVID", "vlan_vid", 2],
                  7: ["OFBVLANPCP", "vlan_pcp", 1],
                  8: ["OFBIPDSCP", "ip_dscp", 1],
                  9: ["OFBIPECN", "ip_ecn", 1],
                  10: ["OFBIPProto", "ip_proto", 1],
                  11: ["OFBIPv4Src", "ipv4_src", 4],
                  12: ["OFBIPv4Dst", "ipv4_dst", 4],
                  13: ["OFBTCPSrc", "tcp_src", 2],
                  14: ["OFBTCPDst", "tcp_dst", 2],
                  15: ["OFBUDPSrc", "udp_src", 2],
                  16: ["OFBUDPDst", "udp_dst", 2],
                  17: ["OFBSCTPSrc", "sctp_src", 2],
                  18: ["OFBSCTPDst", "sctp_dst", 2],
                  19: ["OFBICMPv4Type", "icmpv4_type", 1],
                  20: ["OFBICMPv4Code", "icmpv4_code", 1],
                  21: ["OFBARPOP", "arp_op", 2],
                  22: ["OFBARPSPA", "arp_spa", 4],
                  23: ["OFBARPTPA", "arp_tpa", 4],
                  24: ["OFBARPSHA", "arp_sha", 6],
                  25: ["OFBARPTHA", "arp_tha", 6],
                  26: ["OFBIPv6Src", "ipv6_src", 16],
                  27: ["OFBIPv6Dst", "ipv6_dst", 16],
                  28: ["OFBIPv6FLabel", "ipv6_flabel", 4],
                  29: ["OFBICMPv6Type", "icmpv6_type", 1],
                  30: ["OFBICMPv6Code", "icmpv6_code", 1],
                  31: ["OFBIPv6NDTarget", "ipv6_nd_target", 16],
                  32: ["OFBIPv6NDSLL", "ipv6_sll", 6],
                  33: ["OFBIPv6NDTLL", "ipv6_tll", 6],
                  34: ["OFBMPLSLabel", "mpls_label", 4],
                  35: ["OFBMPLSTC", "mpls_tc", 1],
                  36: ["OFBMPLSBoS", "mpls_bos", 1],
                  37: ["OFBPBBISID", "pbb_isid", 3],
                  38: ["OFBTunnelID", "tunnel_id", 8],
                  39: ["OFBIPv6ExtHdr", "ipv6_ext_hdr_flags", 2]}

# the ipv6flags array is useful only to the OFBIPv6ExtHdr class
ipv6flags = ["NONEXT",
             "ESP",
             "AUTH",
             "DEST",
             "FRAG",
             "ROUTER",
             "HOP",
             "UNREP",
             "UNSEQ"]

# here we fill ofp_oxm_fields with the fields that will be used
# to generate the various OXM classes
# e.g. the call to add_ofp_oxm_fields(0, ["OFBInPort", "in_port", 4])
# will add {0: [ShortEnumField("class",..), BitEnumField("field",..),..]}
ofp_oxm_fields = {}


def add_ofp_oxm_fields(i, org):
    ofp_oxm_fields[i] = [ShortEnumField("class", "OFPXMC_OPENFLOW_BASIC", ofp_oxm_classes),  # noqa: E501
                         BitEnumField("field", i // 2, 7, ofp_oxm_names),
                         BitField("hasmask", i % 2, 1)]
    ofp_oxm_fields[i].append(ByteField("len", org[2] + org[2] * (i % 2)))
    if i // 2 == 0:           # OFBInPort
        ofp_oxm_fields[i].append(IntEnumField(org[1], 0, ofp_port_no))
    elif i // 2 == 3 or i // 2 == 4:          # OFBEthSrc & OFBEthDst
        ofp_oxm_fields[i].append(MACField(org[1], None))
    elif i // 2 == 11 or i // 2 == 12:        # OFBIPv4Src & OFBIPv4Dst
        ofp_oxm_fields[i].append(IPField(org[1], "0"))
    elif i // 2 == 39:        # OFBIPv6ExtHdr
        ofp_oxm_fields[i].append(FlagsField(org[1], 0, 8 * org[2], ipv6flags))
    else:
        ofp_oxm_fields[i].append(BitField(org[1], 0, 8 * org[2]))
    if i % 2:
        ofp_oxm_fields[i].append(BitField(org[1] + "_mask", 0, 8 * org[2]))


# some HM classes are not supported par OFv1.3 but we will create them anyway
for i, cls in ofp_oxm_constr.items():
    add_ofp_oxm_fields(2 * i, cls)
    add_ofp_oxm_fields(2 * i + 1, cls)

# now we create every OXM class with the same call,
# (except that static variable create_oxm_class.i is each time different)
# and we fill ofp_oxm_cls with them
ofp_oxm_cls = {}
ofp_oxm_id_cls = {}


def _create_oxm_cls():
    # static variable initialization
    if not hasattr(_create_oxm_cls, "i"):
        _create_oxm_cls.i = 0

    index = _create_oxm_cls.i
    cls_name = ofp_oxm_constr[index // 4][0]
    # we create standard OXM then OXM ID then OXM with mask then OXM-hasmask ID
    if index % 4 == 2:
        cls_name += "HM"
    if index % 2:
        cls_name += "ID"

    oxm_name = ofp_oxm_names[index // 4]
    oxm_fields = ofp_oxm_fields[index // 2]
    # for ID classes we just want the first 4 fields (no payload)
    if index % 2:
        oxm_fields = oxm_fields[:4]

    cls = type(cls_name, (Packet,), {"name": oxm_name, "fields_desc": oxm_fields})  # noqa: E501
    # the first call to special function type will create the same class as in
    # class OFBInPort(Packet):
    # def __init__(self):
    #         self.name = "OFB_IN_PORT"
    # self.fields_desc = [ ShortEnumField("class", 0x8000, ofp_oxm_classes),
    #                              BitEnumField("field", 0, 7, ofp_oxm_names),
    #                              BitField("hasmask", 0, 1),
    #                              ByteField("len", 4),
    # IntEnumField("in_port", 0, ofp_port_no) ]

    if index % 2 == 0:
        ofp_oxm_cls[index // 2] = cls
    else:
        ofp_oxm_id_cls[index // 2] = cls
    _create_oxm_cls.i += 1
    cls.extract_padding = lambda self, s: (b"", s)
    return cls


OFBInPort = _create_oxm_cls()
OFBInPortID = _create_oxm_cls()
OFBInPortHM = _create_oxm_cls()
OFBInPortHMID = _create_oxm_cls()
OFBInPhyPort = _create_oxm_cls()
OFBInPhyPortID = _create_oxm_cls()
OFBInPhyPortHM = _create_oxm_cls()
OFBInPhyPortHMID = _create_oxm_cls()
OFBMetadata = _create_oxm_cls()
OFBMetadataID = _create_oxm_cls()
OFBMetadataHM = _create_oxm_cls()
OFBMetadataHMID = _create_oxm_cls()
OFBEthDst = _create_oxm_cls()
OFBEthDstID = _create_oxm_cls()
OFBEthDstHM = _create_oxm_cls()
OFBEthDstHMID = _create_oxm_cls()
OFBEthSrc = _create_oxm_cls()
OFBEthSrcID = _create_oxm_cls()
OFBEthSrcHM = _create_oxm_cls()
OFBEthSrcHMID = _create_oxm_cls()
OFBEthType = _create_oxm_cls()
OFBEthTypeID = _create_oxm_cls()
OFBEthTypeHM = _create_oxm_cls()
OFBEthTypeHMID = _create_oxm_cls()
OFBVLANVID = _create_oxm_cls()
OFBVLANVIDID = _create_oxm_cls()
OFBVLANVIDHM = _create_oxm_cls()
OFBVLANVIDHMID = _create_oxm_cls()
OFBVLANPCP = _create_oxm_cls()
OFBVLANPCPID = _create_oxm_cls()
OFBVLANPCPHM = _create_oxm_cls()
OFBVLANPCPHMID = _create_oxm_cls()
OFBIPDSCP = _create_oxm_cls()
OFBIPDSCPID = _create_oxm_cls()
OFBIPDSCPHM = _create_oxm_cls()
OFBIPDSCPHMID = _create_oxm_cls()
OFBIPECN = _create_oxm_cls()
OFBIPECNID = _create_oxm_cls()
OFBIPECNHM = _create_oxm_cls()
OFBIPECNHMID = _create_oxm_cls()
OFBIPProto = _create_oxm_cls()
OFBIPProtoID = _create_oxm_cls()
OFBIPProtoHM = _create_oxm_cls()
OFBIPProtoHMID = _create_oxm_cls()
OFBIPv4Src = _create_oxm_cls()
OFBIPv4SrcID = _create_oxm_cls()
OFBIPv4SrcHM = _create_oxm_cls()
OFBIPv4SrcHMID = _create_oxm_cls()
OFBIPv4Dst = _create_oxm_cls()
OFBIPv4DstID = _create_oxm_cls()
OFBIPv4DstHM = _create_oxm_cls()
OFBIPv4DstHMID = _create_oxm_cls()
OFBTCPSrc = _create_oxm_cls()
OFBTCPSrcID = _create_oxm_cls()
OFBTCPSrcHM = _create_oxm_cls()
OFBTCPSrcHMID = _create_oxm_cls()
OFBTCPDst = _create_oxm_cls()
OFBTCPDstID = _create_oxm_cls()
OFBTCPDstHM = _create_oxm_cls()
OFBTCPDstHMID = _create_oxm_cls()
OFBUDPSrc = _create_oxm_cls()
OFBUDPSrcID = _create_oxm_cls()
OFBUDPSrcHM = _create_oxm_cls()
OFBUDPSrcHMID = _create_oxm_cls()
OFBUDPDst = _create_oxm_cls()
OFBUDPDstID = _create_oxm_cls()
OFBUDPDstHM = _create_oxm_cls()
OFBUDPDstHMID = _create_oxm_cls()
OFBSCTPSrc = _create_oxm_cls()
OFBSCTPSrcID = _create_oxm_cls()
OFBSCTPSrcHM = _create_oxm_cls()
OFBSCTPSrcHMID = _create_oxm_cls()
OFBSCTPDst = _create_oxm_cls()
OFBSCTPDstID = _create_oxm_cls()
OFBSCTPDstHM = _create_oxm_cls()
OFBSCTPDstHMID = _create_oxm_cls()
OFBICMPv4Type = _create_oxm_cls()
OFBICMPv4TypeID = _create_oxm_cls()
OFBICMPv4TypeHM = _create_oxm_cls()
OFBICMPv4TypeHMID = _create_oxm_cls()
OFBICMPv4Code = _create_oxm_cls()
OFBICMPv4CodeID = _create_oxm_cls()
OFBICMPv4CodeHM = _create_oxm_cls()
OFBICMPv4CodeHMID = _create_oxm_cls()
OFBARPOP = _create_oxm_cls()
OFBARPOPID = _create_oxm_cls()
OFBARPOPHM = _create_oxm_cls()
OFBARPOPHMID = _create_oxm_cls()
OFBARPSPA = _create_oxm_cls()
OFBARPSPAID = _create_oxm_cls()
OFBARPSPAHM = _create_oxm_cls()
OFBARPSPAHMID = _create_oxm_cls()
OFBARPTPA = _create_oxm_cls()
OFBARPTPAID = _create_oxm_cls()
OFBARPTPAHM = _create_oxm_cls()
OFBARPTPAHMID = _create_oxm_cls()
OFBARPSHA = _create_oxm_cls()
OFBARPSHAID = _create_oxm_cls()
OFBARPSHAHM = _create_oxm_cls()
OFBARPSHAHMID = _create_oxm_cls()
OFBARPTHA = _create_oxm_cls()
OFBARPTHAID = _create_oxm_cls()
OFBARPTHAHM = _create_oxm_cls()
OFBARPTHAHMID = _create_oxm_cls()
OFBIPv6Src = _create_oxm_cls()
OFBIPv6SrcID = _create_oxm_cls()
OFBIPv6SrcHM = _create_oxm_cls()
OFBIPv6SrcHMID = _create_oxm_cls()
OFBIPv6Dst = _create_oxm_cls()
OFBIPv6DstID = _create_oxm_cls()
OFBIPv6DstHM = _create_oxm_cls()
OFBIPv6DstHMID = _create_oxm_cls()
OFBIPv6FLabel = _create_oxm_cls()
OFBIPv6FLabelID = _create_oxm_cls()
OFBIPv6FLabelHM = _create_oxm_cls()
OFBIPv6FLabelHMID = _create_oxm_cls()
OFBICMPv6Type = _create_oxm_cls()
OFBICMPv6TypeID = _create_oxm_cls()
OFBICMPv6TypeHM = _create_oxm_cls()
OFBICMPv6TypeHMID = _create_oxm_cls()
OFBICMPv6Code = _create_oxm_cls()
OFBICMPv6CodeID = _create_oxm_cls()
OFBICMPv6CodeHM = _create_oxm_cls()
OFBICMPv6CodeHMID = _create_oxm_cls()
OFBIPv6NDTarget = _create_oxm_cls()
OFBIPv6NDTargetID = _create_oxm_cls()
OFBIPv6NDTargetHM = _create_oxm_cls()
OFBIPv6NDTargetHMID = _create_oxm_cls()
OFBIPv6NDSLL = _create_oxm_cls()
OFBIPv6NDSLLID = _create_oxm_cls()
OFBIPv6NDSLLHM = _create_oxm_cls()
OFBIPv6NDSLLHMID = _create_oxm_cls()
OFBIPv6NDTLL = _create_oxm_cls()
OFBIPv6NDTLLID = _create_oxm_cls()
OFBIPv6NDTLLHM = _create_oxm_cls()
OFBIPv6NDTLLHMID = _create_oxm_cls()
OFBMPLSLabel = _create_oxm_cls()
OFBMPLSLabelID = _create_oxm_cls()
OFBMPLSLabelHM = _create_oxm_cls()
OFBMPLSLabelHMID = _create_oxm_cls()
OFBMPLSTC = _create_oxm_cls()
OFBMPLSTCID = _create_oxm_cls()
OFBMPLSTCHM = _create_oxm_cls()
OFBMPLSTCHMID = _create_oxm_cls()
OFBMPLSBoS = _create_oxm_cls()
OFBMPLSBoSID = _create_oxm_cls()
OFBMPLSBoSHM = _create_oxm_cls()
OFBMPLSBoSHMID = _create_oxm_cls()
OFBPBBISID = _create_oxm_cls()
OFBPBBISIDID = _create_oxm_cls()
OFBPBBISIDHM = _create_oxm_cls()
OFBPBBISIDHMID = _create_oxm_cls()
OFBTunnelID = _create_oxm_cls()
OFBTunnelIDID = _create_oxm_cls()
OFBTunnelIDHM = _create_oxm_cls()
OFBTunnelIDHMID = _create_oxm_cls()
OFBIPv6ExtHdr = _create_oxm_cls()
OFBIPv6ExtHdrID = _create_oxm_cls()
OFBIPv6ExtHdrHM = _create_oxm_cls()
OFBIPv6ExtHdrHMID = _create_oxm_cls()

# need_prereq holds a list of prerequisites defined in 7.2.3.8 of the specifications  # noqa: E501
# e.g. if you want to use an OFBTCPSrc instance (code 26)
# you first need to declare an OFBIPProto instance (code 20) with value 6,
# and if you want to use an OFBIPProto instance (still code 20)
# you first need to declare an OFBEthType instance (code 10) with value 0x0800
# (0x0800 means IPv4 by default, but you might want to use 0x86dd with IPv6)
# need_prereq codes are two times higher than previous oxm classes codes,
# except for 21 which is sort of a proxy for IPv6 (see below)
need_prereq = {14: [12, 0x1000],
               16: [10, 0x0800],    # could be 0x86dd
               18: [10, 0x0800],    # could be 0x86dd
               20: [10, 0x0800],    # could be 0x86dd
               21: [10, 0x86dd],
               22: [10, 0x0800],
               24: [10, 0x0800],
               26: [20, 6],
               28: [20, 6],
               30: [20, 17],
               32: [20, 17],
               34: [20, 132],
               36: [20, 132],
               38: [20, 1],
               40: [20, 1],
               42: [10, 0x0806],
               44: [10, 0x0806],
               46: [10, 0x0806],
               48: [10, 0x0806],
               50: [10, 0x0806],
               52: [10, 0x86dd],
               54: [10, 0x86dd],
               56: [10, 0x86dd],
               58: [21, 58],  # small trick here, we refer to normally non-
               60: [21, 58],  # existent field 21 to distinguish ipv6
               62: [58, 135],       # could be 136
               64: [58, 135],
               66: [58, 136],
               68: [10, 0x8847],    # could be 0x8848
               70: [10, 0x8847],    # could be 0x8848
               72: [10, 0x8847],    # could be 0x8848
               74: [10, 0x88e7],
               78: [10, 0x86dd]}


class OXMPacketListField(PacketListField):

    __slots__ = ["autocomplete", "index"]

    def __init__(self, name, default, cls, length_from=None, autocomplete=False):  # noqa: E501
        PacketListField.__init__(self, name, default, cls, length_from=length_from)  # noqa: E501
        self.autocomplete = autocomplete
        self.index = []

    def i2m(self, pkt, val):
            # this part makes for a faster writing of specs-compliant matches
            # expect some unwanted behaviour if you try incoherent associations
            # you might want to set autocomplete=False in __init__ method
        if self.autocomplete or conf.contribs['OPENFLOW']['prereq_autocomplete']:  # noqa: E501
            # val might be modified during the loop so we need a fixed copy
            fix_val = copy.deepcopy(val)
            for oxm in fix_val:
                f = 2 * oxm.field
                fix_index = list(self.index)
                while f in need_prereq:
                    # this loop enables a small recursion
                    # e.g. ipv6_nd<--icmpv6<--ip_proto<--eth_type
                    prereq = need_prereq[f]
                    f = prereq[0]
                    f2 = 20 if f == 21 else f       # ipv6 trick...
                    if f2 not in fix_index:
                        self.index.insert(0, f2)
                        prrq = ofp_oxm_cls[f2]()    # never HM
                        setattr(prrq, ofp_oxm_constr[f2 // 2][1], prereq[1])
                        val.insert(0, prrq)
                    # we could do more complicated stuff to
                    # make sure prerequisite order is correct
                    # but it works well when presented with any coherent input
                    # e.g. you should not mix OFBTCPSrc with OFBICMPv6Code
                    # and expect to get coherent results...
                    # you can still go manual by setting prereq_autocomplete=False  # noqa: E501
        return val

    def m2i(self, pkt, s):
        t = orb(s[2])
        nrm_t = t - t % 2
        if nrm_t not in self.index:
            self.index.append(nrm_t)
        return ofp_oxm_cls.get(t, Raw)(s)

    @staticmethod
    def _get_oxm_length(s):
        return orb(s[3])

    def addfield(self, pkt, s, val):
        return s + b"".join(raw(x) for x in self.i2m(pkt, val))

    def getfield(self, pkt, s):
        lst = []
        lim = self.length_from(pkt)
        ret = s[lim:]
        remain = s[:lim]

        while remain and len(remain) > 4:
            tmp_len = OXMPacketListField._get_oxm_length(remain) + 4
            # this could also be done by parsing oxm_fields (fixed lengths)
            if tmp_len <= 4 or len(remain) < tmp_len:
                # no incoherent length
                break
            current = remain[:tmp_len]
            remain = remain[tmp_len:]
            p = self.m2i(pkt, current)
            lst.append(p)

        self.index = []
        # since OXMPacketListField is called only twice (when OFPMatch and OFPSetField  # noqa: E501
        # classes are created) and not when you want to instantiate an OFPMatch,  # noqa: E501
        # index needs to be reinitialized, otherwise there will be some conflicts  # noqa: E501
        # e.g. if you create OFPMatch with OFBTCPSrc and then change to OFBTCPDst,  # noqa: E501
        # index will already be filled with ethertype and nwproto codes,
        # thus the corresponding fields will not be added to the packet
        return remain + ret, lst


class OXMID(Packet):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and len(_pkt) >= 2:
            t = orb(_pkt[2])
            return ofp_oxm_id_cls.get(t, Raw)
        return Raw

    def extract_padding(self, s):
        return b"", s


class OFPMatch(Packet):
    name = "OFP_MATCH"
    fields_desc = [ShortEnumField("type", 1, {0: "OFPMT_STANDARD",
                                              1: "OFPMT_OXM"}),
                   ShortField("len", None),
                   OXMPacketListField("oxm_fields", [], Packet,
                                      length_from=lambda pkt:pkt.len - 4)]

    def post_build(self, p, pay):
        tmp_len = self.len
        if tmp_len is None:
            tmp_len = len(p) + len(pay)
            p = p[:2] + struct.pack("!H", tmp_len) + p[4:]
            zero_bytes = (8 - tmp_len % 8) % 8
            p += b"\x00" * zero_bytes
        # message with user-defined length will not be automatically padded
        return p + pay

    def extract_padding(self, s):
        tmp_len = self.len
        zero_bytes = (8 - tmp_len % 8) % 8
        return s[zero_bytes:], s[:zero_bytes]

# ofp_match is no longer a fixed-length structure in v1.3
# furthermore it may include variable padding
# we introduce to that end a subclass of PacketField


class MatchField(PacketField):
    def __init__(self, name):
        PacketField.__init__(self, name, OFPMatch(), OFPMatch)

    def getfield(self, pkt, s):
        i = self.m2i(pkt, s)
        # i can be <OFPMatch> or <OFPMatch <Padding>>
        # or <OFPMatch <Raw>> or <OFPMatch <Raw <Padding>>>
        # and we want to return "", <OFPMatch> or "", <OFPMatch <Padding>>
        # or raw(<Raw>), <OFPMatch> or raw(<Raw>), <OFPMatch <Padding>>
        if Raw in i:
            r = i[Raw]
            if Padding in r:
                p = r[Padding]
                i.payload = p
                del(r.payload)
            return r.load, i
        else:
            return b"", i


#                      Actions                      #


class OpenFlow3(OpenFlow):
    name = "OpenFlow v1.3 dissector"

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and len(_pkt) >= 2:
            # port 6653 has been allocated by IANA, port 6633 should no
            # longer be used
            # OpenFlow3 function may be called with None self in OFPPacketField
            of_type = orb(_pkt[1])
            if of_type == 1:
                err_type = orb(_pkt[9])
                # err_type is a short int, but last byte is enough
                if err_type == 255:
                    err_type = 65535
                return ofp_error_cls[err_type]
            elif of_type == 18:
                mp_type = orb(_pkt[9])
                if mp_type == 255:
                    mp_type = 65535
                return ofp_multipart_request_cls[mp_type]
            elif of_type == 19:
                mp_type = orb(_pkt[9])
                if mp_type == 255:
                    mp_type = 65535
                return ofp_multipart_reply_cls[mp_type]
            else:
                return ofpt_cls[of_type]
        return _UnknownOpenFlow


ofp_action_types = {0: "OFPAT_OUTPUT",
                    1: "OFPAT_SET_VLAN_VID",
                    2: "OFPAT_SET_VLAN_PCP",
                    3: "OFPAT_STRIP_VLAN",
                    4: "OFPAT_SET_DL_SRC",
                    5: "OFPAT_SET_DL_DST",
                    6: "OFPAT_SET_NW_SRC",
                    7: "OFPAT_SET_NW_DST",
                    8: "OFPAT_SET_NW_TOS",
                    9: "OFPAT_SET_TP_SRC",
                    10: "OFPAT_SET_TP_DST",
                    # 11: "OFPAT_ENQUEUE",
                    11: "OFPAT_COPY_TTL_OUT",
                    12: "OFPAT_COPY_TTL_IN",
                    13: "OFPAT_SET_MPLS_LABEL",
                    14: "OFPAT_DEC_MPLS_TC",
                    15: "OFPAT_SET_MPLS_TTL",
                    16: "OFPAT_DEC_MPLS_TTL",
                    17: "OFPAT_PUSH_VLAN",
                    18: "OFPAT_POP_VLAN",
                    19: "OFPAT_PUSH_MPLS",
                    20: "OFPAT_POP_MPLS",
                    21: "OFPAT_SET_QUEUE",
                    22: "OFPAT_GROUP",
                    23: "OFPAT_SET_NW_TTL",
                    24: "OFPAT_DEC_NW_TTL",
                    25: "OFPAT_SET_FIELD",
                    26: "OFPAT_PUSH_PBB",
                    27: "OFPAT_POP_PBB",
                    65535: "OFPAT_EXPERIMENTER"}


class OFPAT(_ofp_header):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and len(_pkt) >= 2:
            t = struct.unpack("!H", _pkt[:2])[0]
            return ofp_action_cls.get(t, Raw)
        return Raw

    def extract_padding(self, s):
        return b"", s


class OFPATOutput(OFPAT):
    name = "OFPAT_OUTPUT"
    fields_desc = [ShortEnumField("type", 0, ofp_action_types),
                   ShortField("len", 16),
                   IntEnumField("port", 0, ofp_port_no),
                   ShortEnumField("max_len", "NO_BUFFER", ofp_max_len),
                   XBitField("pad", 0, 48)]


# the following actions are not supported by OFv1.3


class OFPATSetVLANVID(OFPAT):
    name = "OFPAT_SET_VLAN_VID"
    fields_desc = [ShortEnumField("type", 1, ofp_action_types),
                   ShortField("len", 8),
                   ShortField("vlan_vid", 0),
                   XShortField("pad", 0)]


class OFPATSetVLANPCP(OFPAT):
    name = "OFPAT_SET_VLAN_PCP"
    fields_desc = [ShortEnumField("type", 2, ofp_action_types),
                   ShortField("len", 8),
                   ByteField("vlan_pcp", 0),
                   X3BytesField("pad", 0)]


class OFPATStripVLAN(OFPAT):
    name = "OFPAT_STRIP_VLAN"
    fields_desc = [ShortEnumField("type", 3, ofp_action_types),
                   ShortField("len", 8),
                   XIntField("pad", 0)]


class OFPATSetDlSrc(OFPAT):
    name = "OFPAT_SET_DL_SRC"
    fields_desc = [ShortEnumField("type", 4, ofp_action_types),
                   ShortField("len", 16),
                   MACField("dl_addr", "0"),
                   XBitField("pad", 0, 48)]


class OFPATSetDlDst(OFPAT):
    name = "OFPAT_SET_DL_DST"
    fields_desc = [ShortEnumField("type", 5, ofp_action_types),
                   ShortField("len", 16),
                   MACField("dl_addr", "0"),
                   XBitField("pad", 0, 48)]


class OFPATSetNwSrc(OFPAT):
    name = "OFPAT_SET_NW_SRC"
    fields_desc = [ShortEnumField("type", 6, ofp_action_types),
                   ShortField("len", 8),
                   IPField("nw_addr", "0")]


class OFPATSetNwDst(OFPAT):
    name = "OFPAT_SET_NW_DST"
    fields_desc = [ShortEnumField("type", 7, ofp_action_types),
                   ShortField("len", 8),
                   IPField("nw_addr", "0")]


class OFPATSetNwToS(OFPAT):
    name = "OFPAT_SET_TP_TOS"
    fields_desc = [ShortEnumField("type", 8, ofp_action_types),
                   ShortField("len", 8),
                   ByteField("nw_tos", 0),
                   X3BytesField("pad", 0)]


class OFPATSetTpSrc(OFPAT):
    name = "OFPAT_SET_TP_SRC"
    fields_desc = [ShortEnumField("type", 9, ofp_action_types),
                   ShortField("len", 8),
                   ShortField("tp_port", 0),
                   XShortField("pad", 0)]


class OFPATSetTpDst(OFPAT):
    name = "OFPAT_SET_TP_DST"
    fields_desc = [ShortEnumField("type", 10, ofp_action_types),
                   ShortField("len", 8),
                   ShortField("tp_port", 0),
                   XShortField("pad", 0)]

# class OFPATEnqueue(OFPAT):
#       name = "OFPAT_ENQUEUE"
#       fields_desc = [ ShortEnumField("type", 11, ofp_action_types),
#                       ShortField("len", 16),
#                       ShortField("port", 0),
#                       XBitField("pad", 0, 48),
#                       IntEnumField("queue_id", 0, ofp_queue) ]


class OFPATSetMPLSLabel(OFPAT):
    name = "OFPAT_SET_MPLS_LABEL"
    fields_desc = [ShortEnumField("type", 13, ofp_action_types),
                   ShortField("len", 8),
                   IntField("mpls_label", 0)]


class OFPATSetMPLSTC(OFPAT):
    name = "OFPAT_SET_MPLS_TC"
    fields_desc = [ShortEnumField("type", 14, ofp_action_types),
                   ShortField("len", 8),
                   ByteField("mpls_tc", 0),
                   X3BytesField("pad", 0)]

# end of unsupported actions


class OFPATCopyTTLOut(OFPAT):
    name = "OFPAT_COPY_TTL_OUT"
    fields_desc = [ShortEnumField("type", 11, ofp_action_types),
                   ShortField("len", 8),
                   XIntField("pad", 0)]


class OFPATCopyTTLIn(OFPAT):
    name = "OFPAT_COPY_TTL_IN"
    fields_desc = [ShortEnumField("type", 12, ofp_action_types),
                   ShortField("len", 8),
                   XIntField("pad", 0)]


class OFPATSetMPLSTTL(OFPAT):
    name = "OFPAT_SET_MPLS_TTL"
    fields_desc = [ShortEnumField("type", 15, ofp_action_types),
                   ShortField("len", 8),
                   ByteField("mpls_ttl", 0),
                   X3BytesField("pad", 0)]


class OFPATDecMPLSTTL(OFPAT):
    name = "OFPAT_DEC_MPLS_TTL"
    fields_desc = [ShortEnumField("type", 16, ofp_action_types),
                   ShortField("len", 8),
                   XIntField("pad", 0)]


class OFPATPushVLAN(OFPAT):
    name = "OFPAT_PUSH_VLAN"
    fields_desc = [ShortEnumField("type", 17, ofp_action_types),
                   ShortField("len", 8),
                   ShortField("ethertype", 0x8100),    # or 0x88a8
                   XShortField("pad", 0)]


class OFPATPopVLAN(OFPAT):
    name = "OFPAT_POP_VLAN"
    fields_desc = [ShortEnumField("type", 18, ofp_action_types),
                   ShortField("len", 8),
                   XIntField("pad", 0)]


class OFPATPushMPLS(OFPAT):
    name = "OFPAT_PUSH_MPLS"
    fields_desc = [ShortEnumField("type", 19, ofp_action_types),
                   ShortField("len", 8),
                   ShortField("ethertype", 0x8847),    # or 0x8848
                   XShortField("pad", 0)]


class OFPATPopMPLS(OFPAT):
    name = "OFPAT_POP_MPLS"
    fields_desc = [ShortEnumField("type", 20, ofp_action_types),
                   ShortField("len", 8),
                   ShortField("ethertype", 0x8847),    # or 0x8848
                   XShortField("pad", 0)]


class OFPATSetQueue(OFPAT):
    name = "OFPAT_SET_QUEUE"
    fields_desc = [ShortEnumField("type", 21, ofp_action_types),
                   ShortField("len", 8),
                   IntEnumField("queue_id", 0, ofp_queue)]


class OFPATGroup(OFPAT):
    name = "OFPAT_GROUP"
    fields_desc = [ShortEnumField("type", 22, ofp_action_types),
                   ShortField("len", 8),
                   IntEnumField("group_id", 0, ofp_group)]


class OFPATSetNwTTL(OFPAT):
    name = "OFPAT_SET_NW_TTL"
    fields_desc = [ShortEnumField("type", 23, ofp_action_types),
                   ShortField("len", 8),
                   ByteField("nw_ttl", 0),
                   X3BytesField("pad", 0)]


class OFPATDecNwTTL(OFPAT):
    name = "OFPAT_DEC_NW_TTL"
    fields_desc = [ShortEnumField("type", 24, ofp_action_types),
                   ShortField("len", 8),
                   XIntField("pad", 0)]


class OFPATSetField(OFPAT):
    name = "OFPAT_SET_FIELD"
    fields_desc = [ShortEnumField("type", 25, ofp_action_types),
                   ShortField("len", None),
                   # there should not be more than one oxm tlv
                   OXMPacketListField("field", [], Packet,
                                      length_from=lambda pkt:pkt.len - 4,
                                      # /!\ contains padding!
                                      autocomplete=False)]

    def post_build(self, p, pay):
        tmp_len = self.len
        zero_bytes = 0
        if tmp_len is None:
            tmp_len = len(p) + len(pay)
            zero_bytes = (8 - tmp_len % 8) % 8
            tmp_len = tmp_len + zero_bytes    # add padding length
            p = p[:2] + struct.pack("!H", tmp_len) + p[4:]
        else:
            zero_bytes = (8 - tmp_len % 8) % 8
        # every message will be padded correctly
        p += b"\x00" * zero_bytes
        return p + pay

    def extract_padding(self, s):
        return b"", s


class OFPATPushPBB(OFPAT):
    name = "OFPAT_PUSH_PBB"
    fields_desc = [ShortEnumField("type", 26, ofp_action_types),
                   ShortField("len", 8),
                   ShortField("ethertype", 0x88e7),
                   XShortField("pad", 0)]


class OFPATPopPBB(OFPAT):
    name = "OFPAT_POP_PBB"
    fields_desc = [ShortEnumField("type", 27, ofp_action_types),
                   ShortField("len", 8),
                   XIntField("pad", 0)]


class OFPATExperimenter(OFPAT):
    name = "OFPAT_EXPERIMENTER"
    fields_desc = [ShortEnumField("type", 65535, ofp_action_types),
                   ShortField("len", 8),
                   IntField("experimenter", 0)]


ofp_action_cls = {0: OFPATOutput,
                  1: OFPATSetVLANVID,
                  2: OFPATSetVLANPCP,
                  3: OFPATStripVLAN,
                  4: OFPATSetDlSrc,
                  5: OFPATSetDlDst,
                  6: OFPATSetNwSrc,
                  7: OFPATSetNwDst,
                  8: OFPATSetNwToS,
                  9: OFPATSetTpSrc,
                  10: OFPATSetTpDst,
                  # 11: OFPATEnqueue,
                  11: OFPATCopyTTLOut,
                  12: OFPATCopyTTLIn,
                  13: OFPATSetMPLSLabel,
                  14: OFPATSetMPLSTC,
                  15: OFPATSetMPLSTTL,
                  16: OFPATDecMPLSTTL,
                  17: OFPATPushVLAN,
                  18: OFPATPopVLAN,
                  19: OFPATPushMPLS,
                  20: OFPATPopMPLS,
                  21: OFPATSetQueue,
                  22: OFPATGroup,
                  23: OFPATSetNwTTL,
                  24: OFPATDecNwTTL,
                  25: OFPATSetField,
                  26: OFPATPushPBB,
                  27: OFPATPopPBB,
                  65535: OFPATExperimenter}


#                     Action IDs                    #

class OFPATID(_ofp_header):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and len(_pkt) >= 2:
            t = struct.unpack("!H", _pkt[:2])[0]
            return ofp_action_id_cls.get(t, Raw)
        return Raw

    def extract_padding(self, s):
        return b"", s

# length is computed as in instruction structures,
# so we reuse _ofp_header


class OFPATOutputID(OFPATID):
    name = "OFPAT_OUTPUT"
    fields_desc = [ShortEnumField("type", 0, ofp_action_types),
                   ShortField("len", 4)]

# the following actions are not supported by OFv1.3


class OFPATSetVLANVIDID(OFPATID):
    name = "OFPAT_SET_VLAN_VID"
    fields_desc = [ShortEnumField("type", 1, ofp_action_types),
                   ShortField("len", 4)]


class OFPATSetVLANPCPID(OFPATID):
    name = "OFPAT_SET_VLAN_PCP"
    fields_desc = [ShortEnumField("type", 2, ofp_action_types),
                   ShortField("len", 4)]


class OFPATStripVLANID(OFPATID):
    name = "OFPAT_STRIP_VLAN"
    fields_desc = [ShortEnumField("type", 3, ofp_action_types),
                   ShortField("len", 4)]


class OFPATSetDlSrcID(OFPATID):
    name = "OFPAT_SET_DL_SRC"
    fields_desc = [ShortEnumField("type", 4, ofp_action_types),
                   ShortField("len", 4)]


class OFPATSetDlDstID(OFPATID):
    name = "OFPAT_SET_DL_DST"
    fields_desc = [ShortEnumField("type", 5, ofp_action_types),
                   ShortField("len", 4)]


class OFPATSetNwSrcID(OFPATID):
    name = "OFPAT_SET_NW_SRC"
    fields_desc = [ShortEnumField("type", 6, ofp_action_types),
                   ShortField("len", 4)]


class OFPATSetNwDstID(OFPATID):
    name = "OFPAT_SET_NW_DST"
    fields_desc = [ShortEnumField("type", 7, ofp_action_types),
                   ShortField("len", 4)]


class OFPATSetNwToSID(OFPATID):
    name = "OFPAT_SET_TP_TOS"
    fields_desc = [ShortEnumField("type", 8, ofp_action_types),
                   ShortField("len", 4)]


class OFPATSetTpSrcID(OFPATID):
    name = "OFPAT_SET_TP_SRC"
    fields_desc = [ShortEnumField("type", 9, ofp_action_types),
                   ShortField("len", 4)]


class OFPATSetTpDstID(OFPATID):
    name = "OFPAT_SET_TP_DST"
    fields_desc = [ShortEnumField("type", 10, ofp_action_types),
                   ShortField("len", 4)]

# class OFPATEnqueueID(OFPAT):
#       name = "OFPAT_ENQUEUE"
#       fields_desc = [ ShortEnumField("type", 11, ofp_action_types),
#                       ShortField("len", 4) ]


class OFPATSetMPLSLabelID(OFPATID):
    name = "OFPAT_SET_MPLS_LABEL"
    fields_desc = [ShortEnumField("type", 13, ofp_action_types),
                   ShortField("len", 4)]


class OFPATSetMPLSTCID(OFPATID):
    name = "OFPAT_SET_MPLS_TC"
    fields_desc = [ShortEnumField("type", 14, ofp_action_types),
                   ShortField("len", 4)]

# end of unsupported actions


class OFPATCopyTTLOutID(OFPATID):
    name = "OFPAT_COPY_TTL_OUT"
    fields_desc = [ShortEnumField("type", 11, ofp_action_types),
                   ShortField("len", 4)]


class OFPATCopyTTLInID(OFPATID):
    name = "OFPAT_COPY_TTL_IN"
    fields_desc = [ShortEnumField("type", 12, ofp_action_types),
                   ShortField("len", 4)]


class OFPATSetMPLSTTLID(OFPATID):
    name = "OFPAT_SET_MPLS_TTL"
    fields_desc = [ShortEnumField("type", 15, ofp_action_types),
                   ShortField("len", 4)]


class OFPATDecMPLSTTLID(OFPATID):
    name = "OFPAT_DEC_MPLS_TTL"
    fields_desc = [ShortEnumField("type", 16, ofp_action_types),
                   ShortField("len", 4)]


class OFPATPushVLANID(OFPATID):
    name = "OFPAT_PUSH_VLAN"
    fields_desc = [ShortEnumField("type", 17, ofp_action_types),
                   ShortField("len", 4)]


class OFPATPopVLANID(OFPATID):
    name = "OFPAT_POP_VLAN"
    fields_desc = [ShortEnumField("type", 18, ofp_action_types),
                   ShortField("len", 4)]


class OFPATPushMPLSID(OFPATID):
    name = "OFPAT_PUSH_MPLS"
    fields_desc = [ShortEnumField("type", 19, ofp_action_types),
                   ShortField("len", 4)]


class OFPATPopMPLSID(OFPATID):
    name = "OFPAT_POP_MPLS"
    fields_desc = [ShortEnumField("type", 20, ofp_action_types),
                   ShortField("len", 4)]


class OFPATSetQueueID(OFPATID):
    name = "OFPAT_SET_QUEUE"
    fields_desc = [ShortEnumField("type", 21, ofp_action_types),
                   ShortField("len", 4)]


class OFPATGroupID(OFPATID):
    name = "OFPAT_GROUP"
    fields_desc = [ShortEnumField("type", 22, ofp_action_types),
                   ShortField("len", 4)]


class OFPATSetNwTTLID(OFPATID):
    name = "OFPAT_SET_NW_TTL"
    fields_desc = [ShortEnumField("type", 23, ofp_action_types),
                   ShortField("len", 4)]


class OFPATDecNwTTLID(OFPATID):
    name = "OFPAT_DEC_NW_TTL"
    fields_desc = [ShortEnumField("type", 24, ofp_action_types),
                   ShortField("len", 4)]


class OFPATSetFieldID(OFPATID):
    name = "OFPAT_SET_FIELD"
    fields_desc = [ShortEnumField("type", 25, ofp_action_types),
                   ShortField("len", 4)]


class OFPATPushPBBID(OFPATID):
    name = "OFPAT_PUSH_PBB"
    fields_desc = [ShortEnumField("type", 26, ofp_action_types),
                   ShortField("len", 4)]


class OFPATPopPBBID(OFPATID):
    name = "OFPAT_POP_PBB"
    fields_desc = [ShortEnumField("type", 27, ofp_action_types),
                   ShortField("len", 4)]


class OFPATExperimenterID(OFPATID):
    name = "OFPAT_EXPERIMENTER"
    fields_desc = [ShortEnumField("type", 65535, ofp_action_types),
                   ShortField("len", None)]


ofp_action_id_cls = {0: OFPATOutputID,
                     1: OFPATSetVLANVIDID,
                     2: OFPATSetVLANPCPID,
                     3: OFPATStripVLANID,
                     4: OFPATSetDlSrcID,
                     5: OFPATSetDlDstID,
                     6: OFPATSetNwSrcID,
                     7: OFPATSetNwDstID,
                     8: OFPATSetNwToSID,
                     9: OFPATSetTpSrcID,
                     10: OFPATSetTpDstID,
                     # 11: OFPATEnqueueID,
                     11: OFPATCopyTTLOutID,
                     12: OFPATCopyTTLInID,
                     13: OFPATSetMPLSLabelID,
                     14: OFPATSetMPLSTCID,
                     15: OFPATSetMPLSTTLID,
                     16: OFPATDecMPLSTTLID,
                     17: OFPATPushVLANID,
                     18: OFPATPopVLANID,
                     19: OFPATPushMPLSID,
                     20: OFPATPopMPLSID,
                     21: OFPATSetQueueID,
                     22: OFPATGroupID,
                     23: OFPATSetNwTTLID,
                     24: OFPATDecNwTTLID,
                     25: OFPATSetFieldID,
                     26: OFPATPushPBBID,
                     27: OFPATPopPBBID,
                     65535: OFPATExperimenterID}


#                    Instructions                   #


ofp_instruction_types = {1: "OFPIT_GOTO_TABLE",
                         2: "OFPIT_WRITE_METADATA",
                         3: "OFPIT_WRITE_ACTIONS",
                         4: "OFPIT_APPLY_ACTIONS",
                         5: "OFPIT_CLEAR_ACTIONS",
                         6: "OFPIT_METER",
                         65535: "OFPIT_EXPERIMENTER"}


class OFPIT(_ofp_header):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and len(_pkt) >= 2:
            t = struct.unpack("!H", _pkt[:2])[0]
            return ofp_instruction_cls.get(t, Raw)
        return Raw

    def extract_padding(self, s):
        return b"", s


class OFPITGotoTable(OFPIT):
    name = "OFPIT_GOTO_TABLE"
    fields_desc = [ShortEnumField("type", 1, ofp_instruction_types),
                   ShortField("len", 8),
                   ByteEnumField("table_id", 0, ofp_table),
                   X3BytesField("pad", 0)]


class OFPITWriteMetadata(OFPIT):
    name = "OFPIT_WRITE_METADATA"
    fields_desc = [ShortEnumField("type", 2, ofp_instruction_types),
                   ShortField("len", 24),
                   XIntField("pad", 0),
                   LongField("metadata", 0),
                   LongField("metadata_mask", 0)]


class OFPITWriteActions(OFPIT):
    name = "OFPIT_WRITE_ACTIONS"
    fields_desc = [ShortEnumField("type", 3, ofp_instruction_types),
                   ShortField("len", None),
                   XIntField("pad", 0),
                   PacketListField("actions", [], OFPAT,
                                   length_from=lambda pkt:pkt.len - 8)]


class OFPITApplyActions(OFPIT):
    name = "OFPIT_APPLY_ACTIONS"
    fields_desc = [ShortEnumField("type", 4, ofp_instruction_types),
                   ShortField("len", None),
                   XIntField("pad", 0),
                   PacketListField("actions", [], OFPAT,
                                   length_from=lambda pkt:pkt.len - 8)]


class OFPITClearActions(OFPIT):
    name = "OFPIT_CLEAR_ACTIONS"
    fields_desc = [ShortEnumField("type", 5, ofp_instruction_types),
                   ShortField("len", 8),
                   XIntField("pad", 0)]


class OFPITMeter(OFPIT):
    name = "OFPIT_METER"
    fields_desc = [ShortEnumField("type", 6, ofp_instruction_types),
                   ShortField("len", 8),
                   IntEnumField("meter_id", 1, ofp_meter)]


class OFPITExperimenter(OFPIT):
    name = "OFPIT_EXPERIMENTER"
    fields_desc = [ShortEnumField("type", 65535, ofp_instruction_types),
                   ShortField("len", None),
                   IntField("experimenter", 0)]


ofp_instruction_cls = {1: OFPITGotoTable,
                       2: OFPITWriteMetadata,
                       3: OFPITWriteActions,
                       4: OFPITApplyActions,
                       5: OFPITClearActions,
                       6: OFPITMeter,
                       65535: OFPITExperimenter}


#                  Instruction IDs                  #

# length is computed as in instruction structures,
# so we reuse _ofp_header

class OFPITID(_ofp_header):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and len(_pkt) >= 2:
            t = struct.unpack("!H", _pkt[:2])[0]
            return ofp_instruction_id_cls.get(t, Raw)
        return Raw

    def extract_padding(self, s):
        return b"", s


class OFPITGotoTableID(OFPITID):
    name = "OFPIT_GOTO_TABLE"
    fields_desc = [ShortEnumField("type", 1, ofp_instruction_types),
                   ShortField("len", 4)]


class OFPITWriteMetadataID(OFPITID):
    name = "OFPIT_WRITE_METADATA"
    fields_desc = [ShortEnumField("type", 2, ofp_instruction_types),
                   ShortField("len", 4)]


class OFPITWriteActionsID(OFPITID):
    name = "OFPIT_WRITE_ACTIONS"
    fields_desc = [ShortEnumField("type", 3, ofp_instruction_types),
                   ShortField("len", 4)]


class OFPITApplyActionsID(OFPITID):
    name = "OFPIT_APPLY_ACTIONS"
    fields_desc = [ShortEnumField("type", 4, ofp_instruction_types),
                   ShortField("len", 4)]


class OFPITClearActionsID(OFPITID):
    name = "OFPIT_CLEAR_ACTIONS"
    fields_desc = [ShortEnumField("type", 5, ofp_instruction_types),
                   ShortField("len", 4)]


class OFPITMeterID(OFPITID):
    name = "OFPIT_METER"
    fields_desc = [ShortEnumField("type", 6, ofp_instruction_types),
                   ShortField("len", 4)]


class OFPITExperimenterID(OFPITID):
    name = "OFPIT_EXPERIMENTER"
    fields_desc = [ShortEnumField("type", 65535, ofp_instruction_types),
                   ShortField("len", None)]


ofp_instruction_id_cls = {1: OFPITGotoTableID,
                          2: OFPITWriteMetadataID,
                          3: OFPITWriteActionsID,
                          4: OFPITApplyActionsID,
                          5: OFPITClearActionsID,
                          6: OFPITMeterID,
                          65535: OFPITExperimenterID}


#                      Buckets                      #

class OFPBucket(_ofp_header_item):
    name = "OFP_BUCKET"
    fields_desc = [ShortField("len", None),
                   ShortField("weight", 0),
                   IntEnumField("watch_port", 0, ofp_port_no),
                   IntEnumField("watch_group", 0, ofp_group),
                   XIntField("pad", 0),
                   PacketListField("actions", [], OFPAT,
                                   length_from=lambda pkt:pkt.len - 16)]

    def extract_padding(self, s):
        return b"", s


#                       Queues                      #


ofp_queue_property_types = {0: "OFPQT_NONE",
                            1: "OFPQT_MIN_RATE"}


class OFPQT(_ofp_header):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and len(_pkt) >= 2:
            t = struct.unpack("!H", _pkt[:2])[0]
            return ofp_queue_property_cls.get(t, Raw)
        return Raw

    def extract_padding(self, s):
        return b"", s


class OFPQTNone(OFPQT):
    name = "OFPQT_NONE"
    fields_desc = [ShortEnumField("type", 0, ofp_queue_property_types),
                   ShortField("len", 8),
                   XIntField("pad", 0)]


class OFPQTMinRate(OFPQT):
    name = "OFPQT_MIN_RATE"
    fields_desc = [ShortEnumField("type", 1, ofp_queue_property_types),
                   ShortField("len", 16),
                   XIntField("pad1", 0),
                   ShortField("rate", 0),
                   XBitField("pad2", 0, 48)]


ofp_queue_property_cls = {0: OFPQTNone,
                          1: OFPQTMinRate}


class OFPPacketQueue(Packet):
    name = "OFP_PACKET_QUEUE"
    fields_desc = [IntEnumField("queue_id", 0, ofp_queue),
                   ShortField("len", None),
                   XShortField("pad", 0),
                   PacketListField("properties", [], OFPQT,
                                   length_from=lambda pkt:pkt.len - 8)]  # noqa: E501

    def extract_padding(self, s):
        return b"", s

    def post_build(self, p, pay):
        if self.properties == []:
            p += raw(OFPQTNone())
        if self.len is None:
            tmp_len = len(p) + len(pay)
            p = p[:4] + struct.pack("!H", tmp_len) + p[6:]
        return p + pay


#                    Meter bands                    #

ofp_meter_band_types = {0: "OFPMBT_DROP",
                        1: "OFPMBT_DSCP_REMARK",
                        65535: "OFPMBT_EXPERIMENTER"}


class OFPMBT(_ofp_header):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and len(_pkt) >= 2:
            t = struct.unpack("!H", _pkt[:2])[0]
            return ofp_meter_band_cls.get(t, Raw)
        return Raw

    def extract_padding(self, s):
        return b"", s


class OFPMBTDrop(OFPMBT):
    name = "OFPMBT_DROP"
    fields_desc = [ShortEnumField("type", 0, ofp_queue_property_types),
                   ShortField("len", 16),
                   IntField("rate", 0),
                   IntField("burst_size", 0),
                   XIntField("pad", 0)]


class OFPMBTDSCPRemark(OFPMBT):
    name = "OFPMBT_DSCP_REMARK"
    fields_desc = [ShortEnumField("type", 1, ofp_queue_property_types),
                   ShortField("len", 16),
                   IntField("rate", 0),
                   IntField("burst_size", 0),
                   ByteField("prec_level", 0),
                   X3BytesField("pad", 0)]


class OFPMBTExperimenter(OFPMBT):
    name = "OFPMBT_EXPERIMENTER"
    fields_desc = [ShortEnumField("type", 65535, ofp_queue_property_types),
                   ShortField("len", 16),
                   IntField("rate", 0),
                   IntField("burst_size", 0),
                   IntField("experimenter", 0)]


ofp_meter_band_cls = {0: OFPMBTDrop,
                      1: OFPMBTDSCPRemark,
                      2: OFPMBTExperimenter}


#####################################################
#              OpenFlow 1.3 Messages                #
#####################################################

ofp_version = {0x01: "OpenFlow 1.0",
               0x02: "OpenFlow 1.1",
               0x03: "OpenFlow 1.2",
               0x04: "OpenFlow 1.3",
               0x05: "OpenFlow 1.4"}

ofp_type = {0: "OFPT_HELLO",
            1: "OFPT_ERROR",
            2: "OFPT_ECHO_REQUEST",
            3: "OFPT_ECHO_REPLY",
            4: "OFPT_EXPERIMENTER",
            5: "OFPT_FEATURES_REQUEST",
            6: "OFPT_FEATURES_REPLY",
            7: "OFPT_GET_CONFIG_REQUEST",
            8: "OFPT_GET_CONFIG_REPLY",
            9: "OFPT_SET_CONFIG",
            10: "OFPT_PACKET_IN",
            11: "OFPT_FLOW_REMOVED",
            12: "OFPT_PORT_STATUS",
            13: "OFPT_PACKET_OUT",
            14: "OFPT_FLOW_MOD",
            15: "OFPT_GROUP_MOD",
            16: "OFPT_PORT_MOD",
            17: "OFPT_TABLE_MOD",
            18: "OFPT_MULTIPART_REQUEST",
            19: "OFPT_MULTIPART_REPLY",
            20: "OFPT_BARRIER_REQUEST",
            21: "OFPT_BARRIER_REPLY",
            22: "OFPT_QUEUE_GET_CONFIG_REQUEST",
            23: "OFPT_QUEUE_GET_CONFIG_REPLY",
            24: "OFPT_ROLE_REQUEST",
            25: "OFPT_ROLE_REPLY",
            26: "OFPT_GET_ASYNC_REQUEST",
            27: "OFPT_GET_ASYNC_REPLY",
            28: "OFPT_SET_ASYNC",
            29: "OFPT_METER_MOD"}


class OFPTHello(_ofp_header):
    name = "OFPT_HELLO"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 0, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   PacketListField("elements", [], OFPHET,
                                   length_from=lambda pkt: pkt.len - 8)]
    overload_fields = {TCP: {"sport": 6653}}

#####################################################
#                     OFPT_ERROR                    #
#####################################################


ofp_error_type = {0: "OFPET_HELLO_FAILED",
                  1: "OFPET_BAD_REQUEST",
                  2: "OFPET_BAD_ACTION",
                  3: "OFPET_BAD_INSTRUCTION",
                  4: "OFPET_BAD_MATCH",
                  5: "OFPET_FLOW_MOD_FAILED",
                  6: "OFPET_GROUP_MOD_FAILED",
                  7: "OFPET_PORT_MOD_FAILED",
                  8: "OFPET_TABLE_MOD_FAILED",
                  9: "OFPET_QUEUE_OP_FAILED",
                  10: "OFPET_SWITCH_CONFIG_FAILED",
                  11: "OFPET_ROLE_REQUEST_FAILED",
                  12: "OFPET_METER_MOD_FAILED",
                  13: "OFPET_TABLE_FEATURES_FAILED",
                  65535: "OFPET_EXPERIMENTER"}


class OFPETHelloFailed(_ofp_header):
    name = "OFPET_HELLO_FAILED"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 1, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("errtype", 0, ofp_error_type),
                   ShortEnumField("errcode", 0, {0: "OFPHFC_INCOMPATIBLE",
                                                 1: "OFPHFC_EPERM"}),
                   OFPacketField("data", "", Raw)]
    overload_fields = {TCP: {"dport": 6653}}


class OFPETBadRequest(_ofp_header):
    name = "OFPET_BAD_REQUEST"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 1, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("errtype", 1, ofp_error_type),
                   ShortEnumField("errcode", 0, {0: "OFPBRC_BAD_VERSION",
                                                 1: "OFPBRC_BAD_TYPE",
                                                 2: "OFPBRC_BAD_MULTIPART",
                                                 3: "OFPBRC_BAD_EXPERIMENTER",
                                                 4: "OFPBRC_BAD_EXP_TYPE",
                                                 5: "OFPBRC_EPERM",
                                                 6: "OFPBRC_BAD_LEN",
                                                 7: "OFPBRC_BUFFER_EMPTY",
                                                 8: "OFPBRC_BUFFER_UNKNOWN",
                                                 9: "OFPBRC_BAD_TABLE_ID",
                                                 10: "OFPBRC_IS_SLAVE",
                                                 11: "OFPBRC_BAD_PORT",
                                                 12: "OFPBRC_BAD_PACKET",
                                                 13: "OFPBRC_MULTIPART_BUFFER_OVERFLOW"}),  # noqa: E501
                   OFPacketField("data", "", Raw)]
    overload_fields = {TCP: {"dport": 6653}}


class OFPETBadAction(_ofp_header):
    name = "OFPET_BAD_ACTION"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 1, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("errtype", 2, ofp_error_type),
                   ShortEnumField("errcode", 0, {0: "OFPBAC_BAD_TYPE",
                                                 1: "OFPBAC_BAD_LEN",
                                                 2: "OFPBAC_BAD_EXPERIMENTER",
                                                 3: "OFPBAC_BAD_EXP_TYPE",
                                                 4: "OFPBAC_BAD_OUT_PORT",
                                                 5: "OFPBAC_BAD_ARGUMENT",
                                                 6: "OFPBAC_EPERM",
                                                 7: "OFPBAC_TOO_MANY",
                                                 8: "OFPBAC_BAD_QUEUE",
                                                 9: "OFPBAC_BAD_OUT_GROUP",
                                                 10: "OFPBAC_MATCH_INCONSISTENT",  # noqa: E501
                                                 11: "OFPBAC_UNSUPPORTED_ORDER",  # noqa: E501
                                                 12: "OFPBAC_BAD_TAG",
                                                 13: "OFPBAC_BAD_SET_TYPE",
                                                 14: "OFPBAC_BAD_SET_LEN",
                                                 15: "OFPBAC_BAD_SET_ARGUMENT"}),  # noqa: E501
                   OFPacketField("data", "", Raw)]
    overload_fields = {TCP: {"dport": 6653}}


class OFPETBadInstruction(_ofp_header):
    name = "OFPET_BAD_INSTRUCTION"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 1, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("errtype", 3, ofp_error_type),
                   ShortEnumField("errcode", 0, {0: "OFPBIC_UNKNOWN_INST",
                                                 1: "OFPBIC_UNSUP_INST",
                                                 2: "OFPBIC_BAD_TABLE_ID",
                                                 3: "OFPBIC_UNSUP_METADATA",
                                                 4: "OFPBIC_UNSUP_METADATA_MASK",  # noqa: E501
                                                 5: "OFPBIC_BAD_EXPERIMENTER",
                                                 6: "OFPBIC_BAD_EXP_TYPE",
                                                 7: "OFPBIC_BAD_LEN",
                                                 8: "OFPBIC_EPERM"}),
                   OFPacketField("data", "", Raw)]
    overload_fields = {TCP: {"dport": 6653}}


class OFPETBadMatch(_ofp_header):
    name = "OFPET_BAD_MATCH"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 1, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("errtype", 4, ofp_error_type),
                   ShortEnumField("errcode", 0, {0: "OFPBMC_BAD_TYPE",
                                                 1: "OFPBMC_BAD_LEN",
                                                 2: "OFPBMC_BAD_TAG",
                                                 3: "OFPBMC_BAD_DL_ADDR_MASK",
                                                 4: "OFPBMC_BAD_NW_ADDR_MASK",
                                                 5: "OFPBMC_BAD_WILDCARDS",
                                                 6: "OFPBMC_BAD_FIELD",
                                                 7: "OFPBMC_BAD_VALUE",
                                                 8: "OFPBMC_BAD_MASK",
                                                 9: "OFPBMC_BAD_PREREQ",
                                                 10: "OFPBMC_DUP_FIELD",
                                                 11: "OFPBMC_EPERM"}),
                   OFPacketField("data", "", Raw)]
    overload_fields = {TCP: {"dport": 6653}}


class OFPETFlowModFailed(_ofp_header):
    name = "OFPET_FLOW_MOD_FAILED"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 1, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("errtype", 5, ofp_error_type),
                   ShortEnumField("errcode", 0, {0: "OFPFMFC_UNKNOWN",
                                                 1: "OFPFMFC_TABLE_FULL",
                                                 2: "OFPFMFC_BAD_TABLE_ID",
                                                 3: "OFPFMFC_OVERLAP",
                                                 4: "OFPFMFC_EPERM",
                                                 5: "OFPFMFC_BAD_TIMEOUT",
                                                 6: "OFPFMFC_BAD_COMMAND",
                                                 7: "OFPFMFC_BAD_FLAGS"}),
                   OFPacketField("data", "", Raw)]
    overload_fields = {TCP: {"dport": 6653}}


class OFPETGroupModFailed(_ofp_header):
    name = "OFPET_GROUP_MOD_FAILED"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 1, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("errtype", 6, ofp_error_type),
                   ShortEnumField("errcode", 0, {0: "OFPGMFC_GROUP_EXISTS",
                                                 1: "OFPGMFC_INVALID_GROUP",
                                                 2: "OFPGMFC_WEIGHT_UNSUPPORTED",  # noqa: E501
                                                 3: "OFPGMFC_OUT_OF_GROUPS",
                                                 4: "OFPGMFC_OUT_OF_BUCKETS",
                                                 5: "OFPGMFC_CHAINING_UNSUPPORTED",  # noqa: E501
                                                 6: "OFPGMFC_WATCH_UNSUPPORTED",  # noqa: E501
                                                 7: "OFPGMFC_LOOP",
                                                 8: "OFPGMFC_UNKNOWN_GROUP",
                                                 9: "OFPGMFC_CHAINED_GROUP",
                                                 10: "OFPGMFC_BAD_TYPE",
                                                 11: "OFPGMFC_BAD_COMMAND",
                                                 12: "OFPGMFC_BAD_BUCKET",
                                                 13: "OFPGMFC_BAD_WATCH",
                                                 14: "OFPFMFC_EPERM"}),
                   OFPacketField("data", "", Raw)]
    overload_fields = {TCP: {"dport": 6653}}


class OFPETPortModFailed(_ofp_header):
    name = "OFPET_PORT_MOD_FAILED"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 1, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("errtype", 7, ofp_error_type),
                   ShortEnumField("errcode", 0, {0: "OFPPMFC_BAD_PORT",
                                                 1: "OFPPMFC_BAD_HW_ADDR",
                                                 2: "OFPPMFC_BAD_CONFIG",
                                                 3: "OFPPMFC_BAD_ADVERTISE",
                                                 4: "OFPPMFC_EPERM"}),
                   OFPacketField("data", "", Raw)]
    overload_fields = {TCP: {"dport": 6653}}


class OFPETTableModFailed(_ofp_header):
    name = "OFPET_TABLE_MOD_FAILED"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 1, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("errtype", 8, ofp_error_type),
                   ShortEnumField("errcode", 0, {0: "OFPTMFC_BAD_TABLE",
                                                 1: "OFPTMFC_BAD_CONFIG",
                                                 2: "OFPTMFC_EPERM"}),
                   OFPacketField("data", "", Raw)]
    overload_fields = {TCP: {"dport": 6653}}


class OFPETQueueOpFailed(_ofp_header):
    name = "OFPET_QUEUE_OP_FAILED"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 1, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("errtype", 9, ofp_error_type),
                   ShortEnumField("errcode", 0, {0: "OFPQOFC_BAD_PORT",
                                                 1: "OFPQOFC_BAD_QUEUE",
                                                 2: "OFPQOFC_EPERM"}),
                   OFPacketField("data", "", Raw)]
    overload_fields = {TCP: {"dport": 6653}}


class OFPETSwitchConfigFailed(_ofp_header):
    name = "OFPET_SWITCH_CONFIG_FAILED"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 1, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("errtype", 10, ofp_error_type),
                   ShortEnumField("errcode", 0, {0: "OFPSCFC_BAD_FLAGS",
                                                 1: "OFPSCFC_BAD_LEN",
                                                 2: "OFPSCFC_EPERM"}),
                   OFPacketField("data", "", Raw)]
    overload_fields = {TCP: {"dport": 6653}}


class OFPETRoleRequestFailed(_ofp_header):
    name = "OFPET_ROLE_REQUEST_FAILED"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 1, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("errtype", 11, ofp_error_type),
                   ShortEnumField("errcode", 0, {0: "OFPRRFC_STALE",
                                                 1: "OFPRRFC_UNSUP",
                                                 2: "OFPRRFC_BAD_ROLE"}),
                   OFPacketField("data", "", Raw)]
    overload_fields = {TCP: {"dport": 6653}}


class OFPETMeterModFailed(_ofp_header):
    name = "OFPET_METER_MOD_FAILED"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 1, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("errtype", 12, ofp_error_type),
                   ShortEnumField("errcode", 0, {0: "OFPMMFC_UNKNOWN",
                                                 1: "OFPMMFC_METER_EXISTS",
                                                 2: "OFPMMFC_INVALID_METER",
                                                 3: "OFPMMFC_UNKNOWN_METER",
                                                 4: "OFPMMFC_BAD_COMMAND",
                                                 5: "OFPMMFC_BAD_FLAGS",
                                                 6: "OFPMMFC_BAD_RATE",
                                                 7: "OFPMMFC_BAD_BURST",
                                                 8: "OFPMMFC_BAD_BAND",
                                                 9: "OFPMMFC_BAD_BAND_VALUE",
                                                 10: "OFPMMFC_OUT_OF_METERS",
                                                 11: "OFPMMFC_OUT_OF_BANDS"}),
                   OFPacketField("data", "", Raw)]
    overload_fields = {TCP: {"dport": 6653}}


class OFPETTableFeaturesFailed(_ofp_header):
    name = "OFPET_TABLE_FEATURES_FAILED"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 1, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("errtype", 13, ofp_error_type),
                   ShortEnumField("errcode", 0, {0: "OFPTFFC_BAD_TABLE",
                                                 1: "OFPTFFC_BAD_METADATA",
                                                 2: "OFPTFFC_BAD_TYPE",
                                                 3: "OFPTFFC_BAD_LEN",
                                                 4: "OFPTFFC_BAD_ARGUMENT",
                                                 5: "OFPTFFC_EPERM"}),
                   OFPacketField("data", "", Raw)]
    overload_fields = {TCP: {"dport": 6653}}


class OFPETExperimenter(_ofp_header):
    name = "OFPET_EXPERIMENTER"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 1, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("errtype", "OFPET_EXPERIMENTER", ofp_error_type),  # noqa: E501
                   ShortField("exp_type", None),
                   IntField("experimenter", None),
                   OFPacketField("data", "", Raw)]
    overload_fields = {TCP: {"dport": 6653}}


# ofp_error_cls allows generic method OpenFlow3()
# to choose the right class for dissection
ofp_error_cls = {0: OFPETHelloFailed,
                 1: OFPETBadRequest,
                 2: OFPETBadAction,
                 3: OFPETBadInstruction,
                 4: OFPETBadMatch,
                 5: OFPETFlowModFailed,
                 6: OFPETGroupModFailed,
                 7: OFPETPortModFailed,
                 8: OFPETTableModFailed,
                 9: OFPETQueueOpFailed,
                 10: OFPETSwitchConfigFailed,
                 11: OFPETRoleRequestFailed,
                 12: OFPETMeterModFailed,
                 13: OFPETTableFeaturesFailed,
                 65535: OFPETExperimenter}

#                end of OFPT_ERRORS                 #


class OFPTEchoRequest(_ofp_header):
    name = "OFPT_ECHO_REQUEST"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 2, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0)]
    overload_fields = {TCP: {"sport": 6653}}


class OFPTEchoReply(_ofp_header):
    name = "OFPT_ECHO_REPLY"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 3, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0)]
    overload_fields = {TCP: {"sport": 6653}}


class OFPTExperimenter(_ofp_header):
    name = "OFPT_EXPERIMENTER"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 4, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   IntField("experimenter", 0),
                   IntField("exp_type", 0)]
    overload_fields = {TCP: {"sport": 6653}}


class OFPTFeaturesRequest(_ofp_header):
    name = "OFPT_FEATURES_REQUEST"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 5, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0)]
    overload_fields = {TCP: {"sport": 6653}}


class OFPTFeaturesReply(_ofp_header):
    name = "OFPT_FEATURES_REPLY"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 6, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   LongField("datapath_id", 0),
                   IntField("n_buffers", 0),
                   ByteField("n_tables", 1),
                   ByteField("auxiliary_id", 0),
                   XShortField("pad", 0),
                   FlagsField("capabilities", 0, 32, ["FLOW_STATS",
                                                      "TABLE_STATS",
                                                      "PORT_STATS",
                                                      "GROUP_STATS",
                                                      "RESERVED",  # undefined
                                                      "IP_REASM",
                                                      "QUEUE_STATS",
                                                      "ARP_MATCH_IP",  # undefined  # noqa: E501
                                                      "PORT_BLOCKED"]),
                   IntField("reserved", 0)]
    overload_fields = {TCP: {"dport": 6653}}


class OFPTGetConfigRequest(_ofp_header):
    name = "OFPT_GET_CONFIG_REQUEST"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 7, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0)]
    overload_fields = {TCP: {"sport": 6653}}


class OFPTGetConfigReply(_ofp_header):
    name = "OFPT_GET_CONFIG_REPLY"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 8, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("flags", 0, {0: "FRAG_NORMAL",
                                               1: "FRAG_DROP",
                                               2: "FRAG_REASM",
                                               3: "FRAG_MASK"}),
                   ShortField("miss_send_len", 0)]
    overload_fields = {TCP: {"dport": 6653}}


class OFPTSetConfig(_ofp_header):
    name = "OFPT_SET_CONFIG"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 9, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("flags", 0, {0: "FRAG_NORMAL",
                                               1: "FRAG_DROP",
                                               2: "FRAG_REASM",
                                               3: "FRAG_MASK"}),
                   ShortField("miss_send_len", 128)]
    overload_fields = {TCP: {"sport": 6653}}


class OFPTPacketIn(_ofp_header):
    name = "OFPT_PACKET_IN"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 10, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   IntEnumField("buffer_id", "NO_BUFFER", ofp_buffer),
                   ShortField("total_len", 0),
                   ByteEnumField("reason", 0, {0: "OFPR_NO_MATCH",
                                               1: "OFPR_ACTION",
                                               2: "OFPR_INVALID_TTL"}),
                   ByteEnumField("table_id", 0, ofp_table),
                   LongField("cookie", 0),
                   MatchField("match"),
                   XShortField("pad", 0),
                   PacketField("data", "", Ether)]
    overload_fields = {TCP: {"dport": 6653}}


class OFPTFlowRemoved(_ofp_header):
    name = "OFPT_FLOW_REMOVED"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 11, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   LongField("cookie", 0),
                   ShortField("priority", 0),
                   ByteEnumField("reason", 0, {0: "OFPRR_IDLE_TIMEOUT",
                                               1: "OFPRR_HARD_TIMEOUT",
                                               2: "OFPRR_DELETE",
                                               3: "OFPRR_GROUP_DELETE"}),
                   ByteEnumField("table_id", 0, ofp_table),
                   IntField("duration_sec", 0),
                   IntField("duration_nsec", 0),
                   ShortField("idle_timeout", 0),
                   ShortField("hard_timeout", 0),
                   LongField("packet_count", 0),
                   LongField("byte_count", 0),
                   MatchField("match")]
    overload_fields = {TCP: {"dport": 6653}}


class OFPTPortStatus(_ofp_header):
    name = "OFPT_PORT_STATUS"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 12, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ByteEnumField("reason", 0, {0: "OFPPR_ADD",
                                               1: "OFPPR_DELETE",
                                               2: "OFPPR_MODIFY"}),
                   XBitField("pad", 0, 56),
                   PacketField("desc", OFPPort(), OFPPort)]
    overload_fields = {TCP: {"dport": 6653}}


class OFPTPacketOut(_ofp_header):
    name = "OFPT_PACKET_OUT"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 13, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   IntEnumField("buffer_id", "NO_BUFFER", ofp_buffer),
                   IntEnumField("in_port", "CONTROLLER", ofp_port_no),
                   FieldLenField("actions_len", None, fmt="H", length_of="actions"),  # noqa: E501
                   XBitField("pad", 0, 48),
                   PacketListField("actions", [], OFPAT,
                                   OFPAT,
                                   length_from=lambda pkt:pkt.actions_len),
                   PacketField("data", "", Ether)]
    overload_fields = {TCP: {"sport": 6653}}


class OFPTFlowMod(_ofp_header):
    name = "OFPT_FLOW_MOD"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 14, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   LongField("cookie", 0),
                   LongField("cookie_mask", 0),
                   ByteEnumField("table_id", 0, ofp_table),
                   ByteEnumField("cmd", 0, {0: "OFPFC_ADD",
                                            1: "OFPFC_MODIFY",
                                            2: "OFPFC_MODIFY_STRICT",
                                            3: "OFPFC_DELETE",
                                            4: "OFPFC_DELETE_STRICT"}),
                   ShortField("idle_timeout", 0),
                   ShortField("hard_timeout", 0),
                   ShortField("priority", 0),
                   IntEnumField("buffer_id", "NO_BUFFER", ofp_buffer),
                   IntEnumField("out_port", "ANY", ofp_port_no),
                   IntEnumField("out_group", "ANY", ofp_group),
                   FlagsField("flags", 0, 16, ["SEND_FLOW_REM",
                                               "CHECK_OVERLAP",
                                               "RESET_COUNTS",
                                               "NO_PKT_COUNTS",
                                               "NO_BYT_COUNTS"]),
                   XShortField("pad", 0),
                   MatchField("match"),
                   PacketListField("instructions", [], OFPIT,
                                              length_from=lambda pkt:pkt.len - 48 - (pkt.match.len + (8 - pkt.match.len % 8) % 8))]  # noqa: E501
    # include match padding to match.len
    overload_fields = {TCP: {"sport": 6653}}


class OFPTGroupMod(_ofp_header):
    name = "OFPT_GROUP_MOD"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 15, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("cmd", 0, {0: "OFPGC_ADD",
                                             1: "OFPGC_MODIFY",
                                             2: "OFPGC_DELETE"}),
                   ByteEnumField("group_type", 0, {0: "OFPGT_ALL",
                                                   1: "OFPGT_SELECT",
                                                   2: "OFPGT_INDIRECT",
                                                   3: "OFPGT_FF"}),
                   XByteField("pad", 0),
                   IntEnumField("group_id", 0, ofp_group),
                   PacketListField("buckets", [], OFPBucket,
                                   length_from=lambda pkt:pkt.len - 16)]
    overload_fields = {TCP: {"sport": 6653}}


class OFPTPortMod(_ofp_header):
    name = "OFPT_PORT_MOD"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 16, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   IntEnumField("port_no", 0, ofp_port_no),
                   XIntField("pad1", 0),
                   MACField("hw_addr", "0"),
                   XShortField("pad2", 0),
                   FlagsField("config", 0, 32, ofp_port_config),
                   FlagsField("mask", 0, 32, ofp_port_config),
                   FlagsField("advertise", 0, 32, ofp_port_features),
                   XIntField("pad3", 0)]
    overload_fields = {TCP: {"sport": 6653}}


class OFPTTableMod(_ofp_header):
    name = "OFPT_TABLE_MOD"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 17, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ByteEnumField("table_id", 0, ofp_table),
                   X3BytesField("pad", 0),
                   IntEnumField("config", 0, {3: "OFPTC_DEPRECATED_MASK"})]
    overload_fields = {TCP: {"sport": 6653}}

#####################################################
#                  OFPT_MULTIPART                   #
#####################################################


ofp_multipart_types = {0: "OFPMP_DESC",
                       1: "OFPMP_FLOW",
                       2: "OFPMP_AGGREGATE",
                       3: "OFPMP_TABLE",
                       4: "OFPMP_PORT_STATS",
                       5: "OFPMP_QUEUE",
                       6: "OFPMP_GROUP",
                       7: "OFPMP_GROUP_DESC",
                       8: "OFPMP_GROUP_FEATURES",
                       9: "OFPMP_METER",
                       10: "OFPMP_METER_CONFIG",
                       11: "OFPMP_METER_FEATURES",
                       12: "OFPMP_TABLE_FEATURES",
                       13: "OFPMP_PORT_DESC",
                       65535: "OFPST_VENDOR"}

ofpmp_request_flags = ["REQ_MORE"]

ofpmp_reply_flags = ["REPLY_MORE"]


class OFPMPRequestDesc(_ofp_header):
    name = "OFPMP_REQUEST_DESC"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 18, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("mp_type", 0, ofp_multipart_types),
                   FlagsField("flags", 0, 16, ofpmp_request_flags),
                   XIntField("pad", 0)]
    overload_fields = {TCP: {"sport": 6653}}


class OFPMPReplyDesc(_ofp_header):
    name = "OFPMP_REPLY_DESC"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 19, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("mp_type", 0, ofp_multipart_types),
                   FlagsField("flags", 0, 16, ofpmp_reply_flags),
                   XIntField("pad", 0),
                   StrFixedLenField("mfr_desc", "", 256),
                   StrFixedLenField("hw_desc", "", 256),
                   StrFixedLenField("sw_desc", "", 256),
                   StrFixedLenField("serial_num", "", 32),
                   StrFixedLenField("dp_desc", "", 256)]
    overload_fields = {TCP: {"dport": 6653}}


class OFPMPRequestFlow(_ofp_header):
    name = "OFPMP_REQUEST_FLOW"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 18, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("mp_type", 1, ofp_multipart_types),
                   FlagsField("flags", 0, 16, ofpmp_request_flags),
                   XIntField("pad1", 0),
                   ByteEnumField("table_id", "ALL", ofp_table),
                   X3BytesField("pad2", 0),
                   IntEnumField("out_port", "ANY", ofp_port_no),
                   IntEnumField("out_group", "ANY", ofp_group),
                   IntField("pad3", 0),
                   LongField("cookie", 0),
                   LongField("cookie_mask", 0),
                   MatchField("match")]
    overload_fields = {TCP: {"sport": 6653}}


class OFPFlowStats(_ofp_header_item):
    name = "OFP_FLOW_STATS"
    fields_desc = [ShortField("len", None),
                   ByteEnumField("table_id", 0, ofp_table),
                   XByteField("pad1", 0),
                   IntField("duration_sec", 0),
                   IntField("duration_nsec", 0),
                   ShortField("priority", 0),
                   ShortField("idle_timeout", 0),
                   ShortField("hard_timeout", 0),
                   FlagsField("flags", 0, 16, ["SEND_FLOW_REM",
                                               "CHECK_OVERLAP",
                                               "RESET_COUNTS",
                                               "NO_PKT_COUNTS",
                                               "NO_BYT_COUNTS"]),
                   IntField("pad2", 0),
                   LongField("cookie", 0),
                   LongField("packet_count", 0),
                   LongField("byte_count", 0),
                   MatchField("match"),
                   PacketListField("instructions", [], OFPIT,
                                   length_from=lambda pkt:pkt.len - 56 - pkt.match.len)]  # noqa: E501

    def extract_padding(self, s):
        return b"", s


class OFPMPReplyFlow(_ofp_header):
    name = "OFPMP_REPLY_FLOW"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 19, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("mp_type", 1, ofp_multipart_types),
                   FlagsField("flags", 0, 16, ofpmp_reply_flags),
                   XIntField("pad1", 0),
                   PacketListField("flow_stats", [], OFPFlowStats,
                                   length_from=lambda pkt:pkt.len - 16)]
    overload_fields = {TCP: {"dport": 6653}}


class OFPMPRequestAggregate(_ofp_header):
    name = "OFPMP_REQUEST_AGGREGATE"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 18, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("mp_type", 2, ofp_multipart_types),
                   FlagsField("flags", 0, 16, ofpmp_request_flags),
                   XIntField("pad1", 0),
                   ByteEnumField("table_id", "ALL", ofp_table),
                   X3BytesField("pad2", 0),
                   IntEnumField("out_port", "ANY", ofp_port_no),
                   IntEnumField("out_group", "ANY", ofp_group),
                   IntField("pad3", 0),
                   LongField("cookie", 0),
                   LongField("cookie_mask", 0),
                   MatchField("match")]
    overload_fields = {TCP: {"sport": 6653}}


class OFPMPReplyAggregate(_ofp_header):
    name = "OFPMP_REPLY_AGGREGATE"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 19, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("mp_type", 2, ofp_multipart_types),
                   FlagsField("flags", 0, 16, ofpmp_reply_flags),
                   XIntField("pad1", 0),
                   LongField("packet_count", 0),
                   LongField("byte_count", 0),
                   IntField("flow_count", 0),
                   XIntField("pad2", 0)]
    overload_fields = {TCP: {"dport": 6653}}


class OFPMPRequestTable(_ofp_header):
    name = "OFPMP_REQUEST_TABLE"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 18, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("mp_type", 3, ofp_multipart_types),
                   FlagsField("flags", 0, 16, ofpmp_request_flags),
                   XIntField("pad1", 0)]
    overload_fields = {TCP: {"sport": 6653}}


class OFPTableStats(Packet):
    name = "OFP_TABLE_STATS"
    fields_desc = [ByteEnumField("table_id", 0, ofp_table),
                   X3BytesField("pad1", 0),
                   IntField("active_count", 0),
                   LongField("lookup_count", 0),
                   LongField("matched_count", 0)]

    def extract_padding(self, s):
        return b"", s


class OFPMPReplyTable(_ofp_header):
    name = "OFPMP_REPLY_TABLE"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 19, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("mp_type", 3, ofp_multipart_types),
                   FlagsField("flags", 0, 16, ofpmp_reply_flags),
                   XIntField("pad1", 0),
                   PacketListField("table_stats", None, OFPTableStats,
                                   length_from=lambda pkt:pkt.len - 16)]
    overload_fields = {TCP: {"dport": 6653}}


class OFPMPRequestPortStats(_ofp_header):
    name = "OFPMP_REQUEST_PORT_STATS"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 18, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("mp_type", 4, ofp_multipart_types),
                   FlagsField("flags", 0, 16, ofpmp_request_flags),
                   XIntField("pad1", 0),
                   IntEnumField("port_no", "ANY", ofp_port_no),
                   XIntField("pad", 0)]
    overload_fields = {TCP: {"sport": 6653}}


class OFPPortStats(Packet):
    def extract_padding(self, s):
        return b"", s
    name = "OFP_PORT_STATS"
    fields_desc = [IntEnumField("port_no", 0, ofp_port_no),
                   XIntField("pad", 0),
                   LongField("rx_packets", 0),
                   LongField("tx_packets", 0),
                   LongField("rx_bytes", 0),
                   LongField("tx_bytes", 0),
                   LongField("rx_dropped", 0),
                   LongField("tx_dropped", 0),
                   LongField("rx_errors", 0),
                   LongField("tx_errors", 0),
                   LongField("rx_frame_err", 0),
                   LongField("rx_over_err", 0),
                   LongField("rx_crc_err", 0),
                   LongField("collisions", 0),
                   IntField("duration_sec", 0),
                   IntField("duration_nsec", 0)]


class OFPMPReplyPortStats(_ofp_header):
    name = "OFPMP_REPLY_PORT_STATS"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 19, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("mp_type", 4, ofp_multipart_types),
                   FlagsField("flags", 0, 16, ofpmp_reply_flags),
                   XIntField("pad1", 0),
                   PacketListField("port_stats", None, OFPPortStats,
                                   length_from=lambda pkt:pkt.len - 16)]
    overload_fields = {TCP: {"dport": 6653}}


class OFPMPRequestQueue(_ofp_header):
    name = "OFPMP_REQUEST_QUEUE"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 18, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("mp_type", 5, ofp_multipart_types),
                   FlagsField("flags", 0, 16, ofpmp_request_flags),
                   XIntField("pad1", 0),
                   IntEnumField("port_no", "ANY", ofp_port_no),
                   IntEnumField("queue_id", "ALL", ofp_queue)]
    overload_fields = {TCP: {"sport": 6653}}


class OFPQueueStats(Packet):
    name = "OFP_QUEUE_STATS"
    fields_desc = [IntEnumField("port_no", 0, ofp_port_no),
                   IntEnumField("queue_id", 0, ofp_queue),
                   LongField("tx_bytes", 0),
                   LongField("tx_packets", 0),
                   LongField("tx_errors", 0),
                   IntField("duration_sec", 0),
                   IntField("duration_nsec", 0)]

    def extract_padding(self, s):
        return b"", s


class OFPMPReplyQueue(_ofp_header):
    name = "OFPMP_REPLY_QUEUE"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 19, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("mp_type", 5, ofp_multipart_types),
                   FlagsField("flags", 0, 16, ofpmp_reply_flags),
                   XIntField("pad1", 0),
                   PacketListField("queue_stats", None, OFPQueueStats,
                                   length_from=lambda pkt:pkt.len - 16)]
    overload_fields = {TCP: {"dport": 6653}}


class OFPMPRequestGroup(_ofp_header):
    name = "OFPMP_REQUEST_GROUP"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 18, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("mp_type", 6, ofp_multipart_types),
                   FlagsField("flags", 0, 16, ofpmp_request_flags),
                   XIntField("pad1", 0),
                   IntEnumField("group_id", "ANY", ofp_group),
                   XIntField("pad2", 0)]
    overload_fields = {TCP: {"sport": 6653}}


class OFPBucketStats(Packet):
    name = "OFP_BUCKET_STATS"
    fields_desc = [LongField("packet_count", 0),
                   LongField("byte_count", 0)]

    def extract_padding(self, s):
        return b"", s


class OFPGroupStats(_ofp_header_item):
    name = "OFP_GROUP_STATS"
    fields_desc = [ShortField("len", None),
                   XShortField("pad1", 0),
                   IntEnumField("group_id", 0, ofp_group),
                   IntField("ref_count", 0),
                   IntField("pad2", 0),
                   LongField("packet_count", 0),
                   LongField("byte_count", 0),
                   IntField("duration_sec", 0),
                   IntField("duration_nsec", 0),
                   PacketListField("bucket_stats", None, OFPBucketStats,
                                   length_from=lambda pkt:pkt.len - 40)]

    def extract_padding(self, s):
        return b"", s


class OFPMPReplyGroup(_ofp_header):
    name = "OFPMP_REPLY_GROUP"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 19, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("mp_type", 6, ofp_multipart_types),
                   FlagsField("flags", 0, 16, ofpmp_reply_flags),
                   XIntField("pad1", 0),
                   PacketListField("group_stats", [], OFPGroupStats,
                                   length_from=lambda pkt:pkt.len - 16)]
    overload_fields = {TCP: {"dport": 6653}}


class OFPMPRequestGroupDesc(_ofp_header):
    name = "OFPMP_REQUEST_GROUP_DESC"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 18, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("mp_type", 7, ofp_multipart_types),
                   FlagsField("flags", 0, 16, ofpmp_request_flags),
                   XIntField("pad1", 0)]
    overload_fields = {TCP: {"sport": 6653}}


class OFPGroupDesc(_ofp_header_item):
    name = "OFP_GROUP_DESC"
    fields_desc = [ShortField("len", None),
                   ByteEnumField("type", 0, {0: "OFPGT_ALL",
                                             1: "OFPGT_SELECT",
                                             2: "OFPGT_INDIRECT",
                                             3: "OFPGT_FF"}),
                   XByteField("pad", 0),
                   IntEnumField("group_id", 0, ofp_group),
                   PacketListField("buckets", None, OFPBucket,
                                   length_from=lambda pkt: pkt.len - 8)]

    def extract_padding(self, s):
        return b"", s


class OFPMPReplyGroupDesc(_ofp_header):
    name = "OFPMP_REPLY_GROUP_DESC"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 19, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("mp_type", 7, ofp_multipart_types),
                   FlagsField("flags", 0, 16, ofpmp_reply_flags),
                   XIntField("pad1", 0),
                   PacketListField("group_descs", [], OFPGroupDesc,
                                   length_from=lambda pkt:pkt.len - 16)]
    overload_fields = {TCP: {"dport": 6653}}


class OFPMPRequestGroupFeatures(_ofp_header):
    name = "OFPMP_REQUEST_GROUP_FEATURES"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 18, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("mp_type", 8, ofp_multipart_types),
                   FlagsField("flags", 0, 16, ofpmp_request_flags),
                   XIntField("pad1", 0)]
    overload_fields = {TCP: {"sport": 6653}}


ofp_action_types_flags = list(ofp_action_types.values())[:-1]  # no ofpat_experimenter flag  # noqa: E501


class OFPMPReplyGroupFeatures(_ofp_header):
    name = "OFPMP_REPLY_GROUP_FEATURES"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 19, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("mp_type", 8, ofp_multipart_types),
                   FlagsField("flags", 0, 16, ofpmp_reply_flags),
                   XIntField("pad1", 0),
                   FlagsField("types", 0, 32, ["ALL",
                                               "SELECT",
                                               "INDIRECT",
                                               "FF"]),
                   FlagsField("capabilities", 0, 32, ["SELECT_WEIGHT",
                                                      "SELECT_LIVENESS",
                                                      "CHAINING",
                                                      "CHAINING_CHECKS"]),
                   IntField("max_group_all", 0),
                   IntField("max_group_select", 0),
                   IntField("max_group_indirect", 0),
                   IntField("max_group_ff", 0),
                   # no ofpat_experimenter flag
                   FlagsField("actions_all", 0, 32, ofp_action_types_flags),
                   FlagsField("actions_select", 0, 32, ofp_action_types_flags),
                   FlagsField("actions_indirect", 0, 32, ofp_action_types_flags),  # noqa: E501
                   FlagsField("actions_ff", 0, 32, ofp_action_types_flags)]
    overload_fields = {TCP: {"dport": 6653}}


class OFPMPRequestMeter(_ofp_header):
    name = "OFPMP_REQUEST_METER"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 18, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("mp_type", 9, ofp_multipart_types),
                   FlagsField("flags", 0, 16, ofpmp_request_flags),
                   XIntField("pad1", 0),
                   IntEnumField("meter_id", "ALL", ofp_meter),
                   XIntField("pad2", 0)]
    overload_fields = {TCP: {"sport": 6653}}


class OFPMeterBandStats(Packet):
    name = "OFP_METER_BAND_STATS"
    fields_desc = [LongField("packet_band_count", 0),
                   LongField("byte_band_count", 0)]

    def extract_padding(self, s):
        return b"", s


class OFPMeterStats(Packet):
    name = "OFP_GROUP_STATS"
    fields_desc = [IntEnumField("meter_id", 1, ofp_meter),
                   ShortField("len", None),
                   XBitField("pad", 0, 48),
                   IntField("flow_count", 0),
                   LongField("packet_in_count", 0),
                   LongField("byte_in_count", 0),
                   IntField("duration_sec", 0),
                   IntField("duration_nsec", 0),
                   PacketListField("band_stats", None, OFPMeterBandStats,
                                   length_from=lambda pkt:pkt.len - 40)]

    def post_build(self, p, pay):
        if self.len is None:
            tmp_len = len(p) + len(pay)
            p = p[:4] + struct.pack("!H", tmp_len) + p[6:]
        return p + pay

    def extract_padding(self, s):
        return b"", s


class OFPMPReplyMeter(_ofp_header):
    name = "OFPMP_REPLY_METER"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 19, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("mp_type", 9, ofp_multipart_types),
                   FlagsField("flags", 0, 16, ofpmp_reply_flags),
                   XIntField("pad1", 0),
                   PacketListField("meter_stats", [], OFPMeterStats,
                                   length_from=lambda pkt:pkt.len - 16)]
    overload_fields = {TCP: {"dport": 6653}}


class OFPMPRequestMeterConfig(_ofp_header):
    name = "OFPMP_REQUEST_METER_CONFIG"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 18, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("mp_type", 10, ofp_multipart_types),
                   FlagsField("flags", 0, 16, ofpmp_request_flags),
                   XIntField("pad1", 0),
                   IntEnumField("meter_id", "ALL", ofp_meter),
                   XIntField("pad2", 0)]
    overload_fields = {TCP: {"sport": 6653}}


class OFPMeterConfig(_ofp_header_item):
    name = "OFP_METER_CONFIG"
    fields_desc = [ShortField("len", None),
                   FlagsField("flags", 0, 16, ["KBPS",
                                               "PKTPS",
                                               "BURST",
                                               "STATS"]),
                   IntEnumField("meter_id", 1, ofp_meter),
                   PacketListField("bands", [], OFPMBT,
                                   length_from=lambda pkt:pkt.len - 8)]

    def extract_padding(self, s):
        return b"", s


class OFPMPReplyMeterConfig(_ofp_header):
    name = "OFPMP_REPLY_METER_CONFIG"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 19, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("mp_type", 10, ofp_multipart_types),
                   FlagsField("flags", 0, 16, ofpmp_reply_flags),
                   XIntField("pad1", 0),
                   PacketListField("meter_configs", [], OFPMeterConfig,
                                   length_from=lambda pkt:pkt.len - 16)]
    overload_fields = {TCP: {"dport": 6653}}


class OFPMPRequestMeterFeatures(_ofp_header):
    name = "OFPMP_REQUEST_METER_FEATURES"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 18, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("mp_type", 11, ofp_multipart_types),
                   FlagsField("flags", 0, 16, ofpmp_request_flags),
                   XIntField("pad1", 0)]
    overload_fields = {TCP: {"sport": 6653}}


class OFPMPReplyMeterFeatures(_ofp_header):
    name = "OFPMP_REPLY_METER_FEATURES"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 19, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("mp_type", 11, ofp_multipart_types),
                   FlagsField("flags", 0, 16, ofpmp_reply_flags),
                   XIntField("pad1", 0),
                   IntField("max_meter", 0),
                   FlagsField("band_types", 0, 32, ["DROP",
                                                    "DSCP_REMARK",
                                                    "EXPERIMENTER"]),
                   FlagsField("capabilities", 0, 32, ["KPBS",
                                                      "PKTPS",
                                                      "BURST",
                                                      "STATS"]),
                   ByteField("max_bands", 0),
                   ByteField("max_color", 0),
                   XShortField("pad2", 0)]
    overload_fields = {TCP: {"dport": 6653}}

#       table features for multipart messages       #


class OFPTFPT(Packet):
    name = "Dummy OpenFlow3 Table Features Properties Header"

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and len(_pkt) >= 2:
            t = struct.unpack("!H", _pkt[:2])[0]
            return ofp_table_features_prop_cls.get(t, Raw)
        return Raw

    def post_build(self, p, pay):
        tmp_len = self.len
        if tmp_len is None:
            tmp_len = len(p) + len(pay)
            p = p[:2] + struct.pack("!H", tmp_len) + p[4:]
        # every message will be padded correctly
        zero_bytes = (8 - tmp_len % 8) % 8
        p += b"\x00" * zero_bytes
        return p + pay

    def extract_padding(self, s):
        return b"", s


ofp_table_features_prop_types = {0: "OFPTFPT_INSTRUCTIONS",
                                 1: "OFPTFPT_INSTRUCTIONS_MISS",
                                 2: "OFPTFPT_NEXT_TABLES",
                                 3: "OFPTFPT_NEXT_TABLES_MISS",
                                 4: "OFPTFPT_WRITE_ACTIONS",
                                 5: "OFPTFPT_WRITE_ACTIONS_MISS",
                                 6: "OFPTFPT_APPLY_ACTIONS",
                                 7: "OFPTFPT_APPLY_ACTIONS_MISS",
                                 8: "OFPTFPT_MATCH",
                                 10: "OFPTFPT_WILDCARDS",
                                 12: "OFPTFPT_WRITE_SETFIELD",
                                 13: "OFPTFPT_WRITE_SETFIELD_MISS",
                                 14: "OFPTFPT_APPLY_SETFIELD",
                                 15: "OFPTFPT_APPLY_SETFIELD_MISS",
                                 65534: "OFPTFPT_EXPERIMENTER",
                                 65535: "OFPTFPT_EXPERIMENTER_MISS"}


class OFPTFPTInstructions(OFPTFPT):
    name = "OFPTFPT_INSTRUCTIONS"
    fields_desc = [ShortField("type", 0),
                   ShortField("len", None),
                   PacketListField("instruction_ids", [], OFPITID,
                                   length_from=lambda pkt:pkt.len - 4)]


class OFPTFPTInstructionsMiss(OFPTFPT):
    name = "OFPTFPT_INSTRUCTIONS_MISS"
    fields_desc = [ShortField("type", 1),
                   ShortField("len", None),
                   PacketListField("instruction_ids", [], OFPITID,
                                   length_from=lambda pkt:pkt.len - 4)]


class OFPTableID(Packet):
    name = "OFP_TABLE_ID"
    fields_desc = [ByteEnumField("table_id", 0, ofp_table)]

    def extract_padding(self, s):
        return b"", s


class OFPTFPTNextTables(OFPTFPT):
    name = "OFPTFPT_NEXT_TABLES"
    fields_desc = [ShortField("type", 2),
                   ShortField("len", None),
                   PacketListField("next_table_ids", None, OFPTableID,
                                   length_from=lambda pkt:pkt.len - 4)]


class OFPTFPTNextTablesMiss(OFPTFPT):
    name = "OFPTFPT_NEXT_TABLES_MISS"
    fields_desc = [ShortField("type", 3),
                   ShortField("len", None),
                   PacketListField("next_table_ids", None, OFPTableID,
                                   length_from=lambda pkt:pkt.len - 4)]


class OFPTFPTWriteActions(OFPTFPT):
    name = "OFPTFPT_WRITE_ACTIONS"
    fields_desc = [ShortField("type", 4),
                   ShortField("len", None),
                   PacketListField("action_ids", [], OFPATID,
                                   length_from=lambda pkt:pkt.len - 4)]


class OFPTFPTWriteActionsMiss(OFPTFPT):
    name = "OFPTFPT_WRITE_ACTIONS_MISS"
    fields_desc = [ShortField("type", 5),
                   ShortField("len", None),
                   PacketListField("action_ids", [], OFPATID,
                                   length_from=lambda pkt:pkt.len - 4)]


class OFPTFPTApplyActions(OFPTFPT):
    name = "OFPTFPT_APPLY_ACTIONS"
    fields_desc = [ShortField("type", 6),
                   ShortField("len", None),
                   PacketListField("action_ids", [], OFPATID,
                                   length_from=lambda pkt:pkt.len - 4)]


class OFPTFPTApplyActionsMiss(OFPTFPT):
    name = "OFPTFPT_APPLY_ACTIONS_MISS"
    fields_desc = [ShortField("type", 7),
                   ShortField("len", None),
                   PacketListField("action_ids", [], OFPATID,
                                   length_from=lambda pkt:pkt.len - 4)]


class OFPTFPTMatch(OFPTFPT):
    name = "OFPTFPT_MATCH"
    fields_desc = [ShortField("type", 8),
                   ShortField("len", None),
                   PacketListField("oxm_ids", [], OXMID,
                                   length_from=lambda pkt:pkt.len - 4)]


class OFPTFPTWildcards(OFPTFPT):
    name = "OFPTFPT_WILDCARDS"
    fields_desc = [ShortField("type", 10),
                   ShortField("len", None),
                   PacketListField("oxm_ids", [], OXMID,
                                   length_from=lambda pkt:pkt.len - 4)]


class OFPTFPTWriteSetField(OFPTFPT):
    name = "OFPTFPT_WRITE_SETFIELD"
    fields_desc = [ShortField("type", 12),
                   ShortField("len", None),
                   PacketListField("oxm_ids", [], OXMID,
                                   length_from=lambda pkt:pkt.len - 4)]


class OFPTFPTWriteSetFieldMiss(OFPTFPT):
    name = "OFPTFPT_WRITE_SETFIELD_MISS"
    fields_desc = [ShortField("type", 13),
                   ShortField("len", None),
                   PacketListField("oxm_ids", [], OXMID,
                                   length_from=lambda pkt:pkt.len - 4)]


class OFPTFPTApplySetField(OFPTFPT):
    name = "OFPTFPT_APPLY_SETFIELD"
    fields_desc = [ShortField("type", 14),
                   ShortField("len", None),
                   PacketListField("oxm_ids", [], OXMID,
                                   length_from=lambda pkt:pkt.len - 4)]


class OFPTFPTApplySetFieldMiss(OFPTFPT):
    name = "OFPTFPT_APPLY_SETFIELD_MISS"
    fields_desc = [ShortField("type", 15),
                   ShortField("len", None),
                   PacketListField("oxm_ids", [], OXMID,
                                   length_from=lambda pkt:pkt.len - 4)]


class OFPTFPTExperimenter(OFPTFPT):
    name = "OFPTFPT_EXPERIMENTER"
    fields_desc = [ShortField("type", 65534),
                   ShortField("len", None),
                   IntField("experimenter", 0),
                   IntField("exp_type", 0),
                   PacketLenField("experimenter_data", None, Raw,
                                  length_from=lambda pkt: pkt.len - 12)]


class OFPTFPTExperimenterMiss(OFPTFPT):
    name = "OFPTFPT_EXPERIMENTER_MISS"
    fields_desc = [ShortField("type", 65535),
                   ShortField("len", None),
                   IntField("experimenter", 0),
                   IntField("exp_type", 0),
                   PacketLenField("experimenter_data", None, Raw,
                                  length_from=lambda pkt: pkt.len - 12)]


ofp_table_features_prop_cls = {0: OFPTFPTInstructions,
                               1: OFPTFPTInstructionsMiss,
                               2: OFPTFPTNextTables,
                               3: OFPTFPTNextTablesMiss,
                               4: OFPTFPTWriteActions,
                               5: OFPTFPTWriteActionsMiss,
                               6: OFPTFPTApplyActions,
                               7: OFPTFPTApplyActionsMiss,
                               8: OFPTFPTMatch,
                               10: OFPTFPTWildcards,
                               12: OFPTFPTWriteSetField,
                               13: OFPTFPTWriteSetFieldMiss,
                               14: OFPTFPTApplySetField,
                               15: OFPTFPTApplySetFieldMiss,
                               65534: OFPTFPTExperimenter,
                               65535: OFPTFPTExperimenterMiss}


class OFPTableFeatures(_ofp_header_item):
    name = "OFP_TABLE_FEATURES"
    fields_desc = [ShortField("len", None),
                   ByteEnumField("table_id", 0, ofp_table),
                   XBitField("pad", 0, 40),
                   StrFixedLenField("table_name", "", 32),
                   LongField("metadata_match", 0),
                   LongField("metadata_write", 0),
                   IntEnumField("config", 0, {0: "OFPTC_NO_MASK",
                                              3: "OFPTC_DEPRECATED_MASK"}),
                   IntField("max_entries", 0),
                   PacketListField("properties", [], OFPTFPT,
                                   length_from=lambda pkt:pkt.len - 64)]

    def extract_padding(self, s):
        return b"", s


class OFPMPRequestTableFeatures(_ofp_header):
    name = "OFPMP_REQUEST_TABLE_FEATURES"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 18, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("mp_type", 12, ofp_multipart_types),
                   FlagsField("flags", 0, 16, ofpmp_request_flags),
                   XIntField("pad1", 0),
                   PacketListField("table_features", [], OFPTableFeatures,
                                   length_from=lambda pkt:pkt.len - 16)]
    overload_fields = {TCP: {"sport": 6653}}


class OFPMPReplyTableFeatures(_ofp_header):
    name = "OFPMP_REPLY_TABLE_FEATURES"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 19, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("mp_type", 12, ofp_multipart_types),
                   FlagsField("flags", 0, 16, ofpmp_reply_flags),
                   XIntField("pad1", 0),
                   PacketListField("table_features", [], OFPTableFeatures,
                                   length_from=lambda pkt:pkt.len - 16)]
    overload_fields = {TCP: {"dport": 6653}}

#               end of table features               #


class OFPMPRequestPortDesc(_ofp_header):
    name = "OFPMP_REQUEST_PORT_DESC"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 18, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("mp_type", 13, ofp_multipart_types),
                   FlagsField("flags", 0, 16, ofpmp_request_flags),
                   XIntField("pad1", 0),
                   IntEnumField("port_no", 0, ofp_port_no),
                   XIntField("pad", 0)]
    overload_fields = {TCP: {"sport": 6653}}


class OFPMPReplyPortDesc(_ofp_header):
    name = "OFPMP_REPLY_PORT_DESC"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 19, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("mp_type", 13, ofp_multipart_types),
                   FlagsField("flags", 0, 16, ofpmp_reply_flags),
                   XIntField("pad1", 0),
                   PacketListField("ports", None, OFPPort,
                                   length_from=lambda pkt:pkt.len - 16)]
    overload_fields = {TCP: {"dport": 6653}}


class OFPMPRequestExperimenter(_ofp_header):
    name = "OFPST_REQUEST_EXPERIMENTER"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 18, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("mp_type", 65535, ofp_multipart_types),
                   FlagsField("flags", 0, 16, ofpmp_request_flags),
                   XIntField("pad1", 0),
                   IntField("experimenter", 0),
                   IntField("exp_type", 0)]
    overload_fields = {TCP: {"sport": 6653}}


class OFPMPReplyExperimenter(_ofp_header):
    name = "OFPST_REPLY_EXPERIMENTER"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 19, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("mp_type", 65535, ofp_multipart_types),
                   FlagsField("flags", 0, 16, ofpmp_reply_flags),
                   XIntField("pad1", 0),
                   IntField("experimenter", 0),
                   IntField("exp_type", 0)]
    overload_fields = {TCP: {"dport": 6653}}


# ofp_multipart_request/reply_cls allows generic method OpenFlow3()
# to choose the right class for dissection
ofp_multipart_request_cls = {0: OFPMPRequestDesc,
                             1: OFPMPRequestFlow,
                             2: OFPMPRequestAggregate,
                             3: OFPMPRequestTable,
                             4: OFPMPRequestPortStats,
                             5: OFPMPRequestQueue,
                             6: OFPMPRequestGroup,
                             7: OFPMPRequestGroupDesc,
                             8: OFPMPRequestGroupFeatures,
                             9: OFPMPRequestMeter,
                             10: OFPMPRequestMeterConfig,
                             11: OFPMPRequestMeterFeatures,
                             12: OFPMPRequestTableFeatures,
                             13: OFPMPRequestPortDesc,
                             65535: OFPMPRequestExperimenter}

ofp_multipart_reply_cls = {0: OFPMPReplyDesc,
                           1: OFPMPReplyFlow,
                           2: OFPMPReplyAggregate,
                           3: OFPMPReplyTable,
                           4: OFPMPReplyPortStats,
                           5: OFPMPReplyQueue,
                           6: OFPMPReplyGroup,
                           7: OFPMPReplyGroupDesc,
                           8: OFPMPReplyGroupFeatures,
                           9: OFPMPReplyMeter,
                           10: OFPMPReplyMeterConfig,
                           11: OFPMPReplyMeterFeatures,
                           12: OFPMPReplyTableFeatures,
                           13: OFPMPReplyPortDesc,
                           65535: OFPMPReplyExperimenter}

#              end of OFPT_MULTIPART                #


class OFPTBarrierRequest(_ofp_header):
    name = "OFPT_BARRIER_REQUEST"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 20, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0)]
    overload_fields = {TCP: {"sport": 6653}}


class OFPTBarrierReply(_ofp_header):
    name = "OFPT_BARRIER_REPLY"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 21, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0)]
    overload_fields = {TCP: {"dport": 6653}}


class OFPTQueueGetConfigRequest(_ofp_header):
    name = "OFPT_QUEUE_GET_CONFIG_REQUEST"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 22, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   IntEnumField("port_no", "ANY", ofp_port_no),
                   XIntField("pad", 0)]
    overload_fields = {TCP: {"sport": 6653}}


class OFPTQueueGetConfigReply(_ofp_header):
    name = "OFPT_QUEUE_GET_CONFIG_REPLY"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 23, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   IntEnumField("port", 0, ofp_port_no),
                   XIntField("pad", 0),
                   PacketListField("queues", [], OFPPacketQueue,
                                   length_from=lambda pkt:pkt.len - 16)]
    overload_fields = {TCP: {"dport": 6653}}


class OFPTRoleRequest(_ofp_header):
    name = "OFPT_ROLE_REQUEST"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 24, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   IntEnumField("role", 0, {0: "OFPCR_ROLE_NOCHANGE",
                                            1: "OFPCR_ROLE_EQUAL",
                                            2: "OFPCR_ROLE_MASTER",
                                            3: "OFPCR_ROLE_SLAVE"}),
                   XIntField("pad", 0),
                   LongField("generation_id", 0)]
    overload_fields = {TCP: {"sport": 6653}}


class OFPTRoleReply(_ofp_header):
    name = "OFPT_ROLE_REPLY"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 25, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   IntEnumField("role", 0, {0: "OFPCR_ROLE_NOCHANGE",
                                            1: "OFPCR_ROLE_EQUAL",
                                            2: "OFPCR_ROLE_MASTER",
                                            3: "OFPCR_ROLE_SLAVE"}),
                   XIntField("pad", 0),
                   LongField("generation_id", 0)]
    overload_fields = {TCP: {"dport": 6653}}


class OFPTGetAsyncRequest(_ofp_header):
    name = "OFPT_GET_ASYNC_REQUEST"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 26, ofp_type),
                   ShortField("len", 8),
                   IntField("xid", 0)]
    overload_fields = {TCP: {"sport": 6653}}


ofp_packet_in_reason = ["NO_MATCH",
                        "ACTION",
                        "INVALID_TTL"]

ofp_port_reason = ["ADD",
                   "DELETE",
                   "MODIFY"]

ofp_flow_removed_reason = ["IDLE_TIMEOUT",
                           "HARD_TIMEOUT",
                           "DELETE",
                           "GROUP_DELETE"]


class OFPTGetAsyncReply(_ofp_header):
    name = "OFPT_GET_ASYNC_REPLY"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 27, ofp_type),
                   ShortField("len", 32),
                   IntField("xid", 0),
                   FlagsField("packet_in_mask_master", 0, 32, ofp_packet_in_reason),  # noqa: E501
                   FlagsField("packet_in_mask_slave", 0, 32, ofp_packet_in_reason),  # noqa: E501
                   FlagsField("port_status_mask_master", 0, 32, ofp_port_reason),  # noqa: E501
                   FlagsField("port_status_mask_slave", 0, 32, ofp_port_reason),  # noqa: E501
                   FlagsField("flow_removed_mask_master", 0, 32, ofp_flow_removed_reason),  # noqa: E501
                   FlagsField("flow_removed_mask_slave", 0, 32, ofp_flow_removed_reason)]  # noqa: E501
    overload_fields = {TCP: {"dport": 6653}}


class OFPTSetAsync(_ofp_header):
    name = "OFPT_SET_ASYNC"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 28, ofp_type),
                   ShortField("len", 32),
                   IntField("xid", 0),
                   FlagsField("packet_in_mask_master", 0, 32, ofp_packet_in_reason),  # noqa: E501
                   FlagsField("packet_in_mask_slave", 0, 32, ofp_packet_in_reason),  # noqa: E501
                   FlagsField("port_status_mask_master", 0, 32, ofp_port_reason),  # noqa: E501
                   FlagsField("port_status_mask_slave", 0, 32, ofp_port_reason),  # noqa: E501
                   FlagsField("flow_removed_mask_master", 0, 32, ofp_flow_removed_reason),  # noqa: E501
                   FlagsField("flow_removed_mask_slave", 0, 32, ofp_flow_removed_reason)]  # noqa: E501
    overload_fields = {TCP: {"sport": 6653}}


class OFPTMeterMod(_ofp_header):
    name = "OFPT_METER_MOD"
    fields_desc = [ByteEnumField("version", 0x04, ofp_version),
                   ByteEnumField("type", 29, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("cmd", 0, {0: "OFPMC_ADD",
                                             1: "OFPMC_MODIFY",
                                             2: "OFPMC_DELETE"}),
                   FlagsField("flags", 0, 16, ["KBPS",
                                               "PKTPS",
                                               "BURST",
                                               "STATS"]),
                   IntEnumField("meter_id", 1, ofp_meter),
                   PacketListField("bands", [], OFPMBT,
                                   length_from=lambda pkt:pkt.len - 16)]
    overload_fields = {TCP: {"sport": 6653}}


# ofpt_cls allows generic method OpenFlow3() to choose the right class for dissection  # noqa: E501
ofpt_cls = {0: OFPTHello,
            # 1: OFPTError,
            2: OFPTEchoRequest,
            3: OFPTEchoReply,
            4: OFPTExperimenter,
            5: OFPTFeaturesRequest,
            6: OFPTFeaturesReply,
            7: OFPTGetConfigRequest,
            8: OFPTGetConfigReply,
            9: OFPTSetConfig,
            10: OFPTPacketIn,
            11: OFPTFlowRemoved,
            12: OFPTPortStatus,
            13: OFPTPacketOut,
            14: OFPTFlowMod,
            15: OFPTGroupMod,
            16: OFPTPortMod,
            17: OFPTTableMod,
            # 18: OFPTMultipartRequest,
            # 19: OFPTMultipartReply,
            20: OFPTBarrierRequest,
            21: OFPTBarrierReply,
            22: OFPTQueueGetConfigRequest,
            23: OFPTQueueGetConfigReply,
            24: OFPTRoleRequest,
            25: OFPTRoleReply,
            26: OFPTGetAsyncRequest,
            27: OFPTGetAsyncReply,
            28: OFPTSetAsync,
            29: OFPTMeterMod}
