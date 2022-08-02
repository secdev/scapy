# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# Copyright (C) 2014 Maxence Tury <maxence.tury@ssi.gouv.fr>

"""
OpenFlow v1.0.1

OpenFlow is an open standard used in SDN deployments.
Specifications can be retrieved from https://www.opennetworking.org/
"""

# scapy.contrib.description = Openflow v1.0
# scapy.contrib.status = loads

from __future__ import absolute_import
import struct


from scapy.compat import chb, orb, raw
from scapy.config import conf
from scapy.error import warning
from scapy.fields import BitEnumField, BitField, ByteEnumField, ByteField, FieldLenField, FlagsField, IntEnumField, IntField, IPField, LongField, MACField, PacketField, PacketListField, ShortEnumField, ShortField, StrFixedLenField, X3BytesField, XBitField, XByteField, XIntField, XShortField  # noqa: E501
from scapy.layers.l2 import Ether
from scapy.layers.inet import TCP
from scapy.packet import Packet, Raw, bind_bottom_up, bind_top_down
from scapy.utils import binrepr
import scapy.libs.six as six


# If prereq_autocomplete is True then match prerequisites will be
# automatically handled. See OFPMatch class.
conf.contribs['OPENFLOW'] = {'prereq_autocomplete': True}

#####################################################
#                 Predefined values                 #
#####################################################

ofp_port_no = {0xfff8: "IN_PORT",
               0xfff9: "TABLE",
               0xfffa: "NORMAL",
               0xfffb: "FLOOD",
               0xfffc: "ALL",
               0xfffd: "CONTROLLER",
               0xfffe: "LOCAL",
               0xffff: "NONE"}

ofp_table = {0xff: "ALL"}

ofp_queue = {0xffffffff: "ALL"}

ofp_buffer = {0xffffffff: "NO_BUFFER"}

ofp_max_len = {0xffff: "NO_BUFFER"}

#####################################################
#                 Common structures                 #
#####################################################

# The following structures will be used in different types
# of OpenFlow messages: ports, matches, actions, queues.


#                     Ports                     #

ofp_port_config = ["PORT_DOWN",
                   "NO_STP",
                   "NO_RECV",
                   "NO_RECV_STP",
                   "NO_FLOOD",
                   "NO_FWD",
                   "NO_PACKET_IN"]

ofp_port_state = ["LINK_DOWN"]

ofp_port_state_stp = {0: "OFPPS_STP_LISTEN",
                      1: "OFPPS_STP_LEARN",
                      2: "OFPPS_STP_FORWARD",
                      3: "OFPPS_STP_BLOCK"}

ofp_port_features = ["10MB_HD",
                     "10MB_FD",
                     "100MB_HD",
                     "100MB_FD",
                     "1GB_HD",
                     "1GB_FD",
                     "10GB_FD",
                     "COPPER",
                     "FIBER",
                     "AUTONEG",
                     "PAUSE",
                     "PAUSE_ASYM"]


class OFPPhyPort(Packet):
    name = "OFP_PHY_PORT"
    fields_desc = [ShortEnumField("port_no", 0, ofp_port_no),
                   MACField("hw_addr", "0"),
                   StrFixedLenField("port_name", "", 16),
                   FlagsField("config", 0, 32, ofp_port_config),
                   BitEnumField("stp_state", 0, 24, ofp_port_state),
                   FlagsField("state", 0, 8, ofp_port_state),
                   FlagsField("curr", 0, 32, ofp_port_features),
                   FlagsField("advertised", 0, 32, ofp_port_features),
                   FlagsField("supported", 0, 32, ofp_port_features),
                   FlagsField("peer", 0, 32, ofp_port_features)]

    def extract_padding(self, s):
        return b"", s


class OFPMatch(Packet):
    name = "OFP_MATCH"
    fields_desc = [FlagsField("wildcards1", None, 12, ["DL_VLAN_PCP",
                                                       "NW_TOS"]),
                   BitField("nw_dst_mask", None, 6),
                   BitField("nw_src_mask", None, 6),
                   FlagsField("wildcards2", None, 8, ["IN_PORT",
                                                      "DL_VLAN",
                                                      "DL_SRC",
                                                      "DL_DST",
                                                      "DL_TYPE",
                                                      "NW_PROTO",
                                                      "TP_SRC",
                                                      "TP_DST"]),
                   ShortEnumField("in_port", None, ofp_port_no),
                   MACField("dl_src", None),
                   MACField("dl_dst", None),
                   ShortField("dl_vlan", None),
                   ByteField("dl_vlan_pcp", None),
                   XByteField("pad1", None),
                   ShortField("dl_type", None),
                   ByteField("nw_tos", None),
                   ByteField("nw_proto", None),
                   XShortField("pad2", None),
                   IPField("nw_src", "0"),
                   IPField("nw_dst", "0"),
                   ShortField("tp_src", None),
                   ShortField("tp_dst", None)]

    def extract_padding(self, s):
        return b"", s

    # with post_build we create the wildcards field bit by bit
    def post_build(self, p, pay):
        # first 10 bits of an ofp_match are always set to 0
        lst_bits = "0" * 10

        # when one field has not been declared, it is assumed to be wildcarded
        if self.wildcards1 is None:
            if self.nw_tos is None:
                lst_bits += "1"
            else:
                lst_bits += "0"
            if self.dl_vlan_pcp is None:
                lst_bits += "1"
            else:
                lst_bits += "0"
        else:
            w1 = binrepr(self.wildcards1)
            lst_bits += "0" * (2 - len(w1))
            lst_bits += w1

        # ip masks use 6 bits each
        if self.nw_dst_mask is None:
            if self.nw_dst == "0":
                lst_bits += "111111"
            # 0x100000 would be ok too (32-bit IP mask)
            else:
                lst_bits += "0" * 6
        else:
            m1 = binrepr(self.nw_dst_mask)
            lst_bits += "0" * (6 - len(m1))
            lst_bits += m1
        if self.nw_src_mask is None:
            if self.nw_src == "0":
                lst_bits += "111111"
            else:
                lst_bits += "0" * 6
        else:
            m2 = binrepr(self.nw_src_mask)
            lst_bits += "0" * (6 - len(m2))
            lst_bits += m2

        # wildcards2 works the same way as wildcards1
        if self.wildcards2 is None:
            if self.tp_dst is None:
                lst_bits += "1"
            else:
                lst_bits += "0"
            if self.tp_src is None:
                lst_bits += "1"
            else:
                lst_bits += "0"
            if self.nw_proto is None:
                lst_bits += "1"
            else:
                lst_bits += "0"
            if self.dl_type is None:
                lst_bits += "1"
            else:
                lst_bits += "0"
            if self.dl_dst is None:
                lst_bits += "1"
            else:
                lst_bits += "0"
            if self.dl_src is None:
                lst_bits += "1"
            else:
                lst_bits += "0"
            if self.dl_vlan is None:
                lst_bits += "1"
            else:
                lst_bits += "0"
            if self.in_port is None:
                lst_bits += "1"
            else:
                lst_bits += "0"
        else:
            w2 = binrepr(self.wildcards2)
            lst_bits += "0" * (8 - len(w2))
            lst_bits += w2

        # In order to write OFPMatch compliant with the specifications,
        # if prereq_autocomplete has been set to True
        # we assume ethertype=IP or nwproto=TCP when appropriate subfields are provided.  # noqa: E501
        if conf.contribs['OPENFLOW']['prereq_autocomplete']:
            if self.dl_type is None:
                if self.nw_src != "0" or self.nw_dst != "0" or \
                        self.nw_proto is not None or self.nw_tos is not None:
                    p = p[:22] + struct.pack("!H", 0x0800) + p[24:]
                    lst_bits = lst_bits[:-5] + "0" + lst_bits[-4:]
            if self.nw_proto is None:
                if self.tp_src is not None or self.tp_dst is not None:
                    p = p[:22] + struct.pack("!H", 0x0800) + p[24:]
                    lst_bits = lst_bits[:-5] + "0" + lst_bits[-4:]
                    p = p[:25] + struct.pack("!B", 0x06) + p[26:]
                    lst_bits = lst_bits[:-6] + "0" + lst_bits[-5:]

        ins = b"".join(chb(int("".join(x), 2)) for x in zip(*[iter(lst_bits)] * 8))  # noqa: E501
        p = ins + p[4:]
        return p + pay


class _ofp_header(Packet):
    name = "Dummy OpenFlow Header for some lower layers"

    def post_build(self, p, pay):
        if self.len is None:
            tmp_len = len(p) + len(pay)
            p = p[:2] + struct.pack("!H", tmp_len) + p[4:]
        return p + pay


class _ofp_header_item(Packet):
    name = "Dummy OpenFlow Header for items layers"

    def post_build(self, p, pay):
        if self.len is None:
            tmp_len = len(p) + len(pay)
            p = struct.pack("!H", tmp_len) + p[2:]
        return p + pay


#                      Actions                      #


class _UnknownOpenFlow(Raw):
    name = "Unknown OpenFlow packet"


class OpenFlow(_ofp_header):
    name = "OpenFlow dissector"

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and len(_pkt) >= 2:
            version = orb(_pkt[0])
            if version == 0x04:  # OpenFlow 1.3
                from scapy.contrib.openflow3 import OpenFlow3
                return OpenFlow3.dispatch_hook(_pkt, *args, **kargs)
            elif version == 0x01:  # OpenFlow 1.0
                # port 6653 has been allocated by IANA, port 6633 should no
                # longer be used
                # OpenFlow function may be called with a None
                # self in OFPPacketField
                of_type = orb(_pkt[1])
                if of_type == 1:
                    err_type = orb(_pkt[9])
                    # err_type is a short int, but last byte is enough
                    if err_type == 255:
                        err_type = 65535
                    return ofp_error_cls[err_type]
                elif of_type == 16:
                    mp_type = orb(_pkt[9])
                    if mp_type == 255:
                        mp_type = 65535
                    return ofp_stats_request_cls[mp_type]
                elif of_type == 17:
                    mp_type = orb(_pkt[9])
                    if mp_type == 255:
                        mp_type = 65535
                    return ofp_stats_reply_cls[mp_type]
                else:
                    return ofpt_cls[of_type]
            else:
                warning("Unknown OpenFlow packet")
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
                    11: "OFPAT_ENQUEUE",
                    65535: "OFPAT_VENDOR"}


class OFPATOutput(OpenFlow):
    name = "OFPAT_OUTPUT"
    fields_desc = [ShortEnumField("type", 0, ofp_action_types),
                   ShortField("len", 8),
                   ShortEnumField("port", 0, ofp_port_no),
                   ShortEnumField("max_len", "NO_BUFFER", ofp_max_len)]


class OFPATSetVLANVID(OpenFlow):
    name = "OFPAT_SET_VLAN_VID"
    fields_desc = [ShortEnumField("type", 1, ofp_action_types),
                   ShortField("len", 8),
                   ShortField("vlan_vid", 0),
                   XShortField("pad", 0)]


class OFPATSetVLANPCP(OpenFlow):
    name = "OFPAT_SET_VLAN_PCP"
    fields_desc = [ShortEnumField("type", 2, ofp_action_types),
                   ShortField("len", 8),
                   ByteField("vlan_pcp", 0),
                   X3BytesField("pad", 0)]


class OFPATStripVLAN(OpenFlow):
    name = "OFPAT_STRIP_VLAN"
    fields_desc = [ShortEnumField("type", 3, ofp_action_types),
                   ShortField("len", 8),
                   XIntField("pad", 0)]


class OFPATSetDlSrc(OpenFlow):
    name = "OFPAT_SET_DL_SRC"
    fields_desc = [ShortEnumField("type", 4, ofp_action_types),
                   ShortField("len", 16),
                   MACField("dl_addr", "0"),
                   XBitField("pad", 0, 48)]


class OFPATSetDlDst(OpenFlow):
    name = "OFPAT_SET_DL_DST"
    fields_desc = [ShortEnumField("type", 5, ofp_action_types),
                   ShortField("len", 16),
                   MACField("dl_addr", "0"),
                   XBitField("pad", 0, 48)]


class OFPATSetNwSrc(OpenFlow):
    name = "OFPAT_SET_NW_SRC"
    fields_desc = [ShortEnumField("type", 6, ofp_action_types),
                   ShortField("len", 8),
                   IPField("nw_addr", "0")]


class OFPATSetNwDst(OpenFlow):
    name = "OFPAT_SET_NW_DST"
    fields_desc = [ShortEnumField("type", 7, ofp_action_types),
                   ShortField("len", 8),
                   IPField("nw_addr", "0")]


class OFPATSetNwToS(OpenFlow):
    name = "OFPAT_SET_TP_TOS"
    fields_desc = [ShortEnumField("type", 8, ofp_action_types),
                   ShortField("len", 8),
                   ByteField("nw_tos", 0),
                   X3BytesField("pad", 0)]


class OFPATSetTpSrc(OpenFlow):
    name = "OFPAT_SET_TP_SRC"
    fields_desc = [ShortEnumField("type", 9, ofp_action_types),
                   ShortField("len", 8),
                   ShortField("tp_port", 0),
                   XShortField("pad", 0)]


class OFPATSetTpDst(OpenFlow):
    name = "OFPAT_SET_TP_DST"
    fields_desc = [ShortEnumField("type", 10, ofp_action_types),
                   ShortField("len", 8),
                   ShortField("tp_port", 0),
                   XShortField("pad", 0)]


class OFPATEnqueue(OpenFlow):
    name = "OFPAT_ENQUEUE"
    fields_desc = [ShortEnumField("type", 11, ofp_action_types),
                   ShortField("len", 16),
                   ShortEnumField("port", 0, ofp_port_no),
                   XBitField("pad", 0, 48),
                   IntField("queue_id", 0)]


class OFPATVendor(OpenFlow):
    name = "OFPAT_VENDOR"
    fields_desc = [ShortEnumField("type", 65535, ofp_action_types),
                   ShortField("len", 8),
                   IntField("vendor", 0)]


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
                  11: OFPATEnqueue,
                  65535: OFPATVendor}


class OFPAT(Packet):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and len(_pkt) >= 2:
            t = struct.unpack("!H", _pkt[:2])[0]
            return ofp_action_cls.get(t, Raw)
        return Raw

    def extract_padding(self, s):
        return b"", s


#                       Queues                      #


ofp_queue_property_types = {0: "OFPQT_NONE",
                            1: "OFPQT_MIN_RATE"}


class OFPQTNone(_ofp_header):
    name = "OFPQT_NONE"
    fields_desc = [ShortEnumField("type", 0, ofp_queue_property_types),
                   ShortField("len", 8),
                   XIntField("pad", 0)]


class OFPQTMinRate(_ofp_header):
    name = "OFPQT_MIN_RATE"
    fields_desc = [ShortEnumField("type", 1, ofp_queue_property_types),
                   ShortField("len", 16),
                   XIntField("pad", 0),
                   ShortField("rate", 0),
                   XBitField("pad2", 0, 48)]


ofp_queue_property_cls = {0: OFPQTNone,
                          1: OFPQTMinRate}


class OFPQT(Packet):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and len(_pkt) >= 2:
            t = struct.unpack("!H", _pkt[:2])[0]
            return ofp_queue_property_cls.get(t, Raw)
        return Raw

    def extract_padding(self, s):
        return b"", s


class OFPPacketQueue(Packet):
    name = "OFP_PACKET_QUEUE"
    fields_desc = [IntField("queue_id", 0),
                   ShortField("len", None),
                   XShortField("pad", 0),
                   PacketListField("properties", [], OFPQT,
                                   length_from=lambda pkt:pkt.len - 8)]

    def extract_padding(self, s):
        return b"", s

    def post_build(self, p, pay):
        if self.properties == []:
            p += raw(OFPQTNone())
        if self.len is None:
            tmp_len = len(p) + len(pay)
            p = p[:4] + struct.pack("!H", tmp_len) + p[6:]
        return p + pay


#####################################################
#              OpenFlow 1.0 Messages                #
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
            4: "OFPT_VENDOR",
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
            15: "OFPT_PORT_MOD",
            16: "OFPT_STATS_REQUEST",
            17: "OFPT_STATS_REPLY",
            18: "OFPT_BARRIER_REQUEST",
            19: "OFPT_BARRIER_REPLY",
            20: "OFPT_QUEUE_GET_CONFIG_REQUEST",
            21: "OFPT_QUEUE_GET_CONFIG_REPLY"}


class OFPTHello(_ofp_header):
    name = "OFPT_HELLO"
    fields_desc = [ByteEnumField("version", 0x01, ofp_version),
                   ByteEnumField("type", 0, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0)]


#####################################################
#                    OFPT_ERROR                     #
#####################################################

# this class will be used to display some messages
# sent back by the switch after an error


class OFPacketField(PacketField):
    def getfield(self, pkt, s):
        try:
            tmp_len = s[2:4]
            tmp_len = struct.unpack("!H", tmp_len)[0]
            ofload = s[:tmp_len]
            remain = s[tmp_len:]
            return remain, OpenFlow(ofload)
        except Exception:
            return "", Raw(s)


ofp_error_type = {0: "OFPET_HELLO_FAILED",
                  1: "OFPET_BAD_REQUEST",
                  2: "OFPET_BAD_ACTION",
                  3: "OFPET_FLOW_MOD_FAILED",
                  4: "OFPET_PORT_MOD_FAILED",
                  5: "OFPET_QUEUE_OP_FAILED"}


class OFPETHelloFailed(_ofp_header):
    name = "OFPET_HELLO_FAILED"
    fields_desc = [ByteEnumField("version", 0x01, ofp_version),
                   ByteEnumField("type", 1, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("errtype", 0, ofp_error_type),
                   ShortEnumField("errcode", 0, {0: "OFPHFC_INCOMPATIBLE",
                                                 1: "OFPHFC_EPERM"}),
                   OFPacketField("data", "", Raw)]


class OFPETBadRequest(_ofp_header):
    name = "OFPET_BAD_REQUEST"
    fields_desc = [ByteEnumField("version", 0x01, ofp_version),
                   ByteEnumField("type", 1, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("errtype", 1, ofp_error_type),
                   ShortEnumField("errcode", 0, {0: "OFPBRC_BAD_VERSION",
                                                 1: "OFPBRC_BAD_TYPE",
                                                 2: "OFPBRC_BAD_STAT",
                                                 3: "OFPBRC_BAD_VENDOR",
                                                 4: "OFPBRC_BAD_SUBTYPE",
                                                 5: "OFPBRC_EPERM",
                                                 6: "OFPBRC_BAD_LEN",
                                                 7: "OFPBRC_BUFFER_EMPTY",
                                                 8: "OFPBRC_BUFFER_UNKNOWN"}),
                   OFPacketField("data", "", Raw)]


class OFPETBadAction(_ofp_header):
    name = "OFPET_BAD_ACTION"
    fields_desc = [ByteEnumField("version", 0x01, ofp_version),
                   ByteEnumField("type", 1, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("errtype", 2, ofp_error_type),
                   ShortEnumField("errcode", 0, {0: "OFPBAC_BAD_TYPE",
                                                 1: "OFPBAC_BAD_LEN",
                                                 2: "OFPBAC_BAD_VENDOR",
                                                 3: "OFPBAC_BAD_VENDOR_TYPE",
                                                 4: "OFPBAC_BAD_OUT_PORT",
                                                 5: "OFPBAC_BAD_ARGUMENT",
                                                 6: "OFPBAC_EPERM",
                                                 7: "OFPBAC_TOO_MANY",
                                                 8: "OFPBAC_BAD_QUEUE"}),
                   OFPacketField("data", "", Raw)]


class OFPETFlowModFailed(_ofp_header):
    name = "OFPET_FLOW_MOD_FAILED"
    fields_desc = [ByteEnumField("version", 0x01, ofp_version),
                   ByteEnumField("type", 1, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("errtype", 3, ofp_error_type),
                   ShortEnumField("errcode", 0, {0: "OFPFMFC_ALL_TABLES_FULL",
                                                 1: "OFPFMFC_OVERLAP",
                                                 2: "OFPFMFC_EPERM",
                                                 3: "OFPFMFC_BAD_EMERG_TIMEOUT",  # noqa: E501
                                                 4: "OFPFMFC_BAD_COMMAND",
                                                 5: "OFPFMFC_UNSUPPORTED"}),
                   OFPacketField("data", "", Raw)]


class OFPETPortModFailed(_ofp_header):
    name = "OFPET_PORT_MOD_FAILED"
    fields_desc = [ByteEnumField("version", 0x01, ofp_version),
                   ByteEnumField("type", 1, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("errtype", 4, ofp_error_type),
                   ShortEnumField("errcode", 0, {0: "OFPPMFC_BAD_PORT",
                                                 1: "OFPPMFC_BAD_HW_ADDR"}),
                   OFPacketField("data", "", Raw)]


class OFPETQueueOpFailed(_ofp_header):
    name = "OFPET_QUEUE_OP_FAILED"
    fields_desc = [ByteEnumField("version", 0x01, ofp_version),
                   ByteEnumField("type", 1, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("errtype", 5, ofp_error_type),
                   ShortEnumField("errcode", 0, {0: "OFPQOFC_BAD_PORT",
                                                 1: "OFPQOFC_BAD_QUEUE",
                                                 2: "OFPQOFC_EPERM"}),
                   OFPacketField("data", "", Raw)]


# ofp_error_cls allows generic method OpenFlow() to choose the right class for dissection  # noqa: E501
ofp_error_cls = {0: OFPETHelloFailed,
                 1: OFPETBadRequest,
                 2: OFPETBadAction,
                 3: OFPETFlowModFailed,
                 4: OFPETPortModFailed,
                 5: OFPETQueueOpFailed}

#                end of OFPT_ERRORS                 #


class OFPTEchoRequest(_ofp_header):
    name = "OFPT_ECHO_REQUEST"
    fields_desc = [ByteEnumField("version", 0x01, ofp_version),
                   ByteEnumField("type", 2, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0)]


class OFPTEchoReply(_ofp_header):
    name = "OFPT_ECHO_REPLY"
    fields_desc = [ByteEnumField("version", 0x01, ofp_version),
                   ByteEnumField("type", 3, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0)]


class OFPTVendor(_ofp_header):
    name = "OFPT_VENDOR"
    fields_desc = [ByteEnumField("version", 0x01, ofp_version),
                   ByteEnumField("type", 4, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   IntField("vendor", 0)]


class OFPTFeaturesRequest(_ofp_header):
    name = "OFPT_FEATURES_REQUEST"
    fields_desc = [ByteEnumField("version", 0x01, ofp_version),
                   ByteEnumField("type", 5, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0)]


ofp_action_types_flags = [v for v in six.itervalues(ofp_action_types)
                          if v != 'OFPAT_VENDOR']


class OFPTFeaturesReply(_ofp_header):
    name = "OFPT_FEATURES_REPLY"
    fields_desc = [ByteEnumField("version", 0x01, ofp_version),
                   ByteEnumField("type", 6, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   LongField("datapath_id", 0),
                   IntField("n_buffers", 0),
                   ByteField("n_tables", 1),
                   X3BytesField("pad", 0),
                   FlagsField("capabilities", 0, 32, ["FLOW_STATS",
                                                      "TABLE_STATS",
                                                      "PORT_STATS",
                                                      "STP",
                                                      "RESERVED",
                                                      "IP_REASM",
                                                      "QUEUE_STATS",
                                                      "ARP_MATCH_IP"]),
                   FlagsField("actions", 0, 32, ofp_action_types_flags),
                   PacketListField("ports", [], OFPPhyPort,
                                   length_from=lambda pkt:pkt.len - 32)]


class OFPTGetConfigRequest(_ofp_header):
    name = "OFPT_GET_CONFIG_REQUEST"
    fields_desc = [ByteEnumField("version", 0x01, ofp_version),
                   ByteEnumField("type", 7, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0)]


class OFPTGetConfigReply(_ofp_header):
    name = "OFPT_GET_CONFIG_REPLY"
    fields_desc = [ByteEnumField("version", 0x01, ofp_version),
                   ByteEnumField("type", 8, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("flags", 0, {0: "FRAG_NORMAL",
                                               1: "FRAG_DROP",
                                               2: "FRAG_REASM",
                                               3: "FRAG_MASK"}),
                   ShortField("miss_send_len", 0)]


class OFPTSetConfig(_ofp_header):
    name = "OFPT_SET_CONFIG"
    fields_desc = [ByteEnumField("version", 0x01, ofp_version),
                   ByteEnumField("type", 9, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("flags", 0, {0: "FRAG_NORMAL",
                                               1: "FRAG_DROP",
                                               2: "FRAG_REASM",
                                               3: "FRAG_MASK"}),
                   ShortField("miss_send_len", 128)]


class OFPTPacketIn(_ofp_header):
    name = "OFPT_PACKET_IN"
    fields_desc = [ByteEnumField("version", 0x01, ofp_version),
                   ByteEnumField("type", 10, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   IntEnumField("buffer_id", "NO_BUFFER", ofp_buffer),
                   ShortField("total_len", 0),
                   ShortEnumField("in_port", 0, ofp_port_no),
                   ByteEnumField("reason", 0, {0: "OFPR_NO_MATCH",
                                               1: "OFPR_ACTION"}),
                   XByteField("pad", 0),
                   PacketField("data", None, Ether)]


class OFPTFlowRemoved(_ofp_header):
    name = "OFPT_FLOW_REMOVED"
    fields_desc = [ByteEnumField("version", 0x01, ofp_version),
                   ByteEnumField("type", 11, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   PacketField("match", OFPMatch(), OFPMatch),
                   LongField("cookie", 0),
                   ShortField("priority", 0),
                   ByteEnumField("reason", 0, {0: "OFPRR_IDLE_TIMEOUT",
                                               1: "OFPRR_HARD_TIMEOUT",
                                               2: "OFPRR_DELETE"}),
                   XByteField("pad1", 0),
                   IntField("duration_sec", 0),
                   IntField("duration_nsec", 0),
                   ShortField("idle_timeout", 0),
                   XShortField("pad2", 0),
                   LongField("packet_count", 0),
                   LongField("byte_count", 0)]


class OFPTPortStatus(_ofp_header):
    name = "OFPT_PORT_STATUS"
    fields_desc = [ByteEnumField("version", 0x01, ofp_version),
                   ByteEnumField("type", 12, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ByteEnumField("reason", 0, {0: "OFPPR_ADD",
                                               1: "OFPPR_DELETE",
                                               2: "OFPPR_MODIFY"}),
                   XBitField("pad", 0, 56),
                   PacketField("desc", OFPPhyPort(), OFPPhyPort)]


class OFPTPacketOut(_ofp_header):
    name = "OFPT_PACKET_OUT"
    fields_desc = [ByteEnumField("version", 0x01, ofp_version),
                   ByteEnumField("type", 13, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   IntEnumField("buffer_id", "NO_BUFFER", ofp_buffer),
                   ShortEnumField("in_port", "NONE", ofp_port_no),
                   FieldLenField("actions_len", None, fmt="H", length_of="actions"),  # noqa: E501
                   PacketListField("actions", [], OFPAT,
                                   ofp_action_cls,
                                   length_from=lambda pkt:pkt.actions_len),  # noqa: E501
                   PacketField("data", None, Ether)]


class OFPTFlowMod(_ofp_header):
    name = "OFPT_FLOW_MOD"
    fields_desc = [ByteEnumField("version", 0x01, ofp_version),
                   ByteEnumField("type", 14, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   PacketField("match", OFPMatch(), OFPMatch),
                   LongField("cookie", 0),
                   ShortEnumField("cmd", 0, {0: "OFPFC_ADD",
                                             1: "OFPFC_MODIFY",
                                             2: "OFPFC_MODIFY_STRICT",
                                             3: "OFPFC_DELETE",
                                             4: "OFPFC_DELETE_STRICT"}),
                   ShortField("idle_timeout", 0),
                   ShortField("hard_timeout", 0),
                   ShortField("priority", 0),
                   IntEnumField("buffer_id", "NO_BUFFER", ofp_buffer),
                   ShortEnumField("out_port", "NONE", ofp_port_no),
                   FlagsField("flags", 0, 16, ["SEND_FLOW_REM",
                                               "CHECK_OVERLAP",
                                               "EMERG"]),
                   PacketListField("actions", [], OFPAT,
                                   ofp_action_cls,
                                   length_from=lambda pkt:pkt.len - 72)]


class OFPTPortMod(_ofp_header):
    name = "OFPT_PORT_MOD"
    fields_desc = [ByteEnumField("version", 0x01, ofp_version),
                   ByteEnumField("type", 15, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("port_no", 0, ofp_port_no),
                   MACField("hw_addr", "0"),
                   FlagsField("config", 0, 32, ofp_port_config),
                   FlagsField("mask", 0, 32, ofp_port_config),
                   FlagsField("advertise", 0, 32, ofp_port_features),
                   IntField("pad", 0)]


#####################################################
#                     OFPT_STATS                    #
#####################################################


ofp_stats_types = {0: "OFPST_DESC",
                   1: "OFPST_FLOW",
                   2: "OFPST_AGGREGATE",
                   3: "OFPST_TABLE",
                   4: "OFPST_PORT",
                   5: "OFPST_QUEUE",
                   65535: "OFPST_VENDOR"}


class OFPTStatsRequestDesc(_ofp_header):
    name = "OFPST_STATS_REQUEST_DESC"
    fields_desc = [ByteEnumField("version", 0x01, ofp_version),
                   ByteEnumField("type", 16, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("stats_type", 0, ofp_stats_types),
                   FlagsField("flags", 0, 16, [])]


class OFPTStatsReplyDesc(_ofp_header):
    name = "OFPST_STATS_REPLY_DESC"
    fields_desc = [ByteEnumField("version", 0x01, ofp_version),
                   ByteEnumField("type", 17, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("stats_type", 0, ofp_stats_types),
                   FlagsField("flags", 0, 16, []),
                   StrFixedLenField("mfr_desc", "", 256),
                   StrFixedLenField("hw_desc", "", 256),
                   StrFixedLenField("sw_desc", "", 256),
                   StrFixedLenField("serial_num", "", 32),
                   StrFixedLenField("dp_desc", "", 256)]


class OFPTStatsRequestFlow(_ofp_header):
    name = "OFPST_STATS_REQUEST_FLOW"
    fields_desc = [ByteEnumField("version", 0x01, ofp_version),
                   ByteEnumField("type", 16, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("stats_type", 1, ofp_stats_types),
                   FlagsField("flags", 0, 16, []),
                   PacketField("match", OFPMatch(), OFPMatch),
                   ByteEnumField("table_id", "ALL", ofp_table),
                   ByteField("pad", 0),
                   ShortEnumField("out_port", "NONE", ofp_port_no)]


class OFPFlowStats(Packet):
    name = "OFP_FLOW_STATS"
    fields_desc = [ShortField("length", None),
                   ByteField("table_id", 0),
                   XByteField("pad1", 0),
                   PacketField("match", OFPMatch(), OFPMatch),
                   IntField("duration_sec", 0),
                   IntField("duration_nsec", 0),
                   ShortField("priority", 0),
                   ShortField("idle_timeout", 0),
                   ShortField("hard_timeout", 0),
                   XBitField("pad2", 0, 48),
                   LongField("cookie", 0),
                   LongField("packet_count", 0),
                   LongField("byte_count", 0),
                   PacketListField("actions", [], OFPAT,
                                   ofp_action_cls,
                                   length_from=lambda pkt:pkt.length - 88)]

    def post_build(self, p, pay):
        if self.length is None:
            tmp_len = len(p) + len(pay)
            p = struct.pack("!H", tmp_len) + p[2:]
        return p + pay

    def extract_padding(self, s):
        return b"", s


class OFPTStatsReplyFlow(_ofp_header):
    name = "OFPST_STATS_REPLY_FLOW"
    fields_desc = [ByteEnumField("version", 0x01, ofp_version),
                   ByteEnumField("type", 17, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("stats_type", 1, ofp_stats_types),
                   FlagsField("flags", 0, 16, []),
                   PacketListField("flow_stats", [], OFPFlowStats,
                                   length_from=lambda pkt:pkt.len - 12)]  # noqa: E501


class OFPTStatsRequestAggregate(OFPTStatsRequestFlow):
    name = "OFPST_STATS_REQUEST_AGGREGATE"
    stats_type = 2


class OFPTStatsReplyAggregate(_ofp_header):
    name = "OFPST_STATS_REPLY_AGGREGATE"
    fields_desc = [ByteEnumField("version", 0x01, ofp_version),
                   ByteEnumField("type", 17, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("stats_type", 2, ofp_stats_types),
                   FlagsField("flags", 0, 16, []),
                   LongField("packet_count", 0),
                   LongField("byte_count", 0),
                   IntField("flow_count", 0),
                   XIntField("pad", 0)]


class OFPTStatsRequestTable(_ofp_header):
    name = "OFPST_STATS_REQUEST_TABLE"
    fields_desc = [ByteEnumField("version", 0x01, ofp_version),
                   ByteEnumField("type", 16, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("stats_type", 3, ofp_stats_types),
                   FlagsField("flags", 0, 16, [])]


class OFPTableStats(Packet):

    def extract_padding(self, s):
        return b"", s

    name = "OFP_TABLE_STATS"
    fields_desc = [ByteField("table_id", 0),
                   X3BytesField("pad", 0),
                   StrFixedLenField("name", "", 32),
                   FlagsField("wildcards1", 0x003, 12, ["DL_VLAN_PCP",
                                                        "NW_TOS"]),
                   BitField("nw_dst_mask", 63, 6),        # 32 would be enough
                   BitField("nw_src_mask", 63, 6),
                   FlagsField("wildcards2", 0xff, 8, ["IN_PORT",
                                                      "DL_VLAN",
                                                      "DL_SRC",
                                                      "DL_DST",
                                                      "DL_TYPE",
                                                      "NW_PROTO",
                                                      "TP_SRC",
                                                      "TP_DST"]),
                   IntField("max_entries", 0),
                   IntField("active_count", 0),
                   LongField("lookup_count", 0),
                   LongField("matched_count", 0)]


class OFPTStatsReplyTable(_ofp_header):
    name = "OFPST_STATS_REPLY_TABLE"
    fields_desc = [ByteEnumField("version", 0x01, ofp_version),
                   ByteEnumField("type", 17, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("stats_type", 3, ofp_stats_types),
                   FlagsField("flags", 0, 16, []),
                   PacketListField("table_stats", [], OFPTableStats,
                                   length_from=lambda pkt:pkt.len - 12)]


class OFPTStatsRequestPort(_ofp_header):
    name = "OFPST_STATS_REQUEST_PORT"
    fields_desc = [ByteEnumField("version", 0x01, ofp_version),
                   ByteEnumField("type", 16, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("stats_type", 4, ofp_stats_types),
                   FlagsField("flags", 0, 16, []),
                   ShortEnumField("port_no", "NONE", ofp_port_no),
                   XBitField("pad", 0, 48)]


class OFPPortStats(Packet):

    def extract_padding(self, s):
        return b"", s

    name = "OFP_PORT_STATS"
    fields_desc = [ShortEnumField("port_no", 0, ofp_port_no),
                   XBitField("pad", 0, 48),
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
                   LongField("collisions", 0)]


class OFPTStatsReplyPort(_ofp_header):
    name = "OFPST_STATS_REPLY_TABLE"
    fields_desc = [ByteEnumField("version", 0x01, ofp_version),
                   ByteEnumField("type", 17, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("stats_type", 4, ofp_stats_types),
                   FlagsField("flags", 0, 16, []),
                   PacketListField("port_stats", [], OFPPortStats,
                                   length_from=lambda pkt:pkt.len - 12)]


class OFPTStatsRequestQueue(_ofp_header):
    name = "OFPST_STATS_REQUEST_QUEUE"
    fields_desc = [ByteEnumField("version", 0x01, ofp_version),
                   ByteEnumField("type", 16, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("stats_type", 5, ofp_stats_types),
                   FlagsField("flags", 0, 16, []),
                   ShortEnumField("port_no", "NONE", ofp_port_no),
                   XShortField("pad", 0),
                   IntEnumField("queue_id", "ALL", ofp_queue)]


class OFPTStatsReplyQueue(_ofp_header):
    name = "OFPST_STATS_REPLY_QUEUE"
    fields_desc = [ByteEnumField("version", 0x01, ofp_version),
                   ByteEnumField("type", 17, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("stats_type", 5, ofp_stats_types),
                   FlagsField("flags", 0, 16, []),
                   ShortEnumField("port_no", "NONE", ofp_port_no),
                   XShortField("pad", 0),
                   IntEnumField("queue_id", "ALL", ofp_queue),
                   LongField("tx_bytes", 0),
                   LongField("tx_packets", 0),
                   LongField("tx_errors", 0)]


class OFPTStatsRequestVendor(_ofp_header):
    name = "OFPST_STATS_REQUEST_VENDOR"
    fields_desc = [ByteEnumField("version", 0x01, ofp_version),
                   ByteEnumField("type", 16, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("stats_type", 6, ofp_stats_types),
                   FlagsField("flags", 0, 16, []),
                   IntField("vendor", 0)]


class OFPTStatsReplyVendor(_ofp_header):
    name = "OFPST_STATS_REPLY_VENDOR"
    fields_desc = [ByteEnumField("version", 0x01, ofp_version),
                   ByteEnumField("type", 17, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("stats_type", 6, ofp_stats_types),
                   FlagsField("flags", 0, 16, []),
                   IntField("vendor", 0)]


# ofp_stats_request/reply_cls allows generic method OpenFlow() (end of script)
# to choose the right class for dissection
ofp_stats_request_cls = {0: OFPTStatsRequestDesc,
                         1: OFPTStatsRequestFlow,
                         2: OFPTStatsRequestAggregate,
                         3: OFPTStatsRequestTable,
                         4: OFPTStatsRequestPort,
                         5: OFPTStatsRequestQueue,
                         65535: OFPTStatsRequestVendor}

ofp_stats_reply_cls = {0: OFPTStatsReplyDesc,
                       1: OFPTStatsReplyFlow,
                       2: OFPTStatsReplyAggregate,
                       3: OFPTStatsReplyTable,
                       4: OFPTStatsReplyPort,
                       5: OFPTStatsReplyQueue,
                       65535: OFPTStatsReplyVendor}

#                end of OFPT_STATS                  #


class OFPTBarrierRequest(_ofp_header):
    name = "OFPT_BARRIER_REQUEST"
    fields_desc = [ByteEnumField("version", 0x01, ofp_version),
                   ByteEnumField("type", 18, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0)]


class OFPTBarrierReply(_ofp_header):
    name = "OFPT_BARRIER_REPLY"
    fields_desc = [ByteEnumField("version", 0x01, ofp_version),
                   ByteEnumField("type", 19, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0)]


class OFPTQueueGetConfigRequest(_ofp_header):
    name = "OFPT_QUEUE_GET_CONFIG_REQUEST"
    fields_desc = [ByteEnumField("version", 0x01, ofp_version),
                   ByteEnumField("type", 20, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("port", 0, ofp_port_no),
                   XShortField("pad", 0)]


class OFPTQueueGetConfigReply(_ofp_header):
    name = "OFPT_QUEUE_GET_CONFIG_REPLY"
    fields_desc = [ByteEnumField("version", 0x01, ofp_version),
                   ByteEnumField("type", 21, ofp_type),
                   ShortField("len", None),
                   IntField("xid", 0),
                   ShortEnumField("port", 0, ofp_port_no),
                   XBitField("pad", 0, 48),
                   PacketListField("queues", [], OFPPacketQueue,
                                   length_from=lambda pkt:pkt.len - 16)]


# ofpt_cls allows generic method OpenFlow() to choose the right class for dissection  # noqa: E501
ofpt_cls = {0: OFPTHello,
            # 1: OFPTError,
            2: OFPTEchoRequest,
            3: OFPTEchoReply,
            4: OFPTVendor,
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
            15: OFPTPortMod,
            # 16: OFPTStatsRequest,
            # 17: OFPTStatsReply,
            18: OFPTBarrierRequest,
            19: OFPTBarrierReply,
            20: OFPTQueueGetConfigRequest,
            21: OFPTQueueGetConfigReply}


bind_bottom_up(TCP, OpenFlow, dport=6653)
bind_bottom_up(TCP, OpenFlow, sport=6653)
bind_bottom_up(TCP, OpenFlow, dport=6633)
bind_bottom_up(TCP, OpenFlow, sport=6633)

bind_top_down(TCP, _ofp_header, sport=6653, dport=6653)
