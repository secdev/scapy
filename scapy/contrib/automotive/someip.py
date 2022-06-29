# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Sebastian Baar <sebastian.baar@gmx.de>
# Copyright (c) 2018 Jose Amores

# scapy.contrib.description = Scalable service-Oriented MiddlewarE/IP (SOME/IP)
# scapy.contrib.status = loads

import ctypes
import collections
import struct

from scapy.layers.inet import TCP, UDP
from scapy.layers.inet6 import IP6Field
from scapy.compat import raw, orb
from scapy.config import conf
from scapy.packet import Packet, Raw, bind_top_down, bind_bottom_up
from scapy.fields import XShortField, BitEnumField, ConditionalField, \
    BitField, XBitField, IntField, XByteField, ByteEnumField, \
    ShortField, X3BytesField, StrLenField, IPField, FieldLenField, \
    PacketListField, XIntField


class SOMEIP(Packet):
    """ SOME/IP Packet."""

    PROTOCOL_VERSION = 0x01
    INTERFACE_VERSION = 0x01
    LEN_OFFSET = 0x08
    LEN_OFFSET_TP = 0x0c
    TYPE_REQUEST = 0x00
    TYPE_REQUEST_NO_RET = 0x01
    TYPE_NOTIFICATION = 0x02
    TYPE_REQUEST_ACK = 0x40
    TYPE_REQUEST_NORET_ACK = 0x41
    TYPE_NOTIFICATION_ACK = 0x42
    TYPE_RESPONSE = 0x80
    TYPE_ERROR = 0x81
    TYPE_RESPONSE_ACK = 0xc0
    TYPE_ERROR_ACK = 0xc1
    TYPE_TP_REQUEST = 0x20
    TYPE_TP_REQUEST_NO_RET = 0x21
    TYPE_TP_NOTIFICATION = 0x22
    TYPE_TP_RESPONSE = 0xa0
    TYPE_TP_ERROR = 0xa1
    RET_E_OK = 0x00
    RET_E_NOT_OK = 0x01
    RET_E_UNKNOWN_SERVICE = 0x02
    RET_E_UNKNOWN_METHOD = 0x03
    RET_E_NOT_READY = 0x04
    RET_E_NOT_REACHABLE = 0x05
    RET_E_TIMEOUT = 0x06
    RET_E_WRONG_PROTOCOL_V = 0x07
    RET_E_WRONG_INTERFACE_V = 0x08
    RET_E_MALFORMED_MSG = 0x09
    RET_E_WRONG_MESSAGE_TYPE = 0x0a

    _OVERALL_LEN_NOPAYLOAD = 16

    name = "SOME/IP"

    fields_desc = [
        XShortField("srv_id", 0),
        BitEnumField("sub_id", 0, 1, {0: "METHOD_ID", 1: "EVENT_ID"}),
        ConditionalField(XBitField("method_id", 0, 15),
                         lambda pkt: pkt.sub_id == 0),
        ConditionalField(XBitField("event_id", 0, 15),
                         lambda pkt: pkt.sub_id == 1),
        IntField("len", None),
        XShortField("client_id", 0),
        XShortField("session_id", 0),
        XByteField("proto_ver", PROTOCOL_VERSION),
        XByteField("iface_ver", INTERFACE_VERSION),
        ByteEnumField("msg_type", TYPE_REQUEST, {
            TYPE_REQUEST: "REQUEST",
            TYPE_REQUEST_NO_RET: "REQUEST_NO_RETURN",
            TYPE_NOTIFICATION: "NOTIFICATION",
            TYPE_REQUEST_ACK: "REQUEST_ACK",
            TYPE_REQUEST_NORET_ACK: "REQUEST_NO_RETURN_ACK",
            TYPE_NOTIFICATION_ACK: "NOTIFICATION_ACK",
            TYPE_RESPONSE: "RESPONSE",
            TYPE_ERROR: "ERROR",
            TYPE_RESPONSE_ACK: "RESPONSE_ACK",
            TYPE_ERROR_ACK: "ERROR_ACK",
            TYPE_TP_REQUEST: "TP_REQUEST",
            TYPE_TP_REQUEST_NO_RET: "TP_REQUEST_NO_RETURN",
            TYPE_TP_NOTIFICATION: "TP_NOTIFICATION",
            TYPE_TP_RESPONSE: "TP_RESPONSE",
            TYPE_TP_ERROR: "TP_ERROR",
        }),
        ByteEnumField("retcode", 0, {
            RET_E_OK: "E_OK",
            RET_E_NOT_OK: "E_NOT_OK",
            RET_E_UNKNOWN_SERVICE: "E_UNKNOWN_SERVICE",
            RET_E_UNKNOWN_METHOD: "E_UNKNOWN_METHOD",
            RET_E_NOT_READY: "E_NOT_READY",
            RET_E_NOT_REACHABLE: "E_NOT_REACHABLE",
            RET_E_TIMEOUT: "E_TIMEOUT",
            RET_E_WRONG_PROTOCOL_V: "E_WRONG_PROTOCOL_VERSION",
            RET_E_WRONG_INTERFACE_V: "E_WRONG_INTERFACE_VERSION",
            RET_E_MALFORMED_MSG: "E_MALFORMED_MESSAGE",
            RET_E_WRONG_MESSAGE_TYPE: "E_WRONG_MESSAGE_TYPE",
        }),
        ConditionalField(BitField("offset", 0, 28),
                         lambda pkt: SOMEIP._is_tp(pkt)),
        ConditionalField(BitField("res", 0, 3),
                         lambda pkt: SOMEIP._is_tp(pkt)),
        ConditionalField(BitField("more_seg", 0, 1),
                         lambda pkt: SOMEIP._is_tp(pkt))
    ]

    def post_build(self, pkt, pay):
        length = self.len
        if length is None:
            if SOMEIP._is_tp(self):
                length = SOMEIP.LEN_OFFSET_TP + len(pay)
            else:
                length = SOMEIP.LEN_OFFSET + len(pay)

            pkt = pkt[:4] + struct.pack("!I", length) + pkt[8:]
        return pkt + pay

    def answers(self, other):
        if isinstance(other, type(self)):
            if self.msg_type in [SOMEIP.TYPE_REQUEST_NO_RET,
                                 SOMEIP.TYPE_REQUEST_NORET_ACK,
                                 SOMEIP.TYPE_NOTIFICATION,
                                 SOMEIP.TYPE_TP_REQUEST_NO_RET,
                                 SOMEIP.TYPE_TP_NOTIFICATION]:
                return 0
            return self.payload.answers(other.payload)
        return 0

    @staticmethod
    def _is_tp(pkt):
        """Returns true if pkt is using SOMEIP-TP, else returns false."""

        tp = [SOMEIP.TYPE_TP_REQUEST, SOMEIP.TYPE_TP_REQUEST_NO_RET,
              SOMEIP.TYPE_TP_NOTIFICATION, SOMEIP.TYPE_TP_RESPONSE,
              SOMEIP.TYPE_TP_ERROR]
        if isinstance(pkt, Packet):
            return pkt.msg_type in tp
        else:
            return pkt[15] in tp

    def fragment(self, fragsize=1392):
        """Fragment SOME/IP-TP"""
        fnb = 0
        fl = self
        lst = list()
        while fl.underlayer is not None:
            fnb += 1
            fl = fl.underlayer

        for p in fl:
            s = raw(p[fnb].payload)
            nb = (len(s) + fragsize) // fragsize
            for i in range(nb):
                q = p.copy()
                del q[fnb].payload
                q[fnb].len = SOMEIP.LEN_OFFSET_TP + \
                    len(s[i * fragsize:(i + 1) * fragsize])
                q[fnb].more_seg = 1
                if i == nb - 1:
                    q[fnb].more_seg = 0
                q[fnb].offset += i * fragsize // 16
                r = conf.raw_layer(load=s[i * fragsize:(i + 1) * fragsize])
                r.overload_fields = p[fnb].payload.overload_fields.copy()
                q.add_payload(r)
                lst.append(q)

        return lst


def _bind_someip_layers():
    bind_top_down(UDP, SOMEIP, sport=30490, dport=30490)

    for i in range(15):
        bind_bottom_up(UDP, SOMEIP, sport=30490 + i)
        bind_bottom_up(TCP, SOMEIP, sport=30490 + i)
        bind_bottom_up(UDP, SOMEIP, dport=30490 + i)
        bind_bottom_up(TCP, SOMEIP, dport=30490 + i)


_bind_someip_layers()


class _SDPacketBase(Packet):
    """ base class to be used among all SD Packet definitions."""
    def extract_padding(self, s):
        return "", s


SDENTRY_TYPE_SRV_FINDSERVICE = 0x00
SDENTRY_TYPE_SRV_OFFERSERVICE = 0x01
SDENTRY_TYPE_SRV = (SDENTRY_TYPE_SRV_FINDSERVICE,
                    SDENTRY_TYPE_SRV_OFFERSERVICE)
SDENTRY_TYPE_EVTGRP_SUBSCRIBE = 0x06
SDENTRY_TYPE_EVTGRP_SUBSCRIBE_ACK = 0x07
SDENTRY_TYPE_EVTGRP = (SDENTRY_TYPE_EVTGRP_SUBSCRIBE,
                       SDENTRY_TYPE_EVTGRP_SUBSCRIBE_ACK)
SDENTRY_OVERALL_LEN = 16


def _MAKE_SDENTRY_COMMON_FIELDS_DESC(type):
    return [
        XByteField("type", type),
        XByteField("index_1", 0),
        XByteField("index_2", 0),
        XBitField("n_opt_1", 0, 4),
        XBitField("n_opt_2", 0, 4),
        XShortField("srv_id", 0),
        XShortField("inst_id", 0),
        XByteField("major_ver", 0),
        X3BytesField("ttl", 0)
    ]


class SDEntry_Service(_SDPacketBase):
    name = "Service Entry"
    fields_desc = _MAKE_SDENTRY_COMMON_FIELDS_DESC(
        SDENTRY_TYPE_SRV_FINDSERVICE)
    fields_desc += [
        XIntField("minor_ver", 0)
    ]


class SDEntry_EventGroup(_SDPacketBase):
    name = "Eventgroup Entry"
    fields_desc = _MAKE_SDENTRY_COMMON_FIELDS_DESC(
        SDENTRY_TYPE_EVTGRP_SUBSCRIBE)
    fields_desc += [
        XBitField("res", 0, 12),
        XBitField("cnt", 0, 4),
        XShortField("eventgroup_id", 0)
    ]


def _sdentry_class(payload, **kargs):
    TYPE_PAYLOAD_I = 0
    pl_type = orb(payload[TYPE_PAYLOAD_I])
    cls = None

    if pl_type in SDENTRY_TYPE_SRV:
        cls = SDEntry_Service
    elif pl_type in SDENTRY_TYPE_EVTGRP:
        cls = SDEntry_EventGroup

    return cls(payload, **kargs)


def _sdoption_class(payload, **kargs):
    pl_type = orb(payload[2])

    cls = {
        SDOPTION_CFG_TYPE: SDOption_Config,
        SDOPTION_LOADBALANCE_TYPE: SDOption_LoadBalance,
        SDOPTION_IP4_ENDPOINT_TYPE: SDOption_IP4_EndPoint,
        SDOPTION_IP4_MCAST_TYPE: SDOption_IP4_Multicast,
        SDOPTION_IP4_SDENDPOINT_TYPE: SDOption_IP4_SD_EndPoint,
        SDOPTION_IP6_ENDPOINT_TYPE: SDOption_IP6_EndPoint,
        SDOPTION_IP6_MCAST_TYPE: SDOption_IP6_Multicast,
        SDOPTION_IP6_SDENDPOINT_TYPE: SDOption_IP6_SD_EndPoint
    }.get(pl_type, Raw)

    return cls(payload, **kargs)


# SD Option
SDOPTION_CFG_TYPE = 0x01
SDOPTION_LOADBALANCE_TYPE = 0x02
SDOPTION_LOADBALANCE_LEN = 0x05
SDOPTION_IP4_ENDPOINT_TYPE = 0x04
SDOPTION_IP4_ENDPOINT_LEN = 0x0009
SDOPTION_IP4_MCAST_TYPE = 0x14
SDOPTION_IP4_MCAST_LEN = 0x0009
SDOPTION_IP4_SDENDPOINT_TYPE = 0x24
SDOPTION_IP4_SDENDPOINT_LEN = 0x0009
SDOPTION_IP6_ENDPOINT_TYPE = 0x06
SDOPTION_IP6_ENDPOINT_LEN = 0x0015
SDOPTION_IP6_MCAST_TYPE = 0x16
SDOPTION_IP6_MCAST_LEN = 0x0015
SDOPTION_IP6_SDENDPOINT_TYPE = 0x26
SDOPTION_IP6_SDENDPOINT_LEN = 0x0015


def _MAKE_COMMON_SDOPTION_FIELDS_DESC(type, length=None):
    return [
        ShortField("len", length),
        XByteField("type", type),
        XByteField("res_hdr", 0)
    ]


def _MAKE_COMMON_IP_SDOPTION_FIELDS_DESC():
    return [
        XByteField("res_tail", 0),
        ByteEnumField("l4_proto", 0x11, {0x06: "TCP", 0x11: "UDP"}),
        ShortField("port", 0)
    ]


class SDOption_Config(_SDPacketBase):
    name = "Config Option"
    fields_desc = _MAKE_COMMON_SDOPTION_FIELDS_DESC(SDOPTION_CFG_TYPE) + [
        StrLenField("cfg_str", "\x00", length_from=lambda pkt: pkt.len - 1)
    ]

    def post_build(self, pkt, pay):
        if self.len is None:
            length = len(self.cfg_str) + 1  # res_hdr field takes 1 byte
            pkt = struct.pack("!H", length) + pkt[2:]
        return pkt + pay

    @staticmethod
    def make_string(data):
        # Build a valid null-terminated configuration string from a dict or a
        # list with key-value pairs.
        #
        # Example:
        #    >>> SDOption_Config.make_string({ "hello": "world" })
        #    b'\x0bhello=world\x00'
        #
        #    >>> SDOption_Config.make_string([
        #    ...     ("x", "y"),
        #    ...     ("abc", "def"),
        #    ...     ("123", "456")
        #    ... ])
        #    b'\x03x=y\x07abc=def\x07123=456\x00'

        if isinstance(data, dict):
            data = data.items()

        # combine entries
        data = ("{}={}".format(k, v) for k, v in data)
        # prepend length
        data = ("{}{}".format(chr(len(v)), v) for v in data)
        # concatenate
        data = "".join(data)
        data += "\x00"

        return data.encode("utf8")


class SDOption_LoadBalance(_SDPacketBase):
    name = "LoadBalance Option"
    fields_desc = _MAKE_COMMON_SDOPTION_FIELDS_DESC(
        SDOPTION_LOADBALANCE_TYPE, SDOPTION_LOADBALANCE_LEN)
    fields_desc += [
        ShortField("priority", 0),
        ShortField("weight", 0)
    ]


class SDOption_IP4_EndPoint(_SDPacketBase):
    name = "IP4 EndPoint Option"
    fields_desc = _MAKE_COMMON_SDOPTION_FIELDS_DESC(
        SDOPTION_IP4_ENDPOINT_TYPE, SDOPTION_IP4_ENDPOINT_LEN)
    fields_desc += [
        IPField("addr", "0.0.0.0"),
    ] + _MAKE_COMMON_IP_SDOPTION_FIELDS_DESC()


class SDOption_IP4_Multicast(_SDPacketBase):
    name = "IP4 Multicast Option"
    fields_desc = _MAKE_COMMON_SDOPTION_FIELDS_DESC(
        SDOPTION_IP4_MCAST_TYPE, SDOPTION_IP4_MCAST_LEN)
    fields_desc += [
        IPField("addr", "0.0.0.0"),
    ] + _MAKE_COMMON_IP_SDOPTION_FIELDS_DESC()


class SDOption_IP4_SD_EndPoint(_SDPacketBase):
    name = "IP4 SDEndPoint Option"
    fields_desc = _MAKE_COMMON_SDOPTION_FIELDS_DESC(
        SDOPTION_IP4_SDENDPOINT_TYPE, SDOPTION_IP4_SDENDPOINT_LEN)
    fields_desc += [
        IPField("addr", "0.0.0.0"),
    ] + _MAKE_COMMON_IP_SDOPTION_FIELDS_DESC()


class SDOption_IP6_EndPoint(_SDPacketBase):
    name = "IP6 EndPoint Option"
    fields_desc = _MAKE_COMMON_SDOPTION_FIELDS_DESC(
        SDOPTION_IP6_ENDPOINT_TYPE, SDOPTION_IP6_ENDPOINT_LEN)
    fields_desc += [
        IP6Field("addr", "::"),
    ] + _MAKE_COMMON_IP_SDOPTION_FIELDS_DESC()


class SDOption_IP6_Multicast(_SDPacketBase):
    name = "IP6 Multicast Option"
    fields_desc = _MAKE_COMMON_SDOPTION_FIELDS_DESC(
        SDOPTION_IP6_MCAST_TYPE, SDOPTION_IP6_MCAST_LEN)
    fields_desc += [
        IP6Field("addr", "::"),
    ] + _MAKE_COMMON_IP_SDOPTION_FIELDS_DESC()


class SDOption_IP6_SD_EndPoint(_SDPacketBase):
    name = "IP6 SDEndPoint Option"
    fields_desc = _MAKE_COMMON_SDOPTION_FIELDS_DESC(
        SDOPTION_IP6_SDENDPOINT_TYPE, SDOPTION_IP6_SDENDPOINT_LEN)
    fields_desc += [
        IP6Field("addr", "::"),
    ] + _MAKE_COMMON_IP_SDOPTION_FIELDS_DESC()


##
# SD PACKAGE DEFINITION
##
class SD(_SDPacketBase):
    """
    SD Packet

    NOTE :   when adding 'entries' or 'options', do not use list.append()
        method but create a new list
    e.g. :  p = SD()
            p.option_array = [SDOption_Config(),SDOption_IP6_EndPoint()]
    """
    SOMEIP_MSGID_SRVID = 0xffff
    SOMEIP_MSGID_SUBID = 0x1
    SOMEIP_MSGID_EVENTID = 0x100
    SOMEIP_CLIENT_ID = 0x0000
    SOMEIP_MINIMUM_SESSION_ID = 0x0001
    SOMEIP_PROTO_VER = 0x01
    SOMEIP_IFACE_VER = 0x01
    SOMEIP_MSG_TYPE = SOMEIP.TYPE_NOTIFICATION
    SOMEIP_RETCODE = SOMEIP.RET_E_OK

    _sdFlag = collections.namedtuple('Flag', 'mask offset')
    FLAGSDEF = {
        "REBOOT": _sdFlag(mask=0x80, offset=7),
        "UNICAST": _sdFlag(mask=0x40, offset=6)
    }

    name = "SD"
    fields_desc = [
        XByteField("flags", 0),
        X3BytesField("res", 0),
        FieldLenField("len_entry_array", None,
                      length_of="entry_array", fmt="!I"),
        PacketListField("entry_array", None, _sdentry_class,
                        length_from=lambda pkt: pkt.len_entry_array),
        FieldLenField("len_option_array", None,
                      length_of="option_array", fmt="!I"),
        PacketListField("option_array", None, _sdoption_class,
                        length_from=lambda pkt: pkt.len_option_array)
    ]

    def get_flag(self, name):
        name = name.upper()
        if name in self.FLAGSDEF:
            return ((self.flags & self.FLAGSDEF[name].mask) >>
                    self.FLAGSDEF[name].offset)
        else:
            return None

    def set_flag(self, name, value):
        name = name.upper()
        if name in self.FLAGSDEF:
            self.flags = (self.flags &
                          (ctypes.c_ubyte(~self.FLAGSDEF[name].mask).value)) \
                | ((value & 0x01) << self.FLAGSDEF[name].offset)

    def set_entryArray(self, entry_list):
        if isinstance(entry_list, list):
            self.entry_array = entry_list
        else:
            self.entry_array = [entry_list]

    def set_optionArray(self, option_list):
        if isinstance(option_list, list):
            self.option_array = option_list
        else:
            self.option_array = [option_list]


bind_top_down(SOMEIP, SD,
              srv_id=SD.SOMEIP_MSGID_SRVID,
              sub_id=SD.SOMEIP_MSGID_SUBID,
              client_id=SD.SOMEIP_CLIENT_ID,
              session_id=SD.SOMEIP_MINIMUM_SESSION_ID,
              event_id=SD.SOMEIP_MSGID_EVENTID,
              proto_ver=SD.SOMEIP_PROTO_VER,
              iface_ver=SD.SOMEIP_IFACE_VER,
              msg_type=SD.SOMEIP_MSG_TYPE,
              retcode=SD.SOMEIP_RETCODE)

bind_bottom_up(SOMEIP, SD,
               srv_id=SD.SOMEIP_MSGID_SRVID,
               sub_id=SD.SOMEIP_MSGID_SUBID,
               event_id=SD.SOMEIP_MSGID_EVENTID,
               proto_ver=SD.SOMEIP_PROTO_VER,
               iface_ver=SD.SOMEIP_IFACE_VER,
               msg_type=SD.SOMEIP_MSG_TYPE,
               retcode=SD.SOMEIP_RETCODE)

# FIXME: Service Discovery messages shall be transported over UDP
#        (TR_SOMEIP_00248)
# FIXME: The port 30490 (UDP and TCP as well) shall be only used for SOME/IP-SD
#        and not used for applications communicating over SOME/IP
#        (TR_SOMEIP_00020)
