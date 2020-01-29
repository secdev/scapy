# MIT License

# Copyright (c) 2018 Jose Amores

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Sebastian Baar <sebastian.baar@gmx.de>
# This program is published under a GPLv2 license

# scapy.contrib.description = Scalable service-Oriented MiddlewarE/IP (SOME/IP)
# scapy.contrib.status = loads

import ctypes
import collections
import struct

from scapy.layers.inet import TCP, UDP
from scapy.layers.inet6 import IP6Field
from scapy.compat import raw, orb
from scapy.config import conf
from scapy.modules.six.moves import range
from scapy.packet import Packet, Raw, bind_top_down, bind_bottom_up
from scapy.fields import XShortField, BitEnumField, ConditionalField, \
    BitField, XBitField, IntField, XByteField, ByteEnumField, ByteField, \
    ShortField, X3BytesField, StrField, IPField, FieldLenField, \
    PacketListField


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
    TYPE_TP_RESPONSE = 0x23
    TYPE_TP_ERROR = 0x24
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
        if other.__class__ == self.__class__:
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
    # use this dictionary to set default values for desired fields (mostly on
    # subclasses where not all fields are defined locally)
    # - key : field_name, value : desired value
    # - it will be used from 'init_fields' function, upon packet initialization
    #
    # example : _defaults =
    #  {'field_1_name':field_1_value,'field_2_name':field_2_value}
    _defaults = {}

    def _set_defaults(self):
        for key in self._defaults:
            try:
                self.get_field(key)
            except KeyError:
                pass
            else:
                self.setfieldval(key, self._defaults[key])

    def init_fields(self):
        super(_SDPacketBase, self).init_fields()
        self._set_defaults()


# SD ENTRY
# - Service
# - EventGroup
class _SDEntry(_SDPacketBase):
    TYPE_FMT = ">B"
    TYPE_PAYLOAD_I = 0
    TYPE_SRV_FINDSERVICE = 0x00
    TYPE_SRV_OFFERSERVICE = 0x01
    TYPE_SRV = (TYPE_SRV_FINDSERVICE, TYPE_SRV_OFFERSERVICE)
    TYPE_EVTGRP_SUBSCRIBE = 0x06
    TYPE_EVTGRP_SUBSCRIBE_ACK = 0x07
    TYPE_EVTGRP = (TYPE_EVTGRP_SUBSCRIBE, TYPE_EVTGRP_SUBSCRIBE_ACK)
    OVERALL_LEN = 16

    fields_desc = [
        ByteField("type", 0),
        ByteField("index_1", 0),
        ByteField("index_2", 0),
        BitField("n_opt_1", 0, 4),
        BitField("n_opt_2", 0, 4),
        ShortField("srv_id", 0),
        ShortField("inst_id", 0),
        ByteField("major_ver", 0),
        X3BytesField("ttl", 0)
    ]

    def guess_payload_class(self, payload):
        pl_type = orb(payload[_SDEntry.TYPE_PAYLOAD_I])

        if pl_type in _SDEntry.TYPE_SRV:
            return SDEntry_Service
        elif pl_type in _SDEntry.TYPE_EVTGRP:
            return SDEntry_EventGroup


class SDEntry_Service(_SDEntry):
    _defaults = {"type": _SDEntry.TYPE_SRV_FINDSERVICE}

    name = "Service Entry"
    fields_desc = [
        _SDEntry,
        IntField("minor_ver", 0)
    ]


class SDEntry_EventGroup(_SDEntry):
    _defaults = {"type": _SDEntry.TYPE_EVTGRP_SUBSCRIBE}

    name = "Eventgroup Entry"
    fields_desc = [
        _SDEntry,
        BitField("res", 0, 12),
        BitField("cnt", 0, 4),
        ShortField("eventgroup_id", 0)
    ]


# SD Option
# - Configuration
# - LoadBalancing
# - IPv4 EndPoint
# - IPv6 EndPoint
# - IPv4 MultiCast
# - IPv6 MultiCast
# - IPv4 EndPoint
# - IPv6 EndPoint
class _SDOption(_SDPacketBase):
    CFG_TYPE = 0x01
    CFG_OVERALL_LEN = 4
    LOADBALANCE_TYPE = 0x02
    LOADBALANCE_LEN = 0x05
    LOADBALANCE_OVERALL_LEN = 8
    IP4_ENDPOINT_TYPE = 0x04
    IP4_ENDPOINT_LEN = 0x0009
    IP4_MCAST_TYPE = 0x14
    IP4_MCAST_LEN = 0x0009
    IP4_SDENDPOINT_TYPE = 0x24
    IP4_SDENDPOINT_LEN = 0x0009
    IP4_OVERALL_LEN = 12
    IP6_ENDPOINT_TYPE = 0x06
    IP6_ENDPOINT_LEN = 0x0015
    IP6_MCAST_TYPE = 0x16
    IP6_MCAST_LEN = 0x0015
    IP6_SDENDPOINT_TYPE = 0x26
    IP6_SDENDPOINT_LEN = 0x0015
    IP6_OVERALL_LEN = 24

    def guess_payload_class(self, payload):
        pl_type = orb(payload[2])

        return {
            _SDOption.CFG_TYPE: SDOption_Config,
            self.LOADBALANCE_TYPE: SDOption_LoadBalance,
            self.IP4_ENDPOINT_TYPE: SDOption_IP4_EndPoint,
            self.IP4_MCAST_TYPE: SDOption_IP4_Multicast,
            self.IP4_SDENDPOINT_TYPE: SDOption_IP4_SD_EndPoint,
            self.IP6_ENDPOINT_TYPE: SDOption_IP6_EndPoint,
            self.IP6_MCAST_TYPE: SDOption_IP6_Multicast,
            self.IP6_SDENDPOINT_TYPE: SDOption_IP6_SD_EndPoint
        }.get(pl_type, Raw)


class _SDOption_Header(_SDOption):
    fields_desc = [
        ShortField("len", None),
        ByteField("type", 0),
        ByteField("res_hdr", 0)
    ]


class _SDOption_Tail(_SDOption):
    fields_desc = [
        ByteField("res_tail", 0),
        ByteEnumField("l4_proto", 0x06, {0x06: "TCP", 0x11: "UDP"}),
        ShortField("port", 0)
    ]


class _SDOption_IP4(_SDOption):
    fields_desc = [
        _SDOption_Header,
        IPField("addr", "0.0.0.0"),
        _SDOption_Tail
    ]


class _SDOption_IP6(_SDOption):
    fields_desc = [
        _SDOption_Header,
        IP6Field("addr", "2001:cdba:0000:0000:0000:0000:3257:9652"),
        _SDOption_Tail
    ]


class SDOption_Config(_SDOption):
    LEN_OFFSET = 0x01

    name = "Config Option"
    _defaults = {'type': _SDOption.CFG_TYPE}
    fields_desc = [
        _SDOption_Header,
        StrField("cfg_str", "")
    ]

    def post_build(self, pkt, pay):
        length = self.len
        if length is None:
            length = len(self.cfg_str) + self.LEN_OFFSET
            pkt = struct.pack("!H", length) + pkt[2:]
        return pkt + pay


class SDOption_LoadBalance(_SDOption):
    name = "LoadBalance Option"
    _defaults = {'type': _SDOption.LOADBALANCE_TYPE,
                 'len': _SDOption.LOADBALANCE_LEN}
    fields_desc = [
        _SDOption_Header,
        ShortField("priority", 0),
        ShortField("weight", 0)
    ]


class SDOption_IP4_EndPoint(_SDOption_IP4):
    name = "IP4 EndPoint Option"
    _defaults = {'type': _SDOption.IP4_ENDPOINT_TYPE,
                 'len': _SDOption.IP4_ENDPOINT_LEN}


class SDOption_IP4_Multicast(_SDOption_IP4):
    name = "IP4 Multicast Option"
    _defaults = {'type': _SDOption.IP4_MCAST_TYPE,
                 'len': _SDOption.IP4_MCAST_LEN}


class SDOption_IP4_SD_EndPoint(_SDOption_IP4):
    name = "IP4 SDEndPoint Option"
    _defaults = {'type': _SDOption.IP4_SDENDPOINT_TYPE,
                 'len': _SDOption.IP4_SDENDPOINT_LEN}


class SDOption_IP6_EndPoint(_SDOption_IP6):
    name = "IP6 EndPoint Option"
    _defaults = {'type': _SDOption.IP6_ENDPOINT_TYPE,
                 'len': _SDOption.IP6_ENDPOINT_LEN}


class SDOption_IP6_Multicast(_SDOption_IP6):
    name = "IP6 Multicast Option"
    _defaults = {'type': _SDOption.IP6_MCAST_TYPE,
                 'len': _SDOption.IP6_MCAST_LEN}


class SDOption_IP6_SD_EndPoint(_SDOption_IP6):
    name = "IP6 SDEndPoint Option"
    _defaults = {'type': _SDOption.IP6_SDENDPOINT_TYPE,
                 'len': _SDOption.IP6_SDENDPOINT_LEN}


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
        ByteField("flags", 0),
        X3BytesField("res", 0),
        FieldLenField("len_entry_array", None,
                      length_of="entry_array", fmt="!I"),
        PacketListField("entry_array", None, cls=_SDEntry,
                        length_from=lambda pkt: pkt.len_entry_array),
        FieldLenField("len_option_array", None,
                      length_of="option_array", fmt="!I"),
        PacketListField("option_array", None, cls=_SDOption,
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
               client_id=SD.SOMEIP_CLIENT_ID,
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
