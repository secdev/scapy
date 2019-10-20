#! /usr/bin/env python

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

# scapy.contrib.description = SOME/IP Service Discovery
# scapy.contrib.status = loads

import ctypes
import collections
import struct

from scapy.packet import Packet, Raw
from scapy.fields import ByteField, BitField, ShortField, \
    X3BytesField, IntField, ByteEnumField, StrField, IPField, \
    FieldLenField, PacketListField
from scapy.contrib.automotive.someip import SOMEIP
from scapy.layers.inet6 import IP6Field
from scapy.compat import orb


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
#  - Service
#  - EventGroup
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

        if (pl_type in _SDEntry.TYPE_SRV):
            return (SDEntry_Service)
        elif (pl_type in _SDEntry.TYPE_EVTGRP):
            return (SDEntry_EventGroup)


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
#  - Configuration
#  - LoadBalancing
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
        if (length is None):
            length = len(self.cfg_str) + self.LEN_OFFSET
            pkt = struct.pack("!H", length) + pkt[2:]
        return (pkt + pay)


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
    SOMEIP_PROTO_VER = 0x01
    SOMEIP_IFACE_VER = 0x01
    SOMEIP_MSG_TYPE = SOMEIP.TYPE_NOTIFICATION

    name = "SD"
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
        if (name in self.FLAGSDEF):
            return ((self.flags & self.FLAGSDEF[name].mask) >>
                    self.FLAGSDEF[name].offset)
        else:
            return None

    def set_flag(self, name, value):
        name = name.upper()
        if (name in self.FLAGSDEF):
            self.flags = (self.flags &
                          (ctypes.c_ubyte(~self.FLAGSDEF[name].mask).value)) \
                | ((value & 0x01) << self.FLAGSDEF[name].offset)

    def set_entryArray(self, entry_list):
        if (isinstance(entry_list, list)):
            self.entry_array = entry_list
        else:
            self.entry_array = [entry_list]

    def set_optionArray(self, option_list):
        if (isinstance(option_list, list)):
            self.option_array = option_list
        else:
            self.option_array = [option_list]

    def get_someip(self, stacked=False):
        p = SOMEIP()
        p.msg_id.srv_id = SD.SOMEIP_MSGID_SRVID
        p.msg_id.sub_id = SD.SOMEIP_MSGID_SUBID
        p.msg_id.event_id = SD.SOMEIP_MSGID_EVENTID
        p.proto_ver = SD.SOMEIP_PROTO_VER
        p.iface_ver = SD.SOMEIP_IFACE_VER
        p.msg_type = SD.SOMEIP_MSG_TYPE

        if (stacked):
            return (p / self)
        else:
            return (p)
