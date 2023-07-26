# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) 2023 - Claire VACHEROT <clairelex[at]pm.me>

"""HICP

Support for HICP (Host IP Control Protocol).

This protocol is used by HMS Anybus software for device discovery and
configuration.

Note : As the specification is not public, this layer was built based on the
Wireshark dissector and HMS's HICP DLL. It was tested with a Anybus X-gateway
device. Therefore, this implementation may differ from what is written in the
standard.
"""

# scapy.contrib.name = HICP
# scapy.contrib.description = HMS Anybus Host IP Control Protocol
# scapy.contrib.status = loads

from re import match

from scapy.packet import Packet, bind_layers, bind_bottom_up
from scapy.fields import StrField, MACField, IPField, ByteField, RawVal
from scapy.layers.inet import UDP

# HICP command codes
CMD_MODULESCAN = b"Module scan"
CMD_MSRESPONSE = b"Module scan response"
CMD_CONFIGURE = b"Configure"
CMD_RECONFIGURED = b"Reconfigured"
CMD_INVALIDCONF = b"Invalid Configuration"
CMD_INVALIDPWD = b"Invalid Password"
CMD_WINK = b"Wink"
# These commands are implemented in the DLL but never seen in use
CMD_START = b"Start"
CMD_STOP = b"Stop"

# Most of the fields have the format "KEY = value" for each field
KEYS = {
    "protocol_version": "Protocol version",
    "fieldbus_type": "FB type",
    "module_version": "Module version",
    "mac_address": "MAC",
    "new_password": "New password",
    "password": "PSWD",
    "ip_address": "IP",
    "subnet_mask": "SN",
    "gateway_address": "GW",
    "dhcp": "DHCP",
    "hostname": "HN",
    "dns1": "DNS1",
    "dns2": "DNS2"
}

# HICP MAC format is xx-xx-xx-xx-xx-xx (not with :) as str.
FROM_MACFIELD = lambda x: x.replace(":", "-")
TO_MACFIELD = lambda x: x.replace("-", ":")

# Note on building and dissecting: Since the protocol is primarily text-based
# but also highly inconsistent in terms of message format, most of the
# dissection and building process must be reworked for each message type.


class HICPConfigure(Packet):
    name = "Configure request"
    fields_desc = [
        MACField("target", "ff:ff:ff:ff:ff:ff"),
        StrField("password", ""),
        StrField("new_password", ""),
        IPField("ip_address", "255.255.255.255"),
        IPField("subnet_mask", "255.255.255.0"),
        IPField("gateway_address", "0.0.0.0"),
        StrField("dhcp", "OFF"),  # ON or OFF
        StrField("hostname", ""),
        IPField("dns1", "0.0.0.0"),
        IPField("dns2", "0.0.0.0"),
        ByteField("padding", 0)
    ]

    def post_build(self, p, pay):
        p = ["{0}: {1};".format(CMD_CONFIGURE.decode('utf-8'),
                                FROM_MACFIELD(self.target))]
        for field in self.fields_desc[1:]:
            if field.name in KEYS:
                value = getattr(self, field.name)
                if isinstance(value, bytes):
                    value = value.decode('utf-8')
                if field.name in ["password", "new_password"] and not value:
                    continue
                key = KEYS[field.name]
                # The key for password is not the same as usual...
                if field.name == "password":
                    key = "Password"
                p.append("{0} = {1};".format(key, value))
        return "".join(p).encode('utf-8') + b"\x00" + pay

    def do_dissect(self, s):
        res = match(".*: ([^;]+);", s.decode('utf-8'))
        if res:
            self.target = TO_MACFIELD(res.group(1))
        s = s[len(self.target) + 3:]
        for arg in s.split(b";"):
            kv = [x.strip().replace(b"\x00", b"") for x in arg.split(b"=")]
            if len(kv) != 2 or not kv[1]:
                continue
            kv[0] = kv[0].decode('utf-8')
            if kv[0] in KEYS.values():
                field = [x for x, y in KEYS.items() if y == kv[0]][0]
                setattr(self, field, kv[1])


class HICPReconfigured(Packet):
    name = "Reconfigured"
    fields_desc = [
        MACField("source", "ff:ff:ff:ff:ff:ff")
    ]

    def post_build(self, p, pay):
        p = "{0}: {1}".format(CMD_RECONFIGURED.decode('utf-8'),
                              FROM_MACFIELD(self.source))
        return p.encode('utf-8') + b"\x00" + pay

    def do_dissect(self, s):
        res = match(r".*: ([a-fA-F0-9\-\:]+)", s.decode('utf-8'))
        if res:
            self.source = TO_MACFIELD(res.group(1))
        return None


class HICPInvalidConfiguration(Packet):
    name = "Invalid configuration"
    fields_desc = [
        MACField("source", "ff:ff:ff:ff:ff:ff")
    ]

    def post_build(self, p, pay):
        p = "{0}: {1}".format(CMD_INVALIDCONF.decode('utf-8'),
                              FROM_MACFIELD(self.source))
        return p.encode('utf-8') + b"\x00" + pay

    def do_dissect(self, s):
        res = match(r".*: ([a-fA-F0-9\-\:]+)", s.decode('utf-8'))
        if res:
            self.source = TO_MACFIELD(res.group(1))
        return None


class HICPInvalidPassword(Packet):
    name = "Invalid password"
    fields_desc = [
        MACField("source", "ff:ff:ff:ff:ff:ff")
    ]

    def post_build(self, p, pay):
        p = "{0}: {1}".format(CMD_INVALIDPWD.decode('utf-8'),
                              FROM_MACFIELD(self.source))
        return p.encode('utf-8') + b"\x00" + pay

    def do_dissect(self, s):
        res = match(r".*: ([a-fA-F0-9\-\:]+)", s.decode('utf-8'))
        if res:
            self.source = TO_MACFIELD(res.group(1))
        return None


class HICPWink(Packet):
    name = "Wink"
    fields_desc = [
        MACField("target", "ff:ff:ff:ff:ff:ff"),
        ByteField("padding", 0)
    ]

    def post_build(self, p, pay):
        p = "To: {0};{1};".format(FROM_MACFIELD(self.target),
                                  CMD_WINK.decode('utf-8').upper())
        return p.encode('utf-8') + b"\x00" + pay

    def do_dissect(self, s):
        res = match("^To: ([^;]+);", s.decode('utf-8'))
        if res:
            self.target = TO_MACFIELD(res.group(1))


class HICPModuleScanResponse(Packet):
    name = "Module scan response"
    fields_desc = [
        StrField("protocol_version", "1.00"),
        StrField("fieldbus_type", ""),
        StrField("module_version", ""),
        MACField("mac_address", "ff:ff:ff:ff:ff:ff"),
        IPField("ip_address", "255.255.255.255"),
        IPField("subnet_mask", "255.255.255.0"),
        IPField("gateway_address", "0.0.0.0"),
        StrField("dhcp", "OFF"),  # ON or OFF
        StrField("password", "OFF"),  # ON or OFF
        StrField("hostname", ""),
        IPField("dns1", "0.0.0.0"),
        IPField("dns2", "0.0.0.0"),
        ByteField("padding", 0)
    ]

    def post_build(self, p, pay):
        p = []
        for field in self.fields_desc:
            if field.name in KEYS:
                value = getattr(self, field.name)
                if isinstance(value, bytes):
                    value = value.decode('utf-8')
                p.append("{0} = {1};".format(KEYS[field.name], value))
        return "".join(p).encode('utf-8') + b"\x00" + pay

    def do_dissect(self, s):
        for arg in s.split(b";"):
            kv = [x.strip().replace(b"\x00", b"") for x in arg.split(b"=")]
            if len(kv) != 2 or not kv[1]:
                continue
            kv[0] = kv[0].decode('utf-8')
            if kv[0] in KEYS.values():
                field = [x for x, y in KEYS.items() if y == kv[0]][0]
                if field == "mac_address":
                    kv[1] = TO_MACFIELD(kv[1].decode('utf-8'))
                setattr(self, field, kv[1])


class HICPModuleScan(Packet):
    name = "Module scan request"
    fields_desc = [
        StrField("hicp_command", CMD_MODULESCAN),
        ByteField("padding", 0)
    ]

    def do_dissect(self, s):
        if len(s) > len(CMD_MODULESCAN):
            self.hicp_command = s[:len(CMD_MODULESCAN)]
            self.padding = s[len(CMD_MODULESCAN):]
        else:
            self.padding = RawVal(s)

    def post_build(self, p, pay):
        return p.upper() + pay


class HICP(Packet):
    name = "HICP"
    fields_desc = [
        StrField("hicp_command", "")
    ]

    def do_dissect(self, s):
        for cmd in [CMD_MODULESCAN, CMD_CONFIGURE, CMD_RECONFIGURED,
                    CMD_INVALIDCONF, CMD_INVALIDPWD]:
            if s[:len(cmd)] == cmd:
                self.hicp_command = cmd
                return s[len(cmd):]
        if s[:len("To:")] == b"To:":
            self.hicp_command = CMD_WINK
        else:
            self.hicp_command = CMD_MSRESPONSE
        return s

    def post_build(self, p, pay):
        p = p[len(self.hicp_command):]
        return p + pay


bind_bottom_up(UDP, HICP, dport=3250)
bind_bottom_up(UDP, HICP, sport=3250)
bind_layers(UDP, HICP, sport=3250, dport=3250)
bind_layers(HICP, HICPModuleScan, hicp_command=CMD_MODULESCAN)
bind_layers(HICP, HICPModuleScanResponse, hicp_command=CMD_MSRESPONSE)
bind_layers(HICP, HICPWink, hicp_command=CMD_WINK)
bind_layers(HICP, HICPConfigure, hicp_command=CMD_CONFIGURE)
bind_layers(HICP, HICPReconfigured, hicp_command=CMD_RECONFIGURED)
bind_layers(HICP, HICPInvalidConfiguration, hicp_command=CMD_INVALIDCONF)
bind_layers(HICP, HICPInvalidPassword, hicp_command=CMD_INVALIDPWD)
