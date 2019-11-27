# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

# scapy.contrib.description = Socket Secure (SOCKS)
# scapy.contrib.status = loads

"""SOCKS4/5 Protocol

You can change the server ports that are used in the SOCKS layer by editing.
conf.contribs['socks']['serverports']
"""

from scapy.config import conf
from scapy.error import warning
from scapy.layers.dns import DNSStrField
from scapy.layers.inet import TCP, UDP
from scapy.layers.inet6 import IP6Field
from scapy.fields import ByteField, ByteEnumField, ShortField, IPField, \
    StrField, MultipleTypeField
from scapy.packet import Packet, bind_layers, bind_bottom_up

# TODO: support the 3 different authentication exchange procedures for SOCKS5  # noqa: E501
# 1 - Plain (https://tools.ietf.org/html/rfc1928 - 3.Procedure for TCP-based clients)  # noqa: E501
# 2 - Username/password (https://tools.ietf.org/html/rfc1929)
# 3 - GSS-API (https://tools.ietf.org/html/rfc1961)

conf.contribs.setdefault('socks', {})
conf.contribs['socks'].setdefault('serverports', [1080])


class SOCKS(Packet):
    fields_desc = [
        ByteEnumField("vn", 0x5,
                      {0x4: "v4 - Request", 0x0: "v4 - Reply", 0x5: "v5"}),
    ]

    def guess_payload_class(self, pkt):
        d_port = s_port = True
        if self.underlayer and isinstance(self.underlayer, TCP):
            ports = conf.contribs['socks']['serverports']
            d_port = self.underlayer.dport in ports
            s_port = self.underlayer.sport in ports
        if self.vn == 0x5:
            if d_port:
                return SOCKS5Request
            elif s_port:
                return SOCKS5Reply
        elif self.vn == 0x4:
            if d_port:
                return SOCKS4Request
        elif self.vn == 0x0:
            if s_port:
                return SOCKS4Reply
        warning("No TCP underlayer, or dport/sport not in "
                "conf.contribs['socks']['serverports']. "
                "Assuming a SOCKS v5 request layer")
        return SOCKS5Request

    def add_payload(self, payload):
        if self.underlayer and isinstance(self.underlayer, TCP):
            if isinstance(payload, (SOCKS5Request, SOCKS4Request)):
                self.underlayer.dport = 1080
                self.underlayer.sport = 1081
            elif isinstance(payload, (SOCKS5Reply, SOCKS4Reply)):
                self.underlayer.sport = 1080
                self.underlayer.dport = 1081
        Packet.add_payload(self, payload)


bind_bottom_up(TCP, SOCKS, sport=1080)
bind_bottom_up(TCP, SOCKS, dport=1080)

# SOCKS v4

_socks4_cd_request = {
    1: "Connect",
    2: "Bind"
}


class SOCKS4Request(Packet):
    name = "SOCKS 4 - Request"
    overload_fields = {SOCKS: {"vn": 0x4}}
    fields_desc = [
        ByteEnumField("cd", 1, _socks4_cd_request),
        ShortField("dstport", 80),
        IPField("dst", "0.0.0.0"),
        StrField("userid", ""),
        ByteField("null", 0),
    ]


_socks4_cd_reply = {
    90: "Request granted",
    91: "Request rejected",
    92: "Request rejected - SOCKS server cannot connect to identd",
    93: "Request rejected - user-ids mismatch"
}


class SOCKS4Reply(Packet):
    name = "SOCKS 4 - Reply"
    overload_fields = {SOCKS: {"vn": 0x0}}
    fields_desc = [
        ByteEnumField("cd", 90, _socks4_cd_reply),
    ] + SOCKS4Request.fields_desc[1:-2]  # Re-use dstport, dst and userid

# SOCKS v5 - TCP


_socks5_cdtypes = {
    1: "Connect",
    2: "Bind",
    3: "UDP associate",
}


class SOCKS5Request(Packet):
    name = "SOCKS 5 - Request"
    overload_fields = {SOCKS: {"vn": 0x5}}
    fields_desc = [
        ByteEnumField("cd", 0x0, _socks5_cdtypes),
        ByteField("res", 0),
        ByteEnumField("atyp", 0x1,
                      {0x1: "IPv4", 0x3: "DomainName", 0x4: "IPv6"}),
        MultipleTypeField(
            [
                # IPv4
                (IPField("addr", "0.0.0.0"), lambda pkt: pkt.atyp == 0x1),
                # DNS
                (DNSStrField("addr", ""), lambda pkt: pkt.atyp == 0x3),
                # IPv6
                (IP6Field("addr", "::"), lambda pkt: pkt.atyp == 0x4),
            ],
            StrField("addr", "")
        ),
        ShortField("port", 80),
    ]


_socks5_rep = {
    0: "succeeded",
    1: "general server failure",
    2: "connection not allowed by ruleset",
    3: "network unreachable",
    4: "host unreachable",
    5: "connection refused",
    6: "TTL expired",
    7: "command not supported",
    8: "address type not supported",
}


class SOCKS5Reply(Packet):
    name = "SOCKS 5 - Reply"
    overload_fields = {SOCKS: {"vn": 0x5}}
    # All fields are the same except the first one
    fields_desc = [
        ByteEnumField("rep", 0x0, _socks5_rep),
    ] + SOCKS5Request.fields_desc[1:]


# SOCKS v5 - UDP

class SOCKS5UDP(Packet):
    name = "SOCKS 5 - UDP Header"
    fields_desc = [
        ShortField("res", 0),
        ByteField("frag", 0),
    ] + SOCKS5Request.fields_desc[2:]  # Re-use the atyp, addr and port fields

    def guess_payload_class(self, s):
        if self.port == 0:
            return conf.raw_layer
        return UDP(sport=self.port, dport=self.port).guess_payload_class(None)


bind_bottom_up(UDP, SOCKS5UDP, sport=1080)
bind_bottom_up(UDP, SOCKS5UDP, sport=1080)
bind_layers(UDP, SOCKS5UDP, sport=1080, dport=1080)
