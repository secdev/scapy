# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) 2016 Anmol Sarma <me@anmolsarma.in>

# scapy.contrib.description = Constrained Application Protocol (CoAP)
# scapy.contrib.status = loads

"""
RFC 7252 - Constrained Application Protocol (CoAP) layer for Scapy
"""

import struct

from scapy.fields import BitEnumField, BitField, BitFieldLenField, \
    ByteEnumField, ShortField, StrField, StrLenField
from scapy.layers.inet import UDP
from scapy.packet import Packet, bind_layers
from scapy.error import warning
from scapy.compat import raw

"""
CoAP message request codes (RFC 7252 @ section-5.8.1)
"""
EMPTY_MESSAGE = 0
GET = 1
POST = 2
PUT = 3
DELETE = 4
COAP_REQ_CODES = [GET, POST, PUT, DELETE]
"""
CoAP message response codes (RFC 7252 @ section-12.1.2)
"""
EMPTY_ACK = EMPTY_MESSAGE
CONTENT_205 = 69
NOT_FOUND_404 = 132
NOT_ALLOWED_405 = 133
NOT_IMPLEMENTED_501 = 161
"""
CoAP content type (RFC 7252 @ section-12.3)
"""
CF_TEXT_PLAIN = b"\x00"
CF_APP_LINK_FORMAT = b"\x28"
CF_APP_XML = b"\x29"
CF_APP_OCTET_STREAM = b"\x2A"
CF_APP_EXI = b"\x2F"
CF_APP_JSON = b"\x32"
"""
CoAP options (RFC 7252 @ section-5.10)
"""
PAYMARK = b"\xff"
URI_PATH = 11
CONTENT_FORMAT = 12
"""
CoAP message type
"""
CON = 0
NON = 1
ACK = 2
RST = 3

coap_codes = {
    EMPTY_MESSAGE: "Empty",
    # Request codes
    GET: "GET",
    POST: "POST",
    PUT: "PUT",
    DELETE: "DELETE",
    # Response codes
    65: "2.01 Created",
    66: "2.02 Deleted",
    67: "2.03 Valid",
    68: "2.04 Changed",
    CONTENT_205: "2.05 Content",
    128: "4.00 Bad Request",
    129: "4.01 Unauthorized",
    130: "4.02 Bad Option",
    131: "4.03 Forbidden",
    NOT_FOUND_404: "4.04 Not Found",
    NOT_ALLOWED_405: "4.05 Method Not Allowed",
    134: "4.06 Not Acceptable",
    140: "4.12 Precondition Failed",
    141: "4.13 Request Entity Too Large",
    143: "4.15 Unsupported Content-Format",
    160: "5.00 Internal Server Error",
    NOT_IMPLEMENTED_501: "5.01 Not Implemented",
    162: "5.02 Bad Gateway",
    163: "5.03 Service Unavailable",
    164: "5.04 Gateway Timeout",
    165: "5.05 Proxying Not Supported"}

coap_options = ({
    1: "If-Match",
    3: "Uri-Host",
    4: "ETag",
    5: "If-None-Match",
    7: "Uri-Port",
    8: "Location-Path",
    11: "Uri-Path",
    12: "Content-Format",
    14: "Max-Age",
    15: "Uri-Query",
    17: "Accept",
    20: "Location-Query",
    35: "Proxy-Uri",
    39: "Proxy-Scheme",
    60: "Size1"
},
    {
    "If-Match": 1,
    "Uri-Host": 3,
    "ETag": 4,
    "If-None-Match": 5,
    "Uri-Port": 7,
    "Location-Path": 8,
    "Uri-Path": 11,
    "Content-Format": 12,
    "Max-Age": 14,
    "Uri-Query": 15,
    "Accept": 17,
    "Location-Query": 20,
    "Proxy-Uri": 35,
    "Proxy-Scheme": 39,
    "Size1": 60
})


def _get_ext_field_size(val):
    if val >= 15:
        warning("Invalid Option Delta or Length")
    if val == 14:
        return 2
    if val == 13:
        return 1
    return 0


def _get_delta_ext_size(pkt):
    return _get_ext_field_size(pkt.delta)


def _get_len_ext_size(pkt):
    return _get_ext_field_size(pkt.len)


def _get_abs_val(val, ext_val):
    if val >= 15:
        warning("Invalid Option Length or Delta %d" % val)
    if val == 14:
        return 269 + struct.unpack('!H', ext_val)[0]
    if val == 13:
        return 13 + struct.unpack('B', ext_val)[0]
    return val


def _get_opt_val_size(pkt):
    return _get_abs_val(pkt.len, pkt.len_ext)


class _CoAPOpt(Packet):
    fields_desc = [BitField("delta", 0, 4),
                   BitField("len", 0, 4),
                   StrLenField("delta_ext", "", length_from=_get_delta_ext_size),
                   # noqa: E501
                   StrLenField("len_ext", "", length_from=_get_len_ext_size),
                   StrLenField("opt_val", "", length_from=_get_opt_val_size)]

    @staticmethod
    def _populate_extended(val):
        if val >= 269:
            return struct.pack('!H', val - 269), 14
        if val >= 13:
            return struct.pack('B', val - 13), 13
        return None, val

    def do_build(self):
        self.delta_ext, self.delta = self._populate_extended(self.delta)
        self.len_ext, self.len = self._populate_extended(len(self.opt_val))

        return Packet.do_build(self)

    def guess_payload_class(self, payload):
        if payload[:1] != b"\xff":
            return _CoAPOpt
        else:
            return Packet.guess_payload_class(self, payload)


class _CoAPOptsField(StrField):
    islist = 1

    def i2h(self, pkt, x):
        return [(coap_options[0][o[0]], o[1]) if o[0] in coap_options[0] else o for o in
                x]  # noqa: E501

    # consume only the coap layer from the wire string
    def getfield(self, pkt, s):
        opts = self.m2i(pkt, s)
        used = 0
        for o in opts:
            used += o[0]
        return s[used:], [(o[1], o[2]) for o in opts]

    def m2i(self, pkt, x):
        opts = []
        o = _CoAPOpt(x)
        cur_delta = 0
        while isinstance(o, _CoAPOpt):
            cur_delta += _get_abs_val(o.delta, o.delta_ext)
            # size of this option in bytes
            u = 1 + len(o.opt_val) + len(o.delta_ext) + len(o.len_ext)
            opts.append((u, cur_delta, o.opt_val))
            o = o.payload
        return opts

    def i2m(self, pkt, x):
        if not x:
            return b""
        opt_lst = []
        for o in x:
            if isinstance(o[0], str):
                opt_lst.append((coap_options[1][o[0]], o[1]))
            else:
                opt_lst.append(o)
        opt_lst.sort(key=lambda o: o[0])

        opts = _CoAPOpt(delta=opt_lst[0][0], opt_val=opt_lst[0][1])
        high_opt = opt_lst[0][0]
        for o in opt_lst[1:]:
            opts = opts / _CoAPOpt(delta=o[0] - high_opt, opt_val=o[1])
            high_opt = o[0]

        return raw(opts)


class _CoAPPaymark(StrField):

    def i2h(self, pkt, x):
        return x

    def getfield(self, pkt, s):
        (u, m) = self.m2i(pkt, s)
        return s[u:], m

    def m2i(self, pkt, x):
        if len(x) > 0 and x[:1] == b"\xff":
            return 1, b'\xff'
        return 0, b''

    def i2m(self, pkt, x):
        return x


class CoAP(Packet):
    __slots__ = ["content_format"]
    name = "CoAP"

    fields_desc = [BitField("ver", 1, 2),
                   BitEnumField("type", 0, 2, {0: "CON", 1: "NON", 2: "ACK", 3: "RST"}),
                   # noqa: E501
                   BitFieldLenField("tkl", None, 4, length_of='token'),
                   ByteEnumField("code", 0, coap_codes),
                   ShortField("msg_id", 0),
                   StrLenField("token", "", length_from=lambda pkt: pkt.tkl),
                   _CoAPOptsField("options", []),
                   _CoAPPaymark("paymark", b"")
                   ]

    def getfieldval(self, attr):
        v = getattr(self, attr)
        if v:
            return v
        return Packet.getfieldval(self, attr)

    def post_dissect(self, pay):
        for k in self.options:
            if k[0] == "Content-Format":
                self.content_format = k[1]
        return pay

    def hashret(self):
        return struct.pack('I', self.msg_id) + self.token

    def answers(self, other):
        # type: (Packet) -> int
        """
        DEV: true if self is an answer from other
        Any response that is inside coap_codes that is not a request is valid.
        i.e.: do not answer a request with a request.
        """
        if self.code not in COAP_REQ_CODES:
            if self.code in coap_codes.keys():
                return 1
        return 0


bind_layers(UDP, CoAP, sport=5683)
bind_layers(UDP, CoAP, dport=5683)
