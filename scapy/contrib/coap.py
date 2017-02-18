# This file is part of Scapy.
# See http://www.secdev.org/projects/scapy for more information.
#
# Scapy is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# Scapy is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Scapy.  If not, see <http://www.gnu.org/licenses/>.
#
# Copyright (C) 2016 Anmol Sarma <me@anmolsarma.in>

"""
RFC 7252 - Constrained Application Protocol (CoAP) layer for Scapy
"""

from scapy.fields import *
from scapy.layers.inet import UDP
from scapy.packet import *
from scapy.error import warning

coap_codes = {
    0: "Empty",
    # Request codes
    1: "GET",
    2: "POST",
    3: "PUT",
    4: "DELETE",
    # Response codes
    65: "2.01 Created",
    66: "2.02 Deleted",
    67: "2.03 Valid",
    68: "2.04 Changed",
    69: "2.05 Content",
    128: "4.00 Bad Request",
    129: "4.01 Unauthorized",
    130: "4.02 Bad Option",
    131: "4.03 Forbidden",
    132: "4.04 Not Found",
    133: "4.05 Method Not Allowed",
    134: "4.06 Not Acceptable",
    140: "4.12 Precondition Failed",
    141: "4.13 Request Entity Too Large",
    143: "4.15 Unsupported Content-Format",
    160: "5.00 Internal Server Error",
    161: "5.01 Not Implemented",
    162: "5.02 Bad Gateway",
    163: "5.03 Service Unavailable",
    164: "5.04 Gateway Timeout",
    165: "Proxying Not Supported"}

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
        return 269 + struct.unpack('H', ext_val)[0]
    if val == 13:
        return 13 + struct.unpack('B', ext_val)[0]
    return val


def _get_opt_val_size(pkt):
    return _get_abs_val(pkt.len, pkt.len_ext)


class _CoAPOpt(Packet):
    fields_desc = [BitField("delta", 0, 4),
                   BitField("len", 0, 4),
                   StrLenField("delta_ext", None, length_from=_get_delta_ext_size),
                   StrLenField("len_ext", None, length_from=_get_len_ext_size),
                   StrLenField("opt_val", None, length_from=_get_opt_val_size)]

    @staticmethod
    def _populate_extended(val):
        if val >= 269:
            return struct.pack('H', val - 269), 14
        if val >= 13:
            return struct.pack('B', val - 13), 13
        return None, val

    def do_build(self):
        self.delta_ext, self.delta = self._populate_extended(self.delta)
        self.len_ext, self.len = self._populate_extended(len(self.opt_val))

        return Packet.do_build(self)

    def guess_payload_class(self, payload):
        if payload[0] != '\xff':
            return _CoAPOpt
        else:
            return Packet.guess_payload_class(self, payload)


class _CoAPOptsField(StrField):
    islist = 1

    def i2h(self, pkt, x):
        return [(coap_options[0][o[0]], o[1]) if o[0] in coap_options[0] else o for o in x]

    def getfield(self, pkt, s):
        return "", self.m2i(pkt, s)

    def m2i(self, pkt, x):
        opts = []
        o = _CoAPOpt(x)
        cur_delta = 0
        while isinstance(o, _CoAPOpt):
            cur_delta += _get_abs_val(o.delta, o.delta_ext)
            opts.append((cur_delta, o.opt_val))
            o = o.payload
        return opts

    def i2m(self, pkt, x):
        if not x:
            return ""
        opt_lst = []
        for o in x:
            if isinstance(o[0], str):
                opt_lst.append((coap_options[1][o[0]], o[1]))
            else:
                opt_lst.append(o)
        opt_lst.sort(key=lambda o:o[0])

        opts = _CoAPOpt(delta=opt_lst[0][0], opt_val=opt_lst[0][1])
        high_opt = opt_lst[0][0]
        for o in opt_lst[1:]:
            opts = opts / _CoAPOpt(delta=o[0] - high_opt, opt_val=o[1])
            high_opt = o[0]

        return str(opts)


class CoAP(Packet):
    name = "CoAP"

    fields_desc = [BitField("ver", 1, 2),
                   BitEnumField("type", 0, 2, {0: "CON", 1: "NON", 2: "ACK", 3: "RST"}),
                   BitFieldLenField("tkl", None, 4, length_of='token'),
                   ByteEnumField("code", 0, coap_codes),
                   ShortField("msg_id", 0),
                   StrLenField("token", "", length_from=lambda pkt: pkt.tkl),
                   _CoAPOptsField("options", [])
                   ]


bind_layers(UDP, CoAP, sport=5683)
bind_layers(UDP, CoAP, dport=5683)
