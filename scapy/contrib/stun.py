# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Pavel Oborin <oborin.p@gmail.com>

# RFC 8489
# scapy.contrib.description = Session Traversal Utilities for NAT (STUN)
# scapy.contrib.status = loads

"""
    STUN (RFC 8489)

    TLV code derived from the DTP implementation:
      Thanks to Nicolas Bareil,
                Arnaud Ebalard,
                Jochen Bartl.
"""
import struct
import itertools

from scapy.layers.inet import UDP, TCP
from scapy.config import conf
from scapy.packet import Packet, bind_bottom_up, bind_top_down
from scapy.utils import inet_ntoa, inet_aton
from scapy.fields import (
    BitField,
    BitEnumField,
    LenField,
    IntField,
    PadField,
    StrLenField,
    PacketListField,
    XShortField,
    FieldLenField,
    ShortField,
    ByteEnumField,
    ByteField,
    XNBytesField,
    XLongField,
    XIntField,
    XBitField,
    IPField,
    IP6Field,
    MultipleTypeField,
)

MAGIC_COOKIE = 0x2112A442

_stun_class = {
    "request": 0b00,
    "indication": 0b01,
    "success response": 0b10,
    "error response": 0b11
}

_stun_method = {
    "Binding": 0b000000000001
}

# fmt: off
_stun_message_type = {
    "{} {}".format(method, class_):
        (method_code & 0b000000001111)      |    # noqa: E221,W504
        (class_code  & 0b01)           << 4 |    # noqa: E221,W504
        (method_code & 0b000001110000) << 5 |    # noqa: E221,W504
        (class_code  & 0b10)           << 7 |    # noqa: E221,W504
        (method_code & 0b111110000000) << 9
    for (method, method_code), (class_, class_code) in
        itertools.product(_stun_method.items(), _stun_class.items())    # noqa: E131
}
# fmt: on


class STUNGenericTlv(Packet):
    name = "STUN Generic TLV"

    fields_desc = [
        XShortField("type", 0x0000),
        FieldLenField("length", None, length_of="value"),
        PadField(StrLenField("value", "", length_from=lambda pkt:pkt.length), align=4)
    ]

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kwargs):
        if _pkt and len(_pkt) >= 2:
            t = struct.unpack("!H", _pkt[:2])[0]
            return _stun_tlv_class.get(t, cls)
        return cls

    def guess_payload_class(self, payload):
        return conf.padding_layer


class STUNUsername(STUNGenericTlv):
    name = "STUN Username"

    fields_desc = [
        XShortField("type", 0x0006),
        FieldLenField("length", None, length_of="username"),
        PadField(
            StrLenField("username", '', length_from=lambda pkt: pkt.length),
            align=4, padwith=b"\x20"
        )
    ]


class STUNMessageIntegrity(STUNGenericTlv):
    name = "STUN Message Integrity"

    fields_desc = [
        XShortField("type", 0x0008),
        ShortField("length", 20),
        XNBytesField("hmac_sha1", 0, 20)
    ]

    def post_build(self, pkt, pay):
        pkt += pay
        return pkt


class STUNPriority(STUNGenericTlv):
    name = "STUN Priority"

    fields_desc = [
        XShortField("type", 0x0024),
        ShortField("length", 4),
        IntField("priority", 0)
    ]


_xor_mapped_address_family = {
    "IPv4": 0x01,
    "IPv6": 0x02
}


class XorPort(ShortField):

    def m2i(self, pkt, x):
        return x ^ (MAGIC_COOKIE >> 16)

    def i2m(self, pkt, x):
        return x ^ (MAGIC_COOKIE >> 16)


class XorIp(IPField):

    def m2i(self, pkt, x):
        return inet_ntoa(struct.pack(">i", (struct.unpack(">i", x)[0] ^ MAGIC_COOKIE)))

    def i2m(self, pkt, x):
        if x is None:
            return b"\x00\x00\x00\x00"
        return struct.pack(">i", struct.unpack(">i", inet_aton(x))[0] ^ MAGIC_COOKIE)


class XorIp6(IP6Field):

    def m2i(self, pkt, x):
        addr = self._xor_address(pkt, x)
        return super().m2i(pkt, addr)

    def i2m(self, pkt, x):
        addr = super().i2m(pkt, x)
        return self._xor_address(pkt, addr)

    def _xor_address(self, pkt, addr):
        xor_words = [pkt.parent.magic_cookie]
        xor_words += struct.unpack(
            ">III", pkt.parent.transaction_id.to_bytes(12, "big")
        )
        addr_words = struct.unpack(">IIII", addr)
        xor_addr = [a ^ b for a, b in zip(addr_words, xor_words)]
        return struct.pack(">IIII", *xor_addr)


class STUNXorMappedAddress(STUNGenericTlv):
    name = "STUN XOR Mapped Address"

    fields_desc = [
        XShortField("type", 0x0020),
        FieldLenField("length", None, length_of="xip", adjust=lambda pkt, x: x + 4),
        ByteField("RESERVED", 0),
        ByteEnumField("address_family", 1, _xor_mapped_address_family),
        XorPort("xport", 0),
        MultipleTypeField(
            [
                (XorIp("xip", "127.0.0.1"), lambda pkt: pkt.address_family == 1),
                (XorIp6("xip", "::1"), lambda pkt: pkt.address_family == 2),
            ],
            XorIp("xip", "127.0.0.1"),
        ),
    ]


class STUNMappedAddress(STUNGenericTlv):
    name = "STUN Mapped Address"

    fields_desc = [
        XShortField("type", 0x0001),
        FieldLenField("length", None, length_of="ip", adjust=lambda pkt, x: x + 4),
        ByteField("RESERVED", 0),
        ByteEnumField("address_family", 1, _xor_mapped_address_family),
        ShortField("port", 0),
        MultipleTypeField(
            [
                (IPField("ip", "127.0.0.1"), lambda pkt: pkt.address_family == 1),
                (IP6Field("ip", "::1"), lambda pkt: pkt.address_family == 2),
            ],
            IPField("ip", "127.0.0.1"),
        ),
    ]


class STUNUseCandidate(STUNGenericTlv):
    name = "STUN Use Candidate"

    fields_desc = [
        XShortField("type", 0x0025),
        FieldLenField("length", 0, length_of="value"),
        PadField(StrLenField("value", "", length_from=lambda pkt: pkt.length), align=4)
    ]


class STUNFingerprint(STUNGenericTlv):
    name = "STUN Fingerprint"

    fields_desc = [
        XShortField("type", 0x8028),
        ShortField("length", 4),
        XIntField("crc_32", None)
    ]


class STUNIceControlling(STUNGenericTlv):
    name = "STUN ICE-controlling"

    fields_desc = [
        XShortField("type", 0x802a),
        ShortField("length", 8),
        XLongField("tie_breaker", None)
    ]


class STUNGoogNetworkInfo(STUNGenericTlv):
    name = "STUN Google Network Info"

    fields_desc = [
        XShortField("type", 0xc057),
        ShortField("length", 4),
        ShortField("network_id", 0),
        ShortField("network_cost", 999)
    ]


_stun_tlv_class = {
    0x0001: STUNMappedAddress,
    0x0006: STUNUsername,
    0x0008: STUNMessageIntegrity,
    0x0020: STUNXorMappedAddress,
    0x0025: STUNUseCandidate,
    0x0024: STUNPriority,
    0x8028: STUNFingerprint,
    0x802a: STUNIceControlling,
    0xc057: STUNGoogNetworkInfo
}

_stun_tlv_attribute_types = {
    "MAPPED-ADDRESS": 0x0001,
    "USERNAME": 0x0006,
    "MESSAGE-INTEGRITY": 0x0008,
    "ERROR-CODE": 0x0009,
    "UNKNOWN-ATTRIBUTES": 0x000A,
    "REALM": 0x0014,
    "NONCE": 0x0015,
    "XOR-MAPPED-ADDRESS": 0x0020,
    "PRIORITY": 0x0024,
    "USE-CANDIDATE": 0x0025,
    "SOFTWARE": 0x8022,
    "ALTERNATE-SERVER": 0x8023,
    "FINGERPRINT": 0x8028,
    "ICE-CONTROLLED": 0x8029,
    "ICE-CONTROLLING": 0x802a,
    "GOOG-NETWORK-INFO": 0xc057
}


class STUN(Packet):
    description = ""

    fields_desc = [
        BitField('RESERVED', 0b00, size=2),   # <- always zeroes
        BitEnumField('stun_message_type', None, 14, _stun_message_type),
        LenField('length', None, fmt='!h'),
        XIntField('magic_cookie', MAGIC_COOKIE),
        XBitField('transaction_id', None, 96),
        PacketListField("attributes", [], STUNGenericTlv)
    ]

    def post_build(self, pkt, pay):
        pkt += pay
        if self.length is None:
            pkt = pkt[:2] + struct.pack("!h", len(pkt) - 20) + pkt[4:]
        for attr in self.attributes:
            if isinstance(attr, STUNMessageIntegrity):
                pass    # TODO Fill hmac-sha1 in MESSAGE-INTEGRITY attribute
        return pkt


bind_bottom_up(UDP, STUN, sport=3478)
bind_bottom_up(UDP, STUN, dport=3478)
bind_top_down(UDP, STUN, sport=3478, dport=3478)

bind_bottom_up(TCP, STUN, sport=3478)
bind_bottom_up(TCP, STUN, dport=3478)
bind_top_down(TCP, STUN, sport=3478, dport=3478)
