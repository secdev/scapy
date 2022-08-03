# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Pavel Oborin <oborin.p@gmail.com>

# RFC 5389
# scapy.contrib.description = Session Traversal Utilities for NAT (STUN)
# scapy.contrib.status = loads

"""
    STUN (RFC 5389)

    TLV code derived from the DTP implementation. (Thanks to Nicolas Bareil, Arnaud Ebalard, Jochen Bartl)
"""

import struct
import itertools

from scapy.layers.inet import UDP, TCP
from scapy.config import conf
from scapy.packet import Packet, bind_layers
from scapy.fields import BitField, BitEnumField, LenField, IntField, PadField, StrLenField, PacketListField, XShortField, FieldLenField, ShortField, LongField, NBytesField, ByteEnumField, ByteField, XNBytesField, XLongField, XIntField, XBitField

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
    f"{method} {class_}": (method_code & 0b000000001111)      |    # noqa: E221
                          (class_code  & 0b01)           << 4 |    # noqa: E221
                          (method_code & 0b000001110000) << 5 |    # noqa: E221
                          (class_code  & 0b10)           << 7 |    # noqa: E221
                          (method_code & 0b111110000000) << 9
    for (method, method_code), (class_, class_code) in itertools.product(_stun_method.items(), _stun_class.items())
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
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and len(_pkt) >= 2:
            t = struct.unpack("!H", _pkt[:2])[0]
            cls = _stun_tlv_class.get(t, "STUNGenericTlv")
        return cls

    def guess_payload_class(self, p):
        return conf.padding_layer


class STUNUsername(STUNGenericTlv):
    name = "STUN Username"

    fields_desc = [
        XShortField("type", 0x0006),
        FieldLenField("length", None, length_of="username"),
        PadField(StrLenField("username", '', length_from=lambda pkt: pkt.length), align=4)
    ]


class STUNMessageIntegrity(STUNGenericTlv):
    name = "STUN Message Integrity"

    fields_desc = [
        XShortField("type", 0x0008),
        ShortField("length", 20),
        XNBytesField("hmac_sha1", None, 20)
    ]


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


class STUNXorMappedAddress(STUNGenericTlv):
    name = "STUN XOR Mapped Address"

    fields_desc = [
        XShortField("type", 0x0020),
        ShortField("length", 8),
        ByteField("RESERVED", 0),
        ByteEnumField("address_family", 1, _xor_mapped_address_family),
        ShortField("xport", 0),
        IntField("xip", 0)
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
        XIntField('magic_cookie', 0x2112A442),
        XBitField('transaction_id', None, 96),
        PacketListField("tlvlist", [], STUNGenericTlv)
    ]

    def post_build(self, pkt, pay):
        pkt += pay
        if self.length is None:
            pkt = pkt[:2] + struct.pack("!h", (len(pkt) - 20) // 4) + pkt[4:]
        return pkt


bind_layers(UDP, STUN, dport=3478)
bind_layers(TCP, STUN, dport=3478)
