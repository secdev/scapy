# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>

"""
ISAKMP (Internet Security Association and Key Management Protocol).
"""

# Mostly based on https://tools.ietf.org/html/rfc2408

import struct
from scapy.config import conf
from scapy.packet import Packet, bind_bottom_up, bind_top_down, bind_layers
from scapy.compat import chb
from scapy.fields import (
    ByteEnumField,
    ByteField,
    FieldLenField,
    FieldListField,
    FlagsField,
    IPField,
    IntEnumField,
    IntField,
    MultipleTypeField,
    PacketLenField,
    ShortEnumField,
    ShortField,
    StrLenEnumField,
    StrLenField,
    XByteField,
    XStrFixedLenField,
    XStrLenField,
)
from scapy.layers.inet import IP, UDP
from scapy.layers.ipsec import NON_ESP
from scapy.sendrecv import sr
from scapy.volatile import RandString
from scapy.error import warning
from functools import reduce

# TODO: some ISAKMP payloads are not implemented,
# and inherit a default ISAKMP_payload


# see https://www.iana.org/assignments/ipsec-registry/ipsec-registry.xhtml#ipsec-registry-2 for details  # noqa: E501
ISAKMPAttributeTypes = {
    "Encryption": (1, {"DES-CBC": 1,
                       "IDEA-CBC": 2,
                       "Blowfish-CBC": 3,
                       "RC5-R16-B64-CBC": 4,
                       "3DES-CBC": 5,
                       "CAST-CBC": 6,
                       "AES-CBC": 7,
                       "CAMELLIA-CBC": 8, }, 0),
    "Hash": (2, {"MD5": 1,
                 "SHA": 2,
                 "Tiger": 3,
                 "SHA2-256": 4,
                 "SHA2-384": 5,
                 "SHA2-512": 6, }, 0),
    "Authentication": (3, {"PSK": 1,
                           "DSS": 2,
                           "RSA Sig": 3,
                           "RSA Encryption": 4,
                           "RSA Encryption Revised": 5,
                           "ElGamal Encryption": 6,
                           "ElGamal Encryption Revised": 7,
                           "ECDSA Sig": 8,
                           "HybridInitRSA": 64221,
                           "HybridRespRSA": 64222,
                           "HybridInitDSS": 64223,
                           "HybridRespDSS": 64224,
                           "XAUTHInitPreShared": 65001,
                           "XAUTHRespPreShared": 65002,
                           "XAUTHInitDSS": 65003,
                           "XAUTHRespDSS": 65004,
                           "XAUTHInitRSA": 65005,
                           "XAUTHRespRSA": 65006,
                           "XAUTHInitRSAEncryption": 65007,
                           "XAUTHRespRSAEncryption": 65008,
                           "XAUTHInitRSARevisedEncryption": 65009,  # noqa: E501
                           "XAUTHRespRSARevisedEncryptio": 65010, }, 0),  # noqa: E501
    "GroupDesc": (4, {"768MODPgr": 1,
                      "1024MODPgr": 2,
                      "EC2Ngr155": 3,
                      "EC2Ngr185": 4,
                      "1536MODPgr": 5,
                      "2048MODPgr": 14,
                      "3072MODPgr": 15,
                      "4096MODPgr": 16,
                      "6144MODPgr": 17,
                      "8192MODPgr": 18, }, 0),
    "GroupType": (5, {"MODP": 1,
                      "ECP": 2,
                      "EC2N": 3}, 0),
    "GroupPrime": (6, {}, 1),
    "GroupGenerator1": (7, {}, 1),
    "GroupGenerator2": (8, {}, 1),
    "GroupCurveA": (9, {}, 1),
    "GroupCurveB": (10, {}, 1),
    "LifeType": (11, {"Seconds": 1,
                      "Kilobytes": 2}, 0),
    "LifeDuration": (12, {}, 1),
    "PRF": (13, {}, 0),
    "KeyLength": (14, {}, 0),
    "FieldSize": (15, {}, 0),
    "GroupOrder": (16, {}, 1),
}

# see https://www.iana.org/assignments/isakmp-registry/isakmp-registry.xhtml#isakmp-registry-13 for details  # noqa: E501
IPSECAttributeTypes = {
    "LifeType": (1, {"Reserved": 0,
                     "seconds": 1,
                     "kilobytes": 2}, 0),
    "LifeDuration": (2, {}, 1),
    "GroupDesc": (3, ISAKMPAttributeTypes["GroupDesc"][1], 0),
    "EncapsulationMode": (4, {"Reserved": 0,
                              "Tunnel": 1,
                              "Transport": 2,
                              "UDP-Encapsulated-Tunnel": 3,
                              "UDP-Encapsulated-Transport": 4}, 0),
    "AuthenticationAlgorithm": (5, {"HMAC-MD5": 1,
                                    "HMAC-SHA": 2,
                                    "DES-MAC": 3,
                                    "KPDK": 4,
                                    "HMAC-SHA2-256": 5,
                                    "HMAC-SHA2-384": 6,
                                    "HMAC-SHA2-512": 7,
                                    "HMAC-RIPEMD": 8,
                                    "AES-XCBC-MAC": 9,
                                    "SIG-RSA": 10,
                                    "AES-128-GMAC": 11,
                                    "AES-192-GMAC": 12,
                                    "AES-256-GMAC": 13}, 0),
    "KeyLength": (6, {}, 0),
    "KeyRounds": (7, {}, 0),
    "CompressDictionarySize": (8, {}, 0),
    "CompressPrivateAlgorithm": (9, {}, 1),
}

_rev = lambda x: {
    v[0]: (k, {vv: kk for kk, vv in v[1].items()}, v[2])
    for k, v in x.items()
}
ISAKMPTransformNum = _rev(ISAKMPAttributeTypes)
IPSECTransformNum = _rev(IPSECAttributeTypes)

# See IPSEC Security Protocol Identifiers entry in
# https://www.iana.org/assignments/isakmp-registry/isakmp-registry.xhtml#isakmp-registry-3
PROTO_ISAKMP = 1
PROTO_IPSEC_AH = 2
PROTO_IPSEC_ESP = 3
PROTO_IPCOMP = 4
PROTO_GIGABEAM_RADIO = 5


class ISAKMPTransformSetField(StrLenField):
    islist = 1

    @staticmethod
    def type2num(type_val_tuple, proto=0):
        typ, val = type_val_tuple
        if proto == PROTO_ISAKMP:
            type_val, enc_dict, tlv = ISAKMPAttributeTypes.get(typ, (typ, {}, 0))
        elif proto == PROTO_IPSEC_ESP:
            type_val, enc_dict, tlv = IPSECAttributeTypes.get(typ, (typ, {}, 0))
        else:
            type_val, enc_dict, tlv = (typ, {}, 0)
        val = enc_dict.get(val, val)
        if isinstance(val, str):
            raise ValueError("Unknown attribute '%s'" % val)
        s = b""
        if (val & ~0xffff):
            if not tlv:
                warning("%r should not be TLV but is too big => using TLV encoding" % typ)  # noqa: E501
            n = 0
            while val:
                s = chb(val & 0xff) + s
                val >>= 8
                n += 1
            val = n
        else:
            type_val |= 0x8000
        return struct.pack("!HH", type_val, val) + s

    @staticmethod
    def num2type(typ, enc, proto=0):
        if proto == PROTO_ISAKMP:
            val = ISAKMPTransformNum.get(typ, (typ, {}))
        elif proto == PROTO_IPSEC_ESP:
            val = IPSECTransformNum.get(typ, (typ, {}))
        else:
            val = (typ, {})
        enc = val[1].get(enc, enc)
        return (val[0], enc)

    def _get_proto(self, pkt):
        # Ugh
        cur = pkt
        while cur and getattr(cur, "proto", None) is None:
            cur = cur.parent or cur.underlayer
        if cur is None:
            return PROTO_ISAKMP
        return cur.proto

    def i2m(self, pkt, i):
        if i is None:
            return b""
        proto = self._get_proto(pkt)
        i = [ISAKMPTransformSetField.type2num(e, proto=proto) for e in i]
        return b"".join(i)

    def m2i(self, pkt, m):
        # I try to ensure that we don't read off the end of our packet based
        # on bad length fields we're provided in the packet. There are still
        # conditions where struct.unpack() may not get enough packet data, but
        # worst case that should result in broken attributes (which would
        # be expected). (wam)
        lst = []
        proto = self._get_proto(pkt)
        while len(m) >= 4:
            trans_type, = struct.unpack("!H", m[:2])
            is_tlv = not (trans_type & 0x8000)
            if is_tlv:
                # We should probably check to make sure the attribute type we
                # are looking at is allowed to have a TLV format and issue a
                # warning if we're given an TLV on a basic attribute.
                value_len, = struct.unpack("!H", m[2:4])
                if value_len + 4 > len(m):
                    warning("Bad length for ISAKMP transform type=%#6x" % trans_type)  # noqa: E501
                value = m[4:4 + value_len]
                value = reduce(lambda x, y: (x << 8) | y, struct.unpack("!%s" % ("B" * len(value),), value), 0)  # noqa: E501
            else:
                trans_type &= 0x7fff
                value_len = 0
                value, = struct.unpack("!H", m[2:4])
            m = m[4 + value_len:]
            lst.append(ISAKMPTransformSetField.num2type(trans_type, value, proto=proto))
        if len(m) > 0:
            warning("Extra bytes after ISAKMP transform dissection [%r]" % m)
        return lst


ISAKMP_payload_type = {
    0: "None",
    1: "SA",
    2: "Proposal",
    3: "Transform",
    4: "KE",
    5: "ID",
    6: "CERT",
    7: "CR",
    8: "Hash",
    9: "SIG",
    10: "Nonce",
    11: "Notification",
    12: "Delete",
    13: "VendorID",
}

ISAKMP_exchange_type = {
    0: "None",
    1: "base",
    2: "identity protection",
    3: "authentication only",
    4: "aggressive",
    5: "informational",
    32: "quick mode",
}

# https://www.iana.org/assignments/isakmp-registry/isakmp-registry.xhtml#isakmp-registry-3
# IPSEC Security Protocol Identifiers
ISAKMP_protos = {
    1: "ISAKMP",
    2: "IPSEC_AH",
    3: "IPSEC_ESP",
    4: "IPCOMP",
    5: "GIGABEAM_RADIO"
}

ISAKMP_doi = {
    0: "ISAKMP",
    1: "IPSEC",
}


class _ISAKMP_class(Packet):
    def default_payload_class(self, payload):
        if self.next_payload == 0:
            return conf.raw_layer
        return ISAKMP_payload

# -- ISAKMP


class ISAKMP(_ISAKMP_class):  # rfc2408
    name = "ISAKMP"
    fields_desc = [
        XStrFixedLenField("init_cookie", "", 8),
        XStrFixedLenField("resp_cookie", "", 8),
        ByteEnumField("next_payload", 0, ISAKMP_payload_type),
        XByteField("version", 0x10),
        ByteEnumField("exch_type", 0, ISAKMP_exchange_type),
        FlagsField("flags", 0, 8, ["encryption", "commit", "auth_only"]),
        IntField("id", 0),
        IntField("length", None)
    ]

    def guess_payload_class(self, payload):
        if self.flags & 1:
            return conf.raw_layer
        return _ISAKMP_class.guess_payload_class(self, payload)

    def answers(self, other):
        if isinstance(other, ISAKMP):
            if other.init_cookie == self.init_cookie:
                return 1
        return 0

    def post_build(self, p, pay):
        p += pay
        if self.length is None:
            p = p[:24] + struct.pack("!I", len(p)) + p[28:]
        return p


# -- ISAKMP payloads

class ISAKMP_payload(_ISAKMP_class):
    name = "ISAKMP payload"
    show_indent = 0
    fields_desc = [
        ByteEnumField("next_payload", None, ISAKMP_payload_type),
        ByteField("res", 0),
        ShortField("length", None),
        XStrLenField("load", "", length_from=lambda x:x.length - 4),
    ]

    def post_build(self, pkt, pay):
        if self.length is None:
            pkt = pkt[:2] + struct.pack("!H", len(pkt)) + pkt[4:]
        return pkt + pay


class ISAKMP_payload_Transform(ISAKMP_payload):
    name = "IKE Transform"
    deprecated_fields = {
        "num": ("transform_count", ("2.5.0")),
        "id": ("transform_id", ("2.5.0")),
    }
    fields_desc = ISAKMP_payload.fields_desc[:3] + [
        ByteField("transform_count", None),
        ByteEnumField("transform_id", 1, {1: "KEY_IKE"}),
        ShortField("res2", 0),
        ISAKMPTransformSetField("transforms", None, length_from=lambda x: x.length - 8)  # noqa: E501
        #        XIntField("enc",0x80010005L),
        #        XIntField("hash",0x80020002L),
        #        XIntField("auth",0x80030001L),
        #        XIntField("group",0x80040002L),
        #        XIntField("life_type",0x800b0001L),
        #        XIntField("durationh",0x000c0004L),
        #        XIntField("durationl",0x00007080L),
    ]


# https://tools.ietf.org/html/rfc2408#section-3.5
class ISAKMP_payload_Proposal(ISAKMP_payload):
    name = "IKE proposal"
    fields_desc = ISAKMP_payload.fields_desc[:3] + [
        ByteField("proposal", 1),
        ByteEnumField("proto", 1, ISAKMP_protos),
        FieldLenField("SPIsize", None, "SPI", "B"),
        ByteField("trans_nb", None),
        StrLenField("SPI", "", length_from=lambda x: x.SPIsize),
        PacketLenField("trans", conf.raw_layer(), ISAKMP_payload_Transform, length_from=lambda x: x.length - 8),  # noqa: E501
    ]


# VendorID: https://www.rfc-editor.org/rfc/rfc2408#section-3.16

# packet-isakmp.c from wireshark
ISAKMP_VENDOR_IDS = {
    b"\x09\x00\x26\x89\xdf\xd6\xb7\x12": "XAUTH",
    b"\xaf\xca\xd7\x13h\xa1\xf1\xc9k\x86\x96\xfcwW\x01\x00": "RFC 3706 DPD",
    b"@H\xb7\xd5n\xbc\xe8\x85%\xe7\xde\x7f\x00\xd6\xc2\xd3\x80": "Cisco Fragmentation",
    b"J\x13\x1c\x81\x07\x03XE\\W(\xf2\x0e\x95E/": "RFC 3947 Negotiation of NAT-Transversal",  # noqa: E501
    b"\x90\xcb\x80\x91>\xbbin\x08c\x81\xb5\xecB{\x1f": "draft-ietf-ipsec-nat-t-ike-02",
}


class ISAKMP_payload_VendorID(ISAKMP_payload):
    name = "ISAKMP Vendor ID"
    fields_desc = ISAKMP_payload.fields_desc[:3] + [
        StrLenEnumField("VendorID", b"",
                        ISAKMP_VENDOR_IDS,
                        length_from=lambda x: x.length - 4)
    ]


class ISAKMP_payload_SA(ISAKMP_payload):
    name = "ISAKMP SA"
    fields_desc = ISAKMP_payload.fields_desc[:3] + [
        IntEnumField("doi", 1, ISAKMP_doi),
        IntEnumField("situation", 1, {1: "identity"}),
        PacketLenField("prop", conf.raw_layer(), ISAKMP_payload_Proposal, length_from=lambda x: x.length - 12),  # noqa: E501
    ]


class ISAKMP_payload_Nonce(ISAKMP_payload):
    name = "ISAKMP Nonce"


class ISAKMP_payload_KE(ISAKMP_payload):
    name = "ISAKMP Key Exchange"


class ISAKMP_payload_ID(ISAKMP_payload):
    name = "ISAKMP Identification"
    fields_desc = ISAKMP_payload.fields_desc[:3] + [
        ByteEnumField("IDtype", 1, {
            # Beware, apparently in-the-wild the values used
            # appear to be the ones from IKEv2 (RFC4306 sect 3.5)
            # and not ISAKMP (RFC2408 sect A.4)
            1: "IPv4_addr",
            11: "Key"
        }),
        ByteEnumField("ProtoID", 0, {0: "Unused"}),
        ShortEnumField("Port", 0, {0: "Unused"}),
        MultipleTypeField(
            [
                (IPField("IdentData", "127.0.0.1"),
                 lambda pkt: pkt.IDtype == 1),
            ],
            StrLenField("IdentData", "", length_from=lambda x: x.length - 8),
        )
    ]


class ISAKMP_payload_Hash(ISAKMP_payload):
    name = "ISAKMP Hash"


NotifyMessageType = {
    1: "INVALID-PAYLOAD-TYPE",
    2: "DOI-NOT-SUPPORTED",
    3: "SITUATION-NOT-SUPPORTED",
    4: "INVALID-COOKIE",
    5: "INVALID-MAJOR-VERSION",
    6: "INVALID-MINOR-VERSION",
    7: "INVALID-EXCHANGE-TYPE",
    8: "INVALID-FLAGS",
    9: "INVALID-MESSAGE-ID",
    10: "INVALID-PROTOCOL-ID",
    11: "INVALID-SPI",
    12: "INVALID-TRANSFORM-ID",
    13: "ATTRIBUTES-NOT-SUPPORTED",
    14: "NO-PROPOSAL-CHOSEN",
    15: "BAD-PROPOSAL-SYNTAX",
    16: "PAYLOAD-MALFORMED",
    17: "INVALID-KEY-INFORMATION",
    18: "INVALID-ID-INFORMATION",
    19: "INVALID-CERT-ENCODING",
    20: "INVALID-CERTIFICATE",
    21: "CERT-TYPE-UNSUPPORTED",
    22: "INVALID-CERT-AUTHORITY",
    23: "INVALID-HASH-INFORMATION",
    24: "AUTHENTICATION-FAILED",
    25: "INVALID-SIGNATURE",
    26: "ADDRESS-NOTIFICATION",
    27: "NOTIFY-SA-LIFETIME",
    28: "CERTIFICATE-UNAVAILABLE",
    29: "UNSUPPORTED-EXCHANGE-TYPE",
    # RFC 3706
    36136: "R-U-THERE",
    36137: "R-U-THERE-ACK",
}


class ISAKMP_payload_Notify(ISAKMP_payload):
    name = "ISAKMP Notify (Notification)"
    fields_desc = ISAKMP_payload.fields_desc[:3] + [
        IntEnumField("doi", 0, ISAKMP_doi),
        ByteEnumField("proto", 1, ISAKMP_protos),
        FieldLenField("SPIsize", None, "SPI", "B"),
        ShortEnumField("notify_msg_type", None, NotifyMessageType),
        StrLenField("SPI", "", length_from=lambda x: x.SPIsize),
        StrLenField("notify_data", "",
                    length_from=lambda x: x.length - x.SPIsize - 12)
    ]


class ISAKMP_payload_Delete(ISAKMP_payload):
    name = "ISAKMP Delete"
    fields_desc = ISAKMP_payload.fields_desc[:3] + [
        IntEnumField("doi", 0, ISAKMP_doi),
        ByteEnumField("proto", 1, ISAKMP_protos),
        FieldLenField("SPIsize", None, length_of="SPIs", fmt="B",
                      adjust=lambda pkt, x: x and x // len(pkt.SPIs)),
        FieldLenField("SPIcount", None, count_of="SPIs", fmt="H"),
        FieldListField("SPIs", [],
                       StrLenField("", "", length_from=lambda pkt: pkt.SPIsize),
                       count_from=lambda pkt: pkt.SPIcount),
    ]


bind_bottom_up(UDP, ISAKMP, dport=500)
bind_bottom_up(UDP, ISAKMP, sport=500)
bind_top_down(UDP, ISAKMP, dport=500, sport=500)

bind_bottom_up(NON_ESP, ISAKMP)

# Add bindings
bind_top_down(_ISAKMP_class, ISAKMP_payload, next_payload=0)
bind_layers(_ISAKMP_class, ISAKMP_payload_SA, next_payload=1)
bind_layers(_ISAKMP_class, ISAKMP_payload_Proposal, next_payload=2)
bind_layers(_ISAKMP_class, ISAKMP_payload_Transform, next_payload=3)
bind_layers(_ISAKMP_class, ISAKMP_payload_KE, next_payload=4)
bind_layers(_ISAKMP_class, ISAKMP_payload_ID, next_payload=5)
# bind_layers(_ISAKMP_class, ISAKMP_payload_CERT, next_payload=6)
# bind_layers(_ISAKMP_class, ISAKMP_payload_CR, next_payload=7)
bind_layers(_ISAKMP_class, ISAKMP_payload_Hash, next_payload=8)
# bind_layers(_ISAKMP_class, ISAKMP_payload_SIG, next_payload=9)
bind_layers(_ISAKMP_class, ISAKMP_payload_Nonce, next_payload=10)
bind_layers(_ISAKMP_class, ISAKMP_payload_Notify, next_payload=11)
bind_layers(_ISAKMP_class, ISAKMP_payload_Delete, next_payload=12)
bind_layers(_ISAKMP_class, ISAKMP_payload_VendorID, next_payload=13)


def ikescan(ip):
    """Sends/receives a ISAMPK payload SA with payload proposal"""
    pkt = IP(dst=ip)
    pkt /= UDP()
    pkt /= ISAKMP(init_cookie=RandString(8), exch_type=2)
    pkt /= ISAKMP_payload_SA(prop=ISAKMP_payload_Proposal())
    return sr(pkt)
