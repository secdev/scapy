# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

"""
ISAKMP (Internet Security Association and Key Management Protocol).
"""

# Mostly based on https://tools.ietf.org/html/rfc2408

from __future__ import absolute_import
import struct
from scapy.config import conf
from scapy.packet import Packet, bind_bottom_up, bind_top_down, bind_layers
from scapy.compat import chb
from scapy.fields import ByteEnumField, ByteField, FieldLenField, FlagsField, \
    IntEnumField, IntField, PacketLenField, ShortEnumField, ShortField, \
    StrFixedLenField, StrLenField, XByteField
from scapy.layers.inet import IP, UDP
from scapy.sendrecv import sr
from scapy.volatile import RandString
from scapy.error import warning
from functools import reduce

# TODO: some ISAKMP payloads are not implemented,
# and inherit a default ISAKMP_payload


# see http://www.iana.org/assignments/ipsec-registry for details
ISAKMPAttributeTypes = {"Encryption": (1, {"DES-CBC": 1,
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

# the name 'ISAKMPTransformTypes' is actually a misnomer (since the table
# holds info for all ISAKMP Attribute types, not just transforms, but we'll
# keep it for backwards compatibility... for now at least
ISAKMPTransformTypes = ISAKMPAttributeTypes

ISAKMPTransformNum = {}
for n in ISAKMPTransformTypes:
    val = ISAKMPTransformTypes[n]
    tmp = {}
    for e in val[1]:
        tmp[val[1][e]] = e
    ISAKMPTransformNum[val[0]] = (n, tmp, val[2])
del(n)
del(e)
del(tmp)
del(val)


class ISAKMPTransformSetField(StrLenField):
    islist = 1

    @staticmethod
    def type2num(type_val_tuple):
        typ, val = type_val_tuple
        type_val, enc_dict, tlv = ISAKMPTransformTypes.get(typ, (typ, {}, 0))
        val = enc_dict.get(val, val)
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
    def num2type(typ, enc):
        val = ISAKMPTransformNum.get(typ, (typ, {}))
        enc = val[1].get(enc, enc)
        return (val[0], enc)

    def i2m(self, pkt, i):
        if i is None:
            return b""
        i = [ISAKMPTransformSetField.type2num(e) for e in i]
        return b"".join(i)

    def m2i(self, pkt, m):
        # I try to ensure that we don't read off the end of our packet based
        # on bad length fields we're provided in the packet. There are still
        # conditions where struct.unpack() may not get enough packet data, but
        # worst case that should result in broken attributes (which would
        # be expected). (wam)
        lst = []
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
            lst.append(ISAKMPTransformSetField.num2type(trans_type, value))
        if len(m) > 0:
            warning("Extra bytes after ISAKMP transform dissection [%r]" % m)
        return lst


ISAKMP_payload_type = ["None", "SA", "Proposal", "Transform", "KE", "ID",
                       "CERT", "CR", "Hash", "SIG", "Nonce", "Notification",
                       "Delete", "VendorID"]

ISAKMP_exchange_type = ["None", "base", "identity prot.",
                        "auth only", "aggressive", "info"]


class ISAKMP_class(Packet):
    def guess_payload_class(self, payload):
        np = self.next_payload
        if np == 0:
            return conf.raw_layer
        elif np < len(ISAKMP_payload_type):
            pt = ISAKMP_payload_type[np]
            return globals().get("ISAKMP_payload_%s" % pt, ISAKMP_payload)
        else:
            return ISAKMP_payload


class ISAKMP(ISAKMP_class):  # rfc2408
    name = "ISAKMP"
    fields_desc = [
        StrFixedLenField("init_cookie", "", 8),
        StrFixedLenField("resp_cookie", "", 8),
        ByteEnumField("next_payload", 0, ISAKMP_payload_type),
        XByteField("version", 0x10),
        ByteEnumField("exch_type", 0, ISAKMP_exchange_type),
        FlagsField("flags", 0, 8, ["encryption", "commit", "auth_only", "res3", "res4", "res5", "res6", "res7"]),  # XXX use a Flag field  # noqa: E501
        IntField("id", 0),
        IntField("length", None)
    ]

    def guess_payload_class(self, payload):
        if self.flags & 1:
            return conf.raw_layer
        return ISAKMP_class.guess_payload_class(self, payload)

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


class ISAKMP_payload_Transform(ISAKMP_class):
    name = "IKE Transform"
    fields_desc = [
        ByteEnumField("next_payload", None, ISAKMP_payload_type),
        ByteField("res", 0),
        #        ShortField("len",None),
        ShortField("length", None),
        ByteField("num", None),
        ByteEnumField("id", 1, {1: "KEY_IKE"}),
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

    def post_build(self, p, pay):
        if self.length is None:
            tmp_len = len(p)
            tmp_pay = p[:2] + chb((tmp_len >> 8) & 0xff)
            p = tmp_pay + chb(tmp_len & 0xff) + p[4:]
        p += pay
        return p


# https://tools.ietf.org/html/rfc2408#section-3.5
class ISAKMP_payload_Proposal(ISAKMP_class):
    name = "IKE proposal"
#    ISAKMP_payload_type = 0
    fields_desc = [
        ByteEnumField("next_payload", None, ISAKMP_payload_type),
        ByteField("res", 0),
        FieldLenField("length", None, "trans", "H", adjust=lambda pkt, x:x + 8),  # noqa: E501
        ByteField("proposal", 1),
        ByteEnumField("proto", 1, {1: "ISAKMP"}),
        FieldLenField("SPIsize", None, "SPI", "B"),
        ByteField("trans_nb", None),
        StrLenField("SPI", "", length_from=lambda x: x.SPIsize),
        PacketLenField("trans", conf.raw_layer(), ISAKMP_payload_Transform, length_from=lambda x: x.length - 8),  # noqa: E501
    ]


class ISAKMP_payload(ISAKMP_class):
    name = "ISAKMP payload"
    fields_desc = [
        ByteEnumField("next_payload", None, ISAKMP_payload_type),
        ByteField("res", 0),
        FieldLenField("length", None, "load", "H", adjust=lambda pkt, x:x + 4),
        StrLenField("load", "", length_from=lambda x:x.length - 4),
    ]


class ISAKMP_payload_VendorID(ISAKMP_payload):
    name = "ISAKMP Vendor ID"


class ISAKMP_payload_SA(ISAKMP_class):
    name = "ISAKMP SA"
    fields_desc = [
        ByteEnumField("next_payload", None, ISAKMP_payload_type),
        ByteField("res", 0),
        FieldLenField("length", None, "prop", "H", adjust=lambda pkt, x:x + 12),  # noqa: E501
        IntEnumField("DOI", 1, {1: "IPSEC"}),
        IntEnumField("situation", 1, {1: "identity"}),
        PacketLenField("prop", conf.raw_layer(), ISAKMP_payload_Proposal, length_from=lambda x: x.length - 12),  # noqa: E501
    ]


class ISAKMP_payload_Nonce(ISAKMP_payload):
    name = "ISAKMP Nonce"


class ISAKMP_payload_KE(ISAKMP_payload):
    name = "ISAKMP Key Exchange"


class ISAKMP_payload_ID(ISAKMP_class):
    name = "ISAKMP Identification"
    fields_desc = [
        ByteEnumField("next_payload", None, ISAKMP_payload_type),
        ByteField("res", 0),
        FieldLenField("length", None, "load", "H", adjust=lambda pkt, x:x + 8),
        ByteEnumField("IDtype", 1, {1: "IPv4_addr", 11: "Key"}),
        ByteEnumField("ProtoID", 0, {0: "Unused"}),
        ShortEnumField("Port", 0, {0: "Unused"}),
        #        IPField("IdentData","127.0.0.1"),
        StrLenField("load", "", length_from=lambda x: x.length - 8),
    ]


class ISAKMP_payload_Hash(ISAKMP_payload):
    name = "ISAKMP Hash"


bind_bottom_up(UDP, ISAKMP, dport=500)
bind_bottom_up(UDP, ISAKMP, sport=500)
bind_layers(UDP, ISAKMP, dport=500, sport=500)

# Add building bindings
# (Dissection bindings are located in ISAKMP_class.guess_payload_class)
bind_top_down(ISAKMP_class, ISAKMP_payload, next_payload=0)
bind_top_down(ISAKMP_class, ISAKMP_payload_SA, next_payload=1)
bind_top_down(ISAKMP_class, ISAKMP_payload_Proposal, next_payload=2)
bind_top_down(ISAKMP_class, ISAKMP_payload_Transform, next_payload=3)
bind_top_down(ISAKMP_class, ISAKMP_payload_KE, next_payload=4)
bind_top_down(ISAKMP_class, ISAKMP_payload_ID, next_payload=5)
# bind_top_down(ISAKMP_class, ISAKMP_payload_CERT, next_payload=6)
# bind_top_down(ISAKMP_class, ISAKMP_payload_CR, next_payload=7)
bind_top_down(ISAKMP_class, ISAKMP_payload_Hash, next_payload=8)
# bind_top_down(ISAKMP_class, ISAKMP_payload_SIG, next_payload=9)
bind_top_down(ISAKMP_class, ISAKMP_payload_Nonce, next_payload=10)
# bind_top_down(ISAKMP_class, ISAKMP_payload_Notification, next_payload=11)
# bind_top_down(ISAKMP_class, ISAKMP_payload_Delete, next_payload=12)
bind_top_down(ISAKMP_class, ISAKMP_payload_VendorID, next_payload=13)


def ikescan(ip):
    """Sends/receives a ISAMPK payload SA with payload proposal"""
    pkt = IP(dst=ip)
    pkt /= UDP()
    pkt /= ISAKMP(init_cookie=RandString(8), exch_type=2)
    pkt /= ISAKMP_payload_SA(prop=ISAKMP_payload_Proposal())
    return sr(pkt)
