# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (c) 2008 Dirk Loss <dirk-loss de>
# Copyright (c) 2010 Jochen Bartl <jochen.bartl gmail com>

# scapy.contrib.description = Open Shortest Path First (OSPF)
# scapy.contrib.status = loads

"""
OSPF extension for Scapy <http://www.secdev.org/scapy>

This module provides Scapy layers for the Open Shortest Path First
routing protocol as defined in RFC 2328 and RFC 5340.
"""


import struct

from scapy.packet import bind_layers, Packet
from scapy.fields import BitField, ByteEnumField, ByteField, \
    ConditionalField, DestIP6Field, FieldLenField, \
    FieldListField, FlagsField, IP6Field, IP6PrefixField, IPField, \
    IntEnumField, IntField, LenField, PacketListField, ShortEnumField, \
    ShortField, StrLenField, X3BytesField, XIntField, XLongField, XShortField
from scapy.layers.inet import IP, DestIPField
from scapy.layers.inet6 import IPv6, in6_chksum
from scapy.utils import fletcher16_checkbytes, checksum, inet_aton
from scapy.compat import orb
from scapy.config import conf

EXT_VERSION = "v0.9.2"


class OSPFOptionsField(FlagsField):

    def __init__(self, name="options", default=0, size=8,
                 names=None):
        if names is None:
            names = ["MT", "E", "MC", "NP", "L", "DC", "O", "DN"]
        FlagsField.__init__(self, name, default, size, names)


_OSPF_types = {1: "Hello",
               2: "DBDesc",
               3: "LSReq",
               4: "LSUpd",
               5: "LSAck"}


class _NoLLSLenField(LenField):
    """
    LenField that will ignore the size of OSPF_LLS_Hdr if it exists
    in the payload
    """

    def i2m(self, pkt, x):
        if x is None:
            x = self.adjust(len(pkt.payload))
        if OSPF_LLS_Hdr in pkt:
            x -= len(pkt[OSPF_LLS_Hdr])
        return x


class OSPF_Hdr(Packet):
    name = "OSPF Header"
    fields_desc = [
        ByteField("version", 2),
        ByteEnumField("type", 1, _OSPF_types),
        _NoLLSLenField("len", None, adjust=lambda x: x + 24),
        IPField("src", "1.1.1.1"),
        IPField("area", "0.0.0.0"),  # default: backbone
        XShortField("chksum", None),
        ShortEnumField("authtype", 0, {0: "Null", 1: "Simple", 2: "Crypto"}),
        # Null or Simple Authentication
        ConditionalField(XLongField("authdata", 0), lambda pkt: pkt.authtype != 2),  # noqa: E501
        # Crypto Authentication
        ConditionalField(XShortField("reserved", 0), lambda pkt: pkt.authtype == 2),  # noqa: E501
        ConditionalField(ByteField("keyid", 1), lambda pkt: pkt.authtype == 2),
        ConditionalField(ByteField("authdatalen", 0), lambda pkt: pkt.authtype == 2),  # noqa: E501
        ConditionalField(XIntField("seq", 0), lambda pkt: pkt.authtype == 2),
        # TODO: Support authdata (which is appended to the packets as if it were padding)  # noqa: E501
    ]

    def post_build(self, p, pay):
        # See <http://tools.ietf.org/html/rfc5613>
        p += pay
        if self.chksum is None:
            if self.authtype == 2:
                ck = 0   # Crypto, see RFC 2328, D.4.3
            else:
                # Checksum is calculated without authentication data
                # Algorithm is the same as in IP()
                ck = checksum(p[:16] + p[24:])
                p = p[:12] + struct.pack("!H", ck) + p[14:]
            # TODO: Handle Crypto: Add message digest  (RFC 2328, D.4.3)
        return p

    def hashret(self):
        return struct.pack("H", self.area) + self.payload.hashret()

    def answers(self, other):
        if (isinstance(other, OSPF_Hdr) and
            self.area == other.area and
                self.type == 5):  # Only acknowledgements answer other packets
            return self.payload.answers(other.payload)
        return 0


class OSPF_Hello(Packet):
    name = "OSPF Hello"
    fields_desc = [IPField("mask", "255.255.255.0"),
                   ShortField("hellointerval", 10),
                   OSPFOptionsField(),
                   ByteField("prio", 1),
                   IntField("deadinterval", 40),
                   IPField("router", "0.0.0.0"),
                   IPField("backup", "0.0.0.0"),
                   FieldListField("neighbors", [], IPField("", "0.0.0.0"), length_from=lambda pkt: (pkt.underlayer.len - 44) if pkt.underlayer else None)]  # noqa: E501

    def guess_payload_class(self, payload):
        # check presence of LLS data block flag
        if self.options & 0x10 == 0x10:
            return OSPF_LLS_Hdr
        else:
            return Packet.guess_payload_class(self, payload)


class LLS_Generic_TLV(Packet):
    name = "LLS Generic"
    fields_desc = [ShortField("type", 0),
                   FieldLenField("len", None, length_of="val"),
                   StrLenField("val", "", length_from=lambda x: x.len)]

    def guess_payload_class(self, p):
        return conf.padding_layer


class LLS_Extended_Options(LLS_Generic_TLV):
    name = "LLS Extended Options and Flags"
    fields_desc = [ShortField("type", 1),
                   FieldLenField("len", None, fmt="!H", length_of="options"),
                   StrLenField("options", "", length_from=lambda x: x.len)]
    # TODO: FlagsField("options", 0, names=["LR", "RS"], size) with dynamic size  # noqa: E501


class LLS_Crypto_Auth(LLS_Generic_TLV):
    name = "LLS Cryptographic Authentication"
    fields_desc = [ShortField("type", 2),
                   FieldLenField("len", 20, fmt="B", length_of=lambda x: x.authdata + 4),  # noqa: E501
                   XIntField("sequence", 0),
                   StrLenField("authdata", b"\x00" * 16, length_from=lambda x: x.len - 4)]  # noqa: E501


_OSPF_LLSclasses = {1: "LLS_Extended_Options",
                    2: "LLS_Crypto_Auth"}


def _LLSGuessPayloadClass(p, **kargs):
    """ Guess the correct LLS class for a given payload """

    cls = conf.raw_layer
    if len(p) >= 3:
        typ = struct.unpack("!H", p[0:2])[0]
        clsname = _OSPF_LLSclasses.get(typ, "LLS_Generic_TLV")
        cls = globals()[clsname]
    return cls(p, **kargs)


class FieldLenField32Bits(FieldLenField):
    def i2repr(self, pkt, x):
        return repr(x) if not x else str(FieldLenField.i2h(self, pkt, x) << 2) + " bytes"  # noqa: E501


class OSPF_LLS_Hdr(Packet):
    name = "OSPF Link-local signaling"
    fields_desc = [XShortField("chksum", None),
                   FieldLenField32Bits("len", None, length_of="llstlv", adjust=lambda pkt, x: (x + 4) >> 2),  # noqa: E501
                   PacketListField("llstlv", [], _LLSGuessPayloadClass, length_from=lambda x: (x.len << 2) - 4)]  # noqa: E501

    def post_build(self, p, pay):
        p += pay
        if self.chksum is None:
            c = checksum(p)
            p = struct.pack("!H", c) + p[2:]
        return p


_OSPF_LStypes = {1: "router",
                 2: "network",
                 3: "summaryIP",
                 4: "summaryASBR",
                 5: "external",
                 7: "NSSAexternal",
                 9: "linkScopeOpaque",
                 10: "areaScopeOpaque",
                 11: "asScopeOpaque"}

_OSPF_LSclasses = {1: "OSPF_Router_LSA",
                   2: "OSPF_Network_LSA",
                   3: "OSPF_SummaryIP_LSA",
                   4: "OSPF_SummaryASBR_LSA",
                   5: "OSPF_External_LSA",
                   7: "OSPF_NSSA_External_LSA",
                   9: "OSPF_Link_Scope_Opaque_LSA",
                   10: "OSPF_Area_Scope_Opaque_LSA",
                   11: "OSPF_AS_Scope_Opaque_LSA"}


def ospf_lsa_checksum(lsa):
    return fletcher16_checkbytes(b"\x00\x00" + lsa[2:], 16)  # leave out age


class OSPF_LSA_Hdr(Packet):
    name = "OSPF LSA Header"
    fields_desc = [ShortField("age", 1),
                   OSPFOptionsField(),
                   ByteEnumField("type", 1, _OSPF_LStypes),
                   IPField("id", "192.168.0.0"),
                   IPField("adrouter", "1.1.1.1"),
                   XIntField("seq", 0x80000001),
                   XShortField("chksum", 0),
                   ShortField("len", 36)]

    def extract_padding(self, s):
        return "", s


_OSPF_Router_LSA_types = {1: "p2p",
                          2: "transit",
                          3: "stub",
                          4: "virtual"}


class OSPF_Link(Packet):
    name = "OSPF Link"
    fields_desc = [IPField("id", "192.168.0.0"),
                   IPField("data", "255.255.255.0"),
                   ByteEnumField("type", 3, _OSPF_Router_LSA_types),
                   ByteField("toscount", 0),
                   ShortField("metric", 10),
                   # TODO: define correct conditions
                   ConditionalField(ByteField("tos", 0), lambda pkt: False),
                   ConditionalField(ByteField("reserved", 0), lambda pkt: False),  # noqa: E501
                   ConditionalField(ShortField("tosmetric", 0), lambda pkt: False)]  # noqa: E501

    def extract_padding(self, s):
        return "", s


def _LSAGuessPayloadClass(p, **kargs):
    """ Guess the correct LSA class for a given payload """
    # This is heavily based on scapy-cdp.py by Nicolas Bareil and Arnaud Ebalard  # noqa: E501

    cls = conf.raw_layer
    if len(p) >= 4:
        typ = orb(p[3])
        clsname = _OSPF_LSclasses.get(typ, "Raw")
        cls = globals()[clsname]
    return cls(p, **kargs)


class OSPF_BaseLSA(Packet):
    """ An abstract base class for Link State Advertisements """

    def post_build(self, p, pay):
        length = self.len
        if length is None:
            length = len(p)
            p = p[:18] + struct.pack("!H", length) + p[20:]
        if self.chksum is None:
            chksum = ospf_lsa_checksum(p)
            p = p[:16] + chksum + p[18:]
        return p    # p+pay?

    def extract_padding(self, s):
        return "", s


class OSPF_Router_LSA(OSPF_BaseLSA):
    name = "OSPF Router LSA"
    fields_desc = [ShortField("age", 1),
                   OSPFOptionsField(),
                   ByteField("type", 1),
                   IPField("id", "1.1.1.1"),
                   IPField("adrouter", "1.1.1.1"),
                   XIntField("seq", 0x80000001),
                   XShortField("chksum", None),
                   ShortField("len", None),
                   FlagsField("flags", 0, 8, ["B", "E", "V", "W", "Nt"]),
                   ByteField("reserved", 0),
                   FieldLenField("linkcount", None, count_of="linklist"),
                   PacketListField("linklist", [], OSPF_Link,
                                   count_from=lambda pkt: pkt.linkcount,
                                   length_from=lambda pkt: pkt.linkcount * 12)]


class OSPF_Network_LSA(OSPF_BaseLSA):
    name = "OSPF Network LSA"
    fields_desc = [ShortField("age", 1),
                   OSPFOptionsField(),
                   ByteField("type", 2),
                   IPField("id", "192.168.0.0"),
                   IPField("adrouter", "1.1.1.1"),
                   XIntField("seq", 0x80000001),
                   XShortField("chksum", None),
                   ShortField("len", None),
                   IPField("mask", "255.255.255.0"),
                   FieldListField("routerlist", [], IPField("", "1.1.1.1"),
                                  length_from=lambda pkt: pkt.len - 24)]


class OSPF_SummaryIP_LSA(OSPF_BaseLSA):
    name = "OSPF Summary LSA (IP Network)"
    fields_desc = [ShortField("age", 1),
                   OSPFOptionsField(),
                   ByteField("type", 3),
                   IPField("id", "192.168.0.0"),
                   IPField("adrouter", "1.1.1.1"),
                   XIntField("seq", 0x80000001),
                   XShortField("chksum", None),
                   ShortField("len", None),
                   IPField("mask", "255.255.255.0"),
                   ByteField("reserved", 0),
                   X3BytesField("metric", 10),
                   # TODO: Define correct conditions
                   ConditionalField(ByteField("tos", 0), lambda pkt:False),
                   ConditionalField(X3BytesField("tosmetric", 0), lambda pkt:False)]  # noqa: E501


class OSPF_SummaryASBR_LSA(OSPF_SummaryIP_LSA):
    name = "OSPF Summary LSA (AS Boundary Router)"
    type = 4
    id = "2.2.2.2"
    mask = "0.0.0.0"
    metric = 20


class OSPF_External_LSA(OSPF_BaseLSA):
    name = "OSPF External LSA (ASBR)"
    fields_desc = [ShortField("age", 1),
                   OSPFOptionsField(),
                   ByteField("type", 5),
                   IPField("id", "192.168.0.0"),
                   IPField("adrouter", "2.2.2.2"),
                   XIntField("seq", 0x80000001),
                   XShortField("chksum", None),
                   ShortField("len", None),
                   IPField("mask", "255.255.255.0"),
                   FlagsField("ebit", 0, 1, ["E"]),
                   BitField("reserved", 0, 7),
                   X3BytesField("metric", 20),
                   IPField("fwdaddr", "0.0.0.0"),
                   XIntField("tag", 0),
                   # TODO: Define correct conditions
                   ConditionalField(ByteField("tos", 0), lambda pkt:False),
                   ConditionalField(X3BytesField("tosmetric", 0), lambda pkt:False)]  # noqa: E501


class OSPF_NSSA_External_LSA(OSPF_External_LSA):
    name = "OSPF NSSA External LSA"
    type = 7


class OSPF_Link_Scope_Opaque_LSA(OSPF_BaseLSA):
    name = "OSPF Link Scope External LSA"
    type = 9
    fields_desc = [ShortField("age", 1),
                   OSPFOptionsField(),
                   ByteField("type", 9),
                   IPField("id", "192.0.2.1"),
                   IPField("adrouter", "198.51.100.100"),
                   XIntField("seq", 0x80000001),
                   XShortField("chksum", None),
                   ShortField("len", None),
                   StrLenField("data", "data",
                               length_from=lambda pkt: pkt.len - 20)
                   ]

    def opaqueid(self):
        return struct.unpack('>I', inet_aton(self.id))[0] & 0xFFFFFF

    def opaquetype(self):
        return (struct.unpack('>I', inet_aton(self.id))[0] >> 24) & 0xFF


class OSPF_Area_Scope_Opaque_LSA(OSPF_Link_Scope_Opaque_LSA):
    name = "OSPF Area Scope External LSA"
    type = 10


class OSPF_AS_Scope_Opaque_LSA(OSPF_Link_Scope_Opaque_LSA):
    name = "OSPF AS Scope External LSA"
    type = 11


class OSPF_DBDesc(Packet):
    name = "OSPF Database Description"
    fields_desc = [ShortField("mtu", 1500),
                   OSPFOptionsField(),
                   FlagsField("dbdescr", 0, 8, ["MS", "M", "I", "R", "4", "3", "2", "1"]),  # noqa: E501
                   IntField("ddseq", 1),
                   PacketListField("lsaheaders", None, OSPF_LSA_Hdr,
                                   count_from=lambda pkt: None,
                                   length_from=lambda pkt: pkt.underlayer.len - 24 - 8)]  # noqa: E501

    def guess_payload_class(self, payload):
        # check presence of LLS data block flag
        if self.options & 0x10 == 0x10:
            return OSPF_LLS_Hdr
        else:
            return Packet.guess_payload_class(self, payload)


class OSPF_LSReq_Item(Packet):
    name = "OSPF Link State Request (item)"
    fields_desc = [IntEnumField("type", 1, _OSPF_LStypes),
                   IPField("id", "1.1.1.1"),
                   IPField("adrouter", "1.1.1.1")]

    def extract_padding(self, s):
        return "", s


class OSPF_LSReq(Packet):
    name = "OSPF Link State Request (container)"
    fields_desc = [PacketListField("requests", None, OSPF_LSReq_Item,
                                   count_from=lambda pkt:None,
                                   length_from=lambda pkt:pkt.underlayer.len - 24)]  # noqa: E501


class OSPF_LSUpd(Packet):
    name = "OSPF Link State Update"
    fields_desc = [FieldLenField("lsacount", None, fmt="!I", count_of="lsalist"),  # noqa: E501
                   PacketListField("lsalist", None, _LSAGuessPayloadClass,
                                   count_from=lambda pkt: pkt.lsacount,
                                   length_from=lambda pkt: pkt.underlayer.len - 24)]  # noqa: E501


class OSPF_LSAck(Packet):
    name = "OSPF Link State Acknowledgement"
    fields_desc = [PacketListField("lsaheaders", None, OSPF_LSA_Hdr,
                                   count_from=lambda pkt: None,
                                   length_from=lambda pkt: pkt.underlayer.len - 24)]  # noqa: E501

    def answers(self, other):
        if isinstance(other, OSPF_LSUpd):
            for reqLSA in other.lsalist:
                for ackLSA in self.lsaheaders:
                    if (reqLSA.type == ackLSA.type and
                            reqLSA.seq == ackLSA.seq):
                        return 1
        return 0


###############################################################################
# OSPFv3
###############################################################################
class OSPFv3_Hdr(Packet):
    name = "OSPFv3 Header"
    fields_desc = [ByteField("version", 3),
                   ByteEnumField("type", 1, _OSPF_types),
                   ShortField("len", None),
                   IPField("src", "1.1.1.1"),
                   IPField("area", "0.0.0.0"),
                   XShortField("chksum", None),
                   ByteField("instance", 0),
                   ByteField("reserved", 0)]

    def post_build(self, p, pay):
        p += pay
        tmp_len = self.len

        if tmp_len is None:
            tmp_len = len(p)
            p = p[:2] + struct.pack("!H", tmp_len) + p[4:]

        if self.chksum is None:
            chksum = in6_chksum(89, self.underlayer, p)
            p = p[:12] + struct.pack("!H", chksum) + p[14:]

        return p


class OSPFv3OptionsField(FlagsField):

    def __init__(self, name="options", default=0, size=24,
                 names=None):
        if names is None:
            names = ["V6", "E", "MC", "N", "R", "DC", "AF", "L", "I", "F"]
        FlagsField.__init__(self, name, default, size, names)


class OSPFv3_Hello(Packet):
    name = "OSPFv3 Hello"
    fields_desc = [IntField("intid", 0),
                   ByteField("prio", 1),
                   OSPFv3OptionsField(),
                   ShortField("hellointerval", 10),
                   ShortField("deadinterval", 40),
                   IPField("router", "0.0.0.0"),
                   IPField("backup", "0.0.0.0"),
                   FieldListField("neighbors", [], IPField("", "0.0.0.0"),
                                  length_from=lambda pkt: (pkt.underlayer.len - 36))]  # noqa: E501


_OSPFv3_LStypes = {0x2001: "router",
                   0x2002: "network",
                   0x2003: "interAreaPrefix",
                   0x2004: "interAreaRouter",
                   0x4005: "asExternal",
                   0x2007: "type7",
                   0x0008: "link",
                   0x2009: "intraAreaPrefix"}

_OSPFv3_LSclasses = {0x2001: "OSPFv3_Router_LSA",
                     0x2002: "OSPFv3_Network_LSA",
                     0x2003: "OSPFv3_Inter_Area_Prefix_LSA",
                     0x2004: "OSPFv3_Inter_Area_Router_LSA",
                     0x4005: "OSPFv3_AS_External_LSA",
                     0x2007: "OSPFv3_Type_7_LSA",
                     0x0008: "OSPFv3_Link_LSA",
                     0x2009: "OSPFv3_Intra_Area_Prefix_LSA"}


class OSPFv3_LSA_Hdr(Packet):
    name = "OSPFv3 LSA Header"
    fields_desc = [ShortField("age", 1),
                   ShortEnumField("type", 0x2001, _OSPFv3_LStypes),
                   IPField("id", "0.0.0.0"),
                   IPField("adrouter", "1.1.1.1"),
                   XIntField("seq", 0x80000001),
                   XShortField("chksum", 0),
                   ShortField("len", 36)]

    def extract_padding(self, s):
        return "", s


def _OSPFv3_LSAGuessPayloadClass(p, **kargs):
    """ Guess the correct OSPFv3 LSA class for a given payload """

    cls = conf.raw_layer

    if len(p) >= 6:
        typ = struct.unpack("!H", p[2:4])[0]
        clsname = _OSPFv3_LSclasses.get(typ, "Raw")
        cls = globals()[clsname]

    return cls(p, **kargs)


_OSPFv3_Router_LSA_types = {1: "p2p",
                            2: "transit",
                            3: "reserved",
                            4: "virtual"}


class OSPFv3_Link(Packet):
    name = "OSPFv3 Link"
    fields_desc = [ByteEnumField("type", 1, _OSPFv3_Router_LSA_types),
                   ByteField("reserved", 0),
                   ShortField("metric", 10),
                   IntField("intid", 0),
                   IntField("neighintid", 0),
                   IPField("neighbor", "2.2.2.2")]

    def extract_padding(self, s):
        return "", s


class OSPFv3_Router_LSA(OSPF_BaseLSA):
    name = "OSPFv3 Router LSA"
    fields_desc = [ShortField("age", 1),
                   ShortEnumField("type", 0x2001, _OSPFv3_LStypes),
                   IPField("id", "0.0.0.0"),
                   IPField("adrouter", "1.1.1.1"),
                   XIntField("seq", 0x80000001),
                   XShortField("chksum", None),
                   ShortField("len", None),
                   FlagsField("flags", 0, 8, ["B", "E", "V", "W"]),
                   OSPFv3OptionsField(),
                   PacketListField("linklist", [], OSPFv3_Link,
                                   length_from=lambda pkt:pkt.len - 24)]


class OSPFv3_Network_LSA(OSPF_BaseLSA):
    name = "OSPFv3 Network LSA"
    fields_desc = [ShortField("age", 1),
                   ShortEnumField("type", 0x2002, _OSPFv3_LStypes),
                   IPField("id", "0.0.0.0"),
                   IPField("adrouter", "1.1.1.1"),
                   XIntField("seq", 0x80000001),
                   XShortField("chksum", None),
                   ShortField("len", None),
                   ByteField("reserved", 0),
                   OSPFv3OptionsField(),
                   FieldListField("routerlist", [], IPField("", "0.0.0.1"),
                                  length_from=lambda pkt: pkt.len - 24)]


class OSPFv3PrefixOptionsField(FlagsField):

    def __init__(self, name="prefixoptions", default=0, size=8,
                 names=None):
        if names is None:
            names = ["NU", "LA", "MC", "P"]
        FlagsField.__init__(self, name, default, size, names)


class OSPFv3_Inter_Area_Prefix_LSA(OSPF_BaseLSA):
    name = "OSPFv3 Inter Area Prefix LSA"
    fields_desc = [ShortField("age", 1),
                   ShortEnumField("type", 0x2003, _OSPFv3_LStypes),
                   IPField("id", "0.0.0.0"),
                   IPField("adrouter", "1.1.1.1"),
                   XIntField("seq", 0x80000001),
                   XShortField("chksum", None),
                   ShortField("len", None),
                   ByteField("reserved", 0),
                   X3BytesField("metric", 10),
                   FieldLenField("prefixlen", None, length_of="prefix", fmt="B"),  # noqa: E501
                   OSPFv3PrefixOptionsField(),
                   ShortField("reserved2", 0),
                   IP6PrefixField("prefix", "2001:db8:0:42::/64", wordbytes=4, length_from=lambda pkt: pkt.prefixlen)]  # noqa: E501


class OSPFv3_Inter_Area_Router_LSA(OSPF_BaseLSA):
    name = "OSPFv3 Inter Area Router LSA"
    fields_desc = [ShortField("age", 1),
                   ShortEnumField("type", 0x2004, _OSPFv3_LStypes),
                   IPField("id", "0.0.0.0"),
                   IPField("adrouter", "1.1.1.1"),
                   XIntField("seq", 0x80000001),
                   XShortField("chksum", None),
                   ShortField("len", None),
                   ByteField("reserved", 0),
                   OSPFv3OptionsField(),
                   ByteField("reserved2", 0),
                   X3BytesField("metric", 1),
                   IPField("router", "2.2.2.2")]


class OSPFv3_AS_External_LSA(OSPF_BaseLSA):
    name = "OSPFv3 AS External LSA"
    fields_desc = [ShortField("age", 1),
                   ShortEnumField("type", 0x4005, _OSPFv3_LStypes),
                   IPField("id", "0.0.0.0"),
                   IPField("adrouter", "1.1.1.1"),
                   XIntField("seq", 0x80000001),
                   XShortField("chksum", None),
                   ShortField("len", None),
                   FlagsField("flags", 0, 8, ["T", "F", "E"]),
                   X3BytesField("metric", 20),
                   FieldLenField("prefixlen", None, length_of="prefix", fmt="B"),  # noqa: E501
                   OSPFv3PrefixOptionsField(),
                   ShortEnumField("reflstype", 0, _OSPFv3_LStypes),
                   IP6PrefixField("prefix", "2001:db8:0:42::/64", wordbytes=4, length_from=lambda pkt: pkt.prefixlen),  # noqa: E501
                   ConditionalField(IP6Field("fwaddr", "::"), lambda pkt: pkt.flags & 0x02 == 0x02),  # noqa: E501
                   ConditionalField(IntField("tag", 0), lambda pkt: pkt.flags & 0x01 == 0x01),  # noqa: E501
                   ConditionalField(IPField("reflsid", 0), lambda pkt: pkt.reflstype != 0)]  # noqa: E501


class OSPFv3_Type_7_LSA(OSPFv3_AS_External_LSA):
    name = "OSPFv3 Type 7 LSA"
    type = 0x2007


class OSPFv3_Prefix_Item(Packet):
    name = "OSPFv3 Link Prefix Item"
    fields_desc = [FieldLenField("prefixlen", None, length_of="prefix", fmt="B"),  # noqa: E501
                   OSPFv3PrefixOptionsField(),
                   ShortField("metric", 10),
                   IP6PrefixField("prefix", "2001:db8:0:42::/64", wordbytes=4, length_from=lambda pkt: pkt.prefixlen)]  # noqa: E501

    def extract_padding(self, s):
        return "", s


class OSPFv3_Link_LSA(OSPF_BaseLSA):
    name = "OSPFv3 Link LSA"
    fields_desc = [ShortField("age", 1),
                   ShortEnumField("type", 0x0008, _OSPFv3_LStypes),
                   IPField("id", "0.0.0.0"),
                   IPField("adrouter", "1.1.1.1"),
                   XIntField("seq", 0x80000001),
                   XShortField("chksum", None),
                   ShortField("len", None),
                   ByteField("prio", 1),
                   OSPFv3OptionsField(),
                   IP6Field("lladdr", "fe80::"),
                   FieldLenField("prefixes", None, count_of="prefixlist", fmt="I"),  # noqa: E501
                   PacketListField("prefixlist", None, OSPFv3_Prefix_Item,
                                   count_from=lambda pkt: pkt.prefixes)]


class OSPFv3_Intra_Area_Prefix_LSA(OSPF_BaseLSA):
    name = "OSPFv3 Intra Area Prefix LSA"
    fields_desc = [ShortField("age", 1),
                   ShortEnumField("type", 0x2009, _OSPFv3_LStypes),
                   IPField("id", "0.0.0.0"),
                   IPField("adrouter", "1.1.1.1"),
                   XIntField("seq", 0x80000001),
                   XShortField("chksum", None),
                   ShortField("len", None),
                   FieldLenField("prefixes", None, count_of="prefixlist", fmt="H"),  # noqa: E501
                   ShortEnumField("reflstype", 0, _OSPFv3_LStypes),
                   IPField("reflsid", "0.0.0.0"),
                   IPField("refadrouter", "0.0.0.0"),
                   PacketListField("prefixlist", None, OSPFv3_Prefix_Item,
                                   count_from=lambda pkt: pkt.prefixes)]


class OSPFv3_DBDesc(Packet):
    name = "OSPFv3 Database Description"
    fields_desc = [ByteField("reserved", 0),
                   OSPFv3OptionsField(),
                   ShortField("mtu", 1500),
                   ByteField("reserved2", 0),
                   FlagsField("dbdescr", 0, 8, ["MS", "M", "I", "R"]),
                   IntField("ddseq", 1),
                   PacketListField("lsaheaders", None, OSPFv3_LSA_Hdr,
                                   count_from=lambda pkt:None,
                                   length_from=lambda pkt:pkt.underlayer.len - 28)]  # noqa: E501


class OSPFv3_LSReq_Item(Packet):
    name = "OSPFv3 Link State Request (item)"
    fields_desc = [ShortField("reserved", 0),
                   ShortEnumField("type", 0x2001, _OSPFv3_LStypes),
                   IPField("id", "1.1.1.1"),
                   IPField("adrouter", "1.1.1.1")]

    def extract_padding(self, s):
        return "", s


class OSPFv3_LSReq(Packet):
    name = "OSPFv3 Link State Request (container)"
    fields_desc = [PacketListField("requests", None, OSPFv3_LSReq_Item,
                                   count_from=lambda pkt:None,
                                   length_from=lambda pkt:pkt.underlayer.len - 16)]  # noqa: E501


class OSPFv3_LSUpd(Packet):
    name = "OSPFv3 Link State Update"
    fields_desc = [FieldLenField("lsacount", None, fmt="!I", count_of="lsalist"),  # noqa: E501
                   PacketListField("lsalist", [], _OSPFv3_LSAGuessPayloadClass,
                                   count_from=lambda pkt:pkt.lsacount,
                                   length_from=lambda pkt:pkt.underlayer.len - 16)]  # noqa: E501


class OSPFv3_LSAck(Packet):
    name = "OSPFv3 Link State Acknowledgement"
    fields_desc = [PacketListField("lsaheaders", None, OSPFv3_LSA_Hdr,
                                   count_from=lambda pkt:None,
                                   length_from=lambda pkt:pkt.underlayer.len - 16)]  # noqa: E501


bind_layers(IP, OSPF_Hdr, proto=89)
bind_layers(OSPF_Hdr, OSPF_Hello, type=1)
bind_layers(OSPF_Hdr, OSPF_DBDesc, type=2)
bind_layers(OSPF_Hdr, OSPF_LSReq, type=3)
bind_layers(OSPF_Hdr, OSPF_LSUpd, type=4)
bind_layers(OSPF_Hdr, OSPF_LSAck, type=5)
DestIPField.bind_addr(OSPF_Hdr, "224.0.0.5")

bind_layers(IPv6, OSPFv3_Hdr, nh=89)
bind_layers(OSPFv3_Hdr, OSPFv3_Hello, type=1)
bind_layers(OSPFv3_Hdr, OSPFv3_DBDesc, type=2)
bind_layers(OSPFv3_Hdr, OSPFv3_LSReq, type=3)
bind_layers(OSPFv3_Hdr, OSPFv3_LSUpd, type=4)
bind_layers(OSPFv3_Hdr, OSPFv3_LSAck, type=5)
DestIP6Field.bind_addr(OSPFv3_Hdr, "ff02::5")


if __name__ == "__main__":
    from scapy.main import interact
    interact(mydict=globals(), mybanner="OSPF extension %s" % EXT_VERSION)
