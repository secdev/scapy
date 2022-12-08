# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>

"""
PPP (Point to Point Protocol)

[RFC 1661]
"""

import struct
from scapy.config import conf
from scapy.data import DLT_PPP, DLT_PPP_SERIAL, DLT_PPP_ETHER, \
    DLT_PPP_WITH_DIR
from scapy.compat import orb
from scapy.packet import Packet, bind_layers
from scapy.layers.eap import EAP
from scapy.layers.l2 import Ether, CookedLinux, GRE_PPTP
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from scapy.fields import (
    BitField,
    ByteEnumField,
    ByteField,
    ConditionalField,
    EnumField,
    FieldLenField,
    IPField,
    IntField,
    OUIField,
    PacketField,
    PacketListField,
    ShortEnumField,
    ShortField,
    StrLenField,
    XByteField,
    XShortField,
    XStrLenField,
)
from scapy.libs import six


class PPPoE(Packet):
    name = "PPP over Ethernet"
    fields_desc = [BitField("version", 1, 4),
                   BitField("type", 1, 4),
                   ByteEnumField("code", 0, {0: "Session"}),
                   XShortField("sessionid", 0x0),
                   ShortField("len", None)]

    def post_build(self, p, pay):
        p += pay
        if self.len is None:
            tmp_len = len(p) - 6
            p = p[:4] + struct.pack("!H", tmp_len) + p[6:]
        return p


# PPPoE Active Discovery Code fields (RFC2516, RFC5578)
class PPPoED(PPPoE):
    name = "PPP over Ethernet Discovery"

    code_list = {0x00: "PPP Session Stage",
                 0x09: "PPPoE Active Discovery Initiation (PADI)",
                 0x07: "PPPoE Active Discovery Offer (PADO)",
                 0x0a: "PPPoE Active Discovery Session-Grant (PADG)",
                 0x0b: "PPPoE Active Discovery Session-Credit Response (PADC)",
                 0x0c: "PPPoE Active Discovery Quality (PADQ)",
                 0x19: "PPPoE Active Discovery Request (PADR)",
                 0x65: "PPPoE Active Discovery Session-confirmation (PADS)",
                 0xa7: "PPPoE Active Discovery Terminate (PADT)"}

    fields_desc = [BitField("version", 1, 4),
                   BitField("type", 1, 4),
                   ByteEnumField("code", 0x09, code_list),
                   XShortField("sessionid", 0x0),
                   ShortField("len", None)]

    def extract_padding(self, s):
        return s[:self.len], s[self.len:]

    def mysummary(self):
        return self.sprintf("%code%")


# PPPoE Tag types (RFC2516, RFC4638, RFC5578)
class PPPoETag(Packet):
    name = "PPPoE Tag"

    tag_list = {0x0000: 'End-Of-List',
                0x0101: 'Service-Name',
                0x0102: 'AC-Name',
                0x0103: 'Host-Uniq',
                0x0104: 'AC-Cookie',
                0x0105: 'Vendor-Specific',
                0x0106: 'Credits',
                0x0107: 'Metrics',
                0x0108: 'Sequence Number',
                0x0109: 'Credit Scale Factor',
                0x0110: 'Relay-Session-Id',
                0x0120: 'PPP-Max-Payload',
                0x0201: 'Service-Name-Error',
                0x0202: 'AC-System-Error',
                0x0203: 'Generic-Error'}

    fields_desc = [
        ShortEnumField('tag_type', None, tag_list),
        FieldLenField('tag_len', None, length_of='tag_value', fmt='H'),
        StrLenField('tag_value', '', length_from=lambda pkt:pkt.tag_len)
    ]

    def extract_padding(self, s):
        return '', s


class PPPoED_Tags(Packet):
    name = "PPPoE Tag List"
    fields_desc = [PacketListField('tag_list', None, PPPoETag)]

    def mysummary(self):
        return "PPPoE Tags" + ", ".join(
            x.sprintf("%tag_type%") for x in self.tag_list
        ), [PPPoED]


_PPP_PROTOCOLS = {
    0x0001: "Padding Protocol",
    0x0003: "ROHC small-CID [RFC3095]",
    0x0005: "ROHC large-CID [RFC3095]",
    0x0021: "Internet Protocol version 4",
    0x0023: "OSI Network Layer",
    0x0025: "Xerox NS IDP",
    0x0027: "DECnet Phase IV",
    0x0029: "Appletalk",
    0x002b: "Novell IPX",
    0x002d: "Van Jacobson Compressed TCP/IP",
    0x002f: "Van Jacobson Uncompressed TCP/IP",
    0x0031: "Bridging PDU",
    0x0033: "Stream Protocol (ST-II)",
    0x0035: "Banyan Vines",
    0x0037: "reserved (until 1993) [Typo in RFC1172]",
    0x0039: "AppleTalk EDDP",
    0x003b: "AppleTalk SmartBuffered",
    0x003d: "Multi-Link [RFC1717]",
    0x003f: "NETBIOS Framing",
    0x0041: "Cisco Systems",
    0x0043: "Ascom Timeplex",
    0x0045: "Fujitsu Link Backup and Load Balancing (LBLB)",
    0x0047: "DCA Remote Lan",
    0x0049: "Serial Data Transport Protocol (PPP-SDTP)",
    0x004b: "SNA over 802.2",
    0x004d: "SNA",
    0x004f: "IPv6 Header Compression",
    0x0051: "KNX Bridging Data [ianp]",
    0x0053: "Encryption [Meyer]",
    0x0055: "Individual Link Encryption [Meyer]",
    0x0057: "Internet Protocol version 6 [Hinden]",
    0x0059: "PPP Muxing [RFC3153]",
    0x005b: "Vendor-Specific Network Protocol (VSNP) [RFC3772]",
    0x0061: "RTP IPHC Full Header [RFC3544]",
    0x0063: "RTP IPHC Compressed TCP [RFC3544]",
    0x0065: "RTP IPHC Compressed Non TCP [RFC3544]",
    0x0067: "RTP IPHC Compressed UDP 8 [RFC3544]",
    0x0069: "RTP IPHC Compressed RTP 8 [RFC3544]",
    0x006f: "Stampede Bridging",
    0x0071: "Reserved [Fox]",
    0x0073: "MP+ Protocol [Smith]",
    0x007d: "reserved (Control Escape) [RFC1661]",
    0x007f: "reserved (compression inefficient [RFC1662]",
    0x0081: "Reserved Until 20-Oct-2000 [IANA]",
    0x0083: "Reserved Until 20-Oct-2000 [IANA]",
    0x00c1: "NTCITS IPI [Ungar]",
    0x00cf: "reserved (PPP NLID)",
    0x00fb: "single link compression in multilink [RFC1962]",
    0x00fd: "compressed datagram [RFC1962]",
    0x00ff: "reserved (compression inefficient)",
    0x0201: "802.1d Hello Packets",
    0x0203: "IBM Source Routing BPDU",
    0x0205: "DEC LANBridge100 Spanning Tree",
    0x0207: "Cisco Discovery Protocol [Sastry]",
    0x0209: "Netcs Twin Routing [Korfmacher]",
    0x020b: "STP - Scheduled Transfer Protocol [Segal]",
    0x020d: "EDP - Extreme Discovery Protocol [Grosser]",
    0x0211: "Optical Supervisory Channel Protocol (OSCP)[Prasad]",
    0x0213: "Optical Supervisory Channel Protocol (OSCP)[Prasad]",
    0x0231: "Luxcom",
    0x0233: "Sigma Network Systems",
    0x0235: "Apple Client Server Protocol [Ridenour]",
    0x0281: "MPLS Unicast [RFC3032]  ",
    0x0283: "MPLS Multicast [RFC3032]",
    0x0285: "IEEE p1284.4 standard - data packets [Batchelder]",
    0x0287: "ETSI TETRA Network Protocol Type 1 [Nieminen]",
    0x0289: "Multichannel Flow Treatment Protocol [McCann]",
    0x2063: "RTP IPHC Compressed TCP No Delta [RFC3544]",
    0x2065: "RTP IPHC Context State [RFC3544]",
    0x2067: "RTP IPHC Compressed UDP 16 [RFC3544]",
    0x2069: "RTP IPHC Compressed RTP 16 [RFC3544]",
    0x4001: "Cray Communications Control Protocol [Stage]",
    0x4003: "CDPD Mobile Network Registration Protocol [Quick]",
    0x4005: "Expand accelerator protocol [Rachmani]",
    0x4007: "ODSICP NCP [Arvind]",
    0x4009: "DOCSIS DLL [Gaedtke]",
    0x400B: "Cetacean Network Detection Protocol [Siller]",
    0x4021: "Stacker LZS [Simpson]",
    0x4023: "RefTek Protocol [Banfill]",
    0x4025: "Fibre Channel [Rajagopal]",
    0x4027: "EMIT Protocols [Eastham]",
    0x405b: "Vendor-Specific Protocol (VSP) [RFC3772]",
    0x8021: "Internet Protocol Control Protocol",
    0x8023: "OSI Network Layer Control Protocol",
    0x8025: "Xerox NS IDP Control Protocol",
    0x8027: "DECnet Phase IV Control Protocol",
    0x8029: "Appletalk Control Protocol",
    0x802b: "Novell IPX Control Protocol",
    0x802d: "reserved",
    0x802f: "reserved",
    0x8031: "Bridging NCP",
    0x8033: "Stream Protocol Control Protocol",
    0x8035: "Banyan Vines Control Protocol",
    0x8037: "reserved (until 1993)",
    0x8039: "reserved",
    0x803b: "reserved",
    0x803d: "Multi-Link Control Protocol",
    0x803f: "NETBIOS Framing Control Protocol",
    0x8041: "Cisco Systems Control Protocol",
    0x8043: "Ascom Timeplex",
    0x8045: "Fujitsu LBLB Control Protocol",
    0x8047: "DCA Remote Lan Network Control Protocol (RLNCP)",
    0x8049: "Serial Data Control Protocol (PPP-SDCP)",
    0x804b: "SNA over 802.2 Control Protocol",
    0x804d: "SNA Control Protocol",
    0x804f: "IP6 Header Compression Control Protocol",
    0x8051: "KNX Bridging Control Protocol [ianp]",
    0x8053: "Encryption Control Protocol [Meyer]",
    0x8055: "Individual Link Encryption Control Protocol [Meyer]",
    0x8057: "IPv6 Control Protovol [Hinden]",
    0x8059: "PPP Muxing Control Protocol [RFC3153]",
    0x805b: "Vendor-Specific Network Control Protocol (VSNCP) [RFC3772]",
    0x806f: "Stampede Bridging Control Protocol",
    0x8073: "MP+ Control Protocol [Smith]",
    0x8071: "Reserved [Fox]",
    0x807d: "Not Used - reserved [RFC1661]",
    0x8081: "Reserved Until 20-Oct-2000 [IANA]",
    0x8083: "Reserved Until 20-Oct-2000 [IANA]",
    0x80c1: "NTCITS IPI Control Protocol [Ungar]",
    0x80cf: "Not Used - reserved [RFC1661]",
    0x80fb: "single link compression in multilink control [RFC1962]",
    0x80fd: "Compression Control Protocol [RFC1962]",
    0x80ff: "Not Used - reserved [RFC1661]",
    0x8207: "Cisco Discovery Protocol Control [Sastry]",
    0x8209: "Netcs Twin Routing [Korfmacher]",
    0x820b: "STP - Control Protocol [Segal]",
    0x820d: "EDPCP - Extreme Discovery Protocol Ctrl Prtcl [Grosser]",
    0x8235: "Apple Client Server Protocol Control [Ridenour]",
    0x8281: "MPLSCP [RFC3032]",
    0x8285: "IEEE p1284.4 standard - Protocol Control [Batchelder]",
    0x8287: "ETSI TETRA TNP1 Control Protocol [Nieminen]",
    0x8289: "Multichannel Flow Treatment Protocol [McCann]",
    0xc021: "Link Control Protocol",
    0xc023: "Password Authentication Protocol",
    0xc025: "Link Quality Report",
    0xc027: "Shiva Password Authentication Protocol",
    0xc029: "CallBack Control Protocol (CBCP)",
    0xc02b: "BACP Bandwidth Allocation Control Protocol [RFC2125]",
    0xc02d: "BAP [RFC2125]",
    0xc05b: "Vendor-Specific Authentication Protocol (VSAP) [RFC3772]",
    0xc081: "Container Control Protocol [KEN]",
    0xc223: "Challenge Handshake Authentication Protocol",
    0xc225: "RSA Authentication Protocol [Narayana]",
    0xc227: "Extensible Authentication Protocol [RFC2284]",
    0xc229: "Mitsubishi Security Info Exch Ptcl (SIEP) [Seno]",
    0xc26f: "Stampede Bridging Authorization Protocol",
    0xc281: "Proprietary Authentication Protocol [KEN]",
    0xc283: "Proprietary Authentication Protocol [Tackabury]",
    0xc481: "Proprietary Node ID Authentication Protocol [KEN]",
}


class HDLC(Packet):
    fields_desc = [XByteField("address", 0xff),
                   XByteField("control", 0x03)]


# LINKTYPE_PPP_WITH_DIR
class DIR_PPP(Packet):
    fields_desc = [ByteEnumField("direction", 0, ["received", "sent"])]


class _PPPProtoField(EnumField):
    """
    A field that can be either Byte or Short, depending on the PPP RFC.

    See RFC 1661 section 2
    <https://tools.ietf.org/html/rfc1661#section-2>
    """
    def getfield(self, pkt, s):
        if ord(s[:1]) & 0x01:
            self.fmt = "!B"
            self.sz = 1
        else:
            self.fmt = "!H"
            self.sz = 2
        self.struct = struct.Struct(self.fmt)
        return super(_PPPProtoField, self).getfield(pkt, s)

    def addfield(self, pkt, s, val):
        if val < 0x100:
            self.fmt = "!B"
            self.sz = 1
        else:
            self.fmt = "!H"
            self.sz = 2
        self.struct = struct.Struct(self.fmt)
        return super(_PPPProtoField, self).addfield(pkt, s, val)


class PPP(Packet):
    name = "PPP Link Layer"
    fields_desc = [_PPPProtoField("proto", 0x0021, _PPP_PROTOCOLS)]

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and _pkt[:1] == b'\xff':
            return HDLC
        return cls


_PPP_conftypes = {1: "Configure-Request",
                  2: "Configure-Ack",
                  3: "Configure-Nak",
                  4: "Configure-Reject",
                  5: "Terminate-Request",
                  6: "Terminate-Ack",
                  7: "Code-Reject",
                  8: "Protocol-Reject",
                  9: "Echo-Request",
                  10: "Echo-Reply",
                  11: "Discard-Request",
                  14: "Reset-Request",
                  15: "Reset-Ack",
                  }


# PPP IPCP stuff (RFC 1332)

# All IPCP options are defined below (names and associated classes)
_PPP_ipcpopttypes = {1: "IP-Addresses (Deprecated)",
                     2: "IP-Compression-Protocol",
                     3: "IP-Address",
                     # not implemented, present for completeness
                     4: "Mobile-IPv4",
                     129: "Primary-DNS-Address",
                     130: "Primary-NBNS-Address",
                     131: "Secondary-DNS-Address",
                     132: "Secondary-NBNS-Address"}


class PPP_IPCP_Option(Packet):
    name = "PPP IPCP Option"
    fields_desc = [
        ByteEnumField("type", None, _PPP_ipcpopttypes),
        FieldLenField("len", None, length_of="data", fmt="B",
                      adjust=lambda _, val: val + 2),
        StrLenField("data", "", length_from=lambda pkt: max(0, pkt.len - 2)),
    ]

    def extract_padding(self, pay):
        return b"", pay

    registered_options = {}

    @classmethod
    def register_variant(cls):
        cls.registered_options[cls.type.default] = cls

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt:
            o = orb(_pkt[0])
            return cls.registered_options.get(o, cls)
        return cls


class PPP_IPCP_Option_IPAddress(PPP_IPCP_Option):
    name = "PPP IPCP Option: IP Address"
    fields_desc = [
        ByteEnumField("type", 3, _PPP_ipcpopttypes),
        FieldLenField("len", None, length_of="data", fmt="B",
                      adjust=lambda _, val: val + 2),
        IPField("data", "0.0.0.0"),
        StrLenField("garbage", "", length_from=lambda pkt: pkt.len - 6),
    ]


class PPP_IPCP_Option_DNS1(PPP_IPCP_Option_IPAddress):
    name = "PPP IPCP Option: DNS1 Address"
    type = 129


class PPP_IPCP_Option_DNS2(PPP_IPCP_Option_IPAddress):
    name = "PPP IPCP Option: DNS2 Address"
    type = 131


class PPP_IPCP_Option_NBNS1(PPP_IPCP_Option_IPAddress):
    name = "PPP IPCP Option: NBNS1 Address"
    type = 130


class PPP_IPCP_Option_NBNS2(PPP_IPCP_Option_IPAddress):
    name = "PPP IPCP Option: NBNS2 Address"
    type = 132


class PPP_IPCP(Packet):
    fields_desc = [
        ByteEnumField("code", 1, _PPP_conftypes),
        XByteField("id", 0),
        FieldLenField("len", None, fmt="H", length_of="options",
                      adjust=lambda _, val: val + 4),
        PacketListField("options", [], PPP_IPCP_Option,
                        length_from=lambda pkt: pkt.len - 4)
    ]


# ECP

_PPP_ecpopttypes = {0: "OUI",
                    1: "DESE", }


class PPP_ECP_Option(Packet):
    name = "PPP ECP Option"
    fields_desc = [
        ByteEnumField("type", None, _PPP_ecpopttypes),
        FieldLenField("len", None, length_of="data", fmt="B",
                      adjust=lambda _, val: val + 2),
        StrLenField("data", "", length_from=lambda pkt: max(0, pkt.len - 2)),
    ]

    def extract_padding(self, pay):
        return b"", pay

    registered_options = {}

    @classmethod
    def register_variant(cls):
        cls.registered_options[cls.type.default] = cls

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt:
            o = orb(_pkt[0])
            return cls.registered_options.get(o, cls)
        return cls


class PPP_ECP_Option_OUI(PPP_ECP_Option):
    fields_desc = [
        ByteEnumField("type", 0, _PPP_ecpopttypes),
        FieldLenField("len", None, length_of="data", fmt="B",
                      adjust=lambda _, val: val + 6),
        OUIField("oui", 0),
        ByteField("subtype", 0),
        StrLenField("data", "", length_from=lambda pkt: pkt.len - 6),
    ]


class PPP_ECP(Packet):
    fields_desc = [
        ByteEnumField("code", 1, _PPP_conftypes),
        XByteField("id", 0),
        FieldLenField("len", None, fmt="H", length_of="options",
                      adjust=lambda _, val: val + 4),
        PacketListField("options", [], PPP_ECP_Option,
                        length_from=lambda pkt: pkt.len - 4),
    ]

# Link Control Protocol (RFC 1661)


_PPP_lcptypes = {1: "Configure-Request",
                 2: "Configure-Ack",
                 3: "Configure-Nak",
                 4: "Configure-Reject",
                 5: "Terminate-Request",
                 6: "Terminate-Ack",
                 7: "Code-Reject",
                 8: "Protocol-Reject",
                 9: "Echo-Request",
                 10: "Echo-Reply",
                 11: "Discard-Request"}


class PPP_LCP(Packet):
    name = "PPP Link Control Protocol"
    fields_desc = [
        ByteEnumField("code", 5, _PPP_lcptypes),
        XByteField("id", 0),
        FieldLenField("len", None, fmt="H", length_of="data",
                      adjust=lambda _, val: val + 4),
        StrLenField("data", "", length_from=lambda pkt: pkt.len - 4),
    ]

    def mysummary(self):
        return self.sprintf('LCP %code%')

    def extract_padding(self, pay):
        return b"", pay

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt:
            o = orb(_pkt[0])
            if o in [1, 2, 3, 4]:
                return PPP_LCP_Configure
            elif o in [5, 6]:
                return PPP_LCP_Terminate
            elif o == 7:
                return PPP_LCP_Code_Reject
            elif o == 8:
                return PPP_LCP_Protocol_Reject
            elif o in [9, 10]:
                return PPP_LCP_Echo
            elif o == 11:
                return PPP_LCP_Discard_Request
            else:
                return cls
        return cls


_PPP_lcp_optiontypes = {1: "Maximum-Receive-Unit",
                        2: "Async-Control-Character-Map",
                        3: "Authentication-protocol",
                        4: "Quality-protocol",
                        5: "Magic-number",
                        7: "Protocol-Field-Compression",
                        8: "Address-and-Control-Field-Compression",
                        13: "Callback"}


class PPP_LCP_Option(Packet):
    name = "PPP LCP Option"
    fields_desc = [
        ByteEnumField("type", None, _PPP_lcp_optiontypes),
        FieldLenField("len", None, fmt="B", length_of="data",
                      adjust=lambda _, val: val + 2),
        StrLenField("data", None, length_from=lambda pkt: pkt.len - 2),
    ]

    def extract_padding(self, pay):
        return b"", pay

    registered_options = {}

    @classmethod
    def register_variant(cls):
        cls.registered_options[cls.type.default] = cls

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt:
            o = orb(_pkt[0])
            return cls.registered_options.get(o, cls)
        return cls


class PPP_LCP_MRU_Option(PPP_LCP_Option):
    fields_desc = [ByteEnumField("type", 1, _PPP_lcp_optiontypes),
                   ByteField("len", 4),
                   ShortField("max_recv_unit", 1500)]


_PPP_LCP_auth_protocols = {
    0xc023: "Password authentication protocol",
    0xc223: "Challenge-response authentication protocol",
    0xc227: "PPP Extensible authentication protocol",
}

_PPP_LCP_CHAP_algorithms = {
    5: "MD5",
    6: "SHA1",
    128: "MS-CHAP",
    129: "MS-CHAP-v2",
}


class PPP_LCP_ACCM_Option(PPP_LCP_Option):
    fields_desc = [
        ByteEnumField("type", 2, _PPP_lcp_optiontypes),
        ByteField("len", 6),
        BitField("accm", 0x00000000, 32),
    ]


def adjust_auth_len(pkt, x):
    if pkt.auth_protocol == 0xc223:
        return 5
    elif pkt.auth_protocol == 0xc023:
        return 4
    else:
        return x + 4


class PPP_LCP_Auth_Protocol_Option(PPP_LCP_Option):
    fields_desc = [
        ByteEnumField("type", 3, _PPP_lcp_optiontypes),
        FieldLenField("len", None, fmt="B", length_of="data",
                      adjust=adjust_auth_len),
        ShortEnumField("auth_protocol", 0xc023, _PPP_LCP_auth_protocols),
        ConditionalField(
            StrLenField("data", '', length_from=lambda pkt: pkt.len - 4),
            lambda pkt: pkt.auth_protocol != 0xc223
        ),
        ConditionalField(
            ByteEnumField("algorithm", 5, _PPP_LCP_CHAP_algorithms),
            lambda pkt: pkt.auth_protocol == 0xc223
        ),
    ]


_PPP_LCP_quality_protocols = {0xc025: "Link Quality Report"}


class PPP_LCP_Quality_Protocol_Option(PPP_LCP_Option):
    fields_desc = [
        ByteEnumField("type", 4, _PPP_lcp_optiontypes),
        FieldLenField("len", None, fmt="B", length_of="data",
                      adjust=lambda _, val: val + 4),
        ShortEnumField("quality_protocol", 0xc025, _PPP_LCP_quality_protocols),
        StrLenField("data", "", length_from=lambda pkt: pkt.len - 4),
    ]


class PPP_LCP_Magic_Number_Option(PPP_LCP_Option):
    fields_desc = [
        ByteEnumField("type", 5, _PPP_lcp_optiontypes),
        ByteField("len", 6),
        IntField("magic_number", None),
    ]


_PPP_lcp_callback_operations = {
    0: "Location determined by user authentication",
    1: "Dialing string",
    2: "Location identifier",
    3: "E.164 number",
    4: "Distinguished name",
}


class PPP_LCP_Callback_Option(PPP_LCP_Option):
    fields_desc = [
        ByteEnumField("type", 13, _PPP_lcp_optiontypes),
        FieldLenField("len", None, fmt="B", length_of="message",
                      adjust=lambda _, val: val + 3),
        ByteEnumField("operation", 0, _PPP_lcp_callback_operations),
        StrLenField("message", "", length_from=lambda pkt: pkt.len - 3)
    ]


class PPP_LCP_Configure(PPP_LCP):
    fields_desc = [
        ByteEnumField("code", 1, _PPP_lcptypes),
        XByteField("id", 0),
        FieldLenField("len", None, fmt="H", length_of="options",
                      adjust=lambda _, val: val + 4),
        PacketListField("options", [], PPP_LCP_Option,
                        length_from=lambda pkt: pkt.len - 4),
    ]

    def answers(self, other):
        return (
            isinstance(other, PPP_LCP_Configure) and self.code in [2, 3, 4] and
            other.code == 1 and other.id == self.id
        )


class PPP_LCP_Terminate(PPP_LCP):

    def answers(self, other):
        return (
            isinstance(other, PPP_LCP_Terminate) and self.code == 6 and
            other.code == 5 and other.id == self.id
        )


class PPP_LCP_Code_Reject(PPP_LCP):
    fields_desc = [
        ByteEnumField("code", 7, _PPP_lcptypes),
        XByteField("id", 0),
        FieldLenField("len", None, fmt="H", length_of="rejected_packet",
                      adjust=lambda _, val: val + 4),
        PacketField("rejected_packet", None, PPP_LCP),
    ]


class PPP_LCP_Protocol_Reject(PPP_LCP):
    fields_desc = [
        ByteEnumField("code", 8, _PPP_lcptypes),
        XByteField("id", 0),
        FieldLenField("len", None, fmt="H", length_of="rejected_information",
                      adjust=lambda _, val: val + 6),
        ShortEnumField("rejected_protocol", None, _PPP_PROTOCOLS),
        PacketField("rejected_information", None, Packet),
    ]


class PPP_LCP_Discard_Request(PPP_LCP):
    fields_desc = [
        ByteEnumField("code", 11, _PPP_lcptypes),
        XByteField("id", 0),
        FieldLenField("len", None, fmt="H", length_of="data",
                      adjust=lambda _, val: val + 8),
        IntField("magic_number", None),
        StrLenField("data", "", length_from=lambda pkt: pkt.len - 8),
    ]


class PPP_LCP_Echo(PPP_LCP_Discard_Request):
    code = 9

    def answers(self, other):
        return (
            isinstance(other, PPP_LCP_Echo) and self.code == 10 and
            other.code == 9 and self.id == other.id
        )


# Password authentication protocol (RFC 1334)


_PPP_paptypes = {1: "Authenticate-Request",
                 2: "Authenticate-Ack",
                 3: "Authenticate-Nak"}


class PPP_PAP(Packet):
    name = "PPP Password Authentication Protocol"
    fields_desc = [
        ByteEnumField("code", 1, _PPP_paptypes),
        XByteField("id", 0),
        FieldLenField("len", None, fmt="!H", length_of="data",
                      adjust=lambda _, val: val + 4),
        StrLenField("data", "", length_from=lambda pkt: pkt.len - 4),
    ]

    @classmethod
    def dispatch_hook(cls, _pkt=None, *_, **kargs):
        code = None
        if _pkt:
            code = orb(_pkt[0])
        elif "code" in kargs:
            code = kargs["code"]
            if isinstance(code, six.string_types):
                code = cls.fields_desc[0].s2i[code]

        if code == 1:
            return PPP_PAP_Request
        elif code in [2, 3]:
            return PPP_PAP_Response
        return cls

    def extract_padding(self, pay):
        return "", pay


class PPP_PAP_Request(PPP_PAP):
    fields_desc = [
        ByteEnumField("code", 1, _PPP_paptypes),
        XByteField("id", 0),
        FieldLenField("len", None, fmt="!H", length_of="username",
                      adjust=lambda pkt, val: val + 6 + len(pkt.password)),
        FieldLenField("username_len", None, fmt="B", length_of="username"),
        StrLenField("username", None,
                    length_from=lambda pkt: pkt.username_len),
        FieldLenField("passwd_len", None, fmt="B", length_of="password"),
        StrLenField("password", None, length_from=lambda pkt: pkt.passwd_len),
    ]

    def mysummary(self):
        return self.sprintf("PAP-Request username=%PPP_PAP_Request.username%"
                            " password=%PPP_PAP_Request.password%")


class PPP_PAP_Response(PPP_PAP):
    fields_desc = [
        ByteEnumField("code", 2, _PPP_paptypes),
        XByteField("id", 0),
        FieldLenField("len", None, fmt="!H", length_of="message",
                      adjust=lambda _, val: val + 5),
        FieldLenField("msg_len", None, fmt="B", length_of="message"),
        StrLenField("message", "", length_from=lambda pkt: pkt.msg_len),
    ]

    def answers(self, other):
        return isinstance(other, PPP_PAP_Request) and other.id == self.id

    def mysummary(self):
        res = "PAP-Ack" if self.code == 2 else "PAP-Nak"
        if self.msg_len > 0:
            res += self.sprintf(" msg=%PPP_PAP_Response.message%")
        return res


# Challenge Handshake Authentication protocol (RFC1994)

_PPP_chaptypes = {1: "Challenge",
                  2: "Response",
                  3: "Success",
                  4: "Failure"}


class PPP_CHAP(Packet):
    name = "PPP Challenge Handshake Authentication Protocol"
    fields_desc = [
        ByteEnumField("code", 1, _PPP_chaptypes),
        XByteField("id", 0),
        FieldLenField("len", None, fmt="!H", length_of="data",
                      adjust=lambda _, val: val + 4),
        StrLenField("data", "", length_from=lambda pkt: pkt.len - 4),
    ]

    def answers(self, other):
        return isinstance(other, PPP_CHAP_ChallengeResponse) \
            and other.code == 2 and self.code in (3, 4) \
            and self.id == other.id

    @classmethod
    def dispatch_hook(cls, _pkt=None, *_, **kargs):
        code = None
        if _pkt:
            code = orb(_pkt[0])
        elif "code" in kargs:
            code = kargs["code"]
            if isinstance(code, six.string_types):
                code = cls.fields_desc[0].s2i[code]

        if code in (1, 2):
            return PPP_CHAP_ChallengeResponse
        return cls

    def extract_padding(self, pay):
        return "", pay

    def mysummary(self):
        if self.code == 3:
            return self.sprintf("CHAP Success message=%PPP_CHAP.data%")
        elif self.code == 4:
            return self.sprintf("CHAP Failure message=%PPP_CHAP.data%")


class PPP_CHAP_ChallengeResponse(PPP_CHAP):
    fields_desc = [
        ByteEnumField("code", 1, _PPP_chaptypes),
        XByteField("id", 0),
        FieldLenField(
            "len", None, fmt="!H", length_of="value",
            adjust=lambda pkt, val: val + len(pkt.optional_name) + 5,
        ),
        FieldLenField("value_size", None, fmt="B", length_of="value"),
        XStrLenField("value", b'\x00\x00\x00\x00\x00\x00\x00\x00',
                     length_from=lambda pkt: pkt.value_size),
        StrLenField("optional_name", "",
                    length_from=lambda pkt: pkt.len - pkt.value_size - 5),
    ]

    def answers(self, other):
        return isinstance(other, PPP_CHAP_ChallengeResponse) \
            and other.code == 1 and self.code == 2 and self.id == other.id

    def mysummary(self):
        if self.code == 1:
            return self.sprintf(
                "CHAP challenge=0x%PPP_CHAP_ChallengeResponse.value% "
                "optional_name=%PPP_CHAP_ChallengeResponse.optional_name%"
            )
        elif self.code == 2:
            return self.sprintf(
                "CHAP response=0x%PPP_CHAP_ChallengeResponse.value% "
                "optional_name=%PPP_CHAP_ChallengeResponse.optional_name%"
            )
        else:
            return super(PPP_CHAP_ChallengeResponse, self).mysummary()


bind_layers(PPPoED, PPPoED_Tags, type=1)
bind_layers(Ether, PPPoED, type=0x8863)
bind_layers(Ether, PPPoE, type=0x8864)
bind_layers(CookedLinux, PPPoED, proto=0x8863)
bind_layers(CookedLinux, PPPoE, proto=0x8864)
bind_layers(PPPoE, PPP, code=0)
bind_layers(HDLC, PPP,)
bind_layers(DIR_PPP, PPP)
bind_layers(PPP, EAP, proto=0xc227)
bind_layers(PPP, IP, proto=0x0021)
bind_layers(PPP, IPv6, proto=0x0057)
bind_layers(PPP, PPP_CHAP, proto=0xc223)
bind_layers(PPP, PPP_IPCP, proto=0x8021)
bind_layers(PPP, PPP_ECP, proto=0x8053)
bind_layers(PPP, PPP_LCP, proto=0xc021)
bind_layers(PPP, PPP_PAP, proto=0xc023)
bind_layers(Ether, PPP_IPCP, type=0x8021)
bind_layers(Ether, PPP_ECP, type=0x8053)
bind_layers(GRE_PPTP, PPP, proto=0x880b)


conf.l2types.register(DLT_PPP, PPP)
conf.l2types.register(DLT_PPP_SERIAL, HDLC)
conf.l2types.register(DLT_PPP_ETHER, PPPoE)
conf.l2types.register(DLT_PPP_WITH_DIR, DIR_PPP)
