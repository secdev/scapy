# This file is part of Scapy
# Scapy is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# any later version.
#
# Scapy is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Scapy. If not, see <http://www.gnu.org/licenses/>.

# scapy.contrib.description = Internet Key Exchange v2 (IKEv2)
# scapy.contrib.status = loads

import logging
import struct


# Modified from the original ISAKMP code by Yaron Sheffer <yaronf.ietf@gmail.com>, June 2010.  # noqa: E501

from scapy.packet import Packet, bind_layers, split_layers, Raw
from scapy.fields import ByteEnumField, ByteField, ConditionalField, \
    FieldLenField, FlagsField, IP6Field, IPField, IntField, MultiEnumField, \
    PacketField, PacketLenField, PacketListField, ShortEnumField, ShortField, \
    StrFixedLenField, StrLenField, X3BytesField, XByteField
from scapy.layers.x509 import X509_Cert, X509_CRL
from scapy.layers.inet import IP, UDP
from scapy.layers.isakmp import ISAKMP
from scapy.sendrecv import sr
from scapy.config import conf
from scapy.volatile import RandString

# see http://www.iana.org/assignments/ikev2-parameters for details
IKEv2AttributeTypes = {"Encryption": (1, {"DES-IV64": 1,
                                          "DES": 2,
                                          "3DES": 3,
                                          "RC5": 4,
                                          "IDEA": 5,
                                          "CAST": 6,
                                          "Blowfish": 7,
                                          "3IDEA": 8,
                                          "DES-IV32": 9,
                                          "AES-CBC": 12,
                                          "AES-CTR": 13,
                                          "AES-CCM-8": 14,
                                          "AES-CCM-12": 15,
                                          "AES-CCM-16": 16,
                                          "AES-GCM-8ICV": 18,
                                          "AES-GCM-12ICV": 19,
                                          "AES-GCM-16ICV": 20,
                                          "Camellia-CBC": 23,
                                          "Camellia-CTR": 24,
                                          "Camellia-CCM-8ICV": 25,
                                          "Camellia-CCM-12ICV": 26,
                                          "Camellia-CCM-16ICV": 27,
                                          }, 0),
                       "PRF": (2, {"PRF_HMAC_MD5": 1,
                                   "PRF_HMAC_SHA1": 2,
                                   "PRF_HMAC_TIGER": 3,
                                   "PRF_AES128_XCBC": 4,
                                   "PRF_HMAC_SHA2_256": 5,
                                   "PRF_HMAC_SHA2_384": 6,
                                   "PRF_HMAC_SHA2_512": 7,
                                   "PRF_AES128_CMAC": 8,
                                   }, 0),
                       "Integrity": (3, {"HMAC-MD5-96": 1,
                                         "HMAC-SHA1-96": 2,
                                         "DES-MAC": 3,
                                         "KPDK-MD5": 4,
                                         "AES-XCBC-96": 5,
                                         "HMAC-MD5-128": 6,
                                         "HMAC-SHA1-160": 7,
                                         "AES-CMAC-96": 8,
                                         "AES-128-GMAC": 9,
                                         "AES-192-GMAC": 10,
                                         "AES-256-GMAC": 11,
                                         "SHA2-256-128": 12,
                                         "SHA2-384-192": 13,
                                         "SHA2-512-256": 14,
                                         }, 0),
                       "GroupDesc": (4, {"768MODPgr": 1,
                                         "1024MODPgr": 2,
                                         "1536MODPgr": 5,
                                         "2048MODPgr": 14,
                                         "3072MODPgr": 15,
                                         "4096MODPgr": 16,
                                         "6144MODPgr": 17,
                                         "8192MODPgr": 18,
                                         "256randECPgr": 19,
                                         "384randECPgr": 20,
                                         "521randECPgr": 21,
                                         "1024MODP160POSgr": 22,
                                         "2048MODP224POSgr": 23,
                                         "2048MODP256POSgr": 24,
                                         "192randECPgr": 25,
                                         "224randECPgr": 26,
                                         }, 0),
                       "Extended Sequence Number": (5, {"No ESN": 0,
                                                        "ESN": 1}, 0),
                       }

IKEv2AuthenticationTypes = {
    0: "Reserved",
    1: "RSA Digital Signature",
    2: "Shared Key Message Integrity Code",
    3: "DSS Digital Signature",
    9: "ECDSA with SHA-256 on the P-256 curve",
    10: "ECDSA with SHA-384 on the P-384 curve",
    11: "ECDSA with SHA-512 on the P-521 curve",
    12: "Generic Secure Password Authentication Method",
    13: "NULL Authentication",
    14: "Digital Signature"
}

IKEv2NotifyMessageTypes = {
    1: "UNSUPPORTED_CRITICAL_PAYLOAD",
    4: "INVALID_IKE_SPI",
    5: "INVALID_MAJOR_VERSION",
    7: "INVALID_SYNTAX",
    9: "INVALID_MESSAGE_ID",
    11: "INVALID_SPI",
    14: "NO_PROPOSAL_CHOSEN",
    17: "INVALID_KE_PAYLOAD",
    24: "AUTHENTICATION_FAILED",
    34: "SINGLE_PAIR_REQUIRED",
    35: "NO_ADDITIONAL_SAS",
    36: "INTERNAL_ADDRESS_FAILURE",
    37: "FAILED_CP_REQUIRED",
    38: "TS_UNACCEPTABLE",
    39: "INVALID_SELECTORS",
    40: "UNACCEPTABLE_ADDRESSES",
    41: "UNEXPECTED_NAT_DETECTED",
    42: "USE_ASSIGNED_HoA",
    43: "TEMPORARY_FAILURE",
    44: "CHILD_SA_NOT_FOUND",
    45: "INVALID_GROUP_ID",
    46: "AUTHORIZATION_FAILED",
    16384: "INITIAL_CONTACT",
    16385: "SET_WINDOW_SIZE",
    16386: "ADDITIONAL_TS_POSSIBLE",
    16387: "IPCOMP_SUPPORTED",
    16388: "NAT_DETECTION_SOURCE_IP",
    16389: "NAT_DETECTION_DESTINATION_IP",
    16390: "COOKIE",
    16391: "USE_TRANSPORT_MODE",
    16392: "HTTP_CERT_LOOKUP_SUPPORTED",
    16393: "REKEY_SA",
    16394: "ESP_TFC_PADDING_NOT_SUPPORTED",
    16395: "NON_FIRST_FRAGMENTS_ALSO",
    16396: "MOBIKE_SUPPORTED",
    16397: "ADDITIONAL_IP4_ADDRESS",
    16398: "ADDITIONAL_IP6_ADDRESS",
    16399: "NO_ADDITIONAL_ADDRESSES",
    16400: "UPDATE_SA_ADDRESSES",
    16401: "COOKIE2",
    16402: "NO_NATS_ALLOWED",
    16403: "AUTH_LIFETIME",
    16404: "MULTIPLE_AUTH_SUPPORTED",
    16405: "ANOTHER_AUTH_FOLLOWS",
    16406: "REDIRECT_SUPPORTED",
    16407: "REDIRECT",
    16408: "REDIRECTED_FROM",
    16409: "TICKET_LT_OPAQUE",
    16410: "TICKET_REQUEST",
    16411: "TICKET_ACK",
    16412: "TICKET_NACK",
    16413: "TICKET_OPAQUE",
    16414: "LINK_ID",
    16415: "USE_WESP_MODE",
    16416: "ROHC_SUPPORTED",
    16417: "EAP_ONLY_AUTHENTICATION",
    16418: "CHILDLESS_IKEV2_SUPPORTED",
    16419: "QUICK_CRASH_DETECTION",
    16420: "IKEV2_MESSAGE_ID_SYNC_SUPPORTED",
    16421: "IPSEC_REPLAY_COUNTER_SYNC_SUPPORTED",
    16422: "IKEV2_MESSAGE_ID_SYNC",
    16423: "IPSEC_REPLAY_COUNTER_SYNC",
    16424: "SECURE_PASSWORD_METHODS",
    16425: "PSK_PERSIST",
    16426: "PSK_CONFIRM",
    16427: "ERX_SUPPORTED",
    16428: "IFOM_CAPABILITY",
    16429: "SENDER_REQUEST_ID",
    16430: "IKEV2_FRAGMENTATION_SUPPORTED",
    16431: "SIGNATURE_HASH_ALGORITHMS",
    16432: "CLONE_IKE_SA_SUPPORTED",
    16433: "CLONE_IKE_SA"
}

IKEv2CertificateEncodings = {
    1: "PKCS #7 wrapped X.509 certificate",
    2: "PGP Certificate",
    3: "DNS Signed Key",
    4: "X.509 Certificate - Signature",
    6: "Kerberos Token",
    7: "Certificate Revocation List (CRL)",
    8: "Authority Revocation List (ARL)",
    9: "SPKI Certificate",
    10: "X.509 Certificate - Attribute",
    11: "Raw RSA Key",
    12: "Hash and URL of X.509 certificate",
    13: "Hash and URL of X.509 bundle"
}

IKEv2TrafficSelectorTypes = {
    7: "TS_IPV4_ADDR_RANGE",
    8: "TS_IPV6_ADDR_RANGE",
    9: "TS_FC_ADDR_RANGE"
}

IPProtocolIDs = {
    0: "All protocols",
    1: "Internet Control Message Protocol",
    2: "Internet Group Management Protocol",
    3: "Gateway-to-Gateway Protocol",
    4: "IP in IP (encapsulation)",
    5: "Internet Stream Protocol",
    6: "Transmission Control Protocol",
    7: "Core-based trees",
    8: "Exterior Gateway Protocol",
    9: "Interior Gateway Protocol (any private interior gateway (used by Cisco for their IGRP))",  # noqa: E501
    10: "BBN RCC Monitoring",
    11: "Network Voice Protocol",
    12: "Xerox PUP",
    13: "ARGUS",
    14: "EMCON",
    15: "Cross Net Debugger",
    16: "Chaos",
    17: "User Datagram Protocol",
    18: "Multiplexing",
    19: "DCN Measurement Subsystems",
    20: "Host Monitoring Protocol",
    21: "Packet Radio Measurement",
    22: "XEROX NS IDP",
    23: "Trunk-1",
    24: "Trunk-2",
    25: "Leaf-1",
    26: "Leaf-2",
    27: "Reliable Datagram Protocol",
    28: "Internet Reliable Transaction Protocol",
    29: "ISO Transport Protocol Class 4",
    30: "Bulk Data Transfer Protocol",
    31: "MFE Network Services Protocol",
    32: "MERIT Internodal Protocol",
    33: "Datagram Congestion Control Protocol",
    34: "Third Party Connect Protocol",
    35: "Inter-Domain Policy Routing Protocol",
    36: "Xpress Transport Protocol",
    37: "Datagram Delivery Protocol",
    38: "IDPR Control Message Transport Protocol",
    39: "TP++ Transport Protocol",
    40: "IL Transport Protocol",
    41: "IPv6 Encapsulation",
    42: "Source Demand Routing Protocol",
    43: "Routing Header for IPv6",
    44: "Fragment Header for IPv6",
    45: "Inter-Domain Routing Protocol",
    46: "Resource Reservation Protocol",
    47: "Generic Routing Encapsulation",
    48: "Mobile Host Routing Protocol",
    49: "BNA",
    50: "Encapsulating Security Payload",
    51: "Authentication Header",
    52: "Integrated Net Layer Security Protocol",
    53: "SwIPe",
    54: "NBMA Address Resolution Protocol",
    55: "IP Mobility (Min Encap)",
    56: "Transport Layer Security Protocol (using Kryptonet key management)",
    57: "Simple Key-Management for Internet Protocol",
    58: "ICMP for IPv6",
    59: "No Next Header for IPv6",
    60: "Destination Options for IPv6",
    61: "Any host internal protocol",
    62: "CFTP",
    63: "Any local network",
    64: "SATNET and Backroom EXPAK",
    65: "Kryptolan",
    66: "MIT Remote Virtual Disk Protocol",
    67: "Internet Pluribus Packet Core",
    68: "Any distributed file system",
    69: "SATNET Monitoring",
    70: "VISA Protocol",
    71: "Internet Packet Core Utility",
    72: "Computer Protocol Network Executive",
    73: "Computer Protocol Heart Beat",
    74: "Wang Span Network",
    75: "Packet Video Protocol",
    76: "Backroom SATNET Monitoring",
    77: "SUN ND PROTOCOL-Temporary",
    78: "WIDEBAND Monitoring",
    79: "WIDEBAND EXPAK",
    80: "International Organization for Standardization Internet Protocol",
    81: "Versatile Message Transaction Protocol",
    82: "Secure Versatile Message Transaction Protocol",
    83: "VINES",
    84: "Internet Protocol Traffic Manager",
    85: "NSFNET-IGP",
    86: "Dissimilar Gateway Protocol",
    87: "TCF",
    88: "EIGRP",
    89: "Open Shortest Path First",
    90: "Sprite RPC Protocol",
    91: "Locus Address Resolution Protocol",
    92: "Multicast Transport Protocol",
    93: "AX.25",
    94: "IP-within-IP Encapsulation Protocol",
    95: "Mobile Internetworking Control Protocol",
    96: "Semaphore Communications Sec. Pro",
    97: "Ethernet-within-IP Encapsulation",
    98: "Encapsulation Header",
    99: "Any private encryption scheme",
    100: "GMTP",
    101: "Ipsilon Flow Management Protocol",
    102: "PNNI over IP",
    103: "Protocol Independent Multicast",
    104: "IBM's ARIS (Aggregate Route IP Switching) Protocol",
    105: "SCPS (Space Communications Protocol Standards)",
    106: "QNX",
    107: "Active Networks",
    108: "IP Payload Compression Protocol",
    109: "Sitara Networks Protocol",
    110: "Compaq Peer Protocol",
    111: "IPX in IP",
    112: "Virtual Router Redundancy Protocol, Common Address Redundancy Protocol (not IANA assigned)",  # noqa: E501
    113: "PGM Reliable Transport Protocol",
    114: "Any 0-hop protocol",
    115: "Layer Two Tunneling Protocol Version 3",
    116: "D-II Data Exchange (DDX)",
    117: "Interactive Agent Transfer Protocol",
    118: "Schedule Transfer Protocol",
    119: "SpectraLink Radio Protocol",
    120: "Universal Transport Interface Protocol",
    121: "Simple Message Protocol",
    122: "Simple Multicast Protocol",
    123: "Performance Transparency Protocol",
    124: "Intermediate System to Intermediate System (IS-IS) Protocol over IPv4",  # noqa: E501
    125: "Flexible Intra-AS Routing Environment",
    126: "Combat Radio Transport Protocol",
    127: "Combat Radio User Datagram",
    128: "Service-Specific Connection-Oriented Protocol in a Multilink and Connectionless Environment",  # noqa: E501
    129: "IPLT",
    130: "Secure Packet Shield",
    131: "Private IP Encapsulation within IP",
    132: "Stream Control Transmission Protocol",
    133: "Fibre Channel",
    134: "Reservation Protocol (RSVP) End-to-End Ignore",
    135: "Mobility Extension Header for IPv6",
    136: "Lightweight User Datagram Protocol",
    137: "Multiprotocol Label Switching Encapsulated in IP",
    138: "MANET Protocols",
    139: "Host Identity Protocol",
    140: "Site Multihoming by IPv6 Intermediation",
    141: "Wrapped Encapsulating Security Payload",
    142: "Robust Header Compression",
}

# the name 'IKEv2TransformTypes' is actually a misnomer (since the table
# holds info for all IKEv2 Attribute types, not just transforms, but we'll
# keep it for backwards compatibility... for now at least
IKEv2TransformTypes = IKEv2AttributeTypes

IKEv2TransformNum = {}
for n in IKEv2TransformTypes:
    val = IKEv2TransformTypes[n]
    tmp = {}
    for e in val[1]:
        tmp[val[1][e]] = e
    IKEv2TransformNum[val[0]] = tmp

IKEv2Transforms = {}
for n in IKEv2TransformTypes:
    IKEv2Transforms[IKEv2TransformTypes[n][0]] = n

del(n)
del(e)
del(tmp)
del(val)

# Note: Transform and Proposal can only be used inside the SA payload
IKEv2_payload_type = ["None", "", "Proposal", "Transform"]

IKEv2_payload_type.extend([""] * 29)
IKEv2_payload_type.extend(["SA", "KE", "IDi", "IDr", "CERT", "CERTREQ", "AUTH", "Nonce", "Notify", "Delete",  # noqa: E501
                           "VendorID", "TSi", "TSr", "Encrypted", "CP", "EAP", "", "", "", "", "Encrypted_Fragment"])  # noqa: E501

IKEv2_exchange_type = [""] * 34
IKEv2_exchange_type.extend(["IKE_SA_INIT", "IKE_AUTH", "CREATE_CHILD_SA",
                            "INFORMATIONAL", "IKE_SESSION_RESUME"])


class IKEv2_class(Packet):
    def guess_payload_class(self, payload):
        np = self.next_payload
        logging.debug("For IKEv2_class np=%d", np)
        if np == 0:
            return conf.raw_layer
        elif np < len(IKEv2_payload_type):
            pt = IKEv2_payload_type[np]
            logging.debug(globals().get("IKEv2_payload_%s" % pt, IKEv2_payload))  # noqa: E501
            return globals().get("IKEv2_payload_%s" % pt, IKEv2_payload)
        else:
            return IKEv2_payload


class IKEv2(IKEv2_class):  # rfc4306
    name = "IKEv2"
    fields_desc = [
        StrFixedLenField("init_SPI", "", 8),
        StrFixedLenField("resp_SPI", "", 8),
        ByteEnumField("next_payload", 0, IKEv2_payload_type),
        XByteField("version", 0x20),
        ByteEnumField("exch_type", 0, IKEv2_exchange_type),
        FlagsField("flags", 0, 8, ["res0", "res1", "res2", "Initiator", "Version", "Response", "res6", "res7"]),  # noqa: E501
        IntField("id", 0),
        IntField("length", None)  # Length of total message: packets + all payloads  # noqa: E501
    ]

    def guess_payload_class(self, payload):
        if self.flags & 1:
            return conf.raw_layer
        return IKEv2_class.guess_payload_class(self, payload)

    def answers(self, other):
        if isinstance(other, IKEv2):
            if other.init_SPI == self.init_SPI:
                return 1
        return 0

    def post_build(self, p, pay):
        p += pay
        if self.length is None:
            p = p[:24] + struct.pack("!I", len(p)) + p[28:]
        return p


class IKEv2_Key_Length_Attribute(IntField):
    # We only support the fixed-length Key Length attribute (the only one currently defined)  # noqa: E501
    def __init__(self, name):
        IntField.__init__(self, name, 0x800E0000)

    def i2h(self, pkt, x):
        return IntField.i2h(self, pkt, x & 0xFFFF)

    def h2i(self, pkt, x):
        return IntField.h2i(self, pkt, (x if x is not None else 0) | 0x800E0000)  # noqa: E501


class IKEv2_payload_Transform(IKEv2_class):
    name = "IKE Transform"
    fields_desc = [
        ByteEnumField("next_payload", None, {0: "last", 3: "Transform"}),
        ByteField("res", 0),
        ShortField("length", 8),
        ByteEnumField("transform_type", None, IKEv2Transforms),
        ByteField("res2", 0),
        MultiEnumField("transform_id", None, IKEv2TransformNum, depends_on=lambda pkt: pkt.transform_type, fmt="H"),  # noqa: E501
        ConditionalField(IKEv2_Key_Length_Attribute("key_length"), lambda pkt: pkt.length > 8),  # noqa: E501
    ]


class IKEv2_payload_Proposal(IKEv2_class):
    name = "IKEv2 Proposal"
    fields_desc = [
        ByteEnumField("next_payload", None, {0: "last", 2: "Proposal"}),
        ByteField("res", 0),
        FieldLenField("length", None, "trans", "H", adjust=lambda pkt, x: x + 8 + (pkt.SPIsize if pkt.SPIsize else 0)),  # noqa: E501
        ByteField("proposal", 1),
        ByteEnumField("proto", 1, {1: "IKEv2", 2: "AH", 3: "ESP"}),
        FieldLenField("SPIsize", None, "SPI", "B"),
        ByteField("trans_nb", None),
        StrLenField("SPI", "", length_from=lambda pkt: pkt.SPIsize),
        PacketLenField("trans", conf.raw_layer(), IKEv2_payload_Transform, length_from=lambda pkt: pkt.length - 8 - pkt.SPIsize),  # noqa: E501
    ]


class IKEv2_payload(IKEv2_class):
    name = "IKEv2 Payload"
    fields_desc = [
        ByteEnumField("next_payload", None, IKEv2_payload_type),
        FlagsField("flags", 0, 8, ["critical", "res1", "res2", "res3", "res4", "res5", "res6", "res7"]),  # noqa: E501
        FieldLenField("length", None, "load", "H", adjust=lambda pkt, x:x + 4),
        StrLenField("load", "", length_from=lambda x:x.length - 4),
    ]


class IKEv2_payload_AUTH(IKEv2_class):
    name = "IKEv2 Authentication"
    overload_fields = {IKEv2: {"next_payload": 39}}
    fields_desc = [
        ByteEnumField("next_payload", None, IKEv2_payload_type),
        ByteField("res", 0),
        FieldLenField("length", None, "load", "H", adjust=lambda pkt, x:x + 8),
        ByteEnumField("auth_type", None, IKEv2AuthenticationTypes),
        X3BytesField("res2", 0),
        StrLenField("load", "", length_from=lambda x:x.length - 8),
    ]


class IKEv2_payload_VendorID(IKEv2_class):
    name = "IKEv2 Vendor ID"
    overload_fields = {IKEv2: {"next_payload": 43}}
    fields_desc = [
        ByteEnumField("next_payload", None, IKEv2_payload_type),
        ByteField("res", 0),
        FieldLenField("length", None, "vendorID", "H", adjust=lambda pkt, x:x + 4),  # noqa: E501
        StrLenField("vendorID", "", length_from=lambda x:x.length - 4),
    ]


class TrafficSelector(Packet):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and len(_pkt) >= 16:
            ts_type = struct.unpack("!B", _pkt[0:1])[0]
            if ts_type == 7:
                return IPv4TrafficSelector
            elif ts_type == 8:
                return IPv6TrafficSelector
            elif ts_type == 9:
                return EncryptedTrafficSelector
            else:
                return RawTrafficSelector
        return IPv4TrafficSelector


class IPv4TrafficSelector(TrafficSelector):
    name = "IKEv2 IPv4 Traffic Selector"
    fields_desc = [
        ByteEnumField("TS_type", 7, IKEv2TrafficSelectorTypes),
        ByteEnumField("IP_protocol_ID", None, IPProtocolIDs),
        ShortField("length", 16),
        ShortField("start_port", 0),
        ShortField("end_port", 65535),
        IPField("starting_address_v4", "192.168.0.1"),
        IPField("ending_address_v4", "192.168.0.255"),
    ]


class IPv6TrafficSelector(TrafficSelector):
    name = "IKEv2 IPv6 Traffic Selector"
    fields_desc = [
        ByteEnumField("TS_type", 8, IKEv2TrafficSelectorTypes),
        ByteEnumField("IP_protocol_ID", None, IPProtocolIDs),
        ShortField("length", 20),
        ShortField("start_port", 0),
        ShortField("end_port", 65535),
        IP6Field("starting_address_v6", "2001::"),
        IP6Field("ending_address_v6", "2001::"),
    ]


class EncryptedTrafficSelector(TrafficSelector):
    name = "IKEv2 Encrypted Traffic Selector"
    fields_desc = [
        ByteEnumField("TS_type", 9, IKEv2TrafficSelectorTypes),
        ByteEnumField("IP_protocol_ID", None, IPProtocolIDs),
        ShortField("length", 16),
        ByteField("res", 0),
        X3BytesField("starting_address_FC", 0),
        ByteField("res2", 0),
        X3BytesField("ending_address_FC", 0),
        ByteField("starting_R_CTL", 0),
        ByteField("ending_R_CTL", 0),
        ByteField("starting_type", 0),
        ByteField("ending_type", 0),
    ]


class RawTrafficSelector(TrafficSelector):
    name = "IKEv2 Encrypted Traffic Selector"
    fields_desc = [
        ByteEnumField("TS_type", None, IKEv2TrafficSelectorTypes),
        ByteEnumField("IP_protocol_ID", None, IPProtocolIDs),
        FieldLenField("length", None, "load", "H", adjust=lambda pkt, x:x + 4),
        PacketField("load", "", Raw)
    ]


class IKEv2_payload_TSi(IKEv2_class):
    name = "IKEv2 Traffic Selector - Initiator"
    overload_fields = {IKEv2: {"next_payload": 44}}
    fields_desc = [
        ByteEnumField("next_payload", None, IKEv2_payload_type),
        ByteField("res", 0),
        FieldLenField("length", None, "traffic_selector", "H", adjust=lambda pkt, x:x + 8),  # noqa: E501
        ByteField("number_of_TSs", 0),
        X3BytesField("res2", 0),
        PacketListField("traffic_selector", None, TrafficSelector, length_from=lambda x:x.length - 8, count_from=lambda x:x.number_of_TSs),  # noqa: E501
    ]


class IKEv2_payload_TSr(IKEv2_class):
    name = "IKEv2 Traffic Selector - Responder"
    overload_fields = {IKEv2: {"next_payload": 45}}
    fields_desc = [
        ByteEnumField("next_payload", None, IKEv2_payload_type),
        ByteField("res", 0),
        FieldLenField("length", None, "traffic_selector", "H", adjust=lambda pkt, x:x + 8),  # noqa: E501
        ByteField("number_of_TSs", 0),
        X3BytesField("res2", 0),
        PacketListField("traffic_selector", None, TrafficSelector, length_from=lambda x:x.length - 8, count_from=lambda x:x.number_of_TSs),  # noqa: E501
    ]


class IKEv2_payload_Delete(IKEv2_class):
    name = "IKEv2 Vendor ID"
    overload_fields = {IKEv2: {"next_payload": 42}}
    fields_desc = [
        ByteEnumField("next_payload", None, IKEv2_payload_type),
        ByteField("res", 0),
        FieldLenField("length", None, "vendorID", "H", adjust=lambda pkt, x:x + 4),  # noqa: E501
        StrLenField("vendorID", "", length_from=lambda x:x.length - 4),
    ]


class IKEv2_payload_SA(IKEv2_class):
    name = "IKEv2 SA"
    overload_fields = {IKEv2: {"next_payload": 33}}
    fields_desc = [
        ByteEnumField("next_payload", None, IKEv2_payload_type),
        ByteField("res", 0),
        FieldLenField("length", None, "prop", "H", adjust=lambda pkt, x:x + 4),
        PacketLenField("prop", conf.raw_layer(), IKEv2_payload_Proposal, length_from=lambda x:x.length - 4),  # noqa: E501
    ]


class IKEv2_payload_Nonce(IKEv2_class):
    name = "IKEv2 Nonce"
    overload_fields = {IKEv2: {"next_payload": 40}}
    fields_desc = [
        ByteEnumField("next_payload", None, IKEv2_payload_type),
        ByteField("res", 0),
        FieldLenField("length", None, "load", "H", adjust=lambda pkt, x:x + 4),
        StrLenField("load", "", length_from=lambda x:x.length - 4),
    ]


class IKEv2_payload_Notify(IKEv2_class):
    name = "IKEv2 Notify"
    overload_fields = {IKEv2: {"next_payload": 41}}
    fields_desc = [
        ByteEnumField("next_payload", None, IKEv2_payload_type),
        ByteField("res", 0),
        FieldLenField("length", None, "load", "H", adjust=lambda pkt, x:x + 8),
        ByteEnumField("proto", None, {0: "Reserved", 1: "IKE", 2: "AH", 3: "ESP"}),  # noqa: E501
        FieldLenField("SPIsize", None, "SPI", "B"),
        ShortEnumField("type", 0, IKEv2NotifyMessageTypes),
        StrLenField("SPI", "", length_from=lambda x: x.SPIsize),
        StrLenField("load", "", length_from=lambda x: x.length - 8),
    ]


class IKEv2_payload_KE(IKEv2_class):
    name = "IKEv2 Key Exchange"
    overload_fields = {IKEv2: {"next_payload": 34}}
    fields_desc = [
        ByteEnumField("next_payload", None, IKEv2_payload_type),
        ByteField("res", 0),
        FieldLenField("length", None, "load", "H", adjust=lambda pkt, x:x + 8),
        ShortEnumField("group", 0, IKEv2TransformTypes['GroupDesc'][1]),
        ShortField("res2", 0),
        StrLenField("load", "", length_from=lambda x:x.length - 8),
    ]


class IKEv2_payload_IDi(IKEv2_class):
    name = "IKEv2 Identification - Initiator"
    overload_fields = {IKEv2: {"next_payload": 35}}
    fields_desc = [
        ByteEnumField("next_payload", None, IKEv2_payload_type),
        ByteField("res", 0),
        FieldLenField("length", None, "load", "H", adjust=lambda pkt, x:x + 8),
        ByteEnumField("IDtype", 1, {1: "IPv4_addr", 2: "FQDN", 3: "Email_addr", 5: "IPv6_addr", 11: "Key"}),  # noqa: E501
        ByteEnumField("ProtoID", 0, {0: "Unused"}),
        ShortEnumField("Port", 0, {0: "Unused"}),
        #        IPField("IdentData","127.0.0.1"),
        StrLenField("load", "", length_from=lambda x: x.length - 8),
    ]


class IKEv2_payload_IDr(IKEv2_class):
    name = "IKEv2 Identification - Responder"
    overload_fields = {IKEv2: {"next_payload": 36}}
    fields_desc = [
        ByteEnumField("next_payload", None, IKEv2_payload_type),
        ByteField("res", 0),
        FieldLenField("length", None, "load", "H", adjust=lambda pkt, x:x + 8),
        ByteEnumField("IDtype", 1, {1: "IPv4_addr", 2: "FQDN", 3: "Email_addr", 5: "IPv6_addr", 11: "Key"}),  # noqa: E501
        ByteEnumField("ProtoID", 0, {0: "Unused"}),
        ShortEnumField("Port", 0, {0: "Unused"}),
        #        IPField("IdentData","127.0.0.1"),
        StrLenField("load", "", length_from=lambda x: x.length - 8),
    ]


class IKEv2_payload_Encrypted(IKEv2_class):
    name = "IKEv2 Encrypted and Authenticated"
    overload_fields = {IKEv2: {"next_payload": 46}}
    fields_desc = [
        ByteEnumField("next_payload", None, IKEv2_payload_type),
        ByteField("res", 0),
        FieldLenField("length", None, "load", "H", adjust=lambda pkt, x:x + 4),
        StrLenField("load", "", length_from=lambda x:x.length - 4),
    ]


class IKEv2_payload_Encrypted_Fragment(IKEv2_class):
    name = "IKEv2 Encrypted Fragment"
    overload_fields = {IKEv2: {"next_payload": 53}}
    fields_desc = [
        ByteEnumField("next_payload", None, IKEv2_payload_type),
        ByteField("res", 0),
        FieldLenField("length", None, "load", "H", adjust=lambda pkt, x: x + 8),  # noqa: E501
        ShortField("frag_number", 1),
        ShortField("frag_total", 1),
        StrLenField("load", "", length_from=lambda x: x.length - 8),
    ]


class IKEv2_payload_CERTREQ(IKEv2_class):
    name = "IKEv2 Certificate Request"
    fields_desc = [
        ByteEnumField("next_payload", None, IKEv2_payload_type),
        ByteField("res", 0),
        FieldLenField("length", None, "cert_data", "H", adjust=lambda pkt, x:x + 5),  # noqa: E501
        ByteEnumField("cert_type", 0, IKEv2CertificateEncodings),
        StrLenField("cert_data", "", length_from=lambda x:x.length - 5),
    ]


class IKEv2_payload_CERT(IKEv2_class):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and len(_pkt) >= 16:
            ts_type = struct.unpack("!B", _pkt[4:5])[0]
            if ts_type == 4:
                return IKEv2_payload_CERT_CRT
            elif ts_type == 7:
                return IKEv2_payload_CERT_CRL
            else:
                return IKEv2_payload_CERT_STR
        return IKEv2_payload_CERT_STR


class IKEv2_payload_CERT_CRT(IKEv2_payload_CERT):
    name = "IKEv2 Certificate"
    fields_desc = [
        ByteEnumField("next_payload", None, IKEv2_payload_type),
        ByteField("res", 0),
        FieldLenField("length", None, "x509Cert", "H", adjust=lambda pkt, x: x + len(pkt.x509Cert) + 5),  # noqa: E501
        ByteEnumField("cert_type", 4, IKEv2CertificateEncodings),
        PacketLenField("x509Cert", X509_Cert(''), X509_Cert, length_from=lambda x:x.length - 5),  # noqa: E501
    ]


class IKEv2_payload_CERT_CRL(IKEv2_payload_CERT):
    name = "IKEv2 Certificate"
    fields_desc = [
        ByteEnumField("next_payload", None, IKEv2_payload_type),
        ByteField("res", 0),
        FieldLenField("length", None, "x509CRL", "H", adjust=lambda pkt, x: x + len(pkt.x509CRL) + 5),  # noqa: E501
        ByteEnumField("cert_type", 7, IKEv2CertificateEncodings),
        PacketLenField("x509CRL", X509_CRL(''), X509_CRL, length_from=lambda x:x.length - 5),  # noqa: E501
    ]


class IKEv2_payload_CERT_STR(IKEv2_payload_CERT):
    name = "IKEv2 Certificate"
    fields_desc = [
        ByteEnumField("next_payload", None, IKEv2_payload_type),
        ByteField("res", 0),
        FieldLenField("length", None, "cert_data", "H", adjust=lambda pkt, x: x + 5),  # noqa: E501
        ByteEnumField("cert_type", 0, IKEv2CertificateEncodings),
        StrLenField("cert_data", "", length_from=lambda x:x.length - 5),
    ]


IKEv2_payload_type_overload = {}
for i, payloadname in enumerate(IKEv2_payload_type):
    name = "IKEv2_payload_%s" % payloadname
    if name in globals():
        IKEv2_payload_type_overload[globals()[name]] = {"next_payload": i}

del i, payloadname, name
IKEv2_class._overload_fields = IKEv2_payload_type_overload.copy()

split_layers(UDP, ISAKMP, sport=500)
split_layers(UDP, ISAKMP, dport=500)

bind_layers(UDP, IKEv2, dport=500, sport=500)  # TODO: distinguish IKEv1/IKEv2
bind_layers(UDP, IKEv2, dport=4500, sport=4500)


def ikev2scan(ip, **kwargs):
    """Send a IKEv2 SA to an IP and wait for answers."""
    return sr(IP(dst=ip) / UDP() / IKEv2(init_SPI=RandString(8),
                                         exch_type=34) / IKEv2_payload_SA(prop=IKEv2_payload_Proposal()), **kwargs)  # noqa: E501
