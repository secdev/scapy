# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
Internet Key Exchange Protocol Version 2 (IKEv2), RFC 7296
"""

# scapy.contrib.description = Internet Key Exchange Protocol Version 2 (IKEv2), RFC 7296
# scapy.contrib.status = loads

import struct


# Modified from the original ISAKMP code by Yaron Sheffer <yaronf.ietf@gmail.com>, June 2010.  # noqa: E501

from scapy.packet import (
    Packet,
    Raw,
    bind_bottom_up,
    bind_layers,
    bind_top_down,
    split_bottom_up,
)
from scapy.fields import (
    ByteEnumField,
    ByteField,
    ConditionalField,
    FieldLenField,
    FieldListField,
    FlagsField,
    IP6Field,
    IPField,
    IntField,
    MultiEnumField,
    MultipleTypeField,
    PacketField,
    PacketLenField,
    PacketListField,
    ShortEnumField,
    ShortField,
    StrLenField,
    X3BytesField,
    XByteField,
    XStrFixedLenField,
    XStrLenField,
)
from scapy.layers.x509 import X509_Cert, X509_CRL
from scapy.layers.inet import IP, UDP
from scapy.layers.ipsec import NON_ESP
from scapy.layers.isakmp import ISAKMP
from scapy.sendrecv import sr
from scapy.config import conf
from scapy.volatile import RandString

# see https://www.iana.org/assignments/ikev2-parameters for details
IKEv2AttributeTypes = {
    1: (
        "Encryption",
        {
            1: "DES-IV64",
            2: "DES",
            3: "3DES",
            4: "RC5",
            5: "IDEA",
            6: "CAST",
            7: "Blowfish",
            8: "3IDEA",
            9: "DES-IV32",
            12: "AES-CBC",
            13: "AES-CTR",
            14: "AES-CCM-8",
            15: "AES-CCM-12",
            16: "AES-CCM-16",
            18: "AES-GCM-8ICV",
            19: "AES-GCM-12ICV",
            20: "AES-GCM-16ICV",
            23: "Camellia-CBC",
            24: "Camellia-CTR",
            25: "Camellia-CCM-8ICV",
            26: "Camellia-CCM-12ICV",
            27: "Camellia-CCM-16ICV",
            28: "ChaCha20-Poly1305",
            32: "Kuzneychik-MGM-KTREE",
            33: "MAGMA-MGM-KTREE",
        }
    ),
    2: (
        "PRF",
        {
            1: "PRF_HMAC_MD5",
            2: "PRF_HMAC_SHA1",
            3: "PRF_HMAC_TIGER",
            4: "PRF_AES128_XCBC",
            5: "PRF_HMAC_SHA2_256",
            6: "PRF_HMAC_SHA2_384",
            7: "PRF_HMAC_SHA2_512",
            8: "PRF_AES128_CMAC",
            9: "PRF_HMAC_STREEBOG_512",
        }
    ),
    3: (
        "Integrity",
        {
            1: "HMAC-MD5-96",
            2: "HMAC-SHA1-96",
            3: "DES-MAC",
            4: "KPDK-MD5",
            5: "AES-XCBC-96",
            6: "HMAC-MD5-128",
            7: "HMAC-SHA1-160",
            8: "AES-CMAC-96",
            9: "AES-128-GMAC",
            10: "AES-192-GMAC",
            11: "AES-256-GMAC",
            12: "SHA2-256-128",
            13: "SHA2-384-192",
            14: "SHA2-512-256",
        }
    ),
    4: (
        "GroupDesc",
        {
            1: "768MODPgr",
            2: "1024MODPgr",
            5: "1536MODPgr",
            14: "2048MODPgr",
            15: "3072MODPgr",
            16: "4096MODPgr",
            17: "6144MODPgr",
            18: "8192MODPgr",
            19: "256randECPgr",
            20: "384randECPgr",
            21: "521randECPgr",
            22: "1024MODP160POSgr",
            23: "2048MODP224POSgr",
            24: "2048MODP256POSgr",
            25: "192randECPgr",
            26: "224randECPgr",
            27: "brainpoolP224r1gr",
            28: "brainpoolP256r1gr",
            29: "brainpoolP384r1gr",
            30: "brainpoolP512r1gr",
            31: "curve25519gr",
            32: "curve448gr",
            33: "GOST3410_2012_256",
            34: "GOST3410_2012_512",
        }
    ),
    5: (
        "Extended Sequence Number",
        {
            0: "No ESN",
            1: "ESN"
        }
    ),
}

IKEv2TransformTypes = {
    tf_num: tf_name for tf_name, (tf_num, _) in IKEv2AttributeTypes.items()
}

IKEv2TransformAlgorithms = {
    tf_num: tf_dict for tf_num, (_, tf_dict) in IKEv2AttributeTypes.items()
}

IKEv2ProtocolTypes = {
    1: "IKE",
    2: "AH",
    3: "ESP"
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
    47: "NOTIFY_STATE_NOT_FOUND",
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
    16433: "CLONE_IKE_SA",
    16434: "IV2_NOTIFY_PUZZLE",
    16435: "IV2_NOTIFY_USE_PPK",
    16436: "IV2_NOTIFY_PPK_IDENTITY",
    16437: "IV2_NOTIFY_NO_PPK_AUTH",
    16438: "IV2_NOTIFY_INTERMEDIATE_EXCHANGE_SUPPORTED",
    16439: "IV2_NOTIFY_IP4_ALLOWED",
    16440: "IV2_NOTIFY_IP6_ALLOWED",
    16441: "IV2_NOTIFY_ADDITIONAL_KEY_EXCHANGE",
    16442: "IV2_NOTIFY_USE_AGGFRAG",
}

IKEv2GatewayIDTypes = {
    1: "IPv4_addr",
    2: "IPv6_addr",
    3: "FQDN"
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

IKEv2ConfigurationPayloadCFGTypes = {
    1: "CFG_REQUEST",
    2: "CFG_REPLY",
    3: "CFG_SET",
    4: "CFG_ACK"
}

IKEv2ConfigurationAttributeTypes = {
    1: "INTERNAL_IP4_ADDRESS",
    2: "INTERNAL_IP4_NETMASK",
    3: "INTERNAL_IP4_DNS",
    4: "INTERNAL_IP4_NBNS",
    6: "INTERNAL_IP4_DHCP",
    7: "APPLICATION_VERSION",
    8: "INTERNAL_IP6_ADDRESS",
    10: "INTERNAL_IP6_DNS",
    12: "INTERNAL_IP6_DHCP",
    13: "INTERNAL_IP4_SUBNET",
    14: "SUPPORTED_ATTRIBUTES",
    15: "INTERNAL_IP6_SUBNET",
    16: "MIP6_HOME_PREFIX",
    17: "INTERNAL_IP6_LINK",
    18: "INTERNAL_IP6_PREFIX",
    19: "HOME_AGENT_ADDRESS",
    20: "P_CSCF_IP4_ADDRESS",
    21: "P_CSCF_IP6_ADDRESS",
    22: "FTT_KAT",
    23: "EXTERNAL_SOURCE_IP4_NAT_INFO",
    24: "TIMEOUT_PERIOD_FOR_LIVENESS_CHECK",
    25: "INTERNAL_DNS_DOMAIN",
    26: "INTERNAL_DNSSEC_TA"
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

IKEv2PayloadTypes = {
    0: "None",
    2: "Proposal",   # used only inside the SA payload
    3: "Transform",  # used only inside the SA payload
    33: "SA",
    34: "KE",
    35: "IDi",
    36: "IDr",
    37: "CERT",
    38: "CERTREQ",
    39: "AUTH",
    40: "Nonce",
    41: "Notify",
    42: "Delete",
    43: "VendorID",
    44: "TSi",
    45: "TSr",
    46: "Encrypted",
    47: "CP",
    48: "EAP",
    49: "GSPM",
    50: "IDg",
    51: "GSA",
    52: "KD",
    53: "Encrypted_Fragment",
    54: "PS"
}


IKEv2ExchangeTypes = {
    34: "IKE_SA_INIT",
    35: "IKE_AUTH",
    36: "CREATE_CHILD_SA",
    37: "INFORMATIONAL",
    38: "IKE_SESSION_RESUME",
    43: "IKE_INTERMEDIATE"
}


class _IKEv2_Packet(Packet):
    def default_payload_class(self, payload):
        return IKEv2_Payload if self.next_payload else conf.raw_layer


class IKEv2(_IKEv2_Packet):  # rfc4306
    name = "IKEv2"
    fields_desc = [
        XStrFixedLenField("init_SPI", "", 8),
        XStrFixedLenField("resp_SPI", "", 8),
        ByteEnumField("next_payload", 0, IKEv2PayloadTypes),
        XByteField("version", 0x20),
        ByteEnumField("exch_type", 0, IKEv2ExchangeTypes),
        FlagsField("flags", 0, 8, ["res0", "res1", "res2", "Initiator", "Version", "Response", "res6", "res7"]),  # noqa: E501
        IntField("id", 0),
        IntField("length", None)  # Length of total message: packets + all payloads  # noqa: E501
    ]

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and len(_pkt) >= 18:
            version = struct.unpack("!B", _pkt[17:18])[0]
            if version < 0x20:
                return ISAKMP
        return cls

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


class IKEv2_Payload(_IKEv2_Packet):
    name = "IKEv2 Payload"
    fields_desc = [
        ByteEnumField("next_payload", None, IKEv2PayloadTypes),
        FlagsField("flags", 0, 8, ["critical"]),
        ShortField("length", None),
        XStrLenField("load", "", length_from=lambda pkt: pkt.length - 4),
    ]

    def post_build(self, pkt, pay):
        if self.length is None:
            pkt = pkt[:2] + struct.pack("!H", len(pkt)) + pkt[4:]
        return pkt + pay


class IKEv2_Transform(IKEv2_Payload):
    name = "IKEv2 Transform"
    fields_desc = IKEv2_Payload.fields_desc[:2] + [
        ShortField("length", 8),  # can't be None, because 'key_length' depends on it
        ByteEnumField("transform_type", None, IKEv2TransformTypes),
        ByteField("res2", 0),
        MultiEnumField("transform_id", None, IKEv2TransformAlgorithms, depends_on=lambda pkt: pkt.transform_type, fmt="H"),  # noqa: E501
        ConditionalField(IKEv2_Key_Length_Attribute("key_length"), lambda pkt: pkt.length > 8),  # noqa: E501
    ]


class IKEv2_Proposal(IKEv2_Payload):
    name = "IKEv2 Proposal"
    fields_desc = IKEv2_Payload.fields_desc[:3] + [
        ByteField("proposal", 1),
        ByteEnumField("proto", 1, IKEv2ProtocolTypes),
        FieldLenField("SPIsize", None, "SPI", "B"),
        ByteField("trans_nb", None),
        XStrLenField("SPI", "", length_from=lambda pkt: pkt.SPIsize),
        PacketLenField("trans", conf.raw_layer(), IKEv2_Transform, length_from=lambda pkt: pkt.length - 8 - pkt.SPIsize),  # noqa: E501
    ]


class IKEv2_AUTH(IKEv2_Payload):
    name = "IKEv2 Authentication"
    fields_desc = IKEv2_Payload.fields_desc[:3] + [
        ByteEnumField("auth_type", None, IKEv2AuthenticationTypes),
        X3BytesField("res2", 0),
        XStrLenField("load", "", length_from=lambda pkt: pkt.length - 8),
    ]


class IKEv2_VendorID(IKEv2_Payload):
    name = "IKEv2 Vendor ID"
    fields_desc = IKEv2_Payload.fields_desc[:3] + [
        XStrLenField("vendorID", "", length_from=lambda pkt: pkt.length - 4),
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

    def extract_padding(self, s):
        return '', s


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
        FieldLenField("length", None, "load", "H", adjust=lambda pkt, x: x + 4),
        PacketField("load", "", Raw)
    ]


class IKEv2_TSi(IKEv2_Payload):
    name = "IKEv2 Traffic Selector - Initiator"
    fields_desc = IKEv2_Payload.fields_desc[:3] + [
        FieldLenField("number_of_TSs", None, fmt="B",
                      count_of="traffic_selector"),
        X3BytesField("res2", 0),
        PacketListField("traffic_selector", None, TrafficSelector,
                        length_from=lambda pkt: pkt.length - 8,
                        count_from=lambda pkt: pkt.number_of_TSs),
    ]


class IKEv2_TSr(IKEv2_Payload):
    name = "IKEv2 Traffic Selector - Responder"
    fields_desc = IKEv2_Payload.fields_desc[:3] + [
        FieldLenField("number_of_TSs", None, fmt="B",
                      count_of="traffic_selector"),
        X3BytesField("res2", 0),
        PacketListField("traffic_selector", None, TrafficSelector,
                        length_from=lambda pkt: pkt.length - 8,
                        count_from=lambda pkt: pkt.number_of_TSs),
    ]


class IKEv2_Delete(IKEv2_Payload):
    name = "IKEv2 Delete"
    fields_desc = IKEv2_Payload.fields_desc[:3] + [
        ByteEnumField("proto", None, {0: "Reserved", 1: "IKE", 2: "AH", 3: "ESP"}),  # noqa: E501
        FieldLenField("SPIsize", None, "SPI", "B"),
        ShortField("SPInum", 0),
        FieldListField("SPI", [],
                       XStrLenField("", "", length_from=lambda pkt: pkt.SPIsize),
                       count_from=lambda pkt: pkt.SPInum)
    ]


class IKEv2_SA(IKEv2_Payload):
    name = "IKEv2 SA"
    fields_desc = IKEv2_Payload.fields_desc[:3] + [
        PacketLenField("prop", conf.raw_layer(), IKEv2_Proposal, length_from=lambda pkt: pkt.length - 4),  # noqa: E501
    ]


class IKEv2_Nonce(IKEv2_Payload):
    name = "IKEv2 Nonce"
    fields_desc = IKEv2_Payload.fields_desc[:3] + [
        XStrLenField("nonce", "", length_from=lambda pkt: pkt.length - 4),
    ]


class IKEv2_Notify(IKEv2_Payload):
    name = "IKEv2 Notify"
    fields_desc = IKEv2_Payload.fields_desc[:3] + [
        ByteEnumField("proto", None, IKEv2ProtocolTypes),
        FieldLenField("SPIsize", None, "SPI", "B"),
        ShortEnumField("type", 0, IKEv2NotifyMessageTypes),
        XStrLenField("SPI", "", length_from=lambda pkt: pkt.SPIsize),
        ConditionalField(
            XStrLenField("notify", "",
                         length_from=lambda pkt: pkt.length - 8 - pkt.SPIsize),
            lambda pkt: pkt.type not in (16407, 16408)
        ),
        ConditionalField(
            # REDIRECT, REDIRECTED_FROM  (RFC 5685)
            ByteEnumField("gw_id_type", 1, IKEv2GatewayIDTypes),
            lambda pkt: pkt.type in (16407, 16408)
        ),
        ConditionalField(
            # REDIRECT, REDIRECTED_FROM  (RFC 5685)
            FieldLenField("gw_id_len", None, "gw_id", "B"),
            lambda pkt: pkt.type in (16407, 16408)
        ),
        ConditionalField(
            # REDIRECT, REDIRECTED_FROM  (RFC 5685)
            MultipleTypeField(
                [
                    (IPField("gw_id", "127.0.0.1"), lambda x: x.gw_id_type == 1),
                    (IP6Field("gw_id", "::1"), lambda x: x.gw_id_type == 2),
                ],
                StrLenField("gw_id", "", length_from=lambda x: x.gw_id_len)
            ),
            lambda pkt: pkt.type in (16407, 16408)
        ),
        ConditionalField(
            # REDIRECT  (RFC 5685)
            XStrLenField("nonce", "", length_from=lambda x:x.length - 10 - x.gw_id_len),
            lambda pkt: pkt.type == 16407
        )
    ]


class IKEv2_KE(IKEv2_Payload):
    name = "IKEv2 Key Exchange"
    fields_desc = IKEv2_Payload.fields_desc[:3] + [
        ShortEnumField("group", 0, IKEv2TransformAlgorithms[4]),
        ShortField("res2", 0),
        XStrLenField("ke", "", length_from=lambda pkt: pkt.length - 8),
    ]


class IKEv2_IDi(IKEv2_Payload):  # RFC 7296, section 3.5
    name = "IKEv2 Identification - Initiator"
    fields_desc = IKEv2_Payload.fields_desc[:3] + [
        ByteEnumField("IDtype", 1, {1: "IPv4_addr", 2: "FQDN", 3: "Email_addr", 5: "IPv6_addr", 11: "Key"}),  # noqa: E501
        X3BytesField("res2", 0),
        MultipleTypeField(
            [
                (IPField("ID", "127.0.0.1"), lambda pkt: pkt.IDtype == 1),
                (IP6Field("ID", "::1"), lambda pkt: pkt.IDtype == 5),
            ],
            XStrLenField("ID", "", length_from=lambda pkt: pkt.length - 8),
        )
    ]


class IKEv2_IDr(IKEv2_Payload):  # RFC 7296, section 3.5
    name = "IKEv2 Identification - Responder"
    fields_desc = IKEv2_Payload.fields_desc[:3] + [
        ByteEnumField("IDtype", 1, {1: "IPv4_addr", 2: "FQDN", 3: "Email_addr", 5: "IPv6_addr", 11: "Key"}),  # noqa: E501
        X3BytesField("res2", 0),
        MultipleTypeField(
            [
                (IPField("ID", "127.0.0.1"), lambda pkt: pkt.IDtype == 1),
                (IP6Field("ID", "::1"), lambda pkt: pkt.IDtype == 5),
            ],
            XStrLenField("ID", "", length_from=lambda pkt: pkt.length - 8),
        )
    ]


class IKEv2_Encrypted(IKEv2_Payload):
    name = "IKEv2 Encrypted and Authenticated"


class ConfigurationAttribute(Packet):
    name = "IKEv2 Configuration Attribute"
    fields_desc = [
        ShortEnumField("type", 1, IKEv2ConfigurationAttributeTypes),
        FieldLenField("length", None, "value", "H"),
        MultipleTypeField(
            [
                (IPField("value", "127.0.0.1"),
                 lambda pkt: pkt.length == 4 and pkt.type in (1, 2, 3, 4, 6, 20)),
                (IP6Field("value", "::1"),
                 lambda pkt: pkt.length == 16 and pkt.type in (10, 12, 21)),
            ],
            XStrLenField("value", "", length_from=lambda pkt: pkt.length),
        )
    ]

    def extract_padding(self, s):
        return b'', s


class IKEv2_CP(IKEv2_Payload):  # RFC 7296, section 3.15
    name = "IKEv2 Configuration"
    fields_desc = IKEv2_Payload.fields_desc[:3] + [
        ByteEnumField("CFGType", 1, IKEv2ConfigurationPayloadCFGTypes),
        X3BytesField("res2", 0),
        PacketListField("attributes", None, ConfigurationAttribute,
                        length_from=lambda pkt: pkt.length - 8),
    ]


class IKEv2_Encrypted_Fragment(IKEv2_Payload):
    name = "IKEv2 Encrypted and Authenticated Fragment"
    fields_desc = IKEv2_Payload.fields_desc[:3] + [
        ShortField("frag_number", 1),
        ShortField("frag_total", 1),
        XStrLenField("load", "", length_from=lambda pkt: pkt.length - 8),
    ]


class IKEv2_CERTREQ(IKEv2_Payload):
    name = "IKEv2 Certificate Request"
    fields_desc = IKEv2_Payload.fields_desc[:3] + [
        ByteEnumField("cert_encoding", 0, IKEv2CertificateEncodings),
        XStrLenField("cert_authority", "", length_from=lambda pkt: pkt.length - 5),
    ]


class IKEv2_CERT(IKEv2_Payload):
    name = "IKEv2 Certificate"
    fields_desc = IKEv2_Payload.fields_desc[:3] + [
        ByteEnumField("cert_encoding", 4, IKEv2CertificateEncodings),
        MultipleTypeField(
            [
                (PacketLenField("cert_data", X509_Cert(), X509_Cert,
                                length_from=lambda pkt: pkt.length - 5),
                 lambda pkt: pkt.cert_encoding == 4),
                (PacketLenField("cert_data", X509_CRL(), X509_CRL,
                                length_from=lambda pkt: pkt.length - 5),
                 lambda pkt: pkt.cert_encoding == 7)
            ],
            XStrLenField("cert_data", "", length_from=lambda pkt: pkt.length - 5),
        )
    ]


# TODO: the following payloads are not fully dissected yet

class IKEv2_EAP(IKEv2_Payload):
    name = "IKEv2 Extensible Authentication"


class IKEv2_GSPM(IKEv2_Payload):
    name = "Generic Secure Password Method"


class IKEv2_IDg(IKEv2_Payload):
    name = "Group Identification"


class IKEv2_GSA(IKEv2_Payload):
    name = "Group Security Association"


class IKEv2_KD(IKEv2_Payload):
    name = "Key Download"


class IKEv2_PS(IKEv2_Payload):
    name = "Puzzle Solution"


# bind all IKEv2 payload classes together
bind_layers(_IKEv2_Packet, IKEv2_Proposal, next_payload=2)
bind_layers(_IKEv2_Packet, IKEv2_Transform, next_payload=3)
bind_layers(_IKEv2_Packet, IKEv2_SA, next_payload=33)
bind_layers(_IKEv2_Packet, IKEv2_KE, next_payload=34)
bind_layers(_IKEv2_Packet, IKEv2_IDi, next_payload=35)
bind_layers(_IKEv2_Packet, IKEv2_IDr, next_payload=36)
bind_layers(_IKEv2_Packet, IKEv2_CERT, next_payload=37)
bind_layers(_IKEv2_Packet, IKEv2_CERTREQ, next_payload=38)
bind_layers(_IKEv2_Packet, IKEv2_AUTH, next_payload=39)
bind_layers(_IKEv2_Packet, IKEv2_Nonce, next_payload=40)
bind_layers(_IKEv2_Packet, IKEv2_Notify, next_payload=41)
bind_layers(_IKEv2_Packet, IKEv2_Delete, next_payload=42)
bind_layers(_IKEv2_Packet, IKEv2_VendorID, next_payload=43)
bind_layers(_IKEv2_Packet, IKEv2_TSi, next_payload=44)
bind_layers(_IKEv2_Packet, IKEv2_TSr, next_payload=45)
bind_layers(_IKEv2_Packet, IKEv2_Encrypted, next_payload=46)
bind_layers(_IKEv2_Packet, IKEv2_CP, next_payload=47)
bind_layers(_IKEv2_Packet, IKEv2_EAP, next_payload=48)
bind_layers(_IKEv2_Packet, IKEv2_GSPM, next_payload=49)
bind_layers(_IKEv2_Packet, IKEv2_IDg, next_payload=50)
bind_layers(_IKEv2_Packet, IKEv2_GSA, next_payload=51)
bind_layers(_IKEv2_Packet, IKEv2_KD, next_payload=52)
bind_layers(_IKEv2_Packet, IKEv2_Encrypted_Fragment, next_payload=53)
bind_layers(_IKEv2_Packet, IKEv2_PS, next_payload=54)

# the upper bindings for port 500 to ISAKMP are handled by IKEv2.dispatch_hook
split_bottom_up(UDP, ISAKMP, dport=500)
split_bottom_up(UDP, ISAKMP, sport=500)

bind_bottom_up(UDP, IKEv2, dport=500)
bind_bottom_up(UDP, IKEv2, sport=500)
bind_top_down(UDP, IKEv2, dport=500, sport=500)

split_bottom_up(NON_ESP, ISAKMP)
bind_bottom_up(NON_ESP, IKEv2)


def ikev2scan(ip, **kwargs):
    """Send a IKEv2 SA to an IP and wait for answers."""
    return sr(IP(dst=ip) / UDP() / IKEv2(init_SPI=RandString(8),
                                         exch_type=34) / IKEv2_SA(prop=IKEv2_Proposal()), **kwargs)  # noqa: E501
